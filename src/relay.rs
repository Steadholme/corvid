//! Outbound relay: enqueue DKIM-signed mail, then deliver it to each recipient domain's MX.
//!
//! Submission (the webmail compose path + the submission listener) calls [`enqueue_outbound`],
//! which DKIM-signs the message once and writes one [`OutboundItem`] per destination domain
//! into the Postgres-backed queue. A background [`run_worker`] loop then drains the queue:
//! resolve MX, connect on :25 (outbound :25 is open), opportunistic STARTTLS, deliver, and on a
//! transient failure reschedule with capped exponential backoff (permanent failures after
//! `MAX_ATTEMPTS`).

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::dkim::DkimSigner;
use crate::dns;
use crate::model::{Message, OutboundItem};
use crate::store::Store;
use crate::util::{domain_of, new_id, now_secs, read_line};

/// Max delivery attempts before an item is marked permanently failed.
const MAX_ATTEMPTS: i64 = 6;
/// How often the worker scans the queue.
const POLL_INTERVAL: Duration = Duration::from_secs(10);

/// Result of an outbound enqueue that needs the user-facing batch reference.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnqueuedOutbound {
    /// The DKIM-signed raw message that was queued.
    pub raw: String,
    /// Shared id across queue rows for this compose submission.
    pub batch_id: String,
    /// Effective future send time; `0` means immediate.
    pub send_at: i64,
}

/// DKIM-sign `raw` (when the `From` domain matches the signer) and enqueue one outbound item
/// per recipient domain. Returns the signed message (so callers/tests can inspect the
/// `DKIM-Signature`). Null senders / malformed recipients are skipped.
pub async fn enqueue_outbound(
    store: &dyn Store,
    signer: Option<&DkimSigner>,
    raw: &str,
    env_from: &str,
    rcpts: &[String],
) -> Result<String, String> {
    enqueue_outbound_at(store, signer, raw, env_from, rcpts, "", 0).await
}

/// Enqueue one compose submission for a future send time. `send_at <= now` keeps the legacy immediate
/// semantics; a future value marks rows `scheduled` while the relay due query gates on that epoch.
pub async fn enqueue_outbound_at(
    store: &dyn Store,
    signer: Option<&DkimSigner>,
    raw: &str,
    env_from: &str,
    rcpts: &[String],
    mailbox: &str,
    send_at: i64,
) -> Result<String, String> {
    Ok(
        enqueue_outbound_at_with_batch(store, signer, raw, env_from, rcpts, mailbox, send_at)
            .await?
            .raw,
    )
}

/// Enqueue one compose submission and return the batch id the webmail layer can expose as an
/// undo/scheduled reference. This uses the same queue rows and `send_at` gate as
/// [`enqueue_outbound_at`].
pub async fn enqueue_outbound_at_with_batch(
    store: &dyn Store,
    signer: Option<&DkimSigner>,
    raw: &str,
    env_from: &str,
    rcpts: &[String],
    mailbox: &str,
    send_at: i64,
) -> Result<EnqueuedOutbound, String> {
    let signed = match signer {
        Some(s) if from_domain_matches(raw, &s.domain) => {
            s.sign(raw).map_err(|e| format!("dkim sign: {e}"))?
        }
        _ => raw.to_string(),
    };

    // Group recipients by their domain (one queue row per destination domain).
    let mut by_domain: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for r in rcpts {
        if let Some(d) = domain_of(r) {
            by_domain.entry(d).or_default().push(r.clone());
        }
    }
    let now = now_secs();
    let scheduled_at = if send_at > now { send_at } else { 0 };
    let status = if scheduled_at > 0 {
        "scheduled"
    } else {
        "queued"
    };
    let batch_id = new_id("ob");
    for (domain, drcpts) in by_domain {
        let item = OutboundItem {
            id: new_id("o"),
            mailbox: mailbox.to_string(),
            batch_id: batch_id.clone(),
            raw: signed.clone(),
            env_from: env_from.to_string(),
            rcpts: drcpts,
            to_domain: domain,
            attempts: 0,
            next_at: now,
            send_at: scheduled_at,
            sent_copy_filed: false,
            status: status.to_string(),
        };
        store
            .enqueue_outbound(&item)
            .await
            .map_err(|e| format!("enqueue: {e}"))?;
    }
    Ok(EnqueuedOutbound {
        raw: signed,
        batch_id,
        send_at: scheduled_at,
    })
}

/// True when the message's `From:` header is at `domain` (so we should DKIM-sign it).
fn from_domain_matches(raw: &str, domain: &str) -> bool {
    let parsed = crate::rfc822::parse(raw);
    // Extract an address out of the (possibly "Name <addr>") From header.
    let from = parsed.from;
    let addr = from
        .rfind('<')
        .and_then(|i| {
            from[i + 1..]
                .find('>')
                .map(|j| from[i + 1..i + 1 + j].to_string())
        })
        .unwrap_or(from);
    domain_of(&addr).map(|d| d == domain).unwrap_or(false)
}

/// Background queue-draining loop. Runs until the process exits.
pub async fn run_worker(store: Arc<dyn Store>, myhostname: String, try_tls: bool) {
    loop {
        let now = now_secs();
        match store.restore_due_snoozes(now, 100).await {
            Ok(n) if n > 0 => tracing::info!(restored = n, "relay: restored snoozed messages"),
            Ok(_) => {}
            Err(e) => tracing::warn!(error = %e, "relay: failed to restore snoozed messages"),
        }
        match store.due_outbound(now, 20).await {
            Ok(items) => {
                for item in items {
                    process_item(store.as_ref(), &item, &myhostname, try_tls).await;
                }
            }
            Err(e) => tracing::warn!(error = %e, "relay: failed to read outbound queue"),
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

async fn process_item(store: &dyn Store, item: &OutboundItem, myhost: &str, try_tls: bool) {
    match deliver(item, myhost, try_tls).await {
        Ok(()) => {
            let _ = store.mark_outbound_sent(&item.id).await;
            file_scheduled_sent_copy(store, item).await;
            tracing::info!(id = %item.id, domain = %item.to_domain, "relay: delivered");
        }
        Err(err) => {
            let attempts = item.attempts + 1;
            if !err.transient || attempts >= MAX_ATTEMPTS {
                let _ = store.fail_outbound(&item.id).await;
                tracing::warn!(id = %item.id, domain = %item.to_domain, error = %err.msg, "relay: gave up");
            } else {
                // Capped exponential backoff: 1m, 2m, 4m, ... up to ~1h.
                let backoff = 60i64 * (1i64 << (attempts.min(6) - 1));
                let next = now_secs() + backoff.min(3600);
                let _ = store.reschedule_outbound(&item.id, attempts, next).await;
                tracing::info!(id = %item.id, attempts, retry_in_s = backoff, "relay: transient, rescheduled");
            }
        }
    }
}

async fn file_scheduled_sent_copy(store: &dyn Store, item: &OutboundItem) {
    if item.mailbox.trim().is_empty() || item.send_at <= 0 {
        return;
    }
    match store
        .claim_scheduled_sent_copy(&item.mailbox, &item.batch_id)
        .await
    {
        Ok(true) => {}
        Ok(false) => return,
        Err(e) => {
            tracing::warn!(id = %item.id, error = %e, "relay: failed to claim scheduled sent copy");
            return;
        }
    }
    let parsed = crate::rfc822::parse(&item.raw);
    let from = if parsed.from.trim().is_empty() {
        item.env_from.clone()
    } else {
        parsed.from.clone()
    };
    let to = if parsed.to.trim().is_empty() {
        item.rcpts.join(", ")
    } else {
        parsed.to.clone()
    };
    let (message_id, thread_id) =
        crate::delivery::resolve_thread(store, &item.mailbox, &item.raw, &parsed.subject)
            .await
            .unwrap_or_default();
    let msg = Message {
        id: new_id("m"),
        mailbox: item.mailbox.clone(),
        msg_from: from,
        msg_to: to.clone(),
        subject: parsed.subject,
        raw_rfc822: item.raw.clone(),
        body_text: parsed.body_text,
        body_html: parsed.body_html,
        received_at: now_secs(),
        seen: true,
        folder: "Sent".to_string(),
        starred: false,
        snooze_until: 0,
        muted: false,
        thread_id,
        message_id,
    };
    if let Err(e) = store.store_message(&msg).await {
        tracing::warn!(id = %item.id, error = %e, "relay: failed to file scheduled sent copy");
        return;
    }
    crate::delivery::harvest_contacts(store, &item.mailbox, "", &to).await;
}

struct DeliverErr {
    transient: bool,
    msg: String,
}
impl DeliverErr {
    fn transient(msg: impl Into<String>) -> Self {
        Self {
            transient: true,
            msg: msg.into(),
        }
    }
    fn permanent(msg: impl Into<String>) -> Self {
        Self {
            transient: false,
            msg: msg.into(),
        }
    }
}

/// Resolve the destination MX list and try each in preference order until one accepts.
async fn deliver(item: &OutboundItem, myhost: &str, try_tls: bool) -> Result<(), DeliverErr> {
    let mut hosts: Vec<String> = match dns::resolve_mx(&item.to_domain).await {
        Ok(mx) if !mx.is_empty() => mx.into_iter().map(|m| m.exchange).collect(),
        Ok(_) => vec![item.to_domain.clone()], // implicit MX = the domain's A record (RFC 5321)
        Err(e) => return Err(DeliverErr::transient(format!("MX lookup: {e}"))),
    };
    hosts.retain(|h| !h.is_empty());

    let mut last = DeliverErr::transient("no MX host tried");
    for host in hosts {
        match smtp_deliver(&host, myhost, item, try_tls).await {
            Ok(()) => return Ok(()),
            Err(e) => {
                let stop = !e.transient;
                last = e;
                if stop {
                    break;
                }
            }
        }
    }
    Err(last)
}

/// One SMTP delivery conversation to a single MX host.
async fn smtp_deliver(
    host: &str,
    myhost: &str,
    item: &OutboundItem,
    try_tls: bool,
) -> Result<(), DeliverErr> {
    let connect = tokio::time::timeout(Duration::from_secs(20), TcpStream::connect((host, 25)))
        .await
        .map_err(|_| DeliverErr::transient("connect timeout"))?
        .map_err(|e| DeliverErr::transient(format!("connect {host}:25: {e}")))?;

    let mut tcp = connect;
    let mut buf = Vec::new();

    let (code, _) = read_reply(&mut tcp, &mut buf).await?;
    if code != 220 {
        return Err(reply_err(code, "greeting"));
    }
    write_line(&mut tcp, &format!("EHLO {myhost}")).await?;
    let (code, ehlo_text) = read_reply(&mut tcp, &mut buf).await?;
    if code != 250 {
        return Err(reply_err(code, "EHLO"));
    }

    if try_tls && ehlo_text.to_ascii_uppercase().contains("STARTTLS") {
        write_line(&mut tcp, "STARTTLS").await?;
        let (code, _) = read_reply(&mut tcp, &mut buf).await?;
        if code == 220 {
            match tls_connect(tcp, host).await {
                Ok(mut tls) => {
                    return finish_after_ehlo(&mut tls, myhost, item, true).await;
                }
                Err(e) => return Err(DeliverErr::transient(format!("STARTTLS handshake: {e}"))),
            }
        }
        // STARTTLS refused after advertising — fall through to plaintext on the same socket.
    }
    finish_after_ehlo(&mut tcp, myhost, item, false).await
}

/// Finish a delivery (MAIL/RCPT/DATA/QUIT) on an established (optionally TLS) stream.
async fn finish_after_ehlo<S>(
    s: &mut S,
    myhost: &str,
    item: &OutboundItem,
    reissue_ehlo: bool,
) -> Result<(), DeliverErr>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut buf = Vec::new();
    if reissue_ehlo {
        write_line(s, &format!("EHLO {myhost}")).await?;
        let (code, _) = read_reply(s, &mut buf).await?;
        if code != 250 {
            return Err(reply_err(code, "EHLO(tls)"));
        }
    }

    write_line(s, &format!("MAIL FROM:<{}>", item.env_from)).await?;
    let (code, _) = read_reply(s, &mut buf).await?;
    if code != 250 {
        return Err(reply_err(code, "MAIL FROM"));
    }
    for rcpt in &item.rcpts {
        write_line(s, &format!("RCPT TO:<{rcpt}>")).await?;
        let (code, _) = read_reply(s, &mut buf).await?;
        if !(250..=251).contains(&code) {
            return Err(reply_err(code, "RCPT TO"));
        }
    }
    write_line(s, "DATA").await?;
    let (code, _) = read_reply(s, &mut buf).await?;
    if code != 354 {
        return Err(reply_err(code, "DATA"));
    }
    let payload = dot_stuff(&item.raw);
    s.write_all(payload.as_bytes())
        .await
        .map_err(|e| DeliverErr::transient(format!("write DATA: {e}")))?;
    s.write_all(b"\r\n.\r\n")
        .await
        .map_err(|e| DeliverErr::transient(format!("write end-of-DATA: {e}")))?;
    s.flush().await.ok();
    let (code, _) = read_reply(s, &mut buf).await?;
    if code != 250 {
        return Err(reply_err(code, "end-of-DATA"));
    }
    write_line(s, "QUIT").await.ok();
    Ok(())
}

/// Opportunistic (unauthenticated) TLS to the destination: mail STARTTLS is best-effort, so we
/// do NOT verify the server certificate (the connection upgrade is opportunistic encryption).
async fn tls_connect(
    tcp: TcpStream,
    host: &str,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, String> {
    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(danger::NoVerify))
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));
    let server_name = rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|e| format!("server name: {e}"))?;
    connector
        .connect(server_name, tcp)
        .await
        .map_err(|e| e.to_string())
}

/// Dot-stuff a message body for the DATA phase: any line beginning with '.' gets an extra '.'.
/// Also normalises bare LF to CRLF.
fn dot_stuff(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len() + 16);
    for line in raw.replace("\r\n", "\n").split('\n') {
        if let Some(rest) = line.strip_prefix('.') {
            out.push('.');
            out.push('.');
            out.push_str(rest);
        } else {
            out.push_str(line);
        }
        out.push_str("\r\n");
    }
    // Trim the trailing CRLF we just added past the real body (the caller appends the dot line).
    if out.ends_with("\r\n") {
        out.truncate(out.len() - 2);
    }
    out
}

/// Read an SMTP reply (handling multi-line `250-...` continuations). Returns `(code, text)`.
async fn read_reply<S>(s: &mut S, buf: &mut Vec<u8>) -> Result<(u16, String), DeliverErr>
where
    S: AsyncRead + Unpin,
{
    let mut text = String::new();
    loop {
        let line = tokio::time::timeout(Duration::from_secs(60), read_line(s, buf, 65_536))
            .await
            .map_err(|_| DeliverErr::transient("read timeout"))?
            .map_err(|e| DeliverErr::transient(format!("read: {e}")))?
            .ok_or_else(|| DeliverErr::transient("connection closed"))?;
        let code: u16 = line.get(..3).and_then(|c| c.parse().ok()).unwrap_or(0);
        text.push_str(&line);
        text.push('\n');
        // A space (not '-') in the 4th position marks the final line.
        if line.as_bytes().get(3) != Some(&b'-') {
            return Ok((code, text));
        }
    }
}

async fn write_line<S>(s: &mut S, line: &str) -> Result<(), DeliverErr>
where
    S: AsyncWrite + Unpin,
{
    s.write_all(line.as_bytes())
        .await
        .map_err(|e| DeliverErr::transient(format!("write: {e}")))?;
    s.write_all(b"\r\n")
        .await
        .map_err(|e| DeliverErr::transient(format!("write: {e}")))?;
    s.flush().await.ok();
    Ok(())
}

fn reply_err(code: u16, stage: &str) -> DeliverErr {
    let msg = format!("{stage}: server replied {code}");
    if (500..600).contains(&code) {
        DeliverErr::permanent(msg)
    } else {
        DeliverErr::transient(msg)
    }
}

impl From<std::io::Error> for DeliverErr {
    fn from(e: std::io::Error) -> Self {
        DeliverErr::transient(e.to_string())
    }
}

mod danger {
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{DigitallySignedStruct, SignatureScheme};

    /// Accept any server certificate (opportunistic, unauthenticated mail TLS).
    #[derive(Debug)]
    pub struct NoVerify;

    impl ServerCertVerifier for NoVerify {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![
                SignatureScheme::RSA_PKCS1_SHA256,
                SignatureScheme::RSA_PKCS1_SHA384,
                SignatureScheme::RSA_PKCS1_SHA512,
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::ECDSA_NISTP384_SHA384,
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::RSA_PSS_SHA384,
                SignatureScheme::RSA_PSS_SHA512,
                SignatureScheme::ED25519,
            ]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::InMemoryStore;

    #[test]
    fn dot_stuffing_doubles_leading_dots() {
        let raw = "line1\r\n.hidden\r\n..already\r\nlast";
        let s = dot_stuff(raw);
        assert!(s.contains("\r\n..hidden\r\n"));
        assert!(s.contains("\r\n...already\r\n"));
        assert!(s.ends_with("last"));
    }

    #[tokio::test]
    async fn scheduled_sent_copy_is_claimed_once_per_batch() {
        let store = InMemoryStore::new();
        let item = OutboundItem {
            id: "o_one".to_string(),
            mailbox: "w33d@w33d.xyz".to_string(),
            batch_id: "ob_batch".to_string(),
            raw: "From: w33d@w33d.xyz\r\nTo: friend@example.com\r\nSubject: Scheduled\r\n\r\nbody"
                .to_string(),
            env_from: "w33d@w33d.xyz".to_string(),
            rcpts: vec!["friend@example.com".to_string()],
            to_domain: "example.com".to_string(),
            attempts: 0,
            next_at: now_secs(),
            send_at: now_secs() - 1,
            sent_copy_filed: false,
            status: "scheduled".to_string(),
        };

        store.enqueue_outbound(&item).await.unwrap();
        file_scheduled_sent_copy(&store, &item).await;
        file_scheduled_sent_copy(&store, &item).await;

        let sent = store
            .list_folder("w33d@w33d.xyz", "Sent", None, 10)
            .await
            .unwrap();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].subject, "Scheduled");
    }
}
