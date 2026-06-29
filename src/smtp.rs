//! ESMTP server: one state machine ([`Session`]) driven by both the inbound MTA listener and
//! the submission listener.
//!
//! [`Session::handle_line`] is a pure-ish protocol step (its only side effects are the async
//! store/enqueue performed when the terminating `.` of `DATA` arrives), so the whole state
//! machine — greeting, EHLO/HELO, MAIL/RCPT/DATA with dot-unstuffing, RSET/NOOP/QUIT, STARTTLS
//! advertisement, unknown-recipient 550 rejection, size/recipient limits — is exercised in
//! tests by feeding it command strings against an in-memory store, with NO sockets.
//!
//! Two roles share the machine:
//! - [`SmtpRole::Mta`] (inbound): accepts only local recipients, runs an ADVISORY SPF check on
//!   `MAIL FROM`, records it in a `Received-SPF` header, and STORES the message into the
//!   resolved mailbox(es).
//! - [`SmtpRole::Submission`] (outbound): accepts any recipient and, on `DATA`, DKIM-signs +
//!   enqueues the message for relay.
//!
//! The socket driver ([`serve_connection`]) shuttles bytes and performs the actual STARTTLS
//! upgrade (via the concrete [`SmtpStream`] enum), so it never recurses on stream type.

use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;

use crate::config::Config;
use crate::dkim::DkimSigner;
use crate::model::Message;
use crate::relay;
use crate::rfc822;
use crate::spf::{self, SpfResult};
use crate::store::Store;
use crate::util::{domain_of, email_date, message_id, new_id, now_secs, read_line};

/// Which listener a session belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SmtpRole {
    /// Inbound MTA: accept local recipients, store to mailbox.
    Mta,
    /// Submission: accept any recipient, DKIM-sign + enqueue for relay.
    Submission,
}

/// Shared dependencies for SMTP sessions.
pub struct SmtpContext {
    pub config: Arc<Config>,
    pub store: Arc<dyn Store>,
    pub signer: Option<Arc<DkimSigner>>,
    pub tls_acceptor: Option<TlsAcceptor>,
}

/// What the socket driver must do after sending a reply.
#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    /// Continue the session.
    None,
    /// Perform a STARTTLS upgrade, then reset to a fresh (TLS) session.
    StartTls,
    /// Send the reply and close (QUIT).
    Quit,
}

/// A protocol reply: optional text to write (empty during DATA accumulation) + a follow-up.
#[derive(Debug)]
pub struct Reply {
    pub text: String,
    pub action: Action,
}

impl Reply {
    fn say(text: impl Into<String>) -> Self {
        Reply { text: text.into(), action: Action::None }
    }
    fn silent() -> Self {
        Reply { text: String::new(), action: Action::None }
    }
}

/// Per-connection protocol state.
pub struct Session {
    ctx: Arc<SmtpContext>,
    role: SmtpRole,
    tls_active: bool,
    client_ip: Option<IpAddr>,
    helo: Option<String>,
    mail_from: Option<String>,
    spf: SpfResult,
    /// Resolved local mailbox(es) (MTA).
    rcpt_local: Vec<String>,
    /// Original recipient addresses (submission relay targets).
    rcpt_addrs: Vec<String>,
    in_data: bool,
    data: String,
    data_size: usize,
    data_overflow: bool,
}

impl Session {
    pub fn new(
        ctx: Arc<SmtpContext>,
        role: SmtpRole,
        tls_active: bool,
        client_ip: Option<IpAddr>,
    ) -> Self {
        Session {
            ctx,
            role,
            tls_active,
            client_ip,
            helo: None,
            mail_from: None,
            spf: SpfResult::None,
            rcpt_local: Vec::new(),
            rcpt_addrs: Vec::new(),
            in_data: false,
            data: String::new(),
            data_size: 0,
            data_overflow: false,
        }
    }

    /// The 220 greeting written immediately on connect.
    pub fn greeting(&self) -> String {
        format!("220 {} ESMTP Corvid\r\n", self.ctx.config.hostname)
    }

    fn reset_txn(&mut self) {
        self.mail_from = None;
        self.spf = SpfResult::None;
        self.rcpt_local.clear();
        self.rcpt_addrs.clear();
        self.in_data = false;
        self.data.clear();
        self.data_size = 0;
        self.data_overflow = false;
    }

    /// Process one input line, returning the reply + any follow-up action.
    pub async fn handle_line(&mut self, line: &str) -> Reply {
        if self.in_data {
            return self.handle_data_line(line).await;
        }

        let (cmd, arg) = match line.split_once(' ') {
            Some((c, a)) => (c.to_ascii_uppercase(), a.trim()),
            None => (line.trim().to_ascii_uppercase(), ""),
        };

        match cmd.as_str() {
            "EHLO" => self.cmd_ehlo(arg, true),
            "HELO" => self.cmd_ehlo(arg, false),
            "STARTTLS" => self.cmd_starttls(),
            "MAIL" => self.cmd_mail(arg).await,
            "RCPT" => self.cmd_rcpt(arg).await,
            "DATA" => self.cmd_data(),
            "RSET" => {
                self.reset_txn();
                Reply::say("250 2.0.0 Ok\r\n")
            }
            "NOOP" => Reply::say("250 2.0.0 Ok\r\n"),
            "VRFY" => Reply::say("252 2.1.5 Cannot VRFY user\r\n"),
            "EXPN" => Reply::say("502 5.5.1 EXPN not supported\r\n"),
            "HELP" => Reply::say("214 2.0.0 Corvid ESMTP\r\n"),
            "QUIT" => Reply {
                text: "221 2.0.0 Bye\r\n".to_string(),
                action: Action::Quit,
            },
            "" => Reply::say("500 5.5.2 Error: bad syntax\r\n"),
            _ => Reply::say(format!("500 5.5.2 Error: command \"{cmd}\" not recognized\r\n")),
        }
    }

    fn cmd_ehlo(&mut self, arg: &str, esmtp: bool) -> Reply {
        self.helo = Some(arg.to_string());
        self.reset_txn();
        let host = &self.ctx.config.hostname;
        if !esmtp {
            return Reply::say(format!("250 {host}\r\n"));
        }
        let mut lines = vec![
            format!("250-{host}"),
            "250-PIPELINING".to_string(),
            format!("250-SIZE {}", self.ctx.config.max_msg_size),
            "250-8BITMIME".to_string(),
            "250-ENHANCEDSTATUSCODES".to_string(),
        ];
        if self.ctx.tls_acceptor.is_some() && !self.tls_active {
            lines.push("250-STARTTLS".to_string());
        }
        lines.push("250 SMTPUTF8".to_string());
        Reply::say(lines.join("\r\n") + "\r\n")
    }

    fn cmd_starttls(&mut self) -> Reply {
        if self.ctx.tls_acceptor.is_none() {
            return Reply::say("454 4.7.0 TLS not available\r\n");
        }
        if self.tls_active {
            return Reply::say("503 5.5.1 TLS already active\r\n");
        }
        Reply {
            text: "220 2.0.0 Ready to start TLS\r\n".to_string(),
            action: Action::StartTls,
        }
    }

    async fn cmd_mail(&mut self, arg: &str) -> Reply {
        if self.helo.is_none() {
            return Reply::say("503 5.5.1 Error: send HELO/EHLO first\r\n");
        }
        if self.mail_from.is_some() {
            return Reply::say("503 5.5.1 Error: nested MAIL command\r\n");
        }
        let Some(addr) = extract_path(arg, "FROM") else {
            return Reply::say("501 5.5.4 Syntax: MAIL FROM:<address>\r\n");
        };

        // Advisory SPF (MTA only), skipped for loopback / non-IPv4 clients (tests/local inject).
        self.spf = match (self.role, self.client_ip) {
            (SmtpRole::Mta, Some(IpAddr::V4(ip))) if !ip.is_loopback() && !addr.is_empty() => {
                match domain_of(&addr) {
                    Some(d) => spf::check(&d, ip).await,
                    None => SpfResult::None,
                }
            }
            _ => SpfResult::None,
        };

        self.mail_from = Some(addr);
        Reply::say("250 2.1.0 Ok\r\n")
    }

    async fn cmd_rcpt(&mut self, arg: &str) -> Reply {
        if self.mail_from.is_none() {
            return Reply::say("503 5.5.1 Error: need MAIL before RCPT\r\n");
        }
        if self.rcpt_addrs.len() >= self.ctx.config.max_rcpts {
            return Reply::say("452 4.5.3 Too many recipients\r\n");
        }
        let Some(addr) = extract_path(arg, "TO") else {
            return Reply::say("501 5.5.4 Syntax: RCPT TO:<address>\r\n");
        };
        if addr.is_empty() {
            return Reply::say("501 5.1.3 Bad recipient address\r\n");
        }

        match self.role {
            SmtpRole::Mta => match self.ctx.config.resolve_local(&addr) {
                Some(mb) => {
                    if !self.rcpt_local.contains(&mb) {
                        self.rcpt_local.push(mb);
                    }
                    self.rcpt_addrs.push(addr);
                    Reply::say("250 2.1.5 Ok\r\n")
                }
                None => Reply::say("550 5.1.1 No such user here\r\n"),
            },
            SmtpRole::Submission => {
                if domain_of(&addr).is_none() {
                    return Reply::say("501 5.1.3 Bad recipient address\r\n");
                }
                self.rcpt_addrs.push(addr);
                Reply::say("250 2.1.5 Ok\r\n")
            }
        }
    }

    fn cmd_data(&mut self) -> Reply {
        if self.mail_from.is_none() {
            return Reply::say("503 5.5.1 Error: need MAIL command\r\n");
        }
        if self.rcpt_addrs.is_empty() {
            return Reply::say("503 5.5.1 Error: need RCPT command\r\n");
        }
        self.in_data = true;
        Reply::say("354 End data with <CR><LF>.<CR><LF>\r\n")
    }

    async fn handle_data_line(&mut self, line: &str) -> Reply {
        if line == "." {
            self.in_data = false;
            if self.data_overflow {
                self.reset_txn();
                return Reply::say("552 5.3.4 Message size exceeds limit\r\n");
            }
            let reply = self.finalize().await;
            self.reset_txn();
            return reply;
        }
        // Dot-unstuffing: a line starting with '.' had one prepended by the client.
        let content = line.strip_prefix('.').unwrap_or(line);
        self.data_size += content.len() + 2;
        if self.data_size > self.ctx.config.max_msg_size {
            self.data_overflow = true;
        } else {
            self.data.push_str(content);
            self.data.push_str("\r\n");
        }
        Reply::silent()
    }

    /// DATA complete: store (MTA) or DKIM-sign + enqueue (submission).
    async fn finalize(&mut self) -> Reply {
        match self.role {
            SmtpRole::Mta => self.deliver_inbound().await,
            SmtpRole::Submission => self.deliver_outbound().await,
        }
    }

    async fn deliver_inbound(&self) -> Reply {
        let id = new_id("m");
        let helo = self.helo.clone().unwrap_or_default();
        let ip = self.client_ip.map(|i| i.to_string()).unwrap_or_else(|| "unknown".to_string());
        let from = self.mail_from.clone().unwrap_or_default();
        let tls = if self.tls_active { "ESMTPS" } else { "ESMTP" };

        // Trace headers prepended to the stored source.
        let received = format!(
            "Received: from {helo} ([{ip}])\r\n\tby {host} with {tls} id {id};\r\n\t{date}\r\n",
            host = self.ctx.config.hostname,
            date = email_date(),
        );
        let spf_hdr = format!(
            "Received-SPF: {result} (corvid: SPF for {from} from {ip})\r\n",
            result = self.spf.token(),
        );
        let raw = format!("{received}{spf_hdr}{}", self.data);

        let parsed = rfc822::parse(&raw);
        let msg_to = if parsed.to.is_empty() {
            self.rcpt_addrs.join(", ")
        } else {
            parsed.to.clone()
        };

        for mb in &self.rcpt_local {
            let msg = Message {
                id: new_id("m"),
                mailbox: mb.clone(),
                msg_from: parsed.from.clone(),
                msg_to: msg_to.clone(),
                subject: parsed.subject.clone(),
                raw_rfc822: raw.clone(),
                body_text: parsed.body_text.clone(),
                body_html: parsed.body_html.clone(),
                received_at: now_secs(),
                seen: false,
                folder: "INBOX".to_string(),
            };
            if let Err(e) = self.ctx.store.store_message(&msg).await {
                tracing::error!(error = %e, "inbound store failed");
                return Reply::say("451 4.3.0 Temporary storage failure\r\n");
            }
        }
        Reply::say(format!("250 2.0.0 Ok: queued as {id}\r\n"))
    }

    async fn deliver_outbound(&self) -> Reply {
        let env_from = self.mail_from.clone().unwrap_or_default();
        // Ensure Date/Message-ID exist so the signed headers are present.
        let mut raw = self.data.clone();
        raw = ensure_header(&raw, "Date", &email_date());
        raw = ensure_header(&raw, "Message-ID", &message_id(&self.ctx.config.mail_domain));

        let signer = self.ctx.signer.as_deref();
        match relay::enqueue_outbound(self.ctx.store.as_ref(), signer, &raw, &env_from, &self.rcpt_addrs)
            .await
        {
            Ok(_) => Reply::say("250 2.0.0 Ok: message accepted for delivery\r\n"),
            Err(e) => {
                tracing::error!(error = %e, "submission enqueue failed");
                Reply::say("451 4.3.0 Temporary failure, try again later\r\n")
            }
        }
    }
}

/// Parse `FROM:<addr>` / `TO:<addr>` (case-insensitive keyword), tolerating trailing ESMTP
/// params (`SIZE=`, `BODY=`). Returns the bare address (`""` for the null sender `<>`).
fn extract_path(arg: &str, keyword: &str) -> Option<String> {
    let arg = arg.trim();
    let upper = arg.to_ascii_uppercase();
    let kw = format!("{keyword}:");
    let rest = upper.strip_prefix(&kw).map(|_| &arg[kw.len()..])?;
    let rest = rest.trim_start();
    if let Some(start) = rest.find('<') {
        let end = rest[start + 1..].find('>')? + start + 1;
        return Some(rest[start + 1..end].trim().to_string());
    }
    // No angle brackets: take the first whitespace-delimited token.
    Some(rest.split_whitespace().next().unwrap_or("").to_string())
}

/// If `name` is absent from the header block, inject `name: value` at the top.
fn ensure_header(raw: &str, name: &str, value: &str) -> String {
    let (headers, _) = rfc822::split_headers_body(raw);
    let present = rfc822::parse_headers(headers)
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case(&name.to_ascii_lowercase()));
    if present {
        raw.to_string()
    } else {
        format!("{name}: {value}\r\n{raw}")
    }
}

// ---------------------------------------------------------------------------
// Socket driver
// ---------------------------------------------------------------------------

/// Plain TCP or TLS-upgraded stream. Concrete (no generics) so STARTTLS replaces `self` without
/// any stream-type recursion.
pub enum SmtpStream {
    Plain(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
}

impl AsyncRead for SmtpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            SmtpStream::Plain(s) => Pin::new(s).poll_read(cx, buf),
            SmtpStream::Tls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for SmtpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            SmtpStream::Plain(s) => Pin::new(s).poll_write(cx, buf),
            SmtpStream::Tls(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            SmtpStream::Plain(s) => Pin::new(s).poll_flush(cx),
            SmtpStream::Tls(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            SmtpStream::Plain(s) => Pin::new(s).poll_shutdown(cx),
            SmtpStream::Tls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

/// Bind `addr` and serve SMTP sessions for `role` until the process exits.
pub async fn run_listener(
    addr: &str,
    ctx: Arc<SmtpContext>,
    role: SmtpRole,
) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    let what = match role {
        SmtpRole::Mta => "inbound MTA",
        SmtpRole::Submission => "submission",
    };
    tracing::info!(%addr, role = what, "Corvid SMTP listening");
    loop {
        let (stream, peer) = listener.accept().await?;
        let ctx = ctx.clone();
        tokio::spawn(async move {
            if let Err(e) = serve_connection(stream, Some(peer.ip()), ctx, role).await {
                tracing::debug!(error = %e, "smtp session ended");
            }
        });
    }
}

/// Drive a single connection: greeting, then feed lines to the [`Session`], performing the
/// STARTTLS upgrade in place when requested.
pub async fn serve_connection(
    stream: TcpStream,
    client_ip: Option<IpAddr>,
    ctx: Arc<SmtpContext>,
    role: SmtpRole,
) -> std::io::Result<()> {
    let _ = stream.set_nodelay(true);
    let mut s = SmtpStream::Plain(stream);
    let mut sess = Session::new(ctx.clone(), role, false, client_ip);
    let mut leftover: Vec<u8> = Vec::new();

    s.write_all(sess.greeting().as_bytes()).await?;
    s.flush().await?;

    let max_line = ctx.config.max_msg_size.max(1024);
    loop {
        let Some(line) = read_line(&mut s, &mut leftover, max_line).await? else {
            break; // client disconnected
        };
        let reply = sess.handle_line(&line).await;
        if !reply.text.is_empty() {
            s.write_all(reply.text.as_bytes()).await?;
            s.flush().await?;
        }
        match reply.action {
            Action::None => {}
            Action::Quit => break,
            Action::StartTls => {
                let Some(acceptor) = ctx.tls_acceptor.clone() else {
                    break;
                };
                let plain = match s {
                    SmtpStream::Plain(t) => t,
                    SmtpStream::Tls(_) => break, // unreachable: STARTTLS rejected when active
                };
                let tls = acceptor.accept(plain).await?;
                s = SmtpStream::Tls(Box::new(tls));
                // Fresh session over TLS; client re-issues EHLO. No new greeting per RFC 3207.
                sess = Session::new(ctx.clone(), role, true, client_ip);
                leftover.clear();
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_path_variants() {
        assert_eq!(extract_path("FROM:<a@b.com>", "FROM").as_deref(), Some("a@b.com"));
        assert_eq!(extract_path("from:<a@b.com> SIZE=10", "FROM").as_deref(), Some("a@b.com"));
        assert_eq!(extract_path("TO:<w33d@w33d.xyz>", "TO").as_deref(), Some("w33d@w33d.xyz"));
        assert_eq!(extract_path("FROM:<>", "FROM").as_deref(), Some(""));
        assert!(extract_path("TO:<x>", "FROM").is_none());
    }

    #[test]
    fn ensure_header_injects_when_absent() {
        let raw = "From: a@b\r\n\r\nbody";
        let out = ensure_header(raw, "Date", "now");
        assert!(out.starts_with("Date: now\r\n"));
        let out2 = ensure_header(&out, "Date", "later");
        assert_eq!(out2, out, "existing Date is not duplicated");
    }
}
