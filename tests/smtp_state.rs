//! SMTP state-machine test: drives [`corvid::smtp::Session`] directly with command strings
//! (no sockets), asserting the ESMTP flow EHLO/MAIL/RCPT/DATA, unknown-recipient 550 rejection,
//! out-of-sequence errors, and that a valid inbound message is parsed + stored.

use std::sync::Arc;

use corvid::config::Config;
use corvid::model::Mailbox;
use corvid::smtp::{Action, Session, SmtpContext, SmtpRole};
use corvid::store::{InMemoryStore, Store};

async fn ctx() -> Arc<SmtpContext> {
    let config = Arc::new(Config::dev());
    let store = Arc::new(InMemoryStore::new());
    store
        .upsert_mailbox(&Mailbox {
            addr: "w33d@w33d.xyz".to_string(),
            owner_sub: "w33d".to_string(),
            expires_at: 0,
        })
        .await
        .unwrap();
    Arc::new(SmtpContext {
        config,
        store,
        signer: None,
        tls_acceptor: None,
    })
}

#[tokio::test]
async fn full_inbound_flow_stores_message() {
    let ctx = ctx().await;
    let mut s = Session::new(ctx.clone(), SmtpRole::Mta, false, None);

    assert!(s.greeting().starts_with("220 "));

    let ehlo = s.handle_line("EHLO client.example.com").await;
    assert!(ehlo.text.starts_with("250-mail.w33d.xyz"));
    assert!(ehlo.text.contains("SIZE"));
    // No TLS acceptor configured -> STARTTLS must NOT be advertised.
    assert!(!ehlo.text.contains("STARTTLS"));

    // RCPT before MAIL is out of sequence.
    let early = s.handle_line("RCPT TO:<w33d@w33d.xyz>").await;
    assert!(early.text.starts_with("503"));

    let mail = s.handle_line("MAIL FROM:<alice@example.com>").await;
    assert!(mail.text.starts_with("250"));

    // Unknown local recipient is rejected with 550.
    let bad = s.handle_line("RCPT TO:<nobody@w33d.xyz>").await;
    assert!(bad.text.starts_with("550"), "got: {}", bad.text);

    // A foreign domain is also rejected by the inbound MTA.
    let foreign = s.handle_line("RCPT TO:<x@example.org>").await;
    assert!(foreign.text.starts_with("550"));

    // A known alias is accepted.
    let good = s.handle_line("RCPT TO:<postmaster@w33d.xyz>").await;
    assert!(good.text.starts_with("250"));

    let data = s.handle_line("DATA").await;
    assert!(data.text.starts_with("354"));

    for line in [
        "From: Alice <alice@example.com>",
        "To: postmaster@w33d.xyz",
        "Subject: Hello Corvid",
        "",
        "This is the body.",
        ".stuffed line keeps its dot after unstuffing",
    ] {
        let r = s.handle_line(line).await;
        assert!(r.text.is_empty(), "DATA lines produce no reply");
        assert_eq!(r.action, Action::None);
    }

    let done = s.handle_line(".").await;
    assert!(done.text.starts_with("250"), "got: {}", done.text);

    // The message was stored into the primary mailbox.
    let msgs = ctx.store.list_messages("w33d@w33d.xyz", 10).await.unwrap();
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0].subject, "Hello Corvid");
    assert!(msgs[0].msg_from.contains("alice@example.com"));

    let full = ctx.store.get_message(&msgs[0].id).await.unwrap().unwrap();
    assert!(full.body_text.contains("This is the body."));
    assert!(full.raw_rfc822.contains("Received-SPF:"));
    assert_eq!(full.folder, "INBOX");
    assert!(!full.seen);
}

#[tokio::test]
async fn temporary_domains_accept_only_provisioned_full_addresses() {
    let mut config = Config::dev();
    config.temp_mail_domains = vec!["mx.w33d.xyz".to_string()];
    let store = Arc::new(InMemoryStore::new());
    let provisioned = "g0123456789abcdef01234567@mx.w33d.xyz";
    store
        .upsert_mailbox(&Mailbox {
            addr: provisioned.to_string(),
            owner_sub: format!("temp:{provisioned}"),
            expires_at: 0,
        })
        .await
        .unwrap();
    let non_api_mailbox = "g111111111111111111111111@mx.w33d.xyz";
    store
        .upsert_mailbox(&Mailbox {
            addr: non_api_mailbox.to_string(),
            owner_sub: "ordinary-owner".to_string(),
            expires_at: 0,
        })
        .await
        .unwrap();
    let ctx = Arc::new(SmtpContext {
        config: Arc::new(config),
        store,
        signer: None,
        tls_acceptor: None,
    });
    let mut session = Session::new(ctx, SmtpRole::Mta, false, None);
    session.handle_line("EHLO client.example.com").await;
    session.handle_line("MAIL FROM:<alice@example.com>").await;

    let unknown = session
        .handle_line("RCPT TO:<gffffffffffffffffffffffff@mx.w33d.xyz>")
        .await;
    assert!(unknown.text.starts_with("550"), "got: {}", unknown.text);

    let not_api_provisioned = session
        .handle_line(&format!("RCPT TO:<{non_api_mailbox}>"))
        .await;
    assert!(
        not_api_provisioned.text.starts_with("550"),
        "got: {}",
        not_api_provisioned.text
    );

    let known = session
        .handle_line(&format!("RCPT TO:<{}>", provisioned.to_ascii_uppercase()))
        .await;
    assert!(known.text.starts_with("250"), "got: {}", known.text);
}

#[tokio::test]
async fn unknown_command_and_quit() {
    let ctx = ctx().await;
    let mut s = Session::new(ctx, SmtpRole::Mta, false, None);
    s.handle_line("EHLO x").await;
    let bad = s.handle_line("FROBNICATE now").await;
    assert!(bad.text.starts_with("500"));
    let quit = s.handle_line("QUIT").await;
    assert!(quit.text.starts_with("221"));
    assert_eq!(quit.action, Action::Quit);
}

/// A submission context with a configured credential (user = primary mailbox, pass = `s3cret`).
async fn submission_ctx() -> Arc<SmtpContext> {
    let mut config = Config::dev();
    config.submission_password = "s3cret".to_string(); // SUBMISSION_USER unset -> w33d@w33d.xyz
    Arc::new(SmtpContext {
        config: Arc::new(config),
        store: Arc::new(InMemoryStore::new()),
        signer: None,
        tls_acceptor: None,
    })
}

// SASL base64 vectors (see the SUBMISSION_* credential above).
const PLAIN_OK: &str = "AHczM2RAdzMzZC54eXoAczNjcmV0"; // \0 w33d@w33d.xyz \0 s3cret
const PLAIN_BAD: &str = "AHczM2RAdzMzZC54eXoAd3JvbmdwYXNz"; // wrong password
const LOGIN_USER: &str = "dzMzZEB3MzNkLnh5eg=="; // w33d@w33d.xyz
const LOGIN_PASS: &str = "czNjcmV0"; // s3cret

#[tokio::test]
async fn submission_requires_auth_before_mail() {
    let ctx = submission_ctx().await;
    // tls_active = true simulates a post-STARTTLS channel.
    let mut s = Session::new(ctx.clone(), SmtpRole::Submission, true, None);
    let ehlo = s.handle_line("EHLO client").await;
    assert!(ehlo.text.contains("AUTH PLAIN LOGIN"), "AUTH advertised: {}", ehlo.text);

    // MAIL before AUTH is refused — this is the closed relay.
    let early = s.handle_line("MAIL FROM:<w33d@w33d.xyz>").await;
    assert!(early.text.starts_with("530"), "got: {}", early.text);

    // AUTH PLAIN with the correct credential succeeds, then relay is allowed.
    let auth = s.handle_line(&format!("AUTH PLAIN {PLAIN_OK}")).await;
    assert!(auth.text.starts_with("235"), "got: {}", auth.text);
    assert!(s.handle_line("MAIL FROM:<w33d@w33d.xyz>").await.text.starts_with("250"));
    assert!(s.handle_line("RCPT TO:<friend@elsewhere.net>").await.text.starts_with("250"));
    assert!(s.handle_line("DATA").await.text.starts_with("354"));
    for line in ["From: w33d@w33d.xyz", "Subject: Out", "", "hi"] {
        s.handle_line(line).await;
    }
    assert!(s.handle_line(".").await.text.starts_with("250"));

    let due = ctx.store.due_outbound(corvid::now_secs() + 5, 10).await.unwrap();
    assert_eq!(due.len(), 1);
    assert_eq!(due[0].to_domain, "elsewhere.net");
}

#[tokio::test]
async fn submission_auth_login_multistep() {
    let ctx = submission_ctx().await;
    let mut s = Session::new(ctx, SmtpRole::Submission, true, None);
    s.handle_line("EHLO client").await;
    // AUTH LOGIN drives a two-prompt exchange.
    let p1 = s.handle_line("AUTH LOGIN").await;
    assert_eq!(p1.text, "334 VXNlcm5hbWU6\r\n"); // base64("Username:")
    let p2 = s.handle_line(LOGIN_USER).await;
    assert_eq!(p2.text, "334 UGFzc3dvcmQ6\r\n"); // base64("Password:")
    let done = s.handle_line(LOGIN_PASS).await;
    assert!(done.text.starts_with("235"), "got: {}", done.text);
    assert!(s.handle_line("MAIL FROM:<w33d@w33d.xyz>").await.text.starts_with("250"));
}

#[tokio::test]
async fn submission_auth_rejected_on_plaintext_and_bad_password() {
    let ctx = submission_ctx().await;

    // Over a plaintext channel (tls_active = false), AUTH must be refused (538) and never
    // advertised — credentials never cross the wire in the clear.
    let mut plain = Session::new(ctx.clone(), SmtpRole::Submission, false, None);
    let ehlo = plain.handle_line("EHLO c").await;
    assert!(!ehlo.text.contains("AUTH"), "no AUTH advertised without TLS: {}", ehlo.text);
    assert!(plain.handle_line(&format!("AUTH PLAIN {PLAIN_OK}")).await.text.starts_with("538"));

    // Over TLS, a wrong password is rejected (535) and leaves the session unauthenticated.
    let mut s = Session::new(ctx, SmtpRole::Submission, true, None);
    s.handle_line("EHLO c").await;
    assert!(s.handle_line(&format!("AUTH PLAIN {PLAIN_BAD}")).await.text.starts_with("535"));
    assert!(s.handle_line("MAIL FROM:<w33d@w33d.xyz>").await.text.starts_with("530"));
}

#[tokio::test]
async fn submission_fail_secure_when_no_credential() {
    // Default dev config has an empty submission_password -> relay is closed even over TLS.
    let ctx = ctx().await;
    let mut s = Session::new(ctx, SmtpRole::Submission, true, None);
    let ehlo = s.handle_line("EHLO c").await;
    assert!(!ehlo.text.contains("AUTH"), "unconfigured deployment advertises no AUTH");
    assert!(s.handle_line(&format!("AUTH PLAIN {PLAIN_OK}")).await.text.starts_with("535"));
    assert!(s.handle_line("MAIL FROM:<w33d@w33d.xyz>").await.text.starts_with("530"));
}
