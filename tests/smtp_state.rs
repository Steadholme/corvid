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

#[tokio::test]
async fn submission_accepts_external_recipient_and_enqueues() {
    let ctx = ctx().await;
    let mut s = Session::new(ctx.clone(), SmtpRole::Submission, false, None);
    s.handle_line("EHLO client").await;
    assert!(s.handle_line("MAIL FROM:<w33d@w33d.xyz>").await.text.starts_with("250"));
    // Submission relays anywhere.
    assert!(s.handle_line("RCPT TO:<friend@elsewhere.net>").await.text.starts_with("250"));
    assert!(s.handle_line("DATA").await.text.starts_with("354"));
    for line in ["From: w33d@w33d.xyz", "Subject: Out", "", "hi"] {
        s.handle_line(line).await;
    }
    assert!(s.handle_line(".").await.text.starts_with("250"));

    let due = ctx.store.due_outbound(corvid::now_secs() + 5, 10).await.unwrap();
    assert_eq!(due.len(), 1);
    assert_eq!(due[0].to_domain, "elsewhere.net");
    assert_eq!(due[0].rcpts, vec!["friend@elsewhere.net".to_string()]);
}
