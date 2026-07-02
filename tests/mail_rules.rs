//! Mail-productivity trio tests: delivery-time filter rules (driven through the real SMTP
//! [`corvid::smtp::Session`], no sockets), the compose signature prefill, the auto-reply
//! (vacation) responder with its guards, and the `/settings` UI round-trips (in-process axum,
//! in-memory store — no database).

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use tower::ServiceExt;

use corvid::config::Config;
use corvid::model::{FilterRule, Mailbox};
use corvid::smtp::{Session, SmtpContext, SmtpRole};
use corvid::store::{InMemoryStore, Store};
use corvid::{app, build_dev_state, new_id, now_secs, AppState};

const MAILBOX: &str = "w33d@w33d.xyz";

async fn ctx() -> Arc<SmtpContext> {
    let config = Arc::new(Config::dev());
    let store = Arc::new(InMemoryStore::new());
    store
        .upsert_mailbox(&Mailbox {
            addr: MAILBOX.to_string(),
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

fn rule(field: &str, op: &str, needle: &str, action: &str, folder: Option<&str>) -> FilterRule {
    FilterRule {
        id: new_id("fr"),
        mailbox: MAILBOX.to_string(),
        position: 1,
        field: field.to_string(),
        op: op.to_string(),
        needle: needle.to_string(),
        action: action.to_string(),
        target_folder: folder.map(str::to_string),
        target_label: None,
        enabled: true,
        created_at: now_secs(),
    }
}

/// Drive one full inbound SMTP delivery (EHLO/MAIL/RCPT/DATA/.) into the primary mailbox,
/// asserting the server accepts it with 250.
async fn deliver(ctx: &Arc<SmtpContext>, env_from: &str, data_lines: &[&str]) {
    let mut s = Session::new(ctx.clone(), SmtpRole::Mta, false, None);
    s.handle_line("EHLO client.example.com").await;
    assert!(s
        .handle_line(&format!("MAIL FROM:<{env_from}>"))
        .await
        .text
        .starts_with("250"));
    assert!(s
        .handle_line("RCPT TO:<w33d@w33d.xyz>")
        .await
        .text
        .starts_with("250"));
    assert!(s.handle_line("DATA").await.text.starts_with("354"));
    for line in data_lines {
        s.handle_line(line).await;
    }
    let done = s.handle_line(".").await;
    assert!(
        done.text.starts_with("250"),
        "delivery accepted: {}",
        done.text
    );
}

// ---------------------------------------------------------------------------
// Filter rules at delivery time
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rule_moves_matching_mail_into_folder_at_delivery() {
    let ctx = ctx().await;
    ctx.store
        .add_rule(&rule(
            "from",
            "contains",
            "alice@example.com",
            "move",
            Some("Archive"),
        ))
        .await
        .unwrap();

    deliver(
        &ctx,
        "alice@example.com",
        &[
            "From: Alice <alice@example.com>",
            "Subject: Filed",
            "",
            "body",
        ],
    )
    .await;
    deliver(
        &ctx,
        "bob@example.com",
        &["From: bob@example.com", "Subject: Untouched", "", "body"],
    )
    .await;

    let archived = ctx
        .store
        .list_folder(MAILBOX, "Archive", None, 10)
        .await
        .unwrap();
    assert_eq!(archived.len(), 1, "matching mail delivered into Archive");
    assert_eq!(archived[0].subject, "Filed");
    let inbox = ctx
        .store
        .list_folder(MAILBOX, "INBOX", None, 10)
        .await
        .unwrap();
    assert_eq!(inbox.len(), 1, "non-matching mail stays in the Inbox");
    assert_eq!(inbox[0].subject, "Untouched");
}

#[tokio::test]
async fn rules_apply_in_position_order_first_match_wins() {
    let ctx = ctx().await;
    // Both rules match the same mail; the LOWER position must win (star, not move).
    let mut star = rule("subject", "contains", "report", "star", None);
    star.position = 1;
    let mut mv = rule("from", "contains", "example.com", "move", Some("Trash"));
    mv.position = 2;
    ctx.store.add_rule(&mv).await.unwrap();
    ctx.store.add_rule(&star).await.unwrap();

    deliver(
        &ctx,
        "alice@example.com",
        &[
            "From: alice@example.com",
            "Subject: Weekly Report",
            "",
            "body",
        ],
    )
    .await;

    let inbox = ctx
        .store
        .list_folder(MAILBOX, "INBOX", None, 10)
        .await
        .unwrap();
    assert_eq!(
        inbox.len(),
        1,
        "first match (star) wins — the move rule never runs"
    );
    assert!(inbox[0].starred, "star rule applied");
    assert!(ctx
        .store
        .list_folder(MAILBOX, "Trash", None, 10)
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn discard_rule_drops_silently_and_disabled_rules_are_skipped() {
    let ctx = ctx().await;
    ctx.store
        .add_rule(&rule("subject", "equals", "spam offer", "discard", None))
        .await
        .unwrap();
    let mut off = rule("from", "contains", "carol", "discard", None);
    off.enabled = false;
    ctx.store.add_rule(&off).await.unwrap();

    // The SMTP client still sees 250 (silent drop), but nothing is stored.
    deliver(
        &ctx,
        "spammer@junk.example",
        &[
            "From: spammer@junk.example",
            "Subject: SPAM OFFER",
            "",
            "buy now",
        ],
    )
    .await;
    assert_eq!(
        ctx.store.message_count(MAILBOX).await.unwrap(),
        0,
        "discarded, never stored"
    );

    // A disabled rule never fires — carol's mail is delivered normally.
    deliver(
        &ctx,
        "carol@example.com",
        &["From: carol@example.com", "Subject: hello", "", "hi"],
    )
    .await;
    assert_eq!(ctx.store.message_count(MAILBOX).await.unwrap(), 1);
}

#[tokio::test]
async fn markread_rule_presets_seen_flag() {
    let ctx = ctx().await;
    ctx.store
        .add_rule(&rule("to", "contains", "w33d@", "markread", None))
        .await
        .unwrap();
    deliver(
        &ctx,
        "a@b.com",
        &[
            "From: a@b.com",
            "To: w33d@w33d.xyz",
            "Subject: fyi",
            "",
            "x",
        ],
    )
    .await;
    let msgs = ctx.store.list_messages(MAILBOX, 10).await.unwrap();
    assert_eq!(msgs.len(), 1);
    assert!(msgs[0].seen, "delivered pre-marked read");
    assert_eq!(ctx.store.unseen_count(MAILBOX).await.unwrap(), 0);
}

// ---------------------------------------------------------------------------
// Auto-reply (vacation)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn auto_reply_queues_once_per_sender_per_24h() {
    let ctx = ctx().await;
    ctx.store
        .set_auto_reply(MAILBOX, true, "Out of office", "Back next week.", 0)
        .await
        .unwrap();

    deliver(
        &ctx,
        "alice@example.com",
        &["From: alice@example.com", "Subject: ping", "", "x"],
    )
    .await;
    let due = ctx.store.due_outbound(now_secs() + 5, 10).await.unwrap();
    assert_eq!(
        due.len(),
        1,
        "one auto-reply queued via the existing outbound path"
    );
    assert_eq!(due[0].to_domain, "example.com");
    assert_eq!(due[0].rcpts, vec!["alice@example.com".to_string()]);
    assert_eq!(
        due[0].env_from, "",
        "null envelope sender (RFC 3834) prevents loops"
    );
    assert!(due[0].raw.contains("Subject: Out of office"));
    assert!(due[0].raw.contains("Auto-Submitted: auto-replied"));
    assert!(due[0].raw.contains("Back next week."));

    // Same sender again within 24h -> deduped, still exactly one queued item.
    deliver(
        &ctx,
        "alice@example.com",
        &["From: alice@example.com", "Subject: ping2", "", "x"],
    )
    .await;
    assert_eq!(
        ctx.store
            .due_outbound(now_secs() + 5, 10)
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        ctx.store.message_count(MAILBOX).await.unwrap(),
        2,
        "both messages delivered"
    );

    // A different sender gets their own auto-reply.
    deliver(
        &ctx,
        "bob@example.com",
        &["From: bob@example.com", "Subject: hi", "", "x"],
    )
    .await;
    assert_eq!(
        ctx.store
            .due_outbound(now_secs() + 5, 10)
            .await
            .unwrap()
            .len(),
        2
    );
}

#[tokio::test]
async fn auto_reply_suppressed_for_bulk_and_auto_mail() {
    let ctx = ctx().await;
    ctx.store
        .set_auto_reply(MAILBOX, true, "OOO", "away", 0)
        .await
        .unwrap();

    deliver(
        &ctx,
        "list@example.com",
        &[
            "From: list@example.com",
            "Precedence: bulk",
            "Subject: digest",
            "",
            "x",
        ],
    )
    .await;
    deliver(
        &ctx,
        "dev@example.com",
        &[
            "From: dev@example.com",
            "List-Id: <dev.lists.example.com>",
            "Subject: [dev] thread",
            "",
            "x",
        ],
    )
    .await;
    deliver(
        &ctx,
        "bot@example.com",
        &[
            "From: bot@example.com",
            "Auto-Submitted: auto-generated",
            "Subject: notification",
            "",
            "x",
        ],
    )
    .await;
    // Own address: no vacation echo to ourselves.
    deliver(
        &ctx,
        "w33d@w33d.xyz",
        &["From: w33d@w33d.xyz", "Subject: self", "", "x"],
    )
    .await;
    // Empty return-path (a bounce): never answered.
    deliver(
        &ctx,
        "",
        &[
            "From: mailer-daemon@example.com",
            "Subject: bounce",
            "",
            "x",
        ],
    )
    .await;

    assert!(
        ctx.store
            .due_outbound(now_secs() + 5, 10)
            .await
            .unwrap()
            .is_empty(),
        "no auto-reply for bulk/list/auto/self/null-path mail"
    );
    assert_eq!(
        ctx.store.message_count(MAILBOX).await.unwrap(),
        5,
        "all mail still delivered"
    );
}

#[tokio::test]
async fn auto_reply_honours_expiry_and_disabled_state() {
    let ctx = ctx().await;

    // Disabled (default) -> nothing queued.
    deliver(
        &ctx,
        "a@example.com",
        &["From: a@example.com", "Subject: 1", "", "x"],
    )
    .await;
    assert!(ctx
        .store
        .due_outbound(now_secs() + 5, 10)
        .await
        .unwrap()
        .is_empty());

    // Enabled but expired -> nothing queued.
    ctx.store
        .set_auto_reply(MAILBOX, true, "OOO", "away", now_secs() - 10)
        .await
        .unwrap();
    deliver(
        &ctx,
        "b@example.com",
        &["From: b@example.com", "Subject: 2", "", "x"],
    )
    .await;
    assert!(ctx
        .store
        .due_outbound(now_secs() + 5, 10)
        .await
        .unwrap()
        .is_empty());

    // Enabled with a future expiry -> queued.
    ctx.store
        .set_auto_reply(MAILBOX, true, "OOO", "away", now_secs() + 3600)
        .await
        .unwrap();
    deliver(
        &ctx,
        "c@example.com",
        &["From: c@example.com", "Subject: 3", "", "x"],
    )
    .await;
    assert_eq!(
        ctx.store
            .due_outbound(now_secs() + 5, 10)
            .await
            .unwrap()
            .len(),
        1
    );
}

// ---------------------------------------------------------------------------
// Signature prefill + settings UI
// ---------------------------------------------------------------------------

async fn body_string(resp: axum::response::Response) -> String {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

/// Mint a CSRF cookie+token from `GET /settings`, returning `(token, cookie_header_value)`.
async fn mint_csrf(state: &AppState) -> (String, String) {
    let req = Request::builder()
        .uri("/settings")
        .header("x-auth-subject", "w33d")
        .body(Body::empty())
        .unwrap();
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    let set_cookie = resp
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .expect("settings sets a CSRF cookie");
    let token = set_cookie
        .split(';')
        .next()
        .and_then(|kv| kv.split_once('='))
        .map(|(_, v)| v.to_string())
        .unwrap();
    (token.clone(), format!("__Host-csrf={token}"))
}

#[tokio::test]
async fn signature_prefills_compose_and_reply() {
    let state = build_dev_state().await;
    state
        .store
        .set_signature(MAILBOX, "Cheers,\nw33d")
        .await
        .unwrap();

    // Blank compose: the body starts with the signature block.
    let req = Request::builder()
        .uri("/compose")
        .header("x-auth-subject", "w33d")
        .body(Body::empty())
        .unwrap();
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let html = body_string(resp).await;
    assert!(
        html.contains("\n\n--\nCheers,\nw33d"),
        "compose prefilled with signature"
    );

    // Reply: the signature follows the quoted original.
    let msg = corvid::model::Message {
        id: new_id("m"),
        mailbox: MAILBOX.to_string(),
        msg_from: "alice@example.com".to_string(),
        msg_to: MAILBOX.to_string(),
        subject: "Hi".to_string(),
        raw_rfc822: "From: alice@example.com\r\nSubject: Hi\r\n\r\nOriginal line".to_string(),
        body_text: "Original line".to_string(),
        body_html: String::new(),
        received_at: now_secs(),
        seen: false,
        folder: "INBOX".to_string(),
        starred: false,
        snooze_until: 0,
        muted: false,
        thread_id: String::new(),
        message_id: String::new(),
    };
    state.store.store_message(&msg).await.unwrap();
    let req = Request::builder()
        .uri(format!("/compose?reply={}", msg.id))
        .header("x-auth-subject", "w33d")
        .body(Body::empty())
        .unwrap();
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    let html = body_string(resp).await;
    assert!(
        html.contains("&gt; Original line"),
        "quoted original present"
    );
    assert!(
        html.contains("--\nCheers,\nw33d"),
        "signature appended to the reply draft"
    );

    // No signature -> no delimiter block.
    state.store.set_signature(MAILBOX, "").await.unwrap();
    let req = Request::builder()
        .uri("/compose")
        .header("x-auth-subject", "w33d")
        .body(Body::empty())
        .unwrap();
    let html = body_string(app(state.clone()).oneshot(req).await.unwrap()).await;
    assert!(!html.contains("\n\n--\n"), "empty signature adds nothing");
}

#[tokio::test]
async fn settings_page_renders_core_sections() {
    let state = build_dev_state().await;
    let req = Request::builder()
        .uri("/settings")
        .header("x-auth-subject", "w33d")
        .body(Body::empty())
        .unwrap();
    let resp = app(state).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let html = body_string(resp).await;
    assert!(html.contains("Filter rules"));
    assert!(html.contains("Undo send"));
    assert!(html.contains(r#"action="/settings/undo-send""#));
    assert!(html.contains("Templates"));
    assert!(html.contains(r#"action="/settings/templates""#));
    assert!(html.contains("Signature"));
    assert!(html.contains("Auto-reply (vacation)"));
    assert!(html.contains("No filter rules yet"), "empty state rendered");
}

#[tokio::test]
async fn settings_rules_add_reorder_toggle_delete_roundtrip() {
    let state = build_dev_state().await;
    let (token, cookie) = mint_csrf(&state).await;
    let post = |form: String, cookie: String| {
        Request::builder()
            .method("POST")
            .uri("/settings/rules")
            .header("x-auth-subject", "w33d")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::COOKIE, cookie)
            .body(Body::from(form))
            .unwrap()
    };

    // Add two rules (the second one a Move with a target folder).
    let form = format!("csrf={token}&field=from&op=contains&needle=alice&action=star");
    let resp = app(state.clone())
        .oneshot(post(form, cookie.clone()))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER, "rule added");
    let form =
        format!("csrf={token}&field=subject&op=equals&needle=digest&action=move&folder=Archive");
    app(state.clone())
        .oneshot(post(form, cookie.clone()))
        .await
        .unwrap();

    let rules = state.store.list_rules(MAILBOX).await.unwrap();
    assert_eq!(rules.len(), 2);
    assert_eq!(rules[0].needle, "alice");
    assert_eq!(rules[1].action, "move");
    assert_eq!(rules[1].target_folder.as_deref(), Some("Archive"));

    // A Move rule without a real target folder is rejected.
    let form = format!("csrf={token}&field=from&op=contains&needle=x&action=move&folder=Starred");
    let resp = app(state.clone())
        .oneshot(post(form, cookie.clone()))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // Reorder: move the second rule up — it becomes first.
    let second = rules[1].id.clone();
    let form = format!("csrf={token}&cmd=up&id={second}");
    app(state.clone())
        .oneshot(post(form, cookie.clone()))
        .await
        .unwrap();
    let rules = state.store.list_rules(MAILBOX).await.unwrap();
    assert_eq!(rules[0].id, second, "moved to the top");

    // Disable, then delete.
    let form = format!("csrf={token}&cmd=disable&id={second}");
    app(state.clone())
        .oneshot(post(form, cookie.clone()))
        .await
        .unwrap();
    assert!(!state.store.list_rules(MAILBOX).await.unwrap()[0].enabled);
    let form = format!("csrf={token}&cmd=delete&id={second}");
    app(state.clone())
        .oneshot(post(form, cookie.clone()))
        .await
        .unwrap();
    assert_eq!(state.store.list_rules(MAILBOX).await.unwrap().len(), 1);

    // Without a CSRF token every mutation is refused.
    let form = "field=from&op=contains&needle=x&action=star&csrf=".to_string();
    let resp = app(state.clone())
        .oneshot(post(form, cookie.clone()))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn settings_signature_and_autoreply_forms_persist() {
    let state = build_dev_state().await;
    let (token, cookie) = mint_csrf(&state).await;

    let req = Request::builder()
        .method("POST")
        .uri("/settings/signature")
        .header("x-auth-subject", "w33d")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, cookie.clone())
        .body(Body::from(format!(
            "csrf={token}&signature=Regards%2C%0Aw33d"
        )))
        .unwrap();
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        state.store.get_settings(MAILBOX).await.unwrap().signature,
        "Regards,\nw33d"
    );

    let req = Request::builder()
        .method("POST")
        .uri("/settings/undo-send")
        .header("x-auth-subject", "w33d")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, cookie.clone())
        .body(Body::from(format!("csrf={token}&window_secs=20")))
        .unwrap();
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        state
            .store
            .get_settings(MAILBOX)
            .await
            .unwrap()
            .undo_send_window_secs,
        20
    );

    let req = Request::builder()
        .method("POST")
        .uri("/settings/autoreply")
        .header("x-auth-subject", "w33d")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, cookie)
        .body(Body::from(format!(
            "csrf={token}&enabled=on&subject=OOO&body=Back%20soon&until=2027-01-31"
        )))
        .unwrap();
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let s = state.store.get_settings(MAILBOX).await.unwrap();
    assert!(s.auto_reply_enabled);
    assert_eq!(s.auto_reply_subject, "OOO");
    assert_eq!(s.auto_reply_body, "Back soon");
    assert!(
        s.auto_reply_until > now_secs(),
        "expiry stored as a future epoch"
    );

    // The saved values render back into the settings page.
    let req = Request::builder()
        .uri("/settings")
        .header("x-auth-subject", "w33d")
        .body(Body::empty())
        .unwrap();
    let html = body_string(app(state).oneshot(req).await.unwrap()).await;
    assert!(html.contains("Regards,\nw33d"));
    assert!(
        html.contains(r#"value="2027-01-31""#),
        "date input round-trips"
    );
    assert!(html.contains(" checked"), "enabled checkbox checked");
}
