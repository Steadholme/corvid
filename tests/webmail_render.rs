//! Webmail render + send tests, driving the axum router in-process via `tower::oneshot`
//! against the in-memory store (no sockets, no database).

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use tower::ServiceExt;

use corvid::model::Message;
use corvid::{app, build_dev_state, new_id, now_secs, AppState};

fn seed_message(mailbox: &str, subject: &str, from: &str, body: &str) -> Message {
    Message {
        id: new_id("m"),
        mailbox: mailbox.to_string(),
        msg_from: from.to_string(),
        msg_to: "w33d@w33d.xyz".to_string(),
        subject: subject.to_string(),
        raw_rfc822: format!("From: {from}\r\nSubject: {subject}\r\n\r\n{body}"),
        body_text: body.to_string(),
        body_html: String::new(),
        received_at: now_secs(),
        seen: false,
        folder: "INBOX".to_string(),
    }
}

async fn body_string(resp: axum::response::Response) -> String {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

#[tokio::test]
async fn inbox_lists_messages_and_read_marks_seen() {
    let state: AppState = build_dev_state().await;
    let msg = seed_message("w33d@w33d.xyz", "First mail", "Alice <alice@example.com>", "Hello body");
    state.store.store_message(&msg).await.unwrap();

    // Inbox shows the message (signed in as sub `w33d`).
    let req = Request::builder()
        .uri("/")
        .header("x-auth-subject", "w33d")
        .header("x-auth-email", "w33d@holdfast.local")
        .body(Body::empty())
        .unwrap();
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let html = body_string(resp).await;
    assert!(html.contains("First mail"));
    assert!(html.contains("Alice"));
    assert!(html.contains("1 unread"));

    // Read the message -> 200, body rendered, marked seen.
    let req = Request::builder()
        .uri(format!("/m/{}", msg.id))
        .header("x-auth-subject", "w33d")
        .body(Body::empty())
        .unwrap();
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let html = body_string(resp).await;
    assert!(html.contains("Hello body"));

    let reloaded = state.store.get_message(&msg.id).await.unwrap().unwrap();
    assert!(reloaded.seen, "reading marks the message seen");
    assert_eq!(state.store.unseen_count("w33d@w33d.xyz").await.unwrap(), 0);
}

#[tokio::test]
async fn html_body_is_sanitised_on_render() {
    let state = build_dev_state().await;
    let mut msg = seed_message("w33d@w33d.xyz", "Rich", "x@y.com", "");
    msg.body_html = "<p>safe</p><script>alert(1)</script>".to_string();
    state.store.store_message(&msg).await.unwrap();

    let req = Request::builder()
        .uri(format!("/m/{}", msg.id))
        .header("x-auth-subject", "w33d")
        .body(Body::empty())
        .unwrap();
    let resp = app(state).oneshot(req).await.unwrap();
    let html = body_string(resp).await;
    assert!(html.contains("<p>safe</p>"));
    assert!(!html.contains("<script>"));
}

#[tokio::test]
async fn no_mailbox_for_unknown_subject() {
    let state = build_dev_state().await;
    let req = Request::builder()
        .uri("/")
        .header("x-auth-subject", "stranger")
        .body(Body::empty())
        .unwrap();
    let resp = app(state).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let html = body_string(resp).await;
    assert!(html.contains("No mailbox provisioned"));
}

#[tokio::test]
async fn compose_then_send_enqueues_outbound() {
    let state = build_dev_state().await;

    // The compose form mints a CSRF cookie + token.
    let req = Request::builder()
        .uri("/compose")
        .header("x-auth-subject", "w33d")
        .body(Body::empty())
        .unwrap();
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let set_cookie = resp
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .expect("compose sets a CSRF cookie");
    let token = set_cookie
        .split(';')
        .next()
        .and_then(|kv| kv.split_once('='))
        .map(|(_, v)| v.to_string())
        .unwrap();

    // POST /send with the matching cookie + token.
    let form = format!(
        "csrf={token}&to=friend%40example.com&subject=Hi%20there&body=Hello%20outbound"
    );
    let req = Request::builder()
        .method("POST")
        .uri("/send")
        .header("x-auth-subject", "w33d")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, format!("__Host-csrf={token}"))
        .body(Body::from(form))
        .unwrap();
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER, "send redirects on success");

    // The message was enqueued for the recipient domain.
    let due = state.store.due_outbound(now_secs() + 5, 10).await.unwrap();
    assert_eq!(due.len(), 1);
    assert_eq!(due[0].to_domain, "example.com");
    assert_eq!(due[0].env_from, "w33d@w33d.xyz");
    assert!(due[0].raw.contains("Subject: Hi there"));
    assert!(due[0].raw.contains("Hello outbound"));
}

#[tokio::test]
async fn send_rejects_bad_csrf() {
    let state = build_dev_state().await;
    let req = Request::builder()
        .method("POST")
        .uri("/send")
        .header("x-auth-subject", "w33d")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, "__Host-csrf=realtoken")
        .body(Body::from("csrf=WRONG&to=x%40y.com&subject=&body=hi"))
        .unwrap();
    let resp = app(state).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}
