//! Progressive-enhancement layer: the additive JSON action endpoints (`/api/m/{id}/action`,
//! `/api/m/bulk`), the served enhancement JS assets, and the inbox markup hooks the client script
//! binds to. The original form routes + markup are covered by `webmail_render.rs`; these tests lock
//! in that the no-reload siblings share the same CSRF + owner-authorisation guarantees.
use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use tower::ServiceExt;

use corvid::model::Message;
use corvid::{app, build_dev_state, new_id, now_secs, AppState};

fn seed(mailbox: &str, subject: &str) -> Message {
    Message {
        id: new_id("m"),
        mailbox: mailbox.to_string(),
        msg_from: "a@b.com".to_string(),
        msg_to: "w33d@w33d.xyz".to_string(),
        subject: subject.to_string(),
        raw_rfc822: format!("Subject: {subject}\r\n\r\nbody"),
        body_text: "body".to_string(),
        body_html: String::new(),
        received_at: now_secs(),
        seen: false,
        folder: "INBOX".to_string(),
        starred: false,
        thread_id: String::new(),
        message_id: String::new(),
    }
}

async fn body_string(resp: axum::response::Response) -> String {
    let b = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    String::from_utf8(b.to_vec()).unwrap()
}

async fn mint(state: &AppState) -> (String, String) {
    let req = Request::builder().uri("/compose").header("x-auth-subject", "w33d").body(Body::empty()).unwrap();
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    let sc = resp.headers().get(header::SET_COOKIE).unwrap().to_str().unwrap().to_string();
    let token = sc.split(';').next().unwrap().split_once('=').unwrap().1.to_string();
    (token.clone(), format!("__Host-csrf={token}"))
}

#[tokio::test]
async fn inbox_markup_has_enhancement_hooks() {
    let state = build_dev_state().await;
    state.store.store_message(&seed("w33d@w33d.xyz", "Hello")).await.unwrap();
    let req = Request::builder().uri("/").header("x-auth-subject", "w33d").body(Body::empty()).unwrap();
    let html = body_string(app(state).oneshot(req).await.unwrap()).await;
    assert!(html.contains(r#"class="rowcheck"#), "selection checkbox present");
    assert!(html.contains("data-bulkbar"), "bulk toolbar present");
    assert!(html.contains("data-id="), "row carries message id");
    assert!(html.contains(r#"<script src="/assets/webmail.js">"#), "external enhancement js referenced");
    assert!(!html.contains("<script>"), "no inline script token");
    // Unseen row offers optimistic Mark read.
    assert!(html.contains(r#"value="read""#), "unseen row offers read op");
}

#[tokio::test]
async fn assets_js_served() {
    let state = build_dev_state().await;
    for path in ["/assets/webmail.js", "/assets/compose.js"] {
        let req = Request::builder().uri(path).header("x-auth-subject", "w33d").body(Body::empty()).unwrap();
        let resp = app(state.clone()).oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "{path}");
        let ct = resp.headers().get(header::CONTENT_TYPE).unwrap().to_str().unwrap().to_string();
        assert!(ct.contains("javascript"), "{path} ct={ct}");
        let js = body_string(resp).await;
        assert!(js.contains("__corvidToast"), "{path} carries toast helper");
    }
}

#[tokio::test]
async fn api_action_star_and_read() {
    let state = build_dev_state().await;
    let m = seed("w33d@w33d.xyz", "X");
    state.store.store_message(&m).await.unwrap();
    let (token, cookie) = mint(&state).await;

    let req = Request::builder().method("POST").uri(format!("/api/m/{}/action", m.id))
        .header("x-auth-subject", "w33d").header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, cookie.clone()).body(Body::from(format!("csrf={token}&op=star"))).unwrap();
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let j = body_string(resp).await;
    assert!(j.contains("\"starred\":true"), "json: {j}");
    assert!(state.store.get_message(&m.id).await.unwrap().unwrap().starred);

    // Bad CSRF -> 403, no change.
    let req = Request::builder().method("POST").uri(format!("/api/m/{}/action", m.id))
        .header("x-auth-subject", "w33d").header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, "__Host-csrf=real").body(Body::from("csrf=WRONG&op=unstar")).unwrap();
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert!(state.store.get_message(&m.id).await.unwrap().unwrap().starred, "unchanged after bad csrf");
}

#[tokio::test]
async fn api_action_report_spam_and_not_spam_update_sender_lists() {
    let state = build_dev_state().await;
    let m = seed("w33d@w33d.xyz", "Spam candidate");
    state.store.store_message(&m).await.unwrap();
    let (token, cookie) = mint(&state).await;

    let req = Request::builder().method("POST").uri(format!("/api/m/{}/action", m.id))
        .header("x-auth-subject", "w33d").header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, cookie.clone()).body(Body::from(format!("csrf={token}&op=report_spam"))).unwrap();
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(state.store.get_message(&m.id).await.unwrap().unwrap().folder, "Spam");
    let lists = state.store.list_sender_lists("w33d@w33d.xyz").await.unwrap();
    assert_eq!(lists.len(), 1);
    assert_eq!(lists[0].kind, "blocked");
    assert_eq!(lists[0].address_or_domain, "a@b.com");
    assert!(state.store.spam_annotation("w33d@w33d.xyz", &m.id).await.unwrap().is_some());

    let req = Request::builder().method("POST").uri(format!("/api/m/{}/action", m.id))
        .header("x-auth-subject", "w33d").header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, cookie).body(Body::from(format!("csrf={token}&op=not_spam"))).unwrap();
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(state.store.get_message(&m.id).await.unwrap().unwrap().folder, "INBOX");
    let lists = state.store.list_sender_lists("w33d@w33d.xyz").await.unwrap();
    assert_eq!(lists.len(), 1, "safe replaces blocked for the same sender");
    assert_eq!(lists[0].kind, "safe");
    assert!(state.store.spam_annotation("w33d@w33d.xyz", &m.id).await.unwrap().is_none());
}

#[tokio::test]
async fn api_bulk_archives_only_owned() {
    let state = build_dev_state().await;
    state.store.upsert_mailbox(&corvid::model::Mailbox { addr: "alice@w33d.xyz".into(), owner_sub: "alice".into() }).await.unwrap();
    let mine = seed("w33d@w33d.xyz", "mine");
    let hers = seed("alice@w33d.xyz", "hers");
    state.store.store_message(&mine).await.unwrap();
    state.store.store_message(&hers).await.unwrap();
    let (token, cookie) = mint(&state).await;

    let body = format!("csrf={token}&op=archive&ids={},{}", mine.id, hers.id);
    let req = Request::builder().method("POST").uri("/api/m/bulk")
        .header("x-auth-subject", "w33d").header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, cookie).body(Body::from(body)).unwrap();
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let j = body_string(resp).await;
    assert!(j.contains("\"applied\":1"), "only the owned message counted: {j}");
    assert_eq!(state.store.get_message(&mine.id).await.unwrap().unwrap().folder, "Archive");
    assert_eq!(state.store.get_message(&hers.id).await.unwrap().unwrap().folder, "INBOX", "foreign message untouched");
}
