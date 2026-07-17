//! Progressive-enhancement layer: the additive JSON action endpoints (`/api/m/{id}/action`,
//! `/api/m/bulk`), the served enhancement JS assets, and the inbox markup hooks the client script
//! binds to. The original form routes + markup are covered by `webmail_render.rs`; these tests lock
//! in that the no-reload siblings share the same CSRF + owner-authorisation guarantees.
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use tower::ServiceExt;

use corvid::model::Message;
use corvid::{AppState, app, build_dev_state, new_id, now_secs};

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
        snooze_until: 0,
        muted: false,
        thread_id: String::new(),
        message_id: String::new(),
    }
}

async fn body_string(resp: axum::response::Response) -> String {
    let b = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    String::from_utf8(b.to_vec()).unwrap()
}

async fn mint(state: &AppState) -> (String, String) {
    let req = Request::builder()
        .uri("/compose")
        .header("x-auth-subject", "w33d")
        .body(Body::empty())
        .unwrap();
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    let sc = resp
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let token = sc
        .split(';')
        .next()
        .unwrap()
        .split_once('=')
        .unwrap()
        .1
        .to_string();
    (token.clone(), format!("__Host-csrf={token}"))
}

#[tokio::test]
async fn inbox_markup_has_enhancement_hooks() {
    let state = build_dev_state().await;
    state
        .store
        .store_message(&seed("w33d@w33d.xyz", "Hello"))
        .await
        .unwrap();
    let req = Request::builder()
        .uri("/")
        .header("x-auth-subject", "w33d")
        .body(Body::empty())
        .unwrap();
    let html = body_string(app(state).oneshot(req).await.unwrap()).await;
    assert!(
        html.contains(r#"class="rowcheck"#),
        "selection checkbox present"
    );
    assert!(html.contains("data-bulkbar"), "bulk toolbar present");
    assert!(html.contains("data-id="), "row carries message id");
    assert!(
        html.contains(r#"<script src="/assets/webmail.js">"#),
        "external enhancement js referenced"
    );
    assert!(!html.contains("<script>"), "no inline script token");
    // Unseen row offers optimistic Mark read.
    assert!(
        html.contains(r#"value="read""#),
        "unseen row offers read op"
    );
    assert!(html.contains("btn-snooze"), "snooze hook present");
    assert!(html.contains("snooze-menu"), "snooze preset menu present");
    assert!(html.contains("btn-mute"), "mute hook present");
}

#[tokio::test]
async fn assets_js_served() {
    let state = build_dev_state().await;
    for path in ["/assets/webmail.js", "/assets/compose.js"] {
        let req = Request::builder()
            .uri(path)
            .header("x-auth-subject", "w33d")
            .body(Body::empty())
            .unwrap();
        let resp = app(state.clone()).oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "{path}");
        let ct = resp
            .headers()
            .get(header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert!(ct.contains("javascript"), "{path} ct={ct}");
        assert_eq!(
            resp.headers()
                .get(header::CACHE_CONTROL)
                .and_then(|value| value.to_str().ok()),
            Some("public, max-age=0, must-revalidate"),
            "{path} must not leave updated markup paired with a stale interaction bundle"
        );
        let js = body_string(resp).await;
        assert!(js.contains("__corvidToast"), "{path} carries toast helper");
        if path == "/assets/compose.js" {
            assert!(
                js.contains("data-schedule-local"),
                "compose bundle should translate the local schedule control"
            );
        }
    }
}

#[tokio::test]
async fn compose_autosave_upserts_same_draft_and_reopens_it() {
    let state = build_dev_state().await;
    let (token, cookie) = mint(&state).await;

    let form = format!(
        "csrf={token}&to=alice%40example.com&cc=bob%40example.com&subject=First&body=fallback&body_html=%3Cp%3EHello%20%3Cstrong%3Edraft%3C%2Fstrong%3E%3Cscript%3Ex%3C%2Fscript%3E%3C%2Fp%3E"
    );
    let req = Request::builder()
        .method("POST")
        .uri("/compose/autosave")
        .header("x-auth-subject", "w33d")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, cookie.clone())
        .body(Body::from(form))
        .unwrap();
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
    let draft_id = json["draft_id"].as_str().unwrap().to_string();
    assert!(draft_id.starts_with("m_"), "draft id: {draft_id}");

    let drafts = state
        .store
        .list_folder("w33d@w33d.xyz", "Drafts", None, 10)
        .await
        .unwrap();
    assert_eq!(drafts.len(), 1);
    assert_eq!(drafts[0].id, draft_id);
    let stored = state.store.get_message(&draft_id).await.unwrap().unwrap();
    assert!(stored.body_html.contains("<strong>draft</strong>"));
    assert!(!stored.body_html.contains("<script"));

    let form = format!(
        "csrf={token}&draft_id={draft_id}&to=carol%40example.com&cc=dave%40example.com&subject=Second&body=updated"
    );
    let req = Request::builder()
        .method("POST")
        .uri("/compose/autosave")
        .header("x-auth-subject", "w33d")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, cookie.clone())
        .body(Body::from(form))
        .unwrap();
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let drafts = state
        .store
        .list_folder("w33d@w33d.xyz", "Drafts", None, 10)
        .await
        .unwrap();
    assert_eq!(drafts.len(), 1, "same draft row updated");
    assert_eq!(drafts[0].id, draft_id);
    assert_eq!(drafts[0].subject, "Second");
    let stored = state.store.get_message(&draft_id).await.unwrap().unwrap();
    assert_eq!(stored.msg_to, "carol@example.com");
    assert!(stored.raw_rfc822.contains("Cc: dave@example.com"));
    assert_eq!(stored.body_text, "updated");

    let req = Request::builder()
        .uri("/?folder=Drafts")
        .header("x-auth-subject", "w33d")
        .body(Body::empty())
        .unwrap();
    let html = body_string(app(state.clone()).oneshot(req).await.unwrap()).await;
    assert!(
        html.contains(&format!(r#"href="/compose?draft={draft_id}""#)),
        "Drafts row opens compose: {html}"
    );

    let req = Request::builder()
        .uri(format!("/compose?draft={draft_id}"))
        .header("x-auth-subject", "w33d")
        .body(Body::empty())
        .unwrap();
    let html = body_string(app(state).oneshot(req).await.unwrap()).await;
    assert!(html.contains(&format!(r#"name="draft_id" value="{draft_id}""#)));
    assert!(html.contains(r#"value="Second""#));
    assert!(html.contains(r#"<textarea id="body" name="body">updated</textarea>"#));
    assert!(html.contains(r#"class="autosave-status""#));
}

#[tokio::test]
async fn compose_autosave_rejects_bad_csrf() {
    let state = build_dev_state().await;
    let form = "csrf=wrong&subject=Nope&body=x";
    let req = Request::builder()
        .method("POST")
        .uri("/compose/autosave")
        .header("x-auth-subject", "w33d")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, "__Host-csrf=real")
        .body(Body::from(form))
        .unwrap();
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert!(
        state
            .store
            .list_folder("w33d@w33d.xyz", "Drafts", None, 10)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn compose_autosave_preserves_referenced_draft_attachments() {
    let state = build_dev_state().await;
    let (token, cookie) = mint(&state).await;
    let mut draft = seed("w33d@w33d.xyz", "Attach");
    draft.id = new_id("m");
    draft.folder = "Drafts".to_string();
    draft.seen = true;
    draft.msg_to = "friend@example.com".to_string();
    draft.body_text = "old body".to_string();
    draft.raw_rfc822 = format!(
        "From: w33d@w33d.xyz\r\nTo: friend@example.com\r\nSubject: Attach\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"b\"\r\n\r\n--b\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nold body\r\n--b\r\nContent-Type: text/plain; name=\"note.txt\"\r\nContent-Disposition: attachment; filename=\"note.txt\"\r\nContent-Transfer-Encoding: base64\r\n\r\n{}\r\n--b--\r\n",
        "aGVsbG8="
    );
    state.store.store_message(&draft).await.unwrap();

    let req = Request::builder()
        .uri(format!("/compose?draft={}", draft.id))
        .header("x-auth-subject", "w33d")
        .body(Body::empty())
        .unwrap();
    let html = body_string(app(state.clone()).oneshot(req).await.unwrap()).await;
    assert!(html.contains(&format!(r#"name="attachment_refs" value="{}:0""#, draft.id)));
    assert!(html.contains("note.txt"));

    let form = format!(
        "csrf={token}&draft_id={}&attachment_refs={}:0&to=friend%40example.com&subject=Attach&body=new%20body",
        draft.id, draft.id
    );
    let req = Request::builder()
        .method("POST")
        .uri("/compose/autosave")
        .header("x-auth-subject", "w33d")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, cookie)
        .body(Body::from(form))
        .unwrap();
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let stored = state.store.get_message(&draft.id).await.unwrap().unwrap();
    assert_eq!(stored.body_text, "new body");
    let attachments = corvid::rfc822::list_attachments(&stored.raw_rfc822);
    assert_eq!(attachments.len(), 1);
    assert_eq!(attachments[0].filename, "note.txt");
}

#[tokio::test]
async fn send_with_draft_id_cleans_autosaved_draft() {
    let state = build_dev_state().await;
    state
        .store
        .set_undo_send_window("w33d@w33d.xyz", 0)
        .await
        .unwrap();
    let (token, cookie) = mint(&state).await;

    let form = format!("csrf={token}&to=friend%40example.com&subject=Draft&body=old");
    let req = Request::builder()
        .method("POST")
        .uri("/compose/autosave")
        .header("x-auth-subject", "w33d")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, cookie.clone())
        .body(Body::from(form))
        .unwrap();
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    let json: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
    let draft_id = json["draft_id"].as_str().unwrap().to_string();
    assert_eq!(
        state
            .store
            .list_folder("w33d@w33d.xyz", "Drafts", None, 10)
            .await
            .unwrap()
            .len(),
        1
    );

    let form = format!(
        "csrf={token}&draft_id={draft_id}&action=send&to=friend%40example.com&subject=Final&body=ship"
    );
    let req = Request::builder()
        .method("POST")
        .uri("/send")
        .header("x-auth-subject", "w33d")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, cookie)
        .body(Body::from(form))
        .unwrap();
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);

    assert!(
        state
            .store
            .list_folder("w33d@w33d.xyz", "Drafts", None, 10)
            .await
            .unwrap()
            .is_empty()
    );
    let sent = state
        .store
        .list_folder("w33d@w33d.xyz", "Sent", None, 10)
        .await
        .unwrap();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].subject, "Final");
}

#[tokio::test]
async fn api_action_star_and_read() {
    let state = build_dev_state().await;
    let m = seed("w33d@w33d.xyz", "X");
    state.store.store_message(&m).await.unwrap();
    let (token, cookie) = mint(&state).await;

    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/m/{}/action", m.id))
        .header("x-auth-subject", "w33d")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, cookie.clone())
        .body(Body::from(format!("csrf={token}&op=star")))
        .unwrap();
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let j = body_string(resp).await;
    assert!(j.contains("\"starred\":true"), "json: {j}");
    assert!(
        state
            .store
            .get_message(&m.id)
            .await
            .unwrap()
            .unwrap()
            .starred
    );

    // Bad CSRF -> 403, no change.
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/m/{}/action", m.id))
        .header("x-auth-subject", "w33d")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, "__Host-csrf=real")
        .body(Body::from("csrf=WRONG&op=unstar"))
        .unwrap();
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert!(
        state
            .store
            .get_message(&m.id)
            .await
            .unwrap()
            .unwrap()
            .starred,
        "unchanged after bad csrf"
    );
}

#[tokio::test]
async fn api_action_report_spam_and_not_spam_update_sender_lists() {
    let state = build_dev_state().await;
    let m = seed("w33d@w33d.xyz", "Spam candidate");
    state.store.store_message(&m).await.unwrap();
    let (token, cookie) = mint(&state).await;

    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/m/{}/action", m.id))
        .header("x-auth-subject", "w33d")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, cookie.clone())
        .body(Body::from(format!("csrf={token}&op=report_spam")))
        .unwrap();
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        state
            .store
            .get_message(&m.id)
            .await
            .unwrap()
            .unwrap()
            .folder,
        "Spam"
    );
    let lists = state
        .store
        .list_sender_lists("w33d@w33d.xyz")
        .await
        .unwrap();
    assert_eq!(lists.len(), 1);
    assert_eq!(lists[0].kind, "blocked");
    assert_eq!(lists[0].address_or_domain, "a@b.com");
    assert!(
        state
            .store
            .spam_annotation("w33d@w33d.xyz", &m.id)
            .await
            .unwrap()
            .is_some()
    );

    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/m/{}/action", m.id))
        .header("x-auth-subject", "w33d")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, cookie)
        .body(Body::from(format!("csrf={token}&op=not_spam")))
        .unwrap();
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        state
            .store
            .get_message(&m.id)
            .await
            .unwrap()
            .unwrap()
            .folder,
        "INBOX"
    );
    let lists = state
        .store
        .list_sender_lists("w33d@w33d.xyz")
        .await
        .unwrap();
    assert_eq!(lists.len(), 1, "safe replaces blocked for the same sender");
    assert_eq!(lists[0].kind, "safe");
    assert!(
        state
            .store
            .spam_annotation("w33d@w33d.xyz", &m.id)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn api_action_snooze_unsnooze_and_mute() {
    let state = build_dev_state().await;
    let mut m = seed("w33d@w33d.xyz", "Later");
    m.thread_id = "thr:snooze".to_string();
    state.store.store_message(&m).await.unwrap();
    let (token, cookie) = mint(&state).await;
    let until = now_secs() + 3600;

    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/m/{}/action", m.id))
        .header("x-auth-subject", "w33d")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, cookie.clone())
        .body(Body::from(format!(
            "csrf={token}&op=snooze&snooze_until={until}"
        )))
        .unwrap();
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let stored = state.store.get_message(&m.id).await.unwrap().unwrap();
    assert_eq!(stored.folder, "Archive");
    assert_eq!(stored.snooze_until, until);
    assert!(
        state
            .store
            .list_folder("w33d@w33d.xyz", "INBOX", None, 10)
            .await
            .unwrap()
            .is_empty()
    );

    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/m/{}/action", m.id))
        .header("x-auth-subject", "w33d")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, cookie.clone())
        .body(Body::from(format!("csrf={token}&op=unsnooze")))
        .unwrap();
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let stored = state.store.get_message(&m.id).await.unwrap().unwrap();
    assert_eq!(stored.folder, "INBOX");
    assert_eq!(stored.snooze_until, 0);

    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/m/{}/action", m.id))
        .header("x-auth-subject", "w33d")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, cookie.clone())
        .body(Body::from(format!("csrf={token}&op=mute")))
        .unwrap();
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(state.store.get_message(&m.id).await.unwrap().unwrap().muted);

    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/m/{}/action", m.id))
        .header("x-auth-subject", "w33d")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, cookie)
        .body(Body::from(format!("csrf={token}&op=unmute")))
        .unwrap();
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(!state.store.get_message(&m.id).await.unwrap().unwrap().muted);
}

#[tokio::test]
async fn api_bulk_archives_only_owned() {
    let state = build_dev_state().await;
    state
        .store
        .upsert_mailbox(&corvid::model::Mailbox {
            addr: "alice@w33d.xyz".into(),
            owner_sub: "alice".into(),
            expires_at: 0,        })
        .await
        .unwrap();
    let mine = seed("w33d@w33d.xyz", "mine");
    let hers = seed("alice@w33d.xyz", "hers");
    state.store.store_message(&mine).await.unwrap();
    state.store.store_message(&hers).await.unwrap();
    let (token, cookie) = mint(&state).await;

    let body = format!("csrf={token}&op=archive&ids={},{}", mine.id, hers.id);
    let req = Request::builder()
        .method("POST")
        .uri("/api/m/bulk")
        .header("x-auth-subject", "w33d")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, cookie)
        .body(Body::from(body))
        .unwrap();
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let j = body_string(resp).await;
    assert!(
        j.contains("\"applied\":1"),
        "only the owned message counted: {j}"
    );
    assert_eq!(
        state
            .store
            .get_message(&mine.id)
            .await
            .unwrap()
            .unwrap()
            .folder,
        "Archive"
    );
    assert_eq!(
        state
            .store
            .get_message(&hers.id)
            .await
            .unwrap()
            .unwrap()
            .folder,
        "INBOX",
        "foreign message untouched"
    );
}

#[tokio::test]
async fn api_bulk_snooze_and_mute() {
    let state = build_dev_state().await;
    let mut one = seed("w33d@w33d.xyz", "one");
    one.thread_id = "thr:bulk-one".to_string();
    let mut two = seed("w33d@w33d.xyz", "two");
    two.thread_id = "thr:bulk-two".to_string();
    state.store.store_message(&one).await.unwrap();
    state.store.store_message(&two).await.unwrap();
    let (token, cookie) = mint(&state).await;

    let body = format!("csrf={token}&op=mute&ids={},{}", one.id, two.id);
    let req = Request::builder()
        .method("POST")
        .uri("/api/m/bulk")
        .header("x-auth-subject", "w33d")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, cookie.clone())
        .body(Body::from(body))
        .unwrap();
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        state
            .store
            .get_message(&one.id)
            .await
            .unwrap()
            .unwrap()
            .muted
    );
    assert!(
        state
            .store
            .get_message(&two.id)
            .await
            .unwrap()
            .unwrap()
            .muted
    );

    let until = now_secs() + 7200;
    let body = format!(
        "csrf={token}&op=snooze&snooze_until={until}&ids={},{}",
        one.id, two.id
    );
    let req = Request::builder()
        .method("POST")
        .uri("/api/m/bulk")
        .header("x-auth-subject", "w33d")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, cookie)
        .body(Body::from(body))
        .unwrap();
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        state
            .store
            .list_snoozed("w33d@w33d.xyz", now_secs(), None, 10)
            .await
            .unwrap()
            .len(),
        2
    );
}
