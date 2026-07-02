//! Webmail render + send tests, driving the axum router in-process via `tower::oneshot`
//! against the in-memory store (no sockets, no database).

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use tower::ServiceExt;

use corvid::model::{parse_search_query, Label, Message};
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
        starred: false,
        snooze_until: 0,
        muted: false,
        thread_id: String::new(),
        message_id: String::new(),
    }
}

async fn body_string(resp: axum::response::Response) -> String {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

#[tokio::test]
async fn inbox_lists_messages_and_read_marks_seen() {
    let state: AppState = build_dev_state().await;
    let msg = seed_message(
        "w33d@w33d.xyz",
        "First mail",
        "Alice <alice@example.com>",
        "Hello body",
    );
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
    let form =
        format!("csrf={token}&to=friend%40example.com&subject=Hi%20there&body=Hello%20outbound");
    let req = Request::builder()
        .method("POST")
        .uri("/send")
        .header("x-auth-subject", "w33d")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, format!("__Host-csrf={token}"))
        .body(Body::from(form))
        .unwrap();
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::SEE_OTHER,
        "send redirects on success"
    );

    // The message was enqueued for the recipient domain.
    let due = state.store.due_outbound(now_secs() + 5, 10).await.unwrap();
    assert_eq!(due.len(), 1);
    assert_eq!(due[0].to_domain, "example.com");
    assert_eq!(due[0].env_from, "w33d@w33d.xyz");
    assert!(due[0].raw.contains("Subject: Hi there"));
    assert!(due[0].raw.contains("Hello outbound"));
}

/// Mint a CSRF cookie+token from `GET /compose`, returning `(token, cookie_header_value)`.
async fn mint_csrf(state: &AppState) -> (String, String) {
    let req = Request::builder()
        .uri("/compose")
        .header("x-auth-subject", "w33d")
        .body(Body::empty())
        .unwrap();
    let resp = app(state.clone()).oneshot(req).await.unwrap();
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
    (token.clone(), format!("__Host-csrf={token}"))
}

#[tokio::test]
async fn reply_prefills_and_sets_thread_headers() {
    let state = build_dev_state().await;
    let mut msg = seed_message(
        "w33d@w33d.xyz",
        "Project update",
        "Alice <alice@example.com>",
        "Original body line",
    );
    // Give the stored source a Message-ID so the reply can chain In-Reply-To/References.
    msg.raw_rfc822 = format!(
        "From: Alice <alice@example.com>\r\nTo: w33d@w33d.xyz\r\nSubject: Project update\r\n\
         Message-ID: <orig-123@example.com>\r\n\r\nOriginal body line\r\n"
    );
    state.store.store_message(&msg).await.unwrap();

    // The reply compose form prefills To/Subject/quote + carries the thread headers.
    let req = Request::builder()
        .uri(format!("/compose?reply={}", msg.id))
        .header("x-auth-subject", "w33d")
        .body(Body::empty())
        .unwrap();
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let html = body_string(resp).await;
    assert!(
        html.contains(r#"value="Re: Project update""#),
        "subject prefixed Re:"
    );
    assert!(
        html.contains("alice@example.com"),
        "To prefilled with sender"
    );
    assert!(
        html.contains("&lt;orig-123@example.com&gt;"),
        "In-Reply-To hidden field set"
    );
    assert!(
        html.contains("Alice &lt;alice@example.com&gt; wrote:"),
        "quoted attribution"
    );

    // Sending that reply threads the headers into the outbound raw AND files a Sent copy.
    let (token, cookie) = mint_csrf(&state).await;
    let form = format!(
        "csrf={token}&action=send&to=alice%40example.com&subject=Re%3A%20Project%20update\
         &body=my%20reply&in_reply_to=%3Corig-123%40example.com%3E&references=%3Corig-123%40example.com%3E"
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

    let due = state.store.due_outbound(now_secs() + 5, 10).await.unwrap();
    assert_eq!(due.len(), 1);
    assert!(due[0].raw.contains("In-Reply-To: <orig-123@example.com>"));
    assert!(due[0].raw.contains("References: <orig-123@example.com>"));

    // A Sent copy now exists for the sender; INBOX is unaffected.
    let sent = state
        .store
        .list_folder("w33d@w33d.xyz", "Sent", None, 10)
        .await
        .unwrap();
    assert_eq!(sent.len(), 1, "one message filed into Sent");
    let inbox = state
        .store
        .list_folder("w33d@w33d.xyz", "INBOX", None, 10)
        .await
        .unwrap();
    assert_eq!(inbox.len(), 1, "the original inbox message is untouched");
}

#[tokio::test]
async fn save_draft_persists_without_sending() {
    let state = build_dev_state().await;
    let (token, cookie) = mint_csrf(&state).await;

    // action=draft with an empty recipient list is allowed and must NOT enqueue anything.
    let form = format!("csrf={token}&action=draft&to=&subject=Later&body=work%20in%20progress");
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

    let drafts = state
        .store
        .list_folder("w33d@w33d.xyz", "Drafts", None, 10)
        .await
        .unwrap();
    assert_eq!(drafts.len(), 1, "draft saved into Drafts");
    let due = state.store.due_outbound(now_secs() + 5, 10).await.unwrap();
    assert!(due.is_empty(), "a draft never enqueues outbound mail");

    // The folder switcher renders the Drafts tab as active for ?folder=Drafts.
    let req = Request::builder()
        .uri("/?folder=Drafts")
        .header("x-auth-subject", "w33d")
        .body(Body::empty())
        .unwrap();
    let resp = app(state).oneshot(req).await.unwrap();
    let html = body_string(resp).await;
    assert!(
        html.contains(r#"href="/?folder=Drafts""#),
        "Drafts tab present"
    );
    assert!(html.contains("Later"), "draft subject listed");
}

#[tokio::test]
async fn store_mark_unseen_and_set_folder_roundtrip() {
    let state = build_dev_state().await;
    let msg = seed_message("w33d@w33d.xyz", "Toggle", "a@b.com", "x");
    state.store.store_message(&msg).await.unwrap();

    state.store.mark_seen(&msg.id).await.unwrap();
    assert!(
        state
            .store
            .get_message(&msg.id)
            .await
            .unwrap()
            .unwrap()
            .seen
    );
    state.store.mark_unseen(&msg.id).await.unwrap();
    assert!(
        !state
            .store
            .get_message(&msg.id)
            .await
            .unwrap()
            .unwrap()
            .seen
    );

    state.store.set_folder(&msg.id, "Archive").await.unwrap();
    assert_eq!(
        state
            .store
            .get_message(&msg.id)
            .await
            .unwrap()
            .unwrap()
            .folder,
        "Archive"
    );
    // list_folder now filters it out of INBOX and into the new folder.
    assert!(state
        .store
        .list_folder("w33d@w33d.xyz", "INBOX", None, 10)
        .await
        .unwrap()
        .is_empty());
    assert_eq!(
        state
            .store
            .list_folder("w33d@w33d.xyz", "Archive", None, 10)
            .await
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn admin_panel_gated_for_non_admin() {
    let state = build_dev_state().await;
    // An ordinary signed-in user (no admin group) is refused the panel with 403.
    let req = Request::builder()
        .uri("/admin")
        .header("x-auth-subject", "w33d")
        .body(Body::empty())
        .unwrap();
    let resp = app(state).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let html = body_string(resp).await;
    assert!(
        html.contains("administrator group"),
        "renders the 403 admin page"
    );
}

#[tokio::test]
async fn admin_panel_allowed_for_admin() {
    let state = build_dev_state().await;
    // A user in `admins` sees the panel listing the seeded primary mailbox.
    let req = Request::builder()
        .uri("/admin")
        .header("x-auth-subject", "w33d")
        .header("x-auth-groups", "readers, admins")
        .body(Body::empty())
        .unwrap();
    let resp = app(state).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let html = body_string(resp).await;
    assert!(html.contains("Mailbox provisioning"));
    assert!(html.contains("w33d@w33d.xyz"), "seeded mailbox listed");
    assert!(html.contains("Create mailbox"));
}

/// Mint a CSRF cookie+token from an admin `GET /admin`, returning `(token, cookie_header_value)`.
async fn mint_admin_csrf(state: &AppState) -> (String, String) {
    let req = Request::builder()
        .uri("/admin")
        .header("x-auth-subject", "w33d")
        .header("x-auth-groups", "admins")
        .body(Body::empty())
        .unwrap();
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    let set_cookie = resp
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .expect("admin index sets a CSRF cookie");
    let token = set_cookie
        .split(';')
        .next()
        .and_then(|kv| kv.split_once('='))
        .map(|(_, v)| v.to_string())
        .unwrap();
    (token.clone(), format!("__Host-csrf={token}"))
}

#[tokio::test]
async fn admin_creates_mailbox() {
    let state = build_dev_state().await;
    let (token, cookie) = mint_admin_csrf(&state).await;

    let form = format!("csrf={token}&addr=alice%40w33d.xyz&owner_sub=alice");
    let req = Request::builder()
        .method("POST")
        .uri("/admin/mailboxes")
        .header("x-auth-subject", "w33d")
        .header("x-auth-groups", "admins")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, cookie)
        .body(Body::from(form))
        .unwrap();
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::SEE_OTHER,
        "create redirects on success"
    );

    let mb = state
        .store
        .get_mailbox("alice@w33d.xyz")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(mb.owner_sub, "alice");
}

#[tokio::test]
async fn admin_create_mailbox_requires_admin_and_csrf() {
    let state = build_dev_state().await;

    // Non-admin POST is blocked by the gate (403) before any CSRF check.
    let req = Request::builder()
        .method("POST")
        .uri("/admin/mailboxes")
        .header("x-auth-subject", "w33d")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from("csrf=x&addr=bob%40w33d.xyz&owner_sub=bob"))
        .unwrap();
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert!(state
        .store
        .get_mailbox("bob@w33d.xyz")
        .await
        .unwrap()
        .is_none());

    // Admin POST with a bad CSRF token is rejected (403) and creates nothing.
    let req = Request::builder()
        .method("POST")
        .uri("/admin/mailboxes")
        .header("x-auth-subject", "w33d")
        .header("x-auth-groups", "infra-admins")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, "__Host-csrf=realtoken")
        .body(Body::from("csrf=WRONG&addr=bob%40w33d.xyz&owner_sub=bob"))
        .unwrap();
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert!(state
        .store
        .get_mailbox("bob@w33d.xyz")
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn admin_adds_alias() {
    let state = build_dev_state().await;
    let (token, cookie) = mint_admin_csrf(&state).await;

    // Alias to the seeded primary mailbox.
    let form = format!("csrf={token}&local_part=info&mailbox=w33d%40w33d.xyz");
    let req = Request::builder()
        .method("POST")
        .uri("/admin/aliases")
        .header("x-auth-subject", "w33d")
        .header("x-auth-groups", "admins")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, cookie)
        .body(Body::from(form))
        .unwrap();
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);

    let aliases = state.store.list_aliases().await.unwrap();
    assert_eq!(aliases.len(), 1);
    assert_eq!(aliases[0].local_part, "info");
    assert_eq!(aliases[0].mailbox, "w33d@w33d.xyz");
}

#[tokio::test]
async fn admin_alias_rejects_unknown_mailbox() {
    let state = build_dev_state().await;
    let (token, cookie) = mint_admin_csrf(&state).await;

    let form = format!("csrf={token}&local_part=info&mailbox=nobody%40w33d.xyz");
    let req = Request::builder()
        .method("POST")
        .uri("/admin/aliases")
        .header("x-auth-subject", "w33d")
        .header("x-auth-groups", "admins")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, cookie)
        .body(Body::from(form))
        .unwrap();
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(state.store.list_aliases().await.unwrap().is_empty());
}

/// Encode a `multipart/form-data` body from `(name, filename?, content_type?, value)` parts.
/// A `None` filename makes a plain text field; `Some(..)` makes a file part.
fn multipart_body(boundary: &str, parts: &[(&str, Option<&str>, Option<&str>, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    for (name, filename, ctype, value) in parts {
        out.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        match filename {
            Some(fname) => {
                out.extend_from_slice(
                    format!(
                        "Content-Disposition: form-data; name=\"{name}\"; filename=\"{fname}\"\r\n"
                    )
                    .as_bytes(),
                );
                let ct = ctype.unwrap_or("application/octet-stream");
                out.extend_from_slice(format!("Content-Type: {ct}\r\n\r\n").as_bytes());
            }
            None => {
                out.extend_from_slice(
                    format!("Content-Disposition: form-data; name=\"{name}\"\r\n\r\n").as_bytes(),
                );
            }
        }
        out.extend_from_slice(value);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    out
}

#[tokio::test]
async fn multipart_send_with_attachment_roundtrips_to_download() {
    let state = build_dev_state().await;
    let (token, cookie) = mint_csrf(&state).await;

    // Compose a multipart send: text fields + one file part.
    let boundary = "corvidTestBoundary123";
    let body = multipart_body(
        boundary,
        &[
            ("csrf", None, None, token.as_bytes()),
            ("action", None, None, b"send"),
            ("to", None, None, b"friend@example.com"),
            ("subject", None, None, b"With file"),
            ("body", None, None, b"see attachment"),
            (
                "attachments",
                Some("hello.txt"),
                Some("text/plain"),
                b"attached bytes",
            ),
        ],
    );
    let req = Request::builder()
        .method("POST")
        .uri("/send")
        .header("x-auth-subject", "w33d")
        .header(
            header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={boundary}"),
        )
        .header(header::COOKIE, cookie)
        .body(Body::from(body))
        .unwrap();
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::SEE_OTHER,
        "multipart send redirects on success"
    );

    // The outbound raw is multipart/mixed carrying the base64 attachment part.
    let due = state.store.due_outbound(now_secs() + 5, 10).await.unwrap();
    assert_eq!(due.len(), 1);
    assert!(due[0].raw.contains("multipart/mixed"));
    assert!(due[0].raw.contains(r#"filename="hello.txt""#));
    assert!(due[0].raw.contains("see attachment"));

    // A Sent copy was filed; its read view lists the attachment with a download link.
    let sent = state
        .store
        .list_folder("w33d@w33d.xyz", "Sent", None, 10)
        .await
        .unwrap();
    assert_eq!(sent.len(), 1);
    let sent_id = sent[0].id.clone();

    let req = Request::builder()
        .uri(format!("/m/{sent_id}"))
        .header("x-auth-subject", "w33d")
        .body(Body::empty())
        .unwrap();
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let html = body_string(resp).await;
    assert!(
        html.contains("Attachments"),
        "read view shows the attachments strip"
    );
    assert!(
        html.contains(&format!("/m/{sent_id}/attachments/0")),
        "download link present"
    );
    assert!(html.contains("hello.txt"));

    // Downloading the attachment returns the exact bytes with an attachment disposition.
    let req = Request::builder()
        .uri(format!("/m/{sent_id}/attachments/0"))
        .header("x-auth-subject", "w33d")
        .body(Body::empty())
        .unwrap();
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let disp = resp
        .headers()
        .get(header::CONTENT_DISPOSITION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(
        disp.contains(r#"attachment; filename="hello.txt""#),
        "content-disposition: {disp}"
    );
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(&bytes[..], b"attached bytes");
}

#[tokio::test]
async fn attachment_download_denied_across_mailboxes() {
    let state = build_dev_state().await;
    // Provision a second mailbox owned by a different subject, holding an attachment message.
    state
        .store
        .upsert_mailbox(&corvid::model::Mailbox {
            addr: "alice@w33d.xyz".to_string(),
            owner_sub: "alice".to_string(),
        })
        .await
        .unwrap();
    let mut msg = seed_message("alice@w33d.xyz", "Secret", "bob@example.com", "body");
    msg.raw_rfc822 = "Content-Type: multipart/mixed; boundary=\"BB\"\r\n\r\n\
        --BB\r\nContent-Type: text/plain\r\n\r\nbody\r\n\
        --BB\r\nContent-Type: text/plain; name=\"secret.txt\"\r\n\
        Content-Transfer-Encoding: base64\r\n\
        Content-Disposition: attachment; filename=\"secret.txt\"\r\n\r\nc2VjcmV0\r\n--BB--\r\n"
        .to_string();
    state.store.store_message(&msg).await.unwrap();

    // The `w33d` user (different mailbox) must NOT be able to download alice's attachment.
    let req = Request::builder()
        .uri(format!("/m/{}/attachments/0", msg.id))
        .header("x-auth-subject", "w33d")
        .body(Body::empty())
        .unwrap();
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "cross-mailbox attachment access denied"
    );
}

// ---------------------------------------------------------------------------
// Message actions + folder navigation + search
// ---------------------------------------------------------------------------

/// POST a message action with the given CSRF `token`/`cookie` and extra urlencoded `fields`.
async fn action(
    state: &AppState,
    id: &str,
    token: &str,
    cookie: &str,
    fields: &str,
) -> axum::response::Response {
    let body = format!("csrf={token}&{fields}");
    let req = Request::builder()
        .method("POST")
        .uri(format!("/m/{id}/action"))
        .header("x-auth-subject", "w33d")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, cookie.to_string())
        .body(Body::from(body))
        .unwrap();
    app(state.clone()).oneshot(req).await.unwrap()
}

#[tokio::test]
async fn store_starred_and_search_roundtrip() {
    let state = build_dev_state().await;
    let m1 = seed_message(
        "w33d@w33d.xyz",
        "Quarterly report",
        "Alice <alice@example.com>",
        "numbers inside",
    );
    let m2 = seed_message(
        "w33d@w33d.xyz",
        "Lunch",
        "bob@example.com",
        "sandwich plans",
    );
    state.store.store_message(&m1).await.unwrap();
    state.store.store_message(&m2).await.unwrap();

    // Star m1 -> Starred view holds it; unstar -> gone.
    state.store.set_starred(&m1.id, true).await.unwrap();
    let starred = state
        .store
        .list_starred("w33d@w33d.xyz", None, 10)
        .await
        .unwrap();
    assert_eq!(starred.len(), 1);
    assert_eq!(starred[0].id, m1.id);
    assert!(starred[0].starred);
    state.store.set_starred(&m1.id, false).await.unwrap();
    assert!(state
        .store
        .list_starred("w33d@w33d.xyz", None, 10)
        .await
        .unwrap()
        .is_empty());

    // Search over subject / body / from, case-insensitive.
    let q_quarterly = parse_search_query("quarterly");
    let q_sandwich = parse_search_query("SANDWICH");
    let q_alice = parse_search_query("alice");
    let q_nomatch = parse_search_query("nomatch");
    assert_eq!(
        state
            .store
            .search_messages("w33d@w33d.xyz", &q_quarterly, None, None, 10)
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        state
            .store
            .search_messages("w33d@w33d.xyz", &q_sandwich, None, None, 10)
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        state
            .store
            .search_messages("w33d@w33d.xyz", &q_alice, None, None, 10)
            .await
            .unwrap()
            .len(),
        1
    );
    assert!(state
        .store
        .search_messages("w33d@w33d.xyz", &q_nomatch, None, None, 10)
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn search_is_keyset_paginated() {
    let state = build_dev_state().await;
    for i in 0..3i64 {
        let mut m = seed_message(
            "w33d@w33d.xyz",
            &format!("Report {i}"),
            "a@b.com",
            "report body",
        );
        m.received_at = 100 + i;
        state.store.store_message(&m).await.unwrap();
    }
    // Page 1: the two newest.
    let q_report = parse_search_query("report");
    let p1 = state
        .store
        .search_messages("w33d@w33d.xyz", &q_report, None, None, 2)
        .await
        .unwrap();
    assert_eq!(p1.len(), 2);
    assert_eq!(p1[0].received_at, 102);
    assert_eq!(p1[1].received_at, 101);
    // Page 2: keyset off the last row -> the remaining older one, no overlap.
    let last = p1.last().unwrap();
    let p2 = state
        .store
        .search_messages(
            "w33d@w33d.xyz",
            &q_report,
            None,
            Some((last.received_at, last.id.clone())),
            2,
        )
        .await
        .unwrap();
    assert_eq!(p2.len(), 1);
    assert_eq!(p2[0].received_at, 100);
    assert!(!p2.iter().any(|m| p1.iter().any(|x| x.id == m.id)));
}

#[tokio::test]
async fn folder_and_starred_listings_are_keyset_paginated() {
    let state = build_dev_state().await;
    for i in 0..3i64 {
        let mut m = seed_message("w33d@w33d.xyz", &format!("Bulk {i}"), "a@b.com", "body");
        m.received_at = 100 + i;
        state.store.store_message(&m).await.unwrap();
        state.store.set_starred(&m.id, true).await.unwrap();
    }
    // Folder page 1: the two newest; page 2 keysets off the last row -> the older one, no overlap.
    let p1 = state
        .store
        .list_folder("w33d@w33d.xyz", "INBOX", None, 2)
        .await
        .unwrap();
    assert_eq!(p1.len(), 2);
    assert_eq!(p1[0].received_at, 102);
    assert_eq!(p1[1].received_at, 101);
    let last = p1.last().unwrap();
    let p2 = state
        .store
        .list_folder(
            "w33d@w33d.xyz",
            "INBOX",
            Some((last.received_at, last.id.clone())),
            2,
        )
        .await
        .unwrap();
    assert_eq!(p2.len(), 1);
    assert_eq!(p2[0].received_at, 100);
    assert!(!p2.iter().any(|m| p1.iter().any(|x| x.id == m.id)));

    // The Starred view pages by the same keyset scheme.
    let s1 = state
        .store
        .list_starred("w33d@w33d.xyz", None, 2)
        .await
        .unwrap();
    assert_eq!(s1.len(), 2);
    let last = s1.last().unwrap();
    let s2 = state
        .store
        .list_starred(
            "w33d@w33d.xyz",
            Some((last.received_at, last.id.clone())),
            2,
        )
        .await
        .unwrap();
    assert_eq!(s2.len(), 1);
    assert_eq!(s2[0].received_at, 100);
}

#[tokio::test]
async fn search_matches_recipient_and_scopes_to_folder() {
    let state = build_dev_state().await;
    let mut inboxed = seed_message("w33d@w33d.xyz", "Hello inbox", "a@b.com", "body");
    inboxed.msg_to = "team-updates@w33d.xyz".to_string();
    state.store.store_message(&inboxed).await.unwrap();
    let mut sent = seed_message("w33d@w33d.xyz", "Hello sent", "w33d@w33d.xyz", "body");
    sent.folder = "Sent".to_string();
    state.store.store_message(&sent).await.unwrap();

    // The To: addresses are searchable.
    let q_team = parse_search_query("team-updates");
    let hits = state
        .store
        .search_messages("w33d@w33d.xyz", &q_team, None, None, 10)
        .await
        .unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].id, inboxed.id);

    // An unscoped search spans folders; a folder scope narrows it.
    let q_hello = parse_search_query("hello");
    assert_eq!(
        state
            .store
            .search_messages("w33d@w33d.xyz", &q_hello, None, None, 10)
            .await
            .unwrap()
            .len(),
        2
    );
    let scoped = state
        .store
        .search_messages("w33d@w33d.xyz", &q_hello, Some("Sent"), None, 10)
        .await
        .unwrap();
    assert_eq!(scoped.len(), 1);
    assert_eq!(scoped[0].id, sent.id);
    assert!(state
        .store
        .search_messages("w33d@w33d.xyz", &q_hello, Some("Trash"), None, 10)
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn structured_search_operators_filter_in_memory_store() {
    let state = build_dev_state().await;
    let mut report = seed_message(
        "w33d@w33d.xyz",
        "Quarterly Finance",
        "Alice <alice@example.com>",
        "budget numbers",
    );
    report.msg_to = "Bob <bob@example.com>".to_string();
    report.raw_rfc822 = "From: Alice <alice@example.com>\r\nTo: Bob <bob@example.com>\r\nCc: Team <team@example.com>\r\nSubject: Quarterly Finance\r\nContent-Type: multipart/mixed; boundary=\"B\"\r\n\r\n--B\r\nContent-Type: text/plain\r\n\r\nbudget numbers\r\n--B\r\nContent-Disposition: attachment; filename=\"report.txt\"\r\n\r\nattachment\r\n--B--\r\n".to_string();
    report.received_at = 86_400;
    report.folder = "Archive".to_string();
    report.starred = true;
    state.store.store_message(&report).await.unwrap();

    let mut lunch = seed_message(
        "w33d@w33d.xyz",
        "Lunch",
        "carol@example.com",
        "sandwich plans",
    );
    lunch.received_at = 86_401;
    lunch.seen = true;
    state.store.store_message(&lunch).await.unwrap();

    let label = Label {
        id: new_id("lbl"),
        mailbox: "w33d@w33d.xyz".to_string(),
        name: "Finance".to_string(),
        color: String::new(),
    };
    state.store.add_label(&label).await.unwrap();
    state
        .store
        .assign_label("w33d@w33d.xyz", &report.id, &label.id)
        .await
        .unwrap();

    let q = parse_search_query(
        r#"from:alice to:bob cc:team subject:Finance label:Finance is:unread is:starred has:attachment in:Archive after:1970-01-01 before:1970-01-03 larger:10 smaller:10k"#,
    );
    let hits = state
        .store
        .search_messages("w33d@w33d.xyz", &q, None, None, 10)
        .await
        .unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].id, report.id);

    let q_or = parse_search_query("subject:Lunch OR label:Finance");
    let hits = state
        .store
        .search_messages("w33d@w33d.xyz", &q_or, None, None, 10)
        .await
        .unwrap();
    let ids: Vec<&str> = hits.iter().map(|m| m.id.as_str()).collect();
    assert!(ids.contains(&report.id.as_str()));
    assert!(ids.contains(&lunch.id.as_str()));

    let q_exclude = parse_search_query("Finance -from:alice");
    assert!(state
        .store
        .search_messages("w33d@w33d.xyz", &q_exclude, None, None, 10)
        .await
        .unwrap()
        .is_empty());

    let q_phrase = parse_search_query(r#""Quarterly Finance""#);
    let hits = state
        .store
        .search_messages("w33d@w33d.xyz", &q_phrase, None, None, 10)
        .await
        .unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].id, report.id);
}

#[tokio::test]
async fn folder_view_paginates_with_keyset_cursor() {
    let state = build_dev_state().await;
    for i in 0..3i64 {
        let mut m = seed_message("w33d@w33d.xyz", &format!("Bulk {i}"), "a@b.com", "body");
        m.received_at = 100 + i;
        state.store.store_message(&m).await.unwrap();
    }

    // Page 1 (?limit=2): the two newest rows plus a keyset "Load older" link.
    let req = Request::builder()
        .uri("/?folder=INBOX&limit=2")
        .header("x-auth-subject", "w33d")
        .body(Body::empty())
        .unwrap();
    let html = body_string(app(state.clone()).oneshot(req).await.unwrap()).await;
    assert!(
        html.contains("Bulk 2") && html.contains("Bulk 1"),
        "two newest listed"
    );
    assert!(
        !html.contains("Bulk 0"),
        "older row deferred to the next page"
    );
    assert!(
        html.contains("Load older"),
        "full page offers the older page"
    );
    assert!(html.contains("&before="), "link carries the keyset cursor");

    // Follow the cursor: the older page holds the remaining row and no further link.
    let p1 = state
        .store
        .list_folder("w33d@w33d.xyz", "INBOX", None, 2)
        .await
        .unwrap();
    let last = p1.last().unwrap();
    let req = Request::builder()
        .uri(format!(
            "/?folder=INBOX&limit=2&before={}_{}",
            last.received_at, last.id
        ))
        .header("x-auth-subject", "w33d")
        .body(Body::empty())
        .unwrap();
    let html = body_string(app(state.clone()).oneshot(req).await.unwrap()).await;
    assert!(
        html.contains("Bulk 0"),
        "older row reachable through the cursor"
    );
    assert!(
        !html.contains("Bulk 2") && !html.contains("Bulk 1"),
        "no overlap with page 1"
    );
    assert!(
        !html.contains("Load older"),
        "short page ends the pagination"
    );
}

#[tokio::test]
async fn search_view_renders_folder_scope() {
    let state = build_dev_state().await;
    let mut sent = seed_message("w33d@w33d.xyz", "Scoped hello", "w33d@w33d.xyz", "body");
    sent.folder = "Sent".to_string();
    state.store.store_message(&sent).await.unwrap();
    let inboxed = seed_message("w33d@w33d.xyz", "Unscoped hello", "a@b.com", "body");
    state.store.store_message(&inboxed).await.unwrap();

    // ?q= + ?folder= narrows the search to that folder and says so in the heading.
    let req = Request::builder()
        .uri("/?q=hello&folder=Sent")
        .header("x-auth-subject", "w33d")
        .body(Body::empty())
        .unwrap();
    let html = body_string(app(state.clone()).oneshot(req).await.unwrap()).await;
    assert!(html.contains("in Sent"), "heading names the folder scope");
    assert!(html.contains("Scoped "), "the Sent match is listed");
    assert!(
        html.contains(r#"<mark class="search-hit">hello</mark>"#),
        "free text hit is highlighted"
    );
    assert!(
        html.contains("search-hint"),
        "operator hint markup is present"
    );
    assert!(
        !html.contains("Unscoped hello"),
        "the INBOX row is filtered out"
    );

    // A non-INBOX folder view seeds the search box with a hidden folder scope.
    let req = Request::builder()
        .uri("/?folder=Sent")
        .header("x-auth-subject", "w33d")
        .body(Body::empty())
        .unwrap();
    let html = body_string(app(state.clone()).oneshot(req).await.unwrap()).await;
    assert!(html.contains(r#"<input type="hidden" name="folder" value="Sent">"#));

    // The Inbox searches the whole mailbox — no hidden scope.
    let req = Request::builder()
        .uri("/")
        .header("x-auth-subject", "w33d")
        .body(Body::empty())
        .unwrap();
    let html = body_string(app(state.clone()).oneshot(req).await.unwrap()).await;
    assert!(!html.contains(r#"type="hidden" name="folder""#));
}

#[tokio::test]
async fn message_actions_star_archive_move_delete_unread() {
    let state = build_dev_state().await;
    let msg = seed_message("w33d@w33d.xyz", "Actionable", "a@b.com", "hi");
    state.store.store_message(&msg).await.unwrap();
    let (token, cookie) = mint_csrf(&state).await;

    // Star.
    let resp = action(
        &state,
        &msg.id,
        &token,
        &cookie,
        "op=star&return=%2F%3Ffolder%3DINBOX",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert!(
        state
            .store
            .get_message(&msg.id)
            .await
            .unwrap()
            .unwrap()
            .starred
    );

    // Mark unread.
    action(&state, &msg.id, &token, &cookie, "op=unread&return=%2F").await;
    assert!(
        !state
            .store
            .get_message(&msg.id)
            .await
            .unwrap()
            .unwrap()
            .seen
    );

    // Archive.
    action(&state, &msg.id, &token, &cookie, "op=archive&return=%2F").await;
    assert_eq!(
        state
            .store
            .get_message(&msg.id)
            .await
            .unwrap()
            .unwrap()
            .folder,
        "Archive"
    );

    // Move to Drafts (a real folder).
    action(
        &state,
        &msg.id,
        &token,
        &cookie,
        "op=move&folder=Drafts&return=%2F",
    )
    .await;
    assert_eq!(
        state
            .store
            .get_message(&msg.id)
            .await
            .unwrap()
            .unwrap()
            .folder,
        "Drafts"
    );

    // Move to a bogus folder is rejected (400) and does not move.
    let resp = action(
        &state,
        &msg.id,
        &token,
        &cookie,
        "op=move&folder=Nope&return=%2F",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        state
            .store
            .get_message(&msg.id)
            .await
            .unwrap()
            .unwrap()
            .folder,
        "Drafts"
    );

    // Delete -> Trash.
    action(&state, &msg.id, &token, &cookie, "op=delete&return=%2F").await;
    assert_eq!(
        state
            .store
            .get_message(&msg.id)
            .await
            .unwrap()
            .unwrap()
            .folder,
        "Trash"
    );
}

#[tokio::test]
async fn message_action_rejects_bad_csrf() {
    let state = build_dev_state().await;
    let msg = seed_message("w33d@w33d.xyz", "Guarded", "a@b.com", "hi");
    state.store.store_message(&msg).await.unwrap();

    let req = Request::builder()
        .method("POST")
        .uri(format!("/m/{}/action", msg.id))
        .header("x-auth-subject", "w33d")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, "__Host-csrf=realtoken")
        .body(Body::from("csrf=WRONG&op=delete&return=%2F"))
        .unwrap();
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        state
            .store
            .get_message(&msg.id)
            .await
            .unwrap()
            .unwrap()
            .folder,
        "INBOX"
    );
}

#[tokio::test]
async fn message_action_denied_across_mailboxes() {
    let state = build_dev_state().await;
    state
        .store
        .upsert_mailbox(&corvid::model::Mailbox {
            addr: "alice@w33d.xyz".to_string(),
            owner_sub: "alice".to_string(),
        })
        .await
        .unwrap();
    let msg = seed_message("alice@w33d.xyz", "Secret", "bob@example.com", "body");
    state.store.store_message(&msg).await.unwrap();
    let (token, cookie) = mint_csrf(&state).await; // w33d's token

    // w33d (a different mailbox) may not act on alice's message.
    let resp = action(&state, &msg.id, &token, &cookie, "op=delete&return=%2F").await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        state
            .store
            .get_message(&msg.id)
            .await
            .unwrap()
            .unwrap()
            .folder,
        "INBOX"
    );
}

#[tokio::test]
async fn inbox_search_and_starred_views_render() {
    let state = build_dev_state().await;
    let m1 = seed_message(
        "w33d@w33d.xyz",
        "Invoice March",
        "vendor@example.com",
        "please pay",
    );
    state.store.store_message(&m1).await.unwrap();
    state.store.set_starred(&m1.id, true).await.unwrap();

    // Search matches by subject.
    let req = Request::builder()
        .uri("/?q=invoice")
        .header("x-auth-subject", "w33d")
        .body(Body::empty())
        .unwrap();
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let html = body_string(resp).await;
    assert!(html.contains("Search results"), "search heading rendered");
    assert!(html.contains(" March"), "matching message listed");
    assert!(
        html.contains(r#"<mark class="search-hit">Invoice</mark>"#),
        "matching free text is highlighted"
    );

    // A search with no hit shows the empty state.
    let req = Request::builder()
        .uri("/?q=zzzznope")
        .header("x-auth-subject", "w33d")
        .body(Body::empty())
        .unwrap();
    let html = body_string(app(state.clone()).oneshot(req).await.unwrap()).await;
    assert!(html.contains("No messages here."));

    // The Starred view lists the starred message and offers the Starred tab.
    let req = Request::builder()
        .uri("/?folder=Starred")
        .header("x-auth-subject", "w33d")
        .body(Body::empty())
        .unwrap();
    let html = body_string(app(state.clone()).oneshot(req).await.unwrap()).await;
    assert!(
        html.contains(r#"href="/?folder=Starred""#),
        "Starred tab present"
    );
    assert!(
        html.contains("Invoice March"),
        "starred message listed in Starred view"
    );
    // The row exposes the per-message action form.
    assert!(html.contains(r#"action="/m/"#), "row action form present");
    assert!(
        html.contains(r#"value="unstar""#),
        "starred row offers unstar"
    );
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
