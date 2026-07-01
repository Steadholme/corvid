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
    assert!(html.contains(r#"value="Re: Project update""#), "subject prefixed Re:");
    assert!(html.contains("alice@example.com"), "To prefilled with sender");
    assert!(html.contains("&lt;orig-123@example.com&gt;"), "In-Reply-To hidden field set");
    assert!(html.contains("Alice &lt;alice@example.com&gt; wrote:"), "quoted attribution");

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
    let sent = state.store.list_folder("w33d@w33d.xyz", "Sent", 10).await.unwrap();
    assert_eq!(sent.len(), 1, "one message filed into Sent");
    let inbox = state.store.list_folder("w33d@w33d.xyz", "INBOX", 10).await.unwrap();
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

    let drafts = state.store.list_folder("w33d@w33d.xyz", "Drafts", 10).await.unwrap();
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
    assert!(html.contains(r#"href="/?folder=Drafts""#), "Drafts tab present");
    assert!(html.contains("Later"), "draft subject listed");
}

#[tokio::test]
async fn store_mark_unseen_and_set_folder_roundtrip() {
    let state = build_dev_state().await;
    let msg = seed_message("w33d@w33d.xyz", "Toggle", "a@b.com", "x");
    state.store.store_message(&msg).await.unwrap();

    state.store.mark_seen(&msg.id).await.unwrap();
    assert!(state.store.get_message(&msg.id).await.unwrap().unwrap().seen);
    state.store.mark_unseen(&msg.id).await.unwrap();
    assert!(!state.store.get_message(&msg.id).await.unwrap().unwrap().seen);

    state.store.set_folder(&msg.id, "Archive").await.unwrap();
    assert_eq!(state.store.get_message(&msg.id).await.unwrap().unwrap().folder, "Archive");
    // list_folder now filters it out of INBOX and into the new folder.
    assert!(state.store.list_folder("w33d@w33d.xyz", "INBOX", 10).await.unwrap().is_empty());
    assert_eq!(state.store.list_folder("w33d@w33d.xyz", "Archive", 10).await.unwrap().len(), 1);
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
    assert!(html.contains("administrator group"), "renders the 403 admin page");
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
    assert_eq!(resp.status(), StatusCode::SEE_OTHER, "create redirects on success");

    let mb = state.store.get_mailbox("alice@w33d.xyz").await.unwrap().unwrap();
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
    assert!(state.store.get_mailbox("bob@w33d.xyz").await.unwrap().is_none());

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
    assert!(state.store.get_mailbox("bob@w33d.xyz").await.unwrap().is_none());
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
fn multipart_body(
    boundary: &str,
    parts: &[(&str, Option<&str>, Option<&str>, &[u8])],
) -> Vec<u8> {
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
            ("attachments", Some("hello.txt"), Some("text/plain"), b"attached bytes"),
        ],
    );
    let req = Request::builder()
        .method("POST")
        .uri("/send")
        .header("x-auth-subject", "w33d")
        .header(header::CONTENT_TYPE, format!("multipart/form-data; boundary={boundary}"))
        .header(header::COOKIE, cookie)
        .body(Body::from(body))
        .unwrap();
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER, "multipart send redirects on success");

    // The outbound raw is multipart/mixed carrying the base64 attachment part.
    let due = state.store.due_outbound(now_secs() + 5, 10).await.unwrap();
    assert_eq!(due.len(), 1);
    assert!(due[0].raw.contains("multipart/mixed"));
    assert!(due[0].raw.contains(r#"filename="hello.txt""#));
    assert!(due[0].raw.contains("see attachment"));

    // A Sent copy was filed; its read view lists the attachment with a download link.
    let sent = state.store.list_folder("w33d@w33d.xyz", "Sent", 10).await.unwrap();
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
    assert!(html.contains("Attachments"), "read view shows the attachments strip");
    assert!(html.contains(&format!("/m/{sent_id}/attachments/0")), "download link present");
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
    assert!(disp.contains(r#"attachment; filename="hello.txt""#), "content-disposition: {disp}");
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
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
    assert_eq!(resp.status(), StatusCode::NOT_FOUND, "cross-mailbox attachment access denied");
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
