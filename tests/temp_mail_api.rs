use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{header, Request, Response, StatusCode};
use corvid::config::Config;
use corvid::model::{
    Alias, Contact, ContactGroup, FilterRule, Label, Mailbox, Message, OutboundItem, SendIdentity,
    SenderListEntry, Signature, SpamAnnotation, Template,
};
use corvid::store::{InMemoryStore, PgStore, Store};
use corvid::webmail::TEMP_MAIL_MANAGE_SCOPE;
use corvid::{app, now_secs, AppState};
use tower::ServiceExt;

const API: &str = "/api/v1/temp-mailboxes";
const SUBJECT: &str = "user-alice";
const ADDRESS: &str = "gone@old-temp.example";

fn state_with_store(store: Arc<dyn Store>) -> AppState {
    state_with_config(store, Config::dev())
}

fn state_with_config(store: Arc<dyn Store>, config: Config) -> AppState {
    AppState {
        config: Arc::new(config),
        store,
        signer: None,
    }
}

fn request(method: &str, body: &str, subject: Option<&str>, scope: Option<&str>) -> Request<Body> {
    request_at(API, method, body, subject, scope)
}

fn request_at(
    uri: &str,
    method: &str,
    body: &str,
    subject: Option<&str>,
    scope: Option<&str>,
) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(subject) = subject {
        builder = builder.header("x-auth-subject", subject);
    }
    if let Some(scope) = scope {
        builder = builder.header("x-auth-scope", scope);
    }
    builder.body(Body::from(body.to_string())).unwrap()
}

async fn json_body(response: Response<Body>) -> serde_json::Value {
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

fn assert_private_no_store<B>(response: &Response<B>) {
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "private, no-store"
    );
    assert_eq!(
        response.headers().get(header::VARY).unwrap(),
        "Authorization"
    );
}

fn message(id: &str, mailbox: &str) -> Message {
    Message {
        id: id.to_string(),
        mailbox: mailbox.to_string(),
        msg_from: "sender@example.com".into(),
        msg_to: mailbox.to_string(),
        subject: "temporary".into(),
        raw_rfc822: "From: sender@example.com\r\nSubject: temporary\r\n\r\nbody".into(),
        body_text: "body".into(),
        body_html: String::new(),
        received_at: now_secs(),
        seen: false,
        folder: "INBOX".into(),
        starred: false,
        snooze_until: 0,
        muted: false,
        thread_id: String::new(),
        message_id: String::new(),
    }
}

async fn seed_temp(store: &dyn Store, address: &str, subject: &str, expires_at: i64) {
    store
        .upsert_mailbox(&Mailbox {
            addr: address.to_string(),
            owner_sub: format!("temp:{subject}"),
            expires_at,
        })
        .await
        .unwrap();
}

fn multipart_message(id: &str, mailbox: &str, received_at: i64) -> Message {
    Message {
        id: id.to_string(),
        mailbox: mailbox.to_string(),
        msg_from: "Sender <sender@example.com>".into(),
        msg_to: mailbox.to_string(),
        subject: "multipart temporary".into(),
        raw_rfc822: concat!(
            "From: Sender <sender@example.com>\r\n",
            "To: inbox@example.com\r\n",
            "Subject: multipart temporary\r\n",
            "MIME-Version: 1.0\r\n",
            "Content-Type: multipart/mixed; boundary=api-test\r\n",
            "\r\n",
            "--api-test\r\n",
            "Content-Type: text/plain; charset=utf-8\r\n",
            "\r\n",
            "TOP_SECRET_RAW\r\n",
            "--api-test\r\n",
            "Content-Type: text/plain; name=note.txt\r\n",
            "Content-Disposition: attachment; filename=note.txt\r\n",
            "Content-Transfer-Encoding: base64\r\n",
            "\r\n",
            "aGVsbG8=\r\n",
            "--api-test--\r\n"
        )
        .into(),
        body_text: "safe text".into(),
        body_html: concat!(
            r#"<p onclick="evil()">safe</p><script>bad()</script>"#,
            r#"<img src="https://tracker.example/pixel" alt="tracker">"#,
            r#"<img src="cid:inline-logo" alt="inline">"#,
        )
        .into(),
        received_at,
        seen: false,
        folder: "INBOX".into(),
        starred: false,
        snooze_until: 0,
        muted: false,
        thread_id: String::new(),
        message_id: String::new(),
    }
}

#[tokio::test]
async fn delete_api_enforces_gateway_subject_exact_scope_and_json_shape() {
    let store = Arc::new(InMemoryStore::new());
    seed_temp(store.as_ref(), ADDRESS, SUBJECT, now_secs() + 3600).await;
    let state = state_with_store(store.clone());

    for (body, subject, scope, status) in [
        (
            format!(r#"{{"address":"{ADDRESS}"}}"#),
            None,
            Some(TEMP_MAIL_MANAGE_SCOPE),
            StatusCode::UNAUTHORIZED,
        ),
        (
            format!(r#"{{"address":"{ADDRESS}"}}"#),
            Some(SUBJECT),
            None,
            StatusCode::FORBIDDEN,
        ),
        (
            format!(r#"{{"address":"{ADDRESS}"}}"#),
            Some(SUBJECT),
            Some("corvid:temp-mail:manage-extra"),
            StatusCode::FORBIDDEN,
        ),
        (
            format!(r#"{{"address":"{ADDRESS}","owner":"temp:{SUBJECT}"}}"#),
            Some(SUBJECT),
            Some(TEMP_MAIL_MANAGE_SCOPE),
            StatusCode::BAD_REQUEST,
        ),
        (
            r#"{"address":"not an address"}"#.to_string(),
            Some(SUBJECT),
            Some(TEMP_MAIL_MANAGE_SCOPE),
            StatusCode::BAD_REQUEST,
        ),
        (
            format!(r#"{{"address":"{}@example.com"}}"#, "a".repeat(321)),
            Some(SUBJECT),
            Some(TEMP_MAIL_MANAGE_SCOPE),
            StatusCode::BAD_REQUEST,
        ),
        (
            format!(
                r#"{{"address":"{ADDRESS}","padding":"{}"}}"#,
                "x".repeat(5000)
            ),
            Some(SUBJECT),
            Some(TEMP_MAIL_MANAGE_SCOPE),
            StatusCode::PAYLOAD_TOO_LARGE,
        ),
    ] {
        let response = app(state.clone())
            .oneshot(request("DELETE", &body, subject, scope))
            .await
            .unwrap();
        assert_eq!(response.status(), status);
        assert_private_no_store(&response);
    }
    assert!(store.get_mailbox(ADDRESS).await.unwrap().is_some());

    let response = app(state)
        .oneshot(request(
            "PUT",
            "",
            Some(SUBJECT),
            Some(TEMP_MAIL_MANAGE_SCOPE),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_private_no_store(&response);
}

#[tokio::test]
async fn every_temp_api_route_requires_identity_and_scope_and_keeps_private_errors() {
    let state = state_with_store(Arc::new(InMemoryStore::new()));
    let routes = [
        ("GET", API, ""),
        ("POST", API, "{}"),
        ("DELETE", API, r#"{"address":"box@example.com"}"#),
        (
            "POST",
            "/api/v1/temp-mailboxes/renew",
            r#"{"address":"box@example.com"}"#,
        ),
        (
            "POST",
            "/api/v1/temp-mailboxes/messages/list",
            r#"{"address":"box@example.com"}"#,
        ),
        (
            "POST",
            "/api/v1/temp-mailboxes/messages/get",
            r#"{"address":"box@example.com","message_id":"message"}"#,
        ),
        (
            "DELETE",
            "/api/v1/temp-mailboxes/messages",
            r#"{"address":"box@example.com","message_id":"message"}"#,
        ),
        (
            "POST",
            "/api/v1/temp-mailboxes/messages/attachments/get",
            r#"{"address":"box@example.com","message_id":"message","index":0}"#,
        ),
    ];

    for (method, uri, body) in routes {
        let response = app(state.clone())
            .oneshot(request_at(
                uri,
                method,
                body,
                None,
                Some(TEMP_MAIL_MANAGE_SCOPE),
            ))
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "{method} {uri}"
        );
        assert_private_no_store(&response);

        let response = app(state.clone())
            .oneshot(request_at(uri, method, body, Some(SUBJECT), None))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{method} {uri}");
        assert_private_no_store(&response);
    }

    let response = app(state.clone())
        .oneshot(request_at(
            "/api/v1/temp-mailboxes/not-a-route",
            "GET",
            "",
            Some(SUBJECT),
            Some(TEMP_MAIL_MANAGE_SCOPE),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_private_no_store(&response);

    let response = app(state.clone())
        .oneshot(request_at(
            "/api/v1/temp-mailboxes/messages/get",
            "PUT",
            "{}",
            Some(SUBJECT),
            Some(TEMP_MAIL_MANAGE_SCOPE),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_private_no_store(&response);

    let oversized = format!(
        r#"{{"address":"box@example.com","padding":"{}"}}"#,
        "x".repeat(5000)
    );
    let response = app(state)
        .oneshot(request_at(
            "/api/v1/temp-mailboxes/renew",
            "POST",
            &oversized,
            Some(SUBJECT),
            Some(TEMP_MAIL_MANAGE_SCOPE),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_private_no_store(&response);
}

#[tokio::test]
async fn create_and_list_api_enforce_configuration_quota_and_live_owner_scope() {
    let store = Arc::new(InMemoryStore::new());
    let mut config = Config::dev();
    config.temp_mail_domains = vec!["api-temp.example".into()];
    config.temp_mail_max_per_user = 1;
    config.temp_mail_ttl_secs = 600;
    let state = state_with_config(store.clone(), config);

    let response = app(state.clone())
        .oneshot(request(
            "POST",
            r#"{"unexpected":true}"#,
            Some(SUBJECT),
            Some(TEMP_MAIL_MANAGE_SCOPE),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_private_no_store(&response);

    let response = app(state.clone())
        .oneshot(request(
            "POST",
            "{}",
            Some(SUBJECT),
            Some(TEMP_MAIL_MANAGE_SCOPE),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_private_no_store(&response);
    let created = json_body(response).await;
    let address = created["address"].as_str().unwrap().to_string();
    assert!(address.ends_with("@api-temp.example"));
    assert!(created["expires_at"].as_i64().unwrap() > now_secs());
    store
        .store_message(&message("listed-message", &address))
        .await
        .unwrap();
    seed_temp(
        store.as_ref(),
        "expired@api-temp.example",
        SUBJECT,
        now_secs() - 1,
    )
    .await;
    seed_temp(
        store.as_ref(),
        "foreign@api-temp.example",
        "user-bob",
        now_secs() + 600,
    )
    .await;

    let response = app(state.clone())
        .oneshot(request(
            "GET",
            "",
            Some(SUBJECT),
            Some(TEMP_MAIL_MANAGE_SCOPE),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_private_no_store(&response);
    let listed = json_body(response).await;
    assert_eq!(listed["limit"], 1);
    assert_eq!(listed["mailboxes"].as_array().unwrap().len(), 1);
    assert_eq!(listed["mailboxes"][0]["address"], address);
    assert_eq!(listed["mailboxes"][0]["message_count"], 1);

    let response = app(state)
        .oneshot(request(
            "POST",
            "{}",
            Some(SUBJECT),
            Some(TEMP_MAIL_MANAGE_SCOPE),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_private_no_store(&response);

    let disabled = state_with_store(Arc::new(InMemoryStore::new()));
    let response = app(disabled)
        .oneshot(request(
            "POST",
            "{}",
            Some(SUBJECT),
            Some(TEMP_MAIL_MANAGE_SCOPE),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_private_no_store(&response);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_create_requests_cannot_bypass_the_active_mailbox_quota() {
    let store = Arc::new(InMemoryStore::new());
    let mut config = Config::dev();
    config.temp_mail_domains = vec!["api-temp.example".into()];
    config.temp_mail_max_per_user = 1;
    let state = state_with_config(store.clone(), config);

    let mut tasks = Vec::new();
    for _ in 0..16 {
        let state = state.clone();
        tasks.push(tokio::spawn(async move {
            app(state)
                .oneshot(request(
                    "POST",
                    "{}",
                    Some(SUBJECT),
                    Some(TEMP_MAIL_MANAGE_SCOPE),
                ))
                .await
                .unwrap()
                .status()
        }));
    }
    let mut statuses = Vec::new();
    for task in tasks {
        statuses.push(task.await.unwrap());
    }
    assert_eq!(
        statuses
            .iter()
            .filter(|status| **status == StatusCode::CREATED)
            .count(),
        1
    );
    assert_eq!(
        statuses
            .iter()
            .filter(|status| **status == StatusCode::CONFLICT)
            .count(),
        15
    );
    let owner = format!("temp:{SUBJECT}");
    assert_eq!(store.list_temp_mailboxes(&owner).await.unwrap().len(), 1);
}

#[tokio::test]
async fn renew_api_is_owner_scoped_and_can_recover_legacy_temp_mailboxes() {
    let store = Arc::new(InMemoryStore::new());
    let mut config = Config::dev();
    config.temp_mail_max_per_user = 2;
    config.temp_mail_ttl_secs = 7200;
    let state = state_with_config(store.clone(), config);
    let old_expiry = now_secs() + 60;
    seed_temp(store.as_ref(), ADDRESS, SUBJECT, old_expiry).await;
    seed_temp(store.as_ref(), "legacy@old-temp.example", SUBJECT, 0).await;
    seed_temp(store.as_ref(), "over-quota@old-temp.example", SUBJECT, 0).await;
    seed_temp(
        store.as_ref(),
        "foreign@old-temp.example",
        "user-bob",
        old_expiry,
    )
    .await;
    store
        .upsert_mailbox(&Mailbox {
            addr: "permanent@example.com".into(),
            owner_sub: SUBJECT.into(),
            expires_at: 0,
        })
        .await
        .unwrap();

    for address in [ADDRESS, "legacy@old-temp.example"] {
        let response = app(state.clone())
            .oneshot(request_at(
                "/api/v1/temp-mailboxes/renew",
                "POST",
                &format!(r#"{{"address":"{address}"}}"#),
                Some(SUBJECT),
                Some(TEMP_MAIL_MANAGE_SCOPE),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_private_no_store(&response);
        let renewed = json_body(response).await;
        assert_eq!(renewed["address"], address);
        assert!(renewed["expires_at"].as_i64().unwrap() > old_expiry);
    }

    for address in [
        "foreign@old-temp.example",
        "permanent@example.com",
        "missing@old-temp.example",
    ] {
        let response = app(state.clone())
            .oneshot(request_at(
                "/api/v1/temp-mailboxes/renew",
                "POST",
                &format!(r#"{{"address":"{address}"}}"#),
                Some(SUBJECT),
                Some(TEMP_MAIL_MANAGE_SCOPE),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_private_no_store(&response);
    }

    let response = app(state)
        .oneshot(request_at(
            "/api/v1/temp-mailboxes/renew",
            "POST",
            r#"{"address":"over-quota@old-temp.example"}"#,
            Some(SUBJECT),
            Some(TEMP_MAIL_MANAGE_SCOPE),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_private_no_store(&response);
}

#[tokio::test]
async fn message_api_paginates_sanitizes_downloads_and_deletes_with_owner_scope() {
    let store = Arc::new(InMemoryStore::new());
    let state = state_with_store(store.clone());
    let now = now_secs();
    seed_temp(store.as_ref(), ADDRESS, SUBJECT, now + 3600).await;
    seed_temp(
        store.as_ref(),
        "foreign@old-temp.example",
        "user-bob",
        now + 3600,
    )
    .await;
    seed_temp(store.as_ref(), "expired@old-temp.example", SUBJECT, now - 1).await;

    let mut oldest = message("message-1", ADDRESS);
    oldest.received_at = now - 30;
    let mut middle = message("message-2", ADDRESS);
    middle.received_at = now - 20;
    let newest = multipart_message("message-3", ADDRESS, now - 10);
    let foreign = message("foreign-message", "foreign@old-temp.example");
    let expired = message("expired-message", "expired@old-temp.example");
    for message in [&oldest, &middle, &newest, &foreign, &expired] {
        store.store_message(message).await.unwrap();
    }

    let response = app(state.clone())
        .oneshot(request_at(
            "/api/v1/temp-mailboxes/messages/list",
            "POST",
            &format!(r#"{{"address":"{ADDRESS}","limit":2}}"#),
            Some(SUBJECT),
            Some(TEMP_MAIL_MANAGE_SCOPE),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_private_no_store(&response);
    let first_page = json_body(response).await;
    assert_eq!(first_page["messages"].as_array().unwrap().len(), 2);
    assert_eq!(first_page["messages"][0]["id"], "message-3");
    assert_eq!(first_page["messages"][1]["id"], "message-2");
    assert_eq!(first_page["limit"], 2);
    let cursor = first_page["next_before"].clone();

    let second_request = serde_json::json!({
        "address": ADDRESS,
        "limit": 2,
        "before": cursor,
    })
    .to_string();
    let response = app(state.clone())
        .oneshot(request_at(
            "/api/v1/temp-mailboxes/messages/list",
            "POST",
            &second_request,
            Some(SUBJECT),
            Some(TEMP_MAIL_MANAGE_SCOPE),
        ))
        .await
        .unwrap();
    let second_page = json_body(response).await;
    assert_eq!(second_page["messages"].as_array().unwrap().len(), 1);
    assert_eq!(second_page["messages"][0]["id"], "message-1");
    assert!(second_page["next_before"].is_null());

    let response = app(state.clone())
        .oneshot(request_at(
            "/api/v1/temp-mailboxes/messages/get",
            "POST",
            &format!(r#"{{"address":"{ADDRESS}","message_id":"message-3"}}"#),
            Some(SUBJECT),
            Some(TEMP_MAIL_MANAGE_SCOPE),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_private_no_store(&response);
    let detail = json_body(response).await;
    assert!(detail.get("raw_rfc822").is_none());
    assert!(!detail.to_string().contains("TOP_SECRET_RAW"));
    assert!(!detail["body_html"].as_str().unwrap().contains("onclick"));
    assert!(!detail["body_html"].as_str().unwrap().contains("script"));
    assert!(!detail["body_html"].as_str().unwrap().contains("<img"));
    assert!(!detail["body_html"]
        .as_str()
        .unwrap()
        .contains("tracker.example"));
    assert_eq!(detail["seen"], true, "reading a message marks it seen");
    assert!(
        store.get_message("message-3").await.unwrap().unwrap().seen,
        "read state is persisted for subsequent list calls"
    );
    assert_eq!(detail["attachments"].as_array().unwrap().len(), 1);
    assert_eq!(detail["attachments"][0]["index"], 0);

    let response = app(state.clone())
        .oneshot(request_at(
            "/api/v1/temp-mailboxes/messages/attachments/get",
            "POST",
            &format!(r#"{{"address":"{ADDRESS}","message_id":"message-3","index":0}}"#),
            Some(SUBJECT),
            Some(TEMP_MAIL_MANAGE_SCOPE),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_private_no_store(&response);
    assert_eq!(response.headers()[header::CONTENT_TYPE], "text/plain");
    assert_eq!(
        response.headers()[header::CONTENT_DISPOSITION],
        "attachment; filename=\"note.txt\""
    );
    assert_eq!(response.headers()["x-content-type-options"], "nosniff");
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    assert_eq!(&bytes[..], b"hello");

    for address in ["foreign@old-temp.example", "expired@old-temp.example"] {
        let response = app(state.clone())
            .oneshot(request_at(
                "/api/v1/temp-mailboxes/messages/get",
                "POST",
                &format!(r#"{{"address":"{address}","message_id":"foreign-message"}}"#),
                Some(SUBJECT),
                Some(TEMP_MAIL_MANAGE_SCOPE),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_private_no_store(&response);
    }

    let response = app(state.clone())
        .oneshot(request_at(
            "/api/v1/temp-mailboxes/messages",
            "DELETE",
            &format!(r#"{{"address":"{ADDRESS}","message_id":"foreign-message"}}"#),
            Some(SUBJECT),
            Some(TEMP_MAIL_MANAGE_SCOPE),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert!(store
        .get_message("foreign-message")
        .await
        .unwrap()
        .is_some());

    for _ in 0..2 {
        let response = app(state.clone())
            .oneshot(request_at(
                "/api/v1/temp-mailboxes/messages",
                "DELETE",
                &format!(r#"{{"address":"{ADDRESS}","message_id":"message-3"}}"#),
                Some(SUBJECT),
                Some(TEMP_MAIL_MANAGE_SCOPE),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_private_no_store(&response);
    }
    assert!(store.get_message("message-3").await.unwrap().is_none());
}

#[tokio::test]
async fn delete_api_is_owner_scoped_idempotent_and_hides_existence() {
    let store = Arc::new(InMemoryStore::new());
    let state = state_with_store(store.clone());
    seed_temp(store.as_ref(), ADDRESS, SUBJECT, now_secs() + 3600).await;
    store
        .store_message(&message("temp-message", ADDRESS))
        .await
        .unwrap();

    for (address, owner, expires_at) in [
        ("foreign@old-temp.example", "user-bob", now_secs() + 3600),
        ("legacy@old-temp.example", SUBJECT, 0),
    ] {
        seed_temp(store.as_ref(), address, owner, expires_at).await;
    }
    store
        .upsert_mailbox(&Mailbox {
            addr: "permanent@example.com".into(),
            owner_sub: SUBJECT.into(),
            expires_at: 0,
        })
        .await
        .unwrap();

    for address in [
        ADDRESS,
        ADDRESS,
        "missing@old-temp.example",
        "foreign@old-temp.example",
        "permanent@example.com",
        "legacy@old-temp.example",
    ] {
        let body = format!(r#"{{"address":"{address}"}}"#);
        let response = app(state.clone())
            .oneshot(request(
                "DELETE",
                &body,
                Some(SUBJECT),
                Some(&format!("openid {TEMP_MAIL_MANAGE_SCOPE} profile")),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_private_no_store(&response);
    }

    assert!(store.get_mailbox(ADDRESS).await.unwrap().is_none());
    assert!(store.get_message("temp-message").await.unwrap().is_none());
    assert!(store
        .get_mailbox("legacy@old-temp.example")
        .await
        .unwrap()
        .is_none());
    assert!(store
        .get_mailbox("foreign@old-temp.example")
        .await
        .unwrap()
        .is_some());
    assert!(store
        .get_mailbox("permanent@example.com")
        .await
        .unwrap()
        .is_some());
}

#[tokio::test]
async fn delete_api_maps_store_failure_to_503_without_a_database() {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .connect_lazy("postgres://unused:unused@127.0.0.1:1/unused")
        .unwrap();
    pool.close().await;
    let state = state_with_store(Arc::new(PgStore::from_pool(pool)));
    let response = app(state)
        .oneshot(request(
            "DELETE",
            &format!(r#"{{"address":"{ADDRESS}"}}"#),
            Some(SUBJECT),
            Some(TEMP_MAIL_MANAGE_SCOPE),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_private_no_store(&response);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn in_memory_delete_serializes_with_temp_delivery() {
    for n in 0..64 {
        let store = Arc::new(InMemoryStore::new());
        let address = format!("race-{n}@old-temp.example");
        let owner = format!("temp:{SUBJECT}");
        seed_temp(store.as_ref(), &address, SUBJECT, now_secs() + 3600).await;
        let candidate = message(&format!("race-message-{n}"), &address);
        let barrier = Arc::new(tokio::sync::Barrier::new(3));

        let deleting = {
            let store = store.clone();
            let address = address.clone();
            let owner = owner.clone();
            let barrier = barrier.clone();
            tokio::spawn(async move {
                barrier.wait().await;
                store
                    .delete_owned_temp_mailbox(&address, &owner)
                    .await
                    .unwrap()
            })
        };
        let delivering = {
            let store = store.clone();
            let candidate = candidate.clone();
            let barrier = barrier.clone();
            tokio::spawn(async move {
                barrier.wait().await;
                store
                    .store_temp_message_if_live(&candidate, now_secs())
                    .await
                    .unwrap()
            })
        };
        barrier.wait().await;
        assert!(deleting.await.unwrap());
        let _ = delivering.await.unwrap();
        assert!(store.get_mailbox(&address).await.unwrap().is_none());
        assert!(store.get_message(&candidate.id).await.unwrap().is_none());
    }
}

#[tokio::test]
async fn in_memory_delete_cleans_every_mailbox_side_table_and_gc_revalidates() {
    let store = InMemoryStore::new();
    let now = now_secs();
    seed_temp(&store, ADDRESS, SUBJECT, now + 3600).await;
    let msg = message("cleanup-message", ADDRESS);
    store.store_message(&msg).await.unwrap();
    store
        .add_alias(&Alias {
            local_part: "cleanup-alias".into(),
            mailbox: ADDRESS.into(),
        })
        .await
        .unwrap();
    store
        .add_rule(&FilterRule {
            id: "cleanup-rule".into(),
            mailbox: ADDRESS.into(),
            position: 1,
            field: "from".into(),
            op: "contains".into(),
            needle: "example".into(),
            action: "star".into(),
            target_folder: None,
            target_label: None,
            enabled: true,
            created_at: now,
        })
        .await
        .unwrap();
    store
        .set_signature(ADDRESS, "legacy signature")
        .await
        .unwrap();
    assert!(store
        .mark_auto_replied(ADDRESS, "sender@example.com", now)
        .await
        .unwrap());
    store
        .enqueue_outbound(&OutboundItem {
            id: "cleanup-outbound".into(),
            mailbox: ADDRESS.into(),
            batch_id: "cleanup-batch".into(),
            raw: "raw".into(),
            env_from: ADDRESS.into(),
            rcpts: vec!["recipient@example.com".into()],
            to_domain: "example.com".into(),
            attempts: 0,
            next_at: now,
            send_at: 0,
            sent_copy_filed: false,
            status: "queued".into(),
        })
        .await
        .unwrap();
    store
        .add_send_identity(&SendIdentity {
            id: "cleanup-identity".into(),
            mailbox: ADDRESS.into(),
            from_addr: "alias@example.com".into(),
            display_name: String::new(),
            is_default: false,
        })
        .await
        .unwrap();
    store
        .save_contact(
            ADDRESS,
            &Contact {
                addr: "friend@example.com".into(),
                name: "Friend".into(),
                phone: String::new(),
                company: String::new(),
                title: String::new(),
                notes: String::new(),
                manual: true,
                seen_count: 1,
            },
        )
        .await
        .unwrap();
    store
        .save_contact_group(&ContactGroup {
            id: "cleanup-group".into(),
            user: ADDRESS.into(),
            name: "Friends".into(),
            created_at: now,
        })
        .await
        .unwrap();
    store
        .add_contact_group_member(ADDRESS, "cleanup-group", "friend@example.com")
        .await
        .unwrap();
    store
        .upsert_sender_list(&SenderListEntry {
            id: "cleanup-sender".into(),
            user: ADDRESS.into(),
            address_or_domain: "blocked.example".into(),
            kind: "blocked".into(),
            created_at: now,
        })
        .await
        .unwrap();
    store
        .create_signature(&Signature {
            id: "cleanup-signature".into(),
            user: ADDRESS.into(),
            identity: String::new(),
            name: "Default".into(),
            body_html: String::new(),
            body_text: "body".into(),
            is_default: true,
            created_at: now,
        })
        .await
        .unwrap();
    store
        .create_template(&Template {
            id: "cleanup-template".into(),
            user: ADDRESS.into(),
            name: "Template".into(),
            body_html: String::new(),
            body_text: "body".into(),
            created_at: now,
            updated_at: now,
        })
        .await
        .unwrap();
    store
        .add_label(&Label {
            id: "cleanup-label".into(),
            mailbox: ADDRESS.into(),
            name: "Label".into(),
            color: String::new(),
        })
        .await
        .unwrap();
    store
        .assign_label(ADDRESS, &msg.id, "cleanup-label")
        .await
        .unwrap();
    store
        .set_spam_annotation(&SpamAnnotation {
            mailbox: ADDRESS.into(),
            message_id: msg.id.clone(),
            score: 10,
            reason: "test".into(),
        })
        .await
        .unwrap();

    assert!(store
        .delete_owned_temp_mailbox(ADDRESS, &format!("temp:{SUBJECT}"))
        .await
        .unwrap());
    seed_temp(&store, ADDRESS, SUBJECT, now + 3600).await;
    assert_eq!(store.message_count(ADDRESS).await.unwrap(), 0);
    assert!(store
        .list_aliases()
        .await
        .unwrap()
        .iter()
        .all(|alias| alias.mailbox != ADDRESS));
    assert!(store.list_rules(ADDRESS).await.unwrap().is_empty());
    assert!(store.due_outbound(now + 1, 100).await.unwrap().is_empty());
    assert!(store
        .list_send_identities(ADDRESS)
        .await
        .unwrap()
        .is_empty());
    assert!(store.list_contacts(ADDRESS, 100).await.unwrap().is_empty());
    assert!(store.list_contact_groups(ADDRESS).await.unwrap().is_empty());
    assert!(store.list_sender_lists(ADDRESS).await.unwrap().is_empty());
    assert!(store.list_signatures(ADDRESS).await.unwrap().is_empty());
    assert!(store.list_templates(ADDRESS).await.unwrap().is_empty());
    assert!(store.list_labels(ADDRESS).await.unwrap().is_empty());
    assert!(store
        .spam_annotation(ADDRESS, &msg.id)
        .await
        .unwrap()
        .is_none());
    assert!(store
        .mark_auto_replied(ADDRESS, "sender@example.com", now)
        .await
        .unwrap());
    assert!(store
        .get_settings(ADDRESS)
        .await
        .unwrap()
        .signature
        .is_empty());

    let expired = "expired@old-temp.example";
    seed_temp(&store, expired, SUBJECT, now - 1).await;
    assert_eq!(
        store.expired_temp_mailboxes(now).await.unwrap(),
        vec![expired]
    );
    // Simulate a candidate changing ownership after the scan. The deletion transaction must
    // re-check the temp marker rather than blindly trusting the stale candidate address.
    store
        .upsert_mailbox(&Mailbox {
            addr: expired.into(),
            owner_sub: "permanent-owner".into(),
            expires_at: 0,
        })
        .await
        .unwrap();
    assert!(!store
        .delete_expired_temp_mailbox(expired, now)
        .await
        .unwrap());
    assert!(store.get_mailbox(expired).await.unwrap().is_some());
}
