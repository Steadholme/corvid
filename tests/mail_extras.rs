//! Tests for the conversation-threading, send-identity, contacts-autocomplete and label features.
//! Threading + contacts harvest are exercised through the real delivery hook
//! ([`corvid::delivery::process_inbound`]); the identity/label/contacts UIs are driven in-process
//! via the axum router (in-memory store — no sockets, no database).

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use tower::ServiceExt;

use corvid::delivery::process_inbound;
use corvid::model::{Label, Message};
use corvid::store::{InMemoryStore, Store};
use corvid::{app, build_dev_state, new_id, now_secs, AppState};

const MAILBOX: &str = "w33d@w33d.xyz";

/// Construct an inbound message; `thread_id`/`message_id` are left empty so the delivery hook
/// computes them (exactly as the SMTP path does).
fn inbound(from: &str, subject: &str, raw: &str, received_at: i64) -> Message {
    Message {
        id: new_id("m"),
        mailbox: MAILBOX.to_string(),
        msg_from: from.to_string(),
        msg_to: MAILBOX.to_string(),
        subject: subject.to_string(),
        raw_rfc822: raw.to_string(),
        body_text: "body".to_string(),
        body_html: String::new(),
        received_at,
        seen: false,
        folder: "INBOX".to_string(),
        starred: false,
        snooze_until: 0,
        muted: false,
        thread_id: String::new(),
        message_id: String::new(),
    }
}

async fn deliver(store: &InMemoryStore, msg: Message) {
    process_inbound(store, None, "w33d.xyz", "sender@example.com", msg)
        .await
        .expect("delivery stores the message");
}

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

fn post(uri: &str, cookie: &str, form: String) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("x-auth-subject", "w33d")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, cookie.to_string())
        .body(Body::from(form))
        .unwrap()
}

// ---------------------------------------------------------------------------
// Conversation threading
// ---------------------------------------------------------------------------

#[tokio::test]
async fn threading_groups_by_references_headers() {
    let store = InMemoryStore::new();
    // Root A (no refs), then a reply B referencing A, then an unrelated D (different subject).
    let a = inbound(
        "alice@example.com",
        "Project Alpha",
        "From: alice@example.com\r\nSubject: Project Alpha\r\nMessage-ID: <a@ex.com>\r\n\r\nbody",
        100,
    );
    deliver(&store, a).await;
    let b = inbound(
        "bob@example.com",
        "Re: Project Alpha",
        "From: bob@example.com\r\nSubject: Re: Project Alpha\r\nMessage-ID: <b@ex.com>\r\n\
         References: <a@ex.com>\r\nIn-Reply-To: <a@ex.com>\r\n\r\nreply",
        200,
    );
    deliver(&store, b).await;
    let d = inbound(
        "carol@example.com",
        "Weekly Digest",
        "From: carol@example.com\r\nSubject: Weekly Digest\r\nMessage-ID: <d@ex.com>\r\n\r\nnews",
        300,
    );
    deliver(&store, d).await;

    let threads = store
        .list_folder_threads(MAILBOX, "INBOX", None, 50)
        .await
        .unwrap();
    assert_eq!(
        threads.len(),
        2,
        "A+B collapse into one conversation; D is its own"
    );
    // Newest-activity first: the Digest (300) leads, then the Alpha thread (latest 200).
    assert_eq!(threads[0].count, 1);
    assert!(threads[0].latest.subject.contains("Digest"));
    assert_eq!(threads[1].count, 2, "root + reply grouped");
    assert!(
        threads[1].latest.subject.contains("Re: Project Alpha"),
        "latest snippet is the reply"
    );

    // The conversation view lists both messages of the Alpha thread, oldest first.
    let convo = store
        .list_thread(MAILBOX, &threads[1].thread_id, 50)
        .await
        .unwrap();
    assert_eq!(convo.len(), 2);
    assert_eq!(convo[0].subject, "Project Alpha", "root first");
    assert_eq!(convo[1].subject, "Re: Project Alpha");
}

#[tokio::test]
async fn threading_falls_back_to_normalized_subject_when_headers_absent() {
    let store = InMemoryStore::new();
    // Two messages, no References/In-Reply-To, subjects differing only by an "Re:" prefix + case.
    deliver(
        &store,
        inbound(
            "x@ex.com",
            "Notes",
            "From: x@ex.com\r\nSubject: Notes\r\n\r\na",
            100,
        ),
    )
    .await;
    deliver(
        &store,
        inbound(
            "y@ex.com",
            "RE: notes",
            "From: y@ex.com\r\nSubject: RE: notes\r\n\r\nb",
            200,
        ),
    )
    .await;
    // A genuinely different subject stays separate.
    deliver(
        &store,
        inbound(
            "z@ex.com",
            "Invoice",
            "From: z@ex.com\r\nSubject: Invoice\r\n\r\nc",
            300,
        ),
    )
    .await;

    let threads = store
        .list_folder_threads(MAILBOX, "INBOX", None, 50)
        .await
        .unwrap();
    assert_eq!(
        threads.len(),
        2,
        "same normalized subject groups; different subject splits"
    );
    let notes = threads
        .iter()
        .find(|t| t.count == 2)
        .expect("the Notes conversation");
    assert!(notes.thread_id.starts_with("subj:"), "subject fallback key");
}

#[tokio::test]
async fn threaded_view_and_conversation_render() {
    let state = build_dev_state().await;
    let store = state.store.clone();
    // Deliver a two-message thread via the real hook so thread_id is computed.
    let raw_a =
        "From: alice@example.com\r\nSubject: Launch\r\nMessage-ID: <la@ex.com>\r\n\r\nfirst";
    let raw_b = "From: bob@example.com\r\nSubject: Re: Launch\r\nMessage-ID: <lb@ex.com>\r\nReferences: <la@ex.com>\r\n\r\nsecond";
    process_inbound(
        store.as_ref(),
        None,
        "w33d.xyz",
        "alice@example.com",
        inbound("alice@example.com", "Launch", raw_a, 100),
    )
    .await
    .unwrap();
    process_inbound(
        store.as_ref(),
        None,
        "w33d.xyz",
        "bob@example.com",
        inbound("bob@example.com", "Re: Launch", raw_b, 200),
    )
    .await
    .unwrap();

    // Threaded folder view: one collapsed conversation carrying a count of 2.
    let req = Request::builder()
        .uri("/?folder=INBOX&view=threads")
        .header("x-auth-subject", "w33d")
        .body(Body::empty())
        .unwrap();
    let html = body_string(app(state.clone()).oneshot(req).await.unwrap()).await;
    assert!(html.contains("/t?id="), "conversation link present");
    assert!(
        html.contains(r#"class="pill thread-count">2<"#),
        "message count badge shows 2"
    );
    assert!(html.contains("Re: Launch"), "latest snippet shown");
    assert!(
        html.contains(r#"href="/?folder=INBOX""#),
        "Messages toggle back to the flat view"
    );

    // Follow the conversation link: both messages render in order.
    let threads = store
        .list_folder_threads(MAILBOX, "INBOX", None, 10)
        .await
        .unwrap();
    let tid = threads[0].thread_id.clone();
    let req = Request::builder()
        .uri(format!("/t?id={}", urlencode(&tid)))
        .header("x-auth-subject", "w33d")
        .body(Body::empty())
        .unwrap();
    let html = body_string(app(state.clone()).oneshot(req).await.unwrap()).await;
    assert!(
        html.contains("alice@example.com") && html.contains("bob@example.com"),
        "both messages of the conversation are shown"
    );
    assert!(
        html.contains(r#"class="pill thread-count">2<"#),
        "conversation shows its message count"
    );
}

// ---------------------------------------------------------------------------
// Send identities
// ---------------------------------------------------------------------------

#[tokio::test]
async fn identity_add_ownership_and_outbound_from() {
    let state = build_dev_state().await;
    state.store.set_undo_send_window(MAILBOX, 0).await.unwrap();
    let (token, cookie) = mint_csrf(&state).await;

    // Add a self-managed identity at the mail domain.
    let form = format!("csrf={token}&from_addr=info%40w33d.xyz&display_name=HOLDFAST%20Info");
    let resp = app(state.clone())
        .oneshot(post("/settings/identities", &cookie, form))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER, "identity added");
    let identities = state.store.list_send_identities(MAILBOX).await.unwrap();
    assert_eq!(identities.len(), 1);
    let idn_id = identities[0].id.clone();

    // Off-domain identity is rejected (would relay unsigned).
    let form = format!("csrf={token}&from_addr=me%40elsewhere.net");
    let resp = app(state.clone())
        .oneshot(post("/settings/identities", &cookie, form))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // The compose "From" selector offers the identity.
    let req = Request::builder()
        .uri("/compose")
        .header("x-auth-subject", "w33d")
        .header(header::COOKIE, cookie.clone())
        .body(Body::empty())
        .unwrap();
    let html = body_string(app(state.clone()).oneshot(req).await.unwrap()).await;
    assert!(html.contains(r#"name="identity""#), "From selector present");
    assert!(
        html.contains("HOLDFAST Info &lt;info@w33d.xyz&gt;"),
        "identity listed"
    );

    // Sending as the owned identity sets the outbound From + envelope sender to it.
    let form = format!(
        "csrf={token}&action=send&identity={idn_id}&to=friend%40example.com&subject=Hi&body=x"
    );
    let resp = app(state.clone())
        .oneshot(post("/send", &cookie, form))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let due = state.store.due_outbound(now_secs() + 5, 10).await.unwrap();
    assert_eq!(due.len(), 1);
    assert_eq!(
        due[0].env_from, "info@w33d.xyz",
        "envelope sender is the identity"
    );
    assert!(
        due[0].raw.contains("From: HOLDFAST Info <info@w33d.xyz>"),
        "From header is the identity"
    );
    let sent = state
        .store
        .list_folder(MAILBOX, "Sent", None, 10)
        .await
        .unwrap();
    assert_eq!(sent.len(), 1);
    assert_eq!(
        state
            .store
            .get_message(&sent[0].id)
            .await
            .unwrap()
            .unwrap()
            .msg_from,
        "HOLDFAST Info <info@w33d.xyz>"
    );
}

#[tokio::test]
async fn send_rejects_unowned_identity() {
    let state = build_dev_state().await;
    // An identity owned by a DIFFERENT mailbox must not be usable by w33d.
    state
        .store
        .add_send_identity(&corvid::model::SendIdentity {
            id: "si_foreign".to_string(),
            mailbox: "alice@w33d.xyz".to_string(),
            from_addr: "alice@w33d.xyz".to_string(),
            display_name: String::new(),
            is_default: false,
        })
        .await
        .unwrap();
    let (token, cookie) = mint_csrf(&state).await;
    let form = format!(
        "csrf={token}&action=send&identity=si_foreign&to=friend%40example.com&subject=Hi&body=x"
    );
    let resp = app(state.clone())
        .oneshot(post("/send", &cookie, form))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "cannot send as another mailbox's identity"
    );
    assert!(
        state
            .store
            .due_outbound(now_secs() + 5, 10)
            .await
            .unwrap()
            .is_empty(),
        "nothing enqueued"
    );
}

// ---------------------------------------------------------------------------
// Contacts autocomplete
// ---------------------------------------------------------------------------

#[tokio::test]
async fn contacts_harvest_suggest_ranking_and_scope() {
    let store = InMemoryStore::new();
    store
        .upsert_mailbox(&corvid::model::Mailbox {
            addr: MAILBOX.to_string(),
            owner_sub: "w33d".to_string(),
        })
        .await
        .unwrap();
    // Deliver two messages from the same sender (frequency 2) + one from another.
    deliver(
        &store,
        inbound(
            "Frequent <freq@example.com>",
            "one",
            "From: Frequent <freq@example.com>\r\nSubject: one\r\n\r\na",
            100,
        ),
    )
    .await;
    deliver(
        &store,
        inbound(
            "Frequent <freq@example.com>",
            "two",
            "From: Frequent <freq@example.com>\r\nSubject: two\r\n\r\nb",
            200,
        ),
    )
    .await;
    deliver(
        &store,
        inbound(
            "rare@example.com",
            "three",
            "From: rare@example.com\r\nSubject: three\r\n\r\nc",
            300,
        ),
    )
    .await;
    // A manual contact sorts ahead of harvested ones regardless of frequency.
    store
        .upsert_contact(MAILBOX, "vip@example.com", "VIP", true)
        .await
        .unwrap();

    let all = store
        .suggest_contacts(MAILBOX, "example.com", 10)
        .await
        .unwrap();
    assert_eq!(
        all.len(),
        3,
        "self address is never harvested; three correspondents"
    );
    assert_eq!(all[0].addr, "vip@example.com", "manual first");
    assert!(all[0].manual);
    assert_eq!(all[1].addr, "freq@example.com", "then by frequency");
    assert_eq!(all[1].seen_count, 2);
    assert_eq!(all[1].name, "Frequent", "display name harvested");
    assert_eq!(all[2].addr, "rare@example.com");

    // Query narrows by substring over addr + name.
    let hits = store.suggest_contacts(MAILBOX, "freq", 10).await.unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].addr, "freq@example.com");

    // Scope: another mailbox's contacts are invisible.
    assert!(store
        .suggest_contacts("alice@w33d.xyz", "example.com", 10)
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn contacts_suggest_endpoint_is_scoped_json() {
    let state = build_dev_state().await;
    state
        .store
        .upsert_contact(MAILBOX, "friend@example.com", "Friend", true)
        .await
        .unwrap();

    let req = Request::builder()
        .uri("/contacts/suggest?q=friend")
        .header("x-auth-subject", "w33d")
        .body(Body::empty())
        .unwrap();
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;
    assert!(body.contains("friend@example.com") && body.contains("Friend"));

    // An unknown subject (no mailbox) gets an empty array, never another mailbox's data.
    let req = Request::builder()
        .uri("/contacts/suggest?q=friend")
        .header("x-auth-subject", "stranger")
        .body(Body::empty())
        .unwrap();
    let body = body_string(app(state).oneshot(req).await.unwrap()).await;
    assert_eq!(body.trim(), "[]");
}

// ---------------------------------------------------------------------------
// Labels
// ---------------------------------------------------------------------------

#[tokio::test]
async fn label_create_assign_filter_and_remove() {
    let state = build_dev_state().await;
    let (token, cookie) = mint_csrf(&state).await;

    // Create a label.
    let resp = app(state.clone())
        .oneshot(post(
            "/settings/labels",
            &cookie,
            format!("csrf={token}&name=Receipts"),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let labels = state.store.list_labels(MAILBOX).await.unwrap();
    assert_eq!(labels.len(), 1);
    let lid = labels[0].id.clone();

    // A message to label.
    let mut m = inbound(
        "a@b.com",
        "A receipt",
        "From: a@b.com\r\nSubject: A receipt\r\n\r\nbody",
        100,
    );
    m.thread_id = "t1".to_string();
    state.store.store_message(&m).await.unwrap();

    // Assign the label via the read-view control.
    let resp = app(state.clone())
        .oneshot(post(
            &format!("/m/{}/labels", m.id),
            &cookie,
            format!("csrf={token}&op=add&label={lid}"),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let applied = state
        .store
        .labels_for_message(MAILBOX, &m.id)
        .await
        .unwrap();
    assert_eq!(applied.len(), 1);
    assert_eq!(applied[0].name, "Receipts");

    // Label-filter view lists it.
    let by = state
        .store
        .list_by_label(MAILBOX, &lid, None, 10)
        .await
        .unwrap();
    assert_eq!(by.len(), 1);
    assert_eq!(by[0].id, m.id);
    let req = Request::builder()
        .uri(format!("/?label={lid}"))
        .header("x-auth-subject", "w33d")
        .body(Body::empty())
        .unwrap();
    let html = body_string(app(state.clone()).oneshot(req).await.unwrap()).await;
    assert!(
        html.contains("A receipt"),
        "labelled message listed in the label view"
    );
    assert!(html.contains("Label:"), "label heading");

    // Remove it.
    let resp = app(state.clone())
        .oneshot(post(
            &format!("/m/{}/labels", m.id),
            &cookie,
            format!("csrf={token}&op=remove&label={lid}"),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert!(state
        .store
        .labels_for_message(MAILBOX, &m.id)
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn label_assign_denied_across_mailboxes() {
    let state = build_dev_state().await;
    // w33d's label; a message that belongs to a different mailbox must never receive it.
    state
        .store
        .add_label(&Label {
            id: "lbl_x".into(),
            mailbox: MAILBOX.into(),
            name: "Mine".into(),
            color: String::new(),
        })
        .await
        .unwrap();
    state
        .store
        .upsert_mailbox(&corvid::model::Mailbox {
            addr: "alice@w33d.xyz".into(),
            owner_sub: "alice".into(),
        })
        .await
        .unwrap();
    let foreign = inbound("x@y.com", "s", "raw", 1);
    let foreign = Message {
        mailbox: "alice@w33d.xyz".into(),
        ..foreign
    };
    state.store.store_message(&foreign).await.unwrap();

    // Store-level guard: assigning w33d's label to alice's message is a no-op.
    state
        .store
        .assign_label(MAILBOX, &foreign.id, "lbl_x")
        .await
        .unwrap();
    assert!(state
        .store
        .labels_for_message(MAILBOX, &foreign.id)
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn filter_rule_add_label_action_applies_at_delivery() {
    let state = build_dev_state().await;
    let (token, cookie) = mint_csrf(&state).await;

    // Create a label, then a rule that adds it to mail from a given sender.
    app(state.clone())
        .oneshot(post(
            "/settings/labels",
            &cookie,
            format!("csrf={token}&name=Bills"),
        ))
        .await
        .unwrap();
    let lid = state.store.list_labels(MAILBOX).await.unwrap()[0]
        .id
        .clone();
    let form =
        format!("csrf={token}&field=from&op=contains&needle=biller&action=label&label={lid}");
    let resp = app(state.clone())
        .oneshot(post("/settings/rules", &cookie, form))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER, "label rule added");

    // A Move/label rule without a real target is rejected.
    let bad =
        format!("csrf={token}&field=from&op=contains&needle=x&action=label&label=lbl_missing");
    let resp = app(state.clone())
        .oneshot(post("/settings/rules", &cookie, bad))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "label rule needs one of your labels"
    );

    // Deliver a matching message through the hook -> it lands labelled.
    let store = InMemoryStore::new();
    let _ = store; // (delivery below runs against the app's own store)
    process_inbound(
        state.store.as_ref(),
        None,
        "w33d.xyz",
        "biller@example.com",
        inbound(
            "biller@example.com",
            "Statement",
            "From: biller@example.com\r\nSubject: Statement\r\n\r\nbody",
            100,
        ),
    )
    .await
    .unwrap();
    let inbox = state
        .store
        .list_folder(MAILBOX, "INBOX", None, 10)
        .await
        .unwrap();
    assert_eq!(inbox.len(), 1);
    let applied = state
        .store
        .labels_for_message(MAILBOX, &inbox[0].id)
        .await
        .unwrap();
    assert_eq!(
        applied.len(),
        1,
        "the delivery-time rule tagged the message"
    );
    assert_eq!(applied[0].name, "Bills");
}

#[tokio::test]
async fn settings_sender_lists_add_replace_and_delete() {
    let state = build_dev_state().await;
    let (token, cookie) = mint_csrf(&state).await;

    let resp = app(state.clone())
        .oneshot(post(
            "/settings/senders",
            &cookie,
            format!("csrf={token}&kind=blocked&address_or_domain=%40bad.example"),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let entries = state.store.list_sender_lists(MAILBOX).await.unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].kind, "blocked");
    assert_eq!(entries[0].address_or_domain, "bad.example");

    let resp = app(state.clone())
        .oneshot(post(
            "/settings/senders",
            &cookie,
            format!("csrf={token}&kind=safe&address_or_domain=bad.example"),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let entries = state.store.list_sender_lists(MAILBOX).await.unwrap();
    assert_eq!(
        entries.len(),
        1,
        "safe replaces blocked for the same domain"
    );
    assert_eq!(entries[0].kind, "safe");

    let resp = app(state.clone())
        .oneshot(post(
            "/settings/senders",
            &cookie,
            format!("csrf={token}&cmd=delete&id={}", entries[0].id),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert!(state
        .store
        .list_sender_lists(MAILBOX)
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn settings_templates_crud_and_compose_insert_hooks() {
    let state = build_dev_state().await;
    let (token, cookie) = mint_csrf(&state).await;
    let body = "Hello <friend>\nThanks";

    let resp = app(state.clone())
        .oneshot(post(
            "/settings/templates",
            &cookie,
            format!(
                "csrf={token}&cmd=add&name={}&body_text={}",
                urlencode("Follow-up"),
                urlencode(body)
            ),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let templates = state.store.list_templates(MAILBOX).await.unwrap();
    assert_eq!(templates.len(), 1);
    assert_eq!(templates[0].name, "Follow-up");
    assert_eq!(templates[0].body_text, body);

    let req = Request::builder()
        .uri("/compose")
        .header("x-auth-subject", "w33d")
        .body(Body::empty())
        .unwrap();
    let html = body_string(app(state.clone()).oneshot(req).await.unwrap()).await;
    assert!(html.contains(r#"class="template-menu""#));
    assert!(html.contains(r#"btn-insert-template"#));
    assert!(html.contains(r#"data-template-select"#));
    assert!(html.contains("Follow-up"));
    assert!(
        html.contains("Hello &lt;friend&gt;"),
        "template body is escaped in compose data"
    );

    let id = templates[0].id.clone();
    let resp = app(state.clone())
        .oneshot(post(
            "/settings/templates",
            &cookie,
            format!(
                "csrf={token}&cmd=update&id={}&name={}&body_text={}",
                urlencode(&id),
                urlencode("Updated"),
                urlencode("Updated body")
            ),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let updated = state
        .store
        .get_template(MAILBOX, &id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(updated.name, "Updated");
    assert_eq!(updated.body_text, "Updated body");

    let resp = app(state.clone())
        .oneshot(post(
            "/settings/templates",
            &cookie,
            format!("csrf={token}&cmd=delete&id={}", urlencode(&id)),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert!(state
        .store
        .list_templates(MAILBOX)
        .await
        .unwrap()
        .is_empty());
}

/// Minimal percent-encoding matching the webmail's own (unreserved chars pass through).
fn urlencode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}
