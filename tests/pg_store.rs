//! PostgreSQL `Store` integration test — runs ONLY when `TEST_DATABASE_URL` is set (it needs an
//! external Postgres). When unset it prints a note and returns early, so the default
//! `cargo test` run stays database-free.
//!
//! ```text
//! docker run --rm -d --name corvid-testpg -e POSTGRES_PASSWORD=pw -e POSTGRES_DB=corvid \
//!   -p 127.0.0.1:55462:5432 postgres:18-alpine
//! TEST_DATABASE_URL=postgres://postgres:pw@127.0.0.1:55462/corvid \
//!   cargo test --test pg_store -- --nocapture
//! docker rm -f corvid-testpg
//! ```

use corvid::model::{FilterRule, Mailbox, Message, OutboundItem};
use corvid::store::{PgStore, Store, AUTO_REPLY_DEDUPE_SECS};
use corvid::{new_id, now_secs};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pg_store_full_integration() {
    let Ok(url) = std::env::var("TEST_DATABASE_URL") else {
        eprintln!("NOTE: TEST_DATABASE_URL not set — skipping Postgres integration test.");
        return;
    };

    let pg = PgStore::connect(&url).await.expect("connect");
    pg.migrate().await.expect("migrate");
    pg.migrate().await.expect("migrate idempotent");

    // Clean slate.
    for tbl in ["messages", "outbound_queue", "aliases", "filter_rules", "auto_reply_log", "mailboxes"] {
        sqlx_delete(&url, tbl).await;
    }

    // --- mailboxes (idempotent upsert) -------------------------------------
    pg.upsert_mailbox(&Mailbox { addr: "w33d@w33d.xyz".into(), owner_sub: "w33d".into() })
        .await
        .unwrap();
    pg.upsert_mailbox(&Mailbox { addr: "w33d@w33d.xyz".into(), owner_sub: "w33d".into() })
        .await
        .unwrap();
    assert_eq!(
        pg.mailbox_for_owner("w33d").await.unwrap().unwrap().addr,
        "w33d@w33d.xyz"
    );

    // --- messages ----------------------------------------------------------
    let now = now_secs();
    let msg = Message {
        id: new_id("m"),
        mailbox: "w33d@w33d.xyz".into(),
        msg_from: "alice@example.com".into(),
        msg_to: "w33d@w33d.xyz".into(),
        subject: "PG subject".into(),
        raw_rfc822: "From: alice@example.com\r\nSubject: PG subject\r\n\r\nbody".into(),
        body_text: "body".into(),
        body_html: String::new(),
        received_at: now,
        seen: false,
        folder: "INBOX".into(),
        starred: false,
    };
    pg.store_message(&msg).await.unwrap();

    let list = pg.list_messages("w33d@w33d.xyz", 10).await.unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].subject, "PG subject");
    assert_eq!(pg.unseen_count("w33d@w33d.xyz").await.unwrap(), 1);

    pg.mark_seen(&msg.id).await.unwrap();
    assert_eq!(pg.unseen_count("w33d@w33d.xyz").await.unwrap(), 0);
    assert!(pg.get_message(&msg.id).await.unwrap().unwrap().seen);

    // --- star + folder + search -------------------------------------------
    pg.set_starred(&msg.id, true).await.unwrap();
    assert!(pg.get_message(&msg.id).await.unwrap().unwrap().starred);
    let starred = pg.list_starred("w33d@w33d.xyz", None, 10).await.unwrap();
    assert_eq!(starred.len(), 1);
    assert!(starred[0].starred);
    pg.set_starred(&msg.id, false).await.unwrap();
    assert!(pg.list_starred("w33d@w33d.xyz", None, 10).await.unwrap().is_empty());

    // Case-insensitive LIKE search over from/to/subject/body, keyset-paginated.
    assert_eq!(pg.search_messages("w33d@w33d.xyz", "subject", None, None, 10).await.unwrap().len(), 1);
    assert_eq!(pg.search_messages("w33d@w33d.xyz", "ALICE", None, None, 10).await.unwrap().len(), 1);
    assert_eq!(pg.search_messages("w33d@w33d.xyz", "w33d@w33d", None, None, 10).await.unwrap().len(), 1, "To: matches");
    assert!(pg.search_messages("w33d@w33d.xyz", "nomatch", None, None, 10).await.unwrap().is_empty());
    // A LIKE metacharacter in the needle matches literally, never as a wildcard.
    assert!(pg.search_messages("w33d@w33d.xyz", "%", None, None, 10).await.unwrap().is_empty());
    // Keyset off the only row returns nothing more.
    let page = pg.search_messages("w33d@w33d.xyz", "subject", None, None, 10).await.unwrap();
    let last = &page[0];
    assert!(pg
        .search_messages("w33d@w33d.xyz", "subject", None, Some((last.received_at, last.id.clone())), 10)
        .await
        .unwrap()
        .is_empty());

    pg.set_folder(&msg.id, "Archive").await.unwrap();
    assert_eq!(pg.get_message(&msg.id).await.unwrap().unwrap().folder, "Archive");
    assert!(pg.list_folder("w33d@w33d.xyz", "INBOX", None, 10).await.unwrap().is_empty());
    assert_eq!(pg.list_folder("w33d@w33d.xyz", "Archive", None, 10).await.unwrap().len(), 1);

    // Folder-scoped search: the Archive scope hits, the INBOX scope does not.
    assert_eq!(pg.search_messages("w33d@w33d.xyz", "subject", Some("Archive"), None, 10).await.unwrap().len(), 1);
    assert!(pg.search_messages("w33d@w33d.xyz", "subject", Some("INBOX"), None, 10).await.unwrap().is_empty());

    // --- keyset folder pagination -------------------------------------------
    let m2 = Message { id: new_id("m"), subject: "Old A".into(), received_at: now - 1, ..msg.clone() };
    let m3 = Message { id: new_id("m"), subject: "Old B".into(), received_at: now - 2, ..msg.clone() };
    pg.store_message(&m2).await.unwrap();
    pg.store_message(&m3).await.unwrap();

    let p1 = pg.list_folder("w33d@w33d.xyz", "INBOX", None, 1).await.unwrap();
    assert_eq!(p1.len(), 1);
    assert_eq!(p1[0].id, m2.id, "newest INBOX row first");
    let p2 = pg
        .list_folder("w33d@w33d.xyz", "INBOX", Some((p1[0].received_at, p1[0].id.clone())), 1)
        .await
        .unwrap();
    assert_eq!(p2.len(), 1);
    assert_eq!(p2[0].id, m3.id, "cursor walks oldward without overlap");
    assert!(pg
        .list_folder("w33d@w33d.xyz", "INBOX", Some((p2[0].received_at, p2[0].id.clone())), 1)
        .await
        .unwrap()
        .is_empty(), "past the oldest row the page is empty");

    // --- outbound queue ----------------------------------------------------
    let item = OutboundItem {
        id: new_id("o"),
        raw: "DKIM-Signature: ...\r\nFrom: w33d@w33d.xyz\r\n\r\nhi".into(),
        env_from: "w33d@w33d.xyz".into(),
        rcpts: vec!["friend@elsewhere.net".into(), "other@elsewhere.net".into()],
        to_domain: "elsewhere.net".into(),
        attempts: 0,
        next_at: now,
        status: "queued".into(),
    };
    pg.enqueue_outbound(&item).await.unwrap();

    let due = pg.due_outbound(now + 1, 10).await.unwrap();
    assert_eq!(due.len(), 1);
    assert_eq!(due[0].rcpts.len(), 2, "comma-joined rcpts round-trip");

    pg.reschedule_outbound(&item.id, 1, now + 9999).await.unwrap();
    assert_eq!(pg.due_outbound(now + 1, 10).await.unwrap().len(), 0, "rescheduled to the future");

    pg.mark_outbound_sent(&item.id).await.unwrap();

    // --- filter rules --------------------------------------------------------
    let mk_rule = |pos: i64, needle: &str, action: &str, folder: Option<&str>| FilterRule {
        id: new_id("fr"),
        mailbox: "w33d@w33d.xyz".into(),
        position: pos,
        field: "from".into(),
        op: "contains".into(),
        needle: needle.into(),
        action: action.into(),
        target_folder: folder.map(str::to_string),
        enabled: true,
        created_at: now,
    };
    let r1 = mk_rule(2, "alice", "move", Some("Archive"));
    let r2 = mk_rule(1, "bob", "discard", None);
    pg.add_rule(&r1).await.unwrap();
    pg.add_rule(&r2).await.unwrap();

    let rules = pg.list_rules("w33d@w33d.xyz").await.unwrap();
    assert_eq!(rules.len(), 2);
    assert_eq!(rules[0].id, r2.id, "ordered by position ascending");
    assert_eq!(rules[1].target_folder.as_deref(), Some("Archive"), "nullable folder round-trips");
    assert!(rules[0].target_folder.is_none());

    pg.set_rule_enabled("w33d@w33d.xyz", &r2.id, false).await.unwrap();
    assert!(!pg.list_rules("w33d@w33d.xyz").await.unwrap()[0].enabled);
    pg.set_rule_position("w33d@w33d.xyz", &r2.id, 9).await.unwrap();
    assert_eq!(pg.list_rules("w33d@w33d.xyz").await.unwrap()[1].id, r2.id, "repositioned last");
    // Wrong-mailbox scoping: a foreign mailbox can neither toggle nor delete the rule.
    pg.delete_rule("other@w33d.xyz", &r1.id).await.unwrap();
    assert_eq!(pg.list_rules("w33d@w33d.xyz").await.unwrap().len(), 2, "scoped delete is a no-op");
    pg.delete_rule("w33d@w33d.xyz", &r1.id).await.unwrap();
    assert_eq!(pg.list_rules("w33d@w33d.xyz").await.unwrap().len(), 1);

    // --- mailbox settings (signature + auto-reply) ---------------------------
    let s = pg.get_settings("w33d@w33d.xyz").await.unwrap();
    assert_eq!(s.signature, "", "pre-migration/unsaved row reads as defaults");
    assert!(!s.auto_reply_enabled);
    assert_eq!(s.auto_reply_until, 0);

    pg.set_signature("w33d@w33d.xyz", "-- w33d").await.unwrap();
    pg.set_auto_reply("w33d@w33d.xyz", true, "OOO", "away until Monday", now + 3600)
        .await
        .unwrap();
    let s = pg.get_settings("w33d@w33d.xyz").await.unwrap();
    assert_eq!(s.signature, "-- w33d");
    assert!(s.auto_reply_enabled);
    assert_eq!(s.auto_reply_subject, "OOO");
    assert_eq!(s.auto_reply_body, "away until Monday");
    assert_eq!(s.auto_reply_until, now + 3600);
    // An unknown mailbox yields the defaults instead of an error.
    assert!(!pg.get_settings("ghost@w33d.xyz").await.unwrap().auto_reply_enabled);

    // --- auto-reply dedupe log ------------------------------------------------
    assert!(pg.mark_auto_replied("w33d@w33d.xyz", "a@b.com", now).await.unwrap(), "first send allowed");
    assert!(!pg.mark_auto_replied("w33d@w33d.xyz", "a@b.com", now + 60).await.unwrap(), "deduped within 24h");
    assert!(pg.mark_auto_replied("w33d@w33d.xyz", "other@b.com", now).await.unwrap(), "per-sender");
    assert!(
        pg.mark_auto_replied("w33d@w33d.xyz", "a@b.com", now + AUTO_REPLY_DEDUPE_SECS).await.unwrap(),
        "window elapsed -> allowed again"
    );

    for tbl in ["messages", "outbound_queue", "aliases", "filter_rules", "auto_reply_log", "mailboxes"] {
        sqlx_delete(&url, tbl).await;
    }
    println!("PG STORE INTEGRATION OK: mailboxes + messages (seen) + outbound queue (rcpts/reschedule/sent) + rules/settings/auto-reply");
}

async fn sqlx_delete(url: &str, table: &str) {
    use sqlx::postgres::PgPoolOptions;
    let pool = PgPoolOptions::new().max_connections(1).connect(url).await.unwrap();
    sqlx::query(&format!("DELETE FROM {table}")).execute(&pool).await.unwrap();
}
