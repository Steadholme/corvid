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

use corvid::model::{Mailbox, Message, OutboundItem};
use corvid::store::{PgStore, Store};
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
    for tbl in ["messages", "outbound_queue", "aliases", "mailboxes"] {
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
    };
    pg.store_message(&msg).await.unwrap();

    let list = pg.list_messages("w33d@w33d.xyz", 10).await.unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].subject, "PG subject");
    assert_eq!(pg.unseen_count("w33d@w33d.xyz").await.unwrap(), 1);

    pg.mark_seen(&msg.id).await.unwrap();
    assert_eq!(pg.unseen_count("w33d@w33d.xyz").await.unwrap(), 0);
    assert!(pg.get_message(&msg.id).await.unwrap().unwrap().seen);

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

    for tbl in ["messages", "outbound_queue", "aliases", "mailboxes"] {
        sqlx_delete(&url, tbl).await;
    }
    println!("PG STORE INTEGRATION OK: mailboxes + messages (seen) + outbound queue (rcpts/reschedule/sent)");
}

async fn sqlx_delete(url: &str, table: &str) {
    use sqlx::postgres::PgPoolOptions;
    let pool = PgPoolOptions::new().max_connections(1).connect(url).await.unwrap();
    sqlx::query(&format!("DELETE FROM {table}")).execute(&pool).await.unwrap();
}
