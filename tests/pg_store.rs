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

use corvid::model::{parse_search_query, FilterRule, Mailbox, Message, OutboundItem};
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
    for tbl in [
        "messages",
        "outbound_queue",
        "aliases",
        "filter_rules",
        "auto_reply_log",
        "send_identities",
        "contacts",
        "labels",
        "message_labels",
        "mailboxes",
    ] {
        sqlx_delete(&url, tbl).await;
    }

    // --- mailboxes (idempotent upsert) -------------------------------------
    pg.upsert_mailbox(&Mailbox {
        addr: "w33d@w33d.xyz".into(),
        owner_sub: "w33d".into(),
    })
    .await
    .unwrap();
    pg.upsert_mailbox(&Mailbox {
        addr: "w33d@w33d.xyz".into(),
        owner_sub: "w33d".into(),
    })
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
        snooze_until: 0,
        muted: false,
        thread_id: String::new(),
        message_id: String::new(),
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
    assert!(pg
        .list_starred("w33d@w33d.xyz", None, 10)
        .await
        .unwrap()
        .is_empty());

    // Case-insensitive LIKE search over from/to/subject/body, keyset-paginated.
    let q_subject = parse_search_query("subject");
    let q_alice = parse_search_query("ALICE");
    let q_to = parse_search_query("w33d@w33d");
    let q_nomatch = parse_search_query("nomatch");
    assert_eq!(
        pg.search_messages("w33d@w33d.xyz", &q_subject, None, None, 10)
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        pg.search_messages("w33d@w33d.xyz", &q_alice, None, None, 10)
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        pg.search_messages("w33d@w33d.xyz", &q_to, None, None, 10)
            .await
            .unwrap()
            .len(),
        1,
        "To: matches"
    );
    assert!(pg
        .search_messages("w33d@w33d.xyz", &q_nomatch, None, None, 10)
        .await
        .unwrap()
        .is_empty());
    // A LIKE metacharacter in the needle matches literally, never as a wildcard.
    let q_percent = parse_search_query("%");
    assert!(pg
        .search_messages("w33d@w33d.xyz", &q_percent, None, None, 10)
        .await
        .unwrap()
        .is_empty());
    // Keyset off the only row returns nothing more.
    let page = pg
        .search_messages("w33d@w33d.xyz", &q_subject, None, None, 10)
        .await
        .unwrap();
    let last = &page[0];
    assert!(pg
        .search_messages(
            "w33d@w33d.xyz",
            &q_subject,
            None,
            Some((last.received_at, last.id.clone())),
            10
        )
        .await
        .unwrap()
        .is_empty());

    pg.set_folder(&msg.id, "Archive").await.unwrap();
    assert_eq!(
        pg.get_message(&msg.id).await.unwrap().unwrap().folder,
        "Archive"
    );
    assert!(pg
        .list_folder("w33d@w33d.xyz", "INBOX", None, 10)
        .await
        .unwrap()
        .is_empty());
    assert_eq!(
        pg.list_folder("w33d@w33d.xyz", "Archive", None, 10)
            .await
            .unwrap()
            .len(),
        1
    );

    // Folder-scoped search: the Archive scope hits, the INBOX scope does not.
    assert_eq!(
        pg.search_messages("w33d@w33d.xyz", &q_subject, Some("Archive"), None, 10)
            .await
            .unwrap()
            .len(),
        1
    );
    assert!(pg
        .search_messages("w33d@w33d.xyz", &q_subject, Some("INBOX"), None, 10)
        .await
        .unwrap()
        .is_empty());

    // --- keyset folder pagination -------------------------------------------
    let m2 = Message {
        id: new_id("m"),
        subject: "Old A".into(),
        received_at: now - 1,
        ..msg.clone()
    };
    let m3 = Message {
        id: new_id("m"),
        subject: "Old B".into(),
        received_at: now - 2,
        ..msg.clone()
    };
    pg.store_message(&m2).await.unwrap();
    pg.store_message(&m3).await.unwrap();

    let p1 = pg
        .list_folder("w33d@w33d.xyz", "INBOX", None, 1)
        .await
        .unwrap();
    assert_eq!(p1.len(), 1);
    assert_eq!(p1[0].id, m2.id, "newest INBOX row first");
    let p2 = pg
        .list_folder(
            "w33d@w33d.xyz",
            "INBOX",
            Some((p1[0].received_at, p1[0].id.clone())),
            1,
        )
        .await
        .unwrap();
    assert_eq!(p2.len(), 1);
    assert_eq!(p2[0].id, m3.id, "cursor walks oldward without overlap");
    assert!(
        pg.list_folder(
            "w33d@w33d.xyz",
            "INBOX",
            Some((p2[0].received_at, p2[0].id.clone())),
            1
        )
        .await
        .unwrap()
        .is_empty(),
        "past the oldest row the page is empty"
    );

    // --- outbound queue ----------------------------------------------------
    let item = OutboundItem {
        id: new_id("o"),
        mailbox: "w33d@w33d.xyz".into(),
        batch_id: new_id("ob"),
        raw: "DKIM-Signature: ...\r\nFrom: w33d@w33d.xyz\r\n\r\nhi".into(),
        env_from: "w33d@w33d.xyz".into(),
        rcpts: vec!["friend@elsewhere.net".into(), "other@elsewhere.net".into()],
        to_domain: "elsewhere.net".into(),
        attempts: 0,
        next_at: now,
        send_at: 0,
        sent_copy_filed: false,
        status: "queued".into(),
    };
    pg.enqueue_outbound(&item).await.unwrap();

    let due = pg.due_outbound(now + 1, 10).await.unwrap();
    assert_eq!(due.len(), 1);
    assert_eq!(due[0].rcpts.len(), 2, "comma-joined rcpts round-trip");

    pg.reschedule_outbound(&item.id, 1, now + 9999)
        .await
        .unwrap();
    assert_eq!(
        pg.due_outbound(now + 1, 10).await.unwrap().len(),
        0,
        "rescheduled to the future"
    );

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
        target_label: None,
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
    assert_eq!(
        rules[1].target_folder.as_deref(),
        Some("Archive"),
        "nullable folder round-trips"
    );
    assert!(rules[0].target_folder.is_none());

    pg.set_rule_enabled("w33d@w33d.xyz", &r2.id, false)
        .await
        .unwrap();
    assert!(!pg.list_rules("w33d@w33d.xyz").await.unwrap()[0].enabled);
    pg.set_rule_position("w33d@w33d.xyz", &r2.id, 9)
        .await
        .unwrap();
    assert_eq!(
        pg.list_rules("w33d@w33d.xyz").await.unwrap()[1].id,
        r2.id,
        "repositioned last"
    );
    // Wrong-mailbox scoping: a foreign mailbox can neither toggle nor delete the rule.
    pg.delete_rule("other@w33d.xyz", &r1.id).await.unwrap();
    assert_eq!(
        pg.list_rules("w33d@w33d.xyz").await.unwrap().len(),
        2,
        "scoped delete is a no-op"
    );
    pg.delete_rule("w33d@w33d.xyz", &r1.id).await.unwrap();
    assert_eq!(pg.list_rules("w33d@w33d.xyz").await.unwrap().len(), 1);

    // --- mailbox settings (signature + auto-reply) ---------------------------
    let s = pg.get_settings("w33d@w33d.xyz").await.unwrap();
    assert_eq!(
        s.signature, "",
        "pre-migration/unsaved row reads as defaults"
    );
    assert_eq!(s.undo_send_window_secs, 10);
    assert!(!s.auto_reply_enabled);
    assert_eq!(s.auto_reply_until, 0);

    pg.set_signature("w33d@w33d.xyz", "-- w33d").await.unwrap();
    pg.set_undo_send_window("w33d@w33d.xyz", 20).await.unwrap();
    pg.set_auto_reply(
        "w33d@w33d.xyz",
        true,
        "OOO",
        "away until Monday",
        now + 3600,
    )
    .await
    .unwrap();
    let s = pg.get_settings("w33d@w33d.xyz").await.unwrap();
    assert_eq!(s.signature, "-- w33d");
    assert_eq!(s.undo_send_window_secs, 20);
    assert!(s.auto_reply_enabled);
    assert_eq!(s.auto_reply_subject, "OOO");
    assert_eq!(s.auto_reply_body, "away until Monday");
    assert_eq!(s.auto_reply_until, now + 3600);
    // An unknown mailbox yields the defaults instead of an error.
    assert!(
        !pg.get_settings("ghost@w33d.xyz")
            .await
            .unwrap()
            .auto_reply_enabled
    );

    // --- auto-reply dedupe log ------------------------------------------------
    assert!(
        pg.mark_auto_replied("w33d@w33d.xyz", "a@b.com", now)
            .await
            .unwrap(),
        "first send allowed"
    );
    assert!(
        !pg.mark_auto_replied("w33d@w33d.xyz", "a@b.com", now + 60)
            .await
            .unwrap(),
        "deduped within 24h"
    );
    assert!(
        pg.mark_auto_replied("w33d@w33d.xyz", "other@b.com", now)
            .await
            .unwrap(),
        "per-sender"
    );
    assert!(
        pg.mark_auto_replied("w33d@w33d.xyz", "a@b.com", now + AUTO_REPLY_DEDUPE_SECS)
            .await
            .unwrap(),
        "window elapsed -> allowed again"
    );

    // --- conversation threading ----------------------------------------------
    // Fresh mailbox so the earlier Archive-moved rows don't interfere.
    pg.upsert_mailbox(&Mailbox {
        addr: "thr@w33d.xyz".into(),
        owner_sub: "thr".into(),
    })
    .await
    .unwrap();
    let thr = |id: &str, tid: &str, mid: &str, subj: &str, at: i64| Message {
        id: id.into(),
        mailbox: "thr@w33d.xyz".into(),
        msg_from: "peer@example.com".into(),
        msg_to: "thr@w33d.xyz".into(),
        subject: subj.into(),
        raw_rfc822: "raw".into(),
        body_text: "b".into(),
        body_html: String::new(),
        received_at: at,
        seen: false,
        folder: "INBOX".into(),
        starred: false,
        snooze_until: 0,
        muted: false,
        thread_id: tid.into(),
        message_id: mid.into(),
    };
    pg.store_message(&thr("t_root", "<root@ex>", "<root@ex>", "Deploy", now))
        .await
        .unwrap();
    pg.store_message(&thr(
        "t_reply",
        "<root@ex>",
        "<reply@ex>",
        "Re: Deploy",
        now + 1,
    ))
    .await
    .unwrap();
    pg.store_message(&thr(
        "t_other",
        "subj:lunch",
        "<lunch@ex>",
        "Lunch",
        now + 2,
    ))
    .await
    .unwrap();

    // A reference to the root (or the reply) resolves to the shared thread id.
    assert_eq!(
        pg.find_thread_for_refs("thr@w33d.xyz", &["<reply@ex>".into()])
            .await
            .unwrap()
            .as_deref(),
        Some("<root@ex>"),
        "matches an existing message_id -> its thread_id"
    );
    assert!(pg
        .find_thread_for_refs("thr@w33d.xyz", &["<unknown@ex>".into()])
        .await
        .unwrap()
        .is_none());

    let convos = pg
        .list_folder_threads("thr@w33d.xyz", "INBOX", None, 50)
        .await
        .unwrap();
    assert_eq!(convos.len(), 2, "Deploy thread (2) + Lunch (1)");
    assert_eq!(convos[0].thread_id, "subj:lunch", "newest activity first");
    assert_eq!(convos[0].count, 1);
    let deploy = convos.iter().find(|c| c.thread_id == "<root@ex>").unwrap();
    assert_eq!(deploy.count, 2);
    assert_eq!(deploy.unseen, 2);
    assert!(
        deploy.latest.subject.contains("Re: Deploy"),
        "representative is the newest"
    );
    let msgs = pg
        .list_thread("thr@w33d.xyz", "<root@ex>", 50)
        .await
        .unwrap();
    assert_eq!(msgs.len(), 2);
    assert_eq!(msgs[0].id, "t_root", "oldest first");

    // --- send identities -----------------------------------------------------
    use corvid::model::SendIdentity;
    pg.add_send_identity(&SendIdentity {
        id: "si1".into(),
        mailbox: "w33d@w33d.xyz".into(),
        from_addr: "info@w33d.xyz".into(),
        display_name: "Info".into(),
        is_default: true,
    })
    .await
    .unwrap();
    pg.add_send_identity(&SendIdentity {
        id: "si2".into(),
        mailbox: "w33d@w33d.xyz".into(),
        from_addr: "sales@w33d.xyz".into(),
        display_name: String::new(),
        is_default: false,
    })
    .await
    .unwrap();
    let ids = pg.list_send_identities("w33d@w33d.xyz").await.unwrap();
    assert_eq!(ids.len(), 2);
    assert_eq!(ids[0].id, "si1", "default first");
    // Scoped get: only the owning mailbox resolves it.
    assert!(pg
        .get_send_identity("w33d@w33d.xyz", "si1")
        .await
        .unwrap()
        .is_some());
    assert!(
        pg.get_send_identity("alice@w33d.xyz", "si1")
            .await
            .unwrap()
            .is_none(),
        "cross-mailbox get denied"
    );
    pg.delete_send_identity("alice@w33d.xyz", "si1")
        .await
        .unwrap();
    assert_eq!(
        pg.list_send_identities("w33d@w33d.xyz")
            .await
            .unwrap()
            .len(),
        2,
        "scoped delete is a no-op"
    );
    pg.delete_send_identity("w33d@w33d.xyz", "si2")
        .await
        .unwrap();
    assert_eq!(
        pg.list_send_identities("w33d@w33d.xyz")
            .await
            .unwrap()
            .len(),
        1
    );

    // --- contacts ------------------------------------------------------------
    pg.upsert_contact("w33d@w33d.xyz", "Freq@Example.com", "Freq", false)
        .await
        .unwrap();
    pg.upsert_contact("w33d@w33d.xyz", "freq@example.com", "", false)
        .await
        .unwrap(); // bumps seen_count; keeps name
    pg.upsert_contact("w33d@w33d.xyz", "rare@example.com", "", false)
        .await
        .unwrap();
    pg.upsert_contact("w33d@w33d.xyz", "vip@example.com", "VIP", true)
        .await
        .unwrap();
    let sug = pg
        .suggest_contacts("w33d@w33d.xyz", "example.com", 10)
        .await
        .unwrap();
    assert_eq!(sug.len(), 3);
    assert_eq!(sug[0].addr, "vip@example.com", "manual first");
    assert!(sug[0].manual);
    assert_eq!(sug[1].addr, "freq@example.com", "then by frequency");
    assert_eq!(sug[1].seen_count, 2, "second harvest bumped the count");
    assert_eq!(sug[1].name, "Freq", "blank harvest name never clobbers");
    assert!(
        pg.suggest_contacts("alice@w33d.xyz", "example.com", 10)
            .await
            .unwrap()
            .is_empty(),
        "scoped"
    );
    // A LIKE metacharacter is literal in the query.
    assert!(pg
        .suggest_contacts("w33d@w33d.xyz", "%", 10)
        .await
        .unwrap()
        .is_empty());
    pg.delete_contact("w33d@w33d.xyz", "vip@example.com")
        .await
        .unwrap();
    assert_eq!(
        pg.suggest_contacts("w33d@w33d.xyz", "example.com", 10)
            .await
            .unwrap()
            .len(),
        2
    );

    // --- labels + assignments ------------------------------------------------
    use corvid::model::Label;
    pg.add_label(&Label {
        id: "lbl1".into(),
        mailbox: "w33d@w33d.xyz".into(),
        name: "Receipts".into(),
        color: String::new(),
    })
    .await
    .unwrap();
    // A message in w33d's mailbox to tag (the earlier `msg` was moved to Archive but still owned).
    pg.assign_label("w33d@w33d.xyz", &msg.id, "lbl1")
        .await
        .unwrap();
    pg.assign_label("w33d@w33d.xyz", &msg.id, "lbl1")
        .await
        .unwrap(); // idempotent
    let on = pg
        .labels_for_message("w33d@w33d.xyz", &msg.id)
        .await
        .unwrap();
    assert_eq!(on.len(), 1);
    assert_eq!(on[0].name, "Receipts");
    let by = pg
        .list_by_label("w33d@w33d.xyz", "lbl1", None, 10)
        .await
        .unwrap();
    assert_eq!(by.len(), 1);
    assert_eq!(by[0].id, msg.id);
    let q_structured = parse_search_query("from:alice subject:PG label:Receipts is:read in:Archive after:1970-01-01 before:2999-01-01 larger:10 smaller:1k");
    let hits = pg
        .search_messages("w33d@w33d.xyz", &q_structured, None, None, 10)
        .await
        .unwrap();
    assert_eq!(hits.len(), 1, "structured predicates all match");
    assert_eq!(hits[0].id, msg.id);
    let q_or = parse_search_query("label:Receipts OR subject:nope");
    assert_eq!(
        pg.search_messages("w33d@w33d.xyz", &q_or, None, None, 10)
            .await
            .unwrap()
            .len(),
        1,
        "OR combines positives"
    );
    let q_exclude = parse_search_query("subject:PG -label:Receipts");
    assert!(
        pg.search_messages("w33d@w33d.xyz", &q_exclude, None, None, 10)
            .await
            .unwrap()
            .is_empty(),
        "negated predicates exclude"
    );
    // Ownership: a foreign mailbox's assign is a no-op; foreign message rejected too.
    pg.assign_label("alice@w33d.xyz", &msg.id, "lbl1")
        .await
        .unwrap();
    assert!(pg
        .labels_for_message("alice@w33d.xyz", &msg.id)
        .await
        .unwrap()
        .is_empty());
    // Remove one assignment; deleting the label cascades to the join.
    pg.remove_label("w33d@w33d.xyz", &msg.id, "lbl1")
        .await
        .unwrap();
    assert!(pg
        .labels_for_message("w33d@w33d.xyz", &msg.id)
        .await
        .unwrap()
        .is_empty());
    pg.assign_label("w33d@w33d.xyz", &msg.id, "lbl1")
        .await
        .unwrap();
    pg.delete_label("w33d@w33d.xyz", "lbl1").await.unwrap();
    assert!(pg.list_labels("w33d@w33d.xyz").await.unwrap().is_empty());
    assert!(
        pg.list_by_label("w33d@w33d.xyz", "lbl1", None, 10)
            .await
            .unwrap()
            .is_empty(),
        "label delete cascaded"
    );

    // A label-action filter rule round-trips its target_label.
    let lbl_rule = FilterRule {
        id: new_id("fr"),
        mailbox: "w33d@w33d.xyz".into(),
        position: 5,
        field: "from".into(),
        op: "contains".into(),
        needle: "biller".into(),
        action: "label".into(),
        target_folder: None,
        target_label: Some("lblZ".into()),
        enabled: true,
        created_at: now,
    };
    pg.add_rule(&lbl_rule).await.unwrap();
    let loaded = pg.list_rules("w33d@w33d.xyz").await.unwrap();
    assert!(loaded
        .iter()
        .any(|r| r.action == "label" && r.target_label.as_deref() == Some("lblZ")));

    for tbl in [
        "messages",
        "outbound_queue",
        "aliases",
        "filter_rules",
        "auto_reply_log",
        "send_identities",
        "contacts",
        "labels",
        "message_labels",
        "mailboxes",
    ] {
        sqlx_delete(&url, tbl).await;
    }
    println!("PG STORE INTEGRATION OK: mailboxes + messages + threading + identities + contacts + labels + rules/settings/auto-reply");
}

async fn sqlx_delete(url: &str, table: &str) {
    use sqlx::postgres::PgPoolOptions;
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(url)
        .await
        .unwrap();
    sqlx::query(&format!("DELETE FROM {table}"))
        .execute(&pool)
        .await
        .unwrap();
}
