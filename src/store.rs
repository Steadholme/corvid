//! Mail storage.
//!
//! `Store` mirrors the keystone/agora seam: a small async trait with an in-memory and a
//! PostgreSQL implementation, so handlers + the SMTP/relay paths depend only on the trait and
//! a FusionDB-backed store can drop in later. The PostgreSQL layer uses ONLY portable standard
//! SQL (TEXT/BIGINT/BOOLEAN, PRIMARY KEY/NOT NULL/DEFAULT, parameterized queries, plain
//! indexes) and runtime queries (no compile-time macros), so the build needs NO database and
//! the same statements later run unchanged on FusionDB over pgwire.
//!
//! The trait is async: callers `.await` it directly and `PgStore` drives sqlx natively, so a
//! DB round-trip never blocks a worker thread — NO `block_in_place`, NO sync-over-async. The
//! in-memory store never holds a lock across an `.await`.
//!
//! Tables (all standard SQL):
//! - `mailboxes(addr TEXT PK, owner_sub TEXT)`
//! - `messages(id TEXT PK, mailbox TEXT, msg_from TEXT, msg_to TEXT, subject TEXT,
//!    raw_rfc822 TEXT, body_text TEXT, body_html TEXT, received_at BIGINT,
//!    seen BOOLEAN DEFAULT FALSE, folder TEXT DEFAULT 'INBOX')`
//! - `outbound_queue(id TEXT PK, raw TEXT, env_from TEXT, rcpts TEXT, to_domain TEXT,
//!    attempts BIGINT, next_at BIGINT, status TEXT)`

use std::sync::Mutex;

use async_trait::async_trait;
use thiserror::Error;

use crate::model::{Alias, Mailbox, Message, MessageSummary, OutboundItem};

/// Storage failure surfaced to the caller (mapped to a 500 in the webmail layer).
#[derive(Debug, Error)]
pub enum StoreError {
    #[error("store error: {0}")]
    Backend(String),
}

/// Pluggable mail store. All methods are `async` and `.await`ed on the serving runtime.
#[async_trait]
pub trait Store: Send + Sync {
    /// Ensure a mailbox row exists (idempotent upsert; never clobbers `owner_sub` edits — it
    /// updates to the supplied owner). Used at startup to provision the primary mailbox.
    async fn upsert_mailbox(&self, mb: &Mailbox) -> Result<(), StoreError>;
    /// A mailbox by address, if it exists.
    async fn get_mailbox(&self, addr: &str) -> Result<Option<Mailbox>, StoreError>;
    /// The first mailbox owned by `owner_sub`, if any (webmail selects the inbox by SSO sub).
    async fn mailbox_for_owner(&self, owner_sub: &str) -> Result<Option<Mailbox>, StoreError>;
    /// Every provisioned mailbox, ordered by address (admin listing).
    async fn list_mailboxes(&self) -> Result<Vec<Mailbox>, StoreError>;
    /// Total message count across all folders for a mailbox (admin quota view).
    async fn message_count(&self, mailbox: &str) -> Result<i64, StoreError>;

    /// Upsert a mail alias (idempotent; re-points an existing local-part to `mailbox`).
    async fn add_alias(&self, alias: &Alias) -> Result<(), StoreError>;
    /// Every alias, ordered by local-part (admin listing).
    async fn list_aliases(&self) -> Result<Vec<Alias>, StoreError>;

    /// Persist a received/delivered message.
    async fn store_message(&self, msg: &Message) -> Result<(), StoreError>;
    /// Inbox listing for a mailbox, newest first, capped.
    async fn list_messages(
        &self,
        mailbox: &str,
        limit: i64,
    ) -> Result<Vec<MessageSummary>, StoreError>;
    /// Listing for a single folder within a mailbox, newest first, capped.
    async fn list_folder(
        &self,
        mailbox: &str,
        folder: &str,
        limit: i64,
    ) -> Result<Vec<MessageSummary>, StoreError>;
    /// A single message by id, if it exists.
    async fn get_message(&self, id: &str) -> Result<Option<Message>, StoreError>;
    /// Mark a message read.
    async fn mark_seen(&self, id: &str) -> Result<(), StoreError>;
    /// Mark a message unread.
    async fn mark_unseen(&self, id: &str) -> Result<(), StoreError>;
    /// Move a message into `folder`.
    async fn set_folder(&self, id: &str, folder: &str) -> Result<(), StoreError>;
    /// Unread count for the app-bar badge.
    async fn unseen_count(&self, mailbox: &str) -> Result<i64, StoreError>;

    /// Enqueue an outbound message for relay.
    async fn enqueue_outbound(&self, item: &OutboundItem) -> Result<(), StoreError>;
    /// Queued items whose `next_at <= now`, capped (the relay worker's work list).
    async fn due_outbound(&self, now: i64, limit: i64) -> Result<Vec<OutboundItem>, StoreError>;
    /// Mark an outbound item delivered.
    async fn mark_outbound_sent(&self, id: &str) -> Result<(), StoreError>;
    /// Bump attempts + reschedule a transient failure.
    async fn reschedule_outbound(
        &self,
        id: &str,
        attempts: i64,
        next_at: i64,
    ) -> Result<(), StoreError>;
    /// Mark an outbound item permanently failed (gave up).
    async fn fail_outbound(&self, id: &str) -> Result<(), StoreError>;
}

// --------------------------------------------------------------------------------------
// In-memory store (the default; keeps the whole service database-free for dev + tests).
// --------------------------------------------------------------------------------------

#[derive(Default)]
pub struct InMemoryStore {
    mailboxes: Mutex<Vec<Mailbox>>,
    messages: Mutex<Vec<Message>>,
    outbound: Mutex<Vec<OutboundItem>>,
    aliases: Mutex<Vec<Alias>>,
}

impl InMemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

fn summary(m: &Message) -> MessageSummary {
    MessageSummary {
        id: m.id.clone(),
        msg_from: m.msg_from.clone(),
        subject: m.subject.clone(),
        received_at: m.received_at,
        seen: m.seen,
    }
}

#[async_trait]
impl Store for InMemoryStore {
    // The std `Mutex` is fine throughout: each critical section is fully synchronous (no
    // `.await` inside), so a guard is never held across a yield point.
    async fn upsert_mailbox(&self, mb: &Mailbox) -> Result<(), StoreError> {
        let mut v = self.mailboxes.lock().expect("mailboxes lock poisoned");
        if let Some(existing) = v.iter_mut().find(|m| m.addr == mb.addr) {
            existing.owner_sub = mb.owner_sub.clone();
        } else {
            v.push(mb.clone());
        }
        Ok(())
    }

    async fn get_mailbox(&self, addr: &str) -> Result<Option<Mailbox>, StoreError> {
        Ok(self
            .mailboxes
            .lock()
            .expect("mailboxes lock poisoned")
            .iter()
            .find(|m| m.addr == addr)
            .cloned())
    }

    async fn mailbox_for_owner(&self, owner_sub: &str) -> Result<Option<Mailbox>, StoreError> {
        Ok(self
            .mailboxes
            .lock()
            .expect("mailboxes lock poisoned")
            .iter()
            .find(|m| m.owner_sub == owner_sub)
            .cloned())
    }

    async fn list_mailboxes(&self) -> Result<Vec<Mailbox>, StoreError> {
        let mut v: Vec<Mailbox> = self
            .mailboxes
            .lock()
            .expect("mailboxes lock poisoned")
            .clone();
        v.sort_by(|a, b| a.addr.cmp(&b.addr));
        Ok(v)
    }

    async fn message_count(&self, mailbox: &str) -> Result<i64, StoreError> {
        Ok(self
            .messages
            .lock()
            .expect("messages lock poisoned")
            .iter()
            .filter(|m| m.mailbox == mailbox)
            .count() as i64)
    }

    async fn add_alias(&self, alias: &Alias) -> Result<(), StoreError> {
        let mut v = self.aliases.lock().expect("aliases lock poisoned");
        if let Some(existing) = v.iter_mut().find(|a| a.local_part == alias.local_part) {
            existing.mailbox = alias.mailbox.clone();
        } else {
            v.push(alias.clone());
        }
        Ok(())
    }

    async fn list_aliases(&self) -> Result<Vec<Alias>, StoreError> {
        let mut v: Vec<Alias> = self.aliases.lock().expect("aliases lock poisoned").clone();
        v.sort_by(|a, b| a.local_part.cmp(&b.local_part));
        Ok(v)
    }

    async fn store_message(&self, msg: &Message) -> Result<(), StoreError> {
        self.messages
            .lock()
            .expect("messages lock poisoned")
            .push(msg.clone());
        Ok(())
    }

    async fn list_messages(
        &self,
        mailbox: &str,
        limit: i64,
    ) -> Result<Vec<MessageSummary>, StoreError> {
        let mut v: Vec<Message> = self
            .messages
            .lock()
            .expect("messages lock poisoned")
            .iter()
            .filter(|m| m.mailbox == mailbox)
            .cloned()
            .collect();
        v.sort_by(|a, b| b.received_at.cmp(&a.received_at).then_with(|| b.id.cmp(&a.id)));
        v.truncate(limit.max(0) as usize);
        Ok(v.iter().map(summary).collect())
    }

    async fn list_folder(
        &self,
        mailbox: &str,
        folder: &str,
        limit: i64,
    ) -> Result<Vec<MessageSummary>, StoreError> {
        let mut v: Vec<Message> = self
            .messages
            .lock()
            .expect("messages lock poisoned")
            .iter()
            .filter(|m| m.mailbox == mailbox && m.folder == folder)
            .cloned()
            .collect();
        v.sort_by(|a, b| b.received_at.cmp(&a.received_at).then_with(|| b.id.cmp(&a.id)));
        v.truncate(limit.max(0) as usize);
        Ok(v.iter().map(summary).collect())
    }

    async fn get_message(&self, id: &str) -> Result<Option<Message>, StoreError> {
        Ok(self
            .messages
            .lock()
            .expect("messages lock poisoned")
            .iter()
            .find(|m| m.id == id)
            .cloned())
    }

    async fn mark_seen(&self, id: &str) -> Result<(), StoreError> {
        let mut v = self.messages.lock().expect("messages lock poisoned");
        if let Some(m) = v.iter_mut().find(|m| m.id == id) {
            m.seen = true;
        }
        Ok(())
    }

    async fn mark_unseen(&self, id: &str) -> Result<(), StoreError> {
        let mut v = self.messages.lock().expect("messages lock poisoned");
        if let Some(m) = v.iter_mut().find(|m| m.id == id) {
            m.seen = false;
        }
        Ok(())
    }

    async fn set_folder(&self, id: &str, folder: &str) -> Result<(), StoreError> {
        let mut v = self.messages.lock().expect("messages lock poisoned");
        if let Some(m) = v.iter_mut().find(|m| m.id == id) {
            m.folder = folder.to_string();
        }
        Ok(())
    }

    async fn unseen_count(&self, mailbox: &str) -> Result<i64, StoreError> {
        Ok(self
            .messages
            .lock()
            .expect("messages lock poisoned")
            .iter()
            .filter(|m| m.mailbox == mailbox && !m.seen)
            .count() as i64)
    }

    async fn enqueue_outbound(&self, item: &OutboundItem) -> Result<(), StoreError> {
        self.outbound
            .lock()
            .expect("outbound lock poisoned")
            .push(item.clone());
        Ok(())
    }

    async fn due_outbound(&self, now: i64, limit: i64) -> Result<Vec<OutboundItem>, StoreError> {
        let mut v: Vec<OutboundItem> = self
            .outbound
            .lock()
            .expect("outbound lock poisoned")
            .iter()
            .filter(|o| o.status == "queued" && o.next_at <= now)
            .cloned()
            .collect();
        v.sort_by(|a, b| a.next_at.cmp(&b.next_at).then_with(|| a.id.cmp(&b.id)));
        v.truncate(limit.max(0) as usize);
        Ok(v)
    }

    async fn mark_outbound_sent(&self, id: &str) -> Result<(), StoreError> {
        let mut v = self.outbound.lock().expect("outbound lock poisoned");
        if let Some(o) = v.iter_mut().find(|o| o.id == id) {
            o.status = "sent".to_string();
        }
        Ok(())
    }

    async fn reschedule_outbound(
        &self,
        id: &str,
        attempts: i64,
        next_at: i64,
    ) -> Result<(), StoreError> {
        let mut v = self.outbound.lock().expect("outbound lock poisoned");
        if let Some(o) = v.iter_mut().find(|o| o.id == id) {
            o.attempts = attempts;
            o.next_at = next_at;
        }
        Ok(())
    }

    async fn fail_outbound(&self, id: &str) -> Result<(), StoreError> {
        let mut v = self.outbound.lock().expect("outbound lock poisoned");
        if let Some(o) = v.iter_mut().find(|o| o.id == id) {
            o.status = "failed".to_string();
        }
        Ok(())
    }
}

// --------------------------------------------------------------------------------------
// PostgreSQL-backed store (portable: standard SQL, runtime queries, no macros).
// --------------------------------------------------------------------------------------

use sqlx::postgres::{PgPool, PgPoolOptions};
use sqlx::Row;

/// PostgreSQL-backed [`Store`]. Holds just a `PgPool`; the async trait methods drive sqlx
/// natively, so no worker thread is ever blocked on a DB round-trip.
pub struct PgStore {
    pool: PgPool,
}

impl PgStore {
    /// Open a pooled connection. Async; call from within a Tokio runtime.
    pub async fn connect(database_url: &str) -> Result<Self, sqlx::Error> {
        let pool = PgPoolOptions::new()
            .max_connections(8)
            .connect(database_url)
            .await?;
        Ok(Self::from_pool(pool))
    }

    /// Construct from an existing pool (used by tests that share a pool).
    pub fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Idempotent, portable migration. Standard SQL only — safe to run on every startup.
    pub async fn migrate(&self) -> Result<(), sqlx::Error> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS mailboxes (\
                 addr TEXT PRIMARY KEY, \
                 owner_sub TEXT NOT NULL\
             )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS messages (\
                 id TEXT PRIMARY KEY, \
                 mailbox TEXT NOT NULL, \
                 msg_from TEXT NOT NULL DEFAULT '', \
                 msg_to TEXT NOT NULL DEFAULT '', \
                 subject TEXT NOT NULL DEFAULT '', \
                 raw_rfc822 TEXT NOT NULL, \
                 body_text TEXT NOT NULL DEFAULT '', \
                 body_html TEXT NOT NULL DEFAULT '', \
                 received_at BIGINT NOT NULL, \
                 seen BOOLEAN NOT NULL DEFAULT FALSE, \
                 folder TEXT NOT NULL DEFAULT 'INBOX'\
             )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_messages_mailbox ON messages (mailbox, received_at)")
            .execute(&self.pool)
            .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS outbound_queue (\
                 id TEXT PRIMARY KEY, \
                 raw TEXT NOT NULL, \
                 env_from TEXT NOT NULL DEFAULT '', \
                 rcpts TEXT NOT NULL DEFAULT '', \
                 to_domain TEXT NOT NULL, \
                 attempts BIGINT NOT NULL DEFAULT 0, \
                 next_at BIGINT NOT NULL DEFAULT 0, \
                 status TEXT NOT NULL DEFAULT 'queued'\
             )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_outbound_due ON outbound_queue (status, next_at)")
            .execute(&self.pool)
            .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS aliases (\
                 local_part TEXT PRIMARY KEY, \
                 mailbox TEXT NOT NULL\
             )",
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    fn mailbox_from_row(row: &sqlx::postgres::PgRow) -> Result<Mailbox, sqlx::Error> {
        Ok(Mailbox {
            addr: row.try_get("addr")?,
            owner_sub: row.try_get("owner_sub")?,
        })
    }

    fn alias_from_row(row: &sqlx::postgres::PgRow) -> Result<Alias, sqlx::Error> {
        Ok(Alias {
            local_part: row.try_get("local_part")?,
            mailbox: row.try_get("mailbox")?,
        })
    }

    fn message_from_row(row: &sqlx::postgres::PgRow) -> Result<Message, sqlx::Error> {
        Ok(Message {
            id: row.try_get("id")?,
            mailbox: row.try_get("mailbox")?,
            msg_from: row.try_get("msg_from")?,
            msg_to: row.try_get("msg_to")?,
            subject: row.try_get("subject")?,
            raw_rfc822: row.try_get("raw_rfc822")?,
            body_text: row.try_get("body_text")?,
            body_html: row.try_get("body_html")?,
            received_at: row.try_get("received_at")?,
            seen: row.try_get("seen")?,
            folder: row.try_get("folder")?,
        })
    }

    fn outbound_from_row(row: &sqlx::postgres::PgRow) -> Result<OutboundItem, sqlx::Error> {
        let rcpts: String = row.try_get("rcpts")?;
        Ok(OutboundItem {
            id: row.try_get("id")?,
            raw: row.try_get("raw")?,
            env_from: row.try_get("env_from")?,
            rcpts: rcpts.split(',').filter(|s| !s.is_empty()).map(str::to_string).collect(),
            to_domain: row.try_get("to_domain")?,
            attempts: row.try_get("attempts")?,
            next_at: row.try_get("next_at")?,
            status: row.try_get("status")?,
        })
    }
}

#[async_trait]
impl Store for PgStore {
    async fn upsert_mailbox(&self, mb: &Mailbox) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO mailboxes (addr, owner_sub) VALUES ($1, $2) \
             ON CONFLICT (addr) DO UPDATE SET owner_sub = EXCLUDED.owner_sub",
        )
        .bind(&mb.addr)
        .bind(&mb.owner_sub)
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        Ok(())
    }

    async fn get_mailbox(&self, addr: &str) -> Result<Option<Mailbox>, StoreError> {
        let row = sqlx::query("SELECT addr, owner_sub FROM mailboxes WHERE addr = $1")
            .bind(addr)
            .fetch_optional(&self.pool)
            .await
            .map_err(backend)?;
        row.as_ref().map(Self::mailbox_from_row).transpose().map_err(backend)
    }

    async fn mailbox_for_owner(&self, owner_sub: &str) -> Result<Option<Mailbox>, StoreError> {
        let row = sqlx::query(
            "SELECT addr, owner_sub FROM mailboxes WHERE owner_sub = $1 ORDER BY addr LIMIT 1",
        )
        .bind(owner_sub)
        .fetch_optional(&self.pool)
        .await
        .map_err(backend)?;
        row.as_ref().map(Self::mailbox_from_row).transpose().map_err(backend)
    }

    async fn list_mailboxes(&self) -> Result<Vec<Mailbox>, StoreError> {
        let rows = sqlx::query("SELECT addr, owner_sub FROM mailboxes ORDER BY addr ASC")
            .fetch_all(&self.pool)
            .await
            .map_err(backend)?;
        rows.iter()
            .map(Self::mailbox_from_row)
            .collect::<Result<Vec<_>, sqlx::Error>>()
            .map_err(backend)
    }

    async fn message_count(&self, mailbox: &str) -> Result<i64, StoreError> {
        let row = sqlx::query("SELECT COUNT(*) AS n FROM messages WHERE mailbox = $1")
            .bind(mailbox)
            .fetch_one(&self.pool)
            .await
            .map_err(backend)?;
        row.try_get("n").map_err(backend)
    }

    async fn add_alias(&self, alias: &Alias) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO aliases (local_part, mailbox) VALUES ($1, $2) \
             ON CONFLICT (local_part) DO UPDATE SET mailbox = EXCLUDED.mailbox",
        )
        .bind(&alias.local_part)
        .bind(&alias.mailbox)
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        Ok(())
    }

    async fn list_aliases(&self) -> Result<Vec<Alias>, StoreError> {
        let rows = sqlx::query("SELECT local_part, mailbox FROM aliases ORDER BY local_part ASC")
            .fetch_all(&self.pool)
            .await
            .map_err(backend)?;
        rows.iter()
            .map(Self::alias_from_row)
            .collect::<Result<Vec<_>, sqlx::Error>>()
            .map_err(backend)
    }

    async fn store_message(&self, msg: &Message) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO messages \
                 (id, mailbox, msg_from, msg_to, subject, raw_rfc822, body_text, body_html, \
                  received_at, seen, folder) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
        )
        .bind(&msg.id)
        .bind(&msg.mailbox)
        .bind(&msg.msg_from)
        .bind(&msg.msg_to)
        .bind(&msg.subject)
        .bind(&msg.raw_rfc822)
        .bind(&msg.body_text)
        .bind(&msg.body_html)
        .bind(msg.received_at)
        .bind(msg.seen)
        .bind(&msg.folder)
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        Ok(())
    }

    async fn list_messages(
        &self,
        mailbox: &str,
        limit: i64,
    ) -> Result<Vec<MessageSummary>, StoreError> {
        let rows = sqlx::query(
            "SELECT id, msg_from, subject, received_at, seen FROM messages \
             WHERE mailbox = $1 ORDER BY received_at DESC, id DESC LIMIT $2",
        )
        .bind(mailbox)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(backend)?;
        rows.iter()
            .map(|r| {
                Ok(MessageSummary {
                    id: r.try_get("id")?,
                    msg_from: r.try_get("msg_from")?,
                    subject: r.try_get("subject")?,
                    received_at: r.try_get("received_at")?,
                    seen: r.try_get("seen")?,
                })
            })
            .collect::<Result<Vec<_>, sqlx::Error>>()
            .map_err(backend)
    }

    async fn list_folder(
        &self,
        mailbox: &str,
        folder: &str,
        limit: i64,
    ) -> Result<Vec<MessageSummary>, StoreError> {
        let rows = sqlx::query(
            "SELECT id, msg_from, subject, received_at, seen FROM messages \
             WHERE mailbox = $1 AND folder = $2 ORDER BY received_at DESC, id DESC LIMIT $3",
        )
        .bind(mailbox)
        .bind(folder)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(backend)?;
        rows.iter()
            .map(|r| {
                Ok(MessageSummary {
                    id: r.try_get("id")?,
                    msg_from: r.try_get("msg_from")?,
                    subject: r.try_get("subject")?,
                    received_at: r.try_get("received_at")?,
                    seen: r.try_get("seen")?,
                })
            })
            .collect::<Result<Vec<_>, sqlx::Error>>()
            .map_err(backend)
    }

    async fn get_message(&self, id: &str) -> Result<Option<Message>, StoreError> {
        let row = sqlx::query(
            "SELECT id, mailbox, msg_from, msg_to, subject, raw_rfc822, body_text, body_html, \
                    received_at, seen, folder FROM messages WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(backend)?;
        row.as_ref().map(Self::message_from_row).transpose().map_err(backend)
    }

    async fn mark_seen(&self, id: &str) -> Result<(), StoreError> {
        sqlx::query("UPDATE messages SET seen = TRUE WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(backend)?;
        Ok(())
    }

    async fn mark_unseen(&self, id: &str) -> Result<(), StoreError> {
        sqlx::query("UPDATE messages SET seen = FALSE WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(backend)?;
        Ok(())
    }

    async fn set_folder(&self, id: &str, folder: &str) -> Result<(), StoreError> {
        sqlx::query("UPDATE messages SET folder = $1 WHERE id = $2")
            .bind(folder)
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(backend)?;
        Ok(())
    }

    async fn unseen_count(&self, mailbox: &str) -> Result<i64, StoreError> {
        let row = sqlx::query("SELECT COUNT(*) AS n FROM messages WHERE mailbox = $1 AND seen = FALSE")
            .bind(mailbox)
            .fetch_one(&self.pool)
            .await
            .map_err(backend)?;
        row.try_get("n").map_err(backend)
    }

    async fn enqueue_outbound(&self, item: &OutboundItem) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO outbound_queue \
                 (id, raw, env_from, rcpts, to_domain, attempts, next_at, status) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(&item.id)
        .bind(&item.raw)
        .bind(&item.env_from)
        .bind(item.rcpts.join(","))
        .bind(&item.to_domain)
        .bind(item.attempts)
        .bind(item.next_at)
        .bind(&item.status)
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        Ok(())
    }

    async fn due_outbound(&self, now: i64, limit: i64) -> Result<Vec<OutboundItem>, StoreError> {
        let rows = sqlx::query(
            "SELECT id, raw, env_from, rcpts, to_domain, attempts, next_at, status \
             FROM outbound_queue WHERE status = 'queued' AND next_at <= $1 \
             ORDER BY next_at ASC, id ASC LIMIT $2",
        )
        .bind(now)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(backend)?;
        rows.iter()
            .map(Self::outbound_from_row)
            .collect::<Result<Vec<_>, sqlx::Error>>()
            .map_err(backend)
    }

    async fn mark_outbound_sent(&self, id: &str) -> Result<(), StoreError> {
        sqlx::query("UPDATE outbound_queue SET status = 'sent' WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(backend)?;
        Ok(())
    }

    async fn reschedule_outbound(
        &self,
        id: &str,
        attempts: i64,
        next_at: i64,
    ) -> Result<(), StoreError> {
        sqlx::query("UPDATE outbound_queue SET attempts = $1, next_at = $2 WHERE id = $3")
            .bind(attempts)
            .bind(next_at)
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(backend)?;
        Ok(())
    }

    async fn fail_outbound(&self, id: &str) -> Result<(), StoreError> {
        sqlx::query("UPDATE outbound_queue SET status = 'failed' WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(backend)?;
        Ok(())
    }
}

/// Map an sqlx error into a [`StoreError`].
fn backend(e: sqlx::Error) -> StoreError {
    StoreError::Backend(e.to_string())
}
