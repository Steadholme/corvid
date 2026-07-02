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
//! - `filter_rules(id TEXT PK, mailbox TEXT, position BIGINT, field TEXT, op TEXT, needle TEXT,
//!    action TEXT, target_folder TEXT NULL, enabled BOOLEAN, created_at BIGINT)`
//! - `auto_reply_log(mailbox TEXT, sender TEXT, sent_at BIGINT, PK (mailbox, sender))`
//! - settings columns on `mailboxes` (signature, auto_reply_*), added idempotently.

use std::sync::Mutex;

use async_trait::async_trait;
use thiserror::Error;

use crate::model::{
    Alias, Contact, FilterRule, Label, Mailbox, MailboxSettings, Message, MessageSummary,
    OutboundItem, SendIdentity, ThreadSummary,
};

/// The auto-reply dedupe window: at most one auto-reply per `(mailbox, sender)` per 24 hours.
pub const AUTO_REPLY_DEDUPE_SECS: i64 = 86_400;

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
    /// Listing for a single folder within a mailbox, newest first, keyset-paginated: `before` is
    /// the `(received_at, id)` of the last row of the previous page (`None` for the first page).
    async fn list_folder(
        &self,
        mailbox: &str,
        folder: &str,
        before: Option<(i64, String)>,
        limit: i64,
    ) -> Result<Vec<MessageSummary>, StoreError>;
    /// Cross-folder listing of the starred/flagged messages in a mailbox, newest first,
    /// keyset-paginated like [`Store::list_folder`].
    async fn list_starred(
        &self,
        mailbox: &str,
        before: Option<(i64, String)>,
        limit: i64,
    ) -> Result<Vec<MessageSummary>, StoreError>;
    /// Search a mailbox over `From`/`To`/`Subject`/body (case-insensitive substring), newest
    /// first, optionally scoped to one `folder` (`None` searches the whole mailbox),
    /// keyset-paginated: `before` is the `(received_at, id)` of the last row of the previous page
    /// (`None` for the first page). `query` is matched lowercased.
    async fn search_messages(
        &self,
        mailbox: &str,
        query: &str,
        folder: Option<&str>,
        before: Option<(i64, String)>,
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
    /// Set/clear a message's star (flag).
    async fn set_starred(&self, id: &str, starred: bool) -> Result<(), StoreError>;
    /// Unread count for the app-bar badge.
    async fn unseen_count(&self, mailbox: &str) -> Result<i64, StoreError>;

    /// Every filter rule of a mailbox (enabled AND disabled), ordered by position ascending.
    /// Delivery filters on `enabled`; the settings UI lists them all.
    async fn list_rules(&self, mailbox: &str) -> Result<Vec<FilterRule>, StoreError>;
    /// Persist a new filter rule.
    async fn add_rule(&self, rule: &FilterRule) -> Result<(), StoreError>;
    /// Delete a rule by id, scoped to `mailbox` (a user only ever touches their own rules).
    async fn delete_rule(&self, mailbox: &str, id: &str) -> Result<(), StoreError>;
    /// Enable/disable a rule, scoped to `mailbox`.
    async fn set_rule_enabled(&self, mailbox: &str, id: &str, enabled: bool)
        -> Result<(), StoreError>;
    /// Reposition a rule, scoped to `mailbox` (the settings reorder renumbers via these).
    async fn set_rule_position(&self, mailbox: &str, id: &str, position: i64)
        -> Result<(), StoreError>;

    /// Per-mailbox settings (signature + auto-reply). All-defaults when never saved.
    async fn get_settings(&self, mailbox: &str) -> Result<MailboxSettings, StoreError>;
    /// Set the compose signature (empty clears it).
    async fn set_signature(&self, mailbox: &str, signature: &str) -> Result<(), StoreError>;
    /// Set the auto-reply (vacation) configuration (`until` of 0 = no expiry).
    async fn set_auto_reply(
        &self,
        mailbox: &str,
        enabled: bool,
        subject: &str,
        body: &str,
        until: i64,
    ) -> Result<(), StoreError>;
    /// Auto-reply dedupe check-and-record: returns `true` (and records `now`) when NO auto-reply
    /// went to `sender` within [`AUTO_REPLY_DEDUPE_SECS`]; `false` means the caller must not send.
    async fn mark_auto_replied(&self, mailbox: &str, sender: &str, now: i64)
        -> Result<bool, StoreError>;

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

    // --- Conversation threading -----------------------------------------------
    /// The `thread_id` of the earliest existing message in `mailbox` whose own `Message-ID` OR
    /// `thread_id` appears in `refs` (an incoming message's References/In-Reply-To ids). `None`
    /// when nothing links, so the caller roots a fresh thread. Empty `refs` => `None`.
    async fn find_thread_for_refs(
        &self,
        mailbox: &str,
        refs: &[String],
    ) -> Result<Option<String>, StoreError>;
    /// Collapsed conversations for one folder, newest-activity first, keyset-paginated on the
    /// representative (newest) message's `(received_at, id)` — the SAME cursor scheme as
    /// [`Store::list_folder`].
    async fn list_folder_threads(
        &self,
        mailbox: &str,
        folder: &str,
        before: Option<(i64, String)>,
        limit: i64,
    ) -> Result<Vec<ThreadSummary>, StoreError>;
    /// Every message of a conversation within `mailbox`, oldest first (natural reading order),
    /// capped at `limit`.
    async fn list_thread(
        &self,
        mailbox: &str,
        thread_id: &str,
        limit: i64,
    ) -> Result<Vec<Message>, StoreError>;

    // --- Send identities ------------------------------------------------------
    /// Every extra send identity a mailbox owns, ordered default-first then by address.
    async fn list_send_identities(&self, mailbox: &str) -> Result<Vec<SendIdentity>, StoreError>;
    /// Persist a new send identity.
    async fn add_send_identity(&self, identity: &SendIdentity) -> Result<(), StoreError>;
    /// Delete a send identity, scoped to `mailbox` (a user only ever touches their own).
    async fn delete_send_identity(&self, mailbox: &str, id: &str) -> Result<(), StoreError>;
    /// A single send identity by id, scoped to `mailbox` (ownership check on send).
    async fn get_send_identity(
        &self,
        mailbox: &str,
        id: &str,
    ) -> Result<Option<SendIdentity>, StoreError>;

    // --- Contacts -------------------------------------------------------------
    /// Upsert a correspondent for autocomplete: a `manual` upsert sets the manual flag; a
    /// harvested (non-manual) upsert bumps `seen_count`. A blank `name` never clobbers a stored one.
    async fn upsert_contact(
        &self,
        mailbox: &str,
        addr: &str,
        name: &str,
        manual: bool,
    ) -> Result<(), StoreError>;
    /// Autocomplete suggestions for `q` (matched case-insensitively over addr + name), manual
    /// contacts first then by frequency (`seen_count` desc), capped.
    async fn suggest_contacts(
        &self,
        mailbox: &str,
        q: &str,
        limit: i64,
    ) -> Result<Vec<Contact>, StoreError>;
    /// Delete a contact, scoped to `mailbox` (used to prune the list from settings).
    async fn delete_contact(&self, mailbox: &str, addr: &str) -> Result<(), StoreError>;

    // --- Labels ---------------------------------------------------------------
    /// Every label defined by a mailbox, ordered by name.
    async fn list_labels(&self, mailbox: &str) -> Result<Vec<Label>, StoreError>;
    /// Persist a new label.
    async fn add_label(&self, label: &Label) -> Result<(), StoreError>;
    /// Delete a label (and its assignments), scoped to `mailbox`.
    async fn delete_label(&self, mailbox: &str, id: &str) -> Result<(), StoreError>;
    /// Assign a label to a message — idempotent; a no-op unless BOTH the message and the label
    /// belong to `mailbox` (ownership enforced in the store).
    async fn assign_label(
        &self,
        mailbox: &str,
        message_id: &str,
        label_id: &str,
    ) -> Result<(), StoreError>;
    /// Remove a label from a message, scoped to `mailbox`.
    async fn remove_label(
        &self,
        mailbox: &str,
        message_id: &str,
        label_id: &str,
    ) -> Result<(), StoreError>;
    /// The labels currently on a message, scoped to `mailbox`, ordered by name.
    async fn labels_for_message(
        &self,
        mailbox: &str,
        message_id: &str,
    ) -> Result<Vec<Label>, StoreError>;
    /// Messages carrying `label_id` in `mailbox`, newest first, keyset-paginated like
    /// [`Store::list_folder`].
    async fn list_by_label(
        &self,
        mailbox: &str,
        label_id: &str,
        before: Option<(i64, String)>,
        limit: i64,
    ) -> Result<Vec<MessageSummary>, StoreError>;
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
    rules: Mutex<Vec<FilterRule>>,
    settings: Mutex<Vec<MailboxSettings>>,
    /// Auto-reply dedupe log entries: `(mailbox, sender, sent_at)`.
    auto_replies: Mutex<Vec<(String, String, i64)>>,
    send_identities: Mutex<Vec<SendIdentity>>,
    /// Contacts qualified by their owning mailbox: `(mailbox, contact)`.
    contacts: Mutex<Vec<(String, Contact)>>,
    labels: Mutex<Vec<Label>>,
    /// Message↔label assignments: `(mailbox, message_id, label_id)`.
    message_labels: Mutex<Vec<(String, String, String)>>,
}

impl InMemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

/// Keyset filter for the in-memory listings: keep only rows strictly older than the cursor
/// (by `(received_at, id)` descending), i.e. the page AFTER the one that ended at `before`.
fn apply_before(v: &mut Vec<Message>, before: Option<(i64, String)>) {
    if let Some((ts, id)) = before {
        v.retain(|m| m.received_at < ts || (m.received_at == ts && m.id < id));
    }
}

fn summary(m: &Message) -> MessageSummary {
    MessageSummary {
        id: m.id.clone(),
        msg_from: m.msg_from.clone(),
        subject: m.subject.clone(),
        received_at: m.received_at,
        seen: m.seen,
        starred: m.starred,
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
        before: Option<(i64, String)>,
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
        apply_before(&mut v, before);
        v.truncate(limit.max(0) as usize);
        Ok(v.iter().map(summary).collect())
    }

    async fn list_starred(
        &self,
        mailbox: &str,
        before: Option<(i64, String)>,
        limit: i64,
    ) -> Result<Vec<MessageSummary>, StoreError> {
        let mut v: Vec<Message> = self
            .messages
            .lock()
            .expect("messages lock poisoned")
            .iter()
            .filter(|m| m.mailbox == mailbox && m.starred)
            .cloned()
            .collect();
        v.sort_by(|a, b| b.received_at.cmp(&a.received_at).then_with(|| b.id.cmp(&a.id)));
        apply_before(&mut v, before);
        v.truncate(limit.max(0) as usize);
        Ok(v.iter().map(summary).collect())
    }

    async fn search_messages(
        &self,
        mailbox: &str,
        query: &str,
        folder: Option<&str>,
        before: Option<(i64, String)>,
        limit: i64,
    ) -> Result<Vec<MessageSummary>, StoreError> {
        let needle = query.to_lowercase();
        let mut v: Vec<Message> = self
            .messages
            .lock()
            .expect("messages lock poisoned")
            .iter()
            .filter(|m| {
                m.mailbox == mailbox
                    && folder.map_or(true, |f| m.folder == f)
                    && (m.msg_from.to_lowercase().contains(&needle)
                        || m.msg_to.to_lowercase().contains(&needle)
                        || m.subject.to_lowercase().contains(&needle)
                        || m.body_text.to_lowercase().contains(&needle))
            })
            .cloned()
            .collect();
        v.sort_by(|a, b| b.received_at.cmp(&a.received_at).then_with(|| b.id.cmp(&a.id)));
        apply_before(&mut v, before);
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

    async fn set_starred(&self, id: &str, starred: bool) -> Result<(), StoreError> {
        let mut v = self.messages.lock().expect("messages lock poisoned");
        if let Some(m) = v.iter_mut().find(|m| m.id == id) {
            m.starred = starred;
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

    async fn list_rules(&self, mailbox: &str) -> Result<Vec<FilterRule>, StoreError> {
        let mut v: Vec<FilterRule> = self
            .rules
            .lock()
            .expect("rules lock poisoned")
            .iter()
            .filter(|r| r.mailbox == mailbox)
            .cloned()
            .collect();
        v.sort_by(|a, b| a.position.cmp(&b.position).then_with(|| a.id.cmp(&b.id)));
        Ok(v)
    }

    async fn add_rule(&self, rule: &FilterRule) -> Result<(), StoreError> {
        self.rules
            .lock()
            .expect("rules lock poisoned")
            .push(rule.clone());
        Ok(())
    }

    async fn delete_rule(&self, mailbox: &str, id: &str) -> Result<(), StoreError> {
        self.rules
            .lock()
            .expect("rules lock poisoned")
            .retain(|r| !(r.mailbox == mailbox && r.id == id));
        Ok(())
    }

    async fn set_rule_enabled(
        &self,
        mailbox: &str,
        id: &str,
        enabled: bool,
    ) -> Result<(), StoreError> {
        let mut v = self.rules.lock().expect("rules lock poisoned");
        if let Some(r) = v.iter_mut().find(|r| r.mailbox == mailbox && r.id == id) {
            r.enabled = enabled;
        }
        Ok(())
    }

    async fn set_rule_position(
        &self,
        mailbox: &str,
        id: &str,
        position: i64,
    ) -> Result<(), StoreError> {
        let mut v = self.rules.lock().expect("rules lock poisoned");
        if let Some(r) = v.iter_mut().find(|r| r.mailbox == mailbox && r.id == id) {
            r.position = position;
        }
        Ok(())
    }

    async fn get_settings(&self, mailbox: &str) -> Result<MailboxSettings, StoreError> {
        Ok(self
            .settings
            .lock()
            .expect("settings lock poisoned")
            .iter()
            .find(|s| s.mailbox == mailbox)
            .cloned()
            .unwrap_or_else(|| MailboxSettings::default_for(mailbox)))
    }

    async fn set_signature(&self, mailbox: &str, signature: &str) -> Result<(), StoreError> {
        let mut v = self.settings.lock().expect("settings lock poisoned");
        if let Some(s) = v.iter_mut().find(|s| s.mailbox == mailbox) {
            s.signature = signature.to_string();
        } else {
            let mut s = MailboxSettings::default_for(mailbox);
            s.signature = signature.to_string();
            v.push(s);
        }
        Ok(())
    }

    async fn set_auto_reply(
        &self,
        mailbox: &str,
        enabled: bool,
        subject: &str,
        body: &str,
        until: i64,
    ) -> Result<(), StoreError> {
        let mut v = self.settings.lock().expect("settings lock poisoned");
        let s = match v.iter_mut().find(|s| s.mailbox == mailbox) {
            Some(s) => s,
            None => {
                v.push(MailboxSettings::default_for(mailbox));
                v.last_mut().expect("just pushed")
            }
        };
        s.auto_reply_enabled = enabled;
        s.auto_reply_subject = subject.to_string();
        s.auto_reply_body = body.to_string();
        s.auto_reply_until = until;
        Ok(())
    }

    async fn mark_auto_replied(
        &self,
        mailbox: &str,
        sender: &str,
        now: i64,
    ) -> Result<bool, StoreError> {
        let mut v = self.auto_replies.lock().expect("auto_replies lock poisoned");
        if let Some((_, _, sent_at)) =
            v.iter_mut().find(|(m, s, _)| m == mailbox && s == sender)
        {
            if now - *sent_at < AUTO_REPLY_DEDUPE_SECS {
                return Ok(false);
            }
            *sent_at = now;
        } else {
            v.push((mailbox.to_string(), sender.to_string(), now));
        }
        Ok(true)
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

    async fn find_thread_for_refs(
        &self,
        mailbox: &str,
        refs: &[String],
    ) -> Result<Option<String>, StoreError> {
        if refs.is_empty() {
            return Ok(None);
        }
        let mut candidates: Vec<Message> = self
            .messages
            .lock()
            .expect("messages lock poisoned")
            .iter()
            .filter(|m| {
                m.mailbox == mailbox
                    && (refs.iter().any(|r| r == &m.message_id && !m.message_id.is_empty())
                        || refs.iter().any(|r| r == &m.thread_id && !m.thread_id.is_empty()))
            })
            .cloned()
            .collect();
        // Earliest existing message wins (stable thread root).
        candidates.sort_by(|a, b| a.received_at.cmp(&b.received_at).then_with(|| a.id.cmp(&b.id)));
        Ok(candidates
            .into_iter()
            .map(|m| m.thread_id)
            .find(|t| !t.is_empty()))
    }

    async fn list_folder_threads(
        &self,
        mailbox: &str,
        folder: &str,
        before: Option<(i64, String)>,
        limit: i64,
    ) -> Result<Vec<ThreadSummary>, StoreError> {
        let msgs: Vec<Message> = self
            .messages
            .lock()
            .expect("messages lock poisoned")
            .iter()
            .filter(|m| m.mailbox == mailbox && m.folder == folder)
            .cloned()
            .collect();
        // Group by thread_id (empty thread_id => the message is its own singleton, keyed by id).
        let mut groups: std::collections::HashMap<String, Vec<Message>> = std::collections::HashMap::new();
        for m in msgs {
            let key = if m.thread_id.is_empty() { format!("m:{}", m.id) } else { m.thread_id.clone() };
            groups.entry(key).or_default().push(m);
        }
        let mut threads: Vec<ThreadSummary> = groups
            .into_iter()
            .map(|(key, mut group)| {
                group.sort_by(|a, b| {
                    b.received_at.cmp(&a.received_at).then_with(|| b.id.cmp(&a.id))
                });
                let latest = &group[0];
                let unseen = group.iter().filter(|m| !m.seen).count() as i64;
                ThreadSummary {
                    thread_id: if latest.thread_id.is_empty() { key } else { latest.thread_id.clone() },
                    latest: summary(latest),
                    count: group.len() as i64,
                    unseen,
                }
            })
            .collect();
        threads.sort_by(|a, b| {
            b.latest
                .received_at
                .cmp(&a.latest.received_at)
                .then_with(|| b.latest.id.cmp(&a.latest.id))
        });
        if let Some((ts, id)) = before {
            threads.retain(|t| {
                t.latest.received_at < ts || (t.latest.received_at == ts && t.latest.id < id)
            });
        }
        threads.truncate(limit.max(0) as usize);
        Ok(threads)
    }

    async fn list_thread(
        &self,
        mailbox: &str,
        thread_id: &str,
        limit: i64,
    ) -> Result<Vec<Message>, StoreError> {
        let mut v: Vec<Message> = self
            .messages
            .lock()
            .expect("messages lock poisoned")
            .iter()
            .filter(|m| m.mailbox == mailbox && m.thread_id == thread_id)
            .cloned()
            .collect();
        v.sort_by(|a, b| a.received_at.cmp(&b.received_at).then_with(|| a.id.cmp(&b.id)));
        v.truncate(limit.max(0) as usize);
        Ok(v)
    }

    async fn list_send_identities(&self, mailbox: &str) -> Result<Vec<SendIdentity>, StoreError> {
        let mut v: Vec<SendIdentity> = self
            .send_identities
            .lock()
            .expect("send_identities lock poisoned")
            .iter()
            .filter(|i| i.mailbox == mailbox)
            .cloned()
            .collect();
        v.sort_by(|a, b| {
            b.is_default
                .cmp(&a.is_default)
                .then_with(|| a.from_addr.cmp(&b.from_addr))
        });
        Ok(v)
    }

    async fn add_send_identity(&self, identity: &SendIdentity) -> Result<(), StoreError> {
        self.send_identities
            .lock()
            .expect("send_identities lock poisoned")
            .push(identity.clone());
        Ok(())
    }

    async fn delete_send_identity(&self, mailbox: &str, id: &str) -> Result<(), StoreError> {
        self.send_identities
            .lock()
            .expect("send_identities lock poisoned")
            .retain(|i| !(i.mailbox == mailbox && i.id == id));
        Ok(())
    }

    async fn get_send_identity(
        &self,
        mailbox: &str,
        id: &str,
    ) -> Result<Option<SendIdentity>, StoreError> {
        Ok(self
            .send_identities
            .lock()
            .expect("send_identities lock poisoned")
            .iter()
            .find(|i| i.mailbox == mailbox && i.id == id)
            .cloned())
    }

    async fn upsert_contact(
        &self,
        mailbox: &str,
        addr: &str,
        name: &str,
        manual: bool,
    ) -> Result<(), StoreError> {
        let addr_l = addr.trim().to_lowercase();
        if addr_l.is_empty() {
            return Ok(());
        }
        let mut v = self.contacts.lock().expect("contacts lock poisoned");
        if let Some((_, c)) = v.iter_mut().find(|(mb, c)| mb == mailbox && c.addr == addr_l) {
            if !name.trim().is_empty() {
                c.name = name.trim().to_string();
            }
            if manual {
                c.manual = true;
            } else {
                c.seen_count += 1;
            }
        } else {
            v.push((
                mailbox.to_string(),
                Contact {
                    addr: addr_l,
                    name: name.trim().to_string(),
                    manual,
                    seen_count: if manual { 0 } else { 1 },
                },
            ));
        }
        Ok(())
    }

    async fn suggest_contacts(
        &self,
        mailbox: &str,
        q: &str,
        limit: i64,
    ) -> Result<Vec<Contact>, StoreError> {
        let needle = q.trim().to_lowercase();
        let mut v: Vec<Contact> = self
            .contacts
            .lock()
            .expect("contacts lock poisoned")
            .iter()
            .filter(|(mb, _)| mb == mailbox)
            .filter(|(_, c)| {
                needle.is_empty()
                    || c.addr.contains(&needle)
                    || c.name.to_lowercase().contains(&needle)
            })
            .map(|(_, c)| c.clone())
            .collect();
        v.sort_by(|a, b| {
            b.manual
                .cmp(&a.manual)
                .then_with(|| b.seen_count.cmp(&a.seen_count))
                .then_with(|| a.addr.cmp(&b.addr))
        });
        v.truncate(limit.max(0) as usize);
        Ok(v)
    }

    async fn delete_contact(&self, mailbox: &str, addr: &str) -> Result<(), StoreError> {
        let addr_l = addr.trim().to_lowercase();
        self.contacts
            .lock()
            .expect("contacts lock poisoned")
            .retain(|(mb, c)| !(mb == mailbox && c.addr == addr_l));
        Ok(())
    }

    async fn list_labels(&self, mailbox: &str) -> Result<Vec<Label>, StoreError> {
        let mut v: Vec<Label> = self
            .labels
            .lock()
            .expect("labels lock poisoned")
            .iter()
            .filter(|l| l.mailbox == mailbox)
            .cloned()
            .collect();
        v.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()).then_with(|| a.id.cmp(&b.id)));
        Ok(v)
    }

    async fn add_label(&self, label: &Label) -> Result<(), StoreError> {
        self.labels.lock().expect("labels lock poisoned").push(label.clone());
        Ok(())
    }

    async fn delete_label(&self, mailbox: &str, id: &str) -> Result<(), StoreError> {
        self.labels
            .lock()
            .expect("labels lock poisoned")
            .retain(|l| !(l.mailbox == mailbox && l.id == id));
        self.message_labels
            .lock()
            .expect("message_labels lock poisoned")
            .retain(|(mb, _, lid)| !(mb == mailbox && lid == id));
        Ok(())
    }

    async fn assign_label(
        &self,
        mailbox: &str,
        message_id: &str,
        label_id: &str,
    ) -> Result<(), StoreError> {
        // Ownership: both the message and the label must belong to `mailbox`.
        let owns_msg = self
            .messages
            .lock()
            .expect("messages lock poisoned")
            .iter()
            .any(|m| m.id == message_id && m.mailbox == mailbox);
        let owns_label = self
            .labels
            .lock()
            .expect("labels lock poisoned")
            .iter()
            .any(|l| l.id == label_id && l.mailbox == mailbox);
        if !(owns_msg && owns_label) {
            return Ok(());
        }
        let mut v = self.message_labels.lock().expect("message_labels lock poisoned");
        if !v.iter().any(|(mb, m, l)| mb == mailbox && m == message_id && l == label_id) {
            v.push((mailbox.to_string(), message_id.to_string(), label_id.to_string()));
        }
        Ok(())
    }

    async fn remove_label(
        &self,
        mailbox: &str,
        message_id: &str,
        label_id: &str,
    ) -> Result<(), StoreError> {
        self.message_labels
            .lock()
            .expect("message_labels lock poisoned")
            .retain(|(mb, m, l)| !(mb == mailbox && m == message_id && l == label_id));
        Ok(())
    }

    async fn labels_for_message(
        &self,
        mailbox: &str,
        message_id: &str,
    ) -> Result<Vec<Label>, StoreError> {
        let ids: Vec<String> = self
            .message_labels
            .lock()
            .expect("message_labels lock poisoned")
            .iter()
            .filter(|(mb, m, _)| mb == mailbox && m == message_id)
            .map(|(_, _, l)| l.clone())
            .collect();
        let mut v: Vec<Label> = self
            .labels
            .lock()
            .expect("labels lock poisoned")
            .iter()
            .filter(|l| l.mailbox == mailbox && ids.iter().any(|id| id == &l.id))
            .cloned()
            .collect();
        v.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()).then_with(|| a.id.cmp(&b.id)));
        Ok(v)
    }

    async fn list_by_label(
        &self,
        mailbox: &str,
        label_id: &str,
        before: Option<(i64, String)>,
        limit: i64,
    ) -> Result<Vec<MessageSummary>, StoreError> {
        let msg_ids: Vec<String> = self
            .message_labels
            .lock()
            .expect("message_labels lock poisoned")
            .iter()
            .filter(|(mb, _, l)| mb == mailbox && l == label_id)
            .map(|(_, m, _)| m.clone())
            .collect();
        let mut v: Vec<Message> = self
            .messages
            .lock()
            .expect("messages lock poisoned")
            .iter()
            .filter(|m| m.mailbox == mailbox && msg_ids.iter().any(|id| id == &m.id))
            .cloned()
            .collect();
        v.sort_by(|a, b| b.received_at.cmp(&a.received_at).then_with(|| b.id.cmp(&a.id)));
        apply_before(&mut v, before);
        v.truncate(limit.max(0) as usize);
        Ok(v.iter().map(summary).collect())
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
        // Star/flag: added out-of-band (idempotent) so an already-provisioned `messages` table
        // gains the column without a destructive rebuild. Nullable (existing rows read as unset).
        sqlx::query("ALTER TABLE messages ADD COLUMN IF NOT EXISTS starred BOOLEAN DEFAULT FALSE")
            .execute(&self.pool)
            .await?;
        // Conversation threading: the computed `thread_id` (grouping key) and the message's own
        // `Message-ID` (referenced by inbound replies). Both nullable — pre-threading rows read as
        // empty (an ungrouped singleton), so every existing listing behaves byte-identically.
        sqlx::query("ALTER TABLE messages ADD COLUMN IF NOT EXISTS thread_id TEXT")
            .execute(&self.pool)
            .await?;
        sqlx::query("ALTER TABLE messages ADD COLUMN IF NOT EXISTS message_id TEXT")
            .execute(&self.pool)
            .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_messages_thread ON messages (mailbox, thread_id, received_at)")
            .execute(&self.pool)
            .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_messages_msgid ON messages (mailbox, message_id)")
            .execute(&self.pool)
            .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_messages_mailbox ON messages (mailbox, received_at)")
            .execute(&self.pool)
            .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_messages_starred ON messages (mailbox, starred, received_at)")
            .execute(&self.pool)
            .await?;
        // Keyset-pagination path: matches `ORDER BY received_at DESC, id DESC` within a mailbox
        // exactly, so each listing page is a single index range scan.
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_messages_mailbox_keyset ON messages (mailbox, received_at DESC, id DESC)")
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
        // Per-mailbox settings (signature + auto-reply): added out-of-band (idempotent) so an
        // already-provisioned `mailboxes` table gains the columns without a destructive rebuild.
        // Nullable — pre-migration rows read as the defaults (empty / off / no expiry).
        for stmt in [
            "ALTER TABLE mailboxes ADD COLUMN IF NOT EXISTS signature TEXT",
            "ALTER TABLE mailboxes ADD COLUMN IF NOT EXISTS auto_reply_enabled BOOLEAN DEFAULT FALSE",
            "ALTER TABLE mailboxes ADD COLUMN IF NOT EXISTS auto_reply_subject TEXT",
            "ALTER TABLE mailboxes ADD COLUMN IF NOT EXISTS auto_reply_body TEXT",
            "ALTER TABLE mailboxes ADD COLUMN IF NOT EXISTS auto_reply_until BIGINT",
        ] {
            sqlx::query(stmt).execute(&self.pool).await?;
        }
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS filter_rules (\
                 id TEXT PRIMARY KEY, \
                 mailbox TEXT NOT NULL, \
                 position BIGINT NOT NULL DEFAULT 0, \
                 field TEXT NOT NULL, \
                 op TEXT NOT NULL, \
                 needle TEXT NOT NULL DEFAULT '', \
                 action TEXT NOT NULL, \
                 target_folder TEXT, \
                 enabled BOOLEAN NOT NULL DEFAULT TRUE, \
                 created_at BIGINT NOT NULL DEFAULT 0\
             )",
        )
        .execute(&self.pool)
        .await?;
        // `action = label` target: added out-of-band (idempotent). Nullable — existing rules read
        // it as NULL (they carry no label target), so their behaviour is unchanged.
        sqlx::query("ALTER TABLE filter_rules ADD COLUMN IF NOT EXISTS target_label TEXT")
            .execute(&self.pool)
            .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_filter_rules_mailbox ON filter_rules (mailbox, position)")
            .execute(&self.pool)
            .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS auto_reply_log (\
                 mailbox TEXT NOT NULL, \
                 sender TEXT NOT NULL, \
                 sent_at BIGINT NOT NULL, \
                 PRIMARY KEY (mailbox, sender)\
             )",
        )
        .execute(&self.pool)
        .await?;
        // Additional outbound "From" identities a mailbox owns (extra aliases it may send as).
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS send_identities (\
                 id TEXT PRIMARY KEY, \
                 mailbox TEXT NOT NULL, \
                 from_addr TEXT NOT NULL, \
                 display_name TEXT NOT NULL DEFAULT '', \
                 is_default BOOLEAN NOT NULL DEFAULT FALSE\
             )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_send_identities_mailbox ON send_identities (mailbox)")
            .execute(&self.pool)
            .await?;
        // Contacts (harvested correspondents + manual), keyed `(mailbox, addr)` for upsert.
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS contacts (\
                 mailbox TEXT NOT NULL, \
                 addr TEXT NOT NULL, \
                 name TEXT NOT NULL DEFAULT '', \
                 manual BOOLEAN NOT NULL DEFAULT FALSE, \
                 seen_count BIGINT NOT NULL DEFAULT 0, \
                 PRIMARY KEY (mailbox, addr)\
             )",
        )
        .execute(&self.pool)
        .await?;
        // User-defined labels + the message↔label join (labels are orthogonal to folders).
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS labels (\
                 id TEXT PRIMARY KEY, \
                 mailbox TEXT NOT NULL, \
                 name TEXT NOT NULL, \
                 color TEXT NOT NULL DEFAULT ''\
             )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_labels_mailbox ON labels (mailbox, name)")
            .execute(&self.pool)
            .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS message_labels (\
                 mailbox TEXT NOT NULL, \
                 message_id TEXT NOT NULL, \
                 label_id TEXT NOT NULL, \
                 PRIMARY KEY (message_id, label_id)\
             )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_message_labels_label ON message_labels (mailbox, label_id)")
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

    fn rule_from_row(row: &sqlx::postgres::PgRow) -> Result<FilterRule, sqlx::Error> {
        Ok(FilterRule {
            id: row.try_get("id")?,
            mailbox: row.try_get("mailbox")?,
            position: row.try_get("position")?,
            field: row.try_get("field")?,
            op: row.try_get("op")?,
            needle: row.try_get("needle")?,
            action: row.try_get("action")?,
            target_folder: row.try_get("target_folder")?,
            target_label: row.try_get::<Option<String>, _>("target_label")?,
            enabled: row.try_get("enabled")?,
            created_at: row.try_get("created_at")?,
        })
    }

    /// Map the (nullable, post-migration) settings columns of a `mailboxes` row.
    fn settings_from_row(
        mailbox: &str,
        row: &sqlx::postgres::PgRow,
    ) -> Result<MailboxSettings, sqlx::Error> {
        Ok(MailboxSettings {
            mailbox: mailbox.to_string(),
            signature: row.try_get::<Option<String>, _>("signature")?.unwrap_or_default(),
            auto_reply_enabled: row
                .try_get::<Option<bool>, _>("auto_reply_enabled")?
                .unwrap_or(false),
            auto_reply_subject: row
                .try_get::<Option<String>, _>("auto_reply_subject")?
                .unwrap_or_default(),
            auto_reply_body: row
                .try_get::<Option<String>, _>("auto_reply_body")?
                .unwrap_or_default(),
            auto_reply_until: row
                .try_get::<Option<i64>, _>("auto_reply_until")?
                .unwrap_or(0),
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
            // Nullable column (pre-migration rows are NULL) — read as Option, default unset.
            starred: row.try_get::<Option<bool>, _>("starred")?.unwrap_or(false),
            thread_id: row.try_get::<Option<String>, _>("thread_id")?.unwrap_or_default(),
            message_id: row.try_get::<Option<String>, _>("message_id")?.unwrap_or_default(),
        })
    }

    /// The keyset cursor, defaulted to "newer than any real row" so the first page is unbounded.
    /// The id tie-break only fires when `received_at` equals the cursor ts, so the empty id never
    /// matches a real (non-empty) id when ts == `i64::MAX`.
    fn cursor(before: Option<(i64, String)>) -> (i64, String) {
        before.unwrap_or((i64::MAX, String::new()))
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

    fn identity_from_row(row: &sqlx::postgres::PgRow) -> Result<SendIdentity, sqlx::Error> {
        Ok(SendIdentity {
            id: row.try_get("id")?,
            mailbox: row.try_get("mailbox")?,
            from_addr: row.try_get("from_addr")?,
            display_name: row.try_get("display_name")?,
            is_default: row.try_get("is_default")?,
        })
    }

    fn contact_from_row(row: &sqlx::postgres::PgRow) -> Result<Contact, sqlx::Error> {
        Ok(Contact {
            addr: row.try_get("addr")?,
            name: row.try_get("name")?,
            manual: row.try_get("manual")?,
            seen_count: row.try_get("seen_count")?,
        })
    }

    fn label_from_row(row: &sqlx::postgres::PgRow) -> Result<Label, sqlx::Error> {
        Ok(Label {
            id: row.try_get("id")?,
            mailbox: row.try_get("mailbox")?,
            name: row.try_get("name")?,
            color: row.try_get("color")?,
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
                  received_at, seen, folder, starred, thread_id, message_id) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)",
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
        .bind(msg.starred)
        .bind(&msg.thread_id)
        .bind(&msg.message_id)
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
            "SELECT id, msg_from, subject, received_at, seen, starred FROM messages \
             WHERE mailbox = $1 ORDER BY received_at DESC, id DESC LIMIT $2",
        )
        .bind(mailbox)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(backend)?;
        rows.iter()
            .map(summary_from_row)
            .collect::<Result<Vec<_>, sqlx::Error>>()
            .map_err(backend)
    }

    async fn list_folder(
        &self,
        mailbox: &str,
        folder: &str,
        before: Option<(i64, String)>,
        limit: i64,
    ) -> Result<Vec<MessageSummary>, StoreError> {
        let (cur_ts, cur_id) = Self::cursor(before);
        let rows = sqlx::query(
            "SELECT id, msg_from, subject, received_at, seen, starred FROM messages \
             WHERE mailbox = $1 AND folder = $2 \
               AND (received_at < $3 OR (received_at = $3 AND id < $4)) \
             ORDER BY received_at DESC, id DESC LIMIT $5",
        )
        .bind(mailbox)
        .bind(folder)
        .bind(cur_ts)
        .bind(&cur_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(backend)?;
        rows.iter()
            .map(summary_from_row)
            .collect::<Result<Vec<_>, sqlx::Error>>()
            .map_err(backend)
    }

    async fn list_starred(
        &self,
        mailbox: &str,
        before: Option<(i64, String)>,
        limit: i64,
    ) -> Result<Vec<MessageSummary>, StoreError> {
        let (cur_ts, cur_id) = Self::cursor(before);
        let rows = sqlx::query(
            "SELECT id, msg_from, subject, received_at, seen, starred FROM messages \
             WHERE mailbox = $1 AND starred = TRUE \
               AND (received_at < $2 OR (received_at = $2 AND id < $3)) \
             ORDER BY received_at DESC, id DESC LIMIT $4",
        )
        .bind(mailbox)
        .bind(cur_ts)
        .bind(&cur_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(backend)?;
        rows.iter()
            .map(summary_from_row)
            .collect::<Result<Vec<_>, sqlx::Error>>()
            .map_err(backend)
    }

    async fn search_messages(
        &self,
        mailbox: &str,
        query: &str,
        folder: Option<&str>,
        before: Option<(i64, String)>,
        limit: i64,
    ) -> Result<Vec<MessageSummary>, StoreError> {
        // `%needle%` with LIKE special chars escaped; matched case-insensitively via LOWER().
        let pattern = format!("%{}%", like_escape(&query.to_lowercase()));
        // Optional folder scope: the empty string means "whole mailbox" ('' is never a folder).
        let scope = folder.unwrap_or("");
        let (cur_ts, cur_id) = Self::cursor(before);
        let rows = sqlx::query(
            "SELECT id, msg_from, subject, received_at, seen, starred FROM messages \
             WHERE mailbox = $1 \
               AND (LOWER(msg_from) LIKE $2 ESCAPE '\\' \
                    OR LOWER(msg_to) LIKE $2 ESCAPE '\\' \
                    OR LOWER(subject) LIKE $2 ESCAPE '\\' \
                    OR LOWER(body_text) LIKE $2 ESCAPE '\\') \
               AND ($3 = '' OR folder = $3) \
               AND (received_at < $4 OR (received_at = $4 AND id < $5)) \
             ORDER BY received_at DESC, id DESC LIMIT $6",
        )
        .bind(mailbox)
        .bind(&pattern)
        .bind(scope)
        .bind(cur_ts)
        .bind(&cur_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(backend)?;
        rows.iter()
            .map(summary_from_row)
            .collect::<Result<Vec<_>, sqlx::Error>>()
            .map_err(backend)
    }

    async fn get_message(&self, id: &str) -> Result<Option<Message>, StoreError> {
        let row = sqlx::query(
            "SELECT id, mailbox, msg_from, msg_to, subject, raw_rfc822, body_text, body_html, \
                    received_at, seen, folder, starred, thread_id, message_id \
             FROM messages WHERE id = $1",
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

    async fn set_starred(&self, id: &str, starred: bool) -> Result<(), StoreError> {
        sqlx::query("UPDATE messages SET starred = $1 WHERE id = $2")
            .bind(starred)
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

    async fn list_rules(&self, mailbox: &str) -> Result<Vec<FilterRule>, StoreError> {
        let rows = sqlx::query(
            "SELECT id, mailbox, position, field, op, needle, action, target_folder, target_label, \
                    enabled, created_at \
             FROM filter_rules WHERE mailbox = $1 ORDER BY position ASC, id ASC",
        )
        .bind(mailbox)
        .fetch_all(&self.pool)
        .await
        .map_err(backend)?;
        rows.iter()
            .map(Self::rule_from_row)
            .collect::<Result<Vec<_>, sqlx::Error>>()
            .map_err(backend)
    }

    async fn add_rule(&self, rule: &FilterRule) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO filter_rules \
                 (id, mailbox, position, field, op, needle, action, target_folder, target_label, \
                  enabled, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
        )
        .bind(&rule.id)
        .bind(&rule.mailbox)
        .bind(rule.position)
        .bind(&rule.field)
        .bind(&rule.op)
        .bind(&rule.needle)
        .bind(&rule.action)
        .bind(&rule.target_folder)
        .bind(&rule.target_label)
        .bind(rule.enabled)
        .bind(rule.created_at)
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        Ok(())
    }

    async fn delete_rule(&self, mailbox: &str, id: &str) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM filter_rules WHERE mailbox = $1 AND id = $2")
            .bind(mailbox)
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(backend)?;
        Ok(())
    }

    async fn set_rule_enabled(
        &self,
        mailbox: &str,
        id: &str,
        enabled: bool,
    ) -> Result<(), StoreError> {
        sqlx::query("UPDATE filter_rules SET enabled = $1 WHERE mailbox = $2 AND id = $3")
            .bind(enabled)
            .bind(mailbox)
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(backend)?;
        Ok(())
    }

    async fn set_rule_position(
        &self,
        mailbox: &str,
        id: &str,
        position: i64,
    ) -> Result<(), StoreError> {
        sqlx::query("UPDATE filter_rules SET position = $1 WHERE mailbox = $2 AND id = $3")
            .bind(position)
            .bind(mailbox)
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(backend)?;
        Ok(())
    }

    async fn get_settings(&self, mailbox: &str) -> Result<MailboxSettings, StoreError> {
        let row = sqlx::query(
            "SELECT signature, auto_reply_enabled, auto_reply_subject, auto_reply_body, \
                    auto_reply_until \
             FROM mailboxes WHERE addr = $1",
        )
        .bind(mailbox)
        .fetch_optional(&self.pool)
        .await
        .map_err(backend)?;
        match row {
            Some(r) => Self::settings_from_row(mailbox, &r).map_err(backend),
            None => Ok(MailboxSettings::default_for(mailbox)),
        }
    }

    async fn set_signature(&self, mailbox: &str, signature: &str) -> Result<(), StoreError> {
        sqlx::query("UPDATE mailboxes SET signature = $1 WHERE addr = $2")
            .bind(signature)
            .bind(mailbox)
            .execute(&self.pool)
            .await
            .map_err(backend)?;
        Ok(())
    }

    async fn set_auto_reply(
        &self,
        mailbox: &str,
        enabled: bool,
        subject: &str,
        body: &str,
        until: i64,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "UPDATE mailboxes SET auto_reply_enabled = $1, auto_reply_subject = $2, \
                    auto_reply_body = $3, auto_reply_until = $4 \
             WHERE addr = $5",
        )
        .bind(enabled)
        .bind(subject)
        .bind(body)
        .bind(until)
        .bind(mailbox)
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        Ok(())
    }

    async fn mark_auto_replied(
        &self,
        mailbox: &str,
        sender: &str,
        now: i64,
    ) -> Result<bool, StoreError> {
        // Atomic check-and-record: the upsert only lands when no reply was recorded within the
        // dedupe window, so concurrent deliveries never double-send. `rows_affected` is the
        // verdict.
        let res = sqlx::query(
            "INSERT INTO auto_reply_log (mailbox, sender, sent_at) VALUES ($1, $2, $3) \
             ON CONFLICT (mailbox, sender) DO UPDATE SET sent_at = EXCLUDED.sent_at \
             WHERE auto_reply_log.sent_at <= $4",
        )
        .bind(mailbox)
        .bind(sender)
        .bind(now)
        .bind(now - AUTO_REPLY_DEDUPE_SECS)
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        Ok(res.rows_affected() > 0)
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

    async fn find_thread_for_refs(
        &self,
        mailbox: &str,
        refs: &[String],
    ) -> Result<Option<String>, StoreError> {
        if refs.is_empty() {
            return Ok(None);
        }
        // Build `$2,$3,…` for the reference set, reused in both the message_id and thread_id IN
        // lists. The earliest existing linked message's (non-empty) thread_id is the answer.
        let placeholders: Vec<String> = (0..refs.len()).map(|i| format!("${}", i + 2)).collect();
        let ph = placeholders.join(", ");
        let sql = format!(
            "SELECT thread_id FROM messages \
             WHERE mailbox = $1 AND thread_id IS NOT NULL AND thread_id <> '' \
               AND ((message_id IN ({ph})) OR (thread_id IN ({ph}))) \
             ORDER BY received_at ASC, id ASC LIMIT 1"
        );
        let mut q = sqlx::query(&sql).bind(mailbox);
        for r in refs {
            q = q.bind(r);
        }
        let row = q.fetch_optional(&self.pool).await.map_err(backend)?;
        Ok(row.map(|r| r.try_get::<String, _>("thread_id")).transpose().map_err(backend)?)
    }

    async fn list_folder_threads(
        &self,
        mailbox: &str,
        folder: &str,
        before: Option<(i64, String)>,
        limit: i64,
    ) -> Result<Vec<ThreadSummary>, StoreError> {
        let (cur_ts, cur_id) = Self::cursor(before);
        // The grouping key: the thread_id, or a per-message singleton (`m:<id>`) for pre-threading
        // rows. NOT EXISTS keeps only the newest message per group (the representative snippet),
        // keyset-paginated on that representative's (received_at, id). Correlated COUNTs give the
        // thread size + unread tally. All standard SQL (|| concat, NULLIF/COALESCE, subqueries).
        let rows = sqlx::query(
            "SELECT m.id, m.msg_from, m.subject, m.received_at, m.seen, m.starred, \
                    COALESCE(NULLIF(m.thread_id, ''), 'm:' || m.id) AS gk, \
                    (SELECT COUNT(*) FROM messages c WHERE c.mailbox = m.mailbox AND c.folder = m.folder \
                       AND COALESCE(NULLIF(c.thread_id, ''), 'm:' || c.id) = COALESCE(NULLIF(m.thread_id, ''), 'm:' || m.id)) AS cnt, \
                    (SELECT COUNT(*) FROM messages u WHERE u.mailbox = m.mailbox AND u.folder = m.folder AND u.seen = FALSE \
                       AND COALESCE(NULLIF(u.thread_id, ''), 'm:' || u.id) = COALESCE(NULLIF(m.thread_id, ''), 'm:' || m.id)) AS unseen_cnt \
             FROM messages m \
             WHERE m.mailbox = $1 AND m.folder = $2 \
               AND NOT EXISTS ( \
                 SELECT 1 FROM messages n WHERE n.mailbox = m.mailbox AND n.folder = m.folder \
                   AND COALESCE(NULLIF(n.thread_id, ''), 'm:' || n.id) = COALESCE(NULLIF(m.thread_id, ''), 'm:' || m.id) \
                   AND (n.received_at > m.received_at OR (n.received_at = m.received_at AND n.id > m.id)) \
               ) \
               AND (m.received_at < $3 OR (m.received_at = $3 AND m.id < $4)) \
             ORDER BY m.received_at DESC, m.id DESC LIMIT $5",
        )
        .bind(mailbox)
        .bind(folder)
        .bind(cur_ts)
        .bind(&cur_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(backend)?;
        rows.iter()
            .map(|r| {
                Ok(ThreadSummary {
                    thread_id: r.try_get("gk")?,
                    latest: summary_from_row(r)?,
                    count: r.try_get("cnt")?,
                    unseen: r.try_get("unseen_cnt")?,
                })
            })
            .collect::<Result<Vec<_>, sqlx::Error>>()
            .map_err(backend)
    }

    async fn list_thread(
        &self,
        mailbox: &str,
        thread_id: &str,
        limit: i64,
    ) -> Result<Vec<Message>, StoreError> {
        // A singleton conversation key (`m:<id>`) resolves to the one message by id.
        if let Some(mid) = thread_id.strip_prefix("m:") {
            let msg = self.get_message(mid).await?;
            return Ok(msg.into_iter().filter(|m| m.mailbox == mailbox).collect());
        }
        let rows = sqlx::query(
            "SELECT id, mailbox, msg_from, msg_to, subject, raw_rfc822, body_text, body_html, \
                    received_at, seen, folder, starred, thread_id, message_id \
             FROM messages WHERE mailbox = $1 AND thread_id = $2 \
             ORDER BY received_at ASC, id ASC LIMIT $3",
        )
        .bind(mailbox)
        .bind(thread_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(backend)?;
        rows.iter()
            .map(Self::message_from_row)
            .collect::<Result<Vec<_>, sqlx::Error>>()
            .map_err(backend)
    }

    async fn list_send_identities(&self, mailbox: &str) -> Result<Vec<SendIdentity>, StoreError> {
        let rows = sqlx::query(
            "SELECT id, mailbox, from_addr, display_name, is_default FROM send_identities \
             WHERE mailbox = $1 ORDER BY is_default DESC, from_addr ASC",
        )
        .bind(mailbox)
        .fetch_all(&self.pool)
        .await
        .map_err(backend)?;
        rows.iter()
            .map(Self::identity_from_row)
            .collect::<Result<Vec<_>, sqlx::Error>>()
            .map_err(backend)
    }

    async fn add_send_identity(&self, identity: &SendIdentity) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO send_identities (id, mailbox, from_addr, display_name, is_default) \
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(&identity.id)
        .bind(&identity.mailbox)
        .bind(&identity.from_addr)
        .bind(&identity.display_name)
        .bind(identity.is_default)
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        Ok(())
    }

    async fn delete_send_identity(&self, mailbox: &str, id: &str) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM send_identities WHERE mailbox = $1 AND id = $2")
            .bind(mailbox)
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(backend)?;
        Ok(())
    }

    async fn get_send_identity(
        &self,
        mailbox: &str,
        id: &str,
    ) -> Result<Option<SendIdentity>, StoreError> {
        let row = sqlx::query(
            "SELECT id, mailbox, from_addr, display_name, is_default FROM send_identities \
             WHERE mailbox = $1 AND id = $2",
        )
        .bind(mailbox)
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(backend)?;
        row.as_ref().map(Self::identity_from_row).transpose().map_err(backend)
    }

    async fn upsert_contact(
        &self,
        mailbox: &str,
        addr: &str,
        name: &str,
        manual: bool,
    ) -> Result<(), StoreError> {
        let addr_l = addr.trim().to_lowercase();
        if addr_l.is_empty() {
            return Ok(());
        }
        // Harvest bumps seen_count by 1; a manual (re)add sets the flag without inflating frequency.
        let inc: i64 = if manual { 0 } else { 1 };
        sqlx::query(
            "INSERT INTO contacts (mailbox, addr, name, manual, seen_count) \
             VALUES ($1, $2, $3, $4, $5) \
             ON CONFLICT (mailbox, addr) DO UPDATE SET \
               name = CASE WHEN EXCLUDED.name <> '' THEN EXCLUDED.name ELSE contacts.name END, \
               manual = contacts.manual OR EXCLUDED.manual, \
               seen_count = contacts.seen_count + $6",
        )
        .bind(mailbox)
        .bind(&addr_l)
        .bind(name.trim())
        .bind(manual)
        .bind(inc)
        .bind(inc)
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        Ok(())
    }

    async fn suggest_contacts(
        &self,
        mailbox: &str,
        q: &str,
        limit: i64,
    ) -> Result<Vec<Contact>, StoreError> {
        let pattern = format!("%{}%", like_escape(&q.trim().to_lowercase()));
        let rows = sqlx::query(
            "SELECT addr, name, manual, seen_count FROM contacts \
             WHERE mailbox = $1 \
               AND (LOWER(addr) LIKE $2 ESCAPE '\\' OR LOWER(name) LIKE $2 ESCAPE '\\') \
             ORDER BY manual DESC, seen_count DESC, addr ASC LIMIT $3",
        )
        .bind(mailbox)
        .bind(&pattern)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(backend)?;
        rows.iter()
            .map(Self::contact_from_row)
            .collect::<Result<Vec<_>, sqlx::Error>>()
            .map_err(backend)
    }

    async fn delete_contact(&self, mailbox: &str, addr: &str) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM contacts WHERE mailbox = $1 AND addr = $2")
            .bind(mailbox)
            .bind(addr.trim().to_lowercase())
            .execute(&self.pool)
            .await
            .map_err(backend)?;
        Ok(())
    }

    async fn list_labels(&self, mailbox: &str) -> Result<Vec<Label>, StoreError> {
        let rows = sqlx::query(
            "SELECT id, mailbox, name, color FROM labels WHERE mailbox = $1 ORDER BY name ASC, id ASC",
        )
        .bind(mailbox)
        .fetch_all(&self.pool)
        .await
        .map_err(backend)?;
        rows.iter()
            .map(Self::label_from_row)
            .collect::<Result<Vec<_>, sqlx::Error>>()
            .map_err(backend)
    }

    async fn add_label(&self, label: &Label) -> Result<(), StoreError> {
        sqlx::query("INSERT INTO labels (id, mailbox, name, color) VALUES ($1, $2, $3, $4)")
            .bind(&label.id)
            .bind(&label.mailbox)
            .bind(&label.name)
            .bind(&label.color)
            .execute(&self.pool)
            .await
            .map_err(backend)?;
        Ok(())
    }

    async fn delete_label(&self, mailbox: &str, id: &str) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM labels WHERE mailbox = $1 AND id = $2")
            .bind(mailbox)
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(backend)?;
        sqlx::query("DELETE FROM message_labels WHERE mailbox = $1 AND label_id = $2")
            .bind(mailbox)
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(backend)?;
        Ok(())
    }

    async fn assign_label(
        &self,
        mailbox: &str,
        message_id: &str,
        label_id: &str,
    ) -> Result<(), StoreError> {
        // Guarded insert: lands only when BOTH the message and the label belong to `mailbox`.
        sqlx::query(
            "INSERT INTO message_labels (mailbox, message_id, label_id) \
             SELECT $1, $2, $3 \
             WHERE EXISTS (SELECT 1 FROM messages WHERE id = $2 AND mailbox = $1) \
               AND EXISTS (SELECT 1 FROM labels WHERE id = $3 AND mailbox = $1) \
             ON CONFLICT (message_id, label_id) DO NOTHING",
        )
        .bind(mailbox)
        .bind(message_id)
        .bind(label_id)
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        Ok(())
    }

    async fn remove_label(
        &self,
        mailbox: &str,
        message_id: &str,
        label_id: &str,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "DELETE FROM message_labels WHERE mailbox = $1 AND message_id = $2 AND label_id = $3",
        )
        .bind(mailbox)
        .bind(message_id)
        .bind(label_id)
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        Ok(())
    }

    async fn labels_for_message(
        &self,
        mailbox: &str,
        message_id: &str,
    ) -> Result<Vec<Label>, StoreError> {
        let rows = sqlx::query(
            "SELECT l.id, l.mailbox, l.name, l.color FROM labels l \
             JOIN message_labels ml ON ml.label_id = l.id \
             WHERE l.mailbox = $1 AND ml.message_id = $2 AND ml.mailbox = $1 \
             ORDER BY l.name ASC, l.id ASC",
        )
        .bind(mailbox)
        .bind(message_id)
        .fetch_all(&self.pool)
        .await
        .map_err(backend)?;
        rows.iter()
            .map(Self::label_from_row)
            .collect::<Result<Vec<_>, sqlx::Error>>()
            .map_err(backend)
    }

    async fn list_by_label(
        &self,
        mailbox: &str,
        label_id: &str,
        before: Option<(i64, String)>,
        limit: i64,
    ) -> Result<Vec<MessageSummary>, StoreError> {
        let (cur_ts, cur_id) = Self::cursor(before);
        let rows = sqlx::query(
            "SELECT m.id, m.msg_from, m.subject, m.received_at, m.seen, m.starred \
             FROM messages m JOIN message_labels ml ON ml.message_id = m.id \
             WHERE m.mailbox = $1 AND ml.mailbox = $1 AND ml.label_id = $2 \
               AND (m.received_at < $3 OR (m.received_at = $3 AND m.id < $4)) \
             ORDER BY m.received_at DESC, m.id DESC LIMIT $5",
        )
        .bind(mailbox)
        .bind(label_id)
        .bind(cur_ts)
        .bind(&cur_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(backend)?;
        rows.iter()
            .map(summary_from_row)
            .collect::<Result<Vec<_>, sqlx::Error>>()
            .map_err(backend)
    }
}

/// Map a summary row (id, msg_from, subject, received_at, seen, starred) into a [`MessageSummary`].
fn summary_from_row(r: &sqlx::postgres::PgRow) -> Result<MessageSummary, sqlx::Error> {
    Ok(MessageSummary {
        id: r.try_get("id")?,
        msg_from: r.try_get("msg_from")?,
        subject: r.try_get("subject")?,
        received_at: r.try_get("received_at")?,
        seen: r.try_get("seen")?,
        starred: r.try_get::<Option<bool>, _>("starred")?.unwrap_or(false),
    })
}

/// Escape the LIKE metacharacters (`\`, `%`, `_`) in a search needle so it matches literally under
/// `LIKE ... ESCAPE '\'`.
fn like_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if matches!(c, '\\' | '%' | '_') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// Map an sqlx error into a [`StoreError`].
fn backend(e: sqlx::Error) -> StoreError {
    StoreError::Backend(e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn like_escape_neutralises_metacharacters() {
        assert_eq!(like_escape("plain"), "plain");
        assert_eq!(like_escape("50%_off\\now"), "50\\%\\_off\\\\now");
    }

    fn msg(id: &str, received_at: i64) -> Message {
        Message {
            id: id.to_string(),
            mailbox: "w33d@w33d.xyz".to_string(),
            msg_from: String::new(),
            msg_to: String::new(),
            subject: String::new(),
            raw_rfc822: String::new(),
            body_text: String::new(),
            body_html: String::new(),
            received_at,
            seen: false,
            folder: "INBOX".to_string(),
            starred: false,
            thread_id: String::new(),
            message_id: String::new(),
        }
    }

    #[test]
    fn apply_before_keeps_strictly_older_rows() {
        // Ordering is (received_at, id) descending; the cursor row itself is excluded.
        let all = vec![msg("m_c", 200), msg("m_b", 100), msg("m_a", 100), msg("m_z", 50)];

        let mut v = all.clone();
        apply_before(&mut v, None);
        assert_eq!(v.len(), 4, "no cursor keeps everything");

        let mut v = all.clone();
        apply_before(&mut v, Some((100, "m_b".to_string())));
        let ids: Vec<&str> = v.iter().map(|m| m.id.as_str()).collect();
        assert_eq!(ids, ["m_a", "m_z"], "same-ts rows tie-break on id, older ts always kept");
    }
}
