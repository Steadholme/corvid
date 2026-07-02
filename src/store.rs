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
//!    seen BOOLEAN DEFAULT FALSE, folder TEXT DEFAULT 'INBOX',
//!    snooze_until BIGINT DEFAULT 0, muted BOOLEAN DEFAULT FALSE)`
//! - `outbound_queue(id TEXT PK, mailbox TEXT, batch_id TEXT, raw TEXT, env_from TEXT,
//!    rcpts TEXT, to_domain TEXT, attempts BIGINT, next_at BIGINT, send_at BIGINT,
//!    sent_copy_filed BOOLEAN, status TEXT)`
//! - `filter_rules(id TEXT PK, mailbox TEXT, position BIGINT, field TEXT, op TEXT, needle TEXT,
//!    action TEXT, target_folder TEXT NULL, enabled BOOLEAN, created_at BIGINT)`
//! - `auto_reply_log(mailbox TEXT, sender TEXT, sent_at BIGINT, PK (mailbox, sender))`
//! - `contact_groups(id TEXT PK, user TEXT, name TEXT, created_at BIGINT)`
//! - `contact_group_members(group_id TEXT, contact_id TEXT, PK (group_id, contact_id))`
//! - `sender_lists(id TEXT PK, user TEXT, address_or_domain TEXT, kind TEXT, created_at BIGINT)`
//! - `signatures(id TEXT PK, user TEXT, identity TEXT, name TEXT, body_html TEXT, body_text TEXT,
//!    is_default BOOLEAN, created_at BIGINT)`
//! - `templates(id TEXT PK, user TEXT, name TEXT, body_html TEXT, body_text TEXT,
//!    created_at BIGINT, updated_at BIGINT)`
//! - `spam_annotations(message_id TEXT PK, mailbox TEXT, score BIGINT, reason TEXT)`
//! - settings columns on `mailboxes` (signature, undo_send_window_secs, display prefs,
//!   auto_reply_*), added
//!   idempotently.

use std::collections::BTreeMap;
use std::sync::Mutex;

use async_trait::async_trait;
use thiserror::Error;

use crate::model::{
    Alias, Contact, ContactGroup, FilterRule, Label, Mailbox, MailboxSettings, Message,
    MessageSummary, OutboundItem, ScheduledOutbound, SearchPredicate, SearchPredicateKind,
    SearchQuery, SearchState, SendIdentity, SenderListEntry, Signature, SpamAnnotation, Template,
    ThreadSummary, DEFAULT_DENSITY, DEFAULT_READING_PANE, DEFAULT_THEME,
    DEFAULT_UNDO_SEND_WINDOW_SECS,
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
    /// Insert or replace an editable Drafts message by id, scoped to its owning mailbox.
    async fn upsert_draft(&self, msg: &Message) -> Result<(), StoreError>;
    /// Delete a Drafts message by id, scoped to its owning mailbox. Returns whether a row changed.
    async fn delete_draft(&self, mailbox: &str, id: &str) -> Result<bool, StoreError>;
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
    /// Cross-folder listing of currently snoozed messages, newest first, keyset-paginated like
    /// [`Store::list_folder`]. `now` is supplied by the caller so tests and the relay worker are
    /// deterministic.
    async fn list_snoozed(
        &self,
        mailbox: &str,
        now: i64,
        before: Option<(i64, String)>,
        limit: i64,
    ) -> Result<Vec<MessageSummary>, StoreError>;
    /// Search a mailbox with a parsed query, newest first, optionally scoped to one `folder`
    /// (`None` searches the whole mailbox), keyset-paginated: `before` is the `(received_at, id)`
    /// of the last row of the previous page (`None` for the first page). A query containing only
    /// free text preserves the old `From`/`To`/`Subject`/body substring search.
    async fn search_messages(
        &self,
        mailbox: &str,
        query: &SearchQuery,
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
    /// Snooze a message until `until`, moving it out of the Inbox-backed folder listings.
    async fn snooze_message(&self, id: &str, until: i64) -> Result<(), StoreError>;
    /// Clear snooze state and restore the message to the Inbox.
    async fn unsnooze_message(&self, id: &str) -> Result<(), StoreError>;
    /// Restore due snoozed messages to the Inbox, capped so each background tick is bounded.
    async fn restore_due_snoozes(&self, now: i64, limit: i64) -> Result<i64, StoreError>;
    /// Mark every known row in the same conversation muted/unmuted.
    async fn set_thread_muted(&self, msg: &Message, muted: bool) -> Result<(), StoreError>;
    /// Whether an already-known conversation is muted.
    async fn is_thread_muted(&self, mailbox: &str, thread_id: &str) -> Result<bool, StoreError>;
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
    async fn set_rule_enabled(
        &self,
        mailbox: &str,
        id: &str,
        enabled: bool,
    ) -> Result<(), StoreError>;
    /// Reposition a rule, scoped to `mailbox` (the settings reorder renumbers via these).
    async fn set_rule_position(
        &self,
        mailbox: &str,
        id: &str,
        position: i64,
    ) -> Result<(), StoreError>;

    /// Per-mailbox settings (signature + undo send + auto-reply). All-defaults when never saved.
    async fn get_settings(&self, mailbox: &str) -> Result<MailboxSettings, StoreError>;
    /// Set the compose signature (empty clears it).
    async fn set_signature(&self, mailbox: &str, signature: &str) -> Result<(), StoreError>;
    /// Every reusable signature owned by a mailbox, ordered by identity/default/name.
    async fn list_signatures(&self, mailbox: &str) -> Result<Vec<Signature>, StoreError>;
    /// A single signature, scoped to `mailbox`.
    async fn get_signature(&self, mailbox: &str, id: &str)
        -> Result<Option<Signature>, StoreError>;
    /// The default signature for `identity`, falling back to the general default (`identity = ''`).
    async fn get_default_signature_for_identity(
        &self,
        mailbox: &str,
        identity: &str,
    ) -> Result<Option<Signature>, StoreError>;
    /// Persist a new reusable signature.
    async fn create_signature(&self, signature: &Signature) -> Result<(), StoreError>;
    /// Update an existing reusable signature, scoped by its `user` and `id`.
    async fn update_signature(&self, signature: &Signature) -> Result<(), StoreError>;
    /// Delete one reusable signature, scoped to `mailbox`.
    async fn delete_signature(&self, mailbox: &str, id: &str) -> Result<(), StoreError>;
    /// Set the undo-send hold window in seconds (`0` keeps the legacy immediate-send path).
    async fn set_undo_send_window(&self, mailbox: &str, secs: i64) -> Result<(), StoreError>;
    /// Set display preferences for list density, reading pane placement, and theme.
    async fn set_display_preferences(
        &self,
        mailbox: &str,
        density: &str,
        reading_pane: &str,
        theme: &str,
    ) -> Result<(), StoreError>;
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
    async fn mark_auto_replied(
        &self,
        mailbox: &str,
        sender: &str,
        now: i64,
    ) -> Result<bool, StoreError>;

    // --- Compose templates ----------------------------------------------------
    /// Every compose template owned by a mailbox, ordered by name.
    async fn list_templates(&self, mailbox: &str) -> Result<Vec<Template>, StoreError>;
    /// A single compose template, scoped to `mailbox`.
    async fn get_template(&self, mailbox: &str, id: &str) -> Result<Option<Template>, StoreError>;
    /// Persist a new compose template.
    async fn create_template(&self, template: &Template) -> Result<(), StoreError>;
    /// Update an existing compose template, scoped by its `user` and `id`.
    async fn update_template(&self, template: &Template) -> Result<(), StoreError>;
    /// Delete one compose template, scoped to `mailbox`.
    async fn delete_template(&self, mailbox: &str, id: &str) -> Result<(), StoreError>;

    /// Enqueue an outbound message for relay.
    async fn enqueue_outbound(&self, item: &OutboundItem) -> Result<(), StoreError>;
    /// Queued/scheduled items whose retry and schedule gates are due, capped (relay work list).
    async fn due_outbound(&self, now: i64, limit: i64) -> Result<Vec<OutboundItem>, StoreError>;
    /// User-facing scheduled sends for one mailbox, grouped by compose submission.
    async fn list_scheduled_outbound(
        &self,
        mailbox: &str,
        now: i64,
        before: Option<(i64, String)>,
        limit: i64,
    ) -> Result<Vec<ScheduledOutbound>, StoreError>;
    /// A single future scheduled send, grouped by compose submission.
    async fn get_scheduled_outbound(
        &self,
        mailbox: &str,
        batch_id: &str,
        now: i64,
    ) -> Result<Option<ScheduledOutbound>, StoreError>;
    /// Move a future scheduled send to another future epoch. Returns whether a row changed.
    async fn reschedule_scheduled_outbound(
        &self,
        mailbox: &str,
        batch_id: &str,
        send_at: i64,
        now: i64,
    ) -> Result<bool, StoreError>;
    /// Remove a future scheduled send from the queue. Returns whether a row changed.
    async fn cancel_scheduled_outbound(
        &self,
        mailbox: &str,
        batch_id: &str,
        now: i64,
    ) -> Result<bool, StoreError>;
    /// Claim responsibility for filing the Sent copy of a scheduled batch after delivery succeeds.
    async fn claim_scheduled_sent_copy(
        &self,
        mailbox: &str,
        batch_id: &str,
    ) -> Result<bool, StoreError>;
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
    /// Full contact list for settings/export, ordered by name/address.
    async fn list_contacts(&self, mailbox: &str, limit: i64) -> Result<Vec<Contact>, StoreError>;
    /// Persist a full user-managed contact row. Unlike harvest upsert, blank fields are saved.
    async fn save_contact(&self, mailbox: &str, contact: &Contact) -> Result<(), StoreError>;
    /// Contacts that share the same lowercased email address, used by the merge UI.
    async fn duplicate_contacts(&self, mailbox: &str) -> Result<Vec<Contact>, StoreError>;
    /// Merge duplicate rows for one lowercased address, preserving non-empty fields.
    async fn merge_duplicate_contact(&self, mailbox: &str, addr: &str) -> Result<(), StoreError>;

    /// Every contact group owned by a mailbox.
    async fn list_contact_groups(&self, mailbox: &str) -> Result<Vec<ContactGroup>, StoreError>;
    /// Create or rename a contact group.
    async fn save_contact_group(&self, group: &ContactGroup) -> Result<(), StoreError>;
    /// Delete a contact group and its memberships, scoped to `mailbox`.
    async fn delete_contact_group(&self, mailbox: &str, group_id: &str) -> Result<(), StoreError>;
    /// Add a contact address to a group, scoped through the group's owner.
    async fn add_contact_group_member(
        &self,
        mailbox: &str,
        group_id: &str,
        contact_addr: &str,
    ) -> Result<(), StoreError>;
    /// Remove a contact address from a group, scoped through the group's owner.
    async fn delete_contact_group_member(
        &self,
        mailbox: &str,
        group_id: &str,
        contact_addr: &str,
    ) -> Result<(), StoreError>;
    /// Contact rows in a group, scoped to `mailbox`.
    async fn list_contact_group_members(
        &self,
        mailbox: &str,
        group_id: &str,
    ) -> Result<Vec<Contact>, StoreError>;
    /// Expand a typed group name into its member contacts for recipient parsing.
    async fn contacts_for_group_name(
        &self,
        mailbox: &str,
        group_name: &str,
    ) -> Result<Vec<Contact>, StoreError>;

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

    // --- Spam controls ---------------------------------------------------------
    /// Every safe/blocked sender entry for a mailbox, ordered by kind then address/domain.
    async fn list_sender_lists(&self, mailbox: &str) -> Result<Vec<SenderListEntry>, StoreError>;
    /// Idempotently add a safe/blocked sender entry. Adding one kind removes the opposite kind for
    /// the same address/domain so safe-vs-blocked conflicts do not accumulate.
    async fn upsert_sender_list(&self, entry: &SenderListEntry) -> Result<(), StoreError>;
    /// Delete one safe/blocked sender entry, scoped to `mailbox`.
    async fn delete_sender_list(&self, mailbox: &str, id: &str) -> Result<(), StoreError>;
    /// Store/update a spam score explanation for a message.
    async fn set_spam_annotation(&self, annotation: &SpamAnnotation) -> Result<(), StoreError>;
    /// Fetch the spam score explanation for a message, scoped to `mailbox`.
    async fn spam_annotation(
        &self,
        mailbox: &str,
        message_id: &str,
    ) -> Result<Option<SpamAnnotation>, StoreError>;
    /// Remove a spam score explanation for a message, scoped to `mailbox`.
    async fn delete_spam_annotation(
        &self,
        mailbox: &str,
        message_id: &str,
    ) -> Result<(), StoreError>;
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
    signatures: Mutex<Vec<Signature>>,
    templates: Mutex<Vec<Template>>,
    send_identities: Mutex<Vec<SendIdentity>>,
    /// Contacts qualified by their owning mailbox: `(mailbox, contact)`.
    contacts: Mutex<Vec<(String, Contact)>>,
    contact_groups: Mutex<Vec<ContactGroup>>,
    /// Contact group members: `(group_id, contact_addr)`.
    contact_group_members: Mutex<Vec<(String, String)>>,
    labels: Mutex<Vec<Label>>,
    /// Message↔label assignments: `(mailbox, message_id, label_id)`.
    message_labels: Mutex<Vec<(String, String, String)>>,
    sender_lists: Mutex<Vec<SenderListEntry>>,
    spam_annotations: Mutex<Vec<SpamAnnotation>>,
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
        snooze_until: m.snooze_until,
        muted: m.muted,
        folder: m.folder.clone(),
    }
}

fn legacy_signature_id(mailbox: &str) -> String {
    format!("sig_legacy_{mailbox}")
}

fn blank_contact(addr: String, name: String, manual: bool, seen_count: i64) -> Contact {
    Contact {
        addr,
        name,
        phone: String::new(),
        company: String::new(),
        title: String::new(),
        notes: String::new(),
        manual,
        seen_count,
    }
}

fn merge_contact_fields(into: &mut Contact, other: &Contact) {
    if into.name.trim().is_empty() && !other.name.trim().is_empty() {
        into.name = other.name.clone();
    }
    if into.phone.trim().is_empty() && !other.phone.trim().is_empty() {
        into.phone = other.phone.clone();
    }
    if into.company.trim().is_empty() && !other.company.trim().is_empty() {
        into.company = other.company.clone();
    }
    if into.title.trim().is_empty() && !other.title.trim().is_empty() {
        into.title = other.title.clone();
    }
    if into.notes.trim().is_empty() && !other.notes.trim().is_empty() {
        into.notes = other.notes.clone();
    }
    into.manual = into.manual || other.manual;
    into.seen_count += other.seen_count;
}

fn sort_contacts_for_settings(v: &mut [Contact]) {
    v.sort_by(|a, b| {
        let an = if a.name.trim().is_empty() {
            a.addr.to_lowercase()
        } else {
            a.name.to_lowercase()
        };
        let bn = if b.name.trim().is_empty() {
            b.addr.to_lowercase()
        } else {
            b.name.to_lowercase()
        };
        an.cmp(&bn).then_with(|| a.addr.cmp(&b.addr))
    });
}

fn sort_contact_groups(v: &mut [ContactGroup]) {
    v.sort_by(|a, b| {
        a.name
            .to_lowercase()
            .cmp(&b.name.to_lowercase())
            .then_with(|| a.id.cmp(&b.id))
    });
}

fn sort_signatures(v: &mut [Signature]) {
    v.sort_by(|a, b| {
        a.identity
            .cmp(&b.identity)
            .then_with(|| b.is_default.cmp(&a.is_default))
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
            .then_with(|| a.id.cmp(&b.id))
    });
}

fn is_snoozed_at(m: &Message, now: i64) -> bool {
    m.snooze_until > now
}

fn scheduled_from_rows(rows: &[OutboundItem]) -> Option<ScheduledOutbound> {
    let first = rows.first()?;
    let mut rcpts = Vec::new();
    for row in rows {
        for rcpt in &row.rcpts {
            if !rcpts.iter().any(|existing| existing == rcpt) {
                rcpts.push(rcpt.clone());
            }
        }
    }
    Some(ScheduledOutbound {
        batch_id: first.batch_id.clone(),
        mailbox: first.mailbox.clone(),
        raw: first.raw.clone(),
        env_from: first.env_from.clone(),
        rcpts,
        send_at: first.send_at,
        status: first.status.clone(),
    })
}

fn aggregate_scheduled_rows(mut rows: Vec<OutboundItem>) -> Vec<ScheduledOutbound> {
    rows.sort_by(|a, b| {
        a.send_at
            .cmp(&b.send_at)
            .then_with(|| a.batch_id.cmp(&b.batch_id))
            .then_with(|| a.id.cmp(&b.id))
    });
    let mut out = Vec::new();
    let mut i = 0;
    while i < rows.len() {
        let batch_id = rows[i].batch_id.clone();
        let mut j = i + 1;
        while j < rows.len() && rows[j].batch_id == batch_id {
            j += 1;
        }
        if let Some(scheduled) = scheduled_from_rows(&rows[i..j]) {
            out.push(scheduled);
        }
        i = j;
    }
    out
}

fn thread_matches(m: &Message, root: &Message) -> bool {
    if !root.thread_id.is_empty() {
        m.thread_id == root.thread_id || m.message_id == root.thread_id
    } else if !root.message_id.is_empty() {
        m.message_id == root.message_id || m.thread_id == root.message_id
    } else {
        m.id == root.id
    }
}

fn message_matches_search(
    m: &Message,
    query: &SearchQuery,
    labels: &[Label],
    message_labels: &[(String, String, String)],
) -> bool {
    let mut positive_count = 0_usize;
    let mut any_positive_matches = false;
    let mut all_positives_match = true;

    for term in query.text_terms.iter().filter(|term| !term.negated) {
        positive_count += 1;
        let matched = message_matches_text(m, &term.value);
        any_positive_matches |= matched;
        all_positives_match &= matched;
    }
    for predicate in query
        .predicates
        .iter()
        .filter(|predicate| !predicate.negated)
    {
        positive_count += 1;
        let matched = message_matches_predicate(m, predicate, labels, message_labels);
        any_positive_matches |= matched;
        all_positives_match &= matched;
    }

    let positives_match = if positive_count == 0 {
        true
    } else if query.or_mode {
        any_positive_matches
    } else {
        all_positives_match
    };

    positives_match
        && query
            .text_terms
            .iter()
            .filter(|term| term.negated)
            .all(|term| !message_matches_text(m, &term.value))
        && query
            .predicates
            .iter()
            .filter(|predicate| predicate.negated)
            .all(|predicate| !message_matches_predicate(m, predicate, labels, message_labels))
}

fn message_matches_text(m: &Message, value: &str) -> bool {
    let needle = value.to_lowercase();
    contains_lower(&m.msg_from, &needle)
        || contains_lower(&m.msg_to, &needle)
        || contains_lower(&m.subject, &needle)
        || contains_lower(&m.body_text, &needle)
}

fn message_matches_predicate(
    m: &Message,
    predicate: &SearchPredicate,
    labels: &[Label],
    message_labels: &[(String, String, String)],
) -> bool {
    match &predicate.kind {
        SearchPredicateKind::From(value) => contains_ci(&m.msg_from, value),
        SearchPredicateKind::To(value) => contains_ci(&m.msg_to, value),
        SearchPredicateKind::Cc(value) => raw_cc_contains(&m.raw_rfc822, value),
        SearchPredicateKind::Subject(value) => contains_ci(&m.subject, value),
        SearchPredicateKind::Label(value) => message_has_label(m, value, labels, message_labels),
        SearchPredicateKind::Is(SearchState::Read) => m.seen,
        SearchPredicateKind::Is(SearchState::Unread) => !m.seen,
        SearchPredicateKind::Is(SearchState::Starred) => m.starred,
        SearchPredicateKind::HasAttachment => raw_has_attachment(&m.raw_rfc822),
        SearchPredicateKind::InFolder(value) => m.folder.eq_ignore_ascii_case(value),
        SearchPredicateKind::Before(ts) => m.received_at < *ts,
        SearchPredicateKind::After(ts) => m.received_at >= *ts,
        SearchPredicateKind::Larger(bytes) => (m.raw_rfc822.as_bytes().len() as i64) > *bytes,
        SearchPredicateKind::Smaller(bytes) => (m.raw_rfc822.as_bytes().len() as i64) < *bytes,
    }
}

fn contains_ci(haystack: &str, needle: &str) -> bool {
    let needle = needle.to_lowercase();
    contains_lower(haystack, &needle)
}

fn contains_lower(haystack: &str, needle: &str) -> bool {
    haystack.to_lowercase().contains(needle)
}

fn raw_cc_contains(raw: &str, value: &str) -> bool {
    let raw = raw.to_lowercase();
    let needle = value.to_lowercase();
    raw.split("cc:").skip(1).any(|rest| rest.contains(&needle))
}

fn raw_has_attachment(raw: &str) -> bool {
    let raw = raw.to_ascii_lowercase();
    raw.contains("content-disposition: attachment")
        || raw.contains("filename=")
        || raw.contains("name=")
}

fn message_has_label(
    m: &Message,
    value: &str,
    labels: &[Label],
    message_labels: &[(String, String, String)],
) -> bool {
    let value = value.to_lowercase();
    message_labels
        .iter()
        .any(|(mailbox, message_id, label_id)| {
            mailbox == &m.mailbox
                && message_id == &m.id
                && labels.iter().any(|label| {
                    label.mailbox == m.mailbox
                        && label.id == label_id.as_str()
                        && label.name.to_lowercase() == value
                })
        })
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

    async fn upsert_draft(&self, msg: &Message) -> Result<(), StoreError> {
        if msg.folder != "Drafts" {
            return Err(StoreError::Backend(
                "upsert_draft requires folder=Drafts".to_string(),
            ));
        }
        let mut v = self.messages.lock().expect("messages lock poisoned");
        if let Some(existing) = v.iter_mut().find(|m| m.id == msg.id) {
            if existing.mailbox != msg.mailbox || existing.folder != "Drafts" {
                return Err(StoreError::Backend(
                    "draft id is not an editable draft".to_string(),
                ));
            }
            *existing = msg.clone();
        } else {
            v.push(msg.clone());
        }
        Ok(())
    }

    async fn delete_draft(&self, mailbox: &str, id: &str) -> Result<bool, StoreError> {
        let mut v = self.messages.lock().expect("messages lock poisoned");
        let before = v.len();
        v.retain(|m| !(m.mailbox == mailbox && m.id == id && m.folder == "Drafts"));
        Ok(v.len() != before)
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
        v.sort_by(|a, b| {
            b.received_at
                .cmp(&a.received_at)
                .then_with(|| b.id.cmp(&a.id))
        });
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
        let now = crate::util::now_secs();
        let mut v: Vec<Message> = self
            .messages
            .lock()
            .expect("messages lock poisoned")
            .iter()
            .filter(|m| {
                m.mailbox == mailbox
                    && m.folder == folder
                    && (!folder.eq_ignore_ascii_case("INBOX") || !is_snoozed_at(m, now))
            })
            .cloned()
            .collect();
        v.sort_by(|a, b| {
            b.received_at
                .cmp(&a.received_at)
                .then_with(|| b.id.cmp(&a.id))
        });
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
        v.sort_by(|a, b| {
            b.received_at
                .cmp(&a.received_at)
                .then_with(|| b.id.cmp(&a.id))
        });
        apply_before(&mut v, before);
        v.truncate(limit.max(0) as usize);
        Ok(v.iter().map(summary).collect())
    }

    async fn list_snoozed(
        &self,
        mailbox: &str,
        now: i64,
        before: Option<(i64, String)>,
        limit: i64,
    ) -> Result<Vec<MessageSummary>, StoreError> {
        let mut v: Vec<Message> = self
            .messages
            .lock()
            .expect("messages lock poisoned")
            .iter()
            .filter(|m| m.mailbox == mailbox && is_snoozed_at(m, now))
            .cloned()
            .collect();
        v.sort_by(|a, b| {
            b.received_at
                .cmp(&a.received_at)
                .then_with(|| b.id.cmp(&a.id))
        });
        apply_before(&mut v, before);
        v.truncate(limit.max(0) as usize);
        Ok(v.iter().map(summary).collect())
    }

    async fn search_messages(
        &self,
        mailbox: &str,
        query: &SearchQuery,
        folder: Option<&str>,
        before: Option<(i64, String)>,
        limit: i64,
    ) -> Result<Vec<MessageSummary>, StoreError> {
        let now = crate::util::now_secs();
        let labels = self.labels.lock().expect("labels lock poisoned").clone();
        let message_labels = self
            .message_labels
            .lock()
            .expect("message_labels lock poisoned")
            .clone();
        let mut v: Vec<Message> = self
            .messages
            .lock()
            .expect("messages lock poisoned")
            .iter()
            .filter(|m| {
                m.mailbox == mailbox
                    && folder.map_or(true, |f| {
                        m.folder == f
                            && (!f.eq_ignore_ascii_case("INBOX") || !is_snoozed_at(m, now))
                    })
                    && message_matches_search(m, query, &labels, &message_labels)
            })
            .cloned()
            .collect();
        v.sort_by(|a, b| {
            b.received_at
                .cmp(&a.received_at)
                .then_with(|| b.id.cmp(&a.id))
        });
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

    async fn snooze_message(&self, id: &str, until: i64) -> Result<(), StoreError> {
        let mut v = self.messages.lock().expect("messages lock poisoned");
        if let Some(m) = v.iter_mut().find(|m| m.id == id) {
            m.snooze_until = until.max(0);
            if m.snooze_until > 0 {
                m.folder = "Archive".to_string();
            }
        }
        Ok(())
    }

    async fn unsnooze_message(&self, id: &str) -> Result<(), StoreError> {
        let mut v = self.messages.lock().expect("messages lock poisoned");
        if let Some(m) = v.iter_mut().find(|m| m.id == id) {
            m.snooze_until = 0;
            m.folder = "INBOX".to_string();
        }
        Ok(())
    }

    async fn restore_due_snoozes(&self, now: i64, limit: i64) -> Result<i64, StoreError> {
        let mut restored = 0_i64;
        let max = limit.max(0);
        let mut v = self.messages.lock().expect("messages lock poisoned");
        for m in v.iter_mut() {
            if restored >= max {
                break;
            }
            if m.snooze_until > 0 && m.snooze_until <= now {
                m.snooze_until = 0;
                m.folder = "INBOX".to_string();
                restored += 1;
            }
        }
        Ok(restored)
    }

    async fn set_thread_muted(&self, msg: &Message, muted: bool) -> Result<(), StoreError> {
        let mut v = self.messages.lock().expect("messages lock poisoned");
        for m in v
            .iter_mut()
            .filter(|m| m.mailbox == msg.mailbox && thread_matches(m, msg))
        {
            m.muted = muted;
        }
        Ok(())
    }

    async fn is_thread_muted(&self, mailbox: &str, thread_id: &str) -> Result<bool, StoreError> {
        if thread_id.is_empty() {
            return Ok(false);
        }
        Ok(self
            .messages
            .lock()
            .expect("messages lock poisoned")
            .iter()
            .any(|m| {
                m.mailbox == mailbox
                    && m.muted
                    && (m.thread_id == thread_id || m.message_id == thread_id)
            }))
    }

    async fn unseen_count(&self, mailbox: &str) -> Result<i64, StoreError> {
        let now = crate::util::now_secs();
        Ok(self
            .messages
            .lock()
            .expect("messages lock poisoned")
            .iter()
            .filter(|m| m.mailbox == mailbox && !m.seen && !is_snoozed_at(m, now))
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
        drop(v);

        let sig = signature.trim();
        let mut signatures = self.signatures.lock().expect("signatures lock poisoned");
        if sig.is_empty() {
            signatures.retain(|s| {
                !(s.user == mailbox
                    && s.identity.is_empty()
                    && s.id == legacy_signature_id(mailbox))
            });
            return Ok(());
        }
        for s in signatures
            .iter_mut()
            .filter(|s| s.user == mailbox && s.identity.is_empty())
        {
            s.is_default = false;
        }
        let id = legacy_signature_id(mailbox);
        if let Some(existing) = signatures
            .iter_mut()
            .find(|s| s.user == mailbox && s.id == id)
        {
            existing.identity.clear();
            existing.name = "Default".to_string();
            existing.body_html.clear();
            existing.body_text = sig.to_string();
            existing.is_default = true;
        } else {
            signatures.push(Signature {
                id,
                user: mailbox.to_string(),
                identity: String::new(),
                name: "Default".to_string(),
                body_html: String::new(),
                body_text: sig.to_string(),
                is_default: true,
                created_at: crate::util::now_secs(),
            });
        }
        Ok(())
    }

    async fn list_signatures(&self, mailbox: &str) -> Result<Vec<Signature>, StoreError> {
        let mut v: Vec<Signature> = self
            .signatures
            .lock()
            .expect("signatures lock poisoned")
            .iter()
            .filter(|s| s.user == mailbox)
            .cloned()
            .collect();
        sort_signatures(&mut v);
        Ok(v)
    }

    async fn get_signature(
        &self,
        mailbox: &str,
        id: &str,
    ) -> Result<Option<Signature>, StoreError> {
        Ok(self
            .signatures
            .lock()
            .expect("signatures lock poisoned")
            .iter()
            .find(|s| s.user == mailbox && s.id == id)
            .cloned())
    }

    async fn get_default_signature_for_identity(
        &self,
        mailbox: &str,
        identity: &str,
    ) -> Result<Option<Signature>, StoreError> {
        let signatures = self.signatures.lock().expect("signatures lock poisoned");
        let exact_identity = identity.trim();
        if !exact_identity.is_empty() {
            if let Some(sig) = signatures
                .iter()
                .filter(|s| s.user == mailbox && s.identity == exact_identity && s.is_default)
                .max_by(|a, b| {
                    a.created_at
                        .cmp(&b.created_at)
                        .then_with(|| b.id.cmp(&a.id))
                })
                .cloned()
            {
                return Ok(Some(sig));
            }
        }
        Ok(signatures
            .iter()
            .filter(|s| s.user == mailbox && s.identity.is_empty() && s.is_default)
            .max_by(|a, b| {
                a.created_at
                    .cmp(&b.created_at)
                    .then_with(|| b.id.cmp(&a.id))
            })
            .cloned())
    }

    async fn create_signature(&self, signature: &Signature) -> Result<(), StoreError> {
        let mut v = self.signatures.lock().expect("signatures lock poisoned");
        if signature.is_default {
            for existing in v
                .iter_mut()
                .filter(|s| s.user == signature.user && s.identity == signature.identity)
            {
                existing.is_default = false;
            }
        }
        v.push(signature.clone());
        Ok(())
    }

    async fn update_signature(&self, signature: &Signature) -> Result<(), StoreError> {
        let mut v = self.signatures.lock().expect("signatures lock poisoned");
        if signature.is_default {
            for existing in v.iter_mut().filter(|s| {
                s.user == signature.user && s.identity == signature.identity && s.id != signature.id
            }) {
                existing.is_default = false;
            }
        }
        if let Some(existing) = v
            .iter_mut()
            .find(|s| s.user == signature.user && s.id == signature.id)
        {
            existing.identity = signature.identity.clone();
            existing.name = signature.name.clone();
            existing.body_html = signature.body_html.clone();
            existing.body_text = signature.body_text.clone();
            existing.is_default = signature.is_default;
        }
        Ok(())
    }

    async fn delete_signature(&self, mailbox: &str, id: &str) -> Result<(), StoreError> {
        self.signatures
            .lock()
            .expect("signatures lock poisoned")
            .retain(|s| !(s.user == mailbox && s.id == id));
        Ok(())
    }

    async fn set_undo_send_window(&self, mailbox: &str, secs: i64) -> Result<(), StoreError> {
        let mut v = self.settings.lock().expect("settings lock poisoned");
        let s = match v.iter_mut().find(|s| s.mailbox == mailbox) {
            Some(s) => s,
            None => {
                v.push(MailboxSettings::default_for(mailbox));
                v.last_mut().expect("just pushed")
            }
        };
        s.undo_send_window_secs = secs;
        Ok(())
    }

    async fn set_display_preferences(
        &self,
        mailbox: &str,
        density: &str,
        reading_pane: &str,
        theme: &str,
    ) -> Result<(), StoreError> {
        let mut v = self.settings.lock().expect("settings lock poisoned");
        let s = match v.iter_mut().find(|s| s.mailbox == mailbox) {
            Some(s) => s,
            None => {
                v.push(MailboxSettings::default_for(mailbox));
                v.last_mut().expect("just pushed")
            }
        };
        s.density = density.to_string();
        s.reading_pane = reading_pane.to_string();
        s.theme = theme.to_string();
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
        let mut v = self
            .auto_replies
            .lock()
            .expect("auto_replies lock poisoned");
        if let Some((_, _, sent_at)) = v.iter_mut().find(|(m, s, _)| m == mailbox && s == sender) {
            if now - *sent_at < AUTO_REPLY_DEDUPE_SECS {
                return Ok(false);
            }
            *sent_at = now;
        } else {
            v.push((mailbox.to_string(), sender.to_string(), now));
        }
        Ok(true)
    }

    async fn list_templates(&self, mailbox: &str) -> Result<Vec<Template>, StoreError> {
        let mut v: Vec<Template> = self
            .templates
            .lock()
            .expect("templates lock poisoned")
            .iter()
            .filter(|t| t.user == mailbox)
            .cloned()
            .collect();
        v.sort_by(|a, b| {
            a.name
                .to_lowercase()
                .cmp(&b.name.to_lowercase())
                .then_with(|| a.id.cmp(&b.id))
        });
        Ok(v)
    }

    async fn get_template(&self, mailbox: &str, id: &str) -> Result<Option<Template>, StoreError> {
        Ok(self
            .templates
            .lock()
            .expect("templates lock poisoned")
            .iter()
            .find(|t| t.user == mailbox && t.id == id)
            .cloned())
    }

    async fn create_template(&self, template: &Template) -> Result<(), StoreError> {
        self.templates
            .lock()
            .expect("templates lock poisoned")
            .push(template.clone());
        Ok(())
    }

    async fn update_template(&self, template: &Template) -> Result<(), StoreError> {
        let mut v = self.templates.lock().expect("templates lock poisoned");
        if let Some(existing) = v
            .iter_mut()
            .find(|t| t.user == template.user && t.id == template.id)
        {
            existing.name = template.name.clone();
            existing.body_html = template.body_html.clone();
            existing.body_text = template.body_text.clone();
            existing.updated_at = template.updated_at;
        }
        Ok(())
    }

    async fn delete_template(&self, mailbox: &str, id: &str) -> Result<(), StoreError> {
        self.templates
            .lock()
            .expect("templates lock poisoned")
            .retain(|t| !(t.user == mailbox && t.id == id));
        Ok(())
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
            .filter(|o| {
                (o.status == "queued" || o.status == "scheduled")
                    && o.next_at <= now
                    && (o.send_at <= 0 || o.send_at <= now)
            })
            .cloned()
            .collect();
        v.sort_by(|a, b| {
            a.next_at
                .cmp(&b.next_at)
                .then_with(|| a.send_at.cmp(&b.send_at))
                .then_with(|| a.id.cmp(&b.id))
        });
        v.truncate(limit.max(0) as usize);
        Ok(v)
    }

    async fn list_scheduled_outbound(
        &self,
        mailbox: &str,
        now: i64,
        before: Option<(i64, String)>,
        limit: i64,
    ) -> Result<Vec<ScheduledOutbound>, StoreError> {
        let rows: Vec<OutboundItem> = self
            .outbound
            .lock()
            .expect("outbound lock poisoned")
            .iter()
            .filter(|o| {
                o.mailbox == mailbox
                    && o.status == "scheduled"
                    && o.send_at > now
                    && before.as_ref().map_or(true, |(ts, batch_id)| {
                        o.send_at > *ts
                            || (o.send_at == *ts && o.batch_id.as_str() > batch_id.as_str())
                    })
            })
            .cloned()
            .collect();
        let mut scheduled = aggregate_scheduled_rows(rows);
        scheduled.truncate(limit.max(0) as usize);
        Ok(scheduled)
    }

    async fn get_scheduled_outbound(
        &self,
        mailbox: &str,
        batch_id: &str,
        now: i64,
    ) -> Result<Option<ScheduledOutbound>, StoreError> {
        let rows: Vec<OutboundItem> = self
            .outbound
            .lock()
            .expect("outbound lock poisoned")
            .iter()
            .filter(|o| {
                o.mailbox == mailbox
                    && o.batch_id == batch_id
                    && o.status == "scheduled"
                    && o.send_at > now
            })
            .cloned()
            .collect();
        Ok(scheduled_from_rows(&rows))
    }

    async fn reschedule_scheduled_outbound(
        &self,
        mailbox: &str,
        batch_id: &str,
        send_at: i64,
        now: i64,
    ) -> Result<bool, StoreError> {
        let mut changed = false;
        let mut v = self.outbound.lock().expect("outbound lock poisoned");
        for o in v.iter_mut().filter(|o| {
            o.mailbox == mailbox
                && o.batch_id == batch_id
                && o.status == "scheduled"
                && o.send_at > now
        }) {
            o.send_at = send_at;
            o.next_at = now;
            o.attempts = 0;
            changed = true;
        }
        Ok(changed)
    }

    async fn cancel_scheduled_outbound(
        &self,
        mailbox: &str,
        batch_id: &str,
        now: i64,
    ) -> Result<bool, StoreError> {
        let mut v = self.outbound.lock().expect("outbound lock poisoned");
        let before = v.len();
        v.retain(|o| {
            !(o.mailbox == mailbox
                && o.batch_id == batch_id
                && o.status == "scheduled"
                && o.send_at > now)
        });
        Ok(v.len() != before)
    }

    async fn claim_scheduled_sent_copy(
        &self,
        mailbox: &str,
        batch_id: &str,
    ) -> Result<bool, StoreError> {
        let mut claimed = false;
        let mut v = self.outbound.lock().expect("outbound lock poisoned");
        if v.iter()
            .any(|o| o.mailbox == mailbox && o.batch_id == batch_id && o.sent_copy_filed)
        {
            return Ok(false);
        }
        for o in v
            .iter_mut()
            .filter(|o| o.mailbox == mailbox && o.batch_id == batch_id)
        {
            o.sent_copy_filed = true;
            claimed = true;
        }
        Ok(claimed)
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
                    && (refs
                        .iter()
                        .any(|r| r == &m.message_id && !m.message_id.is_empty())
                        || refs
                            .iter()
                            .any(|r| r == &m.thread_id && !m.thread_id.is_empty()))
            })
            .cloned()
            .collect();
        // Earliest existing message wins (stable thread root).
        candidates.sort_by(|a, b| {
            a.received_at
                .cmp(&b.received_at)
                .then_with(|| a.id.cmp(&b.id))
        });
        Ok(candidates
            .into_iter()
            .map(|m| {
                if m.thread_id.is_empty() {
                    m.message_id
                } else {
                    m.thread_id
                }
            })
            .find(|t| !t.is_empty()))
    }

    async fn list_folder_threads(
        &self,
        mailbox: &str,
        folder: &str,
        before: Option<(i64, String)>,
        limit: i64,
    ) -> Result<Vec<ThreadSummary>, StoreError> {
        let now = crate::util::now_secs();
        let msgs: Vec<Message> = self
            .messages
            .lock()
            .expect("messages lock poisoned")
            .iter()
            .filter(|m| {
                m.mailbox == mailbox
                    && m.folder == folder
                    && (!folder.eq_ignore_ascii_case("INBOX") || !is_snoozed_at(m, now))
            })
            .cloned()
            .collect();
        // Group by thread_id (empty thread_id => the message is its own singleton, keyed by id).
        let mut groups: std::collections::HashMap<String, Vec<Message>> =
            std::collections::HashMap::new();
        for m in msgs {
            let key = if m.thread_id.is_empty() {
                format!("m:{}", m.id)
            } else {
                m.thread_id.clone()
            };
            groups.entry(key).or_default().push(m);
        }
        let mut threads: Vec<ThreadSummary> = groups
            .into_iter()
            .map(|(key, mut group)| {
                group.sort_by(|a, b| {
                    b.received_at
                        .cmp(&a.received_at)
                        .then_with(|| b.id.cmp(&a.id))
                });
                let latest = &group[0];
                let unseen = group.iter().filter(|m| !m.seen).count() as i64;
                ThreadSummary {
                    thread_id: if latest.thread_id.is_empty() {
                        key
                    } else {
                        latest.thread_id.clone()
                    },
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
        v.sort_by(|a, b| {
            a.received_at
                .cmp(&b.received_at)
                .then_with(|| a.id.cmp(&b.id))
        });
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
        if let Some((_, c)) = v
            .iter_mut()
            .find(|(mb, c)| mb == mailbox && c.addr == addr_l)
        {
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
                blank_contact(
                    addr_l,
                    name.trim().to_string(),
                    manual,
                    if manual { 0 } else { 1 },
                ),
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
        let owned_groups: Vec<String> = self
            .contact_groups
            .lock()
            .expect("contact_groups lock poisoned")
            .iter()
            .filter(|g| g.user == mailbox)
            .map(|g| g.id.clone())
            .collect();
        self.contact_group_members
            .lock()
            .expect("contact_group_members lock poisoned")
            .retain(|(gid, contact_addr)| {
                contact_addr != &addr_l || !owned_groups.iter().any(|id| id == gid)
            });
        Ok(())
    }

    async fn list_contacts(&self, mailbox: &str, limit: i64) -> Result<Vec<Contact>, StoreError> {
        let mut v: Vec<Contact> = self
            .contacts
            .lock()
            .expect("contacts lock poisoned")
            .iter()
            .filter(|(mb, _)| mb == mailbox)
            .map(|(_, c)| c.clone())
            .collect();
        sort_contacts_for_settings(&mut v);
        v.truncate(limit.max(0) as usize);
        Ok(v)
    }

    async fn save_contact(&self, mailbox: &str, contact: &Contact) -> Result<(), StoreError> {
        let addr_l = contact.addr.trim().to_lowercase();
        if addr_l.is_empty() {
            return Ok(());
        }
        let mut saved = contact.clone();
        saved.addr = addr_l.clone();
        saved.name = saved.name.trim().to_string();
        saved.phone = saved.phone.trim().to_string();
        saved.company = saved.company.trim().to_string();
        saved.title = saved.title.trim().to_string();
        saved.notes = saved.notes.trim().to_string();
        saved.manual = true;
        let mut v = self.contacts.lock().expect("contacts lock poisoned");
        if let Some((_, existing)) = v
            .iter_mut()
            .find(|(mb, c)| mb == mailbox && c.addr == addr_l)
        {
            let seen_count = existing.seen_count.max(saved.seen_count);
            *existing = saved;
            existing.seen_count = seen_count;
        } else {
            v.push((mailbox.to_string(), saved));
        }
        Ok(())
    }

    async fn duplicate_contacts(&self, mailbox: &str) -> Result<Vec<Contact>, StoreError> {
        let mut by_addr: BTreeMap<String, Vec<Contact>> = BTreeMap::new();
        for (_, contact) in self
            .contacts
            .lock()
            .expect("contacts lock poisoned")
            .iter()
            .filter(|(mb, _)| mb == mailbox)
        {
            by_addr
                .entry(contact.addr.to_lowercase())
                .or_default()
                .push(contact.clone());
        }
        let mut dupes: Vec<Contact> = by_addr
            .into_values()
            .filter(|rows| rows.len() > 1)
            .flatten()
            .collect();
        sort_contacts_for_settings(&mut dupes);
        Ok(dupes)
    }

    async fn merge_duplicate_contact(&self, mailbox: &str, addr: &str) -> Result<(), StoreError> {
        let target = addr.trim().to_lowercase();
        if target.is_empty() {
            return Ok(());
        }
        let mut contacts = self.contacts.lock().expect("contacts lock poisoned");
        let mut merged: Option<Contact> = None;
        contacts.retain(|(mb, contact)| {
            if mb == mailbox && contact.addr.to_lowercase() == target {
                match &mut merged {
                    Some(m) => merge_contact_fields(m, contact),
                    None => {
                        let mut c = contact.clone();
                        c.addr = target.clone();
                        merged = Some(c);
                    }
                }
                false
            } else {
                true
            }
        });
        if let Some(contact) = merged {
            contacts.push((mailbox.to_string(), contact));
            let owned_groups: Vec<String> = self
                .contact_groups
                .lock()
                .expect("contact_groups lock poisoned")
                .iter()
                .filter(|g| g.user == mailbox)
                .map(|g| g.id.clone())
                .collect();
            let mut members = self
                .contact_group_members
                .lock()
                .expect("contact_group_members lock poisoned");
            for (gid, contact_addr) in members.iter_mut() {
                if owned_groups.iter().any(|id| id == gid) && contact_addr.to_lowercase() == target
                {
                    *contact_addr = target.clone();
                }
            }
            members.sort();
            members.dedup();
        }
        Ok(())
    }

    async fn list_contact_groups(&self, mailbox: &str) -> Result<Vec<ContactGroup>, StoreError> {
        let mut v: Vec<ContactGroup> = self
            .contact_groups
            .lock()
            .expect("contact_groups lock poisoned")
            .iter()
            .filter(|g| g.user == mailbox)
            .cloned()
            .collect();
        sort_contact_groups(&mut v);
        Ok(v)
    }

    async fn save_contact_group(&self, group: &ContactGroup) -> Result<(), StoreError> {
        let mut saved = group.clone();
        saved.name = saved.name.trim().to_string();
        if saved.name.is_empty() {
            return Ok(());
        }
        let mut groups = self
            .contact_groups
            .lock()
            .expect("contact_groups lock poisoned");
        if let Some(existing) = groups
            .iter_mut()
            .find(|g| g.user == saved.user && g.id == saved.id)
        {
            existing.name = saved.name;
        } else if let Some(existing) = groups
            .iter_mut()
            .find(|g| g.user == saved.user && g.name.eq_ignore_ascii_case(&saved.name))
        {
            existing.name = saved.name;
        } else {
            groups.push(saved);
        }
        Ok(())
    }

    async fn delete_contact_group(&self, mailbox: &str, group_id: &str) -> Result<(), StoreError> {
        let mut groups = self
            .contact_groups
            .lock()
            .expect("contact_groups lock poisoned");
        let before: Vec<String> = groups
            .iter()
            .filter(|g| g.user == mailbox && g.id == group_id)
            .map(|g| g.id.clone())
            .collect();
        groups.retain(|g| !(g.user == mailbox && g.id == group_id));
        drop(groups);
        self.contact_group_members
            .lock()
            .expect("contact_group_members lock poisoned")
            .retain(|(gid, _)| !before.iter().any(|id| id == gid));
        Ok(())
    }

    async fn add_contact_group_member(
        &self,
        mailbox: &str,
        group_id: &str,
        contact_addr: &str,
    ) -> Result<(), StoreError> {
        let addr_l = contact_addr.trim().to_lowercase();
        if addr_l.is_empty() {
            return Ok(());
        }
        let group_owned = self
            .contact_groups
            .lock()
            .expect("contact_groups lock poisoned")
            .iter()
            .any(|g| g.user == mailbox && g.id == group_id);
        let contact_owned = self
            .contacts
            .lock()
            .expect("contacts lock poisoned")
            .iter()
            .any(|(mb, c)| mb == mailbox && c.addr == addr_l);
        if !group_owned || !contact_owned {
            return Ok(());
        }
        let mut members = self
            .contact_group_members
            .lock()
            .expect("contact_group_members lock poisoned");
        if !members
            .iter()
            .any(|(gid, addr)| gid == group_id && addr == &addr_l)
        {
            members.push((group_id.to_string(), addr_l));
        }
        Ok(())
    }

    async fn delete_contact_group_member(
        &self,
        mailbox: &str,
        group_id: &str,
        contact_addr: &str,
    ) -> Result<(), StoreError> {
        let group_owned = self
            .contact_groups
            .lock()
            .expect("contact_groups lock poisoned")
            .iter()
            .any(|g| g.user == mailbox && g.id == group_id);
        if !group_owned {
            return Ok(());
        }
        let addr_l = contact_addr.trim().to_lowercase();
        self.contact_group_members
            .lock()
            .expect("contact_group_members lock poisoned")
            .retain(|(gid, addr)| !(gid == group_id && addr == &addr_l));
        Ok(())
    }

    async fn list_contact_group_members(
        &self,
        mailbox: &str,
        group_id: &str,
    ) -> Result<Vec<Contact>, StoreError> {
        let group_owned = self
            .contact_groups
            .lock()
            .expect("contact_groups lock poisoned")
            .iter()
            .any(|g| g.user == mailbox && g.id == group_id);
        if !group_owned {
            return Ok(Vec::new());
        }
        let member_addrs: Vec<String> = self
            .contact_group_members
            .lock()
            .expect("contact_group_members lock poisoned")
            .iter()
            .filter(|(gid, _)| gid == group_id)
            .map(|(_, addr)| addr.clone())
            .collect();
        let mut v: Vec<Contact> = self
            .contacts
            .lock()
            .expect("contacts lock poisoned")
            .iter()
            .filter(|(mb, c)| mb == mailbox && member_addrs.iter().any(|a| a == &c.addr))
            .map(|(_, c)| c.clone())
            .collect();
        sort_contacts_for_settings(&mut v);
        Ok(v)
    }

    async fn contacts_for_group_name(
        &self,
        mailbox: &str,
        group_name: &str,
    ) -> Result<Vec<Contact>, StoreError> {
        let name = group_name.trim();
        if name.is_empty() {
            return Ok(Vec::new());
        }
        let group_id = self
            .contact_groups
            .lock()
            .expect("contact_groups lock poisoned")
            .iter()
            .find(|g| g.user == mailbox && g.name.eq_ignore_ascii_case(name))
            .map(|g| g.id.clone());
        match group_id {
            Some(id) => self.list_contact_group_members(mailbox, &id).await,
            None => Ok(Vec::new()),
        }
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
        v.sort_by(|a, b| {
            a.name
                .to_lowercase()
                .cmp(&b.name.to_lowercase())
                .then_with(|| a.id.cmp(&b.id))
        });
        Ok(v)
    }

    async fn add_label(&self, label: &Label) -> Result<(), StoreError> {
        self.labels
            .lock()
            .expect("labels lock poisoned")
            .push(label.clone());
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
        let mut v = self
            .message_labels
            .lock()
            .expect("message_labels lock poisoned");
        if !v
            .iter()
            .any(|(mb, m, l)| mb == mailbox && m == message_id && l == label_id)
        {
            v.push((
                mailbox.to_string(),
                message_id.to_string(),
                label_id.to_string(),
            ));
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
        v.sort_by(|a, b| {
            a.name
                .to_lowercase()
                .cmp(&b.name.to_lowercase())
                .then_with(|| a.id.cmp(&b.id))
        });
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
        v.sort_by(|a, b| {
            b.received_at
                .cmp(&a.received_at)
                .then_with(|| b.id.cmp(&a.id))
        });
        apply_before(&mut v, before);
        v.truncate(limit.max(0) as usize);
        Ok(v.iter().map(summary).collect())
    }

    async fn list_sender_lists(&self, mailbox: &str) -> Result<Vec<SenderListEntry>, StoreError> {
        let mut v: Vec<SenderListEntry> = self
            .sender_lists
            .lock()
            .expect("sender_lists lock poisoned")
            .iter()
            .filter(|e| e.user == mailbox)
            .cloned()
            .collect();
        v.sort_by(|a, b| {
            a.kind
                .cmp(&b.kind)
                .then_with(|| a.address_or_domain.cmp(&b.address_or_domain))
                .then_with(|| a.id.cmp(&b.id))
        });
        Ok(v)
    }

    async fn upsert_sender_list(&self, entry: &SenderListEntry) -> Result<(), StoreError> {
        let mut v = self
            .sender_lists
            .lock()
            .expect("sender_lists lock poisoned");
        v.retain(|e| {
            !(e.user == entry.user
                && e.address_or_domain == entry.address_or_domain
                && e.kind != entry.kind)
        });
        if let Some(existing) = v.iter_mut().find(|e| {
            e.user == entry.user
                && e.address_or_domain == entry.address_or_domain
                && e.kind == entry.kind
        }) {
            existing.created_at = entry.created_at;
        } else {
            v.push(entry.clone());
        }
        Ok(())
    }

    async fn delete_sender_list(&self, mailbox: &str, id: &str) -> Result<(), StoreError> {
        self.sender_lists
            .lock()
            .expect("sender_lists lock poisoned")
            .retain(|e| !(e.user == mailbox && e.id == id));
        Ok(())
    }

    async fn set_spam_annotation(&self, annotation: &SpamAnnotation) -> Result<(), StoreError> {
        let mut v = self
            .spam_annotations
            .lock()
            .expect("spam_annotations lock poisoned");
        if let Some(existing) = v
            .iter_mut()
            .find(|a| a.mailbox == annotation.mailbox && a.message_id == annotation.message_id)
        {
            *existing = annotation.clone();
        } else {
            v.push(annotation.clone());
        }
        Ok(())
    }

    async fn spam_annotation(
        &self,
        mailbox: &str,
        message_id: &str,
    ) -> Result<Option<SpamAnnotation>, StoreError> {
        Ok(self
            .spam_annotations
            .lock()
            .expect("spam_annotations lock poisoned")
            .iter()
            .find(|a| a.mailbox == mailbox && a.message_id == message_id)
            .cloned())
    }

    async fn delete_spam_annotation(
        &self,
        mailbox: &str,
        message_id: &str,
    ) -> Result<(), StoreError> {
        self.spam_annotations
            .lock()
            .expect("spam_annotations lock poisoned")
            .retain(|a| !(a.mailbox == mailbox && a.message_id == message_id));
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
                 folder TEXT NOT NULL DEFAULT 'INBOX', \
                 snooze_until BIGINT NOT NULL DEFAULT 0, \
                 muted BOOLEAN NOT NULL DEFAULT FALSE\
             )",
        )
        .execute(&self.pool)
        .await?;
        // Star/flag: added out-of-band (idempotent) so an already-provisioned `messages` table
        // gains the column without a destructive rebuild. Nullable (existing rows read as unset).
        sqlx::query("ALTER TABLE messages ADD COLUMN IF NOT EXISTS starred BOOLEAN DEFAULT FALSE")
            .execute(&self.pool)
            .await?;
        sqlx::query(
            "ALTER TABLE messages ADD COLUMN IF NOT EXISTS snooze_until BIGINT NOT NULL DEFAULT 0",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "ALTER TABLE messages ADD COLUMN IF NOT EXISTS muted BOOLEAN NOT NULL DEFAULT FALSE",
        )
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
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_messages_msgid ON messages (mailbox, message_id)",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_messages_mailbox ON messages (mailbox, received_at)",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_messages_starred ON messages (mailbox, starred, received_at)")
            .execute(&self.pool)
            .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_messages_snoozed ON messages (mailbox, snooze_until, received_at)")
            .execute(&self.pool)
            .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_messages_muted_thread ON messages (mailbox, muted, thread_id)")
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
	                 mailbox TEXT NOT NULL DEFAULT '', \
	                 batch_id TEXT NOT NULL DEFAULT '', \
	                 raw TEXT NOT NULL, \
	                 env_from TEXT NOT NULL DEFAULT '', \
	                 rcpts TEXT NOT NULL DEFAULT '', \
	                 to_domain TEXT NOT NULL, \
	                 attempts BIGINT NOT NULL DEFAULT 0, \
	                 next_at BIGINT NOT NULL DEFAULT 0, \
	                 send_at BIGINT NOT NULL DEFAULT 0, \
	                 sent_copy_filed BOOLEAN NOT NULL DEFAULT FALSE, \
	                 status TEXT NOT NULL DEFAULT 'queued'\
	             )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "ALTER TABLE outbound_queue ADD COLUMN IF NOT EXISTS mailbox TEXT NOT NULL DEFAULT ''",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "ALTER TABLE outbound_queue ADD COLUMN IF NOT EXISTS batch_id TEXT NOT NULL DEFAULT ''",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "ALTER TABLE outbound_queue ADD COLUMN IF NOT EXISTS send_at BIGINT NOT NULL DEFAULT 0",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
	            "ALTER TABLE outbound_queue ADD COLUMN IF NOT EXISTS sent_copy_filed BOOLEAN NOT NULL DEFAULT FALSE",
	        )
	        .execute(&self.pool)
	        .await?;
        sqlx::query("UPDATE outbound_queue SET batch_id = id WHERE batch_id = ''")
            .execute(&self.pool)
            .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_outbound_due ON outbound_queue (status, next_at)",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
	            "CREATE INDEX IF NOT EXISTS idx_outbound_due_send_at ON outbound_queue (status, next_at, send_at)",
	        )
	        .execute(&self.pool)
	        .await?;
        sqlx::query(
	            "CREATE INDEX IF NOT EXISTS idx_outbound_scheduled ON outbound_queue (mailbox, status, send_at, batch_id)",
	        )
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
        // Per-mailbox settings (signature + undo send + display prefs + auto-reply): added out-of-band
        // (idempotent) so an already-provisioned `mailboxes` table gains the columns without a
        // destructive rebuild. Nullable — pre-migration rows read as defaults.
        for stmt in [
            "ALTER TABLE mailboxes ADD COLUMN IF NOT EXISTS signature TEXT",
            "ALTER TABLE mailboxes ADD COLUMN IF NOT EXISTS undo_send_window_secs BIGINT DEFAULT 10",
            "ALTER TABLE mailboxes ADD COLUMN IF NOT EXISTS density TEXT DEFAULT 'normal'",
            "ALTER TABLE mailboxes ADD COLUMN IF NOT EXISTS reading_pane TEXT DEFAULT 'off'",
            "ALTER TABLE mailboxes ADD COLUMN IF NOT EXISTS theme TEXT DEFAULT 'system'",
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
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_send_identities_mailbox ON send_identities (mailbox)",
        )
        .execute(&self.pool)
        .await?;
        // Contacts (harvested correspondents + manual), keyed `(mailbox, addr)` for upsert.
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS contacts (\
                 mailbox TEXT NOT NULL, \
                 addr TEXT NOT NULL, \
                 name TEXT NOT NULL DEFAULT '', \
                 phone TEXT NOT NULL DEFAULT '', \
                 company TEXT NOT NULL DEFAULT '', \
                 title TEXT NOT NULL DEFAULT '', \
                 notes TEXT NOT NULL DEFAULT '', \
                 manual BOOLEAN NOT NULL DEFAULT FALSE, \
                 seen_count BIGINT NOT NULL DEFAULT 0, \
                 PRIMARY KEY (mailbox, addr)\
             )",
        )
        .execute(&self.pool)
        .await?;
        for stmt in [
            "ALTER TABLE contacts ADD COLUMN IF NOT EXISTS phone TEXT NOT NULL DEFAULT ''",
            "ALTER TABLE contacts ADD COLUMN IF NOT EXISTS company TEXT NOT NULL DEFAULT ''",
            "ALTER TABLE contacts ADD COLUMN IF NOT EXISTS title TEXT NOT NULL DEFAULT ''",
            "ALTER TABLE contacts ADD COLUMN IF NOT EXISTS notes TEXT NOT NULL DEFAULT ''",
        ] {
            sqlx::query(stmt).execute(&self.pool).await?;
        }
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS contact_groups (\
                 id TEXT PRIMARY KEY, \
                 \"user\" TEXT NOT NULL, \
                 name TEXT NOT NULL, \
                 created_at BIGINT NOT NULL DEFAULT 0\
             )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_contact_groups_user_name \
             ON contact_groups (\"user\", name)",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS contact_group_members (\
                 group_id TEXT NOT NULL, \
                 contact_id TEXT NOT NULL, \
                 PRIMARY KEY (group_id, contact_id)\
             )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_contact_group_members_contact \
             ON contact_group_members (contact_id, group_id)",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS sender_lists (\
                 id TEXT PRIMARY KEY, \
                 \"user\" TEXT NOT NULL, \
                 address_or_domain TEXT NOT NULL, \
                 kind TEXT NOT NULL, \
                 created_at BIGINT NOT NULL DEFAULT 0\
             )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_sender_lists_unique \
             ON sender_lists (\"user\", address_or_domain, kind)",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_sender_lists_user \
             ON sender_lists (\"user\", kind, address_or_domain)",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS signatures (\
                 id TEXT PRIMARY KEY, \
                 \"user\" TEXT NOT NULL, \
                 identity TEXT NOT NULL DEFAULT '', \
                 name TEXT NOT NULL, \
                 body_html TEXT NOT NULL DEFAULT '', \
                 body_text TEXT NOT NULL DEFAULT '', \
                 is_default BOOLEAN NOT NULL DEFAULT FALSE, \
                 created_at BIGINT NOT NULL DEFAULT 0\
             )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_signatures_user_identity \
             ON signatures (\"user\", identity, is_default, name, id)",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "INSERT INTO signatures \
                 (id, \"user\", identity, name, body_html, body_text, is_default, created_at) \
             SELECT 'sig_legacy_' || addr, addr, '', 'Default', '', signature, TRUE, 0 \
             FROM mailboxes m \
             WHERE COALESCE(signature, '') <> '' \
               AND NOT EXISTS (\
                   SELECT 1 FROM signatures s \
                   WHERE s.\"user\" = m.addr AND s.identity = '' AND s.is_default = TRUE\
               ) \
             ON CONFLICT (id) DO NOTHING",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS templates (\
                 id TEXT PRIMARY KEY, \
                 \"user\" TEXT NOT NULL, \
                 name TEXT NOT NULL, \
                 body_html TEXT NOT NULL DEFAULT '', \
                 body_text TEXT NOT NULL DEFAULT '', \
                 created_at BIGINT NOT NULL DEFAULT 0, \
                 updated_at BIGINT NOT NULL DEFAULT 0\
             )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_templates_user \
             ON templates (\"user\", name, id)",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS spam_annotations (\
                 message_id TEXT PRIMARY KEY, \
                 mailbox TEXT NOT NULL, \
                 score BIGINT NOT NULL DEFAULT 0, \
                 reason TEXT NOT NULL DEFAULT ''\
             )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_spam_annotations_mailbox \
             ON spam_annotations (mailbox, message_id)",
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
            signature: row
                .try_get::<Option<String>, _>("signature")?
                .unwrap_or_default(),
            undo_send_window_secs: row
                .try_get::<Option<i64>, _>("undo_send_window_secs")?
                .unwrap_or(DEFAULT_UNDO_SEND_WINDOW_SECS),
            density: row
                .try_get::<Option<String>, _>("density")?
                .unwrap_or_else(|| DEFAULT_DENSITY.to_string()),
            reading_pane: row
                .try_get::<Option<String>, _>("reading_pane")?
                .unwrap_or_else(|| DEFAULT_READING_PANE.to_string()),
            theme: row
                .try_get::<Option<String>, _>("theme")?
                .unwrap_or_else(|| DEFAULT_THEME.to_string()),
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
            snooze_until: row.try_get::<Option<i64>, _>("snooze_until")?.unwrap_or(0),
            muted: row.try_get::<Option<bool>, _>("muted")?.unwrap_or(false),
            thread_id: row
                .try_get::<Option<String>, _>("thread_id")?
                .unwrap_or_default(),
            message_id: row
                .try_get::<Option<String>, _>("message_id")?
                .unwrap_or_default(),
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
            mailbox: row.try_get("mailbox")?,
            batch_id: row.try_get("batch_id")?,
            raw: row.try_get("raw")?,
            env_from: row.try_get("env_from")?,
            rcpts: rcpts
                .split(',')
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect(),
            to_domain: row.try_get("to_domain")?,
            attempts: row.try_get("attempts")?,
            next_at: row.try_get("next_at")?,
            send_at: row.try_get("send_at")?,
            sent_copy_filed: row.try_get("sent_copy_filed")?,
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
            phone: row
                .try_get::<Option<String>, _>("phone")?
                .unwrap_or_default(),
            company: row
                .try_get::<Option<String>, _>("company")?
                .unwrap_or_default(),
            title: row
                .try_get::<Option<String>, _>("title")?
                .unwrap_or_default(),
            notes: row
                .try_get::<Option<String>, _>("notes")?
                .unwrap_or_default(),
            manual: row.try_get("manual")?,
            seen_count: row.try_get("seen_count")?,
        })
    }

    fn contact_group_from_row(row: &sqlx::postgres::PgRow) -> Result<ContactGroup, sqlx::Error> {
        Ok(ContactGroup {
            id: row.try_get("id")?,
            user: row.try_get("user")?,
            name: row.try_get("name")?,
            created_at: row.try_get("created_at")?,
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

    fn sender_list_from_row(row: &sqlx::postgres::PgRow) -> Result<SenderListEntry, sqlx::Error> {
        Ok(SenderListEntry {
            id: row.try_get("id")?,
            user: row.try_get("user")?,
            address_or_domain: row.try_get("address_or_domain")?,
            kind: row.try_get("kind")?,
            created_at: row.try_get("created_at")?,
        })
    }

    fn signature_from_row(row: &sqlx::postgres::PgRow) -> Result<Signature, sqlx::Error> {
        Ok(Signature {
            id: row.try_get("id")?,
            user: row.try_get("user")?,
            identity: row.try_get("identity")?,
            name: row.try_get("name")?,
            body_html: row.try_get("body_html")?,
            body_text: row.try_get("body_text")?,
            is_default: row.try_get("is_default")?,
            created_at: row.try_get("created_at")?,
        })
    }

    fn template_from_row(row: &sqlx::postgres::PgRow) -> Result<Template, sqlx::Error> {
        Ok(Template {
            id: row.try_get("id")?,
            user: row.try_get("user")?,
            name: row.try_get("name")?,
            body_html: row.try_get("body_html")?,
            body_text: row.try_get("body_text")?,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
        })
    }

    fn spam_annotation_from_row(
        row: &sqlx::postgres::PgRow,
    ) -> Result<SpamAnnotation, sqlx::Error> {
        Ok(SpamAnnotation {
            mailbox: row.try_get("mailbox")?,
            message_id: row.try_get("message_id")?,
            score: row.try_get("score")?,
            reason: row.try_get("reason")?,
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
        row.as_ref()
            .map(Self::mailbox_from_row)
            .transpose()
            .map_err(backend)
    }

    async fn mailbox_for_owner(&self, owner_sub: &str) -> Result<Option<Mailbox>, StoreError> {
        let row = sqlx::query(
            "SELECT addr, owner_sub FROM mailboxes WHERE owner_sub = $1 ORDER BY addr LIMIT 1",
        )
        .bind(owner_sub)
        .fetch_optional(&self.pool)
        .await
        .map_err(backend)?;
        row.as_ref()
            .map(Self::mailbox_from_row)
            .transpose()
            .map_err(backend)
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
                  received_at, seen, folder, starred, snooze_until, muted, thread_id, message_id) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)",
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
        .bind(msg.snooze_until)
        .bind(msg.muted)
        .bind(&msg.thread_id)
        .bind(&msg.message_id)
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        Ok(())
    }

    async fn upsert_draft(&self, msg: &Message) -> Result<(), StoreError> {
        if msg.folder != "Drafts" {
            return Err(StoreError::Backend(
                "upsert_draft requires folder=Drafts".to_string(),
            ));
        }
        let result = sqlx::query(
            "INSERT INTO messages \
                 (id, mailbox, msg_from, msg_to, subject, raw_rfc822, body_text, body_html, \
                  received_at, seen, folder, starred, snooze_until, muted, thread_id, message_id) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'Drafts', $11, $12, $13, $14, $15) \
             ON CONFLICT (id) DO UPDATE SET \
                 msg_from = EXCLUDED.msg_from, \
                 msg_to = EXCLUDED.msg_to, \
                 subject = EXCLUDED.subject, \
                 raw_rfc822 = EXCLUDED.raw_rfc822, \
                 body_text = EXCLUDED.body_text, \
                 body_html = EXCLUDED.body_html, \
                 received_at = EXCLUDED.received_at, \
                 seen = EXCLUDED.seen, \
                 folder = EXCLUDED.folder, \
                 starred = EXCLUDED.starred, \
                 snooze_until = EXCLUDED.snooze_until, \
                 muted = EXCLUDED.muted, \
                 thread_id = EXCLUDED.thread_id, \
                 message_id = EXCLUDED.message_id \
             WHERE messages.mailbox = EXCLUDED.mailbox AND messages.folder = 'Drafts'",
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
        .bind(msg.starred)
        .bind(msg.snooze_until)
        .bind(msg.muted)
        .bind(&msg.thread_id)
        .bind(&msg.message_id)
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        if result.rows_affected() == 0 {
            return Err(StoreError::Backend(
                "draft id is not an editable draft".to_string(),
            ));
        }
        Ok(())
    }

    async fn delete_draft(&self, mailbox: &str, id: &str) -> Result<bool, StoreError> {
        let result = sqlx::query(
            "DELETE FROM messages WHERE mailbox = $1 AND id = $2 AND folder = 'Drafts'",
        )
        .bind(mailbox)
        .bind(id)
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        Ok(result.rows_affected() > 0)
    }

    async fn list_messages(
        &self,
        mailbox: &str,
        limit: i64,
    ) -> Result<Vec<MessageSummary>, StoreError> {
        let rows = sqlx::query(
            "SELECT id, msg_from, subject, received_at, seen, starred, snooze_until, muted, folder FROM messages \
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
            "SELECT id, msg_from, subject, received_at, seen, starred, snooze_until, muted, folder FROM messages \
             WHERE mailbox = $1 AND folder = $2 \
               AND ($2 <> 'INBOX' OR COALESCE(snooze_until, 0) <= $3) \
               AND (received_at < $4 OR (received_at = $4 AND id < $5)) \
             ORDER BY received_at DESC, id DESC LIMIT $6",
        )
        .bind(mailbox)
        .bind(folder)
        .bind(crate::util::now_secs())
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
            "SELECT id, msg_from, subject, received_at, seen, starred, snooze_until, muted, folder FROM messages \
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

    async fn list_snoozed(
        &self,
        mailbox: &str,
        now: i64,
        before: Option<(i64, String)>,
        limit: i64,
    ) -> Result<Vec<MessageSummary>, StoreError> {
        let (cur_ts, cur_id) = Self::cursor(before);
        let rows = sqlx::query(
            "SELECT id, msg_from, subject, received_at, seen, starred, snooze_until, muted, folder FROM messages \
             WHERE mailbox = $1 AND COALESCE(snooze_until, 0) > $2 \
               AND (received_at < $3 OR (received_at = $3 AND id < $4)) \
             ORDER BY received_at DESC, id DESC LIMIT $5",
        )
        .bind(mailbox)
        .bind(now)
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
        query: &SearchQuery,
        folder: Option<&str>,
        before: Option<(i64, String)>,
        limit: i64,
    ) -> Result<Vec<MessageSummary>, StoreError> {
        let (cur_ts, cur_id) = Self::cursor(before);
        let mut sql = String::from(
            "SELECT m.id, m.msg_from, m.subject, m.received_at, m.seen, m.starred, m.snooze_until, m.muted, m.folder FROM messages m WHERE m.mailbox = $1",
        );
        let mut binds = Vec::new();
        let mut next_param = 2_usize;

        if let Some(folder) = folder {
            let param = push_text_param(&mut binds, &mut next_param, folder.to_string());
            sql.push_str(&format!(" AND m.folder = {param}"));
            if folder.eq_ignore_ascii_case("INBOX") {
                let now_param =
                    push_int_param(&mut binds, &mut next_param, crate::util::now_secs());
                sql.push_str(&format!(" AND COALESCE(m.snooze_until, 0) <= {now_param}"));
            }
        }

        let mut positives = Vec::new();
        let mut negatives = Vec::new();
        for term in &query.text_terms {
            let condition = search_text_condition(&term.value, &mut binds, &mut next_param);
            if term.negated {
                negatives.push(condition);
            } else {
                positives.push(condition);
            }
        }
        for predicate in &query.predicates {
            let condition = search_predicate_condition(predicate, &mut binds, &mut next_param);
            if predicate.negated {
                negatives.push(condition);
            } else {
                positives.push(condition);
            }
        }

        if !positives.is_empty() {
            if query.or_mode {
                sql.push_str(" AND (");
                sql.push_str(&positives.join(" OR "));
                sql.push(')');
            } else {
                for condition in positives {
                    sql.push_str(" AND ");
                    sql.push_str(&condition);
                }
            }
        }
        for condition in negatives {
            sql.push_str(" AND NOT (");
            sql.push_str(&condition);
            sql.push(')');
        }

        let cur_ts_param = push_int_param(&mut binds, &mut next_param, cur_ts);
        let cur_id_param = push_text_param(&mut binds, &mut next_param, cur_id);
        let limit_param = push_int_param(&mut binds, &mut next_param, limit);
        sql.push_str(&format!(
            " AND (m.received_at < {cur_ts_param} OR (m.received_at = {cur_ts_param} AND m.id < {cur_id_param})) \
             ORDER BY m.received_at DESC, m.id DESC LIMIT {limit_param}",
        ));

        let mut q = sqlx::query(&sql).bind(mailbox);
        for bind in &binds {
            q = match bind {
                SearchSqlBind::Text(value) => q.bind(value),
                SearchSqlBind::Int(value) => q.bind(*value),
            };
        }
        let rows = q.fetch_all(&self.pool).await.map_err(backend)?;
        rows.iter()
            .map(summary_from_row)
            .collect::<Result<Vec<_>, sqlx::Error>>()
            .map_err(backend)
    }

    async fn get_message(&self, id: &str) -> Result<Option<Message>, StoreError> {
        let row = sqlx::query(
            "SELECT id, mailbox, msg_from, msg_to, subject, raw_rfc822, body_text, body_html, \
                    received_at, seen, folder, starred, snooze_until, muted, thread_id, message_id \
             FROM messages WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(backend)?;
        row.as_ref()
            .map(Self::message_from_row)
            .transpose()
            .map_err(backend)
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

    async fn snooze_message(&self, id: &str, until: i64) -> Result<(), StoreError> {
        sqlx::query(
            "UPDATE messages SET snooze_until = $1, folder = CASE WHEN $1 > 0 THEN 'Archive' ELSE folder END WHERE id = $2",
        )
        .bind(until.max(0))
        .bind(id)
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        Ok(())
    }

    async fn unsnooze_message(&self, id: &str) -> Result<(), StoreError> {
        sqlx::query("UPDATE messages SET snooze_until = 0, folder = 'INBOX' WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(backend)?;
        Ok(())
    }

    async fn restore_due_snoozes(&self, now: i64, limit: i64) -> Result<i64, StoreError> {
        let result = sqlx::query(
            "UPDATE messages SET snooze_until = 0, folder = 'INBOX' \
             WHERE id IN ( \
               SELECT id FROM messages WHERE COALESCE(snooze_until, 0) > 0 AND snooze_until <= $1 \
               ORDER BY snooze_until ASC, id ASC LIMIT $2 \
             )",
        )
        .bind(now)
        .bind(limit.max(0))
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        Ok(result.rows_affected() as i64)
    }

    async fn set_thread_muted(&self, msg: &Message, muted: bool) -> Result<(), StoreError> {
        sqlx::query(
            "UPDATE messages SET muted = $5 \
             WHERE mailbox = $1 AND ( \
               ($2 <> '' AND (thread_id = $2 OR message_id = $2)) \
               OR ($2 = '' AND $3 <> '' AND (message_id = $3 OR thread_id = $3)) \
               OR ($2 = '' AND $3 = '' AND id = $4) \
             )",
        )
        .bind(&msg.mailbox)
        .bind(&msg.thread_id)
        .bind(&msg.message_id)
        .bind(&msg.id)
        .bind(muted)
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        Ok(())
    }

    async fn is_thread_muted(&self, mailbox: &str, thread_id: &str) -> Result<bool, StoreError> {
        if thread_id.is_empty() {
            return Ok(false);
        }
        let row = sqlx::query(
            "SELECT EXISTS( \
               SELECT 1 FROM messages \
               WHERE mailbox = $1 AND muted = TRUE AND (thread_id = $2 OR message_id = $2) \
             ) AS yes",
        )
        .bind(mailbox)
        .bind(thread_id)
        .fetch_one(&self.pool)
        .await
        .map_err(backend)?;
        row.try_get("yes").map_err(backend)
    }

    async fn unseen_count(&self, mailbox: &str) -> Result<i64, StoreError> {
        let row = sqlx::query(
            "SELECT COUNT(*) AS n FROM messages \
             WHERE mailbox = $1 AND seen = FALSE AND COALESCE(snooze_until, 0) <= $2",
        )
        .bind(mailbox)
        .bind(crate::util::now_secs())
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
            "SELECT signature, undo_send_window_secs, density, reading_pane, theme, \
                    auto_reply_enabled, auto_reply_subject, auto_reply_body, auto_reply_until \
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
        let sig = signature.trim();
        let id = legacy_signature_id(mailbox);
        if sig.is_empty() {
            sqlx::query("DELETE FROM signatures WHERE \"user\" = $1 AND id = $2")
                .bind(mailbox)
                .bind(&id)
                .execute(&self.pool)
                .await
                .map_err(backend)?;
            return Ok(());
        }
        sqlx::query(
            "UPDATE signatures SET is_default = FALSE \
             WHERE \"user\" = $1 AND identity = '' AND id <> $2",
        )
        .bind(mailbox)
        .bind(&id)
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        sqlx::query(
            "INSERT INTO signatures \
                 (id, \"user\", identity, name, body_html, body_text, is_default, created_at) \
             VALUES ($1, $2, '', 'Default', '', $3, TRUE, $4) \
             ON CONFLICT (id) DO UPDATE SET \
                 \"user\" = EXCLUDED.\"user\", \
                 identity = '', \
                 name = 'Default', \
                 body_html = '', \
                 body_text = EXCLUDED.body_text, \
                 is_default = TRUE",
        )
        .bind(&id)
        .bind(mailbox)
        .bind(sig)
        .bind(crate::util::now_secs())
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        Ok(())
    }

    async fn list_signatures(&self, mailbox: &str) -> Result<Vec<Signature>, StoreError> {
        let rows = sqlx::query(
            "SELECT id, \"user\", identity, name, body_html, body_text, is_default, created_at \
             FROM signatures WHERE \"user\" = $1 \
             ORDER BY identity ASC, is_default DESC, name ASC, id ASC",
        )
        .bind(mailbox)
        .fetch_all(&self.pool)
        .await
        .map_err(backend)?;
        rows.iter()
            .map(Self::signature_from_row)
            .collect::<Result<Vec<_>, sqlx::Error>>()
            .map_err(backend)
    }

    async fn get_signature(
        &self,
        mailbox: &str,
        id: &str,
    ) -> Result<Option<Signature>, StoreError> {
        let row = sqlx::query(
            "SELECT id, \"user\", identity, name, body_html, body_text, is_default, created_at \
             FROM signatures WHERE \"user\" = $1 AND id = $2",
        )
        .bind(mailbox)
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(backend)?;
        row.as_ref()
            .map(Self::signature_from_row)
            .transpose()
            .map_err(backend)
    }

    async fn get_default_signature_for_identity(
        &self,
        mailbox: &str,
        identity: &str,
    ) -> Result<Option<Signature>, StoreError> {
        let wanted = identity.trim();
        if !wanted.is_empty() {
            let row = sqlx::query(
                "SELECT id, \"user\", identity, name, body_html, body_text, is_default, created_at \
                 FROM signatures \
                 WHERE \"user\" = $1 AND identity = $2 AND is_default = TRUE \
                 ORDER BY created_at DESC, id ASC LIMIT 1",
            )
            .bind(mailbox)
            .bind(wanted)
            .fetch_optional(&self.pool)
            .await
            .map_err(backend)?;
            if let Some(sig) = row
                .as_ref()
                .map(Self::signature_from_row)
                .transpose()
                .map_err(backend)?
            {
                return Ok(Some(sig));
            }
        }
        let row = sqlx::query(
            "SELECT id, \"user\", identity, name, body_html, body_text, is_default, created_at \
             FROM signatures \
             WHERE \"user\" = $1 AND identity = '' AND is_default = TRUE \
             ORDER BY created_at DESC, id ASC LIMIT 1",
        )
        .bind(mailbox)
        .fetch_optional(&self.pool)
        .await
        .map_err(backend)?;
        row.as_ref()
            .map(Self::signature_from_row)
            .transpose()
            .map_err(backend)
    }

    async fn create_signature(&self, signature: &Signature) -> Result<(), StoreError> {
        if signature.is_default {
            sqlx::query(
                "UPDATE signatures SET is_default = FALSE \
                 WHERE \"user\" = $1 AND identity = $2 AND id <> $3",
            )
            .bind(&signature.user)
            .bind(&signature.identity)
            .bind(&signature.id)
            .execute(&self.pool)
            .await
            .map_err(backend)?;
        }
        sqlx::query(
            "INSERT INTO signatures \
                 (id, \"user\", identity, name, body_html, body_text, is_default, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(&signature.id)
        .bind(&signature.user)
        .bind(&signature.identity)
        .bind(&signature.name)
        .bind(&signature.body_html)
        .bind(&signature.body_text)
        .bind(signature.is_default)
        .bind(signature.created_at)
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        Ok(())
    }

    async fn update_signature(&self, signature: &Signature) -> Result<(), StoreError> {
        if signature.is_default {
            sqlx::query(
                "UPDATE signatures SET is_default = FALSE \
                 WHERE \"user\" = $1 AND identity = $2 AND id <> $3",
            )
            .bind(&signature.user)
            .bind(&signature.identity)
            .bind(&signature.id)
            .execute(&self.pool)
            .await
            .map_err(backend)?;
        }
        sqlx::query(
            "UPDATE signatures SET identity = $1, name = $2, body_html = $3, \
                    body_text = $4, is_default = $5 \
             WHERE \"user\" = $6 AND id = $7",
        )
        .bind(&signature.identity)
        .bind(&signature.name)
        .bind(&signature.body_html)
        .bind(&signature.body_text)
        .bind(signature.is_default)
        .bind(&signature.user)
        .bind(&signature.id)
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        Ok(())
    }

    async fn delete_signature(&self, mailbox: &str, id: &str) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM signatures WHERE \"user\" = $1 AND id = $2")
            .bind(mailbox)
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(backend)?;
        Ok(())
    }

    async fn set_undo_send_window(&self, mailbox: &str, secs: i64) -> Result<(), StoreError> {
        sqlx::query("UPDATE mailboxes SET undo_send_window_secs = $1 WHERE addr = $2")
            .bind(secs)
            .bind(mailbox)
            .execute(&self.pool)
            .await
            .map_err(backend)?;
        Ok(())
    }

    async fn set_display_preferences(
        &self,
        mailbox: &str,
        density: &str,
        reading_pane: &str,
        theme: &str,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "UPDATE mailboxes SET density = $1, reading_pane = $2, theme = $3 WHERE addr = $4",
        )
        .bind(density)
        .bind(reading_pane)
        .bind(theme)
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

    async fn list_templates(&self, mailbox: &str) -> Result<Vec<Template>, StoreError> {
        let rows = sqlx::query(
            "SELECT id, \"user\", name, body_html, body_text, created_at, updated_at \
             FROM templates WHERE \"user\" = $1 ORDER BY name ASC, id ASC",
        )
        .bind(mailbox)
        .fetch_all(&self.pool)
        .await
        .map_err(backend)?;
        rows.iter()
            .map(Self::template_from_row)
            .collect::<Result<Vec<_>, sqlx::Error>>()
            .map_err(backend)
    }

    async fn get_template(&self, mailbox: &str, id: &str) -> Result<Option<Template>, StoreError> {
        let row = sqlx::query(
            "SELECT id, \"user\", name, body_html, body_text, created_at, updated_at \
             FROM templates WHERE \"user\" = $1 AND id = $2",
        )
        .bind(mailbox)
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(backend)?;
        row.as_ref()
            .map(Self::template_from_row)
            .transpose()
            .map_err(backend)
    }

    async fn create_template(&self, template: &Template) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO templates \
                 (id, \"user\", name, body_html, body_text, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(&template.id)
        .bind(&template.user)
        .bind(&template.name)
        .bind(&template.body_html)
        .bind(&template.body_text)
        .bind(template.created_at)
        .bind(template.updated_at)
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        Ok(())
    }

    async fn update_template(&self, template: &Template) -> Result<(), StoreError> {
        sqlx::query(
            "UPDATE templates SET name = $1, body_html = $2, body_text = $3, updated_at = $4 \
             WHERE \"user\" = $5 AND id = $6",
        )
        .bind(&template.name)
        .bind(&template.body_html)
        .bind(&template.body_text)
        .bind(template.updated_at)
        .bind(&template.user)
        .bind(&template.id)
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        Ok(())
    }

    async fn delete_template(&self, mailbox: &str, id: &str) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM templates WHERE \"user\" = $1 AND id = $2")
            .bind(mailbox)
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(backend)?;
        Ok(())
    }

    async fn enqueue_outbound(&self, item: &OutboundItem) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO outbound_queue \
                 (id, mailbox, batch_id, raw, env_from, rcpts, to_domain, attempts, next_at, send_at, sent_copy_filed, status) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
        )
        .bind(&item.id)
        .bind(&item.mailbox)
        .bind(&item.batch_id)
        .bind(&item.raw)
        .bind(&item.env_from)
        .bind(item.rcpts.join(","))
        .bind(&item.to_domain)
        .bind(item.attempts)
        .bind(item.next_at)
        .bind(item.send_at)
        .bind(item.sent_copy_filed)
        .bind(&item.status)
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        Ok(())
    }

    async fn due_outbound(&self, now: i64, limit: i64) -> Result<Vec<OutboundItem>, StoreError> {
        let rows = sqlx::query(
            "SELECT id, mailbox, batch_id, raw, env_from, rcpts, to_domain, attempts, next_at, send_at, sent_copy_filed, status \
             FROM outbound_queue \
             WHERE (status = 'queued' OR status = 'scheduled') \
               AND next_at <= $1 \
               AND (send_at <= 0 OR send_at <= $1) \
             ORDER BY next_at ASC, send_at ASC, id ASC LIMIT $2",
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

    async fn list_scheduled_outbound(
        &self,
        mailbox: &str,
        now: i64,
        before: Option<(i64, String)>,
        limit: i64,
    ) -> Result<Vec<ScheduledOutbound>, StoreError> {
        let (cursor_ts, cursor_batch) = before.unwrap_or((-1, String::new()));
        let rows = sqlx::query(
            "SELECT id, mailbox, batch_id, raw, env_from, rcpts, to_domain, attempts, next_at, send_at, sent_copy_filed, status \
             FROM outbound_queue \
             WHERE mailbox = $1 AND status = 'scheduled' AND send_at > $2 \
               AND (send_at > $3 OR (send_at = $3 AND batch_id > $4)) \
             ORDER BY send_at ASC, batch_id ASC, id ASC",
        )
        .bind(mailbox)
        .bind(now)
        .bind(cursor_ts)
        .bind(&cursor_batch)
        .fetch_all(&self.pool)
        .await
        .map_err(backend)?;
        let mut scheduled = rows
            .iter()
            .map(Self::outbound_from_row)
            .collect::<Result<Vec<_>, sqlx::Error>>()
            .map(aggregate_scheduled_rows)
            .map_err(backend)?;
        scheduled.truncate(limit.max(0) as usize);
        Ok(scheduled)
    }

    async fn get_scheduled_outbound(
        &self,
        mailbox: &str,
        batch_id: &str,
        now: i64,
    ) -> Result<Option<ScheduledOutbound>, StoreError> {
        let rows = sqlx::query(
            "SELECT id, mailbox, batch_id, raw, env_from, rcpts, to_domain, attempts, next_at, send_at, sent_copy_filed, status \
             FROM outbound_queue \
             WHERE mailbox = $1 AND batch_id = $2 AND status = 'scheduled' AND send_at > $3 \
             ORDER BY id ASC",
        )
        .bind(mailbox)
        .bind(batch_id)
        .bind(now)
        .fetch_all(&self.pool)
        .await
        .map_err(backend)?;
        let rows = rows
            .iter()
            .map(Self::outbound_from_row)
            .collect::<Result<Vec<_>, sqlx::Error>>()
            .map_err(backend)?;
        Ok(scheduled_from_rows(&rows))
    }

    async fn reschedule_scheduled_outbound(
        &self,
        mailbox: &str,
        batch_id: &str,
        send_at: i64,
        now: i64,
    ) -> Result<bool, StoreError> {
        let res = sqlx::query(
            "UPDATE outbound_queue \
             SET send_at = $1, next_at = $2, attempts = 0, status = 'scheduled' \
             WHERE mailbox = $3 AND batch_id = $4 AND status = 'scheduled' AND send_at > $5",
        )
        .bind(send_at)
        .bind(now)
        .bind(mailbox)
        .bind(batch_id)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        Ok(res.rows_affected() > 0)
    }

    async fn cancel_scheduled_outbound(
        &self,
        mailbox: &str,
        batch_id: &str,
        now: i64,
    ) -> Result<bool, StoreError> {
        let res = sqlx::query(
            "DELETE FROM outbound_queue \
             WHERE mailbox = $1 AND batch_id = $2 AND status = 'scheduled' AND send_at > $3",
        )
        .bind(mailbox)
        .bind(batch_id)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        Ok(res.rows_affected() > 0)
    }

    async fn claim_scheduled_sent_copy(
        &self,
        mailbox: &str,
        batch_id: &str,
    ) -> Result<bool, StoreError> {
        let res = sqlx::query(
            "UPDATE outbound_queue SET sent_copy_filed = TRUE \
             WHERE mailbox = $1 AND batch_id = $2 \
               AND NOT EXISTS (\
                   SELECT 1 FROM outbound_queue \
                   WHERE mailbox = $1 AND batch_id = $2 AND sent_copy_filed = TRUE\
               )",
        )
        .bind(mailbox)
        .bind(batch_id)
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        Ok(res.rows_affected() > 0)
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
            "SELECT COALESCE(NULLIF(thread_id, ''), message_id) AS tid FROM messages \
             WHERE mailbox = $1 AND COALESCE(NULLIF(thread_id, ''), message_id) <> '' \
               AND ((message_id IN ({ph})) OR (thread_id IN ({ph}))) \
             ORDER BY received_at ASC, id ASC LIMIT 1"
        );
        let mut q = sqlx::query(&sql).bind(mailbox);
        for r in refs {
            q = q.bind(r);
        }
        let row = q.fetch_optional(&self.pool).await.map_err(backend)?;
        Ok(row
            .map(|r| r.try_get::<String, _>("tid"))
            .transpose()
            .map_err(backend)?)
    }

    async fn list_folder_threads(
        &self,
        mailbox: &str,
        folder: &str,
        before: Option<(i64, String)>,
        limit: i64,
    ) -> Result<Vec<ThreadSummary>, StoreError> {
        let (cur_ts, cur_id) = Self::cursor(before);
        let now = crate::util::now_secs();
        // The grouping key: the thread_id, or a per-message singleton (`m:<id>`) for pre-threading
        // rows. NOT EXISTS keeps only the newest message per group (the representative snippet),
        // keyset-paginated on that representative's (received_at, id). Correlated COUNTs give the
        // thread size + unread tally. All standard SQL (|| concat, NULLIF/COALESCE, subqueries).
        let rows = sqlx::query(
            "SELECT m.id, m.msg_from, m.subject, m.received_at, m.seen, m.starred, m.snooze_until, m.muted, m.folder, \
                    COALESCE(NULLIF(m.thread_id, ''), 'm:' || m.id) AS gk, \
                    (SELECT COUNT(*) FROM messages c WHERE c.mailbox = m.mailbox AND c.folder = m.folder \
                       AND (m.folder <> 'INBOX' OR COALESCE(c.snooze_until, 0) <= $3) \
                       AND COALESCE(NULLIF(c.thread_id, ''), 'm:' || c.id) = COALESCE(NULLIF(m.thread_id, ''), 'm:' || m.id)) AS cnt, \
                    (SELECT COUNT(*) FROM messages u WHERE u.mailbox = m.mailbox AND u.folder = m.folder AND u.seen = FALSE \
                       AND (m.folder <> 'INBOX' OR COALESCE(u.snooze_until, 0) <= $3) \
                       AND COALESCE(NULLIF(u.thread_id, ''), 'm:' || u.id) = COALESCE(NULLIF(m.thread_id, ''), 'm:' || m.id)) AS unseen_cnt \
             FROM messages m \
             WHERE m.mailbox = $1 AND m.folder = $2 \
               AND ($2 <> 'INBOX' OR COALESCE(m.snooze_until, 0) <= $3) \
               AND NOT EXISTS ( \
                 SELECT 1 FROM messages n WHERE n.mailbox = m.mailbox AND n.folder = m.folder \
                   AND ($2 <> 'INBOX' OR COALESCE(n.snooze_until, 0) <= $3) \
                   AND COALESCE(NULLIF(n.thread_id, ''), 'm:' || n.id) = COALESCE(NULLIF(m.thread_id, ''), 'm:' || m.id) \
                   AND (n.received_at > m.received_at OR (n.received_at = m.received_at AND n.id > m.id)) \
               ) \
               AND (m.received_at < $4 OR (m.received_at = $4 AND m.id < $5)) \
             ORDER BY m.received_at DESC, m.id DESC LIMIT $6",
        )
        .bind(mailbox)
        .bind(folder)
        .bind(now)
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
                    received_at, seen, folder, starred, snooze_until, muted, thread_id, message_id \
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
        row.as_ref()
            .map(Self::identity_from_row)
            .transpose()
            .map_err(backend)
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
            "INSERT INTO contacts (mailbox, addr, name, phone, company, title, notes, manual, seen_count) \
             VALUES ($1, $2, $3, '', '', '', '', $4, $5) \
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
            "SELECT addr, name, phone, company, title, notes, manual, seen_count FROM contacts \
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
        let addr_l = addr.trim().to_lowercase();
        sqlx::query(
            "DELETE FROM contact_group_members \
             WHERE contact_id = $1 \
               AND group_id IN (SELECT id FROM contact_groups WHERE \"user\" = $2)",
        )
        .bind(&addr_l)
        .bind(mailbox)
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        sqlx::query("DELETE FROM contacts WHERE mailbox = $1 AND addr = $2")
            .bind(mailbox)
            .bind(&addr_l)
            .execute(&self.pool)
            .await
            .map_err(backend)?;
        Ok(())
    }

    async fn list_contacts(&self, mailbox: &str, limit: i64) -> Result<Vec<Contact>, StoreError> {
        let rows = sqlx::query(
            "SELECT addr, name, phone, company, title, notes, manual, seen_count FROM contacts \
             WHERE mailbox = $1 \
             ORDER BY LOWER(CASE WHEN name <> '' THEN name ELSE addr END) ASC, addr ASC LIMIT $2",
        )
        .bind(mailbox)
        .bind(limit.max(0))
        .fetch_all(&self.pool)
        .await
        .map_err(backend)?;
        rows.iter()
            .map(Self::contact_from_row)
            .collect::<Result<Vec<_>, sqlx::Error>>()
            .map_err(backend)
    }

    async fn save_contact(&self, mailbox: &str, contact: &Contact) -> Result<(), StoreError> {
        let addr_l = contact.addr.trim().to_lowercase();
        if addr_l.is_empty() {
            return Ok(());
        }
        sqlx::query(
            "INSERT INTO contacts \
                 (mailbox, addr, name, phone, company, title, notes, manual, seen_count) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, TRUE, $8) \
             ON CONFLICT (mailbox, addr) DO UPDATE SET \
               name = EXCLUDED.name, \
               phone = EXCLUDED.phone, \
               company = EXCLUDED.company, \
               title = EXCLUDED.title, \
               notes = EXCLUDED.notes, \
               manual = TRUE, \
               seen_count = CASE \
                 WHEN contacts.seen_count > EXCLUDED.seen_count THEN contacts.seen_count \
                 ELSE EXCLUDED.seen_count \
               END",
        )
        .bind(mailbox)
        .bind(&addr_l)
        .bind(contact.name.trim())
        .bind(contact.phone.trim())
        .bind(contact.company.trim())
        .bind(contact.title.trim())
        .bind(contact.notes.trim())
        .bind(contact.seen_count)
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        Ok(())
    }

    async fn duplicate_contacts(&self, mailbox: &str) -> Result<Vec<Contact>, StoreError> {
        let rows = sqlx::query(
            "SELECT addr, name, phone, company, title, notes, manual, seen_count FROM contacts \
             WHERE mailbox = $1 \
               AND LOWER(addr) IN (\
                 SELECT LOWER(addr) FROM contacts WHERE mailbox = $1 GROUP BY LOWER(addr) HAVING COUNT(*) > 1\
               ) \
             ORDER BY LOWER(addr), addr",
        )
        .bind(mailbox)
        .fetch_all(&self.pool)
        .await
        .map_err(backend)?;
        rows.iter()
            .map(Self::contact_from_row)
            .collect::<Result<Vec<_>, sqlx::Error>>()
            .map_err(backend)
    }

    async fn merge_duplicate_contact(&self, mailbox: &str, addr: &str) -> Result<(), StoreError> {
        let target = addr.trim().to_lowercase();
        if target.is_empty() {
            return Ok(());
        }
        let rows = sqlx::query(
            "SELECT addr, name, phone, company, title, notes, manual, seen_count FROM contacts \
             WHERE mailbox = $1 AND LOWER(addr) = $2 ORDER BY manual DESC, seen_count DESC, addr ASC",
        )
        .bind(mailbox)
        .bind(&target)
        .fetch_all(&self.pool)
        .await
        .map_err(backend)?;
        let mut merged: Option<Contact> = None;
        for row in &rows {
            let contact = Self::contact_from_row(row).map_err(backend)?;
            match &mut merged {
                Some(m) => merge_contact_fields(m, &contact),
                None => {
                    let mut c = contact;
                    c.addr = target.clone();
                    merged = Some(c);
                }
            }
        }
        let Some(contact) = merged else {
            return Ok(());
        };
        sqlx::query("DELETE FROM contacts WHERE mailbox = $1 AND LOWER(addr) = $2")
            .bind(mailbox)
            .bind(&target)
            .execute(&self.pool)
            .await
            .map_err(backend)?;
        sqlx::query(
            "INSERT INTO contacts \
                 (mailbox, addr, name, phone, company, title, notes, manual, seen_count) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind(mailbox)
        .bind(&contact.addr)
        .bind(&contact.name)
        .bind(&contact.phone)
        .bind(&contact.company)
        .bind(&contact.title)
        .bind(&contact.notes)
        .bind(contact.manual)
        .bind(contact.seen_count)
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        sqlx::query(
            "INSERT INTO contact_group_members (group_id, contact_id) \
             SELECT group_id, $1 FROM contact_group_members \
             WHERE LOWER(contact_id) = $1 \
               AND group_id IN (SELECT id FROM contact_groups WHERE \"user\" = $2) \
             ON CONFLICT (group_id, contact_id) DO NOTHING",
        )
        .bind(&target)
        .bind(mailbox)
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        sqlx::query(
            "DELETE FROM contact_group_members \
             WHERE LOWER(contact_id) = $1 AND contact_id <> $1 \
               AND group_id IN (SELECT id FROM contact_groups WHERE \"user\" = $2)",
        )
        .bind(&target)
        .bind(mailbox)
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        Ok(())
    }

    async fn list_contact_groups(&self, mailbox: &str) -> Result<Vec<ContactGroup>, StoreError> {
        let rows = sqlx::query(
            "SELECT id, \"user\", name, created_at FROM contact_groups \
             WHERE \"user\" = $1 ORDER BY LOWER(name) ASC, id ASC",
        )
        .bind(mailbox)
        .fetch_all(&self.pool)
        .await
        .map_err(backend)?;
        rows.iter()
            .map(Self::contact_group_from_row)
            .collect::<Result<Vec<_>, sqlx::Error>>()
            .map_err(backend)
    }

    async fn save_contact_group(&self, group: &ContactGroup) -> Result<(), StoreError> {
        let name = group.name.trim();
        if name.is_empty() {
            return Ok(());
        }
        let updated =
            sqlx::query("UPDATE contact_groups SET name = $3 WHERE id = $1 AND \"user\" = $2")
                .bind(&group.id)
                .bind(&group.user)
                .bind(name)
                .execute(&self.pool)
                .await
                .map_err(backend)?;
        if updated.rows_affected() == 0 {
            sqlx::query(
                "INSERT INTO contact_groups (id, \"user\", name, created_at) \
                 VALUES ($1, $2, $3, $4) \
                 ON CONFLICT (\"user\", name) DO NOTHING",
            )
            .bind(&group.id)
            .bind(&group.user)
            .bind(name)
            .bind(group.created_at)
            .execute(&self.pool)
            .await
            .map_err(backend)?;
        }
        Ok(())
    }

    async fn delete_contact_group(&self, mailbox: &str, group_id: &str) -> Result<(), StoreError> {
        sqlx::query(
            "DELETE FROM contact_group_members \
             WHERE group_id IN (SELECT id FROM contact_groups WHERE \"user\" = $1 AND id = $2)",
        )
        .bind(mailbox)
        .bind(group_id)
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        sqlx::query("DELETE FROM contact_groups WHERE \"user\" = $1 AND id = $2")
            .bind(mailbox)
            .bind(group_id)
            .execute(&self.pool)
            .await
            .map_err(backend)?;
        Ok(())
    }

    async fn add_contact_group_member(
        &self,
        mailbox: &str,
        group_id: &str,
        contact_addr: &str,
    ) -> Result<(), StoreError> {
        let addr_l = contact_addr.trim().to_lowercase();
        if addr_l.is_empty() {
            return Ok(());
        }
        sqlx::query(
            "INSERT INTO contact_group_members (group_id, contact_id) \
             SELECT $1, $2 \
             WHERE EXISTS (SELECT 1 FROM contact_groups WHERE \"user\" = $3 AND id = $1) \
               AND EXISTS (SELECT 1 FROM contacts WHERE mailbox = $3 AND addr = $2) \
             ON CONFLICT (group_id, contact_id) DO NOTHING",
        )
        .bind(group_id)
        .bind(&addr_l)
        .bind(mailbox)
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        Ok(())
    }

    async fn delete_contact_group_member(
        &self,
        mailbox: &str,
        group_id: &str,
        contact_addr: &str,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "DELETE FROM contact_group_members \
             WHERE group_id = $1 AND contact_id = $2 \
               AND group_id IN (SELECT id FROM contact_groups WHERE \"user\" = $3)",
        )
        .bind(group_id)
        .bind(contact_addr.trim().to_lowercase())
        .bind(mailbox)
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        Ok(())
    }

    async fn list_contact_group_members(
        &self,
        mailbox: &str,
        group_id: &str,
    ) -> Result<Vec<Contact>, StoreError> {
        let rows = sqlx::query(
            "SELECT c.addr, c.name, c.phone, c.company, c.title, c.notes, c.manual, c.seen_count \
             FROM contacts c \
             JOIN contact_group_members m ON m.contact_id = c.addr \
             JOIN contact_groups g ON g.id = m.group_id \
             WHERE c.mailbox = $1 AND g.\"user\" = $1 AND g.id = $2 \
             ORDER BY LOWER(CASE WHEN c.name <> '' THEN c.name ELSE c.addr END) ASC, c.addr ASC",
        )
        .bind(mailbox)
        .bind(group_id)
        .fetch_all(&self.pool)
        .await
        .map_err(backend)?;
        rows.iter()
            .map(Self::contact_from_row)
            .collect::<Result<Vec<_>, sqlx::Error>>()
            .map_err(backend)
    }

    async fn contacts_for_group_name(
        &self,
        mailbox: &str,
        group_name: &str,
    ) -> Result<Vec<Contact>, StoreError> {
        let rows = sqlx::query(
            "SELECT c.addr, c.name, c.phone, c.company, c.title, c.notes, c.manual, c.seen_count \
             FROM contacts c \
             JOIN contact_group_members m ON m.contact_id = c.addr \
             JOIN contact_groups g ON g.id = m.group_id \
             WHERE c.mailbox = $1 AND g.\"user\" = $1 AND LOWER(g.name) = LOWER($2) \
             ORDER BY LOWER(CASE WHEN c.name <> '' THEN c.name ELSE c.addr END) ASC, c.addr ASC",
        )
        .bind(mailbox)
        .bind(group_name.trim())
        .fetch_all(&self.pool)
        .await
        .map_err(backend)?;
        rows.iter()
            .map(Self::contact_from_row)
            .collect::<Result<Vec<_>, sqlx::Error>>()
            .map_err(backend)
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
            "SELECT m.id, m.msg_from, m.subject, m.received_at, m.seen, m.starred, m.snooze_until, m.muted, m.folder \
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

    async fn list_sender_lists(&self, mailbox: &str) -> Result<Vec<SenderListEntry>, StoreError> {
        let rows = sqlx::query(
            "SELECT id, \"user\", address_or_domain, kind, created_at FROM sender_lists \
             WHERE \"user\" = $1 ORDER BY kind ASC, address_or_domain ASC, id ASC",
        )
        .bind(mailbox)
        .fetch_all(&self.pool)
        .await
        .map_err(backend)?;
        rows.iter()
            .map(Self::sender_list_from_row)
            .collect::<Result<Vec<_>, sqlx::Error>>()
            .map_err(backend)
    }

    async fn upsert_sender_list(&self, entry: &SenderListEntry) -> Result<(), StoreError> {
        sqlx::query(
            "DELETE FROM sender_lists \
             WHERE \"user\" = $1 AND address_or_domain = $2 AND kind <> $3",
        )
        .bind(&entry.user)
        .bind(&entry.address_or_domain)
        .bind(&entry.kind)
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        sqlx::query(
            "INSERT INTO sender_lists (id, \"user\", address_or_domain, kind, created_at) \
             VALUES ($1, $2, $3, $4, $5) \
             ON CONFLICT (\"user\", address_or_domain, kind) \
             DO UPDATE SET created_at = EXCLUDED.created_at",
        )
        .bind(&entry.id)
        .bind(&entry.user)
        .bind(&entry.address_or_domain)
        .bind(&entry.kind)
        .bind(entry.created_at)
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        Ok(())
    }

    async fn delete_sender_list(&self, mailbox: &str, id: &str) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM sender_lists WHERE \"user\" = $1 AND id = $2")
            .bind(mailbox)
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(backend)?;
        Ok(())
    }

    async fn set_spam_annotation(&self, annotation: &SpamAnnotation) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO spam_annotations (message_id, mailbox, score, reason) \
             VALUES ($1, $2, $3, $4) \
             ON CONFLICT (message_id) DO UPDATE SET \
               mailbox = EXCLUDED.mailbox, score = EXCLUDED.score, reason = EXCLUDED.reason",
        )
        .bind(&annotation.message_id)
        .bind(&annotation.mailbox)
        .bind(annotation.score)
        .bind(&annotation.reason)
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        Ok(())
    }

    async fn spam_annotation(
        &self,
        mailbox: &str,
        message_id: &str,
    ) -> Result<Option<SpamAnnotation>, StoreError> {
        let row = sqlx::query(
            "SELECT message_id, mailbox, score, reason FROM spam_annotations \
             WHERE mailbox = $1 AND message_id = $2",
        )
        .bind(mailbox)
        .bind(message_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(backend)?;
        row.as_ref()
            .map(Self::spam_annotation_from_row)
            .transpose()
            .map_err(backend)
    }

    async fn delete_spam_annotation(
        &self,
        mailbox: &str,
        message_id: &str,
    ) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM spam_annotations WHERE mailbox = $1 AND message_id = $2")
            .bind(mailbox)
            .bind(message_id)
            .execute(&self.pool)
            .await
            .map_err(backend)?;
        Ok(())
    }
}

/// Map a summary row into a
/// [`MessageSummary`].
fn summary_from_row(r: &sqlx::postgres::PgRow) -> Result<MessageSummary, sqlx::Error> {
    Ok(MessageSummary {
        id: r.try_get("id")?,
        msg_from: r.try_get("msg_from")?,
        subject: r.try_get("subject")?,
        received_at: r.try_get("received_at")?,
        seen: r.try_get("seen")?,
        starred: r.try_get::<Option<bool>, _>("starred")?.unwrap_or(false),
        snooze_until: r.try_get::<Option<i64>, _>("snooze_until")?.unwrap_or(0),
        muted: r.try_get::<Option<bool>, _>("muted")?.unwrap_or(false),
        folder: r.try_get("folder")?,
    })
}

enum SearchSqlBind {
    Text(String),
    Int(i64),
}

fn push_text_param(
    binds: &mut Vec<SearchSqlBind>,
    next_param: &mut usize,
    value: String,
) -> String {
    let param = format!("${}", *next_param);
    *next_param += 1;
    binds.push(SearchSqlBind::Text(value));
    param
}

fn push_int_param(binds: &mut Vec<SearchSqlBind>, next_param: &mut usize, value: i64) -> String {
    let param = format!("${}", *next_param);
    *next_param += 1;
    binds.push(SearchSqlBind::Int(value));
    param
}

fn search_like_pattern(value: &str) -> String {
    format!("%{}%", like_escape(&value.to_lowercase()))
}

fn search_text_condition(
    value: &str,
    binds: &mut Vec<SearchSqlBind>,
    next_param: &mut usize,
) -> String {
    let param = push_text_param(binds, next_param, search_like_pattern(value));
    format!(
        "(LOWER(m.msg_from) LIKE {param} ESCAPE '\\' \
          OR LOWER(m.msg_to) LIKE {param} ESCAPE '\\' \
          OR LOWER(m.subject) LIKE {param} ESCAPE '\\' \
          OR LOWER(m.body_text) LIKE {param} ESCAPE '\\')"
    )
}

fn search_predicate_condition(
    predicate: &SearchPredicate,
    binds: &mut Vec<SearchSqlBind>,
    next_param: &mut usize,
) -> String {
    match &predicate.kind {
        SearchPredicateKind::From(value) => {
            let param = push_text_param(binds, next_param, search_like_pattern(value));
            format!("LOWER(m.msg_from) LIKE {param} ESCAPE '\\'")
        }
        SearchPredicateKind::To(value) => {
            let param = push_text_param(binds, next_param, search_like_pattern(value));
            format!("LOWER(m.msg_to) LIKE {param} ESCAPE '\\'")
        }
        SearchPredicateKind::Cc(value) => {
            let pattern = format!("%cc:%{}%", like_escape(&value.to_lowercase()));
            let param = push_text_param(binds, next_param, pattern);
            format!("LOWER(m.raw_rfc822) LIKE {param} ESCAPE '\\'")
        }
        SearchPredicateKind::Subject(value) => {
            let param = push_text_param(binds, next_param, search_like_pattern(value));
            format!("LOWER(m.subject) LIKE {param} ESCAPE '\\'")
        }
        SearchPredicateKind::Label(value) => {
            let param = push_text_param(binds, next_param, value.to_lowercase());
            format!(
                "EXISTS (SELECT 1 FROM message_labels ml \
                 JOIN labels l ON l.id = ml.label_id AND l.mailbox = ml.mailbox \
                 WHERE ml.mailbox = m.mailbox AND ml.message_id = m.id AND LOWER(l.name) = {param})"
            )
        }
        SearchPredicateKind::Is(SearchState::Read) => "m.seen = TRUE".to_string(),
        SearchPredicateKind::Is(SearchState::Unread) => "m.seen = FALSE".to_string(),
        SearchPredicateKind::Is(SearchState::Starred) => "m.starred = TRUE".to_string(),
        SearchPredicateKind::HasAttachment => {
            "(LOWER(m.raw_rfc822) LIKE '%content-disposition:%attachment%' \
              OR LOWER(m.raw_rfc822) LIKE '%filename=%' \
              OR LOWER(m.raw_rfc822) LIKE '%name=%')"
                .to_string()
        }
        SearchPredicateKind::InFolder(value) => {
            let param = push_text_param(binds, next_param, value.to_lowercase());
            format!("LOWER(m.folder) = {param}")
        }
        SearchPredicateKind::Before(ts) => {
            let param = push_int_param(binds, next_param, *ts);
            format!("m.received_at < {param}")
        }
        SearchPredicateKind::After(ts) => {
            let param = push_int_param(binds, next_param, *ts);
            format!("m.received_at >= {param}")
        }
        SearchPredicateKind::Larger(bytes) => {
            let param = push_int_param(binds, next_param, *bytes);
            format!("OCTET_LENGTH(m.raw_rfc822) > {param}")
        }
        SearchPredicateKind::Smaller(bytes) => {
            let param = push_int_param(binds, next_param, *bytes);
            format!("OCTET_LENGTH(m.raw_rfc822) < {param}")
        }
    }
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
            snooze_until: 0,
            muted: false,
            thread_id: String::new(),
            message_id: String::new(),
        }
    }

    #[test]
    fn apply_before_keeps_strictly_older_rows() {
        // Ordering is (received_at, id) descending; the cursor row itself is excluded.
        let all = vec![
            msg("m_c", 200),
            msg("m_b", 100),
            msg("m_a", 100),
            msg("m_z", 50),
        ];

        let mut v = all.clone();
        apply_before(&mut v, None);
        assert_eq!(v.len(), 4, "no cursor keeps everything");

        let mut v = all.clone();
        apply_before(&mut v, Some((100, "m_b".to_string())));
        let ids: Vec<&str> = v.iter().map(|m| m.id.as_str()).collect();
        assert_eq!(
            ids,
            ["m_a", "m_z"],
            "same-ts rows tie-break on id, older ts always kept"
        );
    }

    #[tokio::test]
    async fn snooze_hides_from_inbox_and_restores_when_due() {
        let store = InMemoryStore::new();
        let now = crate::util::now_secs();
        let m = msg("m_snooze", now);
        store.store_message(&m).await.unwrap();

        store.snooze_message(&m.id, now + 60).await.unwrap();
        assert!(store
            .list_folder("w33d@w33d.xyz", "INBOX", None, 10)
            .await
            .unwrap()
            .is_empty());
        let snoozed = store
            .list_snoozed("w33d@w33d.xyz", now, None, 10)
            .await
            .unwrap();
        assert_eq!(snoozed.len(), 1);
        assert_eq!(snoozed[0].snooze_until, now + 60);

        assert_eq!(store.restore_due_snoozes(now, 10).await.unwrap(), 0);
        assert_eq!(store.restore_due_snoozes(now + 60, 10).await.unwrap(), 1);
        let restored = store.get_message(&m.id).await.unwrap().unwrap();
        assert_eq!(restored.snooze_until, 0);
        assert_eq!(restored.folder, "INBOX");
        assert_eq!(
            store
                .list_folder("w33d@w33d.xyz", "INBOX", None, 10)
                .await
                .unwrap()
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn thread_muted_marks_matching_messages() {
        let store = InMemoryStore::new();
        let mut root = msg("m_root", 1);
        root.thread_id = "thr:1".to_string();
        root.message_id = "<root@example>".to_string();
        let mut reply = msg("m_reply", 2);
        reply.thread_id = "thr:1".to_string();
        reply.message_id = "<reply@example>".to_string();
        store.store_message(&root).await.unwrap();
        store.store_message(&reply).await.unwrap();

        store.set_thread_muted(&root, true).await.unwrap();
        assert!(store
            .is_thread_muted("w33d@w33d.xyz", "thr:1")
            .await
            .unwrap());
        assert!(store.get_message("m_root").await.unwrap().unwrap().muted);
        assert!(store.get_message("m_reply").await.unwrap().unwrap().muted);

        store.set_thread_muted(&root, false).await.unwrap();
        assert!(!store
            .is_thread_muted("w33d@w33d.xyz", "thr:1")
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn sender_lists_replace_opposite_kind_and_annotations_roundtrip() {
        let store = InMemoryStore::new();
        let blocked = SenderListEntry {
            id: "sl_block".to_string(),
            user: "w33d@w33d.xyz".to_string(),
            address_or_domain: "bad.example".to_string(),
            kind: "blocked".to_string(),
            created_at: 1,
        };
        store.upsert_sender_list(&blocked).await.unwrap();
        assert_eq!(
            store.list_sender_lists("w33d@w33d.xyz").await.unwrap(),
            vec![blocked.clone()]
        );

        let safe = SenderListEntry {
            id: "sl_safe".to_string(),
            user: "w33d@w33d.xyz".to_string(),
            address_or_domain: "bad.example".to_string(),
            kind: "safe".to_string(),
            created_at: 2,
        };
        store.upsert_sender_list(&safe).await.unwrap();
        let entries = store.list_sender_lists("w33d@w33d.xyz").await.unwrap();
        assert_eq!(entries, vec![safe.clone()], "opposite kind is replaced");

        let annotation = SpamAnnotation {
            mailbox: "w33d@w33d.xyz".to_string(),
            message_id: "m_1".to_string(),
            score: 6,
            reason: "SPF fail; DKIM fail".to_string(),
        };
        store.set_spam_annotation(&annotation).await.unwrap();
        assert_eq!(
            store.spam_annotation("w33d@w33d.xyz", "m_1").await.unwrap(),
            Some(annotation)
        );
        store
            .delete_spam_annotation("w33d@w33d.xyz", "m_1")
            .await
            .unwrap();
        assert!(store
            .spam_annotation("w33d@w33d.xyz", "m_1")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn templates_are_scoped_and_crud_roundtrips() {
        let store = InMemoryStore::new();
        let mut welcome = Template {
            id: "tpl_welcome".to_string(),
            user: "w33d@w33d.xyz".to_string(),
            name: "Welcome".to_string(),
            body_html: "<p>Hello <strong>there</strong></p>".to_string(),
            body_text: "Hello there".to_string(),
            created_at: 1,
            updated_at: 1,
        };
        let other = Template {
            id: "tpl_other".to_string(),
            user: "alice@w33d.xyz".to_string(),
            name: "Alice private".to_string(),
            body_html: String::new(),
            body_text: "Private".to_string(),
            created_at: 2,
            updated_at: 2,
        };

        store.create_template(&welcome).await.unwrap();
        store.create_template(&other).await.unwrap();

        assert_eq!(
            store.list_templates("w33d@w33d.xyz").await.unwrap(),
            vec![welcome.clone()]
        );
        assert_eq!(
            store
                .get_template("alice@w33d.xyz", "tpl_welcome")
                .await
                .unwrap(),
            None,
            "templates are private to the owning mailbox"
        );

        welcome.name = "Welcome v2".to_string();
        welcome.body_text = "Updated".to_string();
        welcome.updated_at = 3;
        store.update_template(&welcome).await.unwrap();
        assert_eq!(
            store
                .get_template("w33d@w33d.xyz", "tpl_welcome")
                .await
                .unwrap()
                .unwrap()
                .body_text,
            "Updated"
        );

        store
            .delete_template("w33d@w33d.xyz", "tpl_welcome")
            .await
            .unwrap();
        assert!(store
            .list_templates("w33d@w33d.xyz")
            .await
            .unwrap()
            .is_empty());
        assert_eq!(
            store.list_templates("alice@w33d.xyz").await.unwrap().len(),
            1
        );
    }
}
