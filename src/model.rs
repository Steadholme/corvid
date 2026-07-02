//! Domain types persisted by the [`crate::store::Store`].

use serde::Serialize;

/// A mailbox: an address that receives mail, owned by a HOLDFAST identity (`owner_sub`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Mailbox {
    /// Canonical address, primary key (e.g. `w33d@w33d.xyz`).
    pub addr: String,
    /// HOLDFAST `sub` of the owner (matches the gateway-injected `X-Auth-Subject`).
    pub owner_sub: String,
}

/// A mail alias: an address local-part that forwards to a target [`Mailbox::addr`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Alias {
    /// The alias local-part (e.g. `info`), primary key.
    pub local_part: String,
    /// The mailbox address this alias delivers into.
    pub mailbox: String,
}

/// A server-side filter rule, applied to inbound mail at DELIVERY time (first match wins).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FilterRule {
    /// Opaque id, primary key.
    pub id: String,
    /// The mailbox whose inbound mail this rule filters.
    pub mailbox: String,
    /// Evaluation order within the mailbox (ascending; first match wins).
    pub position: i64,
    /// Matched message field (`from` | `to` | `subject`).
    pub field: String,
    /// Match operator (`contains` | `equals`), case-insensitive.
    pub op: String,
    /// The text the field is matched against.
    pub needle: String,
    /// What a match does (`move` | `star` | `markread` | `discard` | `label`).
    pub action: String,
    /// Target folder for `action = move` (`None` otherwise).
    pub target_folder: Option<String>,
    /// Target label id for `action = label` (`None` otherwise).
    pub target_label: Option<String>,
    /// Disabled rules are kept but never evaluated at delivery.
    pub enabled: bool,
    /// Creation time (epoch seconds).
    pub created_at: i64,
}

/// Per-mailbox settings: the compose signature + the auto-reply (vacation) responder. Stored on
/// the `mailboxes` row; every field defaults to "off"/empty for a mailbox that never saved any.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct MailboxSettings {
    /// The mailbox these settings belong to ([`Mailbox::addr`]).
    pub mailbox: String,
    /// Compose signature, appended to drafts as `\n\n--\n<signature>` (empty = none).
    pub signature: String,
    /// Whether the auto-reply (vacation) responder is on.
    pub auto_reply_enabled: bool,
    /// Auto-reply subject (empty falls back to `Auto: <original subject>`).
    pub auto_reply_subject: String,
    /// Auto-reply body text.
    pub auto_reply_body: String,
    /// Auto-reply expiry (epoch seconds; `0` = no expiry).
    pub auto_reply_until: i64,
}

impl MailboxSettings {
    /// The all-defaults settings for a mailbox that never saved any.
    pub fn default_for(mailbox: &str) -> Self {
        MailboxSettings {
            mailbox: mailbox.to_string(),
            signature: String::new(),
            auto_reply_enabled: false,
            auto_reply_subject: String::new(),
            auto_reply_body: String::new(),
            auto_reply_until: 0,
        }
    }
}

/// A stored message (one row per delivered/received message).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Message {
    /// Opaque id, primary key.
    pub id: String,
    /// The mailbox this message belongs to (FK-ish to [`Mailbox::addr`]).
    pub mailbox: String,
    /// Parsed `From:` header (display).
    pub msg_from: String,
    /// Parsed `To:` header (display).
    pub msg_to: String,
    /// Parsed `Subject:` header.
    pub subject: String,
    /// The full RFC822 source as received.
    pub raw_rfc822: String,
    /// Parsed plain-text body (best effort).
    pub body_text: String,
    /// Parsed + sanitised HTML body (best effort; empty when none).
    pub body_html: String,
    /// Receipt time (epoch seconds).
    pub received_at: i64,
    /// Read flag.
    pub seen: bool,
    /// Folder (`INBOX` | `Sent` | `Drafts` | `Archive` | `Trash`).
    pub folder: String,
    /// Star/flag: surfaced in the cross-folder `Starred` view.
    pub starred: bool,
    /// The conversation this message belongs to (computed at delivery/send time from the
    /// `References`/`In-Reply-To` chain, falling back to the normalised `Subject`). Empty on
    /// pre-threading rows — read back as an ungrouped singleton.
    pub thread_id: String,
    /// The message's own `Message-ID` header (verbatim, trimmed) — the key inbound replies
    /// reference back to. Empty when the source carried none.
    pub message_id: String,
}

/// A summary row for the inbox list (no body, lighter to fetch/render).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct MessageSummary {
    pub id: String,
    pub msg_from: String,
    pub subject: String,
    pub received_at: i64,
    pub seen: bool,
    pub starred: bool,
}

/// A collapsed conversation row for the threaded folder view: the newest message in the thread
/// (the `latest` summary shown as the snippet) plus the thread's message `count` and how many are
/// still `unseen`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ThreadSummary {
    /// The conversation id (grouping key; also the `?id=` for the conversation view).
    pub thread_id: String,
    /// The newest message in the thread — its from/subject/date drive the collapsed row.
    pub latest: MessageSummary,
    /// Total messages in the thread (within this folder).
    pub count: i64,
    /// How many of those are unread.
    pub unseen: i64,
}

/// An additional outbound "From" identity a mailbox owns (an alias it may send as). The mailbox's
/// own address is always an implicit identity; these are the extra ones the user configures.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SendIdentity {
    /// Opaque id, primary key.
    pub id: String,
    /// The mailbox that owns (and may send as) this identity.
    pub mailbox: String,
    /// The From address (must be at the mail domain so the message stays DKIM-signable).
    pub from_addr: String,
    /// Optional display name (`Display Name <from_addr>`); empty sends the bare address.
    pub display_name: String,
    /// Whether this is the mailbox's preferred default identity.
    pub is_default: bool,
}

/// A correspondent in a mailbox's contact list: either harvested from message From/To
/// correspondents (`manual = false`, `seen_count` tracks frequency) or added by hand
/// (`manual = true`). Backs the To/Cc autocomplete.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Contact {
    /// The email address (lowercased) — unique per mailbox.
    pub addr: String,
    /// Display name (best-effort; empty when only ever seen as a bare address).
    pub name: String,
    /// Manually-added contacts sort ahead of harvested ones.
    pub manual: bool,
    /// How many times this address was seen as a correspondent (harvest frequency).
    pub seen_count: i64,
}

/// An arbitrary, user-defined label a mailbox can apply to messages (orthogonal to folders).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Label {
    /// Opaque id, primary key.
    pub id: String,
    /// The owning mailbox.
    pub mailbox: String,
    /// Display name.
    pub name: String,
    /// Optional colour token (a CSS-safe class suffix); empty = the default pill.
    pub color: String,
}

/// A queued outbound message awaiting relay to a destination domain.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct OutboundItem {
    pub id: String,
    /// The full (already DKIM-signed) RFC822 source to transmit verbatim.
    pub raw: String,
    /// Envelope sender (`MAIL FROM`).
    pub env_from: String,
    /// Envelope recipients (`RCPT TO`) for this destination domain.
    pub rcpts: Vec<String>,
    /// Destination domain whose MX we resolve + deliver to.
    pub to_domain: String,
    /// Delivery attempt count.
    pub attempts: i64,
    /// Earliest next attempt time (epoch seconds).
    pub next_at: i64,
    /// `queued` | `sent` | `failed`.
    pub status: String,
}
