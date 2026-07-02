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
    /// What a match does (`move` | `star` | `markread` | `discard`).
    pub action: String,
    /// Target folder for `action = move` (`None` otherwise).
    pub target_folder: Option<String>,
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
