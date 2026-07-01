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
    /// Folder (only `INBOX` in v1).
    pub folder: String,
}

/// A summary row for the inbox list (no body, lighter to fetch/render).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct MessageSummary {
    pub id: String,
    pub msg_from: String,
    pub subject: String,
    pub received_at: i64,
    pub seen: bool,
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
