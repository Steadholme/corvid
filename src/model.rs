//! Domain types persisted by the [`crate::store::Store`].

use serde::Serialize;
use time::{Date, Month};

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

/// Default Gmail-style undo-send hold window for new/unsaved mailbox settings.
pub const DEFAULT_UNDO_SEND_WINDOW_SECS: i64 = 10;
/// Default mailbox list density (`comfortable` | `normal` | `compact`).
pub const DEFAULT_DENSITY: &str = "normal";
/// Default reading pane placement (`off` | `right` | `bottom`).
pub const DEFAULT_READING_PANE: &str = "off";
/// Default theme preference (`system` | `light` | `dark`).
pub const DEFAULT_THEME: &str = "system";

/// Per-mailbox settings: compose signature, undo-send, display preferences, and the auto-reply
/// (vacation) responder. Stored on the `mailboxes` row; every field defaults to "off"/empty except
/// undo-send/display preferences for a mailbox that never saved any.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct MailboxSettings {
    /// The mailbox these settings belong to ([`Mailbox::addr`]).
    pub mailbox: String,
    /// Compose signature, appended to drafts as `\n\n--\n<signature>` (empty = none).
    pub signature: String,
    /// Gmail-style undo-send hold window in seconds. `0` preserves immediate-send compatibility.
    pub undo_send_window_secs: i64,
    /// Message-list density preference.
    pub density: String,
    /// Reading pane preference (`off` keeps the legacy full-page reader).
    pub reading_pane: String,
    /// Theme preference; frontend CSS handles the visual tokens.
    pub theme: String,
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
            undo_send_window_secs: DEFAULT_UNDO_SEND_WINDOW_SECS,
            density: DEFAULT_DENSITY.to_string(),
            reading_pane: DEFAULT_READING_PANE.to_string(),
            theme: DEFAULT_THEME.to_string(),
            auto_reply_enabled: false,
            auto_reply_subject: String::new(),
            auto_reply_body: String::new(),
            auto_reply_until: 0,
        }
    }
}

/// A reusable compose signature. `identity` is the From address this default belongs to; empty
/// means the mailbox-wide fallback/default signature.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Signature {
    /// Opaque id, primary key.
    pub id: String,
    /// The mailbox/user this signature belongs to.
    pub user: String,
    /// From identity address this signature is scoped to; empty = general fallback.
    pub identity: String,
    /// User-facing name.
    pub name: String,
    /// Sanitised rich HTML body. Empty means use `body_text`.
    pub body_html: String,
    /// Plain-text fallback/body.
    pub body_text: String,
    /// Whether this is the default signature for its `identity`.
    pub is_default: bool,
    /// Creation time (epoch seconds).
    pub created_at: i64,
}

/// A per-mailbox sender allow/block entry used by delivery-time spam placement.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SenderListEntry {
    /// Opaque id, primary key.
    pub id: String,
    /// The mailbox/user this entry belongs to.
    pub user: String,
    /// Lowercase exact address (`alice@example.com`) or domain (`example.com`).
    pub address_or_domain: String,
    /// Entry kind (`blocked` | `safe`).
    pub kind: String,
    /// Creation time (epoch seconds).
    pub created_at: i64,
}

/// A per-mailbox compose template, private to its owning user/mailbox.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Template {
    /// Opaque id, primary key.
    pub id: String,
    /// The mailbox/user this template belongs to.
    pub user: String,
    /// User-facing template name.
    pub name: String,
    /// Sanitised rich HTML body. Empty means use `body_text`.
    pub body_html: String,
    /// Plain-text fallback/body.
    pub body_text: String,
    /// Creation time (epoch seconds).
    pub created_at: i64,
    /// Last update time (epoch seconds).
    pub updated_at: i64,
}

/// Stored explanation for why a message was considered spam-like at delivery/action time.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SpamAnnotation {
    pub mailbox: String,
    pub message_id: String,
    pub score: i64,
    pub reason: String,
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
    /// Folder (`INBOX` | `Sent` | `Drafts` | `Archive` | `Spam` | `Trash`).
    pub folder: String,
    /// Star/flag: surfaced in the cross-folder `Starred` view.
    pub starred: bool,
    /// Snooze expiry (epoch seconds). `0` means the message is not snoozed.
    pub snooze_until: i64,
    /// Muted conversations skip the Inbox for later inbound replies.
    pub muted: bool,
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
    pub snippet: String,
    pub has_attachment: bool,
    pub received_at: i64,
    pub seen: bool,
    pub starred: bool,
    pub snooze_until: i64,
    pub muted: bool,
    pub folder: String,
}

/// Parsed search input: free text terms plus structured predicates. Positive clauses are ANDed by
/// default; when `or_mode` is true, positive clauses are ORed. Negated clauses always exclude.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SearchQuery {
    pub text_terms: Vec<SearchTextTerm>,
    pub predicates: Vec<SearchPredicate>,
    pub or_mode: bool,
}

impl SearchQuery {
    pub fn positive_text_terms(&self) -> impl Iterator<Item = &str> {
        self.text_terms
            .iter()
            .filter(|term| !term.negated)
            .map(|term| term.value.as_str())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SearchTextTerm {
    pub value: String,
    pub negated: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SearchPredicate {
    pub kind: SearchPredicateKind,
    pub negated: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SearchPredicateKind {
    From(String),
    To(String),
    Cc(String),
    Subject(String),
    Label(String),
    Is(SearchState),
    HasAttachment,
    InFolder(String),
    Before(i64),
    After(i64),
    Larger(i64),
    Smaller(i64),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SearchState {
    Read,
    Unread,
    Starred,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SearchToken {
    text: String,
    quoted: bool,
}

/// Parse a Gmail-style search string. Invalid or unknown operators degrade to ordinary text terms,
/// so user input never becomes a request error.
pub fn parse_search_query(raw: &str) -> SearchQuery {
    let raw = raw.trim();
    if raw.is_empty() {
        return SearchQuery::default();
    }

    let tokens = tokenize_search(raw);
    let has_or = tokens
        .iter()
        .any(|token| !token.quoted && token.text.eq_ignore_ascii_case("OR"));
    let has_negation = tokens.iter().any(|token| {
        token
            .text
            .strip_prefix('-')
            .is_some_and(|rest| !rest.is_empty())
    });
    let has_operator = tokens.iter().any(|token| {
        let text = token.text.strip_prefix('-').unwrap_or(&token.text);
        text.split_once(':')
            .is_some_and(|(op, _)| is_search_operator(op))
    });
    let has_quotes = tokens.iter().any(|token| token.quoted);

    if !has_or && !has_negation && !has_operator && !has_quotes {
        return SearchQuery {
            text_terms: vec![SearchTextTerm {
                value: raw.to_string(),
                negated: false,
            }],
            predicates: Vec::new(),
            or_mode: false,
        };
    }

    let mut query = SearchQuery {
        text_terms: Vec::new(),
        predicates: Vec::new(),
        or_mode: has_or,
    };
    for token in tokens {
        if !token.quoted && token.text.eq_ignore_ascii_case("OR") {
            continue;
        }
        let text = token.text.trim();
        if text.is_empty() {
            continue;
        }
        let (negated, clause) = match text.strip_prefix('-') {
            Some(rest) if !rest.is_empty() => (true, rest.trim()),
            _ => (false, text),
        };
        if clause.is_empty() {
            continue;
        }
        if let Some(predicate) = parse_search_predicate(clause, negated) {
            query.predicates.push(predicate);
        } else {
            query.text_terms.push(SearchTextTerm {
                value: clause.to_string(),
                negated,
            });
        }
    }
    query
}

fn tokenize_search(raw: &str) -> Vec<SearchToken> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_quote = false;
    let mut quoted = false;

    for c in raw.chars() {
        match c {
            '"' => {
                in_quote = !in_quote;
                quoted = true;
            }
            c if c.is_whitespace() && !in_quote => {
                if !cur.is_empty() {
                    out.push(SearchToken {
                        text: std::mem::take(&mut cur),
                        quoted,
                    });
                    quoted = false;
                }
            }
            _ => cur.push(c),
        }
    }

    if !cur.is_empty() {
        out.push(SearchToken { text: cur, quoted });
    }
    out
}

fn parse_search_predicate(token: &str, negated: bool) -> Option<SearchPredicate> {
    let (op, value) = token.split_once(':')?;
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    let kind = match op.to_ascii_lowercase().as_str() {
        "from" => SearchPredicateKind::From(value.to_string()),
        "to" => SearchPredicateKind::To(value.to_string()),
        "cc" => SearchPredicateKind::Cc(value.to_string()),
        "subject" => SearchPredicateKind::Subject(value.to_string()),
        "label" => SearchPredicateKind::Label(value.to_string()),
        "is" => match value.to_ascii_lowercase().as_str() {
            "read" => SearchPredicateKind::Is(SearchState::Read),
            "unread" => SearchPredicateKind::Is(SearchState::Unread),
            "starred" => SearchPredicateKind::Is(SearchState::Starred),
            _ => return None,
        },
        "has" => match value.to_ascii_lowercase().as_str() {
            "attachment" => SearchPredicateKind::HasAttachment,
            _ => return None,
        },
        "in" => SearchPredicateKind::InFolder(value.to_string()),
        "before" => SearchPredicateKind::Before(parse_search_date(value)?),
        "after" => SearchPredicateKind::After(parse_search_date(value)?),
        "larger" => SearchPredicateKind::Larger(parse_search_size(value)?),
        "smaller" => SearchPredicateKind::Smaller(parse_search_size(value)?),
        _ => return None,
    };
    Some(SearchPredicate { kind, negated })
}

fn is_search_operator(op: &str) -> bool {
    matches!(
        op.to_ascii_lowercase().as_str(),
        "from"
            | "to"
            | "cc"
            | "subject"
            | "label"
            | "is"
            | "has"
            | "in"
            | "before"
            | "after"
            | "larger"
            | "smaller"
    )
}

fn parse_search_date(value: &str) -> Option<i64> {
    let mut parts = value.split('-');
    let year = parts.next()?.parse::<i32>().ok()?;
    let month = parts.next()?.parse::<u8>().ok()?;
    let day = parts.next()?.parse::<u8>().ok()?;
    if parts.next().is_some() {
        return None;
    }
    let month = Month::try_from(month).ok()?;
    let date = Date::from_calendar_date(year, month, day).ok()?;
    Some(date.midnight().assume_utc().unix_timestamp())
}

fn parse_search_size(value: &str) -> Option<i64> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    let (digits, multiplier) = match value.as_bytes().last().copied() {
        Some(b'k' | b'K') => (&value[..value.len() - 1], 1024_i64),
        Some(b'm' | b'M') => (&value[..value.len() - 1], 1024_i64 * 1024),
        _ => (value, 1),
    };
    if digits.is_empty() || !digits.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    digits.parse::<i64>().ok()?.checked_mul(multiplier)
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
    /// Optional phone number, user-managed.
    pub phone: String,
    /// Optional company/organization, user-managed.
    pub company: String,
    /// Optional job title, user-managed.
    pub title: String,
    /// Free-form private notes, user-managed.
    pub notes: String,
    /// Manually-added contacts sort ahead of harvested ones.
    pub manual: bool,
    /// How many times this address was seen as a correspondent (harvest frequency).
    pub seen_count: i64,
}

/// A user-defined contact group. Members are stored separately by contact address.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ContactGroup {
    /// Opaque id, primary key.
    pub id: String,
    /// The owning mailbox.
    pub user: String,
    /// Display name users can type into the recipient field.
    pub name: String,
    /// Creation time in epoch seconds.
    pub created_at: i64,
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
    /// Owning mailbox for user-authored scheduled sends. Empty for legacy/system queue rows.
    pub mailbox: String,
    /// Shared id across the per-destination queue rows produced by one compose submission.
    pub batch_id: String,
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
    /// User-selected schedule time (epoch seconds). `0` means as soon as `next_at` is due.
    pub send_at: i64,
    /// Whether this batch has already produced its local Sent copy.
    pub sent_copy_filed: bool,
    /// `queued` | `scheduled` | `sent` | `failed`.
    pub status: String,
}

/// One user-facing scheduled send, aggregated from all destination-domain queue rows in a batch.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ScheduledOutbound {
    pub batch_id: String,
    pub mailbox: String,
    pub raw: String,
    pub env_from: String,
    pub rcpts: Vec<String>,
    pub send_at: i64,
    pub status: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_search_query_preserves_bare_substring_search() {
        let q = parse_search_query("quarterly report");
        assert!(!q.or_mode);
        assert!(q.predicates.is_empty());
        assert_eq!(
            q.text_terms,
            vec![SearchTextTerm {
                value: "quarterly report".to_string(),
                negated: false,
            }]
        );
    }

    #[test]
    fn parse_search_query_handles_field_predicates_and_quotes() {
        let q = parse_search_query(r#"from:alice subject:"quarterly report" "exact phrase""#);
        assert_eq!(
            q.predicates,
            vec![
                SearchPredicate {
                    kind: SearchPredicateKind::From("alice".to_string()),
                    negated: false,
                },
                SearchPredicate {
                    kind: SearchPredicateKind::Subject("quarterly report".to_string()),
                    negated: false,
                },
            ]
        );
        assert_eq!(
            q.text_terms,
            vec![SearchTextTerm {
                value: "exact phrase".to_string(),
                negated: false,
            }]
        );
    }

    #[test]
    fn parse_search_query_handles_states_attachment_folder_and_label() {
        let q = parse_search_query(
            "to:bob cc:team label:Finance is:unread has:attachment in:Sent -is:starred",
        );
        assert_eq!(
            q.predicates,
            vec![
                SearchPredicate {
                    kind: SearchPredicateKind::To("bob".to_string()),
                    negated: false,
                },
                SearchPredicate {
                    kind: SearchPredicateKind::Cc("team".to_string()),
                    negated: false,
                },
                SearchPredicate {
                    kind: SearchPredicateKind::Label("Finance".to_string()),
                    negated: false,
                },
                SearchPredicate {
                    kind: SearchPredicateKind::Is(SearchState::Unread),
                    negated: false,
                },
                SearchPredicate {
                    kind: SearchPredicateKind::HasAttachment,
                    negated: false,
                },
                SearchPredicate {
                    kind: SearchPredicateKind::InFolder("Sent".to_string()),
                    negated: false,
                },
                SearchPredicate {
                    kind: SearchPredicateKind::Is(SearchState::Starred),
                    negated: true,
                },
            ]
        );
    }

    #[test]
    fn parse_search_query_handles_dates_sizes_negation_and_or() {
        let q = parse_search_query(
            "after:1970-01-01 before:1970-01-02 larger:10k smaller:2M alpha OR -beta",
        );
        assert!(q.or_mode);
        assert_eq!(
            q.predicates,
            vec![
                SearchPredicate {
                    kind: SearchPredicateKind::After(0),
                    negated: false,
                },
                SearchPredicate {
                    kind: SearchPredicateKind::Before(86_400),
                    negated: false,
                },
                SearchPredicate {
                    kind: SearchPredicateKind::Larger(10 * 1024),
                    negated: false,
                },
                SearchPredicate {
                    kind: SearchPredicateKind::Smaller(2 * 1024 * 1024),
                    negated: false,
                },
            ]
        );
        assert_eq!(
            q.text_terms,
            vec![
                SearchTextTerm {
                    value: "alpha".to_string(),
                    negated: false,
                },
                SearchTextTerm {
                    value: "beta".to_string(),
                    negated: true,
                },
            ]
        );
    }

    #[test]
    fn parse_search_query_degrades_invalid_operators_to_text() {
        let q = parse_search_query("before:not-a-date larger:many is:unknown");
        assert!(q.predicates.is_empty());
        assert_eq!(
            q.text_terms,
            vec![
                SearchTextTerm {
                    value: "before:not-a-date".to_string(),
                    negated: false,
                },
                SearchTextTerm {
                    value: "larger:many".to_string(),
                    negated: false,
                },
                SearchTextTerm {
                    value: "is:unknown".to_string(),
                    negated: false,
                },
            ]
        );
    }
}
