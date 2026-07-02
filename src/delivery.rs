//! Inbound delivery pipeline: server-side filter rules + the auto-reply (vacation) responder.
//!
//! The SMTP DATA path calls [`process_inbound`] instead of storing directly, so both features
//! apply at DELIVERY time (the Fastmail model — rules run on the server, not in a client):
//! - Enabled [`FilterRule`]s are evaluated in position order, FIRST MATCH WINS: `move` re-targets
//!   the folder, `star`/`markread` pre-set the flags, `discard` drops the message silently
//!   (audited — the drop is still counted — but never stored).
//! - After storage the auto-reply MAY queue one reply back to the envelope sender through the
//!   EXISTING outbound relay path ([`relay::enqueue_outbound`]) — never to our own address,
//!   never to an empty return-path, never to bulk/auto-generated mail (`Auto-Submitted`,
//!   `List-Id`, `Precedence: bulk|list|junk`), and at most once per sender per 24h
//!   ([`Store::mark_auto_replied`]). The reply itself goes out with a NULL envelope sender and
//!   `Auto-Submitted: auto-replied` (RFC 3834), so two vacationing mailboxes can never loop.

use crate::dkim::DkimSigner;
use crate::model::{FilterRule, MailboxSettings, Message};
use crate::relay;
use crate::rfc822;
use crate::store::{Store, StoreError};
use crate::util::{email_date, message_id, now_secs};

/// Deliver one accepted inbound message: apply the mailbox's filter rules, store the (possibly
/// adjusted) message, then run the auto-reply responder. A storage failure propagates (the SMTP
/// session replies 451); an auto-reply failure is logged but never fails the delivery.
pub async fn process_inbound(
    store: &dyn Store,
    signer: Option<&DkimSigner>,
    mail_domain: &str,
    env_from: &str,
    msg: Message,
) -> Result<(), StoreError> {
    let mut msg = msg;
    let rules = store.list_rules(&msg.mailbox).await?;
    if let Some(rule) = first_match(&rules, &msg) {
        tracing::info!(
            target: "corvid::audit",
            mailbox = %msg.mailbox,
            rule = %rule.id,
            action = %rule.action,
            from = %msg.msg_from,
            "filter rule matched inbound message",
        );
        match rule.action.as_str() {
            // Dropped silently: the audit line above is the count — nothing is stored and the
            // auto-reply never fires for a discarded message.
            "discard" => return Ok(()),
            "move" => {
                if let Some(f) = rule.target_folder.as_deref().filter(|f| !f.is_empty()) {
                    msg.folder = f.to_string();
                }
            }
            "star" => msg.starred = true,
            "markread" => msg.seen = true,
            _ => {}
        }
    }
    store.store_message(&msg).await?;
    maybe_auto_reply(store, signer, mail_domain, env_from, &msg).await;
    Ok(())
}

/// The first ENABLED rule (position order) matching `msg`, if any — first match wins.
pub fn first_match<'a>(rules: &'a [FilterRule], msg: &Message) -> Option<&'a FilterRule> {
    let mut ordered: Vec<&FilterRule> = rules.iter().filter(|r| r.enabled).collect();
    ordered.sort_by_key(|r| r.position);
    ordered.into_iter().find(|r| rule_matches(r, msg))
}

/// Whether one rule matches a message: `field` selects the haystack, `op` the comparison
/// (both case-insensitive). Unknown fields/ops and empty `contains` needles never match.
pub fn rule_matches(rule: &FilterRule, msg: &Message) -> bool {
    let hay = match rule.field.as_str() {
        "from" => &msg.msg_from,
        "to" => &msg.msg_to,
        "subject" => &msg.subject,
        _ => return false,
    };
    let hay = hay.to_lowercase();
    let needle = rule.needle.to_lowercase();
    match rule.op.as_str() {
        "contains" => !needle.is_empty() && hay.contains(&needle),
        "equals" => hay.trim() == needle.trim(),
        _ => false,
    }
}

/// Whether the auto-reply is switched on and unexpired (`until` of 0 = no expiry).
pub fn auto_reply_active(settings: &MailboxSettings, now: i64) -> bool {
    settings.auto_reply_enabled
        && (settings.auto_reply_until == 0 || now < settings.auto_reply_until)
}

/// The RFC 3834 guards: never auto-reply to our own address, to an empty return-path (a bounce
/// or another auto-responder), or to mail whose headers mark a bulk/automatic origin
/// (`Auto-Submitted` other than `no`, any `List-Id`, `Precedence: bulk|list|junk`).
pub fn auto_reply_allowed(raw: &str, env_from: &str, self_addr: &str) -> bool {
    let sender = env_from.trim();
    if sender.is_empty() || sender.eq_ignore_ascii_case(self_addr) {
        return false;
    }
    let (hb, _) = rfc822::split_headers_body(raw);
    let hdrs = rfc822::parse_headers(hb);
    if let Some(v) = rfc822::header(&hdrs, "auto-submitted") {
        if !v.trim().eq_ignore_ascii_case("no") {
            return false;
        }
    }
    if rfc822::header(&hdrs, "list-id").is_some() {
        return false;
    }
    if let Some(p) = rfc822::header(&hdrs, "precedence") {
        if matches!(p.trim().to_ascii_lowercase().as_str(), "bulk" | "list" | "junk") {
            return false;
        }
    }
    true
}

/// Run the auto-reply responder for one stored inbound message. Best effort: every failure is
/// logged and swallowed (the mail is already delivered).
async fn maybe_auto_reply(
    store: &dyn Store,
    signer: Option<&DkimSigner>,
    mail_domain: &str,
    env_from: &str,
    msg: &Message,
) {
    let settings = match store.get_settings(&msg.mailbox).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, mailbox = %msg.mailbox, "auto-reply: settings lookup failed");
            return;
        }
    };
    let now = now_secs();
    if !auto_reply_active(&settings, now) {
        return;
    }
    if !auto_reply_allowed(&msg.raw_rfc822, env_from, &msg.mailbox) {
        return;
    }
    let sender = env_from.trim().to_lowercase();
    match store.mark_auto_replied(&msg.mailbox, &sender, now).await {
        Ok(true) => {}
        Ok(false) => return, // already replied to this sender within the dedupe window
        Err(e) => {
            tracing::warn!(error = %e, mailbox = %msg.mailbox, "auto-reply: dedupe check failed");
            return;
        }
    }
    let raw = build_auto_reply(&msg.mailbox, env_from, &settings, &msg.subject, mail_domain);
    // NULL envelope sender (MAIL FROM:<>) per RFC 3834 — the remote side's responder (and our
    // own empty-return-path guard above) then suppresses any reply to this reply.
    match relay::enqueue_outbound(store, signer, &raw, "", &[env_from.trim().to_string()]).await {
        Ok(_) => tracing::info!(
            target: "corvid::audit",
            mailbox = %msg.mailbox,
            to = %sender,
            "auto-reply queued",
        ),
        Err(e) => tracing::warn!(error = %e, mailbox = %msg.mailbox, "auto-reply enqueue failed"),
    }
}

/// Build the auto-reply RFC822 source: plain text, `Auto-Submitted: auto-replied`, subject from
/// the settings (falling back to `Auto: <original subject>`).
fn build_auto_reply(
    from: &str,
    to: &str,
    settings: &MailboxSettings,
    orig_subject: &str,
    domain: &str,
) -> String {
    let subject = if settings.auto_reply_subject.trim().is_empty() {
        let orig = orig_subject.trim();
        if orig.is_empty() {
            "Auto-reply".to_string()
        } else {
            format!("Auto: {orig}")
        }
    } else {
        settings.auto_reply_subject.trim().to_string()
    };
    let body = settings.auto_reply_body.replace("\r\n", "\n").replace('\n', "\r\n");
    format!(
        "From: {from}\r\nTo: {to}\r\nSubject: {subject}\r\nDate: {date}\r\nMessage-ID: {mid}\r\n\
         Auto-Submitted: auto-replied\r\nMIME-Version: 1.0\r\n\
         Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n\
         {body}\r\n",
        to = header_safe(to.trim()),
        subject = header_safe(&subject),
        date = email_date(),
        mid = message_id(domain),
    )
}

/// Strip CR/LF from a user-supplied value interpolated into a mail header (header injection).
fn header_safe(s: &str) -> String {
    s.chars().filter(|c| *c != '\r' && *c != '\n').collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg(from: &str, to: &str, subject: &str) -> Message {
        Message {
            id: "m_test".to_string(),
            mailbox: "w33d@w33d.xyz".to_string(),
            msg_from: from.to_string(),
            msg_to: to.to_string(),
            subject: subject.to_string(),
            raw_rfc822: String::new(),
            body_text: String::new(),
            body_html: String::new(),
            received_at: 0,
            seen: false,
            folder: "INBOX".to_string(),
            starred: false,
        }
    }

    fn rule(id: &str, position: i64, field: &str, op: &str, needle: &str) -> FilterRule {
        FilterRule {
            id: id.to_string(),
            mailbox: "w33d@w33d.xyz".to_string(),
            position,
            field: field.to_string(),
            op: op.to_string(),
            needle: needle.to_string(),
            action: "star".to_string(),
            target_folder: None,
            enabled: true,
            created_at: 0,
        }
    }

    #[test]
    fn rule_matches_fields_and_ops_case_insensitively() {
        let m = msg("Alice <ALICE@example.com>", "w33d@w33d.xyz", "Weekly Report");
        assert!(rule_matches(&rule("r", 1, "from", "contains", "alice@example"), &m));
        assert!(rule_matches(&rule("r", 1, "subject", "contains", "weekly"), &m));
        assert!(rule_matches(&rule("r", 1, "subject", "equals", "weekly report"), &m));
        assert!(rule_matches(&rule("r", 1, "to", "equals", "W33D@w33d.xyz"), &m));
        assert!(!rule_matches(&rule("r", 1, "subject", "equals", "weekly"), &m));
        assert!(!rule_matches(&rule("r", 1, "from", "contains", "bob@"), &m));
        // Unknown field/op and an empty contains needle never match.
        assert!(!rule_matches(&rule("r", 1, "body", "contains", "x"), &m));
        assert!(!rule_matches(&rule("r", 1, "from", "regex", "x"), &m));
        assert!(!rule_matches(&rule("r", 1, "from", "contains", ""), &m));
    }

    #[test]
    fn first_match_wins_in_position_order_skipping_disabled() {
        let m = msg("alice@example.com", "w33d@w33d.xyz", "hi");
        // Stored out of order on purpose: position decides, not insertion order.
        let mut r_late = rule("r_late", 5, "from", "contains", "alice");
        r_late.action = "markread".to_string();
        let r_first = rule("r_first", 1, "from", "contains", "alice");
        let r_miss = rule("r_miss", 0, "subject", "equals", "nope");
        let mut r_disabled = rule("r_disabled", 0, "from", "contains", "alice");
        r_disabled.enabled = false;
        let rules = vec![r_late.clone(), r_miss, r_disabled, r_first.clone()];

        let hit = first_match(&rules, &m).expect("a rule matches");
        assert_eq!(hit.id, "r_first", "lowest matching position wins");

        // With the first rule disabled, the later one takes over.
        let mut rules2 = rules.clone();
        rules2.iter_mut().find(|r| r.id == "r_first").unwrap().enabled = false;
        assert_eq!(first_match(&rules2, &m).unwrap().id, "r_late");

        // Nothing enabled matches -> None.
        assert!(first_match(&rules, &msg("bob@x.com", "", "nope2")).is_none());
    }

    #[test]
    fn auto_reply_guards_block_bulk_and_self_and_null_path() {
        let plain = "From: a@b.com\r\nSubject: hi\r\n\r\nbody";
        assert!(auto_reply_allowed(plain, "a@b.com", "w33d@w33d.xyz"));
        // Empty return-path (bounce / another responder) and our own address are blocked.
        assert!(!auto_reply_allowed(plain, "", "w33d@w33d.xyz"));
        assert!(!auto_reply_allowed(plain, "  ", "w33d@w33d.xyz"));
        assert!(!auto_reply_allowed(plain, "W33D@w33d.xyz", "w33d@w33d.xyz"));
        // Bulk/auto markers are blocked; Auto-Submitted: no is explicitly allowed.
        let auto = "Auto-Submitted: auto-generated\r\nFrom: a@b.com\r\n\r\nx";
        assert!(!auto_reply_allowed(auto, "a@b.com", "w33d@w33d.xyz"));
        let auto_no = "Auto-Submitted: no\r\nFrom: a@b.com\r\n\r\nx";
        assert!(auto_reply_allowed(auto_no, "a@b.com", "w33d@w33d.xyz"));
        let list = "List-Id: <dev.lists.example.com>\r\nFrom: a@b.com\r\n\r\nx";
        assert!(!auto_reply_allowed(list, "a@b.com", "w33d@w33d.xyz"));
        for p in ["bulk", "list", "junk", "Bulk"] {
            let raw = format!("Precedence: {p}\r\nFrom: a@b.com\r\n\r\nx");
            assert!(!auto_reply_allowed(&raw, "a@b.com", "w33d@w33d.xyz"), "Precedence: {p}");
        }
        let first_class = "Precedence: first-class\r\nFrom: a@b.com\r\n\r\nx";
        assert!(auto_reply_allowed(first_class, "a@b.com", "w33d@w33d.xyz"));
    }

    #[test]
    fn auto_reply_active_honours_expiry() {
        let mut s = MailboxSettings::default_for("w33d@w33d.xyz");
        assert!(!auto_reply_active(&s, 1000), "disabled by default");
        s.auto_reply_enabled = true;
        assert!(auto_reply_active(&s, 1000), "no expiry when until = 0");
        s.auto_reply_until = 999;
        assert!(!auto_reply_active(&s, 1000), "expired");
        s.auto_reply_until = 1001;
        assert!(auto_reply_active(&s, 1000), "still inside the window");
    }

    #[test]
    fn build_auto_reply_sets_rfc3834_headers_and_strips_injection() {
        let mut s = MailboxSettings::default_for("w33d@w33d.xyz");
        s.auto_reply_subject = "Out\r\nBcc: evil@x.com".to_string();
        s.auto_reply_body = "Back next week.\nCheers".to_string();
        let raw = build_auto_reply("w33d@w33d.xyz", "a@b.com", &s, "orig", "w33d.xyz");
        assert!(raw.contains("Auto-Submitted: auto-replied\r\n"));
        assert!(raw.contains("Subject: OutBcc: evil@x.com\r\n"), "CRLF stripped: {raw}");
        assert!(!raw.contains("\r\nBcc:"), "no injected header");
        assert!(raw.contains("Back next week.\r\nCheers"));

        // Empty configured subject falls back to the original subject.
        s.auto_reply_subject = String::new();
        let raw = build_auto_reply("w33d@w33d.xyz", "a@b.com", &s, "Ping", "w33d.xyz");
        assert!(raw.contains("Subject: Auto: Ping\r\n"));
        let raw = build_auto_reply("w33d@w33d.xyz", "a@b.com", &s, " ", "w33d.xyz");
        assert!(raw.contains("Subject: Auto-reply\r\n"));
    }
}
