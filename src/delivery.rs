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
use crate::model::{FilterRule, MailboxSettings, Message, SenderListEntry, SpamAnnotation};
use crate::relay;
use crate::rfc822;
use crate::store::{Store, StoreError};
use crate::util::{email_date, message_id, new_id, now_secs};

pub const SPAM_FOLDER: &str = "Spam";
pub const SPAM_SCORE_THRESHOLD: i64 = 5;
const SPAM_SCORE_BLOCKED_SENDER: i64 = 10;
const SPAM_SCORE_SPF_FAIL: i64 = 3;
const SPAM_SCORE_DKIM_FAIL: i64 = 3;

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
    // Conversation threading: compute the message's own Message-ID + its thread id from the raw
    // source BEFORE storage (the delivery hook, kept surgical — one helper call).
    let (mid, tid) = resolve_thread(store, &msg.mailbox, &msg.raw_rfc822, &msg.subject).await?;
    msg.message_id = mid;
    msg.thread_id = tid;
    let thread_muted = store.is_thread_muted(&msg.mailbox, &msg.thread_id).await?;
    msg.muted = thread_muted;

    let rules = store.list_rules(&msg.mailbox).await?;
    let mut labelled: Option<String> = None;
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
            // "add label": applied AFTER storage (the join references the stored message id).
            "label" => labelled = rule.target_label.clone().filter(|l| !l.is_empty()),
            _ => {}
        }
    }
    let spam = assess_spam(store, &msg).await?;
    if spam.safe_match.is_some() {
        if msg.folder == SPAM_FOLDER {
            msg.folder = "INBOX".to_string();
        }
    } else if spam.should_spam()
        && (spam.blocked_match.is_some() || msg.folder.eq_ignore_ascii_case("INBOX"))
    {
        tracing::info!(
            target: "corvid::audit",
            mailbox = %msg.mailbox,
            from = %msg.msg_from,
            score = spam.score,
            reasons = %spam.reason_text(),
            "spam assessment placed inbound message in Spam",
        );
        msg.folder = SPAM_FOLDER.to_string();
    }
    if thread_muted && msg.folder.eq_ignore_ascii_case("INBOX") {
        tracing::info!(
            target: "corvid::audit",
            mailbox = %msg.mailbox,
            thread = %msg.thread_id,
            "muted inbound thread archived",
        );
        msg.folder = "Archive".to_string();
    }
    store.store_message(&msg).await?;
    if let Some(annotation) = spam.annotation(&msg) {
        if let Err(e) = store.set_spam_annotation(&annotation).await {
            tracing::warn!(error = %e, mailbox = %msg.mailbox, message = %msg.id, "spam annotation failed");
        }
    }
    if let Some(label_id) = labelled {
        // Best effort: a stale/deleted label just no-ops (store enforces ownership).
        if let Err(e) = store.assign_label(&msg.mailbox, &msg.id, &label_id).await {
            tracing::warn!(error = %e, mailbox = %msg.mailbox, "filter label assignment failed");
        }
    }
    // Harvest the inbound correspondent(s) into the mailbox's contacts (autocomplete). Best effort.
    harvest_contacts(store, &msg.mailbox, &msg.msg_from, "").await;
    maybe_auto_reply(store, signer, mail_domain, env_from, &msg).await;
    Ok(())
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct SpamAssessment {
    score: i64,
    reasons: Vec<String>,
    safe_match: Option<String>,
    blocked_match: Option<String>,
}

impl SpamAssessment {
    fn should_spam(&self) -> bool {
        self.blocked_match.is_some() || self.score >= SPAM_SCORE_THRESHOLD
    }

    fn reason_text(&self) -> String {
        self.reasons.join("; ")
    }

    fn annotation(&self, msg: &Message) -> Option<SpamAnnotation> {
        if self.safe_match.is_some() || self.score <= 0 {
            return None;
        }
        Some(SpamAnnotation {
            mailbox: msg.mailbox.clone(),
            message_id: msg.id.clone(),
            score: self.score,
            reason: self.reason_text(),
        })
    }
}

async fn assess_spam(store: &dyn Store, msg: &Message) -> Result<SpamAssessment, StoreError> {
    let sender = normalize_sender_addr(&msg.msg_from);
    let entries = store.list_sender_lists(&msg.mailbox).await?;
    let mut assessment = SpamAssessment::default();
    if let Some(hit) = sender_list_match(&entries, &sender, "safe") {
        assessment.safe_match = Some(hit.address_or_domain.clone());
        return Ok(assessment);
    }
    if let Some(hit) = sender_list_match(&entries, &sender, "blocked") {
        assessment.blocked_match = Some(hit.address_or_domain.clone());
        assessment.score += SPAM_SCORE_BLOCKED_SENDER;
        assessment.reasons.push(format!(
            "blocked sender list match: {}",
            hit.address_or_domain
        ));
    }

    let (headers, _) = rfc822::split_headers_body(&msg.raw_rfc822);
    let hdrs = rfc822::parse_headers(headers);
    if spf_failed(&hdrs) {
        assessment.score += SPAM_SCORE_SPF_FAIL;
        assessment.reasons.push("SPF fail".to_string());
    }
    if dkim_failed(&hdrs) {
        assessment.score += SPAM_SCORE_DKIM_FAIL;
        assessment.reasons.push("DKIM fail".to_string());
    }
    Ok(assessment)
}

fn sender_list_match<'a>(
    entries: &'a [SenderListEntry],
    sender: &str,
    kind: &str,
) -> Option<&'a SenderListEntry> {
    entries
        .iter()
        .filter(|e| e.kind == kind)
        .find(|e| sender_entry_matches(e, sender))
}

fn sender_entry_matches(entry: &SenderListEntry, sender: &str) -> bool {
    let value = entry
        .address_or_domain
        .trim()
        .trim_start_matches('@')
        .to_ascii_lowercase();
    if value.is_empty() || sender.is_empty() {
        return false;
    }
    if value.contains('@') {
        return sender.eq_ignore_ascii_case(&value);
    }
    sender
        .rsplit_once('@')
        .map(|(_, domain)| domain.eq_ignore_ascii_case(&value))
        .unwrap_or(false)
}

fn normalize_sender_addr(from: &str) -> String {
    let (_, addr) = split_name_addr(from);
    addr.trim()
        .trim_matches('<')
        .trim_matches('>')
        .to_ascii_lowercase()
}

fn spf_failed(hdrs: &[(String, String)]) -> bool {
    rfc822::header(hdrs, "received-spf")
        .and_then(|v| v.split_whitespace().next().map(str::to_ascii_lowercase))
        .is_some_and(|token| token == "fail")
}

fn dkim_failed(hdrs: &[(String, String)]) -> bool {
    hdrs.iter()
        .filter(|(name, _)| name == "authentication-results")
        .any(|(_, value)| {
            let lower = value.to_ascii_lowercase();
            lower.contains("dkim=fail") || lower.contains("dkim=permerror")
        })
}

/// Resolve `(own_message_id, thread_id)` for a message from its raw source + subject. Threading
/// follows the `References`/`In-Reply-To` chain (adopting an existing conversation when any
/// referenced id is already known), falling back to the normalised `Subject` when no thread headers
/// are present. Pure except for the store lookup used to link to an existing thread.
pub async fn resolve_thread(
    store: &dyn Store,
    mailbox: &str,
    raw: &str,
    subject: &str,
) -> Result<(String, String), StoreError> {
    let (hb, _) = rfc822::split_headers_body(raw);
    let hdrs = rfc822::parse_headers(hb);
    let own_mid = rfc822::header(&hdrs, "message-id")
        .unwrap_or_default()
        .trim()
        .to_string();
    let refs = reference_ids(&hdrs);

    // Include our own Message-ID so a reply that arrived before its original still links up when the
    // original lands (the earlier reply already carries the shared thread id).
    let mut lookup: Vec<String> = refs.clone();
    if !own_mid.is_empty() {
        lookup.push(own_mid.clone());
    }
    if !lookup.is_empty() {
        if let Some(tid) = store.find_thread_for_refs(mailbox, &lookup).await? {
            return Ok((own_mid, tid));
        }
    }
    // No existing thread matched: root a References/In-Reply-To chain at its earliest reference.
    if let Some(root) = refs.first() {
        return Ok((own_mid, root.clone()));
    }
    // No thread headers at all -> group by normalised subject (deterministic `subj:` key).
    let norm = normalize_subject(subject);
    if !norm.is_empty() {
        return Ok((own_mid, format!("subj:{norm}")));
    }
    // Degenerate: no headers and no subject — the message is its own thread.
    let tid = if own_mid.is_empty() {
        new_id("t")
    } else {
        own_mid.clone()
    };
    Ok((own_mid, tid))
}

/// The `Message-ID`s a message references, earliest (root) first: every token of `References`
/// followed by `In-Reply-To`, de-duplicated. Each `<...>` angle-addr is kept verbatim (trimmed).
pub fn reference_ids(hdrs: &[(String, String)]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut push_tokens = |v: &str| {
        for tok in v.split_whitespace() {
            let tok = tok.trim();
            if tok.starts_with('<')
                && tok.ends_with('>')
                && tok.len() > 2
                && !out.iter().any(|e| e == tok)
            {
                out.push(tok.to_string());
            }
        }
    };
    if let Some(refs) = rfc822::header(hdrs, "references") {
        push_tokens(&refs);
    }
    if let Some(irt) = rfc822::header(hdrs, "in-reply-to") {
        push_tokens(&irt);
    }
    out
}

/// Normalise a subject for the header-absent threading fallback: strip any run of leading
/// `Re:`/`Fwd:`/`Fw:` prefixes (case-insensitive), collapse internal whitespace, lowercase, trim.
pub fn normalize_subject(subject: &str) -> String {
    let mut s = subject.trim();
    loop {
        let low = s.to_ascii_lowercase();
        let stripped = if let Some(r) = low.strip_prefix("re:") {
            &s[s.len() - r.len()..]
        } else if let Some(r) = low.strip_prefix("fwd:") {
            &s[s.len() - r.len()..]
        } else if let Some(r) = low.strip_prefix("fw:") {
            &s[s.len() - r.len()..]
        } else {
            break;
        };
        s = stripped.trim_start();
    }
    s.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

/// Harvest correspondents from a message's `From`/`To` header strings into the mailbox's contacts
/// (skips the mailbox's own address). Best effort — a store failure is logged, never propagated.
pub async fn harvest_contacts(store: &dyn Store, mailbox: &str, from: &str, to: &str) {
    for field in [from, to] {
        for part in field.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            let (name, addr) = split_name_addr(part);
            let addr_l = addr.to_lowercase();
            if !addr_l.contains('@') || addr_l.eq_ignore_ascii_case(mailbox) {
                continue;
            }
            if let Err(e) = store.upsert_contact(mailbox, &addr_l, &name, false).await {
                tracing::warn!(error = %e, mailbox, "contact harvest failed");
            }
        }
    }
}

/// Split a `Name <addr>` (or bare `addr`) correspondent into `(display_name, address)`.
fn split_name_addr(s: &str) -> (String, String) {
    let s = s.trim();
    if let Some(lt) = s.find('<') {
        if let Some(gt) = s[lt..].find('>') {
            let addr = s[lt + 1..lt + gt].trim().to_string();
            let name = s[..lt].trim().trim_matches('"').trim().to_string();
            return (name, addr);
        }
    }
    (String::new(), s.to_string())
}

/// Summary returned after retroactively applying one filter rule to stored messages.
#[derive(Debug, Default, Clone)]
pub struct RuleRunReport {
    pub scanned: i64,
    pub matched: i64,
    pub changed: i64,
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

/// Apply one existing rule to already-stored messages in `mailbox`, bounded by `limit`.
pub async fn apply_rule_to_existing(
    store: &dyn Store,
    mailbox: &str,
    rule: &FilterRule,
    limit: i64,
) -> Result<RuleRunReport, StoreError> {
    let cands = store.list_messages(mailbox, limit).await?;
    let mut report = RuleRunReport {
        scanned: cands.len() as i64,
        ..RuleRunReport::default()
    };

    for s in &cands {
        let Some(msg) = store.get_message(&s.id).await? else {
            continue;
        };
        if msg.mailbox != mailbox {
            continue;
        }
        if !rule_matches(rule, &msg) {
            continue;
        }
        report.matched += 1;
        match rule.action.as_str() {
            "move" => {
                if let Some(f) = rule.target_folder.as_deref().filter(|f| !f.is_empty()) {
                    store.set_folder(&msg.id, f).await?;
                    report.changed += 1;
                }
            }
            "star" => {
                store.set_starred(&msg.id, true).await?;
                report.changed += 1;
            }
            "markread" => {
                store.mark_seen(&msg.id).await?;
                report.changed += 1;
            }
            "label" => {
                if let Some(l) = rule.target_label.as_deref().filter(|l| !l.is_empty()) {
                    store.assign_label(mailbox, &msg.id, l).await?;
                    report.changed += 1;
                }
            }
            "discard" => {
                store.set_folder(&msg.id, "Trash").await?;
                report.changed += 1;
            }
            _ => {}
        }
    }

    Ok(report)
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
        if matches!(
            p.trim().to_ascii_lowercase().as_str(),
            "bulk" | "list" | "junk"
        ) {
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
    let body = settings
        .auto_reply_body
        .replace("\r\n", "\n")
        .replace('\n', "\r\n");
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
    use crate::store::InMemoryStore;

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
            snooze_until: 0,
            muted: false,
            thread_id: String::new(),
            message_id: String::new(),
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
            target_label: None,
            enabled: true,
            created_at: 0,
        }
    }

    fn sender_entry(kind: &str, value: &str) -> SenderListEntry {
        SenderListEntry {
            id: format!("sl_{kind}"),
            user: "w33d@w33d.xyz".to_string(),
            address_or_domain: value.to_string(),
            kind: kind.to_string(),
            created_at: 0,
        }
    }

    fn stored_msg(
        id: &str,
        mailbox: &str,
        from: &str,
        to: &str,
        subject: &str,
        received_at: i64,
    ) -> Message {
        let mut m = msg(from, to, subject);
        m.id = id.to_string();
        m.mailbox = mailbox.to_string();
        m.received_at = received_at;
        m
    }

    fn action_rule(id: &str, mailbox: &str, field: &str, needle: &str, action: &str) -> FilterRule {
        let mut r = rule(id, 1, field, "contains", needle);
        r.mailbox = mailbox.to_string();
        r.action = action.to_string();
        r
    }

    async fn assert_move_rule_moves_only_match(
        field: &str,
        needle: &str,
        matching: Message,
        miss: Message,
    ) {
        let store = InMemoryStore::new();
        let mailbox = matching.mailbox.clone();
        let matching_id = matching.id.clone();
        let miss_id = miss.id.clone();
        store.store_message(&matching).await.unwrap();
        store.store_message(&miss).await.unwrap();

        let mut r = action_rule("r_move", &mailbox, field, needle, "move");
        r.target_folder = Some("Archive".to_string());
        let rep = apply_rule_to_existing(&store, &mailbox, &r, 10)
            .await
            .unwrap();

        assert_eq!((rep.scanned, rep.matched, rep.changed), (2, 1, 1));
        assert_eq!(
            store
                .get_message(&matching_id)
                .await
                .unwrap()
                .unwrap()
                .folder,
            "Archive"
        );
        assert_eq!(
            store.get_message(&miss_id).await.unwrap().unwrap().folder,
            "INBOX"
        );
    }

    #[test]
    fn rule_matches_fields_and_ops_case_insensitively() {
        let m = msg(
            "Alice <ALICE@example.com>",
            "w33d@w33d.xyz",
            "Weekly Report",
        );
        assert!(rule_matches(
            &rule("r", 1, "from", "contains", "alice@example"),
            &m
        ));
        assert!(rule_matches(
            &rule("r", 1, "subject", "contains", "weekly"),
            &m
        ));
        assert!(rule_matches(
            &rule("r", 1, "subject", "equals", "weekly report"),
            &m
        ));
        assert!(rule_matches(
            &rule("r", 1, "to", "equals", "W33D@w33d.xyz"),
            &m
        ));
        assert!(!rule_matches(
            &rule("r", 1, "subject", "equals", "weekly"),
            &m
        ));
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
        rules2
            .iter_mut()
            .find(|r| r.id == "r_first")
            .unwrap()
            .enabled = false;
        assert_eq!(first_match(&rules2, &m).unwrap().id, "r_late");

        // Nothing enabled matches -> None.
        assert!(first_match(&rules, &msg("bob@x.com", "", "nope2")).is_none());
    }

    #[tokio::test]
    async fn apply_rule_to_existing_moves_only_matching_messages() {
        assert_move_rule_moves_only_match(
            "from",
            "alice@example.com",
            stored_msg(
                "m_from_hit",
                "w33d@w33d.xyz",
                "Alice <alice@example.com>",
                "w33d@w33d.xyz",
                "Hello",
                10,
            ),
            stored_msg(
                "m_from_miss",
                "w33d@w33d.xyz",
                "Bob <bob@example.com>",
                "w33d@w33d.xyz",
                "Hello",
                9,
            ),
        )
        .await;
        assert_move_rule_moves_only_match(
            "subject",
            "quarterly",
            stored_msg(
                "m_subject_hit",
                "w33d@w33d.xyz",
                "reporter@example.com",
                "w33d@w33d.xyz",
                "Quarterly report",
                10,
            ),
            stored_msg(
                "m_subject_miss",
                "w33d@w33d.xyz",
                "reporter@example.com",
                "w33d@w33d.xyz",
                "Weekly report",
                9,
            ),
        )
        .await;
        assert_move_rule_moves_only_match(
            "to",
            "team@example.com",
            stored_msg(
                "m_to_hit",
                "w33d@w33d.xyz",
                "sender@example.com",
                "Team <team@example.com>",
                "Alias mail",
                10,
            ),
            stored_msg(
                "m_to_miss",
                "w33d@w33d.xyz",
                "sender@example.com",
                "w33d@w33d.xyz",
                "Alias mail",
                9,
            ),
        )
        .await;
    }

    #[tokio::test]
    async fn apply_rule_to_existing_star_markread_and_label_are_idempotent() {
        let store = InMemoryStore::new();
        let mailbox = "w33d@w33d.xyz";
        let star = stored_msg(
            "m_star",
            mailbox,
            "news@example.com",
            mailbox,
            "Star this",
            30,
        );
        let read = stored_msg(
            "m_read",
            mailbox,
            "news@example.com",
            mailbox,
            "Read this",
            20,
        );
        let labelled = stored_msg(
            "m_label",
            mailbox,
            "news@example.com",
            mailbox,
            "Label this",
            10,
        );
        store.store_message(&star).await.unwrap();
        store.store_message(&read).await.unwrap();
        store.store_message(&labelled).await.unwrap();
        let label = crate::model::Label {
            id: "lbl_finance".to_string(),
            mailbox: mailbox.to_string(),
            name: "Finance".to_string(),
            color: String::new(),
        };
        store.add_label(&label).await.unwrap();

        let star_rule = action_rule("r_star", mailbox, "subject", "Star this", "star");
        let read_rule = action_rule("r_read", mailbox, "subject", "Read this", "markread");
        let mut label_rule = action_rule("r_label", mailbox, "subject", "Label this", "label");
        label_rule.target_label = Some(label.id.clone());

        for r in [&star_rule, &read_rule, &label_rule] {
            let rep = apply_rule_to_existing(&store, mailbox, r, 10)
                .await
                .unwrap();
            assert_eq!((rep.scanned, rep.matched, rep.changed), (3, 1, 1));
            let rep = apply_rule_to_existing(&store, mailbox, r, 10)
                .await
                .unwrap();
            assert_eq!((rep.scanned, rep.matched, rep.changed), (3, 1, 1));
        }

        assert!(store.get_message("m_star").await.unwrap().unwrap().starred);
        assert!(store.get_message("m_read").await.unwrap().unwrap().seen);
        let labels = store.labels_for_message(mailbox, "m_label").await.unwrap();
        assert_eq!(labels.len(), 1);
        assert_eq!(labels[0].id, label.id);
    }

    #[tokio::test]
    async fn apply_rule_to_existing_discard_moves_to_trash_without_deleting() {
        let store = InMemoryStore::new();
        let mailbox = "w33d@w33d.xyz";
        let m = stored_msg(
            "m_discard",
            mailbox,
            "alerts@example.com",
            mailbox,
            "Discard this",
            1,
        );
        store.store_message(&m).await.unwrap();

        let r = action_rule("r_discard", mailbox, "subject", "Discard this", "discard");
        let rep = apply_rule_to_existing(&store, mailbox, &r, 10)
            .await
            .unwrap();

        assert_eq!((rep.scanned, rep.matched, rep.changed), (1, 1, 1));
        let stored = store.get_message("m_discard").await.unwrap().unwrap();
        assert_eq!(stored.folder, "Trash");
    }

    #[tokio::test]
    async fn apply_rule_to_existing_isolates_mailboxes() {
        let store = InMemoryStore::new();
        let a = stored_msg(
            "m_a",
            "a@w33d.xyz",
            "shared@example.com",
            "a@w33d.xyz",
            "Shared needle",
            2,
        );
        let b = stored_msg(
            "m_b",
            "b@w33d.xyz",
            "shared@example.com",
            "b@w33d.xyz",
            "Shared needle",
            1,
        );
        store.store_message(&a).await.unwrap();
        store.store_message(&b).await.unwrap();

        let mut r = action_rule(
            "r_isolate",
            "a@w33d.xyz",
            "subject",
            "Shared needle",
            "move",
        );
        r.target_folder = Some("Archive".to_string());
        let rep = apply_rule_to_existing(&store, "a@w33d.xyz", &r, 10)
            .await
            .unwrap();

        assert_eq!((rep.scanned, rep.matched, rep.changed), (1, 1, 1));
        assert_eq!(
            store.get_message("m_a").await.unwrap().unwrap().folder,
            "Archive"
        );
        assert_eq!(
            store.get_message("m_b").await.unwrap().unwrap().folder,
            "INBOX"
        );
    }

    #[tokio::test]
    async fn apply_rule_to_existing_honors_scan_limit() {
        let store = InMemoryStore::new();
        let mailbox = "w33d@w33d.xyz";
        let cap = 1000;
        for i in 0..(cap + 1) {
            let m = stored_msg(
                &format!("m_cap_{i}"),
                mailbox,
                "sender@example.com",
                mailbox,
                "Cap match",
                i,
            );
            store.store_message(&m).await.unwrap();
        }

        let r = action_rule("r_cap", mailbox, "subject", "Cap match", "star");
        let rep = apply_rule_to_existing(&store, mailbox, &r, cap)
            .await
            .unwrap();

        assert_eq!(rep.scanned, cap);
        assert_eq!(rep.matched, cap);
        assert_eq!(rep.changed, cap);
    }

    #[tokio::test]
    async fn spam_assessment_is_conservative_and_explainable() {
        let store = InMemoryStore::new();
        let mut one_fail = msg("bad@example.com", "w33d@w33d.xyz", "hi");
        one_fail.raw_rfc822 =
            "Received-SPF: fail (corvid)\r\nAuthentication-Results: mx; dkim=pass\r\n\r\nbody"
                .to_string();
        let one_fail_id = one_fail.id.clone();
        process_inbound(&store, None, "w33d.xyz", "bad@example.com", one_fail)
            .await
            .unwrap();
        assert_eq!(
            store
                .get_message(&one_fail_id)
                .await
                .unwrap()
                .unwrap()
                .folder,
            "INBOX",
            "SPF fail alone stays below the spam threshold"
        );

        let mut both_fail = msg("worse@example.com", "w33d@w33d.xyz", "hi");
        both_fail.id = "m_both".to_string();
        both_fail.raw_rfc822 =
            "Received-SPF: fail (corvid)\r\nAuthentication-Results: mx; dkim=fail\r\n\r\nbody"
                .to_string();
        process_inbound(&store, None, "w33d.xyz", "worse@example.com", both_fail)
            .await
            .unwrap();
        let stored = store.get_message("m_both").await.unwrap().unwrap();
        assert_eq!(stored.folder, SPAM_FOLDER);
        let annotation = store
            .spam_annotation("w33d@w33d.xyz", "m_both")
            .await
            .unwrap()
            .expect("spam reason recorded");
        assert_eq!(annotation.score, SPAM_SCORE_THRESHOLD + 1);
        assert!(annotation.reason.contains("SPF fail"));
        assert!(annotation.reason.contains("DKIM fail"));
    }

    #[tokio::test]
    async fn sender_lists_override_spam_placement() {
        let store = InMemoryStore::new();
        store
            .upsert_sender_list(&sender_entry("blocked", "blocked.example"))
            .await
            .unwrap();
        let mut blocked = msg("Blocked <alice@blocked.example>", "w33d@w33d.xyz", "hi");
        blocked.id = "m_blocked".to_string();
        blocked.raw_rfc822 =
            "Received-SPF: pass (corvid)\r\nAuthentication-Results: mx; dkim=pass\r\n\r\nbody"
                .to_string();
        process_inbound(&store, None, "w33d.xyz", "alice@blocked.example", blocked)
            .await
            .unwrap();
        assert_eq!(
            store
                .get_message("m_blocked")
                .await
                .unwrap()
                .unwrap()
                .folder,
            SPAM_FOLDER,
            "blocked sender hits Spam even when auth passed"
        );

        store
            .upsert_sender_list(&sender_entry("safe", "trusted.example"))
            .await
            .unwrap();
        let mut safe = msg("Bob <bob@trusted.example>", "w33d@w33d.xyz", "hi");
        safe.id = "m_safe".to_string();
        safe.folder = SPAM_FOLDER.to_string();
        safe.raw_rfc822 =
            "Received-SPF: fail (corvid)\r\nAuthentication-Results: mx; dkim=fail\r\n\r\nbody"
                .to_string();
        process_inbound(&store, None, "w33d.xyz", "bob@trusted.example", safe)
            .await
            .unwrap();
        assert_eq!(
            store.get_message("m_safe").await.unwrap().unwrap().folder,
            "INBOX",
            "safe sender never lands in Spam"
        );
    }

    #[tokio::test]
    async fn muted_thread_replies_archive_instead_of_inbox() {
        let store = InMemoryStore::new();
        let mut root = msg("Alice <alice@example.com>", "w33d@w33d.xyz", "Hello");
        root.id = "m_root".to_string();
        root.raw_rfc822 = "Message-ID: <root@example>\r\nFrom: alice@example.com\r\nTo: w33d@w33d.xyz\r\nSubject: Hello\r\n\r\nroot".to_string();
        process_inbound(&store, None, "w33d.xyz", "alice@example.com", root)
            .await
            .unwrap();
        let stored_root = store.get_message("m_root").await.unwrap().unwrap();
        store.set_thread_muted(&stored_root, true).await.unwrap();

        let mut reply = msg("Alice <alice@example.com>", "w33d@w33d.xyz", "Re: Hello");
        reply.id = "m_reply".to_string();
        reply.raw_rfc822 = "Message-ID: <reply@example>\r\nReferences: <root@example>\r\nIn-Reply-To: <root@example>\r\nFrom: alice@example.com\r\nTo: w33d@w33d.xyz\r\nSubject: Re: Hello\r\n\r\nreply".to_string();
        process_inbound(&store, None, "w33d.xyz", "alice@example.com", reply)
            .await
            .unwrap();

        let stored_reply = store.get_message("m_reply").await.unwrap().unwrap();
        assert_eq!(stored_reply.folder, "Archive");
        assert!(stored_reply.muted);
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
            assert!(
                !auto_reply_allowed(&raw, "a@b.com", "w33d@w33d.xyz"),
                "Precedence: {p}"
            );
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
        assert!(
            raw.contains("Subject: OutBcc: evil@x.com\r\n"),
            "CRLF stripped: {raw}"
        );
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
