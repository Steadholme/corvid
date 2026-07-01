//! Webmail (axum) — the v1 mail client, served at `mail.w33d.xyz` BEHIND the gateway SSO.
//!
//! It does NO login of its own: Sluice runs the OIDC browser login against Keystone, strips any
//! inbound `X-Auth-*`, and injects the verified `X-Auth-Subject` / `X-Auth-Email`. The webmail
//! TRUSTS those headers (it is internal-only) and selects the signed-in user's mailbox by
//! `owner_sub`. State-changing POSTs (`/send`) are CSRF-guarded (double-submit `__Host-csrf`).
//!
//! Views:
//! - `GET /healthz`  liveness (container HEALTHCHECK)
//! - `GET /`         inbox list (newest first: from / subject / date / seen)
//! - `GET /m/{id}`   read a message (rendered sanitised body), marks it seen
//! - `GET /compose`  compose form (mints a CSRF token)
//! - `POST /send`    build RFC822, DKIM-sign, enqueue + relay outbound

use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Form, Json, Router};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::Deserialize;
use time::OffsetDateTime;

use crate::model::Mailbox;
use crate::sanitize::esc_text;
use crate::util::{domain_of, email_date, message_id};
use crate::AppState;

const APP_CSS: &str = include_str!("../static/app.css");
const SHELL: &str = include_str!("../templates/shell.html");
const LOGOUT_URL: &str = "https://sso.w33d.xyz/_gw/auth/logout";
const CSRF_COOKIE: &str = "__Host-csrf";

const SHIELD_SVG: &str = r##"<svg viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg"><defs><linearGradient id="hf-shield-sm" x1="8" y1="4" x2="40" y2="44" gradientUnits="userSpaceOnUse"><stop stop-color="#818CF8"/><stop offset="1" stop-color="#4F46E5"/></linearGradient></defs><path d="M24 4 8 9.5V22c0 11 7 17.4 16 21.5C33 39.4 40 33 40 22V9.5L24 4Z" fill="url(#hf-shield-sm)"/><rect x="20" y="19" width="8" height="13" rx="1" fill="#fff" fill-opacity="0.92"/><path d="M20 19v-2.5a4 4 0 0 1 8 0V19" stroke="#fff" stroke-width="2" stroke-opacity="0.92" fill="none"/></svg>"##;

/// Build the webmail router.
pub fn app(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/", get(inbox))
        .route("/m/{id}", get(read_message))
        .route("/compose", get(compose_form))
        .route("/send", post(send))
        .route("/api/send", post(api_send))
        // Reject a forged gateway identity (spoofed X-Auth-* from a rogue in-network peer):
        // when GATEWAY_HMAC_KEY is set, an injected identity MUST carry a valid X-Auth-Sig.
        // No-op when the key is unset or no identity is present (healthz / local dev).
        .layer(axum::middleware::from_fn(require_gateway_sig))
        .with_state(state)
}

/// Middleware enforcing [`gateway_identity_ok`] — 401 on a missing/invalid signature.
async fn require_gateway_sig(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    if gateway_identity_ok(req.headers()) {
        next.run(req).await
    } else {
        (
            StatusCode::UNAUTHORIZED,
            "invalid or missing gateway identity signature",
        )
            .into_response()
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn healthz() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

async fn inbox(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let email = email_display(&headers);
    let Some(mb) = resolve_mailbox(&state, &headers).await else {
        return no_mailbox_page(&email);
    };

    let msgs = match state.store.list_messages(&mb.addr, 200).await {
        Ok(m) => m,
        Err(e) => return error_page(StatusCode::INTERNAL_SERVER_ERROR, "Storage error", &e.to_string()),
    };
    let unseen = state.store.unseen_count(&mb.addr).await.unwrap_or(0);

    let mut rows = String::new();
    if msgs.is_empty() {
        rows.push_str(r#"<li><div class="mailrow"><span class="subject muted">No messages yet.</span></div></li>"#);
    }
    for m in &msgs {
        let cls = if m.seen { "mailrow" } else { "mailrow unseen" };
        let dot = if m.seen { "dot seen" } else { "dot" };
        let subject = if m.subject.trim().is_empty() { "(no subject)".to_string() } else { esc(&m.subject) };
        rows.push_str(&format!(
            r#"<li><a class="{cls}" href="/m/{id}"><span class="{dot}"></span><span class="from">{from}</span><span class="subject">{subject}</span><span class="date">{date}</span></a></li>"#,
            id = esc(&m.id),
            from = esc(&display_from(&m.msg_from)),
            date = fmt_date(m.received_at),
        ));
    }

    let content = format!(
        r#"<div class="page-head"><h1>Inbox <span class="pill">{unseen} unread</span></h1><a class="btn btn-primary btn-sm" href="/compose">Compose</a></div>
<section class="card"><ul class="maillist">{rows}</ul></section>"#,
    );
    Html(render_page("Inbox", &email, &content)).into_response()
}

async fn read_message(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let email = email_display(&headers);
    let Some(mb) = resolve_mailbox(&state, &headers).await else {
        return no_mailbox_page(&email);
    };

    let msg = match state.store.get_message(&id).await {
        Ok(Some(m)) => m,
        Ok(None) => return error_page(StatusCode::NOT_FOUND, "Not found", "No such message."),
        Err(e) => return error_page(StatusCode::INTERNAL_SERVER_ERROR, "Storage error", &e.to_string()),
    };
    // Authorisation: a message is only viewable from its own mailbox.
    if msg.mailbox != mb.addr {
        return error_page(StatusCode::NOT_FOUND, "Not found", "No such message.");
    }
    let _ = state.store.mark_seen(&id).await;

    let body = if !msg.body_html.is_empty() {
        // Already sanitised at store time; re-sanitise defensively on render.
        format!(r#"<div class="msg-body">{}</div>"#, crate::sanitize::sanitize_html(&msg.body_html))
    } else {
        format!(r#"<div class="msg-body"><pre>{}</pre></div>"#, esc(&msg.body_text))
    };

    let subject = if msg.subject.trim().is_empty() { "(no subject)".to_string() } else { esc(&msg.subject) };
    let content = format!(
        r#"<nav class="crumbs"><a href="/">← Inbox</a></nav>
<section class="card pad">
  <header class="msg-head">
    <h1 class="msg-subject">{subject}</h1>
    <div class="msg-meta">
      <b>From</b><span>{from}</span>
      <b>To</b><span>{to}</span>
      <b>Date</b><span>{date}</span>
    </div>
  </header>
  {body}
</section>"#,
        from = esc(&msg.msg_from),
        to = esc(&msg.msg_to),
        date = fmt_date(msg.received_at),
    );
    Html(render_page(&msg.subject, &email, &content)).into_response()
}

async fn compose_form(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let email = email_display(&headers);
    let from = match resolve_mailbox(&state, &headers).await {
        Some(mb) => mb.addr,
        None => return no_mailbox_page(&email),
    };
    let (token, set_cookie) = ensure_csrf(&headers);

    let content = format!(
        r#"<nav class="crumbs"><a href="/">← Inbox</a></nav>
<section class="card pad">
  <div class="page-head"><h1>New message</h1></div>
  <form method="post" action="/send">
    <input type="hidden" name="csrf" value="{token}">
    <div class="field"><label>From</label><input value="{from}" disabled></div>
    <div class="field"><label for="to">To</label><input id="to" name="to" placeholder="someone@example.com" required></div>
    <div class="field"><label for="subject">Subject</label><input id="subject" name="subject" placeholder="Subject"></div>
    <div class="field"><label for="body">Message</label><textarea id="body" name="body"></textarea></div>
    <div class="form-actions"><button class="btn btn-primary" type="submit">Send</button><a class="btn btn-ghost btn-sm" href="/">Cancel</a></div>
  </form>
</section>"#,
        from = esc(&from),
    );
    let html = render_page("Compose", &email, &content);
    match set_cookie {
        Some(c) => ([(header::SET_COOKIE, c)], Html(html)).into_response(),
        None => Html(html).into_response(),
    }
}

#[derive(Deserialize)]
struct SendForm {
    csrf: String,
    to: String,
    #[serde(default)]
    subject: String,
    #[serde(default)]
    body: String,
}

async fn send(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<SendForm>,
) -> Response {
    let email = email_display(&headers);
    if !verify_csrf(&headers, &form.csrf) {
        return error_page(StatusCode::FORBIDDEN, "Request blocked", "CSRF token missing or mismatched.");
    }
    let Some(mb) = resolve_mailbox(&state, &headers).await else {
        return no_mailbox_page(&email);
    };

    let rcpts: Vec<String> = form
        .to
        .split([',', ';'])
        .map(str::trim)
        .filter(|s| s.contains('@') && domain_of(s).is_some())
        .map(str::to_string)
        .collect();
    if rcpts.is_empty() {
        return error_page(StatusCode::BAD_REQUEST, "Invalid request", "At least one valid recipient is required.");
    }

    let raw = build_rfc822(&mb.addr, &form.to, &form.subject, &form.body, &state.config.mail_domain);
    let signer = state.signer.as_deref();
    match crate::relay::enqueue_outbound(state.store.as_ref(), signer, &raw, &mb.addr, &rcpts).await {
        Ok(_) => Redirect::to("/?sent=1").into_response(),
        Err(e) => error_page(StatusCode::INTERNAL_SERVER_ERROR, "Send failed", &e),
    }
}

// ---------------------------------------------------------------------------
// Internal service send API (token-guarded, NOT behind Sluice SSO/CSRF)
// ---------------------------------------------------------------------------

/// JSON body for `POST /api/send`.
#[derive(Deserialize)]
struct ApiSend {
    from: String,
    to: String,
    #[serde(default)]
    subject: String,
    #[serde(default)]
    body: String,
}

/// Token-guarded transactional send for estate services (e.g. Keystone).
///
/// Guarded by a `Bearer` service token from `MAIL_SEND_TOKEN` (constant-time compare; `503` when
/// unset). The `from` address MUST be `@<mail_domain>` (so the message inherits DKIM signing via
/// the SAME [`relay::enqueue_outbound`] path the webmail compose uses); off-domain senders would
/// relay unsigned and are rejected with `400`. Returns `202` on enqueue.
async fn api_send(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<ApiSend>,
) -> Response {
    // Guard: token configured, and a matching Bearer presented (constant-time).
    let expected = state.config.mail_send_token.as_str();
    if expected.is_empty() {
        return json_status(StatusCode::SERVICE_UNAVAILABLE, "send API disabled (MAIL_SEND_TOKEN unset)");
    }
    let presented = bearer_token(&headers).unwrap_or_default();
    if !ct_eq(presented.as_bytes(), expected.as_bytes()) {
        return json_status(StatusCode::UNAUTHORIZED, "invalid or missing bearer token");
    }

    // From must be a bare/angle address at the signing domain, else it would relay unsigned.
    let from_addr = extract_addr(&req.from);
    if domain_of(&from_addr).as_deref() != Some(state.config.mail_domain.to_lowercase().as_str()) {
        return json_status(
            StatusCode::BAD_REQUEST,
            "from must be an address at the mail domain (else the message would relay unsigned)",
        );
    }

    let rcpts: Vec<String> = req
        .to
        .split([',', ';'])
        .map(str::trim)
        .filter(|s| s.contains('@') && domain_of(s).is_some())
        .map(str::to_string)
        .collect();
    if rcpts.is_empty() {
        return json_status(StatusCode::BAD_REQUEST, "at least one valid recipient is required");
    }

    let raw = build_rfc822(&from_addr, &req.to, &req.subject, &req.body, &state.config.mail_domain);
    let signer = state.signer.as_deref();
    match crate::relay::enqueue_outbound(state.store.as_ref(), signer, &raw, &from_addr, &rcpts).await {
        Ok(_) => json_status(StatusCode::ACCEPTED, "queued"),
        Err(e) => json_status(StatusCode::INTERNAL_SERVER_ERROR, &format!("enqueue failed: {e}")),
    }
}

/// Extract the `Authorization: Bearer <token>` value, if present.
fn bearer_token(headers: &HeaderMap) -> Option<String> {
    let raw = header_value(headers, "authorization")?;
    let token = raw.strip_prefix("Bearer ").or_else(|| raw.strip_prefix("bearer "))?;
    let token = token.trim();
    (!token.is_empty()).then(|| token.to_string())
}

/// Extract a bare address from a possibly `Name <addr>` string (lowercased trim left to callers).
fn extract_addr(s: &str) -> String {
    let s = s.trim();
    if let Some(lt) = s.find('<') {
        if let Some(gt) = s[lt..].find('>') {
            return s[lt + 1..lt + gt].trim().to_string();
        }
    }
    s.to_string()
}

/// A small JSON `{status, message}` response with the given HTTP status.
fn json_status(status: StatusCode, message: &str) -> Response {
    let body = serde_json::json!({ "status": status.as_u16(), "message": message });
    (status, Json(body)).into_response()
}

/// Build an RFC822 message for an outbound compose.
fn build_rfc822(from: &str, to: &str, subject: &str, body: &str, domain: &str) -> String {
    let body_norm = body.replace("\r\n", "\n").replace('\n', "\r\n");
    format!(
        "From: {from}\r\nTo: {to}\r\nSubject: {subject}\r\nDate: {date}\r\nMessage-ID: {mid}\r\n\
         MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\
         Content-Transfer-Encoding: 8bit\r\n\r\n{body_norm}\r\n",
        date = email_date(),
        mid = message_id(domain),
    )
}

// ---------------------------------------------------------------------------
// Identity + CSRF + mailbox resolution
// ---------------------------------------------------------------------------

fn header_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// The signed-in user's subject (gateway `X-Auth-Subject`).
fn identity_subject(headers: &HeaderMap) -> Option<String> {
    header_value(headers, "x-auth-subject")
}

/// The signed-in user's email (gateway `X-Auth-Email`).
fn identity_email(headers: &HeaderMap) -> Option<String> {
    header_value(headers, "x-auth-email")
}

/// Resolve the mailbox for the signed-in user: by `owner_sub`, else (defence in depth) by an
/// email whose local-part owns a mailbox.
async fn resolve_mailbox(state: &AppState, headers: &HeaderMap) -> Option<Mailbox> {
    if let Some(sub) = identity_subject(headers) {
        if let Ok(Some(mb)) = state.store.mailbox_for_owner(&sub).await {
            return Some(mb);
        }
    }
    // Fallback: an injected email that matches a mailbox address directly.
    if let Some(em) = identity_email(headers) {
        if let Ok(Some(mb)) = state.store.get_mailbox(&em).await {
            return Some(mb);
        }
    }
    None
}

fn get_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    for hv in headers.get_all(header::COOKIE).iter() {
        let Ok(raw) = hv.to_str() else { continue };
        for pair in raw.split(';') {
            if let Some((k, v)) = pair.trim().split_once('=') {
                if k.trim() == name {
                    return Some(v.trim().to_string());
                }
            }
        }
    }
    None
}

fn new_csrf_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Reuse an existing `__Host-csrf` token, else mint one. Returns `(token, set_cookie?)`.
fn ensure_csrf(headers: &HeaderMap) -> (String, Option<String>) {
    match get_cookie(headers, CSRF_COOKIE) {
        Some(t) if !t.is_empty() => (t, None),
        _ => {
            let token = new_csrf_token();
            let cookie = format!("{CSRF_COOKIE}={token}; Path=/; Secure; SameSite=Lax; Max-Age=3600");
            (token, Some(cookie))
        }
    }
}

/// Double-submit check: the submitted token must equal the `__Host-csrf` cookie (constant time).
fn verify_csrf(headers: &HeaderMap, submitted: &str) -> bool {
    match get_cookie(headers, CSRF_COOKIE) {
        Some(c) if !c.is_empty() => ct_eq(c.as_bytes(), submitted.as_bytes()),
        _ => false,
    }
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
}

// ---------------------------------------------------------------------------
// Gateway identity signature (X-Auth-Sig) verification
// ---------------------------------------------------------------------------

use std::sync::OnceLock;

pub const HEADER_SUBJECT: &str = "x-auth-subject";
pub const HEADER_GROUPS: &str = "x-auth-groups";
/// HMAC binding the injected identity to a 1-minute window (set by Sluice when GATEWAY_HMAC_KEY
/// is configured). See [`gateway_identity_ok`].
pub const HEADER_SIG: &str = "x-auth-sig";

/// The shared gateway HMAC key, read once from `GATEWAY_HMAC_KEY`. Empty (unset) disables
/// verification — the pre-signature behavior, fully backward compatible.
fn gateway_key() -> &'static str {
    static KEY: OnceLock<String> = OnceLock::new();
    KEY.get_or_init(|| std::env::var("GATEWAY_HMAC_KEY").unwrap_or_default())
        .as_str()
}

/// Verify the gateway-injected identity is authentic. When `GATEWAY_HMAC_KEY` is set AND an
/// identity (`X-Auth-Subject`) is present, a valid `X-Auth-Sig` — HMAC-SHA256 over
/// `subject "\n" groups "\n" minute` for the current OR previous minute — is REQUIRED; a rogue
/// peer that POSTs `X-Auth-Subject` directly (bypassing Sluice) cannot forge it. Returns:
/// - `true` when the key is unset (verification off), or no identity header is present
///   (healthz/dev path), or the signature is valid;
/// - `false` when an identity is present but the signature is missing or invalid (=> 401).
pub fn gateway_identity_ok(headers: &HeaderMap) -> bool {
    let key = gateway_key();
    if key.is_empty() {
        return true;
    }
    let Some(subject) = identity_subject(headers) else {
        return true; // no injected identity to verify (healthz / local dev)
    };
    let groups = header_value(headers, HEADER_GROUPS).unwrap_or_default();
    let Some(sig) = header_value(headers, HEADER_SIG) else {
        return false; // identity present but unsigned — reject
    };
    let win = now_unix() / 60;
    // Accept the current and previous minute (clock skew + minute-boundary tolerance).
    [win, win - 1]
        .iter()
        .any(|&w| ct_eq(sig.as_bytes(), sign_identity(key, &subject, &groups, w).as_bytes()))
}

/// Recompute the gateway signature — byte-identical to Sluice's `auth.SignIdentity` (Go).
fn sign_identity(key: &str, subject: &str, groups: &str, window: i64) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes()).expect("HMAC accepts any key len");
    mac.update(subject.as_bytes());
    mac.update(b"\n");
    mac.update(groups.as_bytes());
    mac.update(b"\n");
    mac.update(window.to_string().as_bytes());
    to_hex(&mac.finalize().into_bytes())
}

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn now_unix() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Render helpers
// ---------------------------------------------------------------------------

/// Minimal HTML escaping for text/attribute interpolation.
pub fn esc(s: &str) -> String {
    esc_text(s)
}

fn render_page(title: &str, email_display: &str, content: &str) -> String {
    SHELL
        .replace("{{STYLE}}", APP_CSS)
        .replace("{{SHIELD}}", SHIELD_SVG)
        .replace("{{TITLE}}", &esc(title))
        .replace("{{USERBOX}}", &userbox(email_display))
        .replace("{{CONTENT}}", content)
}

/// The right side of the app-bar: an "All apps" pill back to the apex portal, a user chip
/// (avatar initial + signed-in email) when a gateway identity is known, and the cross-subdomain
/// logout. `email_display` is the already-escaped display string from [`email_display`]; the
/// `—` sentinel (no gateway session) renders the chrome without a user chip.
fn userbox(email_display: &str) -> String {
    let has_email = !email_display.is_empty() && !email_display.starts_with('—');
    let chip = if has_email {
        let initial = email_display
            .chars()
            .next()
            .map(|c| c.to_uppercase().to_string())
            .unwrap_or_else(|| "H".to_string());
        format!(
            "<span class=\"userchip\"><span class=\"userchip__avatar\" aria-hidden=\"true\">{}</span><span class=\"user-email\" title=\"Signed in as\">{}</span></span>",
            esc(&initial),
            email_display,
        )
    } else {
        String::new()
    };
    format!(
        concat!(
            "<a class=\"allapps\" href=\"https://w33d.xyz\" title=\"All apps\">",
            "<svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" aria-hidden=\"true\">",
            "<rect x=\"3\" y=\"3\" width=\"7\" height=\"7\" rx=\"1.5\"/><rect x=\"14\" y=\"3\" width=\"7\" height=\"7\" rx=\"1.5\"/>",
            "<rect x=\"3\" y=\"14\" width=\"7\" height=\"7\" rx=\"1.5\"/><rect x=\"14\" y=\"14\" width=\"7\" height=\"7\" rx=\"1.5\"/></svg>All apps</a>",
            "{chip}",
            "<a class=\"btn btn-ghost btn-sm\" href=\"{logout}\">Log out</a>",
        ),
        chip = chip,
        logout = LOGOUT_URL,
    )
}

fn email_display(headers: &HeaderMap) -> String {
    match identity_email(headers) {
        Some(e) => esc(&e),
        None => "— (no gateway session)".to_string(),
    }
}

fn no_mailbox_page(email: &str) -> Response {
    let content = r#"<section class="card empty-card"><h1 class="empty-title">No mailbox provisioned</h1><p class="muted">Your HOLDFAST identity has no Corvid mailbox yet. Ask an administrator to provision one.</p></section>"#;
    Html(render_page("No mailbox", email, content)).into_response()
}

fn error_page(status: StatusCode, heading: &str, message: &str) -> Response {
    let content = format!(
        r#"<section class="card empty-card"><h1 class="empty-title">{}</h1><p class="muted">{}</p><p><a class="btn btn-primary btn-sm" href="/">Back to inbox</a></p></section>"#,
        esc(heading),
        esc(message),
    );
    (status, Html(render_page(heading, "—", &content))).into_response()
}

/// `From:` display: prefer the display-name, else the bare address.
fn display_from(from: &str) -> String {
    let from = from.trim();
    if let Some(lt) = from.find('<') {
        let name = from[..lt].trim().trim_matches('"').trim();
        if !name.is_empty() {
            return name.to_string();
        }
        if let Some(gt) = from[lt..].find('>') {
            return from[lt + 1..lt + gt].to_string();
        }
    }
    from.to_string()
}

/// Format an epoch-seconds timestamp as `YYYY-MM-DD HH:MM` (UTC).
fn fmt_date(ts: i64) -> String {
    match OffsetDateTime::from_unix_timestamp(ts) {
        Ok(dt) => format!(
            "{:04}-{:02}-{:02} {:02}:{:02}",
            dt.year(),
            dt.month() as u8,
            dt.day(),
            dt.hour(),
            dt.minute()
        ),
        Err(_) => "—".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn sign_identity_matches_go_vector() {
        // MUST equal sluice/internal/auth/sig_test.go — the cross-language contract.
        assert_eq!(
            sign_identity("test-key", "usr_alice", "admins,devs", 1),
            "ddc77236dcfb03dd9f462f7c84e1b25e58f5fc380997695a689e6c3ac4bb3777"
        );
        assert_eq!(
            sign_identity("test-key", "usr_bob", "", 2),
            "930f82fb1224e69c9c5bc46e545c3b108b1eeb6c9078c7a33fc24f30c595f658"
        );
    }

    #[test]
    fn gateway_ok_when_key_unset() {
        // No GATEWAY_HMAC_KEY in the test env => verification disabled => always ok.
        let mut h = HeaderMap::new();
        h.insert(HEADER_SUBJECT, HeaderValue::from_static("user-42"));
        assert!(gateway_identity_ok(&h));
    }

    #[test]
    fn display_from_prefers_name() {
        assert_eq!(display_from("Alice <a@b.com>"), "Alice");
        assert_eq!(display_from("<a@b.com>"), "a@b.com");
        assert_eq!(display_from("bare@x.com"), "bare@x.com");
    }

    #[test]
    fn build_rfc822_has_signed_headers() {
        let raw = build_rfc822("w33d@w33d.xyz", "x@y.com", "Hi", "Body line", "w33d.xyz");
        for h in ["From:", "To:", "Subject:", "Date:", "Message-ID:", "MIME-Version:", "Content-Type:"] {
            assert!(raw.contains(h), "missing {h}");
        }
        assert!(raw.contains("\r\n\r\nBody line\r\n"));
    }

    #[test]
    fn extract_addr_handles_angle_and_bare() {
        assert_eq!(extract_addr("no-reply@w33d.xyz"), "no-reply@w33d.xyz");
        assert_eq!(extract_addr("HOLDFAST <no-reply@w33d.xyz>"), "no-reply@w33d.xyz");
        assert_eq!(extract_addr("  bare@x.com  "), "bare@x.com");
    }

    #[test]
    fn bearer_token_parses_scheme() {
        let mut h = HeaderMap::new();
        h.insert("authorization", "Bearer s3cret".parse().unwrap());
        assert_eq!(bearer_token(&h).as_deref(), Some("s3cret"));
        let mut h2 = HeaderMap::new();
        h2.insert("authorization", "Basic abc".parse().unwrap());
        assert_eq!(bearer_token(&h2), None);
        assert_eq!(bearer_token(&HeaderMap::new()), None);
    }
}
