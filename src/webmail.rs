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
use axum::{Form, Router};
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
const LOGOUT_URL: &str = "https://id.w33d.xyz/_gw/auth/logout";
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
        .with_state(state)
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
        .replace("{{LOGOUT}}", LOGOUT_URL)
        .replace("{{TITLE}}", &esc(title))
        .replace("{{EMAIL}}", email_display)
        .replace("{{CONTENT}}", content)
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
}
