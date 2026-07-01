//! Webmail (axum) — the v1 mail client, served at `mail.w33d.xyz` BEHIND the gateway SSO.
//!
//! It does NO login of its own: Sluice runs the OIDC browser login against Keystone, strips any
//! inbound `X-Auth-*`, and injects the verified `X-Auth-Subject` / `X-Auth-Email`. The webmail
//! TRUSTS those headers (it is internal-only) and selects the signed-in user's mailbox by
//! `owner_sub`. State-changing POSTs (`/send`) are CSRF-guarded (double-submit `__Host-csrf`).
//!
//! Views:
//! - `GET /healthz`  liveness (container HEALTHCHECK)
//! - `GET /`         folder list (`?folder=INBOX|Sent|Drafts`, newest first: from / subject / date)
//!                   or `?q=` full-text search (subject/from/to/body, optional `?folder=` scope);
//!                   both keyset-paginated via `?before=<received_at>_<id>` + `?limit=` (≤200)
//! - `GET /m/{id}`   read a message (rendered sanitised body), marks it seen; reply/forward actions
//! - `GET /compose`  compose form (mints a CSRF token); `?reply|replyall|forward=<id>` prefills it
//! - `POST /send`    `action=send`: build RFC822, DKIM-sign, enqueue + relay + file a Sent copy;
//!                   `action=draft`: persist into the Drafts folder without sending

use axum::extract::{FromRequest, Multipart, Path, Query, Request, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Form, Json, Router};

use crate::rfc822::Attachment;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::Deserialize;
use time::OffsetDateTime;

use crate::model::{Alias, Mailbox, Message};
use crate::sanitize::esc_text;
use crate::util::{domain_of, email_date, message_id, new_id, now_secs};
use crate::AppState;

/// The real (column-backed) folders the webmail surfaces: INBOX for received mail, the two
/// locally-authored ones, plus Archive/Trash that message actions move mail into. These are the
/// legal targets for a move and the values stored in `Message.folder`.
const FOLDERS: [&str; 5] = ["INBOX", "Sent", "Drafts", "Archive", "Trash"];

/// A virtual, cross-folder view of the starred/flagged messages. Selected via `?folder=Starred`
/// but never stored in `Message.folder`.
const STARRED_VIEW: &str = "Starred";

/// Default rows per folder/search page when `?limit=` is absent.
const PAGE_DEFAULT: i64 = 50;

/// Hard ceiling for `?limit=` — one listing page never exceeds this many rows. Older mail stays
/// reachable through the keyset `?before=` cursor instead of a bigger page.
const PAGE_MAX: i64 = 200;

const APP_CSS: &str = include_str!("../static/app.css");
const SHELL: &str = include_str!("../templates/shell.html");
const LOGOUT_URL: &str = "https://sso.w33d.xyz/_gw/auth/logout";
const CSRF_COOKIE: &str = "__Host-csrf";

// Lucide-style line icons (viewBox 0 0 24 24, currentColor, 2px rounded strokes) for the
// Odyssey v2 app-bar nav + user menu. The app-tile (envelope) icon lives in templates/shell.html.
const ICO_INBOX: &str = r#"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M22 12h-6l-2 3h-4l-2-3H2"/><path d="M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z"/></svg>"#;
const ICO_COMPOSE: &str = r#"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3H5a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4Z"/></svg>"#;
const ICO_GRID: &str = r#"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/></svg>"#;
const ICO_CARET: &str = r#"<svg class="usermenu__caret" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m6 9 6 6 6-6"/></svg>"#;
const ICO_USER: &str = r#"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M19 21v-2a4 4 0 0 0-4-4H9a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>"#;
const ICO_LOGOUT: &str = r#"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" x2="9" y1="12" y2="12"/></svg>"#;

/// Build the webmail router.
pub fn app(state: AppState) -> Router {
    // The /admin subtree (mailbox provisioning) is gated by `require_admin`: only users in an
    // ADMIN_GROUPS group see it; every other signed-in user gets a 403. The gate is a
    // `route_layer` so it applies uniformly to ALL admin routes.
    let admin = Router::new()
        .route("/admin", get(admin_index))
        .route("/admin/mailboxes", post(admin_create_mailbox))
        .route("/admin/aliases", post(admin_add_alias))
        .route_layer(axum::middleware::from_fn(require_admin_mw));

    Router::new()
        .route("/healthz", get(healthz))
        .route("/", get(inbox))
        .route("/m/{id}", get(read_message))
        .route("/m/{id}/action", post(message_action))
        .route("/m/{id}/attachments/{idx}", get(download_attachment))
        .route("/compose", get(compose_form))
        .route("/send", post(send))
        .route("/api/send", post(api_send))
        .merge(admin)
        // Reject a forged gateway identity (spoofed X-Auth-* from a rogue in-network peer):
        // when GATEWAY_HMAC_KEY is set, an injected identity MUST carry a valid X-Auth-Sig.
        // No-op when the key is unset or no identity is present (healthz / local dev).
        .layer(axum::middleware::from_fn(require_gateway_sig))
        .with_state(state)
}

/// Middleware enforcing [`require_admin`] on the /admin subtree — renders a 403 page for any
/// signed-in user who is not in an [`ADMIN_GROUPS`] group.
async fn require_admin_mw(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    match require_admin(req.headers()) {
        Ok(()) => next.run(req).await,
        Err(resp) => resp,
    }
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

/// Query string for the inbox: an optional `?folder=` selecting which folder/view to list (or
/// scoping a search), an optional `?q=` full-text search, a `?before=` keyset cursor
/// (`<received_at>_<id>`) paging any listing oldward, and a `?limit=` page size (clamped to
/// [`PAGE_MAX`], default [`PAGE_DEFAULT`]).
#[derive(Deserialize, Default)]
struct InboxQuery {
    #[serde(default)]
    folder: Option<String>,
    #[serde(default)]
    q: Option<String>,
    #[serde(default)]
    before: Option<String>,
    #[serde(default)]
    limit: Option<i64>,
}

async fn inbox(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<InboxQuery>,
) -> Response {
    let email = email_display(&headers);
    let Some(mb) = resolve_mailbox(&state, &headers).await else {
        return no_mailbox_page(&email);
    };
    // Row action forms POST back a double-submit CSRF token; the inbox mints it (like compose).
    let (token, set_cookie) = ensure_csrf(&headers);

    let search = q.q.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let limit = clamp_limit(q.limit);
    let cursor = parse_cursor(q.before.as_deref());

    // Fetch the rows for the active view, plus the return path row actions redirect back to, a
    // `next` keyset link to the older page (only when this page is full), and the folder the
    // search box scopes to.
    let (folder, heading, msgs, next_link, scope) = if let Some(query) = search {
        // Optional folder scope: only a real folder narrows the search; anything else (absent,
        // unknown, the virtual Starred view) searches the whole mailbox.
        let scope = q.folder.as_deref().and_then(real_folder);
        let msgs = match state.store.search_messages(&mb.addr, query, scope, cursor, limit).await {
            Ok(m) => m,
            Err(e) => return error_page(StatusCode::INTERNAL_SERVER_ERROR, "Storage error", &e.to_string()),
        };
        let mut base = format!("/?q={}&limit={limit}", url_encode(query));
        if let Some(f) = scope {
            base.push_str(&format!("&folder={f}"));
        }
        let heading = match scope {
            Some(f) => format!(r#"Search results for &ldquo;{}&rdquo; in {}"#, esc(query), esc(f)),
            None => format!(r#"Search results for &ldquo;{}&rdquo;"#, esc(query)),
        };
        let next = next_page_link(&msgs, limit, &base);
        // A search hit's return path can't carry the query cheaply — send actions back to the inbox.
        ("", heading, msgs, next, scope)
    } else {
        let folder = canonical_folder(q.folder.as_deref());
        let listed = if folder == STARRED_VIEW {
            state.store.list_starred(&mb.addr, cursor, limit).await
        } else {
            state.store.list_folder(&mb.addr, folder, cursor, limit).await
        };
        let msgs = match listed {
            Ok(m) => m,
            Err(e) => return error_page(StatusCode::INTERNAL_SERVER_ERROR, "Storage error", &e.to_string()),
        };
        let heading = if folder == "INBOX" {
            let unseen = state.store.unseen_count(&mb.addr).await.unwrap_or(0);
            format!("Inbox <span class=\"pill\">{unseen} unread</span>")
        } else {
            esc(folder)
        };
        let next = next_page_link(&msgs, limit, &format!("/?folder={folder}&limit={limit}"));
        // Searching from a folder view scopes to it; the Inbox (and Starred) search everything.
        let scope = real_folder(folder).filter(|f| *f != "INBOX");
        (folder, heading, msgs, next, scope)
    };

    // Row actions redirect back to the folder/view they were invoked from (search → inbox).
    let return_to = if folder.is_empty() { "/".to_string() } else { format!("/?folder={folder}") };

    let mut rows = String::new();
    if msgs.is_empty() {
        rows.push_str(r#"<li><div class="mailrow"><span class="subject muted">No messages here.</span></div></li>"#);
    }
    for m in &msgs {
        rows.push_str(&render_row(m, &token, &return_to));
    }

    let content = format!(
        r#"<div class="page-head"><h1>{heading}</h1><a class="btn btn-primary btn-sm" href="/compose">Compose</a></div>
{tabs}
<section class="card"><ul class="maillist">{rows}</ul></section>{next_link}"#,
        tabs = folder_tabs(folder, search.unwrap_or(""), scope),
    );
    let title = if folder.is_empty() { "Search" } else { folder };
    let html = render_page(title, &email, &content, "inbox");
    match set_cookie {
        Some(c) => ([(header::SET_COOKIE, c)], Html(html)).into_response(),
        None => Html(html).into_response(),
    }
}

/// Render one inbox/search row: the message link plus a per-row action form (star, mark-unread,
/// archive, delete, move-to-folder). `token` is the CSRF token; `return_to` is where each action
/// redirects back to.
fn render_row(m: &crate::model::MessageSummary, token: &str, return_to: &str) -> String {
    let cls = if m.seen { "mailrow" } else { "mailrow unseen" };
    let dot = if m.seen { "dot seen" } else { "dot" };
    let subject = if m.subject.trim().is_empty() { "(no subject)".to_string() } else { esc(&m.subject) };
    let star = star_mark(m.starred);
    format!(
        r#"<li class="mailrow-wrap"><a class="{cls}" href="/m/{id}"><span class="{dot}"></span><span class="from">{from}</span><span class="subject">{star}{subject}</span><span class="date">{date}</span></a>{actions}</li>"#,
        id = esc(&m.id),
        from = esc(&display_from(&m.msg_from)),
        date = fmt_date(m.received_at),
        actions = row_actions(&m.id, m.starred, token, return_to),
    )
}

/// A leading star glyph for a row's subject (filled when starred, nothing otherwise).
fn star_mark(starred: bool) -> &'static str {
    if starred { r#"<span class="star on" aria-label="starred">★</span> "# } else { "" }
}

/// The per-message action form (shared by inbox rows and the read view). Double-submit CSRF; every
/// button submits the same form with a distinct `op`.
fn row_actions(id: &str, starred: bool, token: &str, return_to: &str) -> String {
    let (star_op, star_label, star_glyph) = if starred {
        ("unstar", "Unstar", "★")
    } else {
        ("star", "Star", "☆")
    };
    let mut opts = String::new();
    for f in FOLDERS {
        opts.push_str(&format!(r#"<option value="{f}">{f}</option>"#));
    }
    format!(
        r#"<form class="row-actions" method="post" action="/m/{id}/action">
  <input type="hidden" name="csrf" value="{token}">
  <input type="hidden" name="return" value="{ret}">
  <button class="btn btn-ghost btn-sm" type="submit" name="op" value="{star_op}" title="{star_label}">{star_glyph}</button>
  <button class="btn btn-ghost btn-sm" type="submit" name="op" value="unread" title="Mark unread">Unread</button>
  <button class="btn btn-ghost btn-sm" type="submit" name="op" value="archive" title="Archive">Archive</button>
  <button class="btn btn-ghost btn-sm" type="submit" name="op" value="delete" title="Move to Trash">Delete</button>
  <select class="move-select" name="folder" aria-label="Move to folder"><option value="" selected disabled>Move…</option>{opts}</select>
  <button class="btn btn-ghost btn-sm" type="submit" name="op" value="move">Move</button>
</form>"#,
        id = esc(id),
        token = esc(token),
        ret = esc(return_to),
    )
}

/// Parse a `?before=<received_at>_<id>` keyset cursor into `(received_at, id)`. Returns `None`
/// (first page) for a missing or malformed cursor.
fn parse_cursor(raw: Option<&str>) -> Option<(i64, String)> {
    let raw = raw?.trim();
    let (ts, id) = raw.split_once('_')?;
    let ts: i64 = ts.parse().ok()?;
    Some((ts, id.to_string()))
}

/// Clamp a requested `?limit=` page size to `1..=`[`PAGE_MAX`] (default [`PAGE_DEFAULT`]).
fn clamp_limit(requested: Option<i64>) -> i64 {
    requested.unwrap_or(PAGE_DEFAULT).clamp(1, PAGE_MAX)
}

/// The "Load older" keyset link under a listing: rendered only when the page is FULL (`limit`
/// rows), extending `base` (an href already carrying `q`/`folder`/`limit`) with the
/// `(received_at, id)` cursor of the last row. A short page means nothing older exists.
fn next_page_link(msgs: &[crate::model::MessageSummary], limit: i64, base: &str) -> String {
    let Some(last) = msgs.last().filter(|_| msgs.len() as i64 >= limit) else {
        return String::new();
    };
    format!(
        r#"<div class="page-more"><a class="btn btn-ghost btn-sm" href="{base}&before={cursor}">Load older</a></div>"#,
        cursor = url_encode(&format!("{}_{}", last.received_at, last.id)),
    )
}

/// Minimal percent-encoding for a query-string value (keeps unreserved chars, encodes the rest).
fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Clamp an arbitrary `?folder=` to a known [`FOLDERS`] value or the [`STARRED_VIEW`] (defaults to
/// `INBOX`).
fn canonical_folder(requested: Option<&str>) -> &'static str {
    match requested.map(str::trim) {
        Some(f) if f.eq_ignore_ascii_case(STARRED_VIEW) => STARRED_VIEW,
        Some(f) => FOLDERS.into_iter().find(|c| c.eq_ignore_ascii_case(f)).unwrap_or("INBOX"),
        None => "INBOX",
    }
}

/// Render the folder switcher as a row of pill links (INBOX/Sent/Drafts/Archive/Trash/Starred),
/// highlighting the active folder, followed by the `?q=` search box. `scope` is the folder the
/// search box narrows to (carried as a hidden `folder` field); `None` searches the whole mailbox.
fn folder_tabs(active: &str, search_q: &str, scope: Option<&str>) -> String {
    let mut out = String::from(r#"<nav class="folder-tabs">"#);
    for f in FOLDERS.iter().copied().chain(std::iter::once(STARRED_VIEW)) {
        let cls = if f == active { "btn btn-primary btn-sm" } else { "btn btn-ghost btn-sm" };
        let label = if f == "INBOX" { "Inbox" } else { f };
        out.push_str(&format!(r#"<a class="{cls}" href="/?folder={f}">{label}</a>"#));
    }
    let scope_input = scope
        .map(|f| format!(r#"<input type="hidden" name="folder" value="{}">"#, esc(f)))
        .unwrap_or_default();
    out.push_str(&format!(
        r#"<form class="search-box" method="get" action="/">{scope_input}<input type="search" name="q" value="{q}" placeholder="Search mail"><button class="btn btn-ghost btn-sm" type="submit">Search</button></form>"#,
        q = esc(search_q),
    ));
    out.push_str("</nav>");
    out
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
    // Mint/reuse a CSRF token for the read-view action buttons (star/archive/delete/move/unread).
    let (token, set_cookie) = ensure_csrf(&headers);

    let body = if !msg.body_html.is_empty() {
        // Already sanitised at store time; re-sanitise defensively on render.
        format!(r#"<div class="msg-body">{}</div>"#, crate::sanitize::sanitize_html(&msg.body_html))
    } else {
        format!(r#"<div class="msg-body"><pre>{}</pre></div>"#, esc(&msg.body_text))
    };

    // Enumerate the stored raw source's MIME parts and offer a download link per attachment.
    let attachments = render_attachment_list(&msg);

    let subject = if msg.subject.trim().is_empty() { "(no subject)".to_string() } else { esc(&msg.subject) };
    let content = format!(
        r#"<nav class="crumbs"><a href="/?folder={folder}">← {folder_label}</a></nav>
<section class="card pad">
  <header class="msg-head">
    <h1 class="msg-subject">{subject}</h1>
    <div class="msg-meta">
      <b>From</b><span>{from}</span>
      <b>To</b><span>{to}</span>
      <b>Date</b><span>{date}</span>
    </div>
    <div class="form-actions msg-actions">
      <a class="btn btn-primary btn-sm" href="/compose?reply={id}">Reply</a>
      <a class="btn btn-ghost btn-sm" href="/compose?replyall={id}">Reply all</a>
      <a class="btn btn-ghost btn-sm" href="/compose?forward={id}">Forward</a>
    </div>
    {actions}
  </header>
  {attachments}
  {body}
</section>"#,
        from = esc(&msg.msg_from),
        to = esc(&msg.msg_to),
        date = fmt_date(msg.received_at),
        folder = esc(&msg.folder),
        folder_label = if msg.folder == "INBOX" { "Inbox".to_string() } else { esc(&msg.folder) },
        id = esc(&msg.id),
        // Read-view actions return to the message so a star/unread toggle stays in context.
        actions = row_actions(&msg.id, msg.starred, &token, &format!("/m/{}", esc(&msg.id))),
    );
    let html = render_page(&msg.subject, &email, &content, "inbox");
    match set_cookie {
        Some(c) => ([(header::SET_COOKIE, c)], Html(html)).into_response(),
        None => Html(html).into_response(),
    }
}

/// Form body for `POST /m/{id}/action`: a double-submit CSRF token, the operation `op`
/// (`star|unstar|read|unread|archive|delete|move`), a target `folder` (only for `op=move`), and a
/// safe local `return` path to redirect back to.
#[derive(Deserialize, Default)]
struct ActionForm {
    csrf: String,
    #[serde(default)]
    op: String,
    #[serde(default)]
    folder: String,
    #[serde(default, rename = "return")]
    return_to: String,
}

/// `POST /m/{id}/action` — a per-message control invoked from an inbox row or the read view. CSRF
/// double-submit guarded; enforces the SAME mailbox authorisation as the read view (a message is
/// only actionable from its own mailbox). On success mutates via the [`crate::store::Store`], emits
/// a tracing audit line, and redirects to the (validated-local) `return` path.
async fn message_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(form): Form<ActionForm>,
) -> Response {
    if !verify_csrf(&headers, &form.csrf) {
        return error_page(StatusCode::FORBIDDEN, "Request blocked", "CSRF token missing or mismatched.");
    }
    let Some(mb) = resolve_mailbox(&state, &headers).await else {
        return no_mailbox_page(&email_display(&headers));
    };
    let msg = match state.store.get_message(&id).await {
        Ok(Some(m)) => m,
        Ok(None) => return error_page(StatusCode::NOT_FOUND, "Not found", "No such message."),
        Err(e) => return error_page(StatusCode::INTERNAL_SERVER_ERROR, "Storage error", &e.to_string()),
    };
    if msg.mailbox != mb.addr {
        return error_page(StatusCode::NOT_FOUND, "Not found", "No such message.");
    }

    let result = match form.op.as_str() {
        "delete" => state.store.set_folder(&id, "Trash").await,
        "archive" => state.store.set_folder(&id, "Archive").await,
        "move" => {
            let Some(folder) = real_folder(&form.folder) else {
                return error_page(StatusCode::BAD_REQUEST, "Invalid request", "Unknown target folder.");
            };
            state.store.set_folder(&id, folder).await
        }
        "unread" => state.store.mark_unseen(&id).await,
        "read" => state.store.mark_seen(&id).await,
        "star" => state.store.set_starred(&id, true).await,
        "unstar" => state.store.set_starred(&id, false).await,
        _ => return error_page(StatusCode::BAD_REQUEST, "Invalid request", "Unknown action."),
    };
    if let Err(e) = result {
        return error_page(StatusCode::INTERNAL_SERVER_ERROR, "Storage error", &e.to_string());
    }
    tracing::info!(
        target: "corvid::audit",
        actor = %identity_subject(&headers).unwrap_or_default(),
        mailbox = %mb.addr,
        message = %id,
        op = %form.op,
        folder = %form.folder,
        "message action",
    );
    Redirect::to(&safe_return(&form.return_to)).into_response()
}

/// Clamp a requested folder to a real [`FOLDERS`] value (never [`STARRED_VIEW`], which is
/// virtual): the legal target of a move and the legal scope of a folder-filtered search.
fn real_folder(requested: &str) -> Option<&'static str> {
    let r = requested.trim();
    FOLDERS.into_iter().find(|c| c.eq_ignore_ascii_case(r))
}

/// Validate a form-supplied redirect target is a safe SAME-ORIGIN local path: a single leading `/`,
/// no `//` (protocol-relative), and no control/space chars. Falls back to `/` otherwise.
fn safe_return(path: &str) -> String {
    let p = path.trim();
    let ok = p.starts_with('/')
        && !p.starts_with("//")
        && !p.chars().any(|c| c.is_whitespace() || c.is_control());
    if ok { p.to_string() } else { "/".to_string() }
}

/// Render the read-view attachment strip: one download link per MIME attachment part enumerated
/// from the stored raw source. Empty string when the message carries no attachments.
fn render_attachment_list(msg: &Message) -> String {
    let attachments = crate::rfc822::list_attachments(&msg.raw_rfc822);
    if attachments.is_empty() {
        return String::new();
    }
    let mut items = String::new();
    for a in &attachments {
        items.push_str(&format!(
            r#"<li><a class="btn btn-ghost btn-sm" href="/m/{id}/attachments/{idx}" download="{name}">{name}</a> <span class="muted attach-size">{size}</span></li>"#,
            id = esc(&msg.id),
            idx = a.index,
            name = esc(&a.filename),
            size = human_size(a.size),
        ));
    }
    format!(r#"<div class="attachments"><b class="attach-head">Attachments</b><ul class="attach-list">{items}</ul></div>"#)
}

/// A compact human-readable byte size (`820 B`, `4.2 KB`, `1.5 MB`).
fn human_size(bytes: usize) -> String {
    const KB: usize = 1024;
    const MB: usize = 1024 * 1024;
    if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{bytes} B")
    }
}

/// `GET /m/{id}/attachments/{idx}` — stream the Nth attachment of a message the signed-in user owns
/// as a download (`Content-Disposition: attachment`). Enforces the SAME mailbox authorisation as the
/// read view: a message is only reachable from its own mailbox.
async fn download_attachment(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((id, idx)): Path<(String, usize)>,
) -> Response {
    let Some(mb) = resolve_mailbox(&state, &headers).await else {
        return (StatusCode::FORBIDDEN, "no mailbox").into_response();
    };
    let msg = match state.store.get_message(&id).await {
        Ok(Some(m)) => m,
        Ok(None) => return (StatusCode::NOT_FOUND, "no such message").into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    if msg.mailbox != mb.addr {
        return (StatusCode::NOT_FOUND, "no such message").into_response();
    }
    let Some(att) = crate::rfc822::extract_attachment(&msg.raw_rfc822, idx) else {
        return (StatusCode::NOT_FOUND, "no such attachment").into_response();
    };
    // `filename` + `content_type` are already sanitised by rfc822 (no CRLF/quotes), so they are
    // safe to echo into response headers.
    let disposition = format!("attachment; filename=\"{}\"", att.filename);
    (
        [
            (header::CONTENT_TYPE, att.content_type),
            (header::CONTENT_DISPOSITION, disposition),
        ],
        att.data,
    )
        .into_response()
}

/// Query string for `GET /compose`: at most one of these carries a stored message id whose
/// content seeds the reply/forward draft.
#[derive(Deserialize, Default)]
struct ComposeQuery {
    #[serde(default)]
    reply: Option<String>,
    #[serde(default)]
    replyall: Option<String>,
    #[serde(default)]
    forward: Option<String>,
}

/// The prefilled compose fields (empty for a blank New message).
#[derive(Default)]
struct Prefill {
    to: String,
    subject: String,
    body: String,
    in_reply_to: String,
    references: String,
}

async fn compose_form(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ComposeQuery>,
) -> Response {
    let email = email_display(&headers);
    let Some(mb) = resolve_mailbox(&state, &headers).await else {
        return no_mailbox_page(&email);
    };
    let from = mb.addr.clone();
    let (token, set_cookie) = ensure_csrf(&headers);

    // Seed the draft from the original when a reply/forward id is present (and it belongs to us).
    let pre = build_prefill(&state, &mb, &q).await;

    let content = format!(
        r#"<nav class="crumbs"><a href="/">← Inbox</a></nav>
<section class="card pad">
  <div class="page-head"><h1>New message</h1></div>
  <form method="post" action="/send" enctype="multipart/form-data">
    <input type="hidden" name="csrf" value="{token}">
    <input type="hidden" name="in_reply_to" value="{in_reply_to}">
    <input type="hidden" name="references" value="{references}">
    <div class="field"><label>From</label><input value="{from}" disabled></div>
    <div class="field"><label for="to">To</label><input id="to" name="to" value="{to}" placeholder="someone@example.com"></div>
    <div class="field"><label for="subject">Subject</label><input id="subject" name="subject" value="{subject}" placeholder="Subject"></div>
    <div class="field"><label for="body">Message</label><textarea id="body" name="body">{body}</textarea></div>
    <div class="field"><label for="attachments">Attachments</label><input id="attachments" name="attachments" type="file" multiple></div>
    <div class="form-actions">
      <button class="btn btn-primary" type="submit" name="action" value="send">Send</button>
      <button class="btn btn-ghost" type="submit" name="action" value="draft">Save draft</button>
      <a class="btn btn-ghost btn-sm" href="/">Cancel</a>
    </div>
  </form>
</section>"#,
        from = esc(&from),
        to = esc(&pre.to),
        subject = esc(&pre.subject),
        body = esc(&pre.body),
        in_reply_to = esc(&pre.in_reply_to),
        references = esc(&pre.references),
    );
    let html = render_page("Compose", &email, &content, "compose");
    match set_cookie {
        Some(c) => ([(header::SET_COOKIE, c)], Html(html)).into_response(),
        None => Html(html).into_response(),
    }
}

/// Build the reply/forward prefill from the original message referenced by `q`. Returns an empty
/// [`Prefill`] for a blank compose or when the referenced message is not the user's own.
async fn build_prefill(state: &AppState, mb: &Mailbox, q: &ComposeQuery) -> Prefill {
    let (id, kind) = if let Some(id) = &q.reply {
        (id, "reply")
    } else if let Some(id) = &q.replyall {
        (id, "replyall")
    } else if let Some(id) = &q.forward {
        (id, "forward")
    } else {
        return Prefill::default();
    };

    let Ok(Some(msg)) = state.store.get_message(id).await else {
        return Prefill::default();
    };
    // Authorisation: only the owning mailbox may quote a message into a new draft.
    if msg.mailbox != mb.addr {
        return Prefill::default();
    }

    // Thread headers come from the stored raw source (In-Reply-To / References chaining).
    let (hb, _) = crate::rfc822::split_headers_body(&msg.raw_rfc822);
    let hdrs = crate::rfc822::parse_headers(hb);
    let orig_mid = crate::rfc822::header(&hdrs, "message-id").unwrap_or_default();
    let orig_refs = crate::rfc822::header(&hdrs, "references")
        .or_else(|| crate::rfc822::header(&hdrs, "in-reply-to"))
        .unwrap_or_default();

    let (in_reply_to, references) = if kind == "forward" {
        (String::new(), String::new())
    } else {
        let references = match (orig_refs.trim().is_empty(), orig_mid.trim().is_empty()) {
            (true, _) => orig_mid.clone(),
            (false, true) => orig_refs.clone(),
            (false, false) => format!("{} {}", orig_refs.trim(), orig_mid.trim()),
        };
        (orig_mid.clone(), references)
    };

    match kind {
        "forward" => Prefill {
            to: String::new(),
            subject: fwd_subject(&msg.subject),
            body: forward_body(&msg),
            in_reply_to,
            references,
        },
        "replyall" => Prefill {
            to: reply_all_to(&msg, &mb.addr),
            subject: re_subject(&msg.subject),
            body: quote_body(&msg),
            in_reply_to,
            references,
        },
        _ => Prefill {
            to: msg.msg_from.clone(),
            subject: re_subject(&msg.subject),
            body: quote_body(&msg),
            in_reply_to,
            references,
        },
    }
}

/// `Re:`-prefix a subject without stacking prefixes.
fn re_subject(subject: &str) -> String {
    let s = subject.trim();
    if s.len() >= 3 && s[..3].eq_ignore_ascii_case("re:") {
        s.to_string()
    } else if s.is_empty() {
        "Re:".to_string()
    } else {
        format!("Re: {s}")
    }
}

/// `Fwd:`-prefix a subject without stacking prefixes.
fn fwd_subject(subject: &str) -> String {
    let s = subject.trim();
    let low = s.to_ascii_lowercase();
    if low.starts_with("fwd:") || low.starts_with("fw:") {
        s.to_string()
    } else if s.is_empty() {
        "Fwd:".to_string()
    } else {
        format!("Fwd: {s}")
    }
}

/// The reply-all `To`: the original sender plus its other recipients, minus our own address.
fn reply_all_to(msg: &Message, self_addr: &str) -> String {
    let mut recips: Vec<String> = vec![msg.msg_from.trim().to_string()];
    for part in msg.msg_to.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if extract_addr(part).eq_ignore_ascii_case(self_addr) {
            continue; // don't reply to ourselves
        }
        recips.push(part.to_string());
    }
    recips.retain(|s| !s.is_empty());
    recips.join(", ")
}

/// A quoted reply body: an attribution line followed by the original text, `> `-prefixed.
fn quote_body(msg: &Message) -> String {
    let quoted: String = msg
        .body_text
        .lines()
        .map(|l| format!("> {l}\n"))
        .collect();
    format!(
        "\n\nOn {}, {} wrote:\n{}",
        fmt_date(msg.received_at),
        msg.msg_from,
        quoted,
    )
}

/// A forwarded body: a delimiter block with the original headers, then the original text.
fn forward_body(msg: &Message) -> String {
    format!(
        "\n\n---------- Forwarded message ----------\nFrom: {}\nTo: {}\nSubject: {}\nDate: {}\n\n{}\n",
        msg.msg_from,
        msg.msg_to,
        msg.subject,
        fmt_date(msg.received_at),
        msg.body_text,
    )
}

#[derive(Deserialize, Default)]
struct SendForm {
    csrf: String,
    #[serde(default)]
    to: String,
    #[serde(default)]
    subject: String,
    #[serde(default)]
    body: String,
    /// Thread headers carried from a reply draft (empty for a fresh compose).
    #[serde(default)]
    in_reply_to: String,
    #[serde(default)]
    references: String,
    /// `send` (default) or `draft`.
    #[serde(default)]
    action: String,
}

async fn send(State(state): State<AppState>, req: Request) -> Response {
    // Cookies/CSRF live in the headers; capture them before the body extractor consumes `req`.
    let headers = req.headers().clone();
    let email = email_display(&headers);

    // Compose now posts multipart/form-data (so it can carry file parts); the internal callers and
    // the pre-attachment tests still post urlencoded. Accept BOTH: parse attachments only from the
    // multipart body, an empty attachment set otherwise.
    let (form, attachments) = match parse_send(req, &state, &headers).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    if !verify_csrf(&headers, &form.csrf) {
        return error_page(StatusCode::FORBIDDEN, "Request blocked", "CSRF token missing or mismatched.");
    }
    let Some(mb) = resolve_mailbox(&state, &headers).await else {
        return no_mailbox_page(&email);
    };

    let raw = build_rfc822(
        &mb.addr,
        &form.to,
        &form.subject,
        &form.body,
        &form.in_reply_to,
        &form.references,
        &state.config.mail_domain,
        &attachments,
    );

    // "Save draft": persist without sending, and allow an incomplete recipient list.
    if form.action == "draft" {
        store_local_copy(&state, &mb.addr, &form.to, &form.subject, &form.body, &raw, "Drafts").await;
        return Redirect::to("/?folder=Drafts").into_response();
    }

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

    let signer = state.signer.as_deref();
    match crate::relay::enqueue_outbound(state.store.as_ref(), signer, &raw, &mb.addr, &rcpts).await {
        Ok(signed) => {
            // File a copy of the sent message into the sender's Sent folder.
            store_local_copy(&state, &mb.addr, &form.to, &form.subject, &form.body, &signed, "Sent").await;
            Redirect::to("/?folder=Sent").into_response()
        }
        Err(e) => error_page(StatusCode::INTERNAL_SERVER_ERROR, "Send failed", &e),
    }
}

/// Persist a locally-authored message (a Sent copy or a Draft) into `mailbox`'s `folder`. Best
/// effort: a storage error is logged but never fails the user's send/save (the mail already left).
async fn store_local_copy(
    state: &AppState,
    mailbox: &str,
    to: &str,
    subject: &str,
    body: &str,
    raw: &str,
    folder: &str,
) {
    let msg = Message {
        id: new_id("m"),
        mailbox: mailbox.to_string(),
        msg_from: mailbox.to_string(),
        msg_to: to.to_string(),
        subject: subject.to_string(),
        raw_rfc822: raw.to_string(),
        body_text: body.to_string(),
        body_html: String::new(),
        received_at: now_secs(),
        seen: true,
        folder: folder.to_string(),
        starred: false,
    };
    if let Err(e) = state.store.store_message(&msg).await {
        tracing::warn!(error = %e, folder, "failed to file local message copy");
    }
}

/// Parse a `POST /send` body into its [`SendForm`] fields plus any attachment file parts. A
/// `multipart/form-data` body (the compose form) yields both; any other content type is decoded as
/// the legacy `application/x-www-form-urlencoded` form with no attachments (internal callers/tests).
async fn parse_send(
    req: Request,
    state: &AppState,
    headers: &HeaderMap,
) -> Result<(SendForm, Vec<Attachment>), Response> {
    let ct = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if ct.starts_with("multipart/form-data") {
        let mut mp = Multipart::from_request(req, state)
            .await
            .map_err(|e| error_page(StatusCode::BAD_REQUEST, "Invalid request", &e.to_string()))?;
        let mut form = SendForm::default();
        let mut attachments = Vec::new();
        loop {
            let field = match mp.next_field().await {
                Ok(Some(f)) => f,
                Ok(None) => break,
                Err(e) => return Err(error_page(StatusCode::BAD_REQUEST, "Invalid upload", &e.to_string())),
            };
            let name = field.name().unwrap_or("").to_string();
            if name == "attachments" {
                let filename = field.file_name().map(str::to_string).unwrap_or_default();
                let content_type = field
                    .content_type()
                    .map(str::to_string)
                    .unwrap_or_else(|| "application/octet-stream".to_string());
                let data = field
                    .bytes()
                    .await
                    .map_err(|e| error_page(StatusCode::BAD_REQUEST, "Invalid upload", &e.to_string()))?
                    .to_vec();
                // Skip the empty file input a user leaves untouched.
                if !data.is_empty() && !filename.trim().is_empty() {
                    attachments.push(Attachment {
                        filename: crate::rfc822::sanitize_filename(&filename),
                        content_type: crate::rfc822::content_type_base(&content_type),
                        data,
                    });
                }
            } else {
                let text = field.text().await.unwrap_or_default();
                match name.as_str() {
                    "csrf" => form.csrf = text,
                    "to" => form.to = text,
                    "subject" => form.subject = text,
                    "body" => form.body = text,
                    "in_reply_to" => form.in_reply_to = text,
                    "references" => form.references = text,
                    "action" => form.action = text,
                    _ => {}
                }
            }
        }
        Ok((form, attachments))
    } else {
        let Form(form) = Form::<SendForm>::from_request(req, state)
            .await
            .map_err(|e| error_page(StatusCode::BAD_REQUEST, "Invalid request", &e.to_string()))?;
        Ok((form, Vec::new()))
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

    let raw = build_rfc822(&from_addr, &req.to, &req.subject, &req.body, "", "", &state.config.mail_domain, &[]);
    let signer = state.signer.as_deref();
    match crate::relay::enqueue_outbound(state.store.as_ref(), signer, &raw, &from_addr, &rcpts).await {
        Ok(signed) => {
            // File a Sent copy for the sending address (parity with the webmail /send path).
            store_local_copy(&state, &from_addr, &req.to, &req.subject, &req.body, &signed, "Sent").await;
            json_status(StatusCode::ACCEPTED, "queued")
        }
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

/// Build an RFC822 message for an outbound compose. `in_reply_to`/`references` (empty to omit)
/// carry the reply threading headers built from the original's stored raw source. With no
/// `attachments` the body is a single `text/plain` part (unchanged wire format); with attachments
/// it becomes a `multipart/mixed` — a `text/plain` body part followed by one base64
/// `Content-Disposition: attachment` part per file.
fn build_rfc822(
    from: &str,
    to: &str,
    subject: &str,
    body: &str,
    in_reply_to: &str,
    references: &str,
    domain: &str,
    attachments: &[Attachment],
) -> String {
    let body_norm = body.replace("\r\n", "\n").replace('\n', "\r\n");
    let mut thread = String::new();
    if !in_reply_to.trim().is_empty() {
        thread.push_str(&format!("In-Reply-To: {}\r\n", in_reply_to.trim()));
    }
    if !references.trim().is_empty() {
        thread.push_str(&format!("References: {}\r\n", references.trim()));
    }

    let head = format!(
        "From: {from}\r\nTo: {to}\r\nSubject: {subject}\r\nDate: {date}\r\nMessage-ID: {mid}\r\n{thread}MIME-Version: 1.0\r\n",
        date = email_date(),
        mid = message_id(domain),
    );

    if attachments.is_empty() {
        return format!(
            "{head}Content-Type: text/plain; charset=utf-8\r\n\
             Content-Transfer-Encoding: 8bit\r\n\r\n{body_norm}\r\n",
        );
    }

    let boundary = mime_boundary();
    let mut out = format!(
        "{head}Content-Type: multipart/mixed; boundary=\"{boundary}\"\r\n\r\n\
         This is a multi-part message in MIME format.\r\n\
         --{boundary}\r\nContent-Type: text/plain; charset=utf-8\r\n\
         Content-Transfer-Encoding: 8bit\r\n\r\n{body_norm}\r\n",
    );
    for a in attachments {
        let name = crate::rfc822::sanitize_filename(&a.filename);
        let ctype = crate::rfc822::content_type_base(&a.content_type);
        out.push_str(&format!(
            "--{boundary}\r\nContent-Type: {ctype}; name=\"{name}\"\r\n\
             Content-Transfer-Encoding: base64\r\n\
             Content-Disposition: attachment; filename=\"{name}\"\r\n\r\n{payload}\r\n",
            payload = base64_wrapped(&a.data),
        ));
    }
    out.push_str(&format!("--{boundary}--\r\n"));
    out
}

/// A fresh MIME multipart boundary — random enough never to occur in a payload.
fn mime_boundary() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    format!("=_corvid_{}", hex::encode(bytes))
}

/// Base64-encode `data` and hard-wrap it at 76 columns with CRLF (RFC 2045 line-length limit).
fn base64_wrapped(data: &[u8]) -> String {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(data);
    let mut out = String::with_capacity(b64.len() + b64.len() / 76 * 2);
    let bytes = b64.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let end = (i + 76).min(bytes.len());
        out.push_str(&b64[i..end]);
        out.push_str("\r\n");
        i = end;
    }
    // Trim the trailing CRLF; the caller frames the part with its own CRLF.
    out.truncate(out.trim_end_matches("\r\n").len());
    out
}

// ---------------------------------------------------------------------------
// Admin panel — mailbox provisioning (gated by `require_admin`)
// ---------------------------------------------------------------------------

/// Soft per-mailbox message quota, shown alongside the live count in the admin view.
const MAILBOX_QUOTA: i64 = 10_000;

/// `GET /admin` — list every provisioned mailbox with its owner + message-count/quota, plus the
/// forms to create a mailbox and add an alias. Mints a CSRF token for the two POST forms.
async fn admin_index(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let email = email_display(&headers);
    let (token, set_cookie) = ensure_csrf(&headers);

    let mailboxes = match state.store.list_mailboxes().await {
        Ok(m) => m,
        Err(e) => return error_page(StatusCode::INTERNAL_SERVER_ERROR, "Storage error", &e.to_string()),
    };
    let aliases = match state.store.list_aliases().await {
        Ok(a) => a,
        Err(e) => return error_page(StatusCode::INTERNAL_SERVER_ERROR, "Storage error", &e.to_string()),
    };

    let mut mb_rows = String::new();
    if mailboxes.is_empty() {
        mb_rows.push_str(r#"<tr><td colspan="3" class="muted">No mailboxes provisioned.</td></tr>"#);
    }
    for mb in &mailboxes {
        let count = state.store.message_count(&mb.addr).await.unwrap_or(0);
        mb_rows.push_str(&format!(
            r#"<tr><td>{addr}</td><td>{owner}</td><td>{count} / {quota}</td></tr>"#,
            addr = esc(&mb.addr),
            owner = esc(&mb.owner_sub),
            quota = MAILBOX_QUOTA,
        ));
    }

    let mut alias_rows = String::new();
    if aliases.is_empty() {
        alias_rows.push_str(r#"<tr><td colspan="2" class="muted">No aliases.</td></tr>"#);
    }
    for a in &aliases {
        alias_rows.push_str(&format!(
            r#"<tr><td>{lp}</td><td>{mb}</td></tr>"#,
            lp = esc(&a.local_part),
            mb = esc(&a.mailbox),
        ));
    }

    let content = format!(
        r#"<div class="page-head"><h1>Mailbox provisioning</h1></div>
<section class="card pad">
  <h2>Mailboxes</h2>
  <table class="data admin-table">
    <thead><tr><th>Address</th><th>Owner (sub)</th><th>Messages / quota</th></tr></thead>
    <tbody>{mb_rows}</tbody>
  </table>
  <form method="post" action="/admin/mailboxes">
    <input type="hidden" name="csrf" value="{token}">
    <div class="field"><label for="addr">New mailbox address</label><input id="addr" name="addr" placeholder="alice@w33d.xyz"></div>
    <div class="field"><label for="owner_sub">Owner sub</label><input id="owner_sub" name="owner_sub" placeholder="alice"></div>
    <div class="form-actions"><button class="btn btn-primary" type="submit">Create mailbox</button></div>
  </form>
</section>
<section class="card pad">
  <h2>Aliases</h2>
  <table class="data admin-table">
    <thead><tr><th>Local-part</th><th>Delivers to</th></tr></thead>
    <tbody>{alias_rows}</tbody>
  </table>
  <form method="post" action="/admin/aliases">
    <input type="hidden" name="csrf" value="{token}">
    <div class="field"><label for="local_part">Alias local-part</label><input id="local_part" name="local_part" placeholder="info"></div>
    <div class="field"><label for="mailbox">Target mailbox</label><input id="mailbox" name="mailbox" placeholder="alice@w33d.xyz"></div>
    <div class="form-actions"><button class="btn btn-primary" type="submit">Add alias</button></div>
  </form>
</section>"#,
    );
    let html = render_page("Admin", &email, &content, "");
    match set_cookie {
        Some(c) => ([(header::SET_COOKIE, c)], Html(html)).into_response(),
        None => Html(html).into_response(),
    }
}

/// Create-mailbox form (`POST /admin/mailboxes`).
#[derive(Deserialize)]
struct CreateMailboxForm {
    csrf: String,
    #[serde(default)]
    addr: String,
    #[serde(default)]
    owner_sub: String,
}

/// `POST /admin/mailboxes` — provision a new mailbox `(addr, owner_sub)`. CSRF-guarded; rejects a
/// malformed address or a duplicate. On success emits a tracing audit line and redirects to `/admin`.
async fn admin_create_mailbox(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<CreateMailboxForm>,
) -> Response {
    if !verify_csrf(&headers, &form.csrf) {
        return error_page(StatusCode::FORBIDDEN, "Request blocked", "CSRF token missing or mismatched.");
    }
    let addr = form.addr.trim().to_lowercase();
    let owner_sub = form.owner_sub.trim().to_string();
    if addr.is_empty() || !addr.contains('@') || domain_of(&addr).is_none() {
        return error_page(StatusCode::BAD_REQUEST, "Invalid request", "A valid mailbox address (local@domain) is required.");
    }
    if owner_sub.is_empty() {
        return error_page(StatusCode::BAD_REQUEST, "Invalid request", "An owner sub is required.");
    }
    match state.store.get_mailbox(&addr).await {
        Ok(Some(_)) => return error_page(StatusCode::CONFLICT, "Already exists", "A mailbox with that address already exists."),
        Ok(None) => {}
        Err(e) => return error_page(StatusCode::INTERNAL_SERVER_ERROR, "Storage error", &e.to_string()),
    }
    let mb = Mailbox { addr: addr.clone(), owner_sub: owner_sub.clone() };
    if let Err(e) = state.store.upsert_mailbox(&mb).await {
        return error_page(StatusCode::INTERNAL_SERVER_ERROR, "Storage error", &e.to_string());
    }
    tracing::info!(
        target: "corvid::audit",
        actor = %identity_subject(&headers).unwrap_or_default(),
        addr = %addr,
        owner_sub = %owner_sub,
        "admin created mailbox"
    );
    Redirect::to("/admin").into_response()
}

/// Add-alias form (`POST /admin/aliases`).
#[derive(Deserialize)]
struct AddAliasForm {
    csrf: String,
    #[serde(default)]
    local_part: String,
    #[serde(default)]
    mailbox: String,
}

/// `POST /admin/aliases` — map an alias local-part to an existing mailbox. CSRF-guarded; the target
/// mailbox must exist. On success emits a tracing audit line and redirects to `/admin`.
async fn admin_add_alias(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<AddAliasForm>,
) -> Response {
    if !verify_csrf(&headers, &form.csrf) {
        return error_page(StatusCode::FORBIDDEN, "Request blocked", "CSRF token missing or mismatched.");
    }
    let local_part = form.local_part.trim().to_lowercase();
    let mailbox = form.mailbox.trim().to_lowercase();
    if local_part.is_empty() || local_part.contains('@') {
        return error_page(StatusCode::BAD_REQUEST, "Invalid request", "A bare alias local-part (no @) is required.");
    }
    match state.store.get_mailbox(&mailbox).await {
        Ok(Some(_)) => {}
        Ok(None) => return error_page(StatusCode::BAD_REQUEST, "Invalid request", "The target mailbox does not exist."),
        Err(e) => return error_page(StatusCode::INTERNAL_SERVER_ERROR, "Storage error", &e.to_string()),
    }
    let alias = Alias { local_part: local_part.clone(), mailbox: mailbox.clone() };
    if let Err(e) = state.store.add_alias(&alias).await {
        return error_page(StatusCode::INTERNAL_SERVER_ERROR, "Storage error", &e.to_string());
    }
    tracing::info!(
        target: "corvid::audit",
        actor = %identity_subject(&headers).unwrap_or_default(),
        local_part = %local_part,
        mailbox = %mailbox,
        "admin added alias"
    );
    Redirect::to("/admin").into_response()
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

/// Group names that authorize the admin panel. Membership in ANY of these unlocks `/admin`.
pub const ADMIN_GROUPS: &[&str] = &["admins", "infra-admins"];

/// The authenticated user's groups, parsed from the comma-separated `X-Auth-Groups` header
/// (injected AND HMAC-verified by the gateway, so it is trustworthy). Empty when absent/blank.
fn author_groups(headers: &HeaderMap) -> Vec<String> {
    header_value(headers, HEADER_GROUPS)
        .map(|raw| {
            raw.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// Whether the authenticated user belongs to `group` (exact match against `X-Auth-Groups`).
pub fn has_group(headers: &HeaderMap, group: &str) -> bool {
    author_groups(headers).iter().any(|g| g == group)
}

/// Whether the authenticated user is in ANY [`ADMIN_GROUPS`] entry.
fn is_admin(headers: &HeaderMap) -> bool {
    ADMIN_GROUPS.iter().any(|g| has_group(headers, g))
}

/// Require admin group membership for the `/admin` subtree. On success returns `Ok(())`; when the
/// user carries no admin group, returns a rendered `403` page as the `Err` — closes the hole where
/// ANY signed-in user could reach mailbox provisioning.
pub fn require_admin(headers: &HeaderMap) -> Result<(), Response> {
    if is_admin(headers) {
        Ok(())
    } else {
        Err(error_page(
            StatusCode::FORBIDDEN,
            "Forbidden",
            "The admin panel requires an administrator group.",
        ))
    }
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

/// Render a full page into the Odyssey v2 shell. `nav_active` marks the current app-bar nav
/// destination (`"inbox"`, `"compose"`, or `""` for none — e.g. admin/error pages).
fn render_page(title: &str, email_display: &str, content: &str, nav_active: &str) -> String {
    SHELL
        .replace("{{STYLE}}", APP_CSS)
        .replace("{{TITLE}}", &esc(title))
        .replace("{{NAV}}", &nav_bar(nav_active))
        .replace("{{USERBOX}}", &userbox(email_display))
        .replace("{{CONTENT}}", content)
}

/// The app-bar navigation — the existing Inbox (`/`) and Compose (`/compose`) destinations as v2
/// `.appnav` links, marking `active` (`"inbox"`/`"compose"`) with `.is-active`.
fn nav_bar(active: &str) -> String {
    let link = |key: &str, href: &str, label: &str, icon: &str| {
        let cls = if key == active { "appnav is-active" } else { "appnav" };
        format!(r#"<a class="{cls}" href="{href}">{icon}{label}</a>"#)
    };
    format!(
        "{}{}",
        link("inbox", "/", "Inbox", ICO_INBOX),
        link("compose", "/compose", "Compose", ICO_COMPOSE),
    )
}

/// The right side of the app-bar (Odyssey v2): an "All apps" icon button back to the apex portal,
/// plus a focus-within avatar menu whose dropdown lists Account, All apps, and the SAME
/// cross-subdomain sign-out (`LOGOUT_URL`, a GET link) wrapped as a danger menu item.
/// `email_display` is the already-escaped display string from [`email_display`]; the `—` sentinel
/// (no gateway session) still renders a minimal avatar so the chrome never breaks.
fn userbox(email_display: &str) -> String {
    let has_email = !email_display.is_empty() && !email_display.starts_with('—');
    // Name = the local-part; initial = its first alphanumeric char (fallback "C" for Corvid).
    let name = email_display.split('@').next().unwrap_or(email_display);
    let initial = name
        .chars()
        .find(|c| c.is_alphanumeric())
        .filter(|_| has_email)
        .map(|c| c.to_uppercase().to_string())
        .unwrap_or_else(|| "C".to_string());

    let name_label = if has_email {
        format!(r#"<span class="usermenu__name">{email_display}</span>"#)
    } else {
        String::new()
    };
    let head = if has_email {
        format!(
            r#"<div class="usermenu__head"><span class="avatar avatar--lg">{initial}</span><div><b>{name}</b><span>{email_display}</span></div></div>"#,
        )
    } else {
        String::new()
    };

    format!(
        r#"<a class="iconbtn" href="https://w33d.xyz" title="All apps" aria-label="All apps">{grid}</a>
<div class="usermenu">
  <button class="usermenu__btn" type="button" aria-haspopup="true" aria-label="Account menu"><span class="avatar" aria-hidden="true">{initial}</span>{name_label}{caret}</button>
  <div class="usermenu__pop" role="menu">
    {head}
    <a class="menuitem" role="menuitem" href="https://account.w33d.xyz">{user}Account</a>
    <a class="menuitem" role="menuitem" href="https://w33d.xyz">{grid}All apps</a>
    <a class="menuitem menuitem--danger" role="menuitem" href="{logout}">{logout_ico}Log out</a>
  </div>
</div>"#,
        grid = ICO_GRID,
        caret = ICO_CARET,
        user = ICO_USER,
        logout_ico = ICO_LOGOUT,
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
    Html(render_page("No mailbox", email, content, "")).into_response()
}

fn error_page(status: StatusCode, heading: &str, message: &str) -> Response {
    let content = format!(
        r#"<section class="card empty-card"><h1 class="empty-title">{}</h1><p class="muted">{}</p><p><a class="btn btn-primary btn-sm" href="/">Back to inbox</a></p></section>"#,
        esc(heading),
        esc(message),
    );
    (status, Html(render_page(heading, "—", &content, ""))).into_response()
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
    fn has_group_and_require_admin() {
        // No X-Auth-Groups => no groups, not an admin, require_admin rejects.
        let mut none = HeaderMap::new();
        none.insert(HEADER_SUBJECT, HeaderValue::from_static("u_eve"));
        assert!(author_groups(&none).is_empty());
        assert!(!has_group(&none, "admins"));
        assert!(!is_admin(&none));
        assert!(require_admin(&none).is_err());

        // Comma-separated groups, with whitespace, parse and match by exact name.
        let mut admins = HeaderMap::new();
        admins.insert(HEADER_GROUPS, HeaderValue::from_static("dev, infra-admins ,x"));
        assert!(has_group(&admins, "infra-admins"));
        assert!(has_group(&admins, "dev"));
        assert!(!has_group(&admins, "admins"));
        assert!(is_admin(&admins), "infra-admins authorizes the admin panel");
        assert!(require_admin(&admins).is_ok());

        // A non-admin group alone does not authorize.
        let mut other = HeaderMap::new();
        other.insert(HEADER_GROUPS, HeaderValue::from_static("readers,writers"));
        assert!(!is_admin(&other));
        assert!(require_admin(&other).is_err());
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
        let raw = build_rfc822("w33d@w33d.xyz", "x@y.com", "Hi", "Body line", "", "", "w33d.xyz", &[]);
        for h in ["From:", "To:", "Subject:", "Date:", "Message-ID:", "MIME-Version:", "Content-Type:"] {
            assert!(raw.contains(h), "missing {h}");
        }
        assert!(raw.contains("\r\n\r\nBody line\r\n"));
        // No threading headers when none are supplied.
        assert!(!raw.contains("In-Reply-To:"));
        assert!(!raw.contains("References:"));
    }

    #[test]
    fn build_rfc822_includes_thread_headers() {
        let raw = build_rfc822(
            "w33d@w33d.xyz",
            "x@y.com",
            "Re: Hi",
            "Body",
            "<orig@ex.com>",
            "<root@ex.com> <orig@ex.com>",
            "w33d.xyz",
            &[],
        );
        assert!(raw.contains("In-Reply-To: <orig@ex.com>\r\n"));
        assert!(raw.contains("References: <root@ex.com> <orig@ex.com>\r\n"));
    }

    #[test]
    fn build_rfc822_emits_multipart_mixed_with_attachment() {
        let att = Attachment {
            filename: "report.txt".to_string(),
            content_type: "text/plain".to_string(),
            data: b"hello attachment".to_vec(),
        };
        let raw = build_rfc822("w33d@w33d.xyz", "x@y.com", "Files", "See attached", "", "", "w33d.xyz", &[att]);

        assert!(raw.contains("Content-Type: multipart/mixed; boundary="), "top-level is multipart/mixed");
        assert!(raw.contains("Content-Disposition: attachment; filename=\"report.txt\""));
        assert!(raw.contains("Content-Transfer-Encoding: base64"));

        // The stored source round-trips through the reader: body + one decodable attachment.
        let parsed = crate::rfc822::parse(&raw);
        assert!(parsed.body_text.contains("See attached"));
        let metas = crate::rfc822::list_attachments(&raw);
        assert_eq!(metas.len(), 1);
        assert_eq!(metas[0].filename, "report.txt");
        let got = crate::rfc822::extract_attachment(&raw, 0).unwrap();
        assert_eq!(got.data, b"hello attachment");
    }

    #[test]
    fn subject_prefixes_do_not_stack() {
        assert_eq!(re_subject("Hi"), "Re: Hi");
        assert_eq!(re_subject("Re: Hi"), "Re: Hi");
        assert_eq!(re_subject("RE: Hi"), "RE: Hi");
        assert_eq!(fwd_subject("Hi"), "Fwd: Hi");
        assert_eq!(fwd_subject("Fwd: Hi"), "Fwd: Hi");
        assert_eq!(fwd_subject("fw: Hi"), "fw: Hi");
    }

    #[test]
    fn reply_all_excludes_self() {
        let msg = Message {
            id: "m1".to_string(),
            mailbox: "w33d@w33d.xyz".to_string(),
            msg_from: "Alice <alice@ex.com>".to_string(),
            msg_to: "w33d@w33d.xyz, Bob <bob@ex.com>".to_string(),
            subject: "Hi".to_string(),
            raw_rfc822: String::new(),
            body_text: String::new(),
            body_html: String::new(),
            received_at: 0,
            seen: false,
            folder: "INBOX".to_string(),
            starred: false,
        };
        let to = reply_all_to(&msg, "w33d@w33d.xyz");
        assert!(to.contains("alice@ex.com"));
        assert!(to.contains("bob@ex.com"));
        assert!(!to.contains("w33d@w33d.xyz"));
    }

    #[test]
    fn canonical_folder_clamps_unknown() {
        assert_eq!(canonical_folder(Some("Sent")), "Sent");
        assert_eq!(canonical_folder(Some("sent")), "Sent");
        assert_eq!(canonical_folder(Some("bogus")), "INBOX");
        assert_eq!(canonical_folder(None), "INBOX");
    }

    #[test]
    fn real_folder_accepts_only_real_folders() {
        assert_eq!(real_folder("sent"), Some("Sent"));
        assert_eq!(real_folder(" Trash "), Some("Trash"));
        assert_eq!(real_folder("Starred"), None, "the virtual view is not a folder");
        assert_eq!(real_folder("bogus"), None);
    }

    #[test]
    fn clamp_limit_defaults_and_bounds() {
        assert_eq!(clamp_limit(None), PAGE_DEFAULT);
        assert_eq!(clamp_limit(Some(10)), 10);
        assert_eq!(clamp_limit(Some(0)), 1);
        assert_eq!(clamp_limit(Some(-5)), 1);
        assert_eq!(clamp_limit(Some(100_000)), PAGE_MAX);
    }

    #[test]
    fn parse_cursor_accepts_ts_id_and_rejects_junk() {
        assert_eq!(parse_cursor(Some("100_m_abc")), Some((100, "m_abc".to_string())), "id keeps its own underscores");
        assert_eq!(parse_cursor(Some("junk")), None);
        assert_eq!(parse_cursor(Some("notanum_m1")), None);
        assert_eq!(parse_cursor(None), None);
    }

    #[test]
    fn next_page_link_only_on_full_pages() {
        let row = |id: &str, ts: i64| crate::model::MessageSummary {
            id: id.to_string(),
            msg_from: String::new(),
            subject: String::new(),
            received_at: ts,
            seen: false,
            starred: false,
        };
        // Short page (or empty) -> nothing older -> no link.
        assert_eq!(next_page_link(&[], 2, "/?folder=Sent&limit=2"), "");
        assert_eq!(next_page_link(&[row("m_1", 9)], 2, "/?folder=Sent&limit=2"), "");
        // Full page -> link carrying the last row's (received_at, id) cursor.
        let link = next_page_link(&[row("m_2", 9), row("m_1", 8)], 2, "/?folder=Sent&limit=2");
        assert!(link.contains("/?folder=Sent&limit=2&before=8_m_1"), "cursor appended: {link}");
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
