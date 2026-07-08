//! Webmail (axum) — the v1 mail client, served at `mail.w33d.xyz` BEHIND the gateway SSO.
//!
//! It does NO login of its own: Sluice runs the OIDC browser login against Keystone, strips any
//! inbound `X-Auth-*`, and injects the verified `X-Auth-Subject` / `X-Auth-Email`. The webmail
//! TRUSTS those headers (it is internal-only) and selects the signed-in user's mailbox by
//! `owner_sub`. State-changing POSTs (`/send`, `/send/undo`) are CSRF-guarded (double-submit
//! `__Host-csrf`).
//!
//! Views:
//! - `GET /healthz`  liveness (container HEALTHCHECK)
//! - `GET /`         folder list (`?folder=INBOX|Sent|Drafts|Spam`, newest first: from / subject / date)
//!                   or `?q=` full-text search (subject/from/to/body, optional `?folder=` scope);
//!                   both keyset-paginated via `?before=<received_at>_<id>` + `?limit=` (≤200)
//! - `GET /search/advanced` Gmail-style advanced search form; submits to the existing `?q=` search
//! - `GET /m/{id}`   read a message (rendered sanitised body), marks it seen; reply/forward actions
//! - `GET /compose`  compose form (mints a CSRF token); `?reply|replyall|forward=<id>` prefills it
//! - `POST /compose/autosave` upsert the current compose into Drafts as a JSON progressive enhancement
//! - `POST /send`    `action=send`: build RFC822, DKIM-sign, enqueue behind the undo-send window;
//!                   `action=draft`: persist/upsert into the Drafts folder without sending
//! - `POST /send/undo` move a still-held send back to Drafts
//! - `GET /settings` mailbox settings: filter rules / undo send / display / signature / auto-reply
//!   sections
//! - `POST /settings/rules|undo-send|preferences|signature|autoreply` settings mutations
//!   (CSRF-guarded)

use axum::extract::{FromRequest, Multipart, Path, Query, Request, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Form, Json, Router};

use crate::rfc822::Attachment;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::Deserialize;
use std::collections::HashMap;
use time::{Date, Month, OffsetDateTime};

use crate::model::{
    parse_search_query, Alias, Contact, ContactGroup, FilterRule, Label, Mailbox, MailboxSettings,
    Message, ScheduledOutbound, SearchPredicateKind, SearchQuery, SenderListEntry, Signature,
    SpamAnnotation, Template, DEFAULT_DENSITY, DEFAULT_READING_PANE, DEFAULT_THEME,
    DEFAULT_UNDO_SEND_WINDOW_SECS,
};
use crate::sanitize::esc_text;
use crate::store::FolderCounts;
use crate::util::{domain_of, email_date, message_id, new_id, now_secs};
use crate::AppState;

/// The real (column-backed) folders the webmail surfaces: INBOX for received mail, the two
/// locally-authored ones, plus Archive/Spam/Trash that message actions move mail into. These are
/// the legal targets for a move and the values stored in `Message.folder`.
const FOLDERS: [&str; 6] = [
    "INBOX",
    "Sent",
    "Drafts",
    "Archive",
    crate::delivery::SPAM_FOLDER,
    "Trash",
];

/// A virtual, cross-folder view of the starred/flagged messages. Selected via `?folder=Starred`
/// but never stored in `Message.folder`.
const STARRED_VIEW: &str = "Starred";

/// A virtual, cross-folder view of messages whose `snooze_until` is still in the future.
const SNOOZED_VIEW: &str = "Snoozed";
/// A virtual view of outbound queue batches scheduled for future delivery.
const SCHEDULED_VIEW: &str = "Scheduled";

const UNDO_SEND_WINDOW_CHOICES: [i64; 4] = [5, 10, 20, 30];
const UNDO_SEND_MAX_WINDOW_SECS: i64 = 30;
const DENSITY_CHOICES: [&str; 3] = ["comfortable", "normal", "compact"];
const READING_PANE_CHOICES: [&str; 3] = ["off", "right", "bottom"];
const THEME_CHOICES: [&str; 3] = ["system", "light", "dark"];

#[derive(Clone, Copy)]
struct PagePrefs {
    density: &'static str,
    reading_pane: &'static str,
    theme: &'static str,
}

impl Default for PagePrefs {
    fn default() -> Self {
        Self {
            density: DEFAULT_DENSITY,
            reading_pane: DEFAULT_READING_PANE,
            theme: DEFAULT_THEME,
        }
    }
}

/// Default rows per folder/search page when `?limit=` is absent.
const PAGE_DEFAULT: i64 = 50;

/// Hard ceiling for `?limit=` — one listing page never exceeds this many rows. Older mail stays
/// reachable through the keyset `?before=` cursor instead of a bigger page.
const PAGE_MAX: i64 = 200;

/// Corvid-only webmail CSS (mail shell / folder list / mail rows / read view / compose /
/// contacts / threading / density / reading-pane / dark mode) layered AFTER Odyssey's canonical
/// font, tokens, and shared components.
const SERVICE_CSS: &str = include_str!("../static/service.css");
const SHELL: &str = include_str!("../templates/shell.html");

/// Embedded design system for every rendered page's `<style>`: Odyssey canonical CSS followed by
/// the Corvid service layer. Concatenated once on first use.
static APP_CSS: OnceLock<String> = OnceLock::new();

fn app_css() -> &'static str {
    APP_CSS
        .get_or_init(|| {
            let mut css = String::with_capacity(odyssey::APP_CSS.len() + SERVICE_CSS.len());
            css.push_str(odyssey::APP_CSS);
            css.push_str(SERVICE_CSS);
            css
        })
        .as_str()
}

/// Vanilla, dependency-free To/Cc autocomplete. Progressive enhancement: the inputs are plain
/// text fields that submit fine with JS off; this only layers a debounced suggestion listbox on
/// top. Remote strings are written with `textContent` (never innerHTML) so a hostile display-name
/// can never inject markup. ARIA combobox roles + keyboard nav for accessibility.
const COMPOSE_JS: &str = r#"
(function () {
  var boxes = document.querySelectorAll('input[data-autocomplete]');
  boxes.forEach(function (input) {
    var list = document.getElementById(input.getAttribute('aria-controls'));
    if (!list) return;
    var timer = null, active = -1, items = [];
    function lastToken() {
      var v = input.value; var i = v.lastIndexOf(',');
      return i < 0 ? v.trim() : v.slice(i + 1).trim();
    }
    function close() {
      list.hidden = true; list.textContent = ''; active = -1; items = [];
      input.setAttribute('aria-expanded', 'false');
      input.removeAttribute('aria-activedescendant');
    }
    function choose(addr) {
      var v = input.value; var i = v.lastIndexOf(',');
      input.value = (i < 0 ? '' : v.slice(0, i + 1) + ' ') + addr + ', ';
      close(); input.focus();
    }
    function render(sugs) {
      list.textContent = ''; items = []; active = -1;
      sugs.forEach(function (s, idx) {
        var li = document.createElement('li');
        li.setAttribute('role', 'option');
        li.id = list.id + '-opt-' + idx;
        li.className = 'combo__opt';
        var a = document.createElement('span'); a.className = 'combo__addr';
        a.textContent = s.addr;
        li.appendChild(a);
        if (s.name) {
          var n = document.createElement('span'); n.className = 'combo__name';
          n.textContent = s.name; li.appendChild(n);
        }
        li.addEventListener('mousedown', function (e) { e.preventDefault(); choose(s.addr); });
        list.appendChild(li); items.push(li);
      });
      if (items.length) { list.hidden = false; input.setAttribute('aria-expanded', 'true'); }
      else { close(); }
    }
    function highlight(n) {
      items.forEach(function (li) { li.setAttribute('aria-selected', 'false'); li.classList.remove('is-active'); });
      if (n >= 0 && n < items.length) {
        items[n].setAttribute('aria-selected', 'true'); items[n].classList.add('is-active');
        input.setAttribute('aria-activedescendant', items[n].id); active = n;
      }
    }
    function fetchSuggest() {
      var q = lastToken();
      if (q.length < 1) { close(); return; }
      fetch('/contacts/suggest?q=' + encodeURIComponent(q), { headers: { 'Accept': 'application/json' } })
        .then(function (r) { return r.ok ? r.json() : []; })
        .then(function (data) { render(Array.isArray(data) ? data : []); })
        .catch(function () { close(); });
    }
    input.addEventListener('input', function () {
      if (timer) clearTimeout(timer);
      timer = setTimeout(fetchSuggest, 160);
    });
    input.addEventListener('keydown', function (e) {
      if (list.hidden) return;
      if (e.key === 'ArrowDown') { e.preventDefault(); highlight(Math.min(active + 1, items.length - 1)); }
      else if (e.key === 'ArrowUp') { e.preventDefault(); highlight(Math.max(active - 1, 0)); }
      else if (e.key === 'Enter' && active >= 0) { e.preventDefault(); items[active].dispatchEvent(new MouseEvent('mousedown')); }
      else if (e.key === 'Escape') { close(); }
    });
    input.addEventListener('blur', function () { setTimeout(close, 150); });
  });
})();
"#;
/// Shared, dependency-free toast helper. Defines `window.__corvidToast(msg, kind)` used by the
/// webmail + compose enhancement scripts. Remote/dynamic strings are written with `textContent`
/// (never innerHTML). The host is an ARIA live region so success/failure feedback is announced.
const TOAST_JS: &str = r#"
window.__corvidToast = function (msg, kind) {
  var host = document.getElementById('toast-host');
  if (!host) {
    host = document.createElement('div');
    host.id = 'toast-host'; host.className = 'toast-host';
    host.setAttribute('aria-live', 'polite'); host.setAttribute('role', 'status');
    document.body.appendChild(host);
  }
  var t = document.createElement('div');
  t.className = 'toast' + (kind === 'ok' ? ' toast--ok' : kind === 'err' ? ' toast--err' : '');
  var s = document.createElement('span'); s.textContent = msg; t.appendChild(s);
  host.appendChild(t);
  requestAnimationFrame(function () { t.classList.add('is-in'); });
  setTimeout(function () {
    t.classList.remove('is-in');
    setTimeout(function () { if (t.parentNode) t.parentNode.removeChild(t); }, 220);
  }, 3000);
};
"#;

/// Webmail progressive-enhancement layer (inbox list + read/conversation views). Everything here
/// is ADDITIVE: with JS off, the original `<form>` POSTs still work. It provides:
/// - optimistic per-message actions (star / mark-read / archive / snooze / mute / spam / delete / move) via `fetch()` to
///   the JSON siblings of the form routes, rolling back + toasting on failure;
/// - checkbox multi-select + a sticky bulk toolbar (mark-read / archive / snooze / mute / spam / move / delete);
/// - keyboard nav (j/k prev-next, e archive, # delete, r reply, x select, Enter open);
/// - collapse/expand for older messages in a conversation.
///
/// Remote strings are only ever written with `textContent`.
const WEBMAIL_JS: &str = r#"
(function () {
  var toast = window.__corvidToast || function () {};
  var undo = document.querySelector('[data-undo-send]');
  if (undo) {
    var until = parseInt(undo.getAttribute('data-undo-until') || '0', 10);
    var countdown = undo.querySelector('[data-undo-countdown]');
    var btn = undo.querySelector('.btn-undo-send');
    function tickUndo() {
      var left = Math.max(0, until - Math.floor(Date.now() / 1000));
      if (countdown) countdown.textContent = left + 's';
      if (left <= 0) {
        undo.classList.add('is-expired');
        if (btn) btn.disabled = true;
        return;
      }
      setTimeout(tickUndo, 250);
    }
    tickUndo();
  }
  function apiUrl(form) { try { return '/api' + new URL(form.action, location.origin).pathname; } catch (e) { return null; } }
  function field(form, name) { var el = form.querySelector('[name=' + name + ']'); return el ? el.value : ''; }
  function snoozeFields(root) { return { snooze_until: field(root, 'snooze_until'), snooze_custom: field(root, 'snooze_custom') }; }
  function post(url, params) {
    var body = new URLSearchParams();
    Object.keys(params).forEach(function (k) { body.append(k, params[k]); });
    return fetch(url, {
      method: 'POST', credentials: 'same-origin',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json' },
      body: body.toString()
    }).then(function (r) { return r.ok; });
  }

  // ---- optimistic per-message actions ------------------------------------
  function inverse(op) { return op === 'star' ? 'unstar' : op === 'unstar' ? 'star' : op === 'unread' ? 'read' : op === 'read' ? 'unread' : op === 'mute' ? 'unmute' : 'mute'; }
  function applyToggle(row, form, op) {
    if (op === 'star' || op === 'unstar') {
      var on = op === 'star';
      var btn = form.querySelector('button[name=op][value=star],button[name=op][value=unstar]');
      if (btn) { btn.value = on ? 'unstar' : 'star'; btn.title = on ? 'Unstar' : 'Star'; btn.textContent = on ? '★' : '☆'; }
      if (row) {
        row.setAttribute('data-starred', on ? 'true' : 'false');
        var slot = row.querySelector('.mailrow .star-slot');
        if (slot) {
          var st = slot.querySelector('.star');
          if (on && !st) {
            var sp = document.createElement('span'); sp.className = 'star on';
            sp.setAttribute('aria-label', 'starred'); sp.textContent = '★';
            slot.appendChild(sp);
          } else if (!on && st) { st.remove(); }
        }
      }
    } else if (op === 'unread' || op === 'read') {
      if (row) {
        var mr = row.querySelector('.mailrow');
        if (mr) {
          mr.classList.toggle('unseen', op === 'unread');
          var dot = mr.querySelector('.dot'); if (dot) { dot.className = op === 'unread' ? 'dot' : 'dot seen'; }
        }
        row.setAttribute('data-seen', op === 'read' ? 'true' : 'false');
      }
      var ub = form.querySelector('button[name=op][value=read],button[name=op][value=unread]');
      if (ub) {
        var toUnread = op === 'unread';
        ub.value = toUnread ? 'read' : 'unread';
        ub.title = toUnread ? 'Mark read' : 'Mark unread';
        ub.textContent = toUnread ? 'Read' : 'Unread';
      }
    } else if (op === 'mute' || op === 'unmute') {
      var muted = op === 'mute';
      if (row) {
        row.setAttribute('data-muted', muted ? 'true' : 'false');
        row.classList.toggle('is-muted', muted);
      }
      var mb = form.querySelector('button[name=op][value=mute],button[name=op][value=unmute]');
      if (mb) {
        mb.value = muted ? 'unmute' : 'mute';
        mb.title = muted ? 'Unmute thread' : 'Mute thread';
        mb.textContent = muted ? 'Unmute' : 'Mute';
      }
    }
  }
  function enhanceAction(form) {
    form.addEventListener('submit', function (e) {
      var btn = e.submitter; if (!btn || btn.name !== 'op') return;
      var op = btn.value, url = apiUrl(form); if (!url) return;
      var row = form.closest('.mailrow-wrap'), inList = !!form.closest('.maillist');
      if (op === 'star' || op === 'unstar' || op === 'read' || op === 'unread' || op === 'mute' || op === 'unmute') {
        e.preventDefault();
        applyToggle(row, form, op);
        post(url, { csrf: field(form, 'csrf'), op: op }).then(function (ok) {
          if (!ok) { applyToggle(row, form, inverse(op)); toast('Action failed', 'err'); }
        }).catch(function () { applyToggle(row, form, inverse(op)); toast('Action failed', 'err'); });
        return;
      }
      if (op === 'archive' || op === 'delete' || op === 'move' || op === 'report_spam' || op === 'not_spam' || op === 'snooze' || op === 'unsnooze') {
        var folder = op === 'move' ? field(form, 'folder') : '';
        if (op === 'move' && !folder) { e.preventDefault(); toast('Choose a folder to move to', 'err'); return; }
        var snooze = snoozeFields(form);
        if (op === 'snooze' && !snooze.snooze_until && !snooze.snooze_custom) { e.preventDefault(); toast('Choose a snooze time', 'err'); return; }
        if (inList && row) {
          e.preventDefault();
          var parent = row.parentNode, next = row.nextSibling;
          row.remove();
          post(url, { csrf: field(form, 'csrf'), op: op, folder: folder, snooze_until: snooze.snooze_until, snooze_custom: snooze.snooze_custom }).then(function (ok) {
            if (ok) { toast(op === 'delete' ? 'Moved to Trash' : op === 'archive' ? 'Archived' : op === 'report_spam' ? 'Reported spam' : op === 'not_spam' ? 'Moved to Inbox' : op === 'snooze' ? 'Snoozed' : op === 'unsnooze' ? 'Moved to Inbox' : 'Moved', 'ok'); }
            else { if (next) parent.insertBefore(row, next); else parent.appendChild(row); toast('Action failed', 'err'); }
          }).catch(function () { if (next) parent.insertBefore(row, next); else parent.appendChild(row); toast('Action failed', 'err'); });
        }
        // read view (not in a list): fall through to the native form POST + navigation.
      }
    });
  }
  document.querySelectorAll('form.row-actions').forEach(function (form) {
    if (/\/m\/[^/]+\/action$/.test(form.getAttribute('action') || '')) enhanceAction(form);
  });

  // ---- view-transition open tile stamp (pane=off list -> read) -----------
  document.addEventListener('mousedown', function (e) {
    var link = e.target && e.target.closest ? e.target.closest('a.mailrow') : null;
    if (!link) return;
    if ((window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches) || !document.startViewTransition || document.querySelector('.mailbox-layout')) return;
    document.querySelectorAll('.co-tile.co-open').forEach(function (tile) { tile.classList.remove('co-open'); });
    var tile = link.querySelector('.co-tile');
    if (tile) tile.classList.add('co-open');
  });

  // ---- multi-select + sticky bulk toolbar --------------------------------
  var bar = document.querySelector('[data-bulkbar]');
  if (bar) {
    var checks = Array.prototype.slice.call(document.querySelectorAll('.rowcheck'));
    var countEl = bar.querySelector('[data-bulk-count]');
    function selectedRows() { return Array.prototype.slice.call(document.querySelectorAll('.mailrow-wrap.is-selected')); }
    function refresh() { var n = selectedRows().length; if (countEl) countEl.textContent = n + ' selected'; bar.hidden = n === 0; }
    function clearAll() { checks.forEach(function (c) { c.checked = false; var r = c.closest('.mailrow-wrap'); if (r) r.classList.remove('is-selected'); }); refresh(); }
    checks.forEach(function (c) {
      c.addEventListener('change', function () { var r = c.closest('.mailrow-wrap'); if (r) r.classList.toggle('is-selected', c.checked); refresh(); });
    });
    var clearBtn = bar.querySelector('[data-bulk-clear]'); if (clearBtn) clearBtn.addEventListener('click', clearAll);
    bar.querySelectorAll('[data-bulk]').forEach(function (b) {
      b.addEventListener('click', function () {
        var op = b.getAttribute('data-bulk'), rows = selectedRows(); if (!rows.length) return;
        var ids = rows.map(function (r) { return r.getAttribute('data-id'); }).filter(Boolean);
        var csrf = bar.getAttribute('data-csrf');
        if (op === 'mute' || op === 'unmute') {
          var muted = op === 'mute';
          var changedMute = rows.map(function (r) { var prev = r.getAttribute('data-muted') === 'true'; r.setAttribute('data-muted', muted ? 'true' : 'false'); r.classList.toggle('is-muted', muted); return { row: r, prev: prev }; });
          post('/api/m/bulk', { csrf: csrf, op: op, ids: ids.join(',') }).then(function (ok) {
            if (ok) { toast(ids.length + ' ' + (muted ? 'muted' : 'unmuted'), 'ok'); clearAll(); }
            else { changedMute.forEach(function (c) { c.row.setAttribute('data-muted', c.prev ? 'true' : 'false'); c.row.classList.toggle('is-muted', c.prev); }); toast('Bulk action failed', 'err'); }
          }).catch(function () { changedMute.forEach(function (c) { c.row.setAttribute('data-muted', c.prev ? 'true' : 'false'); c.row.classList.toggle('is-muted', c.prev); }); toast('Bulk action failed', 'err'); });
          return;
        }
        if (op === 'read') {
          var changed = rows.map(function (r) {
            var mr = r.querySelector('.mailrow'), was = mr && mr.classList.contains('unseen');
            if (mr) { mr.classList.remove('unseen'); var d = mr.querySelector('.dot'); if (d) d.className = 'dot seen'; }
            r.setAttribute('data-seen', 'true'); return { row: r, was: was };
          });
          post('/api/m/bulk', { csrf: csrf, op: op, ids: ids.join(',') }).then(function (ok) {
            if (ok) { toast(ids.length + ' marked read', 'ok'); clearAll(); }
            else { changed.forEach(function (c) { if (c.was) { var mr = c.row.querySelector('.mailrow'); if (mr) { mr.classList.add('unseen'); var d = mr.querySelector('.dot'); if (d) d.className = 'dot'; } } }); toast('Bulk action failed', 'err'); }
          }).catch(function () { toast('Bulk action failed', 'err'); });
          return;
        }
        var folder = '';
        if (op === 'move') { var sel = bar.querySelector('[data-bulk-folder]'); folder = sel ? sel.value : ''; if (!folder) { toast('Choose a folder to move to', 'err'); return; } }
        var snooze = snoozeFields(bar);
        if (op === 'snooze' && !snooze.snooze_until && !snooze.snooze_custom) { toast('Choose a snooze time', 'err'); return; }
        var det = rows.map(function (r) { return { row: r, parent: r.parentNode, next: r.nextSibling }; });
        det.forEach(function (d) { d.row.remove(); });
        post('/api/m/bulk', { csrf: csrf, op: op, folder: folder, snooze_until: snooze.snooze_until, snooze_custom: snooze.snooze_custom, ids: ids.join(',') }).then(function (ok) {
          if (ok) { toast(ids.length + ' ' + (op === 'delete' ? 'deleted' : op === 'archive' ? 'archived' : op === 'report_spam' ? 'reported spam' : op === 'not_spam' ? 'moved to Inbox' : op === 'snooze' ? 'snoozed' : op === 'unsnooze' ? 'moved to Inbox' : 'moved'), 'ok'); clearAll(); }
          else { det.forEach(function (d) { if (d.next) d.parent.insertBefore(d.row, d.next); else d.parent.appendChild(d.row); }); toast('Bulk action failed', 'err'); }
        }).catch(function () { det.forEach(function (d) { if (d.next) d.parent.insertBefore(d.row, d.next); else d.parent.appendChild(d.row); }); toast('Bulk action failed', 'err'); });
      });
    });
    refresh();
  }

  // ---- keyboard navigation (list views) ----------------------------------
  var list = document.querySelector('.maillist');
  if (list) {
    function rows() { return Array.prototype.slice.call(list.querySelectorAll('.mailrow-wrap')); }
    function cursorIndex(rs) { for (var i = 0; i < rs.length; i++) if (rs[i].classList.contains('is-cursor')) return i; return -1; }
    function setCursor(i) { var rs = rows(); if (!rs.length) return; if (i < 0) i = 0; if (i >= rs.length) i = rs.length - 1; rs.forEach(function (r) { r.classList.remove('is-cursor'); }); rs[i].classList.add('is-cursor'); rs[i].scrollIntoView({ block: 'nearest' }); }
    document.addEventListener('keydown', function (e) {
      if (e.defaultPrevented || e.metaKey || e.ctrlKey || e.altKey) return;
      var t = e.target; if (t && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || t.tagName === 'SELECT' || t.isContentEditable)) return;
      if (e.key === 'c') { e.preventDefault(); location.href = '/compose'; return; }
      if (e.key === '/') { var search = document.querySelector('.search-box input[type=search]'); if (search) { e.preventDefault(); search.focus(); } return; }
      var rs = rows(); if (!rs.length) return; var i = cursorIndex(rs), cur = i >= 0 ? rs[i] : null;
      function clickBtn(val) { if (!cur || !cur.getAttribute('data-id')) return; var b = cur.querySelector('button[name=op][value=' + val + ']'); if (b) { e.preventDefault(); b.click(); setCursor(Math.min(i, rows().length - 1)); } }
      switch (e.key) {
        case 'j': e.preventDefault(); setCursor(i < 0 ? 0 : i + 1); break;
        case 'k': e.preventDefault(); setCursor(i < 0 ? 0 : i - 1); break;
        case 'Enter': if (cur) { var a = cur.querySelector('a.mailrow'); if (a) { e.preventDefault(); location.href = a.getAttribute('href'); } } break;
        case 'x': if (cur) { var c = cur.querySelector('.rowcheck'); if (c) { e.preventDefault(); c.checked = !c.checked; c.dispatchEvent(new Event('change', { bubbles: true })); } } break;
        case 'e': clickBtn('archive'); break;
        case '#': clickBtn('delete'); break;
        case 'r': if (cur && cur.getAttribute('data-id')) { e.preventDefault(); location.href = '/compose?reply=' + encodeURIComponent(cur.getAttribute('data-id')); } break;
        case 's': if (cur) clickBtn(cur.getAttribute('data-starred') === 'true' ? 'unstar' : 'star'); break;
      }
    });
  }

  // ---- keyboard shortcuts (pane=off read view) ---------------------------
  var readPane = document.querySelector('[data-read-pane]');
  if (readPane && !document.querySelector('.maillist')) {
    document.addEventListener('keydown', function (e) {
      if (e.defaultPrevented || e.metaKey || e.ctrlKey || e.altKey) return;
      var t = e.target; if (t && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || t.tagName === 'SELECT' || t.isContentEditable)) return;
      var form = readPane.querySelector('form.row-actions');
      function go(sel) { var a = readPane.querySelector(sel); if (a) { e.preventDefault(); location.href = a.getAttribute('href'); } }
      function clickRead(val) { var b = form && form.querySelector('button[name=op][value=' + val + ']'); if (b) { e.preventDefault(); b.click(); } }
      switch (e.key) {
        case 'r': go('.msg-actions a[href^="/compose?reply="]'); break;
        case 'f': go('.msg-actions a[href^="/compose?forward="]'); break;
        case 'a':
        case 'e': clickRead('archive'); break;
        case '#': clickRead('delete'); break;
        case 's': var star = form && form.querySelector('button[name=op][value=star],button[name=op][value=unstar]'); if (star) { e.preventDefault(); star.click(); } break;
      }
    });
  }

  // ---- conversation collapse/expand --------------------------------------
  var convo = Array.prototype.slice.call(document.querySelectorAll('[data-convo-item]'));
  if (convo.length > 1) {
    convo.forEach(function (item, idx) {
      var toggle = item.querySelector('[data-convo-toggle]'); if (!toggle) return;
      function set(collapsed) { item.classList.toggle('is-collapsed', collapsed); toggle.setAttribute('aria-expanded', collapsed ? 'false' : 'true'); toggle.textContent = collapsed ? 'Expand' : 'Collapse'; }
      if (idx < convo.length - 1) set(true);
      toggle.addEventListener('click', function () { set(!item.classList.contains('is-collapsed')); });
    });
  }
})();
"#;

/// Compose-form enhancement layer (additive; the plain form still submits with JS off). Adds a
/// subject character counter, debounced Drafts autosave, an in-flight ("Sending…"/"Saving…") button
/// state, a client-side recipient check before send, and a blur-rendered recipient-chip reflection of
/// the To/Cc fields (the text inputs stay the canonical `name=` source of truth).
const COMPOSE_UX_JS: &str = r#"
(function () {
  var toast = window.__corvidToast || function () {};
  var form = document.querySelector('form[action="/send"]'); if (!form) return;

  var body = form.querySelector('#body');
  var rich = form.querySelector('#body-rich');
  var bodyHtml = form.querySelector('#body_html');
  var toolbar = form.querySelector('[data-compose-toolbar]');
  function escapeHtml(s) {
    return (s || '').replace(/[&<>"']/g, function (c) {
      return c === '&' ? '&amp;' : c === '<' ? '&lt;' : c === '>' ? '&gt;' : c === '"' ? '&quot;' : '&#39;';
    });
  }
  function textToHtml(s) {
    var lines = (s || '').replace(/\r\n/g, '\n').replace(/\r/g, '\n').split('\n');
    var html = [], para = [], quote = [];
    function flushPara() {
      if (!para.length) return;
      html.push('<p>' + para.map(escapeHtml).join('<br>') + '</p>');
      para = [];
    }
    function flushQuote() {
      if (!quote.length) return;
      html.push('<blockquote>' + quote.map(escapeHtml).join('<br>') + '</blockquote>');
      quote = [];
    }
    lines.forEach(function (line) {
      if (/^>\s?/.test(line)) {
        flushPara();
        quote.push(line.replace(/^>\s?/, ''));
        return;
      }
      if (line.trim() === '') {
        flushPara(); flushQuote();
        return;
      }
      flushQuote();
      para.push(line);
    });
    flushPara(); flushQuote();
    return html.join('');
  }
  function syncRich() {
    if (!rich || !body || !bodyHtml) return;
    bodyHtml.value = rich.innerHTML;
    var text = rich.innerText != null ? rich.innerText : (rich.textContent || '');
    body.value = text.replace(/\u00a0/g, ' ');
  }
  if (body && rich && bodyHtml && toolbar) {
    rich.innerHTML = bodyHtml.value || textToHtml(body.value);
    toolbar.hidden = false;
    rich.hidden = false;
    body.hidden = true;
    rich.addEventListener('input', syncRich);
    toolbar.querySelectorAll('[data-cmd]').forEach(function (btn) {
      btn.addEventListener('click', function (e) {
        e.preventDefault();
        rich.focus();
        var cmd = btn.getAttribute('data-cmd');
        if (cmd === 'createLink') {
          var href = window.prompt('Link URL');
          if (href === null) return;
          href = href.trim();
          if (href) document.execCommand('createLink', false, href);
          else document.execCommand('unlink', false, null);
        } else if (cmd === 'blockquote') {
          document.execCommand('formatBlock', false, 'blockquote');
        } else if (cmd === 'clear') {
          document.execCommand('removeFormat', false, null);
          document.execCommand('unlink', false, null);
        } else {
          document.execCommand(cmd, false, null);
        }
        syncRich();
      });
    });
    syncRich();
  }

  function htmlToText(html) {
    var tmp = document.createElement('div');
    tmp.innerHTML = html || '';
    return tmp.innerText != null ? tmp.innerText : (tmp.textContent || '');
  }
  function insertPlainText(text) {
    if (!body) return;
    var start = typeof body.selectionStart === 'number' ? body.selectionStart : body.value.length;
    var end = typeof body.selectionEnd === 'number' ? body.selectionEnd : start;
    body.value = body.value.slice(0, start) + text + body.value.slice(end);
    body.selectionStart = body.selectionEnd = start + text.length;
    body.focus();
  }
  function insertTemplate() {
    var select = form.querySelector('[data-template-select]');
    if (!select || !select.value) return;
    var opt = select.options[select.selectedIndex];
    if (!opt) return;
    var html = opt.getAttribute('data-body-html') || '';
    var text = opt.getAttribute('data-body-text') || '';
    if (rich && !rich.hidden) {
      rich.focus();
      document.execCommand('insertHTML', false, html || textToHtml(text));
      syncRich();
    } else {
      insertPlainText(text || htmlToText(html));
    }
    select.selectedIndex = 0;
    toast('Template inserted', 'ok');
    scheduleAutosave(800);
  }
  var templateSelect = form.querySelector('[data-template-select]');
  if (templateSelect) {
    templateSelect.addEventListener('change', function () { if (templateSelect.value) insertTemplate(); });
  }
  var templateButton = form.querySelector('[data-template-insert]');
  if (templateButton) {
    templateButton.addEventListener('click', function (e) { e.preventDefault(); insertTemplate(); });
  }

  function decodeData(v) {
    try { return decodeURIComponent(v || ''); } catch (_) { return ''; }
  }
  function encodeData(v) {
    try { return encodeURIComponent(v || ''); } catch (_) { return ''; }
  }
  var identitySelect = form.querySelector('[name="identity"]');
  var initialSignatureText = decodeData(form.getAttribute('data-current-signature-text'));
  var initialSignatureHtml = decodeData(form.getAttribute('data-current-signature-html'));
  var initialBodyText = body ? body.value : '';
  var initialBodyHtml = bodyHtml ? bodyHtml.value : '';
  function selectedSignature(attr) {
    if (!identitySelect) return '';
    var opt = identitySelect.options[identitySelect.selectedIndex];
    return opt ? decodeData(opt.getAttribute(attr)) : '';
  }
  function currentHtml() {
    if (rich && !rich.hidden) return rich.innerHTML;
    return bodyHtml ? bodyHtml.value : '';
  }
  function setCurrentSignature(text, html) {
    form.setAttribute('data-current-signature-text', encodeData(text));
    form.setAttribute('data-current-signature-html', encodeData(html));
  }
  function replaceSignatureForIdentity() {
    if (!identitySelect || !body) return;
    syncRich();
    var oldText = decodeData(form.getAttribute('data-current-signature-text'));
    var oldHtml = decodeData(form.getAttribute('data-current-signature-html'));
    var newText = selectedSignature('data-signature-text');
    var newHtml = selectedSignature('data-signature-html');
    var html = currentHtml();
    var changed = false;

    if (oldHtml && html.slice(-oldHtml.length) === oldHtml) {
      if (rich && !rich.hidden) {
        rich.innerHTML = html.slice(0, -oldHtml.length) + newHtml;
      } else if (bodyHtml) {
        bodyHtml.value = html.slice(0, -oldHtml.length) + newHtml;
      }
      syncRich();
      changed = true;
    } else if (oldText && body.value.slice(-oldText.length) === oldText) {
      body.value = body.value.slice(0, -oldText.length) + newText;
      if (rich && !rich.hidden) rich.innerHTML = textToHtml(body.value);
      if (bodyHtml && oldHtml && bodyHtml.value.slice(-oldHtml.length) === oldHtml) {
        bodyHtml.value = bodyHtml.value.slice(0, -oldHtml.length) + newHtml;
      }
      syncRich();
      changed = true;
    } else if (!oldText && !oldHtml && body.value === initialBodyText && html === initialBodyHtml) {
      if (newHtml && rich && !rich.hidden) {
        rich.innerHTML = (html || textToHtml(body.value)) + newHtml;
        syncRich();
      } else {
        body.value = body.value + newText;
        if (rich && !rich.hidden) rich.innerHTML = textToHtml(body.value);
        syncRich();
      }
      changed = !!(newText || newHtml);
    }

    if (changed) {
      setCurrentSignature(newText, newHtml);
      initialSignatureText = newText;
      initialSignatureHtml = newHtml;
      scheduleAutosave(800);
    }
  }
  if (identitySelect) {
    identitySelect.addEventListener('change', replaceSignatureForIdentity);
    setCurrentSignature(initialSignatureText, initialSignatureHtml);
  }

  var subject = form.querySelector('#subject');
  if (subject) {
    var cc = document.createElement('span'); cc.className = 'charcount';
    subject.insertAdjacentElement('afterend', cc);
    var MAX = 200;
    function upd() { var n = subject.value.length; cc.textContent = n + ' / ' + MAX; cc.classList.toggle('over', n > MAX); }
    subject.addEventListener('input', upd); upd();
  }

  function chipify(input) {
    if (!input) return;
    var combo = input.closest('.combo') || input;
    var wrap = document.createElement('div'); wrap.className = 'chips'; wrap.hidden = true;
    combo.parentNode.insertBefore(wrap, combo.nextSibling);
    function tokens() { return input.value.split(',').map(function (s) { return s.trim(); }).filter(Boolean); }
    function render() {
      wrap.textContent = ''; var list = tokens();
      list.forEach(function (tok, idx) {
        var chip = document.createElement('span'); chip.className = 'chip';
        var lbl = document.createElement('span'); lbl.textContent = tok; chip.appendChild(lbl);
        var x = document.createElement('button'); x.type = 'button'; x.className = 'chip__x';
        x.setAttribute('aria-label', 'Remove ' + tok); x.textContent = '×';
        x.addEventListener('click', function () { var l = tokens(); l.splice(idx, 1); input.value = l.length ? l.join(', ') + ', ' : ''; input.dispatchEvent(new Event('input', { bubbles: true })); render(); input.focus(); });
        chip.appendChild(x); wrap.appendChild(chip);
      });
      wrap.hidden = list.length === 0;
    }
    input.addEventListener('input', function () { wrap.hidden = true; });
    input.addEventListener('blur', function () { setTimeout(render, 160); });
    render();
  }
  chipify(form.querySelector('#to'));
  chipify(form.querySelector('#cc'));

  var autosaveStatus = form.querySelector('[data-autosave-status]');
  var draftId = form.querySelector('input[name="draft_id"]');
  var autosaveTimer = null, autosaveInFlight = false, autosaveQueued = false, autosaveStopped = false;
  var autosaveController = null;
  function setAutosaveStatus(text) {
    if (autosaveStatus) autosaveStatus.textContent = text || '';
  }
  function named(name) { return form.querySelector('[name="' + name + '"]'); }
  function val(name) { var el = named(name); return el ? el.value : ''; }
  function hasDraftContent() {
    syncRich();
    return !!(val('to').trim() || val('cc').trim() || val('subject').trim() || val('body').trim() || val('body_html').trim());
  }
  function autosavePayload() {
    syncRich();
    var data = new URLSearchParams();
    ['csrf', 'draft_id', 'attachment_refs', 'to', 'cc', 'subject', 'body', 'body_html', 'in_reply_to', 'references', 'identity'].forEach(function (name) {
      data.set(name, val(name));
    });
    data.set('body_text', val('body'));
    return data;
  }
  function scheduleAutosave(delay) {
    if (autosaveStopped) return;
    if (autosaveTimer) clearTimeout(autosaveTimer);
    autosaveTimer = setTimeout(runAutosave, delay || 2500);
  }
  function runAutosave() {
    if (autosaveStopped || !draftId || !hasDraftContent()) return;
    if (autosaveInFlight) { autosaveQueued = true; return; }
    autosaveInFlight = true;
    autosaveController = window.AbortController ? new AbortController() : null;
    setAutosaveStatus('Saving…');
    fetch('/compose/autosave', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json' },
      body: autosavePayload(),
      signal: autosaveController ? autosaveController.signal : undefined
    }).then(function (r) {
      if (!r.ok) throw new Error('autosave failed');
      return r.json();
    }).then(function (data) {
      if (data && data.draft_id) draftId.value = data.draft_id;
      setAutosaveStatus('Saved just now');
    }).catch(function (err) {
      if (err && err.name === 'AbortError') return;
      setAutosaveStatus('Autosave failed');
    }).finally(function () {
      autosaveInFlight = false; autosaveController = null;
      if (autosaveQueued && !autosaveStopped) { autosaveQueued = false; scheduleAutosave(800); }
    });
  }
  ['to', 'cc', 'subject', 'body', 'body_html', 'identity'].forEach(function (name) {
    var el = named(name);
    if (el) el.addEventListener('input', function () { scheduleAutosave(2500); });
    if (el && el.tagName === 'SELECT') el.addEventListener('change', function () { scheduleAutosave(800); });
  });
  if (rich) rich.addEventListener('input', function () { scheduleAutosave(2500); });

  form.addEventListener('submit', function (e) {
    syncRich();
    var btn = e.submitter, action = btn ? btn.value : 'send';
    if (action === 'send') {
      var to = form.querySelector('#to');
      if (to && !to.value.trim()) { e.preventDefault(); toast('Add at least one recipient', 'err'); to.focus(); return; }
    }
    autosaveStopped = true;
    if (autosaveTimer) clearTimeout(autosaveTimer);
    if (autosaveController) autosaveController.abort();
    // Disable AFTER the submit is queued so the submitter's name/value still posts.
    if (btn) setTimeout(function () { btn.disabled = true; btn.classList.add('is-busy'); btn.textContent = action === 'draft' ? 'Saving…' : 'Sending…'; }, 0);
  });
})();
"#;
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
const ICO_SETTINGS: &str = r#"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z"/><circle cx="12" cy="12" r="3"/></svg>"#;
const ICO_PENCIL: &str = r#"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 20h9"/><path d="M16.5 3.5a2.12 2.12 0 0 1 3 3L7 19l-4 1 1-4Z"/></svg>"#;
const ICO_SEND: &str = r#"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m22 2-7 20-4-9-9-4Z"/><path d="M22 2 11 13"/></svg>"#;
const ICO_DRAFT: &str = r#"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M15 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7Z"/><path d="M14 2v4a2 2 0 0 0 2 2h4"/><path d="M10 12h4"/><path d="M10 16h4"/></svg>"#;
const ICO_ARCHIVE: &str = r#"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="3" width="18" height="4" rx="1"/><path d="M5 7v12a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V7"/><path d="M10 12h4"/></svg>"#;
const ICO_SPAM: &str = r#"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 9v4"/><path d="M12 17h.01"/><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0Z"/></svg>"#;
const ICO_TRASH: &str = r#"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M3 6h18"/><path d="M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/><path d="M19 6 18 20a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/></svg>"#;
const ICO_CLOCK: &str = r#"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/></svg>"#;
const ICO_CAL: &str = r#"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M8 2v4"/><path d="M16 2v4"/><rect x="3" y="4" width="18" height="18" rx="2"/><path d="M3 10h18"/></svg>"#;
const ICO_STAR: &str = r#"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m12 2 3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01Z"/></svg>"#;
const ICO_CLIP: &str = r#"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m21.44 11.05-9.19 9.19a6 6 0 0 1-8.49-8.49l9.19-9.19a4 4 0 0 1 5.66 5.66l-9.2 9.19a2 2 0 1 1-2.83-2.83l8.49-8.48"/></svg>"#;

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
        .route("/search/advanced", get(advanced_search))
        .route("/t", get(conversation))
        .route("/m/{id}", get(read_message))
        .route("/m/{id}/action", post(message_action))
        // JSON siblings of the form routes above — progressive enhancement for the optimistic,
        // no-reload row/bulk actions. Same double-submit CSRF + owner authz + audit; small JSON out.
        .route("/api/m/{id}/action", post(api_message_action))
        .route("/api/m/bulk", post(api_bulk_action))
        .route("/m/{id}/labels", post(message_labels_post))
        .route("/m/{id}/attachments/{idx}", get(download_attachment))
        .route("/compose", get(compose_form))
        .route("/compose/autosave", post(compose_autosave))
        .route("/send", post(send))
        .route("/send/undo", post(send_undo))
        .route("/scheduled/{batch_id}/action", post(scheduled_action))
        .route("/api/send", post(api_send))
        .route("/contacts/suggest", get(contacts_suggest))
        // Progressive-enhancement JS, served as cacheable static assets (never inlined).
        .route("/assets/webmail.js", get(asset_webmail_js))
        .route("/assets/compose.js", get(asset_compose_js))
        .route("/settings", get(settings_page))
        .route(
            "/settings/rules",
            get(settings_rules_redirect).post(settings_rules_post),
        )
        .route("/settings/signature", post(settings_signature))
        .route(
            "/settings/signatures",
            get(settings_signatures_redirect).post(settings_signatures_post),
        )
        .route("/settings/undo-send", post(settings_undo_send))
        .route("/settings/preferences", post(settings_preferences))
        .route("/settings/autoreply", post(settings_autoreply))
        .route(
            "/settings/templates",
            get(settings_templates_redirect).post(settings_templates_post),
        )
        .route("/settings/identities", post(settings_identities_post))
        .route("/settings/labels", post(settings_labels_post))
        .route("/settings/contacts", post(settings_contacts_post))
        .route(
            "/settings/contact-groups",
            post(settings_contact_groups_post),
        )
        .route("/settings/contacts/import", post(settings_contacts_import))
        .route("/settings/contacts/export", get(settings_contacts_export))
        .route("/settings/senders", post(settings_senders_post))
        .merge(admin)
        // Reject a forged gateway identity (spoofed X-Auth-* from a rogue in-network peer):
        // when GATEWAY_HMAC_KEY is set, an injected identity MUST carry a valid X-Auth-Sig.
        // No-op when the key is unset or no identity is present (healthz / local dev).
        .layer(axum::middleware::from_fn(require_gateway_sig))
        .with_state(state)
}

/// Middleware enforcing [`require_admin`] on the /admin subtree — renders a 403 page for any
/// signed-in user who is not in an [`ADMIN_GROUPS`] group.
async fn require_admin_mw(req: axum::extract::Request, next: axum::middleware::Next) -> Response {
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

/// `GET /assets/webmail.js` — the inbox/read/conversation progressive-enhancement bundle (toast +
/// optimistic actions + multi-select bulk toolbar + keyboard nav + conversation collapse). Served
/// as a cacheable static asset (not inlined) so the pages carry no inline `<script>`.
async fn asset_webmail_js() -> Response {
    js_asset(&format!(
        "{TOAST_JS}\n{WEBMAIL_JS}\n{}",
        odyssey::MOTION_JS
    ))
}

/// `GET /assets/compose.js` — the compose bundle (contacts autocomplete + toast + subject counter,
/// in-flight send state, and the recipient-chip reflection).
async fn asset_compose_js() -> Response {
    js_asset(&format!("{COMPOSE_JS}\n{TOAST_JS}\n{COMPOSE_UX_JS}"))
}

/// Wrap a JS body in a cacheable `application/javascript` response.
fn js_asset(body: &str) -> Response {
    (
        [
            (
                header::CONTENT_TYPE,
                "application/javascript; charset=utf-8",
            ),
            (header::CACHE_CONTROL, "public, max-age=3600"),
        ],
        body.to_string(),
    )
        .into_response()
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
    /// `threads` collapses the folder into conversations; anything else lists messages.
    #[serde(default)]
    view: Option<String>,
    /// A label id to filter by (a flat cross-folder listing of that label's messages).
    #[serde(default)]
    label: Option<String>,
    /// Opaque outbound batch reference for the post-send undo bar.
    #[serde(default)]
    undo: Option<String>,
    /// Epoch seconds when the undo window closes.
    #[serde(default)]
    undo_until: Option<String>,
}

/// Query string for `GET /search/advanced`. The same page both renders the independent advanced
/// form and, when submitted, redirects to either the existing search results or the rule prefill.
#[derive(Deserialize, Default)]
struct AdvancedSearchQuery {
    #[serde(default)]
    from: String,
    #[serde(default)]
    to: String,
    #[serde(default)]
    subject: String,
    #[serde(default)]
    has_words: String,
    #[serde(default)]
    doesnt_have: String,
    #[serde(default)]
    size_cmp: String,
    #[serde(default)]
    size: String,
    #[serde(default)]
    size_unit: String,
    #[serde(default)]
    after: String,
    #[serde(default)]
    before: String,
    #[serde(default)]
    folder: String,
    #[serde(default)]
    has_attachment: Option<String>,
    #[serde(default)]
    mode: String,
}

impl AdvancedSearchQuery {
    fn has_input(&self) -> bool {
        !self.from.trim().is_empty()
            || !self.to.trim().is_empty()
            || !self.subject.trim().is_empty()
            || !self.has_words.trim().is_empty()
            || !self.doesnt_have.trim().is_empty()
            || !self.size.trim().is_empty()
            || !self.after.trim().is_empty()
            || !self.before.trim().is_empty()
            || !self.folder.trim().is_empty()
            || self.has_attachment.is_some()
    }
}

async fn advanced_search(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<AdvancedSearchQuery>,
) -> Response {
    let email = email_display(&headers);
    let Some(mb) = resolve_mailbox(&state, &headers).await else {
        return no_mailbox_page(&email);
    };
    let settings = settings_for_page(&state, &mb.addr).await;
    let prefs = page_prefs(&settings);

    if q.has_input() {
        if let Some(search) = build_advanced_search_query(&q) {
            let href = if q.mode == "filter" {
                format!("/settings?filter_q={}#filter-rules", url_encode(&search))
            } else {
                format!("/?q={}", url_encode(&search))
            };
            return Redirect::to(&href).into_response();
        }
    }

    let content = render_advanced_search_form(&q);
    Html(render_page_with_prefs(
        "Advanced search",
        &email,
        &content,
        "inbox",
        prefs,
    ))
    .into_response()
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
    let undo_bar = render_undo_bar(q.undo.as_deref(), q.undo_until.as_deref(), &token);

    let search = q.q.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let parsed_search = search.map(parse_search_query);
    let limit = clamp_limit(q.limit);
    let cursor = parse_cursor(q.before.as_deref());
    // The mailbox's labels drive both the tab strip and the label-filter view.
    let labels = state.store.list_labels(&mb.addr).await.unwrap_or_default();
    let counts = state
        .store
        .folder_counts(&mb.addr)
        .await
        .unwrap_or_default();
    let settings = settings_for_page(&state, &mb.addr).await;
    let prefs = page_prefs(&settings);

    // Label-filter view: a flat, cross-folder listing of one label's messages.
    if let Some(label_id) = q.label.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        let Some(label) = labels.iter().find(|l| l.id == label_id) else {
            return error_page(StatusCode::NOT_FOUND, "Not found", "No such label.");
        };
        let msgs = match state
            .store
            .list_by_label(&mb.addr, label_id, cursor, limit)
            .await
        {
            Ok(m) => m,
            Err(e) => {
                return error_page(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Storage error",
                    &e.to_string(),
                );
            }
        };
        let base = format!("/?label={}&limit={limit}", url_encode(label_id));
        let next_link = next_page_link(&msgs, limit, &base);
        let return_to = base.clone();
        let mut rows = String::new();
        if msgs.is_empty() {
            rows.push_str(&empty_row(
                "No messages with this label.",
                "Apply this label from a message or an \"Add label\" filter rule and it shows up here.",
            ));
        }
        for m in &msgs {
            rows.push_str(&render_row(m, &token, &return_to, prefs));
        }
        let list = render_list_with_optional_read_pane(&rows, prefs);
        let heading = format!(r#"Label: <span class="pill">{}</span>"#, esc(&label.name));
        let main = format!(
            r#"<div class="page-head"><h1>{heading}</h1></div>
{toolbar}
{list}{bulk}{next_link}
{undo_bar}
<script src="/assets/webmail.js"></script>"#,
            toolbar = list_toolbar(&FolderTabs {
                active: "",
                search_q: "",
                scope: None,
                active_label: label_id,
                threads_on: false
            }),
            list = list,
            bulk = bulk_toolbar(&token),
            undo_bar = undo_bar,
        );
        let content = mail_shell(mail_sidebar("", label_id, &labels, &counts), main);
        let html = render_mail_page(&label.name, &email, &content, prefs);
        return match set_cookie {
            Some(c) => ([(header::SET_COOKIE, c)], Html(html)).into_response(),
            None => Html(html).into_response(),
        };
    }

    // Threaded folder view: collapsed conversations for a real folder (not search / not Starred).
    let threads_on = q.view.as_deref() == Some("threads") && search.is_none();
    if threads_on {
        let folder = canonical_folder(q.folder.as_deref());
        if folder != STARRED_VIEW && folder != SNOOZED_VIEW && folder != SCHEDULED_VIEW {
            let threads = match state
                .store
                .list_folder_threads(&mb.addr, folder, cursor, limit)
                .await
            {
                Ok(t) => t,
                Err(e) => {
                    return error_page(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Storage error",
                        &e.to_string(),
                    );
                }
            };
            let mut rows = String::new();
            if threads.is_empty() {
                rows.push_str(&empty_row(
                    "No conversations here.",
                    "Mail you receive and send groups into conversations automatically.",
                ));
            }
            for t in &threads {
                rows.push_str(&render_thread_row(t, prefs));
            }
            let base = format!("/?folder={folder}&view=threads&limit={limit}");
            let next_link = next_thread_link(&threads, limit, &base);
            let heading = if folder == "INBOX" {
                "Inbox".to_string()
            } else {
                esc(folder)
            };
            let list = render_list_with_optional_read_pane(&rows, prefs);
            let main = format!(
                r#"<div class="page-head"><h1>{heading}</h1></div>
{toolbar}
{list}{next_link}
{undo_bar}
<script src="/assets/webmail.js"></script>"#,
                toolbar = list_toolbar(&FolderTabs {
                    active: folder,
                    search_q: "",
                    scope: real_folder(folder).filter(|f| *f != "INBOX"),
                    active_label: "",
                    threads_on: true
                }),
                list = list,
                undo_bar = undo_bar,
            );
            let content = mail_shell(mail_sidebar(folder, "", &labels, &counts), main);
            let html = render_mail_page(folder, &email, &content, prefs);
            return match set_cookie {
                Some(c) => ([(header::SET_COOKIE, c)], Html(html)).into_response(),
                None => Html(html).into_response(),
            };
        }
    }

    if search.is_none() && canonical_folder(q.folder.as_deref()) == SCHEDULED_VIEW {
        let scheduled = match state
            .store
            .list_scheduled_outbound(
                &mb.addr,
                now_secs() + UNDO_SEND_MAX_WINDOW_SECS,
                cursor,
                limit,
            )
            .await
        {
            Ok(s) => s,
            Err(e) => {
                return error_page(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Storage error",
                    &e.to_string(),
                );
            }
        };
        let mut rows = String::new();
        if scheduled.is_empty() {
            rows.push_str(&empty_row(
                "No scheduled sends.",
                "Messages you schedule from Compose show up here until their send time.",
            ));
        }
        for item in &scheduled {
            rows.push_str(&render_scheduled_row(item, &token, prefs));
        }
        let base = format!("/?folder=Scheduled&limit={limit}");
        let next_link = next_scheduled_link(&scheduled, limit, &base);
        let list = render_list_with_optional_read_pane(&rows, prefs);
        let main = format!(
            r#"<div class="page-head"><h1>Scheduled</h1></div>
{toolbar}
{list}{next_link}
{undo_bar}
<script src="/assets/webmail.js"></script>"#,
            toolbar = list_toolbar(&FolderTabs {
                active: SCHEDULED_VIEW,
                search_q: "",
                scope: None,
                active_label: "",
                threads_on: false,
            }),
            list = list,
            undo_bar = undo_bar,
        );
        let content = mail_shell(mail_sidebar(SCHEDULED_VIEW, "", &labels, &counts), main);
        let html = render_mail_page(SCHEDULED_VIEW, &email, &content, prefs);
        return match set_cookie {
            Some(c) => ([(header::SET_COOKIE, c)], Html(html)).into_response(),
            None => Html(html).into_response(),
        };
    }

    // Fetch the rows for the active view, plus the return path row actions redirect back to, a
    // `next` keyset link to the older page (only when this page is full), and the folder the
    // search box scopes to.
    let (folder, heading, msgs, next_link, scope) = if let Some(query) = search {
        let parsed = parsed_search
            .as_ref()
            .expect("parsed search exists when raw search exists");
        // Optional folder scope: only a real folder narrows the search; anything else (absent,
        // unknown, the virtual Starred view) searches the whole mailbox.
        let scope = q.folder.as_deref().and_then(real_folder);
        let msgs = match state
            .store
            .search_messages(&mb.addr, parsed, scope, cursor, limit)
            .await
        {
            Ok(m) => m,
            Err(e) => {
                return error_page(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Storage error",
                    &e.to_string(),
                );
            }
        };
        let mut base = format!("/?q={}&limit={limit}", url_encode(query));
        if let Some(f) = scope {
            base.push_str(&format!("&folder={f}"));
        }
        let heading = match scope {
            Some(f) => format!(
                r#"Search results for &ldquo;{}&rdquo; in {}"#,
                esc(query),
                esc(f)
            ),
            None => format!(r#"Search results for &ldquo;{}&rdquo;"#, esc(query)),
        };
        let next = next_page_link(&msgs, limit, &base);
        // A search hit's return path can't carry the query cheaply — send actions back to the inbox.
        ("", heading, msgs, next, scope)
    } else {
        let folder = canonical_folder(q.folder.as_deref());
        let listed = if folder == STARRED_VIEW {
            state.store.list_starred(&mb.addr, cursor, limit).await
        } else if folder == SNOOZED_VIEW {
            state
                .store
                .list_snoozed(&mb.addr, now_secs(), cursor, limit)
                .await
        } else {
            state
                .store
                .list_folder(&mb.addr, folder, cursor, limit)
                .await
        };
        let msgs = match listed {
            Ok(m) => m,
            Err(e) => {
                return error_page(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Storage error",
                    &e.to_string(),
                );
            }
        };
        let heading = if folder == "INBOX" {
            let unseen = state.store.unseen_count(&mb.addr).await.unwrap_or(0);
            format!("Inbox <span class=\"pill\">{unseen} unread</span>")
        } else {
            esc(folder)
        };
        let next = next_page_link(&msgs, limit, &format!("/?folder={folder}&limit={limit}"));
        // Searching from a folder view scopes to it; the Inbox and virtual views search everything.
        let scope = real_folder(folder).filter(|f| *f != "INBOX");
        (folder, heading, msgs, next, scope)
    };

    // Row actions redirect back to the folder/view they were invoked from (search → inbox).
    let return_to = if folder.is_empty() {
        "/".to_string()
    } else {
        format!("/?folder={folder}")
    };

    let mut rows = String::new();
    if msgs.is_empty() {
        let subtext = if folder.is_empty() {
            "No mail matched your search. Try a different term or clear the search."
        } else {
            "This folder is empty. New mail will appear here."
        };
        rows.push_str(&empty_row("No messages here.", subtext));
    }
    for m in &msgs {
        match parsed_search.as_ref() {
            Some(query) => rows.push_str(&render_search_row(m, &token, &return_to, query, prefs)),
            None => rows.push_str(&render_row(m, &token, &return_to, prefs)),
        }
    }

    let search_actions = search.map(render_search_actions).unwrap_or_default();
    let list = render_list_with_optional_read_pane(&rows, prefs);
    let main = format!(
        r#"<div class="page-head"><h1>{heading}</h1></div>
{toolbar}
{search_actions}
{list}{bulk}{next_link}
{undo_bar}
<script src="/assets/webmail.js"></script>"#,
        toolbar = list_toolbar(&FolderTabs {
            active: folder,
            search_q: search.unwrap_or(""),
            scope,
            active_label: "",
            threads_on: false,
        }),
        list = list,
        bulk = bulk_toolbar(&token),
        undo_bar = undo_bar,
    );
    let title = if folder.is_empty() { "Search" } else { folder };
    let content = mail_shell(mail_sidebar(folder, "", &labels, &counts), main);
    let html = render_mail_page(title, &email, &content, prefs);
    match set_cookie {
        Some(c) => ([(header::SET_COOKIE, c)], Html(html)).into_response(),
        None => Html(html).into_response(),
    }
}

fn render_search_actions(query: &str) -> String {
    let q = url_encode(query);
    format!(
        r#"<div class="search-actions"><a class="btn btn-ghost btn-sm adv-search-link" href="/search/advanced">Advanced search</a><a class="btn btn-ghost btn-sm btn-create-filter" href="/settings?filter_q={q}#filter-rules">Create filter</a></div>"#
    )
}

fn render_advanced_search_form(q: &AdvancedSearchQuery) -> String {
    let size_cmp = match q.size_cmp.trim() {
        "smaller" => "smaller",
        _ => "larger",
    };
    let size_unit = match q.size_unit.trim().to_ascii_lowercase().as_str() {
        "b" => "b",
        "k" | "kb" => "k",
        _ => "m",
    };
    let folder = real_folder(&q.folder).unwrap_or("");
    let has_attachment_checked = if q.has_attachment.is_some() {
        " checked"
    } else {
        ""
    };
    let folder_options = advanced_folder_options(folder);

    format!(
        r#"<div class="page-head"><h1>Advanced search</h1></div>
<section class="card pad adv-search">
  <form class="adv-search__form" method="get" action="/search/advanced">
    <div class="field adv-search__field"><label for="adv_from">From</label><input id="adv_from" name="from" value="{from}"></div>
    <div class="field adv-search__field"><label for="adv_to">To</label><input id="adv_to" name="to" value="{to}"></div>
    <div class="field adv-search__field"><label for="adv_subject">Subject</label><input id="adv_subject" name="subject" value="{subject}"></div>
    <div class="field adv-search__field"><label for="adv_has_words">Has the words</label><input id="adv_has_words" name="has_words" value="{has_words}"></div>
    <div class="field adv-search__field"><label for="adv_doesnt_have">Doesn't have</label><input id="adv_doesnt_have" name="doesnt_have" value="{doesnt_have}"></div>
    <div class="field adv-search__field adv-search__field--size"><label for="adv_size">Size</label><select name="size_cmp" aria-label="Size comparison"><option value="larger"{larger_sel}>Larger than</option><option value="smaller"{smaller_sel}>Smaller than</option></select><input id="adv_size" name="size" inputmode="numeric" value="{size}"><select name="size_unit" aria-label="Size unit"><option value="b"{b_sel}>B</option><option value="k"{k_sel}>KB</option><option value="m"{m_sel}>MB</option></select></div>
    <div class="field adv-search__field"><label for="adv_after">After</label><input id="adv_after" name="after" type="date" value="{after}"></div>
    <div class="field adv-search__field"><label for="adv_before">Before</label><input id="adv_before" name="before" type="date" value="{before}"></div>
    <div class="field adv-search__field"><label for="adv_folder">In folder</label><select id="adv_folder" name="folder">{folder_options}</select></div>
    <div class="field adv-search__field"><label><input type="checkbox" name="has_attachment" value="on"{has_attachment_checked}> Has attachment</label></div>
    <div class="form-actions"><button class="btn btn-primary" type="submit" name="mode" value="search">Search</button><button class="btn btn-ghost btn-create-filter" type="submit" name="mode" value="filter">Create filter</button></div>
  </form>
</section>"#,
        from = esc(&q.from),
        to = esc(&q.to),
        subject = esc(&q.subject),
        has_words = esc(&q.has_words),
        doesnt_have = esc(&q.doesnt_have),
        size = esc(&q.size),
        after = esc(&q.after),
        before = esc(&q.before),
        larger_sel = selected_attr(size_cmp, "larger"),
        smaller_sel = selected_attr(size_cmp, "smaller"),
        b_sel = selected_attr(size_unit, "b"),
        k_sel = selected_attr(size_unit, "k"),
        m_sel = selected_attr(size_unit, "m"),
    )
}

fn advanced_folder_options(selected: &str) -> String {
    let mut out = format!(
        r#"<option value=""{}>Anywhere</option>"#,
        selected_attr(selected, "")
    );
    for f in FOLDERS {
        out.push_str(&format!(
            r#"<option value="{f}"{}>{f}</option>"#,
            selected_attr(selected, f)
        ));
    }
    out
}

fn selected_attr(value: &str, selected: &str) -> &'static str {
    if value == selected {
        " selected"
    } else {
        ""
    }
}

fn build_advanced_search_query(q: &AdvancedSearchQuery) -> Option<String> {
    let mut parts = Vec::new();
    push_search_predicate(&mut parts, "from", &q.from);
    push_search_predicate(&mut parts, "to", &q.to);
    push_search_predicate(&mut parts, "subject", &q.subject);
    push_search_text(&mut parts, &q.has_words, false);
    push_search_text(&mut parts, &q.doesnt_have, true);
    if let Some(size) = advanced_size_clause(&q.size_cmp, &q.size, &q.size_unit) {
        parts.push(size);
    }
    if let Some(after) = valid_search_date(&q.after) {
        parts.push(format!("after:{after}"));
    }
    if let Some(before) = valid_search_date(&q.before) {
        parts.push(format!("before:{before}"));
    }
    if let Some(folder) = real_folder(&q.folder) {
        parts.push(format!("in:{folder}"));
    }
    if q.has_attachment.is_some() {
        parts.push("has:attachment".to_string());
    }
    (!parts.is_empty()).then(|| parts.join(" "))
}

fn push_search_predicate(parts: &mut Vec<String>, op: &str, value: &str) {
    if let Some(value) = search_value(value) {
        parts.push(format!("{op}:{value}"));
    }
}

fn push_search_text(parts: &mut Vec<String>, value: &str, negated: bool) {
    if let Some(value) = search_value(value) {
        if negated {
            parts.push(format!("-{value}"));
        } else {
            parts.push(value);
        }
    }
}

fn search_value(value: &str) -> Option<String> {
    let value = value.replace('"', " ");
    let value = value.split_whitespace().collect::<Vec<_>>().join(" ");
    if value.is_empty() {
        return None;
    }
    if value.chars().any(char::is_whitespace) {
        Some(format!(r#""{value}""#))
    } else {
        Some(value)
    }
}

fn advanced_size_clause(cmp: &str, size: &str, unit: &str) -> Option<String> {
    let cmp = match cmp.trim() {
        "larger" | "smaller" => cmp.trim(),
        _ => return None,
    };
    let size = size.trim();
    if size.is_empty() || !size.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let suffix = match unit.trim().to_ascii_lowercase().as_str() {
        "" | "b" | "byte" | "bytes" => "",
        "k" | "kb" => "K",
        "m" | "mb" => "M",
        _ => return None,
    };
    Some(format!("{cmp}:{size}{suffix}"))
}

fn valid_search_date(value: &str) -> Option<String> {
    let value = value.trim();
    let mut parts = value.split('-');
    let year = parts.next()?.parse::<i32>().ok()?;
    let month = parts.next()?.parse::<u8>().ok()?;
    let day = parts.next()?.parse::<u8>().ok()?;
    if parts.next().is_some() {
        return None;
    }
    let month = Month::try_from(month).ok()?;
    Date::from_calendar_date(year, month, day).ok()?;
    Some(value.to_string())
}

fn render_undo_bar(batch_id: Option<&str>, undo_until: Option<&str>, token: &str) -> String {
    let Some(batch_id) = batch_id.map(str::trim).filter(|s| !s.is_empty()) else {
        return String::new();
    };
    let Some(until) = undo_until
        .map(str::trim)
        .and_then(|s| s.parse::<i64>().ok())
    else {
        return String::new();
    };
    let remaining = until - now_secs();
    if remaining <= 0 {
        return String::new();
    }
    format!(
        r#"<div class="undo-bar" role="status" data-undo-send data-undo-until="{until}">
  <span class="undo-bar__message">Message scheduled to send.</span>
  <span class="undo-bar__countdown" data-undo-countdown>{remaining}s</span>
  <form class="undo-bar__form" method="post" action="/send/undo">
    <input type="hidden" name="csrf" value="{token}">
    <input type="hidden" name="batch_id" value="{batch_id}">
    <button class="btn btn-primary btn-sm btn-undo-send" type="submit">Undo</button>
  </form>
</div>"#,
        token = esc(token),
        batch_id = esc(batch_id),
    )
}

/// Render one inbox/search row: the message link plus a per-row action form (star, mark-unread,
/// archive, spam/not-spam, delete, move-to-folder). `token` is the CSRF token; `return_to` is where
/// each action redirects back to.
fn render_message_list(rows: &str, prefs: PagePrefs) -> String {
    format!(
        r#"<section class="card mail-list-pane mail-list-pane--{density}" data-density="{density}"><ul class="maillist maillist--{density}" data-density="{density}" data-motion-list>{rows}</ul></section>"#,
        density = esc(prefs.density),
    )
}

fn render_list_with_optional_read_pane(rows: &str, prefs: PagePrefs) -> String {
    let list = render_message_list(rows, prefs);
    if prefs.reading_pane == "off" {
        return list;
    }
    format!(
        r#"<div class="mailbox-layout mailbox-layout--{pane}" data-pane="{pane}">{list}<section class="card pad read-pane read-pane--empty" data-read-pane aria-label="Reading pane"></section></div>"#,
        pane = esc(prefs.reading_pane),
    )
}

fn render_split_reader(rows: &str, read_html: &str, prefs: PagePrefs) -> String {
    if prefs.reading_pane == "off" {
        return read_html.to_string();
    }
    let list = render_message_list(rows, prefs);
    format!(
        r#"<div class="mailbox-layout mailbox-layout--{pane}" data-pane="{pane}">{list}{read_html}</div>"#,
        pane = esc(prefs.reading_pane),
    )
}

fn render_row(
    m: &crate::model::MessageSummary,
    token: &str,
    return_to: &str,
    prefs: PagePrefs,
) -> String {
    render_row_inner(m, token, return_to, None, prefs)
}

fn render_search_row(
    m: &crate::model::MessageSummary,
    token: &str,
    return_to: &str,
    query: &SearchQuery,
    prefs: PagePrefs,
) -> String {
    render_row_inner(m, token, return_to, Some(query), prefs)
}

fn render_row_inner(
    m: &crate::model::MessageSummary,
    token: &str,
    return_to: &str,
    query: Option<&SearchQuery>,
    prefs: PagePrefs,
) -> String {
    let cls = if m.seen { "mailrow" } else { "mailrow unseen" };
    let dot = if m.seen { "dot seen" } else { "dot" };
    let subject_text = if m.subject.trim().is_empty() {
        "(no subject)".to_string()
    } else {
        m.subject.clone()
    };
    let subject = query
        .map(|q| highlight_search_hits(&subject_text, q))
        .unwrap_or_else(|| esc(&subject_text));
    let from_display = display_from(&m.msg_from);
    let from = query
        .map(|q| highlight_search_hits(&from_display, q))
        .unwrap_or_else(|| esc(&from_display));
    let (from_name, from_addr) = from_display_parts(&m.msg_from);
    let avatar_key = if from_addr.is_empty() {
        from_name.as_str()
    } else {
        from_addr.as_str()
    };
    let tile = format!(
        r#"<span class="co-tile avatar--h{hue}" aria-hidden="true">{initial}</span>"#,
        hue = avatar_hue(avatar_key),
        initial = esc(&avatar_initial(&from_name, &from_addr)),
    );
    let star = star_mark(m.starred);
    let unread = if m.seen {
        String::new()
    } else {
        r#"<span class="sr-only">unread</span>"#.to_string()
    };
    let snip = clean_snippet(&m.snippet);
    let snip_html = if snip.is_empty() {
        String::new()
    } else {
        format!(r#"<span class="snip">{}</span>"#, esc(&snip))
    };
    let att = if m.has_attachment {
        format!(r#"<span class="att" aria-label="Has attachment">{ICO_CLIP}</span>"#)
    } else {
        String::new()
    };
    let state_cls = format!(
        "mailrow-wrap--{}{}{}{}",
        prefs.density,
        folder_class(&m.folder),
        if m.snooze_until > now_secs() {
            " is-snoozed"
        } else {
            ""
        },
        if m.muted { " is-muted" } else { "" }
    );
    let href = if m.folder == "Drafts" {
        format!("/compose?draft={}", url_encode(&m.id))
    } else {
        format!("/m/{}", url_encode(&m.id))
    };
    format!(
        r#"<li class="mailrow-wrap {state_cls}" data-id="{id}" data-starred="{starred}" data-seen="{seen}" data-snooze-until="{snooze_until}" data-muted="{muted}"><label class="mailcheck"><input type="checkbox" class="rowcheck" aria-label="Select message"></label><a class="{cls} mailrow--{density}" href="{href}"><span class="{dot}"></span>{unread}<span class="star-slot">{star}</span>{tile}<span class="from">{from}</span><span class="subject"><span class="subj-text">{subject}</span>{snip}</span>{att}<span class="date" title="{date_full}">{date}</span></a>{actions}</li>"#,
        id = esc(&m.id),
        href = esc(&href),
        density = esc(prefs.density),
        starred = m.starred,
        seen = m.seen,
        snooze_until = m.snooze_until,
        muted = m.muted,
        state_cls = state_cls,
        tile = tile,
        from = from,
        snip = snip_html,
        att = att,
        date_full = fmt_date(m.received_at),
        date = fmt_date_list(m.received_at),
        actions = row_actions(
            &m.id,
            m.starred,
            m.seen,
            &m.folder,
            m.snooze_until,
            m.muted,
            token,
            return_to
        ),
    )
}

fn render_scheduled_row(item: &ScheduledOutbound, token: &str, prefs: PagePrefs) -> String {
    let parsed = crate::rfc822::parse(&item.raw);
    let subject_text = if parsed.subject.trim().is_empty() {
        "(no subject)".to_string()
    } else {
        parsed.subject
    };
    let to_display = if parsed.to.trim().is_empty() {
        item.rcpts.join(", ")
    } else {
        parsed.to
    };
    let from_display = if parsed.from.trim().is_empty() {
        item.env_from.clone()
    } else {
        parsed.from
    };
    let controls = schedule_controls_for(now_secs(), item.send_at);
    format!(
        r#"<li class="mailrow-wrap mailrow-wrap--{density} folder-scheduled is-scheduled" data-id="{id}" data-send-at="{send_at}"><a class="mailrow mailrow--{density}" href="/compose?scheduled={scheduled}"><span class="dot seen"></span><span class="star-slot"></span><span class="from">{to}</span><span class="subject"><span class="subj-text">{subject}</span></span><span class="date" title="{date_full}">{date}</span></a><form class="row-actions scheduled-actions" method="post" action="/scheduled/{scheduled}/action">
  <input type="hidden" name="csrf" value="{token}">
  <input type="hidden" name="return" value="/?folder=Scheduled">
  {controls}
  <button class="btn btn-ghost btn-sm btn-reschedule-scheduled" type="submit" name="op" value="reschedule">Reschedule</button>
  <a class="btn btn-ghost btn-sm btn-edit-scheduled" href="/compose?scheduled={scheduled}">Edit</a>
  <button class="btn btn-ghost btn-sm btn-draft-scheduled" type="submit" name="op" value="draft">Move to Drafts</button>
  <button class="btn btn-danger btn-sm btn-cancel-scheduled" type="submit" name="op" value="cancel">Cancel</button>
</form><span class="sr-only">From {from}</span></li>"#,
        id = esc(&item.batch_id),
        density = esc(prefs.density),
        scheduled = url_encode(&item.batch_id),
        send_at = item.send_at,
        token = esc(token),
        controls = controls,
        to = esc(&to_display),
        from = esc(&from_display),
        subject = esc(&subject_text),
        date_full = fmt_date(item.send_at),
        date = fmt_date_list(item.send_at),
    )
}

fn highlight_search_hits(text: &str, query: &SearchQuery) -> String {
    let terms: Vec<&str> = query
        .positive_text_terms()
        .map(str::trim)
        .filter(|term| !term.is_empty())
        .collect();
    if terms.is_empty() || text.is_empty() {
        return esc(text);
    }

    let mut out = String::new();
    let mut pos = 0_usize;
    while pos < text.len() {
        let mut best: Option<(usize, usize)> = None;
        for term in &terms {
            if let Some((start, end)) = find_term_ascii_ci(&text[pos..], term) {
                let start = pos + start;
                let end = pos + end;
                match best {
                    Some((best_start, best_end))
                        if best_start < start
                            || (best_start == start && best_end - best_start >= end - start) => {}
                    _ => best = Some((start, end)),
                }
            }
        }
        let Some((start, end)) = best else {
            out.push_str(&esc(&text[pos..]));
            break;
        };
        out.push_str(&esc(&text[pos..start]));
        out.push_str(r#"<mark class="search-hit">"#);
        out.push_str(&esc(&text[start..end]));
        out.push_str("</mark>");
        pos = end;
    }
    out
}

fn find_term_ascii_ci(text: &str, term: &str) -> Option<(usize, usize)> {
    if term.is_empty() || term.len() > text.len() {
        return None;
    }
    for (start, _) in text.char_indices() {
        let end = start + term.len();
        if end > text.len() {
            return None;
        }
        if let Some(candidate) = text.get(start..end) {
            if candidate.eq_ignore_ascii_case(term) {
                return Some((start, end));
            }
        }
    }
    None
}

/// A leading star glyph for a row's subject (filled when starred, nothing otherwise).
fn star_mark(starred: bool) -> &'static str {
    if starred {
        r#"<span class="star on" aria-label="starred">★</span> "#
    } else {
        ""
    }
}

fn folder_class(folder: &str) -> String {
    let mut slug = String::new();
    for ch in folder.chars() {
        if ch.is_ascii_alphanumeric() {
            slug.push(ch.to_ascii_lowercase());
        } else if !slug.ends_with('-') {
            slug.push('-');
        }
    }
    while slug.ends_with('-') {
        slug.pop();
    }
    if slug.is_empty() {
        "folder-unknown".to_string()
    } else {
        format!("folder-{slug}")
    }
}

fn snooze_controls(now: i64) -> String {
    let presets = [
        (now + 3 * 60 * 60, "Later"),
        (now + 6 * 60 * 60, "Tonight"),
        (now + 24 * 60 * 60, "Tomorrow"),
        (now + 7 * 24 * 60 * 60, "Next week"),
    ];
    let mut opts = String::new();
    for (until, label) in presets {
        opts.push_str(&format!(r#"<option value="{until}">{label}</option>"#));
    }
    format!(
        r#"<select class="snooze-menu" name="snooze_until" aria-label="Snooze until">{opts}</select>
  <input class="snooze-custom" type="number" name="snooze_custom" min="{min}" placeholder="Epoch" aria-label="Custom snooze epoch">"#,
        min = now + 1,
    )
}

fn schedule_controls_for(now: i64, selected: i64) -> String {
    let presets = schedule_presets(now);
    let mut opts = String::new();
    let mut matched = false;
    for (send_at, label) in presets {
        let sel = if selected == send_at {
            matched = true;
            " selected"
        } else {
            ""
        };
        opts.push_str(&format!(
            r#"<option value="{send_at}"{sel}>{label}</option>"#
        ));
    }
    let custom_value = if selected > now && !matched {
        format!(r#" value="{selected}""#)
    } else {
        String::new()
    };
    format!(
        r#"<select class="schedule-menu" name="schedule_at" aria-label="Schedule send time">{opts}</select>
  <input class="schedule-custom" type="number" name="schedule_custom" min="{min}" placeholder="Epoch" aria-label="Custom schedule epoch"{custom_value}>"#,
        min = now + 1,
    )
}

fn undo_send_window_options(selected: i64) -> String {
    let mut opts = String::new();
    let selected = effective_undo_send_window_secs(selected);
    for secs in UNDO_SEND_WINDOW_CHOICES {
        let sel = if secs == selected { " selected" } else { "" };
        opts.push_str(&format!(
            r#"<option value="{secs}"{sel}>{secs} seconds</option>"#
        ));
    }
    opts
}

fn page_prefs(settings: &MailboxSettings) -> PagePrefs {
    PagePrefs {
        density: effective_density(&settings.density),
        reading_pane: effective_reading_pane(&settings.reading_pane),
        theme: effective_theme(&settings.theme),
    }
}

async fn settings_for_page(state: &AppState, mailbox: &str) -> MailboxSettings {
    match state.store.get_settings(mailbox).await {
        Ok(settings) => settings,
        Err(e) => {
            tracing::warn!(mailbox, error = %e, "failed to load mailbox settings; using defaults");
            MailboxSettings::default_for(mailbox)
        }
    }
}

fn display_preference_options(settings: &MailboxSettings) -> (String, String, String) {
    let prefs = page_prefs(settings);
    (
        select_options_selected(&DENSITY_CHOICES, prefs.density, density_label),
        select_options_selected(
            &READING_PANE_CHOICES,
            prefs.reading_pane,
            reading_pane_label,
        ),
        select_options_selected(&THEME_CHOICES, prefs.theme, theme_label),
    )
}

fn density_label(value: &str) -> String {
    match value {
        "comfortable" => "Comfortable".to_string(),
        "normal" => "Normal".to_string(),
        "compact" => "Compact".to_string(),
        other => esc(other),
    }
}

fn reading_pane_label(value: &str) -> String {
    match value {
        "off" => "Off".to_string(),
        "right" => "Right".to_string(),
        "bottom" => "Bottom".to_string(),
        other => esc(other),
    }
}

fn theme_label(value: &str) -> String {
    match value {
        "system" => "System".to_string(),
        "light" => "Light".to_string(),
        "dark" => "Dark".to_string(),
        other => esc(other),
    }
}

fn schedule_presets(now: i64) -> [(i64, &'static str); 3] {
    let day = now.div_euclid(86_400) * 86_400;
    let tonight = future_utc_time(day + 20 * 60 * 60, now);
    let tomorrow_morning = future_utc_time(day + 86_400 + 9 * 60 * 60, now);
    let days_since_epoch = day.div_euclid(86_400);
    // 1970-01-01 was Thursday; with Monday=0 this is 3.
    let weekday = (days_since_epoch + 3).rem_euclid(7);
    let mut days_until_monday = (7 - weekday).rem_euclid(7);
    if days_until_monday == 0 {
        days_until_monday = 7;
    }
    let next_monday_morning = day + days_until_monday * 86_400 + 9 * 60 * 60;
    [
        (tonight, "Tonight"),
        (tomorrow_morning, "Tomorrow morning"),
        (next_monday_morning, "Next Monday morning"),
    ]
}

fn future_utc_time(candidate: i64, now: i64) -> i64 {
    if candidate > now {
        candidate
    } else {
        candidate + 86_400
    }
}

/// The per-message action form (shared by inbox rows and the read view). Double-submit CSRF; every
/// button submits the same form with a distinct `op`. The read/unread button reflects the current
/// `seen` state (so a read row offers "Unread" and an unread row offers "Read" — the optimistic
/// mark-read affordance). No-JS users still POST this form; the enhancement layer intercepts it.
fn row_actions(
    id: &str,
    starred: bool,
    seen: bool,
    folder: &str,
    snooze_until: i64,
    muted: bool,
    token: &str,
    return_to: &str,
) -> String {
    let (star_op, star_label, star_glyph) = if starred {
        ("unstar", "Unstar", "★")
    } else {
        ("star", "Star", "☆")
    };
    let (seen_op, seen_label) = if seen {
        ("unread", "Unread")
    } else {
        ("read", "Read")
    };
    let spam_button = if folder.eq_ignore_ascii_case(crate::delivery::SPAM_FOLDER) {
        r#"<button class="btn btn-ghost btn-sm btn-not-spam" type="submit" name="op" value="not_spam" title="Move to Inbox and trust sender">Not spam</button>"#
    } else {
        r#"<button class="btn btn-ghost btn-sm btn-report-spam" type="submit" name="op" value="report_spam" title="Move to Spam and block sender">Report spam</button>"#
    };
    let now = now_secs();
    let snooze_controls = snooze_controls(now);
    let unsnooze_button = if snooze_until > now {
        r#"<button class="btn btn-ghost btn-sm btn-unsnooze" type="submit" name="op" value="unsnooze" title="Move back to Inbox">Unsnooze</button>"#
    } else {
        ""
    };
    let (mute_op, mute_label) = if muted {
        ("unmute", "Unmute")
    } else {
        ("mute", "Mute")
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
  <button class="btn btn-ghost btn-sm" type="submit" name="op" value="{seen_op}" title="Mark {seen_label_lc}">{seen_label}</button>
  <button class="btn btn-ghost btn-sm" type="submit" name="op" value="archive" title="Archive">Archive</button>
  <button class="btn btn-ghost btn-sm btn-mute" type="submit" name="op" value="{mute_op}" title="{mute_label} thread">{mute_label}</button>
  {snooze_controls}
  <button class="btn btn-ghost btn-sm btn-snooze" type="submit" name="op" value="snooze" title="Snooze">Snooze</button>
  {unsnooze_button}
  {spam_button}
  <button class="btn btn-ghost btn-sm" type="submit" name="op" value="delete" title="Move to Trash">Delete</button>
  <select class="move-select" name="folder" aria-label="Move to folder"><option value="" selected disabled>Move…</option>{opts}</select>
  <button class="btn btn-ghost btn-sm" type="submit" name="op" value="move">Move</button>
</form>"#,
        id = esc(id),
        token = esc(token),
        ret = esc(return_to),
        spam_button = spam_button,
        snooze_controls = snooze_controls,
        unsnooze_button = unsnooze_button,
        seen_label_lc = seen_label.to_ascii_lowercase(),
    )
}

/// An Odyssey v2 `.empty` state as a `maillist` row: soft icon + title + subtext + a primary action.
/// `title` carries the exact copy older tests assert on (e.g. "No messages here.").
fn empty_row(title: &str, subtext: &str) -> String {
    format!(
        r#"<li class="maillist-empty"><div class="empty"><div class="empty__ico">{ico}</div><h3>{title}</h3><p>{sub}</p><a class="btn btn-primary btn-sm" href="/compose">Compose</a></div></li>"#,
        ico = ICO_INBOX,
        title = esc(title),
        sub = esc(subtext),
    )
}

/// The sticky multi-select bulk toolbar (hidden until the enhancement layer reveals it on the first
/// selection). Buttons are plain `type=button`s driven by [`WEBMAIL_JS`] against `/api/m/bulk`;
/// `data-csrf` carries the double-submit token. No-JS users never see it (it stays `hidden`).
fn bulk_toolbar(token: &str) -> String {
    let mut opts = String::new();
    for f in FOLDERS {
        opts.push_str(&format!(r#"<option value="{f}">{f}</option>"#));
    }
    let snooze_controls = snooze_controls(now_secs());
    format!(
        r#"<div class="bulkbar" role="toolbar" aria-label="Bulk actions" data-bulkbar data-csrf="{token}" hidden>
  <div class="bulkbar__lead">
    <span class="bulkbar__count" data-bulk-count>0 selected</span>
    <button class="btn btn-ghost btn-sm" type="button" data-bulk-clear>Clear</button>
  </div>
  <div class="bulkbar__actions">
    <button class="btn btn-ghost btn-sm" type="button" data-bulk="read">Mark read</button>
    <button class="btn btn-ghost btn-sm" type="button" data-bulk="archive">Archive</button>
    <button class="btn btn-ghost btn-sm btn-mute" type="button" data-bulk="mute">Mute</button>
    <button class="btn btn-ghost btn-sm btn-mute" type="button" data-bulk="unmute">Unmute</button>
    {snooze_controls}
    <button class="btn btn-ghost btn-sm btn-snooze" type="button" data-bulk="snooze">Snooze</button>
    <button class="btn btn-ghost btn-sm btn-unsnooze" type="button" data-bulk="unsnooze">Unsnooze</button>
    <button class="btn btn-ghost btn-sm btn-report-spam" type="button" data-bulk="report_spam">Report spam</button>
    <button class="btn btn-ghost btn-sm btn-not-spam" type="button" data-bulk="not_spam">Not spam</button>
    <select class="move-select" data-bulk-folder aria-label="Move selected to folder"><option value="" selected disabled>Move…</option>{opts}</select>
    <button class="btn btn-ghost btn-sm" type="button" data-bulk="move">Move</button>
    <button class="btn btn-danger btn-sm" type="button" data-bulk="delete">Delete</button>
  </div>
</div>"#,
        token = esc(token),
        snooze_controls = snooze_controls,
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

fn next_scheduled_link(msgs: &[ScheduledOutbound], limit: i64, base: &str) -> String {
    let Some(last) = msgs.last().filter(|_| msgs.len() as i64 >= limit) else {
        return String::new();
    };
    format!(
        r#"<div class="page-more"><a class="btn btn-ghost btn-sm" href="{base}&before={cursor}">Load more</a></div>"#,
        cursor = url_encode(&format!("{}_{}", last.send_at, last.batch_id)),
    )
}

/// Minimal percent-encoding for a query-string value (keeps unreserved chars, encodes the rest).
fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
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
        Some(f) if f.eq_ignore_ascii_case(SNOOZED_VIEW) => SNOOZED_VIEW,
        Some(f) if f.eq_ignore_ascii_case(SCHEDULED_VIEW) => SCHEDULED_VIEW,
        Some(f) => FOLDERS
            .into_iter()
            .find(|c| c.eq_ignore_ascii_case(f))
            .unwrap_or("INBOX"),
        None => "INBOX",
    }
}

fn render_message_body(msg: &Message) -> String {
    if !msg.body_html.is_empty() {
        let inline = crate::rfc822::list_inline_attachments(&msg.raw_rfc822);
        let rewritten = rewrite_cid_image_sources(&msg.body_html, &msg.id, &inline);
        let marked = mark_gmail_quote_blocks(&rewritten);
        let clean = crate::sanitize::sanitize_html(&marked);
        let folded = fold_quoted_html(&clean);
        format!(r#"<div class="msg-body">{folded}</div>"#)
    } else {
        render_plain_message_body(&msg.body_text)
    }
}

fn render_plain_message_body(text: &str) -> String {
    let inner = if let Some((visible, quoted)) = split_quoted_text(text) {
        let mut html = String::new();
        let visible = visible.trim_end_matches(['\r', '\n']);
        if !visible.trim().is_empty() {
            html.push_str(&format!(r#"<pre>{}</pre>"#, esc(visible)));
        }
        let quoted = quoted.trim_start_matches(['\r', '\n']);
        html.push_str(&quote_details(&format!(r#"<pre>{}</pre>"#, esc(quoted))));
        html
    } else {
        format!(r#"<pre>{}</pre>"#, esc(text))
    };
    format!(r#"<div class="msg-body">{inner}</div>"#)
}

fn rewrite_cid_image_sources(
    html: &str,
    msg_id: &str,
    inline: &[crate::rfc822::InlineAttachmentMeta],
) -> String {
    if inline.is_empty() || !html.to_ascii_lowercase().contains("cid:") {
        return html.to_string();
    }

    let encoded_id = url_encode(msg_id);
    let mut cid_urls = HashMap::new();
    for part in inline {
        cid_urls
            .entry(part.content_id.clone())
            .or_insert_with(|| format!("/m/{encoded_id}/attachments/{idx}", idx = part.index));
    }

    let mut out = String::with_capacity(html.len());
    let mut i = 0;
    while let Some(rel) = find_ascii_case_insensitive(&html[i..], "<img") {
        let tag_start = i + rel;
        if !is_img_tag_start(html, tag_start) {
            out.push_str(&html[i..tag_start + 1]);
            i = tag_start + 1;
            continue;
        }
        out.push_str(&html[i..tag_start]);
        let Some(tag_end) = find_html_tag_end(html.as_bytes(), tag_start) else {
            out.push_str(&html[tag_start..]);
            return out;
        };
        let tag = &html[tag_start..=tag_end];
        out.push_str(&rewrite_img_src_attr(tag, &cid_urls));
        i = tag_end + 1;
    }
    out.push_str(&html[i..]);
    out
}

fn rewrite_img_src_attr(tag: &str, cid_urls: &HashMap<String, String>) -> String {
    let bytes = tag.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if !is_attr_name_char(bytes[i]) {
            i += 1;
            continue;
        }

        let name_start = i;
        while i < bytes.len() && is_attr_name_char(bytes[i]) {
            i += 1;
        }
        let name = &tag[name_start..i];
        let mut j = i;
        while j < bytes.len() && bytes[j].is_ascii_whitespace() {
            j += 1;
        }
        if j >= bytes.len() || bytes[j] != b'=' {
            i = j;
            continue;
        }
        j += 1;
        while j < bytes.len() && bytes[j].is_ascii_whitespace() {
            j += 1;
        }
        if j >= bytes.len() {
            break;
        }

        let quote = matches!(bytes[j], b'"' | b'\'').then_some(bytes[j]);
        let value_start = if quote.is_some() { j + 1 } else { j };
        let mut value_end = value_start;
        if let Some(q) = quote {
            while value_end < bytes.len() && bytes[value_end] != q {
                value_end += 1;
            }
        } else {
            while value_end < bytes.len()
                && !bytes[value_end].is_ascii_whitespace()
                && !matches!(bytes[value_end], b'>' | b'/')
            {
                value_end += 1;
            }
        }

        if name.eq_ignore_ascii_case("src") {
            let value = &tag[value_start..value_end];
            if let Some(cid) = cid_src_value(value) {
                if let Some(url) = cid_urls.get(&cid) {
                    let mut rewritten = String::with_capacity(tag.len() + url.len());
                    rewritten.push_str(&tag[..value_start]);
                    rewritten.push_str(url);
                    rewritten.push_str(&tag[value_end..]);
                    return rewritten;
                }
            }
        }

        i = if quote.is_some() {
            value_end.saturating_add(1)
        } else {
            value_end
        };
    }
    tag.to_string()
}

fn cid_src_value(value: &str) -> Option<String> {
    let value = value.trim();
    if !value.to_ascii_lowercase().starts_with("cid:") {
        return None;
    }
    let decoded = percent_decode_lossy(&value[4..]);
    crate::rfc822::normalize_content_id(&decoded)
}

fn percent_decode_lossy(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (hex_value(bytes[i + 1]), hex_value(bytes[i + 2])) {
                out.push((hi << 4) | lo);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_value(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn mark_gmail_quote_blocks(html: &str) -> String {
    let lower = html.to_ascii_lowercase();
    let Some(hit) = lower.find("gmail_quote") else {
        return html.to_string();
    };
    let Some(tag_start) = html[..hit].rfind('<') else {
        return html.to_string();
    };
    let Some(tag_end) = find_html_tag_end(html.as_bytes(), tag_start) else {
        return html.to_string();
    };
    let tag = &html[tag_start..=tag_end];
    if tag.starts_with("</") || !tag.to_ascii_lowercase().contains("gmail_quote") {
        return html.to_string();
    }
    format!(
        "{}<blockquote>{}</blockquote>",
        &html[..tag_start],
        &html[tag_start..]
    )
}

fn fold_quoted_html(html: &str) -> String {
    if let Some(block_start) = find_ascii_case_insensitive(html, "<blockquote") {
        let start = attribution_start_before(html, block_start).unwrap_or(block_start);
        let end = matching_blockquote_end(html, block_start).unwrap_or(html.len());
        return fold_html_range(html, start, end);
    }
    if let Some(start) = wrote_quote_start(html) {
        return fold_html_range(html, start, html.len());
    }
    html.to_string()
}

fn fold_html_range(html: &str, start: usize, end: usize) -> String {
    let mut out = String::with_capacity(html.len() + 120);
    out.push_str(&html[..start]);
    out.push_str(&quote_details(&html[start..end]));
    out.push_str(&html[end..]);
    out
}

fn quote_details(inner: &str) -> String {
    format!(
        r#"<details class="quote-fold"><summary class="btn-expand-quote">&middot;&middot;&middot; Show quoted text</summary>{inner}</details>"#
    )
}

fn split_quoted_text(text: &str) -> Option<(&str, &str)> {
    let mut line_start = 0;
    let mut previous_nonblank = None;
    for line in text.split_inclusive('\n') {
        let without_newline = line.trim_end_matches(['\r', '\n']);
        let trimmed = without_newline.trim_start();
        let lower = trimmed.to_ascii_lowercase();
        let starts_quote = trimmed.starts_with('>')
            || looks_like_wrote_line(trimmed)
            || lower.starts_with("-----original message-----");
        if starts_quote {
            let start = if trimmed.starts_with('>') {
                previous_nonblank
                    .filter(|prev| looks_like_wrote_line(text[*prev..line_start].trim()))
                    .unwrap_or(line_start)
            } else {
                line_start
            };
            return (!text[start..].trim().is_empty()).then_some((&text[..start], &text[start..]));
        }
        if !trimmed.is_empty() {
            previous_nonblank = Some(line_start);
        }
        line_start += line.len();
    }
    None
}

fn looks_like_wrote_line(line: &str) -> bool {
    let lower = line.trim().to_ascii_lowercase();
    lower.starts_with("on ") && lower.contains(" wrote:")
}

fn wrote_quote_start(html: &str) -> Option<usize> {
    let lower = html.to_ascii_lowercase();
    let mut search = 0;
    while let Some(rel) = lower[search..].find(" wrote:") {
        let wrote = search + rel;
        if let Some(on) = lower[..wrote].rfind("on ") {
            if wrote.saturating_sub(on) <= 300 {
                return Some(html_block_start_before(html, on));
            }
        }
        search = wrote + " wrote:".len();
    }
    None
}

fn attribution_start_before(html: &str, block_start: usize) -> Option<usize> {
    let prefix = &html[..block_start];
    let lower = prefix.to_ascii_lowercase();
    let wrote = lower.rfind(" wrote:")?;
    if block_start.saturating_sub(wrote) > 500 {
        return None;
    }
    let on = lower[..wrote].rfind("on ")?;
    if wrote.saturating_sub(on) > 300 {
        return None;
    }
    Some(html_block_start_before(html, on))
}

fn html_block_start_before(html: &str, text_pos: usize) -> usize {
    let before = &html[..text_pos];
    ["<blockquote", "<div", "<p"]
        .iter()
        .filter_map(|needle| find_ascii_case_insensitive_reverse(before, needle))
        .max()
        .unwrap_or(text_pos)
}

fn matching_blockquote_end(html: &str, start: usize) -> Option<usize> {
    let lower = html.to_ascii_lowercase();
    let mut pos = start;
    let mut depth = 0usize;
    loop {
        let next_open = lower[pos..].find("<blockquote").map(|p| pos + p);
        let next_close = lower[pos..].find("</blockquote>").map(|p| pos + p);
        match (next_open, next_close) {
            (Some(open), Some(close)) if open < close => {
                depth += 1;
                pos = open + "<blockquote".len();
            }
            (Some(open), None) => {
                depth += 1;
                pos = open + "<blockquote".len();
            }
            (_, Some(close)) => {
                if depth == 0 {
                    return None;
                }
                depth -= 1;
                let end = close + "</blockquote>".len();
                if depth == 0 {
                    return Some(end);
                }
                pos = end;
            }
            _ => return None,
        }
    }
}

fn find_ascii_case_insensitive(haystack: &str, needle: &str) -> Option<usize> {
    haystack
        .to_ascii_lowercase()
        .find(&needle.to_ascii_lowercase())
}

fn find_ascii_case_insensitive_reverse(haystack: &str, needle: &str) -> Option<usize> {
    haystack
        .to_ascii_lowercase()
        .rfind(&needle.to_ascii_lowercase())
}

fn is_img_tag_start(html: &str, start: usize) -> bool {
    let bytes = html.as_bytes();
    let after = start + "<img".len();
    after >= bytes.len()
        || matches!(
            bytes[after],
            b'>' | b'/' | b' ' | b'\t' | b'\r' | b'\n' | 0x0c
        )
}

fn find_html_tag_end(bytes: &[u8], start: usize) -> Option<usize> {
    let mut j = start + 1;
    let mut quote = None;
    while j < bytes.len() {
        match quote {
            Some(q) => {
                if bytes[j] == q {
                    quote = None;
                }
            }
            None => match bytes[j] {
                b'"' | b'\'' => quote = Some(bytes[j]),
                b'>' => return Some(j),
                _ => {}
            },
        }
        j += 1;
    }
    None
}

fn is_attr_name_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b':')
}

/// Inputs for [`list_toolbar`]: which folder/label is active, the current search text + scope,
/// and whether the folder is showing the threaded (conversation) view.
struct FolderTabs<'a> {
    active: &'a str,
    search_q: &'a str,
    scope: Option<&'a str>,
    active_label: &'a str,
    threads_on: bool,
}

fn sidebar_count(n: i64, unread: bool) -> String {
    if n <= 0 {
        return String::new();
    }
    let cls = if unread {
        "mail-side__count mail-side__count--unread"
    } else {
        "mail-side__count"
    };
    format!(r#"<span class="{cls}">{n}</span>"#)
}

fn sidebar_item(
    active: &str,
    active_label: &str,
    key: &str,
    href: &str,
    icon: &str,
    name: &str,
    count: String,
) -> String {
    let is_active = active_label.is_empty() && active == key;
    let active_cls = if is_active { " is-active" } else { "" };
    let current = if is_active {
        r#" aria-current="page""#
    } else {
        ""
    };
    let aria = if key == "INBOX" && !count.is_empty() {
        format!(r#" aria-label="Inbox, {} unread""#, count_text(&count))
    } else {
        String::new()
    };
    format!(
        r#"<li><a class="mail-side__item{active_cls}" href="{href}"{current}{aria}>{icon}<span class="mail-side__name">{name}</span>{count}</a></li>"#,
        href = esc(href),
        name = esc(name),
    )
}

fn count_text(html: &str) -> String {
    html.chars().filter(|ch| ch.is_ascii_digit()).collect()
}

fn mail_sidebar(
    active: &str,
    active_label: &str,
    labels: &[Label],
    counts: &FolderCounts,
) -> String {
    let mut primary = String::new();
    // The sidebar Inbox count is intentionally INBOX-scoped; the page-head "N unread" pill keeps
    // the existing mailbox-wide unseen_count semantics.
    primary.push_str(&sidebar_item(
        active,
        active_label,
        "INBOX",
        "/?folder=INBOX",
        ICO_INBOX,
        "Inbox",
        sidebar_count(counts.inbox_unseen, true),
    ));
    primary.push_str(&sidebar_item(
        active,
        active_label,
        STARRED_VIEW,
        "/?folder=Starred",
        ICO_STAR,
        "Starred",
        String::new(),
    ));
    primary.push_str(&sidebar_item(
        active,
        active_label,
        SNOOZED_VIEW,
        "/?folder=Snoozed",
        ICO_CLOCK,
        "Snoozed",
        sidebar_count(counts.snoozed_total, false),
    ));
    primary.push_str(&sidebar_item(
        active,
        active_label,
        "Sent",
        "/?folder=Sent",
        ICO_SEND,
        "Sent",
        String::new(),
    ));
    primary.push_str(&sidebar_item(
        active,
        active_label,
        "Drafts",
        "/?folder=Drafts",
        ICO_DRAFT,
        "Drafts",
        sidebar_count(counts.drafts_total, false),
    ));

    let mut secondary = String::new();
    secondary.push_str(&sidebar_item(
        active,
        active_label,
        "Archive",
        "/?folder=Archive",
        ICO_ARCHIVE,
        "Archive",
        String::new(),
    ));
    secondary.push_str(&sidebar_item(
        active,
        active_label,
        crate::delivery::SPAM_FOLDER,
        "/?folder=Spam",
        ICO_SPAM,
        "Spam",
        sidebar_count(counts.spam_unseen, false),
    ));
    secondary.push_str(&sidebar_item(
        active,
        active_label,
        "Trash",
        "/?folder=Trash",
        ICO_TRASH,
        "Trash",
        String::new(),
    ));
    secondary.push_str(&sidebar_item(
        active,
        active_label,
        SCHEDULED_VIEW,
        "/?folder=Scheduled",
        ICO_CAL,
        "Scheduled",
        sidebar_count(counts.scheduled_total, false),
    ));

    let labels_html = if labels.is_empty() {
        String::new()
    } else {
        let mut items = String::new();
        for label in labels {
            let is_active = label.id == active_label;
            let active_cls = if is_active { " is-active" } else { "" };
            let current = if is_active {
                r#" aria-current="page""#
            } else {
                ""
            };
            items.push_str(&format!(
                r#"<li><a class="mail-side__item{active_cls}" href="/?label={id}"{current}><span class="mail-side__dot mail-side__dot--default" aria-hidden="true"></span><span class="mail-side__name">{name}</span></a></li>"#,
                id = url_encode(&label.id),
                name = esc(&label.name),
            ));
        }
        format!(
            r#"<details class="mail-side__labels" open><summary class="mail-side__heading">Labels</summary><ul class="mail-side__list">{items}</ul></details>"#
        )
    };

    format!(
        r#"<nav class="mail-side" aria-label="Mail folders">
  <a class="btn btn-primary mail-side__compose" href="/compose">{compose}<span>Compose</span></a>
  <ul class="mail-side__list">{primary}</ul>
  <div class="mail-side__sep" role="presentation"></div>
  <ul class="mail-side__list">{secondary}</ul>
  {labels}
</nav>"#,
        compose = ICO_PENCIL,
        labels = labels_html,
    )
}

fn mail_shell(sidebar: String, main: String) -> String {
    format!(r#"<div class="mail-shell">{sidebar}<div class="mail-main">{main}</div></div>"#)
}

/// Render the list toolbar: scoped search box, operator hint, and the Threads/Messages view
/// toggle. Folder and label navigation live in the persistent sidebar.
fn list_toolbar(t: &FolderTabs) -> String {
    let scope_input = t
        .scope
        .map(|f| format!(r#"<input type="hidden" name="folder" value="{}">"#, esc(f)))
        .unwrap_or_default();
    let mut toggle = String::new();
    if t.active_label.is_empty()
        && !t.active.is_empty()
        && t.active != STARRED_VIEW
        && t.active != SNOOZED_VIEW
        && t.active != SCHEDULED_VIEW
    {
        if t.threads_on {
            toggle.push_str(&format!(
                r#"<a class="btn btn-subtle btn-sm threads-toggle" href="/?folder={f}" title="Show individual messages">Messages</a>"#,
                f = t.active,
            ));
        } else {
            toggle.push_str(&format!(
                r#"<a class="btn btn-subtle btn-sm threads-toggle" href="/?folder={f}&view=threads" title="Group into conversations">Threads</a>"#,
                f = t.active,
            ));
        }
    }
    format!(
        r#"<div class="list-toolbar">
  <form class="search-box" method="get" action="/">{scope_input}<input type="search" name="q" value="{q}" placeholder="Search mail"><button class="btn btn-ghost btn-sm" type="submit">Search</button>
    <div class="search-hint">from: to: cc: subject: label: is:unread is:read is:starred has:attachment in: before: after: larger: smaller: "exact phrase" -exclude OR <a class="adv-search-link" href="/search/advanced">Advanced search →</a></div>
  </form>
  <span class="list-toolbar__spacer"></span>
  {toggle}
</div>"#,
        q = esc(t.search_q),
    )
}

/// Render one collapsed conversation row for the threaded folder view: the latest message's
/// from/subject/date, a message count, and the unread indicator, linking to the conversation view.
fn render_thread_row(t: &crate::model::ThreadSummary, prefs: PagePrefs) -> String {
    let m = &t.latest;
    let cls = if t.unseen > 0 {
        "mailrow unseen"
    } else {
        "mailrow"
    };
    let dot = if t.unseen > 0 { "dot" } else { "dot seen" };
    let subject = if m.subject.trim().is_empty() {
        "(no subject)".to_string()
    } else {
        esc(&m.subject)
    };
    let count_badge = if t.count > 1 {
        format!(r#"<span class="pill thread-count">{}</span>"#, t.count)
    } else {
        String::new()
    };
    let unread = if t.unseen > 0 {
        r#"<span class="sr-only">unread</span>"#
    } else {
        ""
    };
    let snip = clean_snippet(&m.snippet);
    let snip_html = if snip.is_empty() {
        String::new()
    } else {
        format!(r#"<span class="snip">{}</span>"#, esc(&snip))
    };
    format!(
        r#"<li class="mailrow-wrap mailrow-wrap--{density}"><a class="{cls} mailrow--{density}" href="/t?id={id}"><span class="{dot}"></span>{unread}<span class="from">{from}</span><span class="count-slot">{count}</span><span class="subject"><span class="subj-text">{subject}</span>{snip}</span><span class="date" title="{date_full}">{date}</span></a></li>"#,
        id = url_encode(&t.thread_id),
        density = esc(prefs.density),
        from = esc(&display_from(&m.msg_from)),
        count = count_badge,
        snip = snip_html,
        date_full = fmt_date(m.received_at),
        date = fmt_date_list(m.received_at),
    )
}

/// The keyset "Load older" link for the threaded view — same rule as [`next_page_link`] but keyed
/// on the last conversation's representative (newest) message `(received_at, id)`.
fn next_thread_link(threads: &[crate::model::ThreadSummary], limit: i64, base: &str) -> String {
    let Some(last) = threads.last().filter(|_| threads.len() as i64 >= limit) else {
        return String::new();
    };
    format!(
        r#"<div class="page-more"><a class="btn btn-ghost btn-sm" href="{base}&before={cursor}">Load older</a></div>"#,
        cursor = url_encode(&format!("{}_{}", last.latest.received_at, last.latest.id)),
    )
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
        Err(e) => {
            return error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Storage error",
                &e.to_string(),
            );
        }
    };
    // Authorisation: a message is only viewable from its own mailbox.
    if msg.mailbox != mb.addr {
        return error_page(StatusCode::NOT_FOUND, "Not found", "No such message.");
    }
    let _ = state.store.mark_seen(&id).await;
    // Mint/reuse a CSRF token for the read-view action buttons (star/archive/delete/move/unread).
    let (token, set_cookie) = ensure_csrf(&headers);
    let settings = settings_for_page(&state, &mb.addr).await;
    let prefs = page_prefs(&settings);

    let body = render_message_body(&msg);

    // Enumerate the stored raw source's MIME parts and offer a download link per attachment.
    let attachments = render_attachment_list(&msg);

    // Label strip + assign/remove control (scoped to this mailbox's labels).
    let all_labels = state.store.list_labels(&mb.addr).await.unwrap_or_default();
    let counts = state
        .store
        .folder_counts(&mb.addr)
        .await
        .unwrap_or_default();
    let msg_labels = state
        .store
        .labels_for_message(&mb.addr, &id)
        .await
        .unwrap_or_default();
    let labels_html = render_message_labels(&msg.id, &all_labels, &msg_labels, &token);
    let spam_banner = render_spam_banner(
        msg.folder
            .eq_ignore_ascii_case(crate::delivery::SPAM_FOLDER),
        state
            .store
            .spam_annotation(&mb.addr, &id)
            .await
            .unwrap_or_default()
            .as_ref(),
    );

    // "View conversation" link when this message is part of a multi-message thread.
    let convo_html = if !msg.thread_id.is_empty() {
        let count = state
            .store
            .list_thread(&mb.addr, &msg.thread_id, 200)
            .await
            .map(|v| v.len())
            .unwrap_or(0);
        if count > 1 {
            format!(
                r#"<a class="btn btn-ghost btn-sm" href="/t?id={tid}">View conversation ({count})</a>"#,
                tid = url_encode(&msg.thread_id),
            )
        } else {
            String::new()
        }
    } else {
        String::new()
    };

    let subject = if msg.subject.trim().is_empty() {
        "(no subject)".to_string()
    } else {
        esc(&msg.subject)
    };
    let sender = msg_from_block(&msg.msg_from, &msg.msg_to, msg.received_at);
    let mut pane_rows = String::new();
    if prefs.reading_pane != "off" {
        let return_to = format!("/m/{}", url_encode(&msg.id));
        match state
            .store
            .list_folder(&mb.addr, &msg.folder, None, PAGE_DEFAULT)
            .await
        {
            Ok(msgs) => {
                for item in &msgs {
                    pane_rows.push_str(&render_row(item, &token, &return_to, prefs));
                }
            }
            Err(e) => {
                tracing::warn!(
                    mailbox = %mb.addr,
                    folder = %msg.folder,
                    error = %e,
                    "failed to load reading-pane list"
                );
            }
        }
    }
    let read_card = format!(
        r#"<section class="card pad read-pane read-pane--message" data-read-pane>
  <header class="msg-head">
    <h1 class="msg-subject">{subject}</h1>
    {sender}
    <div class="form-actions msg-actions">
      <a class="btn btn-primary btn-sm" href="/compose?reply={id}">Reply</a>
      <a class="btn btn-ghost btn-sm" href="/compose?replyall={id}">Reply all</a>
      <a class="btn btn-ghost btn-sm" href="/compose?forward={id}">Forward</a>
      {convo}
    </div>
    <div class="co-actionbar">{actions}</div>
    {labels}
  </header>
  {spam_banner}
  {attachments}
  {body}
</section>"#,
        sender = sender,
        id = esc(&msg.id),
        convo = convo_html,
        labels = labels_html,
        spam_banner = spam_banner,
        // Read-view actions return to the message so a star/unread toggle stays in context.
        actions = row_actions(
            &msg.id,
            msg.starred,
            msg.seen,
            &msg.folder,
            msg.snooze_until,
            msg.muted,
            &token,
            &format!("/m/{}", url_encode(&msg.id))
        ),
    );
    let reader = render_split_reader(&pane_rows, &read_card, prefs);
    let content = format!(
        r#"<nav class="crumbs"><a href="/?folder={folder}">← {folder_label}</a></nav>
{reader}"#,
        folder = esc(&msg.folder),
        folder_label = if msg.folder == "INBOX" {
            "Inbox".to_string()
        } else {
            esc(&msg.folder)
        },
    );
    let content = format!("{content}\n<script src=\"/assets/webmail.js\"></script>");
    let content = mail_shell(mail_sidebar(&msg.folder, "", &all_labels, &counts), content);
    let html = render_mail_page(&msg.subject, &email, &content, prefs);
    match set_cookie {
        Some(c) => ([(header::SET_COOKIE, c)], Html(html)).into_response(),
        None => Html(html).into_response(),
    }
}

/// Render the read-view label strip: a removable pill per applied label plus an add-label form
/// (only offering labels not already applied). CSRF double-submit; posts to `/m/{id}/labels`.
fn render_message_labels(id: &str, all: &[Label], applied: &[Label], token: &str) -> String {
    let mut pills = String::new();
    for l in applied {
        pills.push_str(&format!(
            r#"<form class="label-chip" method="post" action="/m/{id}/labels"><input type="hidden" name="csrf" value="{token}"><input type="hidden" name="op" value="remove"><input type="hidden" name="label" value="{lid}"><span class="pill label-pill">{name}</span><button class="label-x" type="submit" title="Remove label" aria-label="Remove label {name}">×</button></form>"#,
            id = esc(id),
            token = esc(token),
            lid = esc(&l.id),
            name = esc(&l.name),
        ));
    }
    let available: Vec<&Label> = all
        .iter()
        .filter(|l| !applied.iter().any(|a| a.id == l.id))
        .collect();
    let add_form = if available.is_empty() {
        String::new()
    } else {
        let mut opts = String::from(r#"<option value="" selected disabled>Add label…</option>"#);
        for l in &available {
            opts.push_str(&format!(
                r#"<option value="{id}">{name}</option>"#,
                id = esc(&l.id),
                name = esc(&l.name)
            ));
        }
        format!(
            r#"<form class="row-actions" method="post" action="/m/{id}/labels"><input type="hidden" name="csrf" value="{token}"><input type="hidden" name="op" value="add"><select class="move-select" name="label" aria-label="Add label">{opts}</select><button class="btn btn-ghost btn-sm" type="submit">Add</button></form>"#,
            id = esc(id),
            token = esc(token),
        )
    };
    format!(r#"<div class="msg-labels">{pills}{add_form}</div>"#)
}

fn render_spam_banner(in_spam: bool, annotation: Option<&SpamAnnotation>) -> String {
    if !in_spam {
        return String::new();
    }
    let detail = annotation
        .filter(|a| !a.reason.trim().is_empty())
        .map(|a| format!(" Score {}: {}", a.score, a.reason.trim()))
        .unwrap_or_else(|| " Marked as spam.".to_string());
    format!(
        r#"<div class="spam-banner" role="note"><b>Spam</b><span>{detail}</span></div>"#,
        detail = esc(&detail),
    )
}

/// Query for `GET /t`: the conversation (thread) id.
#[derive(Deserialize)]
struct ConversationQuery {
    id: String,
}

/// `GET /t?id=<thread_id>` — the conversation view: every message in the thread the signed-in user
/// owns, oldest first. Marks the whole thread read. Reply/forward act on the newest message.
async fn conversation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ConversationQuery>,
) -> Response {
    let email = email_display(&headers);
    let Some(mb) = resolve_mailbox(&state, &headers).await else {
        return no_mailbox_page(&email);
    };
    let settings = settings_for_page(&state, &mb.addr).await;
    let prefs = page_prefs(&settings);
    let labels = state.store.list_labels(&mb.addr).await.unwrap_or_default();
    let counts = state
        .store
        .folder_counts(&mb.addr)
        .await
        .unwrap_or_default();
    let msgs = match state.store.list_thread(&mb.addr, &q.id, PAGE_MAX).await {
        Ok(m) => m,
        Err(e) => {
            return error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Storage error",
                &e.to_string(),
            );
        }
    };
    if msgs.is_empty() {
        return error_page(StatusCode::NOT_FOUND, "Not found", "No such conversation.");
    }

    // The subject of the conversation = the earliest message's subject.
    let subject = msgs
        .first()
        .map(|m| {
            if m.subject.trim().is_empty() {
                "(no subject)".to_string()
            } else {
                esc(&m.subject)
            }
        })
        .unwrap_or_else(|| "(no subject)".to_string());
    let latest_id = msgs.last().map(|m| m.id.clone()).unwrap_or_default();

    let mut blocks = String::new();
    for m in &msgs {
        let _ = state.store.mark_seen(&m.id).await;
        let body = render_message_body(m);
        let attachments = render_attachment_list(m);
        let sender = msg_from_block(&m.msg_from, &m.msg_to, m.received_at);
        blocks.push_str(&format!(
            r#"<section class="card pad read-pane read-pane--conversation convo-msg" data-read-pane data-convo-item>
  <header class="msg-head">
    {sender}
    <div class="form-actions msg-actions">
      <button class="btn btn-ghost btn-sm convo-toggle" type="button" data-convo-toggle aria-expanded="true">Collapse</button>
      <a class="btn btn-ghost btn-sm" href="/m/{id}">Open</a>
      <a class="btn btn-ghost btn-sm" href="/compose?reply={id}">Reply</a>
      <a class="btn btn-ghost btn-sm" href="/compose?forward={id}">Forward</a>
    </div>
  </header>
  {attachments}
  {body}
</section>"#,
            sender = sender,
            id = esc(&m.id),
        ));
    }

    let main = format!(
        r#"<nav class="crumbs"><a href="/">← Inbox</a></nav>
<div class="page-head"><h1>{subject} <span class="pill thread-count">{count}</span></h1><a class="btn btn-primary btn-sm" href="/compose?replyall={latest}">Reply all</a></div>
{blocks}
<script src="/assets/webmail.js"></script>"#,
        count = msgs.len(),
        latest = esc(&latest_id),
    );
    let content = mail_shell(mail_sidebar("INBOX", "", &labels, &counts), main);
    Html(render_mail_page("Conversation", &email, &content, prefs)).into_response()
}

/// Form body for `POST /m/{id}/labels`: CSRF, `op` (`add`|`remove`), and the `label` id.
#[derive(Deserialize, Default)]
struct MessageLabelForm {
    csrf: String,
    #[serde(default)]
    op: String,
    #[serde(default)]
    label: String,
}

/// `POST /m/{id}/labels` — add/remove a label on a message. CSRF-guarded; the store enforces that
/// both the message and the label belong to the signed-in user's mailbox. Redirects back to the
/// message.
async fn message_labels_post(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(form): Form<MessageLabelForm>,
) -> Response {
    if !verify_csrf(&headers, &form.csrf) {
        return error_page(
            StatusCode::FORBIDDEN,
            "Request blocked",
            "CSRF token missing or mismatched.",
        );
    }
    let Some(mb) = resolve_mailbox(&state, &headers).await else {
        return no_mailbox_page(&email_display(&headers));
    };
    // Authorisation: the message must belong to this mailbox (mirrors the read/action views).
    match state.store.get_message(&id).await {
        Ok(Some(m)) if m.mailbox == mb.addr => {}
        Ok(_) => return error_page(StatusCode::NOT_FOUND, "Not found", "No such message."),
        Err(e) => {
            return error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Storage error",
                &e.to_string(),
            );
        }
    }
    let label_id = form.label.trim();
    let result = match form.op.as_str() {
        "add" => state.store.assign_label(&mb.addr, &id, label_id).await,
        "remove" => state.store.remove_label(&mb.addr, &id, label_id).await,
        _ => {
            return error_page(
                StatusCode::BAD_REQUEST,
                "Invalid request",
                "Unknown label action.",
            );
        }
    };
    if let Err(e) = result {
        return error_page(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Storage error",
            &e.to_string(),
        );
    }
    tracing::info!(
        target: "corvid::audit",
        actor = %identity_subject(&headers).unwrap_or_default(),
        mailbox = %mb.addr,
        message = %id,
        op = %form.op,
        label = %label_id,
        "message label change",
    );
    Redirect::to(&format!("/m/{}", url_encode(&id))).into_response()
}

/// Form body for `POST /m/{id}/action`: a double-submit CSRF token, the operation `op`
/// (`star|unstar|read|unread|archive|snooze|unsnooze|mute|unmute|report_spam|not_spam|delete|move`),
/// a target `folder` (only for `op=move`), and a safe local `return` path to redirect back to.
#[derive(Deserialize, Default)]
struct ActionForm {
    csrf: String,
    #[serde(default)]
    op: String,
    #[serde(default)]
    folder: String,
    #[serde(default)]
    snooze_until: String,
    #[serde(default)]
    snooze_custom: String,
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
        return error_page(
            StatusCode::FORBIDDEN,
            "Request blocked",
            "CSRF token missing or mismatched.",
        );
    }
    let Some(mb) = resolve_mailbox(&state, &headers).await else {
        return no_mailbox_page(&email_display(&headers));
    };
    let msg = match state.store.get_message(&id).await {
        Ok(Some(m)) => m,
        Ok(None) => return error_page(StatusCode::NOT_FOUND, "Not found", "No such message."),
        Err(e) => {
            return error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Storage error",
                &e.to_string(),
            );
        }
    };
    if msg.mailbox != mb.addr {
        return error_page(StatusCode::NOT_FOUND, "Not found", "No such message.");
    }

    if let Err((code, message)) = apply_message_op(
        &state,
        &msg,
        &form.op,
        &form.folder,
        &form.snooze_until,
        &form.snooze_custom,
    )
    .await
    {
        if code == StatusCode::BAD_REQUEST {
            return error_page(StatusCode::BAD_REQUEST, "Invalid request", &message);
        }
        return error_page(StatusCode::INTERNAL_SERVER_ERROR, "Storage error", &message);
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

/// Apply a single per-message `op` to `id`, returning the message's resulting (op-implied) state as
/// a small JSON value on success. Shared by [`api_message_action`] (one message) and
/// [`api_bulk_action`] (a batch) so both endpoints run the SAME store mutations as the form route.
/// `Err((status, message))` marks an invalid op / target folder or a storage failure.
async fn apply_message_op(
    state: &AppState,
    msg: &Message,
    op: &str,
    folder: &str,
    snooze_until: &str,
    snooze_custom: &str,
) -> Result<serde_json::Value, (StatusCode, String)> {
    use serde_json::json;
    let err500 = |e: crate::store::StoreError| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string());
    let id = msg.id.as_str();
    match op {
        "delete" => state
            .store
            .set_folder(id, "Trash")
            .await
            .map(|_| json!({"ok": true, "id": id, "op": op, "folder": "Trash"}))
            .map_err(err500),
        "archive" => state
            .store
            .set_folder(id, "Archive")
            .await
            .map(|_| json!({"ok": true, "id": id, "op": op, "folder": "Archive"}))
            .map_err(err500),
        "move" => {
            let Some(f) = real_folder(folder) else {
                return Err((StatusCode::BAD_REQUEST, "unknown target folder".to_string()));
            };
            state
                .store
                .set_folder(id, f)
                .await
                .map(|_| json!({"ok": true, "id": id, "op": op, "folder": f}))
                .map_err(err500)
        }
        "report_spam" => {
            state
                .store
                .set_folder(id, crate::delivery::SPAM_FOLDER)
                .await
                .map_err(err500)?;
            let listed = upsert_sender_for_message(state, msg, "blocked")
                .await
                .map_err(err500)?;
            let reason = listed
                .as_deref()
                .map(|addr| format!("User reported as spam; blocked sender list match: {addr}"))
                .unwrap_or_else(|| "User reported as spam".to_string());
            state
                .store
                .set_spam_annotation(&SpamAnnotation {
                    mailbox: msg.mailbox.clone(),
                    message_id: msg.id.clone(),
                    score: 100,
                    reason,
                })
                .await
                .map_err(err500)?;
            Ok(json!({"ok": true, "id": id, "op": op, "folder": crate::delivery::SPAM_FOLDER}))
        }
        "not_spam" => {
            state.store.set_folder(id, "INBOX").await.map_err(err500)?;
            upsert_sender_for_message(state, msg, "safe")
                .await
                .map_err(err500)?;
            state
                .store
                .delete_spam_annotation(&msg.mailbox, id)
                .await
                .map_err(err500)?;
            Ok(json!({"ok": true, "id": id, "op": op, "folder": "INBOX"}))
        }
        "snooze" => {
            let until = parse_snooze_epoch(snooze_until, snooze_custom)?;
            state
                .store
                .snooze_message(id, until)
                .await
                .map_err(err500)?;
            Ok(json!({"ok": true, "id": id, "op": op, "folder": "Archive", "snooze_until": until}))
        }
        "unsnooze" => {
            state.store.unsnooze_message(id).await.map_err(err500)?;
            Ok(json!({"ok": true, "id": id, "op": op, "folder": "INBOX", "snooze_until": 0}))
        }
        "mute" => {
            state
                .store
                .set_thread_muted(msg, true)
                .await
                .map_err(err500)?;
            Ok(json!({"ok": true, "id": id, "op": op, "muted": true}))
        }
        "unmute" => {
            state
                .store
                .set_thread_muted(msg, false)
                .await
                .map_err(err500)?;
            Ok(json!({"ok": true, "id": id, "op": op, "muted": false}))
        }
        "unread" => state
            .store
            .mark_unseen(id)
            .await
            .map(|_| json!({"ok": true, "id": id, "op": op, "seen": false}))
            .map_err(err500),
        "read" => state
            .store
            .mark_seen(id)
            .await
            .map(|_| json!({"ok": true, "id": id, "op": op, "seen": true}))
            .map_err(err500),
        "star" => state
            .store
            .set_starred(id, true)
            .await
            .map(|_| json!({"ok": true, "id": id, "op": op, "starred": true}))
            .map_err(err500),
        "unstar" => state
            .store
            .set_starred(id, false)
            .await
            .map(|_| json!({"ok": true, "id": id, "op": op, "starred": false}))
            .map_err(err500),
        _ => Err((StatusCode::BAD_REQUEST, "unknown action".to_string())),
    }
}

fn parse_snooze_epoch(preset: &str, custom: &str) -> Result<i64, (StatusCode, String)> {
    parse_future_epoch(preset, custom, "snooze")
}

fn parse_schedule_epoch(preset: &str, custom: &str) -> Result<i64, (StatusCode, String)> {
    parse_future_epoch(preset, custom, "schedule")
}

fn parse_undo_send_window_secs(raw: &str) -> Result<i64, (StatusCode, String)> {
    let secs = raw.trim().parse::<i64>().map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "Undo send window must be 5, 10, 20, or 30 seconds.".to_string(),
        )
    })?;
    if UNDO_SEND_WINDOW_CHOICES.contains(&secs) {
        Ok(secs)
    } else {
        Err((
            StatusCode::BAD_REQUEST,
            "Undo send window must be 5, 10, 20, or 30 seconds.".to_string(),
        ))
    }
}

fn effective_undo_send_window_secs(secs: i64) -> i64 {
    if secs == 0 || UNDO_SEND_WINDOW_CHOICES.contains(&secs) {
        secs
    } else {
        DEFAULT_UNDO_SEND_WINDOW_SECS
    }
}

fn effective_density(raw: &str) -> &'static str {
    choice_or_default(raw, &DENSITY_CHOICES, DEFAULT_DENSITY)
}

fn effective_reading_pane(raw: &str) -> &'static str {
    choice_or_default(raw, &READING_PANE_CHOICES, DEFAULT_READING_PANE)
}

fn effective_theme(raw: &str) -> &'static str {
    choice_or_default(raw, &THEME_CHOICES, DEFAULT_THEME)
}

fn choice_or_default(raw: &str, choices: &[&'static str], default: &'static str) -> &'static str {
    let raw = raw.trim();
    choices
        .iter()
        .copied()
        .find(|choice| *choice == raw)
        .unwrap_or(default)
}

fn parse_display_choice(
    raw: &str,
    choices: &[&'static str],
    label: &str,
) -> Result<&'static str, (StatusCode, String)> {
    let raw = raw.trim();
    choices
        .iter()
        .copied()
        .find(|choice| *choice == raw)
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                format!("Invalid {label} preference."),
            )
        })
}

fn parse_future_epoch(
    preset: &str,
    custom: &str,
    label: &str,
) -> Result<i64, (StatusCode, String)> {
    let raw = custom.trim();
    let raw = if raw.is_empty() { preset.trim() } else { raw };
    let until = raw
        .parse::<i64>()
        .map_err(|_| (StatusCode::BAD_REQUEST, format!("invalid {label} time")))?;
    if until <= now_secs() {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("{label} time must be in the future"),
        ));
    }
    Ok(until)
}

#[derive(Deserialize, Default)]
struct ScheduledActionForm {
    csrf: String,
    #[serde(default)]
    op: String,
    #[serde(default)]
    schedule_at: String,
    #[serde(default)]
    schedule_custom: String,
    #[serde(default, rename = "return")]
    return_to: String,
}

async fn scheduled_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(batch_id): Path<String>,
    Form(form): Form<ScheduledActionForm>,
) -> Response {
    if !verify_csrf(&headers, &form.csrf) {
        return error_page(
            StatusCode::FORBIDDEN,
            "Request blocked",
            "CSRF token missing or mismatched.",
        );
    }
    let Some(mb) = resolve_mailbox(&state, &headers).await else {
        return no_mailbox_page(&email_display(&headers));
    };
    let now = now_secs();
    let result = match form.op.as_str() {
        "reschedule" => {
            let send_at = match parse_schedule_epoch(&form.schedule_at, &form.schedule_custom) {
                Ok(ts) => ts,
                Err((code, message)) => return error_page(code, "Invalid request", &message),
            };
            state
                .store
                .reschedule_scheduled_outbound(&mb.addr, &batch_id, send_at, now)
                .await
        }
        "cancel" => {
            state
                .store
                .cancel_scheduled_outbound(&mb.addr, &batch_id, now)
                .await
        }
        "draft" => {
            let item = match state
                .store
                .get_scheduled_outbound(&mb.addr, &batch_id, now)
                .await
            {
                Ok(Some(item)) => item,
                Ok(None) => {
                    return error_page(
                        StatusCode::NOT_FOUND,
                        "Not found",
                        "No such scheduled send.",
                    );
                }
                Err(e) => {
                    return error_page(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Storage error",
                        &e.to_string(),
                    );
                }
            };
            let parsed = crate::rfc822::parse(&item.raw);
            let from = if parsed.from.trim().is_empty() {
                item.env_from.clone()
            } else {
                parsed.from
            };
            let to = if parsed.to.trim().is_empty() {
                item.rcpts.join(", ")
            } else {
                parsed.to
            };
            store_local_copy(
                &state,
                &mb.addr,
                &from,
                &to,
                &parsed.subject,
                &parsed.body_text,
                &parsed.body_html,
                &item.raw,
                "Drafts",
            )
            .await;
            state
                .store
                .cancel_scheduled_outbound(&mb.addr, &batch_id, now)
                .await
        }
        _ => {
            return error_page(
                StatusCode::BAD_REQUEST,
                "Invalid request",
                "Unknown action.",
            );
        }
    };
    let changed = match result {
        Ok(changed) => changed,
        Err(e) => {
            return error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Storage error",
                &e.to_string(),
            );
        }
    };
    if !changed {
        return error_page(
            StatusCode::NOT_FOUND,
            "Not found",
            "No such scheduled send.",
        );
    }
    tracing::info!(
        target: "corvid::audit",
        actor = %identity_subject(&headers).unwrap_or_default(),
        mailbox = %mb.addr,
        batch = %batch_id,
        op = %form.op,
        "scheduled send action",
    );
    if form.op == "draft" {
        Redirect::to("/?folder=Drafts").into_response()
    } else {
        Redirect::to(&safe_return(&form.return_to)).into_response()
    }
}

#[derive(Deserialize, Default)]
struct UndoSendForm {
    csrf: String,
    #[serde(default)]
    batch_id: String,
}

async fn send_undo(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<UndoSendForm>,
) -> Response {
    if !verify_csrf(&headers, &form.csrf) {
        return error_page(
            StatusCode::FORBIDDEN,
            "Request blocked",
            "CSRF token missing or mismatched.",
        );
    }
    let Some(mb) = resolve_mailbox(&state, &headers).await else {
        return no_mailbox_page(&email_display(&headers));
    };
    let batch_id = form.batch_id.trim();
    if batch_id.is_empty() {
        return error_page(
            StatusCode::BAD_REQUEST,
            "Invalid request",
            "Missing undo token.",
        );
    }
    let now = now_secs();
    let item = match state
        .store
        .get_scheduled_outbound(&mb.addr, batch_id, now)
        .await
    {
        Ok(Some(item)) => item,
        Ok(None) => {
            return error_page(
                StatusCode::NOT_FOUND,
                "Not found",
                "Undo window has expired.",
            );
        }
        Err(e) => {
            return error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Storage error",
                &e.to_string(),
            );
        }
    };
    let changed = match state
        .store
        .cancel_scheduled_outbound(&mb.addr, batch_id, now)
        .await
    {
        Ok(changed) => changed,
        Err(e) => {
            return error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Storage error",
                &e.to_string(),
            );
        }
    };
    if !changed {
        return error_page(
            StatusCode::NOT_FOUND,
            "Not found",
            "Undo window has expired.",
        );
    }
    let parsed = crate::rfc822::parse(&item.raw);
    let from = if parsed.from.trim().is_empty() {
        item.env_from.clone()
    } else {
        parsed.from
    };
    let to = if parsed.to.trim().is_empty() {
        item.rcpts.join(", ")
    } else {
        parsed.to
    };
    store_local_copy(
        &state,
        &mb.addr,
        &from,
        &to,
        &parsed.subject,
        &parsed.body_text,
        &parsed.body_html,
        &item.raw,
        "Drafts",
    )
    .await;
    tracing::info!(
        target: "corvid::audit",
        actor = %identity_subject(&headers).unwrap_or_default(),
        mailbox = %mb.addr,
        batch = %batch_id,
        "send undone",
    );
    Redirect::to("/?folder=Drafts").into_response()
}

async fn cancel_replaced_scheduled(state: &AppState, mailbox: &str, batch_id: &str) {
    let batch_id = batch_id.trim();
    if batch_id.is_empty() {
        return;
    }
    if let Err(e) = state
        .store
        .cancel_scheduled_outbound(mailbox, batch_id, now_secs())
        .await
    {
        tracing::warn!(error = %e, mailbox, batch_id, "failed to remove replaced scheduled send");
    }
}

async fn upsert_sender_for_message(
    state: &AppState,
    msg: &Message,
    kind: &str,
) -> Result<Option<String>, crate::store::StoreError> {
    let Some(address_or_domain) = normalize_sender_list_value(&msg.msg_from) else {
        return Ok(None);
    };
    let entry = SenderListEntry {
        id: new_id("sl"),
        user: msg.mailbox.clone(),
        address_or_domain: address_or_domain.clone(),
        kind: kind.to_string(),
        created_at: now_secs(),
    };
    state.store.upsert_sender_list(&entry).await?;
    Ok(Some(address_or_domain))
}

fn normalize_sender_list_value(raw: &str) -> Option<String> {
    let extracted = extract_addr(raw);
    let mut value = extracted
        .trim()
        .trim_start_matches('@')
        .trim_end_matches('.')
        .to_ascii_lowercase();
    value.retain(|c| !c.is_whitespace() && !c.is_control());
    if value.is_empty() {
        return None;
    }
    if value.contains('@') {
        let (local, domain) = value.split_once('@')?;
        if local.is_empty() || domain.is_empty() || !domain.contains('.') {
            return None;
        }
        return Some(value);
    }
    if value.contains('.') {
        Some(value)
    } else {
        None
    }
}

/// `POST /api/m/{id}/action` — the JSON sibling of [`message_action`] powering the optimistic,
/// no-reload row/read actions. IDENTICAL guard rails: double-submit CSRF, the SAME owner
/// authorisation (a message is only actionable from its own mailbox), the SAME store mutation, and
/// a mirrored audit line. Returns a small JSON envelope describing the message's new state.
async fn api_message_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(form): Form<ActionForm>,
) -> Response {
    if !verify_csrf(&headers, &form.csrf) {
        return json_status(StatusCode::FORBIDDEN, "CSRF token missing or mismatched");
    }
    let Some(mb) = resolve_mailbox(&state, &headers).await else {
        return json_status(StatusCode::FORBIDDEN, "no mailbox for this identity");
    };
    let msg = match state.store.get_message(&id).await {
        Ok(Some(m)) => m,
        Ok(None) => return json_status(StatusCode::NOT_FOUND, "no such message"),
        Err(e) => return json_status(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    };
    if msg.mailbox != mb.addr {
        return json_status(StatusCode::NOT_FOUND, "no such message");
    }
    match apply_message_op(
        &state,
        &msg,
        &form.op,
        &form.folder,
        &form.snooze_until,
        &form.snooze_custom,
    )
    .await
    {
        Ok(body) => {
            tracing::info!(
                target: "corvid::audit",
                actor = %identity_subject(&headers).unwrap_or_default(),
                mailbox = %mb.addr,
                message = %id,
                op = %form.op,
                folder = %form.folder,
                "message action (api)",
            );
            (StatusCode::OK, Json(body)).into_response()
        }
        Err((code, message)) => json_status(code, &message),
    }
}

/// Form body for `POST /api/m/bulk`: CSRF, `op`, an optional `folder` (for `move`), and a
/// comma-separated `ids` batch.
#[derive(Deserialize, Default)]
struct BulkForm {
    csrf: String,
    #[serde(default)]
    op: String,
    #[serde(default)]
    folder: String,
    #[serde(default)]
    snooze_until: String,
    #[serde(default)]
    snooze_custom: String,
    #[serde(default)]
    ids: String,
}

/// `POST /api/m/bulk` — apply one `op` (`read|unread|archive|snooze|unsnooze|mute|unmute|report_spam|not_spam|delete|move`) to a batch of the
/// signed-in mailbox's messages, for the multi-select bulk toolbar. Double-submit CSRF; EACH id is
/// re-checked to belong to this mailbox (a forged/foreign id in the batch is skipped, never
/// actioned), reusing the SAME per-message store mutations via [`apply_message_op`]. Returns the
/// count actually applied.
async fn api_bulk_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<BulkForm>,
) -> Response {
    if !verify_csrf(&headers, &form.csrf) {
        return json_status(StatusCode::FORBIDDEN, "CSRF token missing or mismatched");
    }
    let Some(mb) = resolve_mailbox(&state, &headers).await else {
        return json_status(StatusCode::FORBIDDEN, "no mailbox for this identity");
    };
    // A deliberately narrow (non-star) bulk op set; `move` still needs a real target folder.
    if !matches!(
        form.op.as_str(),
        "read"
            | "unread"
            | "archive"
            | "snooze"
            | "unsnooze"
            | "mute"
            | "unmute"
            | "report_spam"
            | "not_spam"
            | "delete"
            | "move"
    ) {
        return json_status(StatusCode::BAD_REQUEST, "unknown bulk action");
    }
    if form.op == "move" && real_folder(&form.folder).is_none() {
        return json_status(StatusCode::BAD_REQUEST, "unknown target folder");
    }
    if form.op == "snooze" && parse_snooze_epoch(&form.snooze_until, &form.snooze_custom).is_err() {
        return json_status(StatusCode::BAD_REQUEST, "invalid snooze time");
    }
    let ids: Vec<&str> = form
        .ids
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    let mut applied = 0i64;
    for id in ids {
        // Cross-mailbox safety: only act on ids this mailbox actually owns.
        let msg = match state.store.get_message(id).await {
            Ok(Some(m)) if m.mailbox == mb.addr => m,
            _ => continue,
        };
        if apply_message_op(
            &state,
            &msg,
            &form.op,
            &form.folder,
            &form.snooze_until,
            &form.snooze_custom,
        )
        .await
        .is_ok()
        {
            applied += 1;
        }
    }
    tracing::info!(
        target: "corvid::audit",
        actor = %identity_subject(&headers).unwrap_or_default(),
        mailbox = %mb.addr,
        op = %form.op,
        folder = %form.folder,
        applied,
        "bulk message action (api)",
    );
    (
        StatusCode::OK,
        Json(serde_json::json!({ "ok": true, "op": form.op, "applied": applied })),
    )
        .into_response()
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
    if ok {
        p.to_string()
    } else {
        "/".to_string()
    }
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
    format!(
        r#"<div class="attachments"><b class="attach-head">Attachments</b><ul class="attach-list">{items}</ul></div>"#
    )
}

fn draft_attachment_refs(msg: &Message) -> (String, String) {
    let attachments = crate::rfc822::list_attachments(&msg.raw_rfc822);
    if attachments.is_empty() {
        return (String::new(), String::new());
    }
    let mut refs = Vec::new();
    let mut items = String::new();
    for a in &attachments {
        refs.push(format!("{}:{}", msg.id, a.index));
        items.push_str(&format!(
            r#"<li>{name} <span class="muted attach-size">{size}</span></li>"#,
            name = esc(&a.filename),
            size = human_size(a.size),
        ));
    }
    (
        refs.join(","),
        format!(
            r#"<div class="attachments compose-attachments"><b class="attach-head">Attached to this draft</b><ul class="attach-list">{items}</ul></div>"#
        ),
    )
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
    let Some((att, inline)) = crate::rfc822::extract_attachment_with_inline(&msg.raw_rfc822, idx)
    else {
        return (StatusCode::NOT_FOUND, "no such attachment").into_response();
    };
    // `filename` + `content_type` are already sanitised by rfc822 (no CRLF/quotes), so they are
    // safe to echo into response headers.
    let disposition_kind = if inline { "inline" } else { "attachment" };
    let disposition = format!("{disposition_kind}; filename=\"{}\"", att.filename);
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
    draft: Option<String>,
    #[serde(default)]
    reply: Option<String>,
    #[serde(default)]
    replyall: Option<String>,
    #[serde(default)]
    forward: Option<String>,
    #[serde(default)]
    scheduled: Option<String>,
}

/// The prefilled compose fields (empty for a blank New message).
#[derive(Default)]
struct Prefill {
    to: String,
    cc: String,
    subject: String,
    body: String,
    body_html: String,
    in_reply_to: String,
    references: String,
    draft_id: String,
    attachment_refs: String,
    attachment_list: String,
    scheduled_batch_id: String,
    schedule_at: i64,
}

fn default_signature_for_identity<'a>(
    signatures: &'a [Signature],
    identity: &str,
) -> Option<&'a Signature> {
    let wanted = identity.trim();
    if !wanted.is_empty() {
        if let Some(sig) = signatures
            .iter()
            .filter(|s| s.identity == wanted && s.is_default)
            .max_by(|a, b| {
                a.created_at
                    .cmp(&b.created_at)
                    .then_with(|| b.id.cmp(&a.id))
            })
        {
            return Some(sig);
        }
    }
    signatures
        .iter()
        .filter(|s| s.identity.is_empty() && s.is_default)
        .max_by(|a, b| {
            a.created_at
                .cmp(&b.created_at)
                .then_with(|| b.id.cmp(&a.id))
        })
}

fn plain_text_to_compose_html(text: &str) -> String {
    let text = text.trim();
    if text.is_empty() {
        return String::new();
    }
    format!("<p>{}</p>", esc(text).replace('\n', "<br>"))
}

fn signature_blocks(sig: &Signature) -> (String, String) {
    let clean_html = crate::sanitize::sanitize_html(&sig.body_html);
    let body_text = if sig.body_text.trim().is_empty() && !clean_html.trim().is_empty() {
        crate::sanitize::html_to_text(&clean_html)
    } else {
        sig.body_text.trim().to_string()
    };
    if body_text.trim().is_empty() && clean_html.trim().is_empty() {
        return (String::new(), String::new());
    }

    let text_block = if body_text.trim().is_empty() {
        String::new()
    } else {
        format!("\n\n--\n{}", body_text.trim())
    };
    let html_block = if clean_html.trim().is_empty() {
        plain_text_to_compose_html(&text_block)
    } else {
        format!("<p><br></p><p>--</p>{clean_html}")
    };
    (text_block, html_block)
}

fn append_signature_to_prefill(pre: &mut Prefill, sig: &Signature) -> (String, String) {
    let (sig_text, sig_html) = signature_blocks(sig);
    if sig_text.is_empty() && sig_html.is_empty() {
        return (String::new(), String::new());
    }
    let base_text = pre.body.clone();
    pre.body.push_str(&sig_text);
    if !sig_html.trim().is_empty() && !sig.body_html.trim().is_empty() {
        let base_html = if pre.body_html.trim().is_empty() {
            plain_text_to_compose_html(&base_text)
        } else {
            crate::sanitize::sanitize_html(&pre.body_html)
        };
        pre.body_html = format!("{base_html}{sig_html}");
    }
    (sig_text, sig_html)
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
    let (token, set_cookie) = ensure_csrf(&headers);
    let settings = settings_for_page(&state, &mb.addr).await;
    let prefs = page_prefs(&settings);

    // Seed the draft from the original when a reply/forward id is present (and it belongs to us).
    let mut pre = build_prefill(&state, &mb, &q).await;

    // The "From" selector: the mailbox's own address (implicit default) plus any owned identities.
    let identities = state
        .store
        .list_send_identities(&mb.addr)
        .await
        .unwrap_or_default();
    let signatures = state
        .store
        .list_signatures(&mb.addr)
        .await
        .unwrap_or_default();
    let default_selected = !identities.iter().any(|i| i.is_default);
    let selected_identity_addr = identities
        .iter()
        .find(|i| i.is_default)
        .map(|i| i.from_addr.as_str())
        .unwrap_or(mb.addr.as_str());
    let mut current_signature_text = String::new();
    let mut current_signature_html = String::new();
    // Per-identity signature: appended to new drafts (blank compose, reply, forward) as the
    // conventional `--` delimited block. Editing an existing Drafts row or scheduled send keeps
    // the stored body unchanged.
    if pre.draft_id.is_empty() && pre.scheduled_batch_id.is_empty() {
        if let Some(sig) = default_signature_for_identity(&signatures, selected_identity_addr) {
            let (text, html) = append_signature_to_prefill(&mut pre, sig);
            current_signature_text = text;
            current_signature_html = html;
        }
    }
    let (mailbox_sig_text, mailbox_sig_html) =
        default_signature_for_identity(&signatures, &mb.addr)
            .map(signature_blocks)
            .unwrap_or_default();
    let mut from_options = format!(
        r#"<option value="" data-identity-addr="{identity}" data-signature-text="{sig_text}" data-signature-html="{sig_html}"{sel}>{addr}</option>"#,
        addr = esc(&mb.addr),
        identity = esc(&mb.addr),
        sig_text = url_encode(&mailbox_sig_text),
        sig_html = url_encode(&mailbox_sig_html),
        sel = if default_selected { " selected" } else { "" },
    );
    for idn in &identities {
        let label = if idn.display_name.trim().is_empty() {
            idn.from_addr.clone()
        } else {
            format!("{} <{}>", idn.display_name, idn.from_addr)
        };
        let (sig_text, sig_html) = default_signature_for_identity(&signatures, &idn.from_addr)
            .map(signature_blocks)
            .unwrap_or_default();
        from_options.push_str(&format!(
            r#"<option value="{id}" data-identity-addr="{identity}" data-signature-text="{sig_text}" data-signature-html="{sig_html}"{sel}>{label}</option>"#,
            id = esc(&idn.id),
            identity = esc(&idn.from_addr),
            sig_text = url_encode(&sig_text),
            sig_html = url_encode(&sig_html),
            label = esc(&label),
            sel = if idn.is_default { " selected" } else { "" },
        ));
    }
    let templates = state
        .store
        .list_templates(&mb.addr)
        .await
        .unwrap_or_default();

    let content = format!(
        r#"<nav class="crumbs"><a href="/">← Inbox</a></nav>
<section class="card pad compose-card co-composer">
  <div class="page-head"><h1>New message</h1></div>
  <form method="post" action="/send" enctype="multipart/form-data" data-current-signature-text="{current_signature_text}" data-current-signature-html="{current_signature_html}">
    <input type="hidden" name="csrf" value="{token}">
    <input type="hidden" name="in_reply_to" value="{in_reply_to}">
    <input type="hidden" name="references" value="{references}">
    <input type="hidden" name="draft_id" value="{draft_id}">
    <input type="hidden" name="attachment_refs" value="{attachment_refs}">
    <input type="hidden" name="scheduled_batch_id" value="{scheduled_batch_id}">
    <div class="field"><label for="from">From</label><select id="from" name="identity">{from_options}</select></div>
    <div class="field"><label for="to">To</label>
      <div class="combo"><input id="to" name="to" value="{to}" placeholder="someone@example.com" role="combobox" aria-expanded="false" aria-autocomplete="list" aria-controls="to-list" autocomplete="off" data-autocomplete><ul class="combo__list" id="to-list" role="listbox" hidden></ul></div>
    </div>
    <div class="field"><label for="cc">Cc</label>
      <div class="combo"><input id="cc" name="cc" value="{cc}" placeholder="(optional)" role="combobox" aria-expanded="false" aria-autocomplete="list" aria-controls="cc-list" autocomplete="off" data-autocomplete><ul class="combo__list" id="cc-list" role="listbox" hidden></ul></div>
    </div>
    <div class="field"><label for="subject">Subject</label><input id="subject" name="subject" value="{subject}" placeholder="Subject"></div>
    <div class="field compose-field"><label for="body">Message</label>
      <input type="hidden" id="body_html" name="body_html" value="{body_html}">
      <div class="compose-toolbar" data-compose-toolbar role="toolbar" aria-label="Formatting tools" hidden>
        <button class="btn btn-ghost btn-sm" type="button" data-cmd="bold" title="Bold" aria-label="Bold"><strong>B</strong></button>
        <button class="btn btn-ghost btn-sm" type="button" data-cmd="italic" title="Italic" aria-label="Italic"><em>I</em></button>
        <button class="btn btn-ghost btn-sm" type="button" data-cmd="underline" title="Underline" aria-label="Underline"><u>U</u></button>
        <button class="btn btn-ghost btn-sm" type="button" data-cmd="insertUnorderedList" title="Bulleted list" aria-label="Bulleted list">UL</button>
        <button class="btn btn-ghost btn-sm" type="button" data-cmd="insertOrderedList" title="Numbered list" aria-label="Numbered list">OL</button>
        <button class="btn btn-ghost btn-sm" type="button" data-cmd="outdent" title="Outdent" aria-label="Outdent">Out</button>
        <button class="btn btn-ghost btn-sm" type="button" data-cmd="indent" title="Indent" aria-label="Indent">In</button>
        <button class="btn btn-ghost btn-sm" type="button" data-cmd="blockquote" title="Quote" aria-label="Quote">Quote</button>
        <button class="btn btn-ghost btn-sm" type="button" data-cmd="createLink" title="Insert or edit link" aria-label="Insert or edit link">Link</button>
        <button class="btn btn-ghost btn-sm" type="button" data-cmd="unlink" title="Remove link" aria-label="Remove link">Unlink</button>
        <button class="btn btn-ghost btn-sm" type="button" data-cmd="clear" title="Clear formatting" aria-label="Clear formatting">Tx</button>
      </div>
      {template_controls}
      <div id="body-rich" class="compose-rich" role="textbox" aria-multiline="true" contenteditable="true" data-source="body" data-placeholder="Write your message…" hidden></div>
      <textarea id="body" name="body">{body}</textarea>
    </div>
    <div class="field"><label for="attachments">Attachments</label><input id="attachments" name="attachments" type="file" multiple>{attachment_list}</div>
    <div class="form-actions">
      <span class="autosave-status" data-autosave-status aria-live="polite"></span>
      <div class="send-split">
        <button class="btn btn-primary" type="submit" name="action" value="send">Send</button>
        <details class="co-schedule"><summary aria-label="Schedule send"></summary><div class="co-schedule__panel">{schedule_controls}<button class="btn btn-ghost btn-schedule-send" type="submit" name="action" value="schedule">Schedule send</button></div></details>
      </div>
      <button class="btn btn-ghost" type="submit" name="action" value="draft">Save draft</button>
      <a class="btn btn-ghost btn-sm" href="/">Cancel</a>
    </div>
  </form>
</section>
<script src="/assets/compose.js"></script>"#,
        to = esc(&pre.to),
        cc = esc(&pre.cc),
        subject = esc(&pre.subject),
        body = esc(&pre.body),
        body_html = esc(&pre.body_html),
        in_reply_to = esc(&pre.in_reply_to),
        references = esc(&pre.references),
        draft_id = esc(&pre.draft_id),
        attachment_refs = esc(&pre.attachment_refs),
        attachment_list = pre.attachment_list,
        scheduled_batch_id = esc(&pre.scheduled_batch_id),
        current_signature_text = url_encode(&current_signature_text),
        current_signature_html = url_encode(&current_signature_html),
        schedule_controls = schedule_controls_for(now_secs(), pre.schedule_at),
        template_controls = render_compose_template_controls(&templates),
    );
    let html = render_page_with_prefs("Compose", &email, &content, "compose", prefs);
    match set_cookie {
        Some(c) => ([(header::SET_COOKIE, c)], Html(html)).into_response(),
        None => Html(html).into_response(),
    }
}

fn render_compose_template_controls(templates: &[Template]) -> String {
    if templates.is_empty() {
        return String::new();
    }
    let mut opts = String::from(r#"<option value="">Insert template...</option>"#);
    for t in templates {
        let body_html = crate::sanitize::sanitize_html(&t.body_html);
        opts.push_str(&format!(
            r#"<option value="{id}" data-body-html="{body_html}" data-body-text="{body_text}">{name}</option>"#,
            id = esc(&t.id),
            body_html = esc(&body_html),
            body_text = esc(&t.body_text),
            name = esc(&t.name),
        ));
    }
    format!(
        r#"<div class="template-menu" data-template-menu>
        <label for="template_select">Template</label>
        <select id="template_select" data-template-select>{opts}</select>
        <button class="btn btn-ghost btn-sm btn-insert-template" type="button" data-template-insert>Insert</button>
        <a class="btn btn-ghost btn-sm" href="/settings#templates">Manage</a>
      </div>"#,
    )
}

/// Build the reply/forward prefill from the original message referenced by `q`. Returns an empty
/// [`Prefill`] for a blank compose or when the referenced message is not the user's own.
async fn build_prefill(state: &AppState, mb: &Mailbox, q: &ComposeQuery) -> Prefill {
    if let Some(id) = q.draft.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        if let Ok(Some(msg)) = state.store.get_message(id).await {
            if msg.mailbox == mb.addr && msg.folder == "Drafts" {
                let (headers, _) = crate::rfc822::split_headers_body(&msg.raw_rfc822);
                let hdrs = crate::rfc822::parse_headers(headers);
                let (attachment_refs, attachment_list) = draft_attachment_refs(&msg);
                return Prefill {
                    to: msg.msg_to,
                    cc: crate::rfc822::header(&hdrs, "cc").unwrap_or_default(),
                    subject: msg.subject,
                    body: msg.body_text,
                    body_html: msg.body_html,
                    in_reply_to: crate::rfc822::header(&hdrs, "in-reply-to").unwrap_or_default(),
                    references: crate::rfc822::header(&hdrs, "references").unwrap_or_default(),
                    draft_id: id.to_string(),
                    attachment_refs,
                    attachment_list,
                    ..Prefill::default()
                };
            }
        }
    }

    if let Some(batch_id) = q
        .scheduled
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        if let Ok(Some(item)) = state
            .store
            .get_scheduled_outbound(&mb.addr, batch_id, now_secs())
            .await
        {
            let parsed = crate::rfc822::parse(&item.raw);
            let (headers, _) = crate::rfc822::split_headers_body(&item.raw);
            let hdrs = crate::rfc822::parse_headers(headers);
            return Prefill {
                to: parsed.to,
                cc: crate::rfc822::header(&hdrs, "cc").unwrap_or_default(),
                subject: parsed.subject,
                body: parsed.body_text,
                body_html: parsed.body_html,
                in_reply_to: crate::rfc822::header(&hdrs, "in-reply-to").unwrap_or_default(),
                references: crate::rfc822::header(&hdrs, "references").unwrap_or_default(),
                draft_id: String::new(),
                attachment_refs: String::new(),
                attachment_list: String::new(),
                scheduled_batch_id: item.batch_id,
                schedule_at: item.send_at,
            };
        }
    }

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
            ..Prefill::default()
        },
        "replyall" => Prefill {
            to: reply_all_to(&msg, &mb.addr),
            subject: re_subject(&msg.subject),
            body: quote_body(&msg),
            in_reply_to,
            references,
            ..Prefill::default()
        },
        _ => Prefill {
            to: msg.msg_from.clone(),
            subject: re_subject(&msg.subject),
            body: quote_body(&msg),
            in_reply_to,
            references,
            ..Prefill::default()
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
    let quoted: String = msg.body_text.lines().map(|l| format!("> {l}\n")).collect();
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
    /// Optional carbon-copy recipients (also relayed). Empty for a plain send.
    #[serde(default)]
    cc: String,
    #[serde(default)]
    subject: String,
    #[serde(default)]
    body: String,
    /// Sanitised server-side before it is used. Empty means legacy plain-text compose.
    #[serde(default)]
    body_html: String,
    /// Thread headers carried from a reply draft (empty for a fresh compose).
    #[serde(default)]
    in_reply_to: String,
    #[serde(default)]
    references: String,
    /// Existing Drafts message being edited/autosaved.
    #[serde(default)]
    draft_id: String,
    /// Attachment references carried forward from an existing Drafts row.
    #[serde(default)]
    attachment_refs: String,
    /// Chosen send-identity id (empty = the mailbox's own address, the default identity).
    #[serde(default)]
    identity: String,
    /// Existing scheduled batch being edited/replaced.
    #[serde(default)]
    scheduled_batch_id: String,
    /// Preset schedule epoch used when `action=schedule`.
    #[serde(default)]
    schedule_at: String,
    /// Custom schedule epoch overrides `schedule_at` when present.
    #[serde(default)]
    schedule_custom: String,
    /// `send` (default), `schedule`, or `draft`.
    #[serde(default)]
    action: String,
}

#[derive(Deserialize, Default)]
struct AutosaveForm {
    csrf: String,
    #[serde(default)]
    draft_id: String,
    #[serde(default)]
    to: String,
    #[serde(default)]
    cc: String,
    #[serde(default)]
    subject: String,
    #[serde(default)]
    body: String,
    #[serde(default)]
    body_text: String,
    #[serde(default)]
    body_html: String,
    #[serde(default)]
    in_reply_to: String,
    #[serde(default)]
    references: String,
    #[serde(default)]
    identity: String,
    #[serde(default)]
    attachment_refs: String,
}

async fn compose_autosave(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<AutosaveForm>,
) -> Response {
    if !verify_csrf(&headers, &form.csrf) {
        return json_status(StatusCode::FORBIDDEN, "CSRF token missing or mismatched");
    }
    let Some(mb) = resolve_mailbox(&state, &headers).await else {
        return json_status(StatusCode::FORBIDDEN, "no mailbox for this identity");
    };
    let from_header = match resolve_from_header_json(&state, &mb.addr, &form.identity).await {
        Ok(from) => from,
        Err(resp) => return resp,
    };
    let body_source = if form.body_text.is_empty() {
        form.body.as_str()
    } else {
        form.body_text.as_str()
    };
    let (body_text, body_html) = compose_body_parts(body_source, &form.body_html);
    let attachments = draft_attachments_from_refs(&state, &mb.addr, &form.attachment_refs).await;
    let raw = build_rfc822(
        &from_header,
        &form.to,
        &form.cc,
        &form.subject,
        &body_text,
        &body_html,
        &form.in_reply_to,
        &form.references,
        &state.config.mail_domain,
        &attachments,
    );
    match upsert_draft_copy(
        &state,
        &mb.addr,
        &form.draft_id,
        &from_header,
        &form.to,
        &form.subject,
        &body_text,
        &body_html,
        &raw,
    )
    .await
    {
        Ok(draft_id) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "ok": true,
                "draft_id": draft_id,
                "saved_at": now_secs(),
            })),
        )
            .into_response(),
        Err(e) => json_status(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

async fn send(State(state): State<AppState>, req: Request) -> Response {
    // Cookies/CSRF live in the headers; capture them before the body extractor consumes `req`.
    let headers = req.headers().clone();
    let email = email_display(&headers);

    // Compose now posts multipart/form-data (so it can carry file parts); the internal callers and
    // the pre-attachment tests still post urlencoded. Accept BOTH: parse attachments only from the
    // multipart body, an empty attachment set otherwise.
    let (form, mut attachments) = match parse_send(req, &state, &headers).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    if !verify_csrf(&headers, &form.csrf) {
        return error_page(
            StatusCode::FORBIDDEN,
            "Request blocked",
            "CSRF token missing or mismatched.",
        );
    }
    let Some(mb) = resolve_mailbox(&state, &headers).await else {
        return no_mailbox_page(&email);
    };

    // Resolve the outbound "From": the mailbox's own address (default), or a send identity the
    // mailbox OWNS. A submitted-but-unowned identity is rejected (never silently sent as the mailbox).
    let (from_header, env_from) =
        match resolve_from_identity(&state, &mb.addr, &form.identity).await {
            Ok(v) => v,
            Err(resp) => return *resp,
        };
    let (body_text, body_html) = compose_body_parts(&form.body, &form.body_html);
    let mut referenced_attachments =
        draft_attachments_from_refs(&state, &mb.addr, &form.attachment_refs).await;
    if !referenced_attachments.is_empty() {
        referenced_attachments.append(&mut attachments);
        attachments = referenced_attachments;
    }

    // "Save draft": persist without sending, and allow an incomplete recipient list.
    if form.action == "draft" {
        let raw = build_rfc822(
            &from_header,
            &form.to,
            &form.cc,
            &form.subject,
            &body_text,
            &body_html,
            &form.in_reply_to,
            &form.references,
            &state.config.mail_domain,
            &attachments,
        );
        match upsert_draft_copy(
            &state,
            &mb.addr,
            &form.draft_id,
            &from_header,
            &form.to,
            &form.subject,
            &body_text,
            &body_html,
            &raw,
        )
        .await
        {
            Ok(_) => {}
            Err(e) => {
                return error_page(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Storage error",
                    &e.to_string(),
                );
            }
        }
        cancel_replaced_scheduled(&state, &mb.addr, &form.scheduled_batch_id).await;
        return Redirect::to("/?folder=Drafts").into_response();
    }

    let (expanded_to, expanded_cc) =
        match expand_recipient_fields(&state, &mb.addr, &form.to, &form.cc).await {
            Ok(v) => v,
            Err(e) => {
                return error_page(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Storage error",
                    &e.to_string(),
                );
            }
        };
    let raw = build_rfc822(
        &from_header,
        &expanded_to,
        &expanded_cc,
        &form.subject,
        &body_text,
        &body_html,
        &form.in_reply_to,
        &form.references,
        &state.config.mail_domain,
        &attachments,
    );

    // To + Cc are both relayed.
    let rcpts = recipient_rcpts(&expanded_to, &expanded_cc);
    if rcpts.is_empty() {
        return error_page(
            StatusCode::BAD_REQUEST,
            "Invalid request",
            "At least one valid recipient is required.",
        );
    }

    let signer = state.signer.as_deref();
    if form.action == "schedule" {
        let send_at = match parse_schedule_epoch(&form.schedule_at, &form.schedule_custom) {
            Ok(ts) => ts,
            Err((code, message)) => return error_page(code, "Invalid request", &message),
        };
        return match crate::relay::enqueue_outbound_at(
            state.store.as_ref(),
            signer,
            &raw,
            &env_from,
            &rcpts,
            &mb.addr,
            send_at,
        )
        .await
        {
            Ok(_) => {
                cancel_replaced_scheduled(&state, &mb.addr, &form.scheduled_batch_id).await;
                delete_submitted_draft(&state, &mb.addr, &form.draft_id).await;
                Redirect::to("/?folder=Scheduled").into_response()
            }
            Err(e) => error_page(StatusCode::INTERNAL_SERVER_ERROR, "Send failed", &e),
        };
    }

    let undo_window_secs = match state.store.get_settings(&mb.addr).await {
        Ok(settings) => effective_undo_send_window_secs(settings.undo_send_window_secs),
        Err(e) => {
            return error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Storage error",
                &e.to_string(),
            );
        }
    };
    if undo_window_secs > 0 {
        let send_at = now_secs() + undo_window_secs;
        return match crate::relay::enqueue_outbound_at_with_batch(
            state.store.as_ref(),
            signer,
            &raw,
            &env_from,
            &rcpts,
            &mb.addr,
            send_at,
        )
        .await
        {
            Ok(enqueued) => {
                cancel_replaced_scheduled(&state, &mb.addr, &form.scheduled_batch_id).await;
                delete_submitted_draft(&state, &mb.addr, &form.draft_id).await;
                Redirect::to(&format!(
                    "/?folder=Sent&undo={}&undo_until={}",
                    url_encode(&enqueued.batch_id),
                    enqueued.send_at
                ))
                .into_response()
            }
            Err(e) => error_page(StatusCode::INTERNAL_SERVER_ERROR, "Send failed", &e),
        };
    }

    match crate::relay::enqueue_outbound(state.store.as_ref(), signer, &raw, &env_from, &rcpts)
        .await
    {
        Ok(signed) => {
            // File a copy of the sent message into the sender's Sent folder.
            store_local_copy(
                &state,
                &mb.addr,
                &from_header,
                &expanded_to,
                &form.subject,
                &body_text,
                &body_html,
                &signed,
                "Sent",
            )
            .await;
            cancel_replaced_scheduled(&state, &mb.addr, &form.scheduled_batch_id).await;
            delete_submitted_draft(&state, &mb.addr, &form.draft_id).await;
            Redirect::to("/?folder=Sent").into_response()
        }
        Err(e) => error_page(StatusCode::INTERNAL_SERVER_ERROR, "Send failed", &e),
    }
}

/// Resolve the outbound From for a send: `(from_header, env_from_addr)`. An empty identity id uses
/// the mailbox's own address (the implicit default — byte-identical to the pre-identity behaviour).
/// A non-empty id must resolve to an identity the mailbox OWNS, else a `400` is returned so a forged
/// identity id can never send as another address.
async fn resolve_from_identity(
    state: &AppState,
    mailbox: &str,
    identity_id: &str,
) -> Result<(String, String), Box<Response>> {
    let id = identity_id.trim();
    if id.is_empty() {
        return Ok((mailbox.to_string(), mailbox.to_string()));
    }
    match state.store.get_send_identity(mailbox, id).await {
        Ok(Some(idn)) => {
            let display = idn.display_name.trim();
            let from_header = if display.is_empty() {
                idn.from_addr.clone()
            } else {
                format!("{} <{}>", header_safe(display), idn.from_addr)
            };
            Ok((from_header, idn.from_addr))
        }
        Ok(None) => Err(Box::new(error_page(
            StatusCode::BAD_REQUEST,
            "Invalid request",
            "That send identity is not available for this mailbox.",
        ))),
        Err(e) => Err(Box::new(error_page(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Storage error",
            &e.to_string(),
        ))),
    }
}

async fn resolve_from_header_json(
    state: &AppState,
    mailbox: &str,
    identity_id: &str,
) -> Result<String, Response> {
    let id = identity_id.trim();
    if id.is_empty() {
        return Ok(mailbox.to_string());
    }
    match state.store.get_send_identity(mailbox, id).await {
        Ok(Some(idn)) => {
            let display = idn.display_name.trim();
            if display.is_empty() {
                Ok(idn.from_addr)
            } else {
                Ok(format!("{} <{}>", header_safe(display), idn.from_addr))
            }
        }
        Ok(None) => Err(json_status(
            StatusCode::BAD_REQUEST,
            "send identity is not available for this mailbox",
        )),
        Err(e) => Err(json_status(
            StatusCode::INTERNAL_SERVER_ERROR,
            &e.to_string(),
        )),
    }
}

/// Strip CR/LF from a value interpolated into a mail header (header injection defence).
fn header_safe(s: &str) -> String {
    s.chars().filter(|c| *c != '\r' && *c != '\n').collect()
}

/// Server-side representation of a compose body. Rich HTML is sanitised before MIME assembly and
/// the plain alternative is derived from that clean HTML; an empty HTML field preserves the legacy
/// plain-text path exactly.
fn compose_body_parts(body: &str, body_html: &str) -> (String, String) {
    let clean_html = crate::sanitize::sanitize_html(body_html);
    if clean_html.trim().is_empty() {
        return (body.to_string(), String::new());
    }
    let html_text = crate::sanitize::html_to_text(&clean_html);
    let plain = if html_text.trim().is_empty() && !body.trim().is_empty() {
        body.to_string()
    } else {
        html_text
    };
    (plain, clean_html)
}

async fn expand_recipient_fields(
    state: &AppState,
    mailbox: &str,
    to: &str,
    cc: &str,
) -> Result<(String, String), crate::store::StoreError> {
    let expanded_to = expand_recipient_field(state, mailbox, to).await?;
    let expanded_cc = expand_recipient_field(state, mailbox, cc).await?;
    Ok((expanded_to, expanded_cc))
}

async fn expand_recipient_field(
    state: &AppState,
    mailbox: &str,
    raw: &str,
) -> Result<String, crate::store::StoreError> {
    let mut expanded = Vec::new();
    for token in recipient_tokens(raw) {
        let addr = extract_addr(&token).to_lowercase();
        if is_valid_recipient_addr(&addr) {
            push_unique_addr(&mut expanded, addr);
            continue;
        }
        for contact in state.store.contacts_for_group_name(mailbox, &token).await? {
            push_unique_addr(&mut expanded, contact.addr);
        }
    }
    Ok(expanded.join(", "))
}

fn recipient_tokens(raw: &str) -> Vec<String> {
    raw.split([',', ';'])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

fn is_valid_recipient_addr(addr: &str) -> bool {
    addr.contains('@') && domain_of(addr).is_some()
}

fn push_unique_addr(out: &mut Vec<String>, addr: String) {
    if !out
        .iter()
        .any(|existing| existing.eq_ignore_ascii_case(&addr))
    {
        out.push(addr);
    }
}

fn recipient_rcpts(to: &str, cc: &str) -> Vec<String> {
    let mut rcpts = Vec::new();
    for token in recipient_tokens(to)
        .into_iter()
        .chain(recipient_tokens(cc).into_iter())
    {
        let addr = extract_addr(&token).to_lowercase();
        if is_valid_recipient_addr(&addr) {
            push_unique_addr(&mut rcpts, addr);
        }
    }
    rcpts
}

/// Persist a locally-authored message (a Sent copy or a Draft) into `mailbox`'s `folder`, from the
/// chosen `from` identity. Best effort: a storage error is logged but never fails the user's
/// send/save (the mail already left). Threads the copy into its conversation and harvests the
/// recipient(s) into contacts so both features cover self-authored mail too.
#[allow(clippy::too_many_arguments)]
async fn store_local_copy(
    state: &AppState,
    mailbox: &str,
    from: &str,
    to: &str,
    subject: &str,
    body: &str,
    body_html: &str,
    raw: &str,
    folder: &str,
) {
    let msg = local_copy_message(
        state,
        mailbox,
        new_id("m"),
        from,
        to,
        subject,
        body,
        body_html,
        raw,
        folder,
    )
    .await;
    if let Err(e) = state.store.store_message(&msg).await {
        tracing::warn!(error = %e, folder, "failed to file local message copy");
    }
    crate::delivery::harvest_contacts(state.store.as_ref(), mailbox, "", to).await;
}

#[allow(clippy::too_many_arguments)]
async fn upsert_draft_copy(
    state: &AppState,
    mailbox: &str,
    draft_id: &str,
    from: &str,
    to: &str,
    subject: &str,
    body: &str,
    body_html: &str,
    raw: &str,
) -> Result<String, crate::store::StoreError> {
    let id = draft_id_for_upsert(state, mailbox, draft_id).await?;
    let msg = local_copy_message(
        state,
        mailbox,
        id.clone(),
        from,
        to,
        subject,
        body,
        body_html,
        raw,
        "Drafts",
    )
    .await;
    state.store.upsert_draft(&msg).await?;
    crate::delivery::harvest_contacts(state.store.as_ref(), mailbox, "", to).await;
    Ok(id)
}

async fn delete_submitted_draft(state: &AppState, mailbox: &str, draft_id: &str) {
    let id = draft_id.trim();
    if id.is_empty() {
        return;
    }
    if let Err(e) = state.store.delete_draft(mailbox, id).await {
        tracing::warn!(error = %e, draft = %id, "failed to delete submitted draft");
    }
}

async fn draft_attachments_from_refs(
    state: &AppState,
    mailbox: &str,
    refs: &str,
) -> Vec<Attachment> {
    let mut attachments = Vec::new();
    for token in refs.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let Some((draft_id, idx)) = token.split_once(':') else {
            continue;
        };
        if !looks_like_message_id(draft_id) {
            continue;
        }
        let Ok(index) = idx.parse::<usize>() else {
            continue;
        };
        let Ok(Some(msg)) = state.store.get_message(draft_id).await else {
            continue;
        };
        if msg.mailbox != mailbox || msg.folder != "Drafts" {
            continue;
        }
        if let Some(att) = crate::rfc822::extract_attachment(&msg.raw_rfc822, index) {
            attachments.push(att);
        }
    }
    attachments
}

async fn draft_id_for_upsert(
    state: &AppState,
    mailbox: &str,
    requested: &str,
) -> Result<String, crate::store::StoreError> {
    let id = requested.trim();
    if id.is_empty() || !looks_like_message_id(id) {
        return Ok(new_id("m"));
    }
    match state.store.get_message(id).await? {
        Some(existing) if existing.mailbox == mailbox && existing.folder == "Drafts" => {
            Ok(id.to_string())
        }
        Some(_) => Ok(new_id("m")),
        None => Ok(id.to_string()),
    }
}

fn looks_like_message_id(id: &str) -> bool {
    id.len() <= 80
        && id.starts_with("m_")
        && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

#[allow(clippy::too_many_arguments)]
async fn local_copy_message(
    state: &AppState,
    mailbox: &str,
    id: String,
    from: &str,
    to: &str,
    subject: &str,
    body: &str,
    body_html: &str,
    raw: &str,
    folder: &str,
) -> Message {
    let (message_id, thread_id) =
        crate::delivery::resolve_thread(state.store.as_ref(), mailbox, raw, subject)
            .await
            .unwrap_or_default();
    Message {
        id,
        mailbox: mailbox.to_string(),
        msg_from: from.to_string(),
        msg_to: to.to_string(),
        subject: subject.to_string(),
        raw_rfc822: raw.to_string(),
        body_text: body.to_string(),
        body_html: body_html.to_string(),
        received_at: now_secs(),
        seen: true,
        folder: folder.to_string(),
        starred: false,
        snooze_until: 0,
        muted: false,
        thread_id,
        message_id,
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
                Err(e) => {
                    return Err(error_page(
                        StatusCode::BAD_REQUEST,
                        "Invalid upload",
                        &e.to_string(),
                    ));
                }
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
                    .map_err(|e| {
                        error_page(StatusCode::BAD_REQUEST, "Invalid upload", &e.to_string())
                    })?
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
                    "cc" => form.cc = text,
                    "subject" => form.subject = text,
                    "body" => form.body = text,
                    "body_html" => form.body_html = text,
                    "in_reply_to" => form.in_reply_to = text,
                    "references" => form.references = text,
                    "draft_id" => form.draft_id = text,
                    "attachment_refs" => form.attachment_refs = text,
                    "identity" => form.identity = text,
                    "scheduled_batch_id" => form.scheduled_batch_id = text,
                    "schedule_at" => form.schedule_at = text,
                    "schedule_custom" => form.schedule_custom = text,
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
        return json_status(
            StatusCode::SERVICE_UNAVAILABLE,
            "send API disabled (MAIL_SEND_TOKEN unset)",
        );
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
        return json_status(
            StatusCode::BAD_REQUEST,
            "at least one valid recipient is required",
        );
    }

    let raw = build_rfc822(
        &from_addr,
        &req.to,
        "",
        &req.subject,
        &req.body,
        "",
        "",
        "",
        &state.config.mail_domain,
        &[],
    );
    let signer = state.signer.as_deref();
    match crate::relay::enqueue_outbound(state.store.as_ref(), signer, &raw, &from_addr, &rcpts)
        .await
    {
        Ok(signed) => {
            // File a Sent copy for the sending address (parity with the webmail /send path).
            store_local_copy(
                &state,
                &from_addr,
                &from_addr,
                &req.to,
                &req.subject,
                &req.body,
                "",
                &signed,
                "Sent",
            )
            .await;
            json_status(StatusCode::ACCEPTED, "queued")
        }
        Err(e) => json_status(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("enqueue failed: {e}"),
        ),
    }
}

/// Query for `GET /contacts/suggest`.
#[derive(Deserialize, Default)]
struct SuggestQuery {
    #[serde(default)]
    q: String,
}

/// Number of autocomplete suggestions returned per keystroke.
const SUGGEST_LIMIT: i64 = 8;

/// `GET /contacts/suggest?q=` — the To/Cc autocomplete backend. Returns a JSON array of
/// `{addr, name, …}` suggestions from the SIGNED-IN mailbox's contacts only (strictly scoped);
/// an unauthenticated / mailbox-less caller gets an empty array (the combobox just shows nothing).
async fn contacts_suggest(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<SuggestQuery>,
) -> Response {
    let Some(mb) = resolve_mailbox(&state, &headers).await else {
        return Json(Vec::<crate::model::Contact>::new()).into_response();
    };
    match state
        .store
        .suggest_contacts(&mb.addr, &q.q, SUGGEST_LIMIT)
        .await
    {
        Ok(mut list) => {
            let needle = q.q.trim().to_lowercase();
            if (list.len() as i64) < SUGGEST_LIMIT {
                if let Ok(groups) = state.store.list_contact_groups(&mb.addr).await {
                    for group in groups {
                        if (list.len() as i64) >= SUGGEST_LIMIT {
                            break;
                        }
                        if needle.is_empty() || group.name.to_lowercase().contains(&needle) {
                            list.push(Contact {
                                addr: group.name,
                                name: "Group".to_string(),
                                phone: String::new(),
                                company: String::new(),
                                title: String::new(),
                                notes: String::new(),
                                manual: true,
                                seen_count: 0,
                            });
                        }
                    }
                }
            }
            Json(list).into_response()
        }
        Err(_) => Json(Vec::<crate::model::Contact>::new()).into_response(),
    }
}

/// Extract the `Authorization: Bearer <token>` value, if present.
fn bearer_token(headers: &HeaderMap) -> Option<String> {
    let raw = header_value(headers, "authorization")?;
    let token = raw
        .strip_prefix("Bearer ")
        .or_else(|| raw.strip_prefix("bearer "))?;
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
/// carry the reply threading headers built from the original's stored raw source. With no HTML and
/// no `attachments` the body is a single `text/plain` part (unchanged wire format). Rich compose
/// sends a `multipart/alternative`; when files are present that alternative becomes the first part
/// of a `multipart/mixed`, followed by one base64 `Content-Disposition: attachment` part per file.
#[allow(clippy::too_many_arguments)]
fn build_rfc822(
    from: &str,
    to: &str,
    cc: &str,
    subject: &str,
    body: &str,
    body_html: &str,
    in_reply_to: &str,
    references: &str,
    domain: &str,
    attachments: &[Attachment],
) -> String {
    let body_norm = mime_text(body);
    let html_norm = mime_text(body_html);
    let has_html = !body_html.trim().is_empty();
    let mut thread = String::new();
    if !in_reply_to.trim().is_empty() {
        thread.push_str(&format!("In-Reply-To: {}\r\n", in_reply_to.trim()));
    }
    if !references.trim().is_empty() {
        thread.push_str(&format!("References: {}\r\n", references.trim()));
    }
    // Cc is optional: emitted only when present, so a send without a Cc is byte-identical to before.
    let cc_hdr = if cc.trim().is_empty() {
        String::new()
    } else {
        format!("Cc: {}\r\n", cc.trim())
    };

    let head = format!(
        "From: {from}\r\nTo: {to}\r\n{cc_hdr}Subject: {subject}\r\nDate: {date}\r\nMessage-ID: {mid}\r\n{thread}MIME-Version: 1.0\r\n",
        date = email_date(),
        mid = message_id(domain),
    );

    if attachments.is_empty() && !has_html {
        return format!(
            "{head}Content-Type: text/plain; charset=utf-8\r\n\
             Content-Transfer-Encoding: 8bit\r\n\r\n{body_norm}\r\n",
        );
    }

    if attachments.is_empty() {
        let boundary = mime_boundary();
        let mut out = format!(
            "{head}Content-Type: multipart/alternative; boundary=\"{boundary}\"\r\n\r\n\
             This is a multi-part message in MIME format.\r\n",
        );
        push_alternative_body(&mut out, &boundary, &body_norm, &html_norm);
        return out;
    }

    let boundary = mime_boundary();
    let mut out = format!(
        "{head}Content-Type: multipart/mixed; boundary=\"{boundary}\"\r\n\r\n\
         This is a multi-part message in MIME format.\r\n",
    );
    if has_html {
        let alt_boundary = mime_boundary();
        out.push_str(&format!(
            "--{boundary}\r\nContent-Type: multipart/alternative; boundary=\"{alt_boundary}\"\r\n\r\n",
        ));
        push_alternative_body(&mut out, &alt_boundary, &body_norm, &html_norm);
    } else {
        out.push_str(&format!(
            "--{boundary}\r\nContent-Type: text/plain; charset=utf-8\r\n\
             Content-Transfer-Encoding: 8bit\r\n\r\n{body_norm}\r\n",
        ));
    }
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

/// Normalise a MIME text part to CRLF without otherwise changing content.
fn mime_text(s: &str) -> String {
    s.replace("\r\n", "\n")
        .replace('\r', "\n")
        .replace('\n', "\r\n")
}

/// Append the two body alternatives in the order preferred by mail clients: plain, then HTML.
fn push_alternative_body(out: &mut String, boundary: &str, body_norm: &str, html_norm: &str) {
    out.push_str(&format!(
        "--{boundary}\r\nContent-Type: text/plain; charset=utf-8\r\n\
         Content-Transfer-Encoding: 8bit\r\n\r\n{body_norm}\r\n\
         --{boundary}\r\nContent-Type: text/html; charset=utf-8\r\n\
         Content-Transfer-Encoding: 8bit\r\n\r\n{html_norm}\r\n\
         --{boundary}--\r\n",
    ));
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
        Err(e) => {
            return error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Storage error",
                &e.to_string(),
            );
        }
    };
    let aliases = match state.store.list_aliases().await {
        Ok(a) => a,
        Err(e) => {
            return error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Storage error",
                &e.to_string(),
            );
        }
    };

    let mut mb_rows = String::new();
    if mailboxes.is_empty() {
        mb_rows
            .push_str(r#"<tr><td colspan="3" class="muted">No mailboxes provisioned.</td></tr>"#);
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
        return error_page(
            StatusCode::FORBIDDEN,
            "Request blocked",
            "CSRF token missing or mismatched.",
        );
    }
    let addr = form.addr.trim().to_lowercase();
    let owner_sub = form.owner_sub.trim().to_string();
    if addr.is_empty() || !addr.contains('@') || domain_of(&addr).is_none() {
        return error_page(
            StatusCode::BAD_REQUEST,
            "Invalid request",
            "A valid mailbox address (local@domain) is required.",
        );
    }
    if owner_sub.is_empty() {
        return error_page(
            StatusCode::BAD_REQUEST,
            "Invalid request",
            "An owner sub is required.",
        );
    }
    match state.store.get_mailbox(&addr).await {
        Ok(Some(_)) => {
            return error_page(
                StatusCode::CONFLICT,
                "Already exists",
                "A mailbox with that address already exists.",
            );
        }
        Ok(None) => {}
        Err(e) => {
            return error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Storage error",
                &e.to_string(),
            );
        }
    }
    let mb = Mailbox {
        addr: addr.clone(),
        owner_sub: owner_sub.clone(),
    };
    if let Err(e) = state.store.upsert_mailbox(&mb).await {
        return error_page(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Storage error",
            &e.to_string(),
        );
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
        return error_page(
            StatusCode::FORBIDDEN,
            "Request blocked",
            "CSRF token missing or mismatched.",
        );
    }
    let local_part = form.local_part.trim().to_lowercase();
    let mailbox = form.mailbox.trim().to_lowercase();
    if local_part.is_empty() || local_part.contains('@') {
        return error_page(
            StatusCode::BAD_REQUEST,
            "Invalid request",
            "A bare alias local-part (no @) is required.",
        );
    }
    match state.store.get_mailbox(&mailbox).await {
        Ok(Some(_)) => {}
        Ok(None) => {
            return error_page(
                StatusCode::BAD_REQUEST,
                "Invalid request",
                "The target mailbox does not exist.",
            );
        }
        Err(e) => {
            return error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Storage error",
                &e.to_string(),
            );
        }
    }
    let alias = Alias {
        local_part: local_part.clone(),
        mailbox: mailbox.clone(),
    };
    if let Err(e) = state.store.add_alias(&alias).await {
        return error_page(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Storage error",
            &e.to_string(),
        );
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
// Settings — filter rules / signature / display / auto-reply (per-mailbox)
// ---------------------------------------------------------------------------

/// The legal rule match fields / operators / actions (the settings selects + POST validation).
const RULE_FIELDS: [&str; 3] = ["from", "to", "subject"];
const RULE_OPS: [&str; 2] = ["contains", "equals"];
const RULE_ACTIONS: [&str; 5] = ["move", "star", "markread", "discard", "label"];
const RULE_RUN_SCAN_CAP: i64 = 1000;

/// `GET /settings` — the mailbox settings page: filter rules (list + add form), signature, display,
/// and auto-reply (vacation), all POSTing back with the same double-submit CSRF token.
async fn settings_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<SettingsQuery>,
) -> Response {
    let email = email_display(&headers);
    let Some(mb) = resolve_mailbox(&state, &headers).await else {
        return no_mailbox_page(&email);
    };
    let (token, set_cookie) = ensure_csrf(&headers);

    let rules = match state.store.list_rules(&mb.addr).await {
        Ok(r) => r,
        Err(e) => {
            return error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Storage error",
                &e.to_string(),
            );
        }
    };
    let settings = match state.store.get_settings(&mb.addr).await {
        Ok(s) => s,
        Err(e) => {
            return error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Storage error",
                &e.to_string(),
            );
        }
    };
    let labels = state.store.list_labels(&mb.addr).await.unwrap_or_default();
    let identities = state
        .store
        .list_send_identities(&mb.addr)
        .await
        .unwrap_or_default();
    let signatures = match state.store.list_signatures(&mb.addr).await {
        Ok(list) => list,
        Err(e) => {
            return error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Storage error",
                &e.to_string(),
            );
        }
    };
    let contacts = match state.store.list_contacts(&mb.addr, 500).await {
        Ok(list) => list,
        Err(e) => {
            return error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Storage error",
                &e.to_string(),
            );
        }
    };
    let contact_groups = match state.store.list_contact_groups(&mb.addr).await {
        Ok(list) => list,
        Err(e) => {
            return error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Storage error",
                &e.to_string(),
            );
        }
    };
    let mut contact_group_members = Vec::new();
    for group in &contact_groups {
        match state
            .store
            .list_contact_group_members(&mb.addr, &group.id)
            .await
        {
            Ok(members) => contact_group_members.push((group.clone(), members)),
            Err(e) => {
                return error_page(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Storage error",
                    &e.to_string(),
                );
            }
        }
    }
    let duplicate_contacts = match state.store.duplicate_contacts(&mb.addr).await {
        Ok(list) => list,
        Err(e) => {
            return error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Storage error",
                &e.to_string(),
            );
        }
    };
    let sender_lists = match state.store.list_sender_lists(&mb.addr).await {
        Ok(list) => list,
        Err(e) => {
            return error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Storage error",
                &e.to_string(),
            );
        }
    };
    let templates = match state.store.list_templates(&mb.addr).await {
        Ok(list) => list,
        Err(e) => {
            return error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Storage error",
                &e.to_string(),
            );
        }
    };

    let mut rule_rows = String::new();
    if rules.is_empty() {
        rule_rows.push_str(r#"<tr><td colspan="5" class="muted">No filter rules yet — incoming mail lands in the Inbox.</td></tr>"#);
    }
    for (i, r) in rules.iter().enumerate() {
        rule_rows.push_str(&render_rule_row(i, rules.len(), r, &labels, &token));
    }
    let rule_run_banner = if q.ran.is_empty() {
        String::new()
    } else {
        format!(
            r#"<div class="spam-banner" role="note"><b>Filter applied</b><span>{m} matched, {c} updated.</span></div>"#,
            m = q.matched,
            c = q.changed,
        )
    };

    let rule_prefill = rule_prefill_from_search(&q.filter_q);
    let rule_field = rule_prefill
        .as_ref()
        .map(|p| p.field.as_str())
        .unwrap_or("");
    let rule_op = rule_prefill.as_ref().map(|p| p.op.as_str()).unwrap_or("");
    let rule_needle = rule_prefill
        .as_ref()
        .map(|p| p.needle.as_str())
        .unwrap_or("");
    let rule_form_class = if rule_prefill.is_some() {
        "filter-rule-form is-prefilled"
    } else {
        "filter-rule-form"
    };
    let field_opts = select_options_selected(&RULE_FIELDS, rule_field, |f| field_label(f));
    let op_opts = select_options_selected(&RULE_OPS, rule_op, |o| o.to_string());
    let action_opts = select_options(&RULE_ACTIONS, |a| action_label(a));
    let mut folder_opts = String::new();
    for f in FOLDERS {
        folder_opts.push_str(&format!(r#"<option value="{f}">{f}</option>"#));
    }
    // Label select for the `label` rule action (empty when the mailbox has none yet).
    let mut rule_label_opts = String::new();
    for l in &labels {
        rule_label_opts.push_str(&format!(
            r#"<option value="{id}">{name}</option>"#,
            id = esc(&l.id),
            name = esc(&l.name)
        ));
    }

    let ar_checked = if settings.auto_reply_enabled {
        " checked"
    } else {
        ""
    };
    let undo_window_opts = undo_send_window_options(settings.undo_send_window_secs);
    let (density_opts, reading_pane_opts, theme_opts) = display_preference_options(&settings);
    let content = format!(
        r#"<div class="page-head"><h1>Settings</h1></div>
<section id="filter-rules" class="card pad filter-rules">
  <h2>Filter rules</h2>
  <p class="muted">Applied to incoming mail at delivery, top to bottom — the first matching rule wins.</p>
  {rule_run_banner}
  <table class="data admin-table">
    <thead><tr><th>#</th><th>Match</th><th>Action</th><th>Status</th><th></th></tr></thead>
    <tbody>{rule_rows}</tbody>
  </table>
  <form class="{rule_form_class}" method="post" action="/settings/rules">
    <input type="hidden" name="csrf" value="{token}">
    <div class="field"><label for="rule_field">Field</label><select id="rule_field" name="field">{field_opts}</select></div>
    <div class="field"><label for="rule_op">Condition</label><select id="rule_op" name="op">{op_opts}</select></div>
    <div class="field"><label for="rule_needle">Text to match</label><input id="rule_needle" name="needle" value="{rule_needle}" placeholder="newsletter@example.com"></div>
    <div class="field"><label for="rule_action">Action</label><select id="rule_action" name="action">{action_opts}</select></div>
    <div class="field"><label for="rule_folder">Target folder (for Move)</label><select id="rule_folder" name="folder">{folder_opts}</select></div>
    <div class="field"><label for="rule_label">Target label (for Add label)</label><select id="rule_label" name="label">{rule_label_opts}</select></div>
    <div class="form-actions"><button class="btn btn-primary" type="submit">Add rule</button></div>
  </form>
</section>
{templates_section}
{senders_section}
{labels_section}
{identities_section}
{contacts_section}
{signatures_section}
<section class="card pad undo-send-settings">
  <h2>Undo send</h2>
  <form method="post" action="/settings/undo-send">
    <input type="hidden" name="csrf" value="{token}">
    <div class="field"><label for="undo_send_window_secs">Cancellation period</label><select id="undo_send_window_secs" name="window_secs">{undo_window_opts}</select><p class="hint">Messages wait in the outbound queue for this period before delivery.</p></div>
    <div class="form-actions"><button class="btn btn-primary" type="submit">Save undo send</button></div>
  </form>
</section>
<section class="card pad display-settings">
  <h2>Display</h2>
  <form method="post" action="/settings/preferences">
    <input type="hidden" name="csrf" value="{token}">
    <div class="field"><label for="density">Density</label><select id="density" name="density">{density_opts}</select></div>
    <div class="field"><label for="reading_pane">Reading pane</label><select id="reading_pane" name="reading_pane">{reading_pane_opts}</select></div>
    <div class="field"><label for="theme">Theme</label><select id="theme" name="theme">{theme_opts}</select></div>
    <div class="form-actions"><button class="btn btn-primary" type="submit">Save display</button></div>
  </form>
</section>
<section class="card pad">
  <h2>Auto-reply (vacation)</h2>
  <form method="post" action="/settings/autoreply">
    <input type="hidden" name="csrf" value="{token}">
    <div class="field"><label><input type="checkbox" name="enabled" value="on"{ar_checked}> Enable auto-reply</label></div>
    <div class="field"><label for="ar_subject">Subject</label><input id="ar_subject" name="subject" value="{ar_subject}" placeholder="Out of office"></div>
    <div class="field"><label for="ar_body">Message</label><textarea id="ar_body" name="body">{ar_body}</textarea></div>
    <div class="field"><label for="ar_until">Until (UTC)</label><input id="ar_until" name="until" type="date" value="{ar_until}"><p class="hint">Leave empty for no end date. Each sender receives at most one auto-reply per 24 hours.</p></div>
    <div class="form-actions"><button class="btn btn-primary" type="submit">Save auto-reply</button></div>
  </form>
</section>"#,
        token = esc(&token),
        rule_run_banner = rule_run_banner,
        rule_needle = esc(rule_needle),
        ar_subject = esc(&settings.auto_reply_subject),
        ar_body = esc(&settings.auto_reply_body),
        ar_until = fmt_until(settings.auto_reply_until),
        undo_window_opts = undo_window_opts,
        density_opts = density_opts,
        reading_pane_opts = reading_pane_opts,
        theme_opts = theme_opts,
        templates_section = render_templates_section(&templates, &token),
        labels_section = render_labels_section(&labels, &token),
        senders_section = render_sender_lists_section(&sender_lists, &token),
        identities_section = render_identities_section(&identities, &mb.addr, &token),
        signatures_section = render_signatures_section(&signatures, &identities, &mb.addr, &token),
        contacts_section = render_contacts_section(
            &contacts,
            &contact_group_members,
            &duplicate_contacts,
            &token
        ),
    );
    let html = render_page_with_prefs(
        "Settings",
        &email,
        &content,
        "settings",
        page_prefs(&settings),
    );
    match set_cookie {
        Some(c) => ([(header::SET_COOKIE, c)], Html(html)).into_response(),
        None => Html(html).into_response(),
    }
}

/// Query string for `GET /settings`. `filter_q` is a search query carried from search results or
/// advanced search; settings maps the first delivery-rule-compatible predicate into the add form.
#[derive(Deserialize, Default)]
struct SettingsQuery {
    #[serde(default)]
    filter_q: String,
    #[serde(default)]
    ran: String,
    #[serde(default)]
    matched: i64,
    #[serde(default)]
    changed: i64,
}

/// One filter-rule table row: the match/action summary plus its inline control form
/// (up/down/enable-disable/delete), all POSTing back to `/settings/rules` with the CSRF token.
/// `labels` resolves an `Add label` rule's target id to its display name.
fn render_rule_row(
    index: usize,
    total: usize,
    r: &FilterRule,
    labels: &[Label],
    token: &str,
) -> String {
    let status = if r.enabled {
        r#"<span class="pill pill-ok">Enabled</span>"#
    } else {
        r#"<span class="pill">Disabled</span>"#
    };
    let toggle = if r.enabled {
        ("disable", "Disable")
    } else {
        ("enable", "Enable")
    };
    let action = match r.action.as_str() {
        "move" => format!("Move to {}", esc(r.target_folder.as_deref().unwrap_or("?"))),
        "label" => {
            let name = r
                .target_label
                .as_deref()
                .and_then(|id| labels.iter().find(|l| l.id == id))
                .map(|l| l.name.clone())
                .unwrap_or_else(|| "?".to_string());
            format!("Add label {}", esc(&name))
        }
        other => action_label(other),
    };
    let up = if index > 0 {
        r#"<button class="btn btn-ghost btn-sm" type="submit" name="cmd" value="up" title="Move up">↑</button>"#
    } else {
        ""
    };
    let down = if index + 1 < total {
        r#"<button class="btn btn-ghost btn-sm" type="submit" name="cmd" value="down" title="Move down">↓</button>"#
    } else {
        ""
    };
    let discard_confirm = if r.action == "discard" {
        r#" onsubmit="return !event.submitter || event.submitter.value !== 'run' || confirm('Move all matching mail to Trash?')"#
    } else {
        ""
    };
    format!(
        r#"<tr><td class="mono">{n}</td><td>{field} {op} &ldquo;{needle}&rdquo;</td><td>{action}</td><td>{status}</td><td>
<form class="row-actions" method="post" action="/settings/rules"{discard_confirm}>
  <input type="hidden" name="csrf" value="{token}">
  <input type="hidden" name="id" value="{id}">
  {up}{down}
  <button class="btn btn-ghost btn-sm" type="submit" name="cmd" value="{toggle_cmd}">{toggle_label}</button>
  <button class="btn btn-ghost btn-sm" type="submit" name="cmd" value="run" title="Apply this filter to existing mail (Discard moves matches to Trash)">Run now</button>
  <button class="btn btn-ghost btn-sm" type="submit" name="cmd" value="delete">Delete</button>
</form></td></tr>"#,
        n = index + 1,
        field = field_label(&r.field),
        op = esc(&r.op),
        needle = esc(&r.needle),
        id = esc(&r.id),
        token = esc(token),
        discard_confirm = discard_confirm,
        toggle_cmd = toggle.0,
        toggle_label = toggle.1,
    )
}

/// `<option>` list for a settings select, labelled by `label`.
fn select_options(values: &[&str], label: impl Fn(&str) -> String) -> String {
    select_options_selected(values, "", label)
}

fn select_options_selected(
    values: &[&str],
    selected: &str,
    label: impl Fn(&str) -> String,
) -> String {
    let mut out = String::new();
    for v in values {
        out.push_str(&format!(
            r#"<option value="{v}"{}>{}</option>"#,
            selected_attr(v, selected),
            label(v)
        ));
    }
    out
}

#[derive(Default)]
struct RulePrefill {
    field: String,
    op: String,
    needle: String,
}

fn rule_prefill_from_search(raw: &str) -> Option<RulePrefill> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    let query = parse_search_query(raw);
    for predicate in query.predicates {
        if predicate.negated {
            continue;
        }
        let (field, needle) = match predicate.kind {
            SearchPredicateKind::From(value) => ("from", value),
            SearchPredicateKind::To(value) => ("to", value),
            SearchPredicateKind::Subject(value) => ("subject", value),
            _ => continue,
        };
        let needle = needle.trim();
        if !needle.is_empty() {
            return Some(RulePrefill {
                field: field.to_string(),
                op: "contains".to_string(),
                needle: needle.to_string(),
            });
        }
    }
    None
}

fn field_label(field: &str) -> String {
    match field {
        "from" => "From".to_string(),
        "to" => "To".to_string(),
        "subject" => "Subject".to_string(),
        other => esc(other),
    }
}

fn action_label(action: &str) -> String {
    match action {
        "move" => "Move to folder".to_string(),
        "star" => "Star".to_string(),
        "markread" => "Mark read".to_string(),
        "discard" => "Discard".to_string(),
        "label" => "Add label".to_string(),
        other => esc(other),
    }
}

/// `GET /settings/rules` — the rules live on the one settings page.
async fn settings_rules_redirect() -> Response {
    Redirect::to("/settings").into_response()
}

/// Form body for `POST /settings/rules`: `cmd` empty/`add` creates a rule from the
/// field/op/needle/action(/folder) selects; `up|down|enable|disable|delete` operate on `id`.
#[derive(Deserialize, Default)]
struct RuleForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    cmd: String,
    #[serde(default)]
    id: String,
    #[serde(default)]
    field: String,
    #[serde(default)]
    op: String,
    #[serde(default)]
    needle: String,
    #[serde(default)]
    action: String,
    #[serde(default)]
    folder: String,
    /// Target label id for the `label` action.
    #[serde(default)]
    label: String,
}

/// `POST /settings/rules` — add/reorder/toggle/delete a filter rule. CSRF-guarded; every store
/// call is scoped to the signed-in user's own mailbox. Emits a tracing audit line and redirects
/// back to `/settings`.
async fn settings_rules_post(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<RuleForm>,
) -> Response {
    if !verify_csrf(&headers, &form.csrf) {
        return error_page(
            StatusCode::FORBIDDEN,
            "Request blocked",
            "CSRF token missing or mismatched.",
        );
    }
    let Some(mb) = resolve_mailbox(&state, &headers).await else {
        return no_mailbox_page(&email_display(&headers));
    };

    let mut run_report: Option<crate::delivery::RuleRunReport> = None;
    let result = match form.cmd.as_str() {
        "" | "add" => add_rule_from_form(&state, &mb.addr, &form).await,
        "up" | "down" => reorder_rule(&state, &mb.addr, &form.id, form.cmd == "up").await,
        "enable" => state
            .store
            .set_rule_enabled(&mb.addr, &form.id, true)
            .await
            .map_err(|e| e.to_string()),
        "disable" => state
            .store
            .set_rule_enabled(&mb.addr, &form.id, false)
            .await
            .map_err(|e| e.to_string()),
        "delete" => state
            .store
            .delete_rule(&mb.addr, &form.id)
            .await
            .map_err(|e| e.to_string()),
        "run" => match run_rule_now(&state, &mb.addr, &form.id).await {
            Ok(rep) => {
                run_report = Some(rep);
                Ok(())
            }
            Err(e) => Err(e),
        },
        _ => {
            return error_page(
                StatusCode::BAD_REQUEST,
                "Invalid request",
                "Unknown rule command.",
            );
        }
    };
    if let Err(e) = result {
        return error_page(StatusCode::BAD_REQUEST, "Invalid request", &e);
    }
    if let Some(rep) = run_report {
        tracing::info!(
            target: "corvid::audit",
            actor = %identity_subject(&headers).unwrap_or_default(),
            mailbox = %mb.addr,
            cmd = %"run",
            rule = %form.id,
            matched = rep.matched,
            changed = rep.changed,
            "filter rule change",
        );
        return Redirect::to(&format!(
            "/settings?ran={}&matched={}&changed={}",
            url_encode(&form.id),
            rep.matched,
            rep.changed
        ))
        .into_response();
    }
    tracing::info!(
        target: "corvid::audit",
        actor = %identity_subject(&headers).unwrap_or_default(),
        mailbox = %mb.addr,
        cmd = %if form.cmd.is_empty() { "add" } else { form.cmd.as_str() },
        rule = %form.id,
        "filter rule change",
    );
    Redirect::to("/settings").into_response()
}

async fn run_rule_now(
    state: &AppState,
    mailbox: &str,
    id: &str,
) -> Result<crate::delivery::RuleRunReport, String> {
    let rules = state
        .store
        .list_rules(mailbox)
        .await
        .map_err(|e| e.to_string())?;
    let Some(rule) = rules.iter().find(|r| r.id == id) else {
        return Err("Unknown rule.".to_string());
    };
    crate::delivery::apply_rule_to_existing(state.store.as_ref(), mailbox, rule, RULE_RUN_SCAN_CAP)
        .await
        .map_err(|e| e.to_string())
}

/// Validate + persist a new rule from the add form (appended at the end of the order).
async fn add_rule_from_form(
    state: &AppState,
    mailbox: &str,
    form: &RuleForm,
) -> Result<(), String> {
    let field = form.field.trim().to_lowercase();
    let op = form.op.trim().to_lowercase();
    let action = form.action.trim().to_lowercase();
    let needle = form.needle.trim().to_string();
    if !RULE_FIELDS.contains(&field.as_str()) {
        return Err("Unknown match field.".to_string());
    }
    if !RULE_OPS.contains(&op.as_str()) {
        return Err("Unknown match condition.".to_string());
    }
    if !RULE_ACTIONS.contains(&action.as_str()) {
        return Err("Unknown rule action.".to_string());
    }
    if needle.is_empty() {
        return Err("The text to match is required.".to_string());
    }
    let target_folder = if action == "move" {
        let Some(f) = real_folder(&form.folder) else {
            return Err("A Move rule needs a real target folder.".to_string());
        };
        Some(f.to_string())
    } else {
        None
    };
    // The `label` action needs a target label the mailbox actually owns.
    let target_label = if action == "label" {
        let lid = form.label.trim();
        let owned = state
            .store
            .list_labels(mailbox)
            .await
            .map_err(|e| e.to_string())?
            .into_iter()
            .any(|l| l.id == lid);
        if lid.is_empty() || !owned {
            return Err("An Add-label rule needs one of your labels.".to_string());
        }
        Some(lid.to_string())
    } else {
        None
    };
    let existing = state
        .store
        .list_rules(mailbox)
        .await
        .map_err(|e| e.to_string())?;
    let position = existing.iter().map(|r| r.position).max().unwrap_or(0) + 1;
    let rule = FilterRule {
        id: new_id("fr"),
        mailbox: mailbox.to_string(),
        position,
        field,
        op,
        needle,
        action,
        target_folder,
        target_label,
        enabled: true,
        created_at: now_secs(),
    };
    state.store.add_rule(&rule).await.map_err(|e| e.to_string())
}

/// Move a rule one slot up/down: renumber the whole order with the two neighbours swapped
/// (robust against legacy position ties). A no-op at either edge.
async fn reorder_rule(state: &AppState, mailbox: &str, id: &str, up: bool) -> Result<(), String> {
    let rules = state
        .store
        .list_rules(mailbox)
        .await
        .map_err(|e| e.to_string())?;
    let Some(idx) = rules.iter().position(|r| r.id == id) else {
        return Err("No such rule.".to_string());
    };
    let other = if up {
        idx.checked_sub(1)
    } else {
        (idx + 1 < rules.len()).then_some(idx + 1)
    };
    let Some(oidx) = other else {
        return Ok(()); // already at the edge
    };
    let mut order: Vec<&str> = rules.iter().map(|r| r.id.as_str()).collect();
    order.swap(idx, oidx);
    for (i, rid) in order.iter().enumerate() {
        state
            .store
            .set_rule_position(mailbox, rid, (i + 1) as i64)
            .await
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// Form body for `POST /settings/signature`.
#[derive(Deserialize, Default)]
struct SignatureForm {
    csrf: String,
    #[serde(default)]
    signature: String,
}

/// `POST /settings/signature` — save the compose signature (empty clears it). CSRF-guarded;
/// emits a tracing audit line and redirects back to `/settings`.
async fn settings_signature(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<SignatureForm>,
) -> Response {
    if !verify_csrf(&headers, &form.csrf) {
        return error_page(
            StatusCode::FORBIDDEN,
            "Request blocked",
            "CSRF token missing or mismatched.",
        );
    }
    let Some(mb) = resolve_mailbox(&state, &headers).await else {
        return no_mailbox_page(&email_display(&headers));
    };
    if let Err(e) = state
        .store
        .set_signature(&mb.addr, form.signature.trim())
        .await
    {
        return error_page(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Storage error",
            &e.to_string(),
        );
    }
    tracing::info!(
        target: "corvid::audit",
        actor = %identity_subject(&headers).unwrap_or_default(),
        mailbox = %mb.addr,
        cleared = %form.signature.trim().is_empty(),
        "signature updated",
    );
    Redirect::to("/settings").into_response()
}

/// `GET /settings/signatures` — signatures are managed on the main settings page.
async fn settings_signatures_redirect() -> Response {
    Redirect::to("/settings#signatures").into_response()
}

fn render_signature_identity_options(
    identities: &[crate::model::SendIdentity],
    mailbox: &str,
    selected: &str,
) -> String {
    let mut opts = String::new();
    let general_selected = selected.trim().is_empty();
    opts.push_str(&format!(
        r#"<option value=""{sel}>General default</option>"#,
        sel = if general_selected { " selected" } else { "" },
    ));
    opts.push_str(&format!(
        r#"<option value="{addr}"{sel}>{addr}</option>"#,
        addr = esc(mailbox),
        sel = if selected == mailbox { " selected" } else { "" },
    ));
    let mut known = selected.trim().is_empty() || selected == mailbox;
    for i in identities {
        if i.from_addr == selected {
            known = true;
        }
        let label = if i.display_name.trim().is_empty() {
            i.from_addr.clone()
        } else {
            format!("{} <{}>", i.display_name, i.from_addr)
        };
        opts.push_str(&format!(
            r#"<option value="{addr}"{sel}>{label}</option>"#,
            addr = esc(&i.from_addr),
            label = esc(&label),
            sel = if i.from_addr == selected {
                " selected"
            } else {
                ""
            },
        ));
    }
    if !known {
        opts.push_str(&format!(
            r#"<option value="{addr}" selected>{addr}</option>"#,
            addr = esc(selected)
        ));
    }
    opts
}

fn render_signatures_section(
    signatures: &[Signature],
    identities: &[crate::model::SendIdentity],
    mailbox: &str,
    token: &str,
) -> String {
    let mut list = String::new();
    if signatures.is_empty() {
        list.push_str(r#"<p class="muted">No signatures yet.</p>"#);
    }
    for (i, s) in signatures.iter().enumerate() {
        let class = if s.is_default {
            "signature-item signature-default"
        } else {
            "signature-item"
        };
        let checked = if s.is_default { " checked" } else { "" };
        let identity_opts = render_signature_identity_options(identities, mailbox, &s.identity);
        list.push_str(&format!(
            r#"<div class="{class}">
  <form method="post" action="/settings/signatures">
    <input type="hidden" name="csrf" value="{token}">
    <input type="hidden" name="id" value="{id}">
    <div class="field"><label for="sig_name_{i}">Name</label><input id="sig_name_{i}" name="name" value="{name}"></div>
    <div class="field"><label for="sig_identity_{i}">From identity</label><select id="sig_identity_{i}" name="identity">{identity_opts}</select></div>
    <div class="field"><label for="sig_body_{i}">Plain text</label><textarea id="sig_body_{i}" name="body_text">{body_text}</textarea></div>
    <div class="field"><label for="sig_html_{i}">Rich HTML</label><textarea id="sig_html_{i}" name="body_html">{body_html}</textarea></div>
    <div class="field"><label><input type="checkbox" name="is_default" value="on"{checked}> Default for this identity</label></div>
    <div class="form-actions">
      <button class="btn btn-primary btn-sm" type="submit" name="cmd" value="update">Save signature</button>
      <button class="btn btn-ghost btn-sm" type="submit" name="cmd" value="delete">Delete</button>
    </div>
  </form>
</div>"#,
            token = esc(token),
            id = esc(&s.id),
            name = esc(&s.name),
            body_text = esc(&s.body_text),
            body_html = esc(&s.body_html),
        ));
    }
    let identity_opts = render_signature_identity_options(identities, mailbox, "");
    format!(
        r#"<section id="signatures" class="card pad signature-list">
  <h2>Signatures</h2>
  <div class="signature-list__items">{list}</div>
  <form class="signature-create" method="post" action="/settings/signatures">
    <input type="hidden" name="csrf" value="{token}">
    <div class="field"><label for="sig_new_name">Name</label><input id="sig_new_name" name="name" placeholder="Default"></div>
    <div class="field"><label for="sig_new_identity">From identity</label><select id="sig_new_identity" name="identity">{identity_opts}</select></div>
    <div class="field"><label for="sig_new_body">Plain text</label><textarea id="sig_new_body" name="body_text"></textarea></div>
    <div class="field"><label for="sig_new_html">Rich HTML</label><textarea id="sig_new_html" name="body_html"></textarea></div>
    <div class="field"><label><input type="checkbox" name="is_default" value="on" checked> Default for this identity</label></div>
    <div class="form-actions"><button class="btn btn-primary" type="submit" name="cmd" value="add">Add signature</button></div>
  </form>
</section>"#,
        token = esc(token),
    )
}

/// Form body for `POST /settings/signatures`: add/update/delete a reusable compose signature.
#[derive(Deserialize, Default)]
struct SignatureCrudForm {
    csrf: String,
    #[serde(default)]
    cmd: String,
    #[serde(default)]
    id: String,
    #[serde(default)]
    identity: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    body_text: String,
    #[serde(default)]
    body_html: String,
    #[serde(default)]
    is_default: String,
}

enum SignatureFormError {
    Invalid(String),
    Store(crate::store::StoreError),
}

async fn settings_signatures_post(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<SignatureCrudForm>,
) -> Response {
    if !verify_csrf(&headers, &form.csrf) {
        return error_page(
            StatusCode::FORBIDDEN,
            "Request blocked",
            "CSRF token missing or mismatched.",
        );
    }
    let Some(mb) = resolve_mailbox(&state, &headers).await else {
        return no_mailbox_page(&email_display(&headers));
    };
    let identities = match state.store.list_send_identities(&mb.addr).await {
        Ok(v) => v,
        Err(e) => {
            return error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Storage error",
                &e.to_string(),
            );
        }
    };
    let result = match form.cmd.as_str() {
        "delete" => state
            .store
            .delete_signature(&mb.addr, form.id.trim())
            .await
            .map_err(SignatureFormError::Store),
        "update" => update_signature_from_form(&state, &mb.addr, &identities, &form).await,
        "" | "add" => create_signature_from_form(&state, &mb.addr, &identities, &form).await,
        _ => Err(SignatureFormError::Invalid(
            "Unknown signature command.".to_string(),
        )),
    };
    if let Err(e) = result {
        return match e {
            SignatureFormError::Invalid(message) => {
                error_page(StatusCode::BAD_REQUEST, "Invalid request", &message)
            }
            SignatureFormError::Store(e) => error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Storage error",
                &e.to_string(),
            ),
        };
    }
    tracing::info!(
        target: "corvid::audit",
        actor = %identity_subject(&headers).unwrap_or_default(),
        mailbox = %mb.addr,
        cmd = %if form.cmd.is_empty() { "add" } else { form.cmd.as_str() },
        signature = %form.id,
        "signature change",
    );
    Redirect::to("/settings#signatures").into_response()
}

async fn create_signature_from_form(
    state: &AppState,
    mailbox: &str,
    identities: &[crate::model::SendIdentity],
    form: &SignatureCrudForm,
) -> Result<(), SignatureFormError> {
    let name = signature_name(&form.name)?;
    let identity = signature_identity(&form.identity, mailbox, identities)?;
    let (body_text, body_html) = signature_body_parts(&form.body_text, &form.body_html)?;
    let signature = Signature {
        id: new_id("sig"),
        user: mailbox.to_string(),
        identity,
        name,
        body_html,
        body_text,
        is_default: !form.is_default.trim().is_empty(),
        created_at: now_secs(),
    };
    state
        .store
        .create_signature(&signature)
        .await
        .map_err(SignatureFormError::Store)
}

async fn update_signature_from_form(
    state: &AppState,
    mailbox: &str,
    identities: &[crate::model::SendIdentity],
    form: &SignatureCrudForm,
) -> Result<(), SignatureFormError> {
    let id = form.id.trim();
    let Some(existing) = state
        .store
        .get_signature(mailbox, id)
        .await
        .map_err(SignatureFormError::Store)?
    else {
        return Err(SignatureFormError::Invalid(
            "No such signature.".to_string(),
        ));
    };
    let name = signature_name(&form.name)?;
    let identity = signature_identity(&form.identity, mailbox, identities)?;
    let (body_text, body_html) = signature_body_parts(&form.body_text, &form.body_html)?;
    let signature = Signature {
        id: existing.id,
        user: mailbox.to_string(),
        identity,
        name,
        body_html,
        body_text,
        is_default: !form.is_default.trim().is_empty(),
        created_at: existing.created_at,
    };
    state
        .store
        .update_signature(&signature)
        .await
        .map_err(SignatureFormError::Store)
}

fn signature_name(raw: &str) -> Result<String, SignatureFormError> {
    let name = raw.trim();
    if name.is_empty() {
        return Err(SignatureFormError::Invalid(
            "A signature name is required.".to_string(),
        ));
    }
    Ok(name.to_string())
}

fn signature_identity(
    raw: &str,
    mailbox: &str,
    identities: &[crate::model::SendIdentity],
) -> Result<String, SignatureFormError> {
    let identity = raw.trim();
    if identity.is_empty() {
        return Ok(String::new());
    }
    if identity.eq_ignore_ascii_case(mailbox)
        || identities
            .iter()
            .any(|i| i.from_addr.eq_ignore_ascii_case(identity))
    {
        return Ok(identity.to_lowercase());
    }
    Err(SignatureFormError::Invalid(
        "That From identity is not available for this mailbox.".to_string(),
    ))
}

fn signature_body_parts(
    body_text: &str,
    body_html: &str,
) -> Result<(String, String), SignatureFormError> {
    let clean_html = crate::sanitize::sanitize_html(body_html);
    if clean_html.trim().is_empty() {
        let text = body_text.trim();
        if text.is_empty() {
            return Err(SignatureFormError::Invalid(
                "A signature body is required.".to_string(),
            ));
        }
        return Ok((text.to_string(), String::new()));
    }
    let text = if body_text.trim().is_empty() {
        crate::sanitize::html_to_text(&clean_html)
    } else {
        body_text.trim().to_string()
    };
    Ok((text, clean_html))
}

/// Form body for `POST /settings/undo-send`.
#[derive(Deserialize, Default)]
struct UndoSendSettingsForm {
    csrf: String,
    #[serde(default)]
    window_secs: String,
}

/// `POST /settings/undo-send` — save the Gmail-style cancellation window. CSRF-guarded; emits a
/// tracing audit line and redirects back to `/settings`.
async fn settings_undo_send(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<UndoSendSettingsForm>,
) -> Response {
    if !verify_csrf(&headers, &form.csrf) {
        return error_page(
            StatusCode::FORBIDDEN,
            "Request blocked",
            "CSRF token missing or mismatched.",
        );
    }
    let Some(mb) = resolve_mailbox(&state, &headers).await else {
        return no_mailbox_page(&email_display(&headers));
    };
    let secs = match parse_undo_send_window_secs(&form.window_secs) {
        Ok(secs) => secs,
        Err((code, message)) => return error_page(code, "Invalid request", &message),
    };
    if let Err(e) = state.store.set_undo_send_window(&mb.addr, secs).await {
        return error_page(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Storage error",
            &e.to_string(),
        );
    }
    tracing::info!(
        target: "corvid::audit",
        actor = %identity_subject(&headers).unwrap_or_default(),
        mailbox = %mb.addr,
        secs,
        "undo-send window updated",
    );
    Redirect::to("/settings").into_response()
}

/// Form body for `POST /settings/preferences`.
#[derive(Deserialize, Default)]
struct DisplayPreferencesForm {
    csrf: String,
    #[serde(default)]
    density: String,
    #[serde(default)]
    reading_pane: String,
    #[serde(default)]
    theme: String,
}

/// `POST /settings/preferences` — save display density, reading pane, and theme preferences.
/// CSRF-guarded; values are finite strings so the root `data-*` attributes stay predictable.
async fn settings_preferences(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<DisplayPreferencesForm>,
) -> Response {
    if !verify_csrf(&headers, &form.csrf) {
        return error_page(
            StatusCode::FORBIDDEN,
            "Request blocked",
            "CSRF token missing or mismatched.",
        );
    }
    let Some(mb) = resolve_mailbox(&state, &headers).await else {
        return no_mailbox_page(&email_display(&headers));
    };
    let density = match parse_display_choice(&form.density, &DENSITY_CHOICES, "density") {
        Ok(value) => value,
        Err((code, message)) => return error_page(code, "Invalid request", &message),
    };
    let reading_pane =
        match parse_display_choice(&form.reading_pane, &READING_PANE_CHOICES, "reading pane") {
            Ok(value) => value,
            Err((code, message)) => return error_page(code, "Invalid request", &message),
        };
    let theme = match parse_display_choice(&form.theme, &THEME_CHOICES, "theme") {
        Ok(value) => value,
        Err((code, message)) => return error_page(code, "Invalid request", &message),
    };
    if let Err(e) = state
        .store
        .set_display_preferences(&mb.addr, density, reading_pane, theme)
        .await
    {
        return error_page(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Storage error",
            &e.to_string(),
        );
    }
    tracing::info!(
        target: "corvid::audit",
        actor = %identity_subject(&headers).unwrap_or_default(),
        mailbox = %mb.addr,
        density,
        reading_pane,
        theme,
        "display preferences updated",
    );
    Redirect::to("/settings").into_response()
}

/// Form body for `POST /settings/autoreply`. `enabled` is a checkbox (absent = off); `until` is
/// an optional `YYYY-MM-DD` (empty = no expiry).
#[derive(Deserialize, Default)]
struct AutoReplyForm {
    csrf: String,
    #[serde(default)]
    enabled: String,
    #[serde(default)]
    subject: String,
    #[serde(default)]
    body: String,
    #[serde(default)]
    until: String,
}

/// `POST /settings/autoreply` — save the auto-reply (vacation) configuration. CSRF-guarded;
/// emits a tracing audit line and redirects back to `/settings`.
async fn settings_autoreply(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<AutoReplyForm>,
) -> Response {
    if !verify_csrf(&headers, &form.csrf) {
        return error_page(
            StatusCode::FORBIDDEN,
            "Request blocked",
            "CSRF token missing or mismatched.",
        );
    }
    let Some(mb) = resolve_mailbox(&state, &headers).await else {
        return no_mailbox_page(&email_display(&headers));
    };
    let Some(until) = parse_until(&form.until) else {
        return error_page(
            StatusCode::BAD_REQUEST,
            "Invalid request",
            "The end date must be YYYY-MM-DD (or empty).",
        );
    };
    let enabled = !form.enabled.trim().is_empty();
    if let Err(e) = state
        .store
        .set_auto_reply(&mb.addr, enabled, form.subject.trim(), &form.body, until)
        .await
    {
        return error_page(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Storage error",
            &e.to_string(),
        );
    }
    tracing::info!(
        target: "corvid::audit",
        actor = %identity_subject(&headers).unwrap_or_default(),
        mailbox = %mb.addr,
        enabled,
        until,
        "auto-reply updated",
    );
    Redirect::to("/settings").into_response()
}

/// Parse the auto-reply end date: empty = `Some(0)` (no expiry), `YYYY-MM-DD` = that day's
/// midnight UTC, anything else = `None` (rejected).
fn parse_until(s: &str) -> Option<i64> {
    let s = s.trim();
    if s.is_empty() {
        return Some(0);
    }
    let mut it = s.split('-');
    let y: i32 = it.next()?.parse().ok()?;
    let m: u8 = it.next()?.parse().ok()?;
    let d: u8 = it.next()?.parse().ok()?;
    if it.next().is_some() {
        return None;
    }
    let date = time::Date::from_calendar_date(y, time::Month::try_from(m).ok()?, d).ok()?;
    Some(date.midnight().assume_utc().unix_timestamp())
}

/// Format a stored `auto_reply_until` back into the date input's `YYYY-MM-DD` (empty for 0).
fn fmt_until(ts: i64) -> String {
    if ts <= 0 {
        return String::new();
    }
    match OffsetDateTime::from_unix_timestamp(ts) {
        Ok(dt) => format!("{:04}-{:02}-{:02}", dt.year(), dt.month() as u8, dt.day()),
        Err(_) => String::new(),
    }
}

/// `GET /settings/templates` — templates are managed on the main settings page.
async fn settings_templates_redirect() -> Response {
    Redirect::to("/settings#templates").into_response()
}

// ---------------------------------------------------------------------------
// Settings — templates / labels / send identities / contacts (per-mailbox)
// ---------------------------------------------------------------------------

fn render_templates_section(templates: &[Template], token: &str) -> String {
    let mut list = String::new();
    if templates.is_empty() {
        list.push_str(r#"<p class="muted">No templates yet.</p>"#);
    }
    for (i, t) in templates.iter().enumerate() {
        list.push_str(&format!(
            r#"<div class="template-item">
  <form method="post" action="/settings/templates">
    <input type="hidden" name="csrf" value="{token}">
    <input type="hidden" name="id" value="{id}">
    <div class="field"><label for="tpl_name_{i}">Name</label><input id="tpl_name_{i}" name="name" value="{name}"></div>
    <div class="field"><label for="tpl_body_{i}">Body</label><textarea id="tpl_body_{i}" name="body_text">{body}</textarea></div>
    <div class="form-actions">
      <button class="btn btn-primary btn-sm" type="submit" name="cmd" value="update">Save template</button>
      <button class="btn btn-ghost btn-sm" type="submit" name="cmd" value="delete">Delete</button>
    </div>
  </form>
</div>"#,
            token = esc(token),
            id = esc(&t.id),
            name = esc(&t.name),
            body = esc(&t.body_text),
            i = i,
        ));
    }
    format!(
        r#"<section id="templates" class="card pad template-list">
  <h2>Templates</h2>
  <div class="template-list__items">{list}</div>
  <form class="template-create" method="post" action="/settings/templates">
    <input type="hidden" name="csrf" value="{token}">
    <div class="field"><label for="tpl_new_name">Name</label><input id="tpl_new_name" name="name" placeholder="Follow-up"></div>
    <div class="field"><label for="tpl_new_body">Body</label><textarea id="tpl_new_body" name="body_text"></textarea></div>
    <div class="form-actions"><button class="btn btn-primary" type="submit" name="cmd" value="add">Add template</button></div>
  </form>
</section>"#,
        token = esc(token),
    )
}

/// Form body for `POST /settings/templates`: add/update/delete a private compose template.
#[derive(Deserialize, Default)]
struct TemplateForm {
    csrf: String,
    #[serde(default)]
    cmd: String,
    #[serde(default)]
    id: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    body_text: String,
    #[serde(default)]
    body_html: String,
}

enum TemplateFormError {
    Invalid(String),
    Store(crate::store::StoreError),
}

async fn settings_templates_post(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<TemplateForm>,
) -> Response {
    if !verify_csrf(&headers, &form.csrf) {
        return error_page(
            StatusCode::FORBIDDEN,
            "Request blocked",
            "CSRF token missing or mismatched.",
        );
    }
    let Some(mb) = resolve_mailbox(&state, &headers).await else {
        return no_mailbox_page(&email_display(&headers));
    };

    let result = match form.cmd.as_str() {
        "delete" => state
            .store
            .delete_template(&mb.addr, form.id.trim())
            .await
            .map_err(TemplateFormError::Store),
        "update" => update_template_from_form(&state, &mb.addr, &form).await,
        "" | "add" => create_template_from_form(&state, &mb.addr, &form).await,
        _ => Err(TemplateFormError::Invalid(
            "Unknown template command.".to_string(),
        )),
    };
    if let Err(e) = result {
        return match e {
            TemplateFormError::Invalid(message) => {
                error_page(StatusCode::BAD_REQUEST, "Invalid request", &message)
            }
            TemplateFormError::Store(e) => error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Storage error",
                &e.to_string(),
            ),
        };
    }
    tracing::info!(
        target: "corvid::audit",
        actor = %identity_subject(&headers).unwrap_or_default(),
        mailbox = %mb.addr,
        cmd = %if form.cmd.is_empty() { "add" } else { form.cmd.as_str() },
        template = %form.id,
        "template change",
    );
    Redirect::to("/settings#templates").into_response()
}

async fn create_template_from_form(
    state: &AppState,
    mailbox: &str,
    form: &TemplateForm,
) -> Result<(), TemplateFormError> {
    let name = template_name(&form.name)?;
    let (body_text, body_html) = template_body_parts(&form.body_text, &form.body_html)?;
    let now = now_secs();
    let template = Template {
        id: new_id("tpl"),
        user: mailbox.to_string(),
        name,
        body_html,
        body_text,
        created_at: now,
        updated_at: now,
    };
    state
        .store
        .create_template(&template)
        .await
        .map_err(TemplateFormError::Store)
}

async fn update_template_from_form(
    state: &AppState,
    mailbox: &str,
    form: &TemplateForm,
) -> Result<(), TemplateFormError> {
    let id = form.id.trim();
    let Some(existing) = state
        .store
        .get_template(mailbox, id)
        .await
        .map_err(TemplateFormError::Store)?
    else {
        return Err(TemplateFormError::Invalid("No such template.".to_string()));
    };
    let name = template_name(&form.name)?;
    let (body_text, body_html) = template_body_parts(&form.body_text, &form.body_html)?;
    let template = Template {
        id: existing.id,
        user: mailbox.to_string(),
        name,
        body_html,
        body_text,
        created_at: existing.created_at,
        updated_at: now_secs(),
    };
    state
        .store
        .update_template(&template)
        .await
        .map_err(TemplateFormError::Store)
}

fn template_name(raw: &str) -> Result<String, TemplateFormError> {
    let name = raw.trim();
    if name.is_empty() {
        return Err(TemplateFormError::Invalid(
            "A template name is required.".to_string(),
        ));
    }
    Ok(name.to_string())
}

fn template_body_parts(
    body_text: &str,
    body_html: &str,
) -> Result<(String, String), TemplateFormError> {
    let clean_html = crate::sanitize::sanitize_html(body_html);
    if clean_html.trim().is_empty() {
        if body_text.trim().is_empty() {
            return Err(TemplateFormError::Invalid(
                "A template body is required.".to_string(),
            ));
        }
        return Ok((body_text.to_string(), String::new()));
    }
    let text = if body_text.trim().is_empty() {
        crate::sanitize::html_to_text(&clean_html)
    } else {
        body_text.to_string()
    };
    Ok((text, clean_html))
}

fn render_sender_lists_section(entries: &[SenderListEntry], token: &str) -> String {
    let mut rows = String::new();
    if entries.is_empty() {
        rows.push_str(
            r#"<tr><td colspan="3" class="muted">No safe or blocked senders yet.</td></tr>"#,
        );
    }
    for e in entries {
        let kind_cls = if e.kind == "safe" {
            "sender-list-safe"
        } else {
            "sender-list-blocked"
        };
        rows.push_str(&format!(
            r#"<tr class="{kind_cls}"><td>{addr}</td><td><span class="pill">{kind}</span></td><td>
<form class="row-actions" method="post" action="/settings/senders">
  <input type="hidden" name="csrf" value="{token}">
  <input type="hidden" name="id" value="{id}">
  <button class="btn btn-ghost btn-sm" type="submit" name="cmd" value="delete">Delete</button>
</form></td></tr>"#,
            addr = esc(&e.address_or_domain),
            kind = sender_kind_label(&e.kind),
            id = esc(&e.id),
            token = esc(token),
        ));
    }
    format!(
        r#"<section class="card pad sender-lists">
  <h2>Safe and blocked senders</h2>
  <table class="data admin-table">
    <thead><tr><th>Address or domain</th><th>List</th><th></th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
  <form method="post" action="/settings/senders">
    <input type="hidden" name="csrf" value="{token}">
    <div class="field"><label for="sender_addr">Address or domain</label><input id="sender_addr" name="address_or_domain" placeholder="sender@example.com"></div>
    <div class="field"><label for="sender_kind">List</label><select id="sender_kind" name="kind"><option value="blocked">Blocked</option><option value="safe">Safe</option></select></div>
    <div class="form-actions"><button class="btn btn-primary" type="submit" name="cmd" value="add">Add sender</button></div>
  </form>
</section>"#,
        token = esc(token),
    )
}

fn sender_kind_label(kind: &str) -> String {
    match kind {
        "safe" => "Safe".to_string(),
        "blocked" => "Blocked".to_string(),
        other => esc(other),
    }
}

/// Form body for `POST /settings/senders`: CSRF, `cmd` (`add`|`delete`), `id` (delete), plus
/// `address_or_domain` and `kind` (`blocked`|`safe`) for add.
#[derive(Deserialize, Default)]
struct SenderForm {
    csrf: String,
    #[serde(default)]
    cmd: String,
    #[serde(default)]
    id: String,
    #[serde(default)]
    address_or_domain: String,
    #[serde(default)]
    kind: String,
}

async fn settings_senders_post(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<SenderForm>,
) -> Response {
    if !verify_csrf(&headers, &form.csrf) {
        return error_page(
            StatusCode::FORBIDDEN,
            "Request blocked",
            "CSRF token missing or mismatched.",
        );
    }
    let Some(mb) = resolve_mailbox(&state, &headers).await else {
        return no_mailbox_page(&email_display(&headers));
    };

    let result = match form.cmd.as_str() {
        "delete" => {
            state
                .store
                .delete_sender_list(&mb.addr, form.id.trim())
                .await
        }
        _ => {
            let kind = match form.kind.as_str() {
                "safe" => "safe",
                "" | "blocked" => "blocked",
                _ => {
                    return error_page(
                        StatusCode::BAD_REQUEST,
                        "Invalid request",
                        "Unknown sender list kind.",
                    );
                }
            };
            let Some(address_or_domain) = normalize_sender_list_value(&form.address_or_domain)
            else {
                return error_page(
                    StatusCode::BAD_REQUEST,
                    "Invalid request",
                    "A valid sender address or domain is required.",
                );
            };
            let entry = SenderListEntry {
                id: new_id("sl"),
                user: mb.addr.clone(),
                address_or_domain,
                kind: kind.to_string(),
                created_at: now_secs(),
            };
            state.store.upsert_sender_list(&entry).await
        }
    };
    if let Err(e) = result {
        return error_page(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Storage error",
            &e.to_string(),
        );
    }
    tracing::info!(
        target: "corvid::audit",
        actor = %identity_subject(&headers).unwrap_or_default(),
        mailbox = %mb.addr,
        cmd = %if form.cmd.is_empty() { "add" } else { form.cmd.as_str() },
        "sender list change",
    );
    Redirect::to("/settings").into_response()
}

/// The Labels settings card: existing labels (with delete) + an add form.
fn render_labels_section(labels: &[Label], token: &str) -> String {
    let mut rows = String::new();
    if labels.is_empty() {
        rows.push_str(r#"<tr><td colspan="2" class="muted">No labels yet.</td></tr>"#);
    }
    for l in labels {
        rows.push_str(&format!(
            r#"<tr><td><span class="pill label-pill">{name}</span></td><td>
<form class="row-actions" method="post" action="/settings/labels">
  <input type="hidden" name="csrf" value="{token}">
  <input type="hidden" name="id" value="{id}">
  <button class="btn btn-ghost btn-sm" type="submit" name="cmd" value="delete">Delete</button>
</form></td></tr>"#,
            name = esc(&l.name),
            id = esc(&l.id),
            token = esc(token),
        ));
    }
    format!(
        r#"<section class="card pad">
  <h2>Labels</h2>
  <p class="muted">Arbitrary tags you can apply to messages (independent of folders). Filter by a label from the tab strip, or add one automatically with an "Add label" filter rule.</p>
  <table class="data admin-table">
    <thead><tr><th>Label</th><th></th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
  <form method="post" action="/settings/labels">
    <input type="hidden" name="csrf" value="{token}">
    <div class="field"><label for="label_name">New label</label><input id="label_name" name="name" placeholder="Receipts"></div>
    <div class="form-actions"><button class="btn btn-primary" type="submit">Add label</button></div>
  </form>
</section>"#,
        token = esc(token),
    )
}

/// The Send identities settings card: the mailbox's own address (implicit), each configured
/// identity (with delete), and an add form.
fn render_identities_section(
    identities: &[crate::model::SendIdentity],
    mailbox: &str,
    token: &str,
) -> String {
    let mut rows = format!(
        r#"<tr><td>{addr}</td><td class="muted">mailbox default</td><td></td></tr>"#,
        addr = esc(mailbox),
    );
    for i in identities {
        let display = if i.display_name.trim().is_empty() {
            String::from("—")
        } else {
            esc(&i.display_name)
        };
        let def = if i.is_default {
            r#"<span class="pill pill-ok">default</span>"#
        } else {
            ""
        };
        rows.push_str(&format!(
            r#"<tr><td>{addr}</td><td>{display} {def}</td><td>
<form class="row-actions" method="post" action="/settings/identities">
  <input type="hidden" name="csrf" value="{token}">
  <input type="hidden" name="id" value="{id}">
  <button class="btn btn-ghost btn-sm" type="submit" name="cmd" value="delete">Delete</button>
</form></td></tr>"#,
            addr = esc(&i.from_addr),
            id = esc(&i.id),
            token = esc(token),
        ));
    }
    format!(
        r#"<section class="card pad">
  <h2>Send identities</h2>
  <p class="muted">Extra "From" addresses you may send as (must be at this mail domain so outgoing mail stays signed). Pick one in the compose "From" selector.</p>
  <table class="data admin-table">
    <thead><tr><th>From address</th><th>Display / default</th><th></th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
  <form method="post" action="/settings/identities">
    <input type="hidden" name="csrf" value="{token}">
    <div class="field"><label for="idn_addr">From address</label><input id="idn_addr" name="from_addr" placeholder="info@w33d.xyz"></div>
    <div class="field"><label for="idn_name">Display name</label><input id="idn_name" name="display_name" placeholder="HOLDFAST Info"></div>
    <div class="field"><label><input type="checkbox" name="is_default" value="on"> Make this my default From</label></div>
    <div class="form-actions"><button class="btn btn-primary" type="submit">Add identity</button></div>
  </form>
</section>"#,
        token = esc(token),
    )
}

/// The Contacts settings card: rich contact cards, group management, import/export, and duplicate
/// merge. The class hooks are intentionally SSR-only; visual styling stays in the stylesheet owner.
fn render_contacts_section(
    contacts: &[Contact],
    groups: &[(ContactGroup, Vec<Contact>)],
    duplicate_contacts: &[Contact],
    token: &str,
) -> String {
    let mut cards = String::new();
    if contacts.is_empty() {
        cards.push_str(
            r#"<p class="muted contact-empty">No contacts yet - they build up as you send and receive mail.</p>"#,
        );
    }
    for c in contacts {
        cards.push_str(&render_contact_card(c, token));
    }

    let mut duplicates = String::new();
    if !duplicate_contacts.is_empty() {
        for c in duplicate_contacts {
            duplicates.push_str(&format!(
                r#"<form class="row-actions contact-duplicate" method="post" action="/settings/contacts">
  <input type="hidden" name="csrf" value="{token}">
  <input type="hidden" name="addr" value="{addr}">
  <span>{label}</span>
  <button class="btn btn-ghost btn-sm" type="submit" name="cmd" value="merge">Merge</button>
</form>"#,
                token = esc(token),
                addr = esc(&c.addr),
                label = esc(&contact_label(c)),
            ));
        }
        duplicates =
            format!(r#"<div class="contact-duplicates"><h3>Duplicates</h3>{duplicates}</div>"#);
    }

    let mut group_cards = String::new();
    if groups.is_empty() {
        group_cards.push_str(r#"<p class="muted contact-group-empty">No groups yet.</p>"#);
    }
    for (group, members) in groups {
        group_cards.push_str(&render_contact_group_card(group, members, contacts, token));
    }

    format!(
        r#"<section class="contacts-settings" id="contacts">
  <h2>Contacts</h2>
  <p class="muted">Correspondents power autocomplete and contact groups expand in the To/Cc fields.</p>
  <div class="contact-actions">
    <a class="btn btn-ghost btn-sm btn-export-vcard" href="/settings/contacts/export?format=vcf">Export vCard</a>
    <a class="btn btn-ghost btn-sm btn-export-csv" href="/settings/contacts/export?format=csv">Export CSV</a>
  </div>
  <div class="contact-grid">{cards}</div>
  {duplicates}
  <form class="contact-card contact-create" method="post" action="/settings/contacts">
    <input type="hidden" name="csrf" value="{token}">
    <div class="field"><label for="ct_addr">Address</label><input id="ct_addr" name="addr" placeholder="friend@example.com"></div>
    <div class="field"><label for="ct_name">Name</label><input id="ct_name" name="name" placeholder="Friend"></div>
    <div class="field"><label for="ct_phone">Phone</label><input id="ct_phone" name="phone"></div>
    <div class="field"><label for="ct_company">Company</label><input id="ct_company" name="company"></div>
    <div class="field"><label for="ct_title">Title</label><input id="ct_title" name="title"></div>
    <div class="field"><label for="ct_notes">Notes</label><textarea id="ct_notes" name="notes"></textarea></div>
    <div class="form-actions"><button class="btn btn-primary" type="submit" name="cmd" value="add">Add contact</button></div>
  </form>
  <div class="contact-groups">
    <h3>Groups</h3>
    {group_cards}
    <form class="contact-group contact-group-create" method="post" action="/settings/contact-groups">
      <input type="hidden" name="csrf" value="{token}">
      <div class="field"><label for="cg_name">Group name</label><input id="cg_name" name="name" placeholder="Team"></div>
      <div class="form-actions"><button class="btn btn-primary" type="submit" name="cmd" value="add">Add group</button></div>
    </form>
  </div>
  <form class="contact-import" method="post" action="/settings/contacts/import" enctype="multipart/form-data">
    <input type="hidden" name="csrf" value="{token}">
    <div class="field"><label for="ct_import_format">Format</label><select id="ct_import_format" name="format"><option value="auto">Auto</option><option value="vcf">vCard</option><option value="csv">CSV</option></select></div>
    <div class="field"><label for="ct_import_file">File</label><input id="ct_import_file" name="file" type="file" accept=".vcf,.vcard,.csv,text/vcard,text/csv"></div>
    <div class="field"><label for="ct_import_data">Paste</label><textarea id="ct_import_data" name="data"></textarea></div>
    <div class="form-actions"><button class="btn btn-primary btn-import-vcard" type="submit">Import</button></div>
  </form>
</section>"#,
        cards = cards,
        duplicates = duplicates,
        group_cards = group_cards,
        token = esc(token),
    )
}

fn render_contact_card(c: &Contact, token: &str) -> String {
    let kind = if c.manual { "manual" } else { "auto" };
    format!(
        r#"<article class="contact-card" data-contact="{addr}">
  <form method="post" action="/settings/contacts">
    <input type="hidden" name="csrf" value="{token}">
    <input type="hidden" name="addr" value="{addr}">
    <header><h3>{label}</h3><span class="muted">{kind}</span></header>
    <div class="field"><label>Name</label><input name="name" value="{name}"></div>
    <div class="field"><label>Phone</label><input name="phone" value="{phone}"></div>
    <div class="field"><label>Company</label><input name="company" value="{company}"></div>
    <div class="field"><label>Title</label><input name="title" value="{title}"></div>
    <div class="field"><label>Notes</label><textarea name="notes">{notes}</textarea></div>
    <div class="form-actions">
      <button class="btn btn-primary btn-sm" type="submit" name="cmd" value="update">Save</button>
      <button class="btn btn-ghost btn-sm" type="submit" name="cmd" value="delete">Delete</button>
    </div>
  </form>
</article>"#,
        token = esc(token),
        addr = esc(&c.addr),
        label = esc(&contact_label(c)),
        kind = kind,
        name = esc(&c.name),
        phone = esc(&c.phone),
        company = esc(&c.company),
        title = esc(&c.title),
        notes = esc(&c.notes),
    )
}

fn render_contact_group_card(
    group: &ContactGroup,
    members: &[Contact],
    contacts: &[Contact],
    token: &str,
) -> String {
    let mut member_rows = String::new();
    if members.is_empty() {
        member_rows.push_str(r#"<li class="muted">No members.</li>"#);
    }
    for member in members {
        member_rows.push_str(&format!(
            r#"<li>
  <form class="row-actions" method="post" action="/settings/contact-groups">
    <input type="hidden" name="csrf" value="{token}">
    <input type="hidden" name="id" value="{id}">
    <input type="hidden" name="addr" value="{addr}">
    <span>{label}</span>
    <button class="btn btn-ghost btn-sm" type="submit" name="cmd" value="remove-member">Remove</button>
  </form>
</li>"#,
            token = esc(token),
            id = esc(&group.id),
            addr = esc(&member.addr),
            label = esc(&contact_label(member)),
        ));
    }
    format!(
        r#"<article class="contact-group" data-group="{id}">
  <form method="post" action="/settings/contact-groups">
    <input type="hidden" name="csrf" value="{token}">
    <input type="hidden" name="id" value="{id}">
    <div class="field"><label>Group name</label><input name="name" value="{name}"></div>
    <div class="form-actions">
      <button class="btn btn-primary btn-sm" type="submit" name="cmd" value="update">Save</button>
      <button class="btn btn-ghost btn-sm" type="submit" name="cmd" value="delete">Delete</button>
    </div>
  </form>
  <ul class="contact-group-members">{member_rows}</ul>
  <form class="row-actions" method="post" action="/settings/contact-groups">
    <input type="hidden" name="csrf" value="{token}">
    <input type="hidden" name="id" value="{id}">
    <select name="addr" aria-label="Contact">{options}</select>
    <button class="btn btn-ghost btn-sm" type="submit" name="cmd" value="add-member">Add member</button>
  </form>
</article>"#,
        token = esc(token),
        id = esc(&group.id),
        name = esc(&group.name),
        member_rows = member_rows,
        options = render_contact_options(contacts, ""),
    )
}

fn render_contact_options(contacts: &[Contact], selected: &str) -> String {
    let mut options = String::new();
    for c in contacts {
        let sel = if c.addr == selected { " selected" } else { "" };
        options.push_str(&format!(
            r#"<option value="{addr}"{sel}>{label}</option>"#,
            addr = esc(&c.addr),
            label = esc(&contact_label(c)),
            sel = sel,
        ));
    }
    options
}

fn contact_label(c: &Contact) -> String {
    if c.name.trim().is_empty() {
        c.addr.clone()
    } else {
        format!("{} <{}>", c.name.trim(), c.addr)
    }
}

/// Form body for `POST /settings/labels`: CSRF, `cmd` (`add`|`delete`), and the label `name` (add)
/// or `id` (delete).
#[derive(Deserialize, Default)]
struct LabelForm {
    csrf: String,
    #[serde(default)]
    cmd: String,
    #[serde(default)]
    id: String,
    #[serde(default)]
    name: String,
}

/// `POST /settings/labels` — create/delete a label, scoped to the signed-in mailbox. CSRF-guarded.
async fn settings_labels_post(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<LabelForm>,
) -> Response {
    if !verify_csrf(&headers, &form.csrf) {
        return error_page(
            StatusCode::FORBIDDEN,
            "Request blocked",
            "CSRF token missing or mismatched.",
        );
    }
    let Some(mb) = resolve_mailbox(&state, &headers).await else {
        return no_mailbox_page(&email_display(&headers));
    };
    let result = match form.cmd.as_str() {
        "delete" => state.store.delete_label(&mb.addr, form.id.trim()).await,
        _ => {
            let name = form.name.trim();
            if name.is_empty() {
                return error_page(
                    StatusCode::BAD_REQUEST,
                    "Invalid request",
                    "A label name is required.",
                );
            }
            let label = Label {
                id: new_id("lbl"),
                mailbox: mb.addr.clone(),
                name: name.to_string(),
                color: String::new(),
            };
            state.store.add_label(&label).await
        }
    };
    if let Err(e) = result {
        return error_page(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Storage error",
            &e.to_string(),
        );
    }
    tracing::info!(
        target: "corvid::audit",
        actor = %identity_subject(&headers).unwrap_or_default(),
        mailbox = %mb.addr,
        cmd = %if form.cmd.is_empty() { "add" } else { form.cmd.as_str() },
        "label change",
    );
    Redirect::to("/settings").into_response()
}

/// Form body for `POST /settings/identities`: CSRF, `cmd` (`add`|`delete`), the `id` (delete), and
/// the `from_addr`/`display_name`/`is_default` (add).
#[derive(Deserialize, Default)]
struct IdentityForm {
    csrf: String,
    #[serde(default)]
    cmd: String,
    #[serde(default)]
    id: String,
    #[serde(default)]
    from_addr: String,
    #[serde(default)]
    display_name: String,
    #[serde(default)]
    is_default: String,
}

/// `POST /settings/identities` — add/delete a send identity, scoped to the signed-in mailbox.
/// CSRF-guarded. A new identity's `from_addr` must be at the mail domain (so outbound stays
/// DKIM-signable — the same rule the internal send API enforces).
async fn settings_identities_post(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<IdentityForm>,
) -> Response {
    if !verify_csrf(&headers, &form.csrf) {
        return error_page(
            StatusCode::FORBIDDEN,
            "Request blocked",
            "CSRF token missing or mismatched.",
        );
    }
    let Some(mb) = resolve_mailbox(&state, &headers).await else {
        return no_mailbox_page(&email_display(&headers));
    };
    let result = match form.cmd.as_str() {
        "delete" => {
            state
                .store
                .delete_send_identity(&mb.addr, form.id.trim())
                .await
        }
        _ => {
            let from_addr = extract_addr(&form.from_addr).to_lowercase();
            if from_addr.is_empty()
                || domain_of(&from_addr).as_deref()
                    != Some(state.config.mail_domain.to_lowercase().as_str())
            {
                return error_page(
                    StatusCode::BAD_REQUEST,
                    "Invalid request",
                    "A send identity must be an address at this mail domain.",
                );
            }
            let identity = crate::model::SendIdentity {
                id: new_id("si"),
                mailbox: mb.addr.clone(),
                from_addr,
                display_name: header_safe(form.display_name.trim()),
                is_default: !form.is_default.trim().is_empty(),
            };
            state.store.add_send_identity(&identity).await
        }
    };
    if let Err(e) = result {
        return error_page(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Storage error",
            &e.to_string(),
        );
    }
    tracing::info!(
        target: "corvid::audit",
        actor = %identity_subject(&headers).unwrap_or_default(),
        mailbox = %mb.addr,
        cmd = %if form.cmd.is_empty() { "add" } else { form.cmd.as_str() },
        "send identity change",
    );
    Redirect::to("/settings").into_response()
}

/// Form body for `POST /settings/contacts`: CSRF, `cmd` (`add`|`delete`), the `addr`, and `name`.
#[derive(Deserialize, Default)]
struct ContactForm {
    csrf: String,
    #[serde(default)]
    cmd: String,
    #[serde(default)]
    addr: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    phone: String,
    #[serde(default)]
    company: String,
    #[serde(default)]
    title: String,
    #[serde(default)]
    notes: String,
}

/// `POST /settings/contacts` — add a manual contact or delete one, scoped to the signed-in mailbox.
/// CSRF-guarded.
async fn settings_contacts_post(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<ContactForm>,
) -> Response {
    if !verify_csrf(&headers, &form.csrf) {
        return error_page(
            StatusCode::FORBIDDEN,
            "Request blocked",
            "CSRF token missing or mismatched.",
        );
    }
    let Some(mb) = resolve_mailbox(&state, &headers).await else {
        return no_mailbox_page(&email_display(&headers));
    };
    let addr = extract_addr(&form.addr).to_lowercase();
    let result = match form.cmd.as_str() {
        "delete" => state.store.delete_contact(&mb.addr, &addr).await,
        "merge" => state.store.merge_duplicate_contact(&mb.addr, &addr).await,
        _ => {
            if !addr.contains('@') {
                return error_page(
                    StatusCode::BAD_REQUEST,
                    "Invalid request",
                    "A valid contact address is required.",
                );
            }
            let contact = Contact {
                addr: addr.clone(),
                name: form.name.trim().to_string(),
                phone: form.phone.trim().to_string(),
                company: form.company.trim().to_string(),
                title: form.title.trim().to_string(),
                notes: form.notes.trim().to_string(),
                manual: true,
                seen_count: 0,
            };
            state.store.save_contact(&mb.addr, &contact).await
        }
    };
    if let Err(e) = result {
        return error_page(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Storage error",
            &e.to_string(),
        );
    }
    tracing::info!(
        target: "corvid::audit",
        actor = %identity_subject(&headers).unwrap_or_default(),
        mailbox = %mb.addr,
        cmd = %if form.cmd.is_empty() { "add" } else { form.cmd.as_str() },
        "contact change",
    );
    Redirect::to("/settings").into_response()
}

#[derive(Deserialize, Default)]
struct ContactGroupForm {
    csrf: String,
    #[serde(default)]
    cmd: String,
    #[serde(default)]
    id: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    addr: String,
}

async fn settings_contact_groups_post(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<ContactGroupForm>,
) -> Response {
    if !verify_csrf(&headers, &form.csrf) {
        return error_page(
            StatusCode::FORBIDDEN,
            "Request blocked",
            "CSRF token missing or mismatched.",
        );
    }
    let Some(mb) = resolve_mailbox(&state, &headers).await else {
        return no_mailbox_page(&email_display(&headers));
    };
    let result = match form.cmd.as_str() {
        "delete" => {
            state
                .store
                .delete_contact_group(&mb.addr, form.id.trim())
                .await
        }
        "add-member" => {
            let addr = extract_addr(&form.addr).to_lowercase();
            state
                .store
                .add_contact_group_member(&mb.addr, form.id.trim(), &addr)
                .await
        }
        "remove-member" => {
            let addr = extract_addr(&form.addr).to_lowercase();
            state
                .store
                .delete_contact_group_member(&mb.addr, form.id.trim(), &addr)
                .await
        }
        _ => {
            let name = form.name.trim();
            if name.is_empty() || name.contains(',') || name.contains(';') {
                return error_page(
                    StatusCode::BAD_REQUEST,
                    "Invalid request",
                    "A group name is required and cannot contain recipient separators.",
                );
            }
            let id = if form.id.trim().is_empty() {
                new_id("cg")
            } else {
                form.id.trim().to_string()
            };
            let group = ContactGroup {
                id,
                user: mb.addr.clone(),
                name: name.to_string(),
                created_at: now_secs(),
            };
            state.store.save_contact_group(&group).await
        }
    };
    if let Err(e) = result {
        return error_page(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Storage error",
            &e.to_string(),
        );
    }
    tracing::info!(
        target: "corvid::audit",
        actor = %identity_subject(&headers).unwrap_or_default(),
        mailbox = %mb.addr,
        cmd = %if form.cmd.is_empty() { "add" } else { form.cmd.as_str() },
        "contact group change",
    );
    Redirect::to("/settings#contacts").into_response()
}

#[derive(Deserialize, Default)]
struct ContactExportQuery {
    #[serde(default)]
    format: String,
}

async fn settings_contacts_export(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ContactExportQuery>,
) -> Response {
    let Some(mb) = resolve_mailbox(&state, &headers).await else {
        return no_mailbox_page(&email_display(&headers));
    };
    let contacts = match state.store.list_contacts(&mb.addr, 10_000).await {
        Ok(list) => list,
        Err(e) => {
            return error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Storage error",
                &e.to_string(),
            );
        }
    };
    if q.format.eq_ignore_ascii_case("csv") {
        (
            [
                (header::CONTENT_TYPE, "text/csv; charset=utf-8".to_string()),
                (
                    header::CONTENT_DISPOSITION,
                    "attachment; filename=\"contacts.csv\"".to_string(),
                ),
            ],
            export_contacts_csv(&contacts),
        )
            .into_response()
    } else {
        (
            [
                (
                    header::CONTENT_TYPE,
                    "text/vcard; charset=utf-8".to_string(),
                ),
                (
                    header::CONTENT_DISPOSITION,
                    "attachment; filename=\"contacts.vcf\"".to_string(),
                ),
            ],
            export_contacts_vcard(&contacts),
        )
            .into_response()
    }
}

#[derive(Default)]
struct ContactImportPayload {
    csrf: String,
    format: String,
    data: String,
}

#[derive(Deserialize, Default)]
struct ContactImportForm {
    csrf: String,
    #[serde(default)]
    format: String,
    #[serde(default)]
    data: String,
}

async fn settings_contacts_import(
    State(state): State<AppState>,
    headers: HeaderMap,
    req: Request,
) -> Response {
    let payload = match parse_contact_import(req, &state, &headers).await {
        Ok(payload) => payload,
        Err(resp) => return resp,
    };
    if !verify_csrf(&headers, &payload.csrf) {
        return error_page(
            StatusCode::FORBIDDEN,
            "Request blocked",
            "CSRF token missing or mismatched.",
        );
    }
    let Some(mb) = resolve_mailbox(&state, &headers).await else {
        return no_mailbox_page(&email_display(&headers));
    };
    let mut parsed = parse_imported_contacts(&payload.data, &payload.format);
    let existing = match state.store.list_contacts(&mb.addr, 10_000).await {
        Ok(list) => list,
        Err(e) => {
            return error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Storage error",
                &e.to_string(),
            );
        }
    };
    let mut by_addr: HashMap<String, Contact> = existing
        .into_iter()
        .map(|c| (c.addr.to_lowercase(), c))
        .collect();
    let mut imported = 0_i64;
    for mut contact in parsed.contacts.drain(..) {
        contact.addr = extract_addr(&contact.addr).to_lowercase();
        if !is_valid_recipient_addr(&contact.addr) {
            parsed.skipped += 1;
            continue;
        }
        contact.manual = true;
        let merged = if let Some(existing) = by_addr.get(&contact.addr) {
            merge_import_contact(existing, &contact)
        } else {
            contact
        };
        if let Err(e) = state.store.save_contact(&mb.addr, &merged).await {
            return error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Storage error",
                &e.to_string(),
            );
        }
        by_addr.insert(merged.addr.clone(), merged);
        imported += 1;
    }
    tracing::info!(
        target: "corvid::audit",
        actor = %identity_subject(&headers).unwrap_or_default(),
        mailbox = %mb.addr,
        imported,
        skipped = parsed.skipped,
        "contacts import",
    );
    Redirect::to("/settings#contacts").into_response()
}

async fn parse_contact_import(
    req: Request,
    state: &AppState,
    headers: &HeaderMap,
) -> Result<ContactImportPayload, Response> {
    let ct = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if ct.starts_with("multipart/form-data") {
        let mut mp = Multipart::from_request(req, state)
            .await
            .map_err(|e| error_page(StatusCode::BAD_REQUEST, "Invalid request", &e.to_string()))?;
        let mut payload = ContactImportPayload::default();
        loop {
            let field = match mp.next_field().await {
                Ok(Some(f)) => f,
                Ok(None) => break,
                Err(e) => {
                    return Err(error_page(
                        StatusCode::BAD_REQUEST,
                        "Invalid upload",
                        &e.to_string(),
                    ));
                }
            };
            let name = field.name().unwrap_or("").to_string();
            if name == "file" {
                let filename = field.file_name().map(str::to_string).unwrap_or_default();
                let bytes = field.bytes().await.map_err(|e| {
                    error_page(StatusCode::BAD_REQUEST, "Invalid upload", &e.to_string())
                })?;
                if !bytes.is_empty() {
                    payload.data = String::from_utf8_lossy(&bytes).into_owned();
                    if payload.format.trim().is_empty() || payload.format == "auto" {
                        payload.format = contact_format_from_filename(&filename);
                    }
                }
            } else {
                let text = field.text().await.unwrap_or_default();
                match name.as_str() {
                    "csrf" => payload.csrf = text,
                    "format" => payload.format = text,
                    "data" if !text.trim().is_empty() && payload.data.trim().is_empty() => {
                        payload.data = text
                    }
                    _ => {}
                }
            }
        }
        Ok(payload)
    } else {
        let Form(form) = Form::<ContactImportForm>::from_request(req, state)
            .await
            .map_err(|e| error_page(StatusCode::BAD_REQUEST, "Invalid request", &e.to_string()))?;
        Ok(ContactImportPayload {
            csrf: form.csrf,
            format: form.format,
            data: form.data,
        })
    }
}

struct ContactImportResult {
    contacts: Vec<Contact>,
    skipped: i64,
}

fn parse_imported_contacts(data: &str, format: &str) -> ContactImportResult {
    let fmt = format.trim().to_lowercase();
    if fmt == "csv" {
        return parse_contacts_csv(data);
    }
    if fmt == "vcf" || fmt == "vcard" {
        return parse_contacts_vcard(data);
    }
    if data.to_ascii_uppercase().contains("BEGIN:VCARD") {
        parse_contacts_vcard(data)
    } else {
        parse_contacts_csv(data)
    }
}

fn contact_format_from_filename(filename: &str) -> String {
    let lower = filename.to_lowercase();
    if lower.ends_with(".csv") {
        "csv".to_string()
    } else if lower.ends_with(".vcf") || lower.ends_with(".vcard") {
        "vcf".to_string()
    } else {
        "auto".to_string()
    }
}

fn parse_contacts_csv(data: &str) -> ContactImportResult {
    let mut contacts = Vec::new();
    let mut skipped = 0_i64;
    let mut rows = data
        .lines()
        .map(str::trim_end)
        .filter(|line| !line.trim().is_empty());
    let Some(first) = rows.next() else {
        return ContactImportResult { contacts, skipped };
    };
    let first_fields = parse_csv_line(first);
    let lower: Vec<String> = first_fields.iter().map(|f| f.to_lowercase()).collect();
    let has_header = lower
        .iter()
        .any(|f| matches!(f.as_str(), "email" | "addr" | "address"));
    let header = if has_header {
        lower
    } else {
        vec![
            "name".to_string(),
            "email".to_string(),
            "phone".to_string(),
            "company".to_string(),
            "title".to_string(),
            "notes".to_string(),
        ]
    };
    if !has_header {
        match contact_from_csv_fields(&header, &first_fields) {
            Some(contact) => contacts.push(contact),
            None => skipped += 1,
        }
    }
    for line in rows {
        let fields = parse_csv_line(line);
        match contact_from_csv_fields(&header, &fields) {
            Some(contact) => contacts.push(contact),
            None => skipped += 1,
        }
    }
    ContactImportResult { contacts, skipped }
}

fn contact_from_csv_fields(header: &[String], fields: &[String]) -> Option<Contact> {
    let get = |names: &[&str]| -> String {
        for name in names {
            if let Some(idx) = header.iter().position(|h| h == name) {
                return fields.get(idx).cloned().unwrap_or_default();
            }
        }
        String::new()
    };
    let addr = get(&["email", "addr", "address"]).trim().to_lowercase();
    if !is_valid_recipient_addr(&addr) {
        return None;
    }
    Some(Contact {
        addr,
        name: get(&["name", "full name", "fn"]).trim().to_string(),
        phone: get(&["phone", "tel", "telephone"]).trim().to_string(),
        company: get(&["company", "org", "organization"]).trim().to_string(),
        title: get(&["title", "job title"]).trim().to_string(),
        notes: get(&["notes", "note"]).trim().to_string(),
        manual: true,
        seen_count: 0,
    })
}

fn parse_csv_line(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut field = String::new();
    let mut chars = line.chars().peekable();
    let mut in_quotes = false;
    while let Some(ch) = chars.next() {
        match ch {
            '"' if in_quotes && chars.peek() == Some(&'"') => {
                field.push('"');
                chars.next();
            }
            '"' => in_quotes = !in_quotes,
            ',' if !in_quotes => {
                out.push(field.trim().to_string());
                field.clear();
            }
            _ => field.push(ch),
        }
    }
    out.push(field.trim().to_string());
    out
}

fn parse_contacts_vcard(data: &str) -> ContactImportResult {
    let mut contacts = Vec::new();
    let mut skipped = 0_i64;
    let lines = unfold_vcard_lines(data);
    let mut current: HashMap<String, String> = HashMap::new();
    let mut in_card = false;
    for line in lines {
        let upper = line.to_ascii_uppercase();
        if upper == "BEGIN:VCARD" {
            current.clear();
            in_card = true;
            continue;
        }
        if upper == "END:VCARD" {
            if let Some(contact) = contact_from_vcard_map(&current) {
                contacts.push(contact);
            } else {
                skipped += 1;
            }
            in_card = false;
            continue;
        }
        if !in_card {
            continue;
        }
        let Some((raw_key, value)) = line.split_once(':') else {
            continue;
        };
        let key = raw_key
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_uppercase();
        if matches!(
            key.as_str(),
            "FN" | "N" | "EMAIL" | "TEL" | "ORG" | "TITLE" | "NOTE"
        ) && !current.contains_key(&key)
        {
            current.insert(key, vcard_unescape(value.trim()));
        }
    }
    ContactImportResult { contacts, skipped }
}

fn unfold_vcard_lines(data: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for raw in data.lines() {
        let line = raw.trim_end_matches('\r');
        if line.starts_with(' ') || line.starts_with('\t') {
            if let Some(last) = out.last_mut() {
                last.push_str(line.trim_start());
            }
        } else {
            out.push(line.to_string());
        }
    }
    out
}

fn contact_from_vcard_map(values: &HashMap<String, String>) -> Option<Contact> {
    let addr = values.get("EMAIL")?.trim().to_lowercase();
    if !is_valid_recipient_addr(&addr) {
        return None;
    }
    let name = values
        .get("FN")
        .cloned()
        .or_else(|| values.get("N").map(|n| vcard_n_to_name(n)))
        .unwrap_or_default();
    Some(Contact {
        addr,
        name: name.trim().to_string(),
        phone: values.get("TEL").cloned().unwrap_or_default(),
        company: values.get("ORG").cloned().unwrap_or_default(),
        title: values.get("TITLE").cloned().unwrap_or_default(),
        notes: values.get("NOTE").cloned().unwrap_or_default(),
        manual: true,
        seen_count: 0,
    })
}

fn vcard_n_to_name(n: &str) -> String {
    let parts: Vec<&str> = n.split(';').collect();
    let family = parts.first().copied().unwrap_or("");
    let given = parts.get(1).copied().unwrap_or("");
    format!("{given} {family}").trim().to_string()
}

fn vcard_unescape(value: &str) -> String {
    value
        .replace("\\n", "\n")
        .replace("\\N", "\n")
        .replace("\\,", ",")
        .replace("\\;", ";")
        .replace("\\\\", "\\")
}

fn merge_import_contact(existing: &Contact, imported: &Contact) -> Contact {
    let mut merged = existing.clone();
    if merged.name.trim().is_empty() && !imported.name.trim().is_empty() {
        merged.name = imported.name.clone();
    }
    if merged.phone.trim().is_empty() && !imported.phone.trim().is_empty() {
        merged.phone = imported.phone.clone();
    }
    if merged.company.trim().is_empty() && !imported.company.trim().is_empty() {
        merged.company = imported.company.clone();
    }
    if merged.title.trim().is_empty() && !imported.title.trim().is_empty() {
        merged.title = imported.title.clone();
    }
    if merged.notes.trim().is_empty() && !imported.notes.trim().is_empty() {
        merged.notes = imported.notes.clone();
    }
    merged.manual = true;
    merged
}

fn export_contacts_csv(contacts: &[Contact]) -> String {
    let mut out = String::from("name,email,phone,company,title,notes\n");
    for c in contacts {
        out.push_str(&format!(
            "{},{},{},{},{},{}\n",
            csv_escape(&c.name),
            csv_escape(&c.addr),
            csv_escape(&c.phone),
            csv_escape(&c.company),
            csv_escape(&c.title),
            csv_escape(&c.notes),
        ));
    }
    out
}

fn csv_escape(value: &str) -> String {
    if value.contains(',') || value.contains('"') || value.contains('\n') || value.contains('\r') {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

fn export_contacts_vcard(contacts: &[Contact]) -> String {
    let mut out = String::new();
    for c in contacts {
        out.push_str("BEGIN:VCARD\r\nVERSION:3.0\r\n");
        out.push_str(&format!(
            "FN:{}\r\nEMAIL;TYPE=INTERNET:{}\r\n",
            vcard_escape(if c.name.trim().is_empty() {
                &c.addr
            } else {
                &c.name
            }),
            vcard_escape(&c.addr)
        ));
        if !c.phone.trim().is_empty() {
            out.push_str(&format!("TEL:{}\r\n", vcard_escape(&c.phone)));
        }
        if !c.company.trim().is_empty() {
            out.push_str(&format!("ORG:{}\r\n", vcard_escape(&c.company)));
        }
        if !c.title.trim().is_empty() {
            out.push_str(&format!("TITLE:{}\r\n", vcard_escape(&c.title)));
        }
        if !c.notes.trim().is_empty() {
            out.push_str(&format!("NOTE:{}\r\n", vcard_escape(&c.notes)));
        }
        out.push_str("END:VCARD\r\n");
    }
    out
}

fn vcard_escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('\n', "\\n")
        .replace('\r', "")
        .replace(';', "\\;")
        .replace(',', "\\,")
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
            let cookie =
                format!("{CSRF_COOKIE}={token}; Path=/; Secure; SameSite=Lax; Max-Age=3600");
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
    [win, win - 1].iter().any(|&w| {
        ct_eq(
            sig.as_bytes(),
            sign_identity(key, &subject, &groups, w).as_bytes(),
        )
    })
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
    render_page_with_prefs(
        title,
        email_display,
        content,
        nav_active,
        PagePrefs::default(),
    )
}

fn render_page_with_prefs(
    title: &str,
    email_display: &str,
    content: &str,
    nav_active: &str,
    prefs: PagePrefs,
) -> String {
    render_shell(title, email_display, content, nav_active, prefs, "")
}

fn render_mail_page(title: &str, email_display: &str, content: &str, prefs: PagePrefs) -> String {
    render_shell(title, email_display, content, "inbox", prefs, " wrap--mail")
}

fn render_shell(
    title: &str,
    email_display: &str,
    content: &str,
    nav_active: &str,
    prefs: PagePrefs,
    wrap_mod: &str,
) -> String {
    SHELL
        .replace("{{STYLE}}", app_css())
        .replace("{{WRAP}}", wrap_mod)
        .replace("{{TITLE}}", &esc(title))
        .replace("{{THEME}}", &esc(prefs.theme))
        .replace("{{DENSITY}}", &esc(prefs.density))
        .replace("{{PANE}}", &esc(prefs.reading_pane))
        .replace("{{NAV}}", &nav_bar(nav_active))
        .replace("{{USERBOX}}", &userbox(email_display))
        .replace("{{CONTENT}}", content)
}

/// The app-bar navigation — the existing Inbox (`/`) and Compose (`/compose`) destinations as v2
/// `.appnav` links, marking `active` (`"inbox"`/`"compose"`) with `.is-active`.
fn nav_bar(active: &str) -> String {
    let link = |key: &str, href: &str, label: &str, icon: &str| {
        let cls = if key == active {
            "appnav is-active"
        } else {
            "appnav"
        };
        format!(r#"<a class="{cls}" href="{href}">{icon}{label}</a>"#)
    };
    format!(
        "{}{}{}",
        link("inbox", "/", "Inbox", ICO_INBOX),
        link("compose", "/compose", "Compose", ICO_COMPOSE),
        link("settings", "/settings", "Settings", ICO_SETTINGS),
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

fn from_display_parts(raw: &str) -> (String, String) {
    let raw = raw.trim();
    if let Some(lt) = raw.find('<') {
        let name = raw[..lt].trim().trim_matches('"').trim();
        if let Some(gt) = raw[lt..].find('>') {
            let addr = raw[lt + 1..lt + gt].trim();
            if name.is_empty() {
                return (addr.to_string(), String::new());
            }
            return (name.to_string(), addr.to_string());
        }
    }
    (raw.to_string(), String::new())
}

fn recips_short(to: &str) -> String {
    let recipients: Vec<&str> = to
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    let Some(first) = recipients.first() else {
        return "to undisclosed recipients".to_string();
    };
    let first = display_from(first);
    if recipients.len() > 1 {
        format!("to {first}, +{}", recipients.len() - 1)
    } else {
        format!("to {first}")
    }
}

fn avatar_hue(addr: &str) -> u8 {
    (addr.bytes().fold(0_u32, |sum, b| sum + b as u32) % 6) as u8
}

fn avatar_initial(name: &str, addr: &str) -> String {
    name.chars()
        .chain(addr.chars())
        .find(|ch| ch.is_ascii_alphanumeric())
        .map(|ch| ch.to_ascii_uppercase().to_string())
        .unwrap_or_else(|| "?".to_string())
}

fn clean_snippet(snippet: &str) -> String {
    let without_quotes = snippet
        .lines()
        .map(str::trim)
        .filter(|line| {
            !line.starts_with('>')
                && !(line.starts_with("On ") && line.contains("wrote:"))
                && !line.is_empty()
        })
        .collect::<Vec<_>>()
        .join(" ");
    let collapsed = without_quotes
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    collapsed.chars().take(120).collect()
}

fn msg_from_block(from_raw: &str, to_raw: &str, received_at: i64) -> String {
    let (name, addr) = from_display_parts(from_raw);
    let hue_key = if addr.is_empty() {
        name.as_str()
    } else {
        addr.as_str()
    };
    let addr_html = if addr.is_empty() {
        String::new()
    } else {
        format!(
            r#" <span class="msg-from__addr">&lt;{}&gt;</span>"#,
            esc(&addr)
        )
    };
    let date = fmt_date(received_at);
    format!(
        r#"<div class="msg-from">
    <span class="msg-avatar avatar--h{hue}" aria-hidden="true">{initial}</span>
    <div class="msg-from__who">
      <div class="msg-from__line"><span class="msg-from__name">{name}</span>{addr_html}</div>
      <details class="msg-recips"><summary class="msg-recips__summary">{recips}</summary>
        <div class="msg-meta"><b>From</b><span>{from}</span><b>To</b><span>{to}</span><b>Date</b><span>{date}</span></div>
      </details>
    </div>
    <span class="msg-from__date" title="{date}">{date}</span>
  </div>"#,
        hue = avatar_hue(hue_key),
        initial = esc(&avatar_initial(&name, &addr)),
        name = esc(&name),
        addr_html = addr_html,
        recips = esc(&recips_short(to_raw)),
        from = esc(from_raw),
        to = esc(to_raw),
    )
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

fn fmt_date_list(ts: i64) -> String {
    let Ok(dt) = OffsetDateTime::from_unix_timestamp(ts) else {
        return "—".to_string();
    };
    let now = OffsetDateTime::now_utc();
    if dt.date() == now.date() {
        return format!("{:02}:{:02}", dt.hour(), dt.minute());
    }
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    if dt.year() == now.year() {
        return format!("{} {}", MONTHS[dt.month() as usize - 1], dt.day());
    }
    format!("{:04}-{:02}-{:02}", dt.year(), dt.month() as u8, dt.day())
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
        admins.insert(
            HEADER_GROUPS,
            HeaderValue::from_static("dev, infra-admins ,x"),
        );
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
    fn display_preference_values_are_finite() {
        assert_eq!(effective_density("compact"), "compact");
        assert_eq!(effective_density("spacious"), DEFAULT_DENSITY);
        assert_eq!(effective_reading_pane("bottom"), "bottom");
        assert_eq!(effective_reading_pane("sidecar"), DEFAULT_READING_PANE);
        assert_eq!(effective_theme("dark"), "dark");
        assert_eq!(effective_theme("sepia"), DEFAULT_THEME);
        assert!(parse_display_choice("right", &READING_PANE_CHOICES, "reading pane").is_ok());
        assert!(parse_display_choice("invalid", &THEME_CHOICES, "theme").is_err());
    }

    #[tokio::test]
    async fn display_preferences_render_shell_and_pane_hooks() {
        use tower::ServiceExt;

        let state = crate::build_dev_state().await;
        state
            .store
            .set_display_preferences("w33d@w33d.xyz", "compact", "right", "dark")
            .await
            .unwrap();
        state
            .store
            .store_message(&Message {
                id: "msg-density-1".to_string(),
                mailbox: "w33d@w33d.xyz".to_string(),
                msg_from: "Alice <alice@example.com>".to_string(),
                msg_to: "w33d@w33d.xyz".to_string(),
                subject: "Density hooks".to_string(),
                raw_rfc822: "From: Alice <alice@example.com>\r\n\r\nHello".to_string(),
                body_text: "Hello".to_string(),
                body_html: String::new(),
                received_at: 1,
                seen: false,
                folder: "INBOX".to_string(),
                starred: false,
                snooze_until: 0,
                muted: false,
                thread_id: String::new(),
                message_id: String::new(),
            })
            .await
            .unwrap();

        let req = Request::builder()
            .uri("/")
            .header("x-auth-subject", "w33d")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = app(state.clone()).oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(bytes.to_vec()).unwrap();
        for needle in [
            r#"<html lang="en" data-theme="dark" data-density="compact" data-pane="right">"#,
            r#"class="mailbox-layout mailbox-layout--right" data-pane="right""#,
            r#"class="card mail-list-pane mail-list-pane--compact" data-density="compact""#,
            r#"class="maillist maillist--compact" data-density="compact""#,
            "mailrow-wrap--compact",
            "read-pane--empty",
        ] {
            assert!(html.contains(needle), "missing display hook {needle}");
        }

        let req = Request::builder()
            .uri("/settings")
            .header("x-auth-subject", "w33d")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = app(state).oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(bytes.to_vec()).unwrap();
        for needle in [
            r#"action="/settings/preferences""#,
            r#"<option value="compact" selected>Compact</option>"#,
            r#"<option value="right" selected>Right</option>"#,
            r#"<option value="dark" selected>Dark</option>"#,
        ] {
            assert!(html.contains(needle), "missing settings hook {needle}");
        }
    }

    #[tokio::test]
    async fn display_preferences_post_saves_values() {
        use tower::ServiceExt;

        let state = crate::build_dev_state().await;
        let req = Request::builder()
            .uri("/settings")
            .header("x-auth-subject", "w33d")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = app(state.clone()).oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let set_cookie = resp
            .headers()
            .get(header::SET_COOKIE)
            .and_then(|v| v.to_str().ok())
            .unwrap()
            .to_string();
        let cookie_pair = set_cookie.split(';').next().unwrap().to_string();
        let token = cookie_pair
            .strip_prefix("__Host-csrf=")
            .expect("csrf cookie prefix");

        let form = format!("csrf={token}&density=comfortable&reading_pane=bottom&theme=light");
        let req = Request::builder()
            .method("POST")
            .uri("/settings/preferences")
            .header("x-auth-subject", "w33d")
            .header(header::COOKIE, cookie_pair)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(axum::body::Body::from(form))
            .unwrap();
        let resp = app(state.clone()).oneshot(req).await.unwrap();
        assert!(
            resp.status().is_redirection(),
            "expected redirect, got {}",
            resp.status()
        );
        let settings = state.store.get_settings("w33d@w33d.xyz").await.unwrap();
        assert_eq!(settings.density, "comfortable");
        assert_eq!(settings.reading_pane, "bottom");
        assert_eq!(settings.theme, "light");
    }

    #[tokio::test]
    async fn compose_form_renders_rich_editor_hooks() {
        use tower::ServiceExt;

        let state = crate::build_dev_state().await;
        state
            .store
            .set_undo_send_window("w33d@w33d.xyz", 0)
            .await
            .unwrap();
        let req = Request::builder()
            .uri("/compose")
            .header("x-auth-subject", "w33d")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = app(state).oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(bytes.to_vec()).unwrap();
        for needle in [
            r#"name="body_html""#,
            r#"data-compose-toolbar"#,
            r#"contenteditable="true""#,
            r#"data-cmd="bold""#,
            r#"data-cmd="createLink""#,
            r#"<textarea id="body" name="body">"#,
            r#"class="send-split""#,
            r#"class="schedule-menu""#,
            r#"btn-schedule-send"#,
        ] {
            assert!(html.contains(needle), "missing compose hook {needle}");
        }
    }

    #[tokio::test]
    async fn rich_html_send_is_sanitised_and_enqueued_as_alternative() {
        use tower::ServiceExt;

        let state = crate::build_dev_state().await;
        state
            .store
            .set_undo_send_window("w33d@w33d.xyz", 0)
            .await
            .unwrap();
        let req = Request::builder()
            .uri("/compose")
            .header("x-auth-subject", "w33d")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = app(state.clone()).oneshot(req).await.unwrap();
        let set_cookie = resp
            .headers()
            .get(header::SET_COOKIE)
            .and_then(|v| v.to_str().ok())
            .unwrap()
            .to_string();
        let token = set_cookie
            .split(';')
            .next()
            .and_then(|kv| kv.split_once('='))
            .map(|(_, v)| v.to_string())
            .unwrap();
        let form = format!(
            "csrf={token}&action=send&to=friend%40example.com&subject=Rich&body=fallback&body_html=%3Cp%3EHello%20%3Cstrong%3Erich%3C%2Fstrong%3E%3Cscript%3Ealert(1)%3C%2Fscript%3E%3C%2Fp%3E"
        );
        let req = Request::builder()
            .method("POST")
            .uri("/send")
            .header("x-auth-subject", "w33d")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::COOKIE, format!("__Host-csrf={token}"))
            .body(axum::body::Body::from(form))
            .unwrap();
        let resp = app(state.clone()).oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);

        let due = state.store.due_outbound(now_secs() + 5, 10).await.unwrap();
        assert_eq!(due.len(), 1);
        assert!(due[0]
            .raw
            .contains("Content-Type: multipart/alternative; boundary="));
        assert!(due[0]
            .raw
            .contains("Content-Type: text/html; charset=utf-8"));
        assert!(due[0].raw.contains("<strong>rich</strong>"));
        assert!(!due[0].raw.contains("<script"));
        assert!(!due[0].raw.contains("alert(1)"));

        let parsed = crate::rfc822::parse(&due[0].raw);
        assert!(parsed.body_text.contains("Hello rich"));
        assert!(parsed.body_html.contains("<strong>rich</strong>"));
    }

    #[test]
    fn build_rfc822_has_signed_headers() {
        let raw = build_rfc822(
            "w33d@w33d.xyz",
            "x@y.com",
            "",
            "Hi",
            "Body line",
            "",
            "",
            "",
            "w33d.xyz",
            &[],
        );
        for h in [
            "From:",
            "To:",
            "Subject:",
            "Date:",
            "Message-ID:",
            "MIME-Version:",
            "Content-Type:",
        ] {
            assert!(raw.contains(h), "missing {h}");
        }
        assert!(raw.contains("\r\n\r\nBody line\r\n"));
        // No threading headers when none are supplied, and no Cc when unset.
        assert!(!raw.contains("In-Reply-To:"));
        assert!(!raw.contains("References:"));
        assert!(!raw.contains("Cc:"));
    }

    #[test]
    fn build_rfc822_includes_thread_headers() {
        let raw = build_rfc822(
            "w33d@w33d.xyz",
            "x@y.com",
            "",
            "Re: Hi",
            "Body",
            "",
            "<orig@ex.com>",
            "<root@ex.com> <orig@ex.com>",
            "w33d.xyz",
            &[],
        );
        assert!(raw.contains("In-Reply-To: <orig@ex.com>\r\n"));
        assert!(raw.contains("References: <root@ex.com> <orig@ex.com>\r\n"));
    }

    #[test]
    fn build_rfc822_includes_cc_when_present() {
        let raw = build_rfc822(
            "w33d@w33d.xyz",
            "x@y.com",
            "cc@z.com",
            "Hi",
            "Body",
            "",
            "",
            "",
            "w33d.xyz",
            &[],
        );
        assert!(raw.contains("Cc: cc@z.com\r\n"), "Cc header emitted");
    }

    #[test]
    fn compose_body_parts_sanitises_html_and_derives_plain_text() {
        let (plain, html) = compose_body_parts(
            "fallback",
            r#"<p>Hello <strong>rich</strong><script>alert(1)</script></p><span style="color:#336699;position:absolute">blue</span>"#,
        );
        assert!(plain.contains("Hello rich"));
        assert!(plain.contains("blue"));
        assert!(html.contains("<strong>rich</strong>"));
        assert!(html.contains(r#"<span style="color: #336699">blue</span>"#));
        assert!(!html.contains("<script"));
        assert!(!html.contains("position"));
        assert!(!html.contains("alert(1)"));
    }

    #[test]
    fn build_rfc822_emits_multipart_alternative_with_html() {
        let raw = build_rfc822(
            "w33d@w33d.xyz",
            "x@y.com",
            "",
            "Rich",
            "Hello rich",
            "<p>Hello <strong>rich</strong></p>",
            "",
            "",
            "w33d.xyz",
            &[],
        );
        assert!(raw.contains("Content-Type: multipart/alternative; boundary="));
        assert!(raw.contains("Content-Type: text/plain; charset=utf-8"));
        assert!(raw.contains("Content-Type: text/html; charset=utf-8"));
        assert!(raw.contains("<p>Hello <strong>rich</strong></p>"));

        let parsed = crate::rfc822::parse(&raw);
        assert!(parsed.body_text.contains("Hello rich"));
        assert!(parsed.body_html.contains("<strong>rich</strong>"));
    }

    #[test]
    fn build_rfc822_emits_multipart_mixed_with_attachment() {
        let att = Attachment {
            filename: "report.txt".to_string(),
            content_type: "text/plain".to_string(),
            data: b"hello attachment".to_vec(),
        };
        let raw = build_rfc822(
            "w33d@w33d.xyz",
            "x@y.com",
            "",
            "Files",
            "See attached",
            "",
            "",
            "",
            "w33d.xyz",
            &[att],
        );

        assert!(
            raw.contains("Content-Type: multipart/mixed; boundary="),
            "top-level is multipart/mixed"
        );
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
    fn build_rfc822_nests_alternative_inside_mixed_with_attachment() {
        let att = Attachment {
            filename: "report.txt".to_string(),
            content_type: "text/plain".to_string(),
            data: b"hello attachment".to_vec(),
        };
        let raw = build_rfc822(
            "w33d@w33d.xyz",
            "x@y.com",
            "",
            "Rich files",
            "See attached",
            "<p>See <strong>attached</strong></p>",
            "",
            "",
            "w33d.xyz",
            &[att],
        );

        assert!(raw.contains("Content-Type: multipart/mixed; boundary="));
        assert!(raw.contains("Content-Type: multipart/alternative; boundary="));
        assert!(raw.contains("Content-Type: text/html; charset=utf-8"));

        let parsed = crate::rfc822::parse(&raw);
        assert!(parsed.body_text.contains("See attached"));
        assert!(parsed.body_html.contains("<strong>attached</strong>"));
        let metas = crate::rfc822::list_attachments(&raw);
        assert_eq!(metas.len(), 1);
        assert_eq!(metas[0].filename, "report.txt");
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
            snooze_until: 0,
            muted: false,
            thread_id: String::new(),
            message_id: String::new(),
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
        assert_eq!(canonical_folder(Some("spam")), "Spam");
        assert_eq!(canonical_folder(Some("snoozed")), "Snoozed");
        assert_eq!(canonical_folder(Some("scheduled")), "Scheduled");
        assert_eq!(canonical_folder(Some("bogus")), "INBOX");
        assert_eq!(canonical_folder(None), "INBOX");
    }

    #[test]
    fn real_folder_accepts_only_real_folders() {
        assert_eq!(real_folder("sent"), Some("Sent"));
        assert_eq!(real_folder("spam"), Some("Spam"));
        assert_eq!(real_folder(" Trash "), Some("Trash"));
        assert_eq!(
            real_folder("Starred"),
            None,
            "the virtual view is not a folder"
        );
        assert_eq!(
            real_folder("Snoozed"),
            None,
            "the virtual view is not a folder"
        );
        assert_eq!(
            real_folder("Scheduled"),
            None,
            "the scheduled queue view is not a folder"
        );
        assert_eq!(real_folder("bogus"), None);
    }

    #[test]
    fn folder_class_exposes_spam_hook() {
        assert_eq!(folder_class("Spam"), "folder-spam");
        assert_eq!(folder_class("Snoozed"), "folder-snoozed");
        assert_eq!(folder_class("Scheduled"), "folder-scheduled");
        assert_eq!(folder_class("INBOX"), "folder-inbox");
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
        assert_eq!(
            parse_cursor(Some("100_m_abc")),
            Some((100, "m_abc".to_string())),
            "id keeps its own underscores"
        );
        assert_eq!(parse_cursor(Some("junk")), None);
        assert_eq!(parse_cursor(Some("notanum_m1")), None);
        assert_eq!(parse_cursor(None), None);
    }

    #[test]
    fn advanced_search_query_assembles_supported_operators() {
        let q = AdvancedSearchQuery {
            from: "Alice Example".to_string(),
            to: "bob@example.com".to_string(),
            subject: "Q3".to_string(),
            has_words: "budget review".to_string(),
            doesnt_have: "draft".to_string(),
            size_cmp: "larger".to_string(),
            size: "10".to_string(),
            size_unit: "m".to_string(),
            after: "2026-07-01".to_string(),
            before: "2026-07-31".to_string(),
            folder: "Archive".to_string(),
            has_attachment: Some("on".to_string()),
            mode: "search".to_string(),
        };

        assert_eq!(
            build_advanced_search_query(&q).as_deref(),
            Some(
                r#"from:"Alice Example" to:bob@example.com subject:Q3 "budget review" -draft larger:10M after:2026-07-01 before:2026-07-31 in:Archive has:attachment"#
            )
        );
    }

    #[test]
    fn advanced_search_query_ignores_invalid_values() {
        let q = AdvancedSearchQuery {
            size_cmp: "larger".to_string(),
            size: "many".to_string(),
            after: "not-a-date".to_string(),
            before: "2026-99-99".to_string(),
            folder: "Starred".to_string(),
            ..Default::default()
        };

        assert!(q.has_input());
        assert_eq!(build_advanced_search_query(&q), None);
    }

    #[test]
    fn rule_prefill_from_search_uses_first_supported_positive_predicate() {
        let prefill =
            rule_prefill_from_search("-from:blocked has:attachment subject:\"Quarterly Report\"")
                .expect("subject predicate can prefill a delivery rule");

        assert_eq!(prefill.field, "subject");
        assert_eq!(prefill.op, "contains");
        assert_eq!(prefill.needle, "Quarterly Report");
        assert!(rule_prefill_from_search("has:attachment larger:10M").is_none());
    }

    #[test]
    fn next_page_link_only_on_full_pages() {
        let row = |id: &str, ts: i64| crate::model::MessageSummary {
            id: id.to_string(),
            msg_from: String::new(),
            subject: String::new(),
            snippet: String::new(),
            has_attachment: false,
            received_at: ts,
            seen: false,
            starred: false,
            snooze_until: 0,
            muted: false,
            folder: "INBOX".to_string(),
        };
        // Short page (or empty) -> nothing older -> no link.
        assert_eq!(next_page_link(&[], 2, "/?folder=Sent&limit=2"), "");
        assert_eq!(
            next_page_link(&[row("m_1", 9)], 2, "/?folder=Sent&limit=2"),
            ""
        );
        // Full page -> link carrying the last row's (received_at, id) cursor.
        let link = next_page_link(&[row("m_2", 9), row("m_1", 8)], 2, "/?folder=Sent&limit=2");
        assert!(
            link.contains("/?folder=Sent&limit=2&before=8_m_1"),
            "cursor appended: {link}"
        );
    }

    #[test]
    fn extract_addr_handles_angle_and_bare() {
        assert_eq!(extract_addr("no-reply@w33d.xyz"), "no-reply@w33d.xyz");
        assert_eq!(
            extract_addr("HOLDFAST <no-reply@w33d.xyz>"),
            "no-reply@w33d.xyz"
        );
        assert_eq!(extract_addr("  bare@x.com  "), "bare@x.com");
    }

    #[test]
    fn parse_until_roundtrips_and_rejects_junk() {
        assert_eq!(parse_until(""), Some(0), "empty = no expiry");
        assert_eq!(parse_until("  "), Some(0));
        let ts = parse_until("2026-07-15").expect("valid date");
        assert!(ts > 0);
        assert_eq!(
            fmt_until(ts),
            "2026-07-15",
            "round-trips through the date input"
        );
        assert_eq!(fmt_until(0), "");
        assert_eq!(parse_until("2026-13-01"), None, "no month 13");
        assert_eq!(parse_until("soon"), None);
        assert_eq!(parse_until("2026-07-15-99"), None);
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
