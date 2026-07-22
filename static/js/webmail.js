
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
  function localDateTime(epoch) {
    var date = new Date(epoch * 1000);
    if (!Number.isFinite(date.getTime())) return '';
    return new Date(date.getTime() - date.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
  }
  function syncLocalEpoch(local, hidden) {
    if (!local || !hidden) return true;
    local.setCustomValidity('');
    if (!local.value) {
      hidden.value = '';
      return true;
    }
    var original = local.getAttribute('data-original-local') || '';
    if (original && local.value === original && hidden.value) return true;
    var millis = Date.parse(local.value);
    var epoch = Number.isFinite(millis) ? Math.floor(millis / 1000) : 0;
    if (!epoch || localDateTime(epoch) !== local.value) {
      hidden.value = '';
      local.setCustomValidity('Choose a valid local date and time.');
      return false;
    }
    var ambiguous = [-7200000, -5400000, -3600000, -1800000, 1800000, 3600000, 5400000, 7200000]
      .some(function (shift) { return localDateTime(Math.floor((millis + shift) / 1000)) === local.value; });
    if (ambiguous) {
      hidden.value = '';
      local.setCustomValidity('This local time occurs twice. Choose a time outside the daylight-saving change.');
      return false;
    }
    hidden.value = String(epoch);
    return true;
  }
  function snoozeFields(root) {
    var local = root.querySelector('[data-snooze-local]');
    var hidden = root.querySelector('[name=snooze_custom]');
    var valid = syncLocalEpoch(local, hidden);
    return {
      snooze_until: field(root, 'snooze_until'),
      snooze_custom: field(root, 'snooze_custom'),
      invalid: !valid
    };
  }
  function syncSchedule(root) {
    var local = root.querySelector('[data-schedule-local]');
    var hidden = root.querySelector('[name=schedule_custom]');
    return syncLocalEpoch(local, hidden);
  }
  document.querySelectorAll('[data-snooze-local]').forEach(function (local) {
    var root = local.closest('form') || document;
    var menu = root.querySelector('[name=snooze_until]');
    var hidden = root.querySelector('[name=snooze_custom]');
    var customOption = root.querySelector('[data-snooze-custom-option]');
    var minimum = parseInt(local.getAttribute('data-min-epoch') || '0', 10);
    local.hidden = false;
    if (customOption) customOption.hidden = false;
    if (minimum > 0) local.min = localDateTime(minimum);
    local.addEventListener('input', function () {
      if (menu) menu.value = '';
      local.setCustomValidity('');
    });
    if (menu) menu.addEventListener('change', function () {
      local.value = '';
      local.setCustomValidity('');
      if (hidden) hidden.value = '';
    });
  });
  document.querySelectorAll('[data-schedule-local]').forEach(function (local) {
    var root = local.closest('form') || document;
    var hidden = root.querySelector('[name=schedule_custom]');
    var menu = root.querySelector('[name=schedule_at]');
    var customOption = root.querySelector('[data-schedule-custom-option]');
    var minimum = parseInt(local.getAttribute('data-min-epoch') || '0', 10);
    local.hidden = false;
    if (customOption) customOption.hidden = false;
    if (minimum > 0) local.min = localDateTime(minimum);
    if (hidden && hidden.value) {
      local.value = localDateTime(parseInt(hidden.value, 10));
      local.setAttribute('data-original-local', local.value);
    }
    local.addEventListener('input', function () {
      if (menu) menu.value = '';
      local.setCustomValidity('');
    });
    if (menu) menu.addEventListener('change', function () {
      if (menu.value) {
        local.value = '';
        local.removeAttribute('data-original-local');
        local.setCustomValidity('');
        if (hidden) hidden.value = '';
      }
    });
  });
  document.addEventListener('submit', function (e) {
    var action = e.submitter ? e.submitter.value : '';
    var submitsSchedule = action === 'schedule' || action === 'reschedule';
    if (submitsSchedule && e.target && e.target.querySelector && e.target.querySelector('[data-schedule-local]')) {
      if (!syncSchedule(e.target)) {
        e.preventDefault();
        var local = e.target.querySelector('[data-schedule-local]');
        if (local) local.reportValidity();
      }
    }
  }, true);
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
        if (op === 'snooze' && snooze.invalid) {
          e.preventDefault();
          var invalidSnooze = form.querySelector('[data-snooze-local]');
          if (invalidSnooze) invalidSnooze.reportValidity();
          return;
        }
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
        if (op === 'snooze' && snooze.invalid) {
          var invalidBulkSnooze = bar.querySelector('[data-snooze-local]');
          if (invalidBulkSnooze) invalidBulkSnooze.reportValidity();
          return;
        }
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
