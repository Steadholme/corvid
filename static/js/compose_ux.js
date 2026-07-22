
(function () {
  var toast = window.__corvidToast || function () {};
  var form = document.querySelector('form[action="/send"]'); if (!form) return;

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
  var scheduleLocal = form.querySelector('[data-schedule-local]');
  var scheduleHidden = form.querySelector('[name="schedule_custom"]');
  var scheduleMenu = form.querySelector('[name="schedule_at"]');
  var scheduleCustomOption = form.querySelector('[data-schedule-custom-option]');
  if (scheduleLocal) {
    var scheduleMinimum = parseInt(scheduleLocal.getAttribute('data-min-epoch') || '0', 10);
    scheduleLocal.hidden = false;
    if (scheduleCustomOption) scheduleCustomOption.hidden = false;
    if (scheduleMinimum > 0) scheduleLocal.min = localDateTime(scheduleMinimum);
    if (scheduleHidden && scheduleHidden.value) {
      scheduleLocal.value = localDateTime(parseInt(scheduleHidden.value, 10));
      scheduleLocal.setAttribute('data-original-local', scheduleLocal.value);
    }
  }
  if (scheduleMenu && scheduleLocal) {
    scheduleLocal.addEventListener('input', function () {
      scheduleMenu.value = '';
      scheduleLocal.setCustomValidity('');
    });
    scheduleMenu.addEventListener('change', function () {
      if (scheduleMenu.value) {
        scheduleLocal.value = '';
        scheduleLocal.removeAttribute('data-original-local');
        scheduleLocal.setCustomValidity('');
        if (scheduleHidden) scheduleHidden.value = '';
      }
    });
  }
  function syncSchedule() {
    return syncLocalEpoch(scheduleLocal, scheduleHidden);
  }

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
    if (action === 'schedule') {
      if (!syncSchedule()) {
        e.preventDefault();
        if (scheduleLocal) scheduleLocal.reportValidity();
        return;
      }
      if ((!scheduleMenu || !scheduleMenu.value) && (!scheduleHidden || !scheduleHidden.value)) {
        e.preventDefault();
        toast('Choose a schedule time', 'err');
        if (scheduleLocal) scheduleLocal.focus();
        return;
      }
    }
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
