
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
