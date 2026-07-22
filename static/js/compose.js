
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
