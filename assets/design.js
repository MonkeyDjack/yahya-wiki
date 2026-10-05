/* YAHYA Wiki — слой оформления (аудит 2026-10).
 * 1) вместо эмодзи/символов-пиктограмм — inline-SVG в стиле Lucide (бренд: «эмодзи — никогда»);
 * 2) шторка снизу для оборота карточки на ≤768px;
 * 3) мелочи: Enter/Space на карточке, «Принципы» свёрнуты по умолчанию, фото на тёмном фоне.
 * Не трогает данные и логику: работает поверх готового DOM (MutationObserver). */
(function () {
  'use strict';

  /* ── Иконки (пути Lucide, 24×24, stroke) ── */
  var P = {
    gift: '<rect x="3" y="8" width="18" height="4" rx="1"/><path d="M12 8v13"/><path d="M19 12v7a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2v-7"/><path d="M7.5 8a2.5 2.5 0 0 1 0-5A4.8 8 0 0 1 12 8a4.8 8 0 0 1 4.5-5 2.5 2.5 0 0 1 0 5"/>',
    target: '<circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/>',
    cap: '<path d="M21.42 10.922a1 1 0 0 0-.019-1.838L12.83 5.18a2 2 0 0 0-1.66 0L2.6 9.08a1 1 0 0 0 0 1.832l8.57 3.908a2 2 0 0 0 1.66 0z"/><path d="M22 10v6"/><path d="M6 12.5V16a6 3 0 0 0 12 0v-3.5"/>',
    book: '<path d="M12 7v14"/><path d="M3 18a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1h5a4 4 0 0 1 4 4 4 4 0 0 1 4-4h5a1 1 0 0 1 1 1v13a1 1 0 0 1-1 1h-6a3 3 0 0 0-3 3 3 3 0 0 0-3-3z"/>',
    scroll: '<path d="M15 12h-5"/><path d="M15 8h-5"/><path d="M19 17V5a2 2 0 0 0-2-2H4"/><path d="M8 21h12a2 2 0 0 0 2-2v-1a1 1 0 0 0-1-1H11a1 1 0 0 0-1 1v1a2 2 0 1 1-4 0V5a2 2 0 1 0-4 0v2a1 1 0 0 0 1 1h3"/>',
    warehouse: '<path d="M22 8.35V20a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V8.35A2 2 0 0 1 3.26 6.5l8-3.2a2 2 0 0 1 1.48 0l8 3.2A2 2 0 0 1 22 8.35Z"/><path d="M6 18h12"/><path d="M6 14h12"/><rect x="6" y="10" width="12" height="12"/>',
    user: '<path d="M19 21v-2a4 4 0 0 0-4-4H9a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/>',
    users: '<path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/>',
    coffee: '<path d="M10 2v2"/><path d="M14 2v2"/><path d="M16 8a1 1 0 0 1 1 1v8a4 4 0 0 1-4 4H7a4 4 0 0 1-4-4V9a1 1 0 0 1 1-1h14a4 4 0 1 1 0 8h-1"/><path d="M6 2v2"/>',
    bag: '<path d="M6 2 3 6v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2V6l-3-4Z"/><path d="M3 6h18"/><path d="M16 10a4 4 0 0 1-8 0"/>',
    grid: '<rect width="7" height="7" x="3" y="3" rx="1"/><rect width="7" height="7" x="14" y="3" rx="1"/><rect width="7" height="7" x="14" y="14" rx="1"/><rect width="7" height="7" x="3" y="14" rx="1"/>',
    utensils: '<path d="M3 2v7c0 1.1.9 2 2 2h4a2 2 0 0 0 2-2V2"/><path d="M7 2v20"/><path d="M21 15V2a5 5 0 0 0-5 5v6c0 1.1.9 2 2 2h3Zm0 0v7"/>',
    sunrise: '<path d="M12 2v8"/><path d="m4.93 10.93 1.41 1.41"/><path d="M2 18h2"/><path d="M20 18h2"/><path d="m19.07 10.93-1.41 1.41"/><path d="M22 22H2"/><path d="m8 6 4-4 4 4"/><path d="M16 18a4 4 0 0 0-8 0"/>',
    check: '<path d="M20 6 9 17l-5-5"/>',
    x: '<path d="M18 6 6 18"/><path d="m6 6 12 12"/>',
    pencil: '<path d="M21.174 6.812a1 1 0 0 0-3.986-3.987L3.842 16.174a2 2 0 0 0-.5.83l-1.321 4.352a.5.5 0 0 0 .623.622l4.353-1.32a2 2 0 0 0 .83-.497z"/><path d="m15 5 4 4"/>',
    rotate: '<path d="M21 12a9 9 0 1 1-9-9c2.52 0 4.93 1 6.74 2.74L21 8"/><path d="M21 3v5h-5"/>',
    settings: '<circle cx="12" cy="12" r="3"/><path d="M12 2v3"/><path d="M12 19v3"/><path d="M2 12h3"/><path d="M19 12h3"/><path d="m4.9 4.9 2.1 2.1"/><path d="m17 17 2.1 2.1"/><path d="M4.9 19.1 7 17"/><path d="m17 7 2.1-2.1"/>',
    alert: '<path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3"/><path d="M12 9v4"/><path d="M12 17h.01"/>',
    star: '<path d="M11.525 2.295a.53.53 0 0 1 .95 0l2.31 4.679a2.123 2.123 0 0 0 1.595 1.16l5.166.756a.53.53 0 0 1 .294.904l-3.736 3.638a2.123 2.123 0 0 0-.611 1.878l.882 5.14a.53.53 0 0 1-.771.56l-4.618-2.428a2.122 2.122 0 0 0-1.973 0L6.396 21.01a.53.53 0 0 1-.77-.56l.881-5.139a2.122 2.122 0 0 0-.611-1.879L2.16 9.795a.53.53 0 0 1 .294-.906l5.165-.755a2.122 2.122 0 0 0 1.597-1.16z"/>',
    key: '<path d="M2.586 17.414A2 2 0 0 0 2 18.828V21a1 1 0 0 0 1 1h3a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h1a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h.172a2 2 0 0 0 1.414-.586l.814-.814a6.5 6.5 0 1 0-4-4z"/><circle cx="16.5" cy="7.5" r=".5" fill="currentColor"/>',
    lock: '<rect width="18" height="11" x="3" y="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>',
    clip: '<rect width="8" height="4" x="8" y="2" rx="1"/><path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2"/><path d="M12 11h4"/><path d="M12 16h4"/><path d="M8 11h.01"/><path d="M8 16h.01"/>',
    search: '<circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/>',
    hourglass: '<path d="M5 22h14"/><path d="M5 2h14"/><path d="M17 22v-4.172a2 2 0 0 0-.586-1.414L12 12l-4.414 4.414A2 2 0 0 0 7 17.828V22"/><path d="M7 2v4.172a2 2 0 0 0 .586 1.414L12 12l4.414-4.414A2 2 0 0 0 17 6.172V2"/>',
    trash: '<path d="M3 6h18"/><path d="M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6"/><path d="M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2"/><path d="M10 11v6"/><path d="M14 11v6"/>',
    cok: '<circle cx="12" cy="12" r="10"/><path d="m9 12 2 2 4-4"/>',
    cx: '<circle cx="12" cy="12" r="10"/><path d="m15 9-6 6"/><path d="m9 9 6 6"/>',
    arrowup: '<path d="M7 7h10v10"/><path d="M7 17 17 7"/>',
    sparkles: '<path d="M9.937 15.5A2 2 0 0 0 8.5 14.063l-6.135-1.582a.5.5 0 0 1 0-.962L8.5 9.936A2 2 0 0 0 9.937 8.5l1.582-6.135a.5.5 0 0 1 .963 0L14.063 8.5A2 2 0 0 0 15.5 9.937l6.135 1.581a.5.5 0 0 1 0 .964L15.5 14.063a2 2 0 0 0-1.437 1.437l-1.582 6.135a.5.5 0 0 1-.963 0z"/>',
    help: '<circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/><path d="M12 17h.01"/>',
    cash: '<rect width="20" height="12" x="2" y="6" rx="2"/><circle cx="12" cy="12" r="2"/><path d="M6 12h.01M18 12h.01"/>',
    receipt: '<path d="M4 2v20l2-1 2 1 2-1 2 1 2-1 2 1 2-1 2 1V2l-2 1-2-1-2 1-2-1-2 1-2-1-2 1Z"/><path d="M16 8h-6a2 2 0 1 0 0 4h4a2 2 0 1 1 0 4H8"/><path d="M12 17.5v-11"/>',
    calc: '<rect width="16" height="20" x="4" y="2" rx="2"/><line x1="8" x2="16" y1="6" y2="6"/><line x1="16" x2="16" y1="14" y2="18"/><path d="M16 10h.01M12 10h.01M8 10h.01M12 14h.01M8 14h.01M12 18h.01M8 18h.01"/>',
    phone: '<rect width="14" height="20" x="5" y="2" rx="2"/><path d="M12 18h.01"/>',
    camera: '<path d="M14.5 4h-5L7 7H4a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2V9a2 2 0 0 0-2-2h-3l-2.5-3z"/><circle cx="12" cy="13" r="3"/>',
    ruler: '<path d="M21.3 15.3a2.4 2.4 0 0 1 0 3.4l-2.6 2.6a2.4 2.4 0 0 1-3.4 0L2.7 8.7a2.41 2.41 0 0 1 0-3.4l2.6-2.6a2.41 2.41 0 0 1 3.4 0Z"/><path d="m14.5 12.5 2-2"/><path d="m11.5 9.5 2-2"/><path d="m8.5 6.5 2-2"/><path d="m17.5 15.5 2-2"/>',
    home: '<path d="M15 21v-8a1 1 0 0 0-1-1h-4a1 1 0 0 0-1 1v8"/><path d="M3 10a2 2 0 0 1 .709-1.528l7-5.999a2 2 0 0 1 2.582 0l7 5.999A2 2 0 0 1 21 10v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>',
    building: '<path d="M6 22V4a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v18Z"/><path d="M6 12H4a2 2 0 0 0-2 2v6a2 2 0 0 0 2 2h2"/><path d="M18 9h2a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2h-2"/><path d="M10 6h4"/><path d="M10 10h4"/><path d="M10 14h4"/><path d="M10 18h4"/>',
    heart: '<path d="M19 14c1.49-1.46 3-3.21 3-5.5A5.5 5.5 0 0 0 16.5 3c-1.76 0-3 .5-4.5 2-1.5-1.5-2.74-2-4.5-2A5.5 5.5 0 0 0 2 8.5c0 2.3 1.5 4.05 3 5.5l7 7Z"/>',
    briefcase: '<path d="M16 20V4a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v16"/><rect width="20" height="14" x="2" y="6" rx="2"/>',
    zap: '<path d="M4 14a1 1 0 0 1-.78-1.63l9.9-10.2a.5.5 0 0 1 .86.46l-1.92 6.02A1 1 0 0 0 13 10h7a1 1 0 0 1 .78 1.63l-9.9 10.2a.5.5 0 0 1-.86-.46l1.92-6.02A1 1 0 0 0 11 14z"/>',
    cake: '<path d="M20 21v-8a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v8"/><path d="M4 16s.5-1 2-1 2.5 2 4 2 2.5-2 4-2 2.5 2 4 2 2-1 2-1"/><path d="M2 21h20"/><path d="M7 8v3"/><path d="M12 8v3"/><path d="M17 8v3"/><path d="M7 4h.01"/><path d="M12 4h.01"/><path d="M17 4h.01"/>',
    cup: '<path d="m6 8 1.75 12.28a2 2 0 0 0 2 1.72h4.54a2 2 0 0 0 2-1.72L18 8"/><path d="M5 8h14"/><path d="M7 15a6.47 6.47 0 0 1 5 0 6.47 6.47 0 0 0 5 0"/><path d="m12 8 1-6h2"/>',
    plus: '<path d="M5 12h14"/><path d="M12 5v14"/>',
    printer: '<path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"/><path d="M6 9V3a1 1 0 0 1 1-1h10a1 1 0 0 1 1 1v6"/><rect x="6" y="14" width="12" height="8" rx="1"/>'
  };

  /* символ → имя иконки (несопоставленные эмодзи просто убираются) */
  var MAP = {
    '🍫': 'gift', '🎁': 'gift', '🎯': 'target', '🎓': 'cap',
    '📖': 'book', '📚': 'book', '📜': 'scroll', '📦': 'warehouse',
    '👤': 'user', '👩': 'user', '👨': 'user', '👶': 'user', '👴': 'user', '👋': 'user',
    '👥': 'users', '👭': 'users', '💑': 'users', '👨‍👩‍👧': 'users',
    '☕': 'coffee', '🍵': 'coffee', '🛍': 'bag', '🧩': 'grid',
    '🍽': 'utensils', '🌅': 'sunrise', '🌄': 'sunrise', '☀': 'sunrise', '🥐': 'sunrise',
    '✓': 'check', '✔': 'check', '✗': 'x', '✘': 'x', '✖': 'x',
    '✎': 'pencil', '✏': 'pencil', '📝': 'scroll',
    '↻': 'rotate', '🔄': 'rotate', '🎲': 'rotate',
    '⚙': 'settings', '⚠': 'alert', '★': 'star', '⭐': 'star', '✦': 'star', '👑': 'star', '🎫': 'star',
    '🏆': 'star', '🇰🇬': 'star',
    '🔑': 'key', '🔒': 'lock', '📋': 'clip', '🔍': 'search',
    '⏳': 'hourglass', '🗑': 'trash',
    '✅': 'cok', '❌': 'cx', '🚀': 'arrowup', '✈': 'arrowup',
    '🎉': 'sparkles', '🎈': 'sparkles', '💎': 'sparkles', '🍿': 'sparkles',
    '🤔': 'help',
    '💰': 'cash', '🧾': 'receipt', '🧮': 'calc', '📲': 'phone', '📷': 'camera',
    '📏': 'ruler', '🏠': 'home', '🏢': 'building', '🏬': 'building', '🏫': 'building',
    '💘': 'heart', '💼': 'briefcase', '👔': 'briefcase', '⚡': 'zap',
    '🎂': 'cake', '🥤': 'cup', '➕': 'plus', '💾': 'check',
    '⎓': 'printer', '⎙': 'printer'
  };

  var keys = Object.keys(MAP).sort(function (a, b) { return b.length - a.length; });
  var esc = function (s) { return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); };
  // 1) известные символы (+ VS16), 2) прочие эмодзи — убираем
  var RE = new RegExp('(' + keys.map(esc).join('|') + ')[\\uFE0E\\uFE0F]?|[\\uD83C-\\uD83E][\\uDC00-\\uDFFF](?:\\u200D[\\uD83C-\\uD83E][\\uDC00-\\uDFFF])*[\\uFE0E\\uFE0F]?|[\\u2600-\\u27BF][\\uFE0E\\uFE0F]?|[\\u23E9-\\u23FF]|[\\u2B50\\u2B55]', 'g');
  var QUICK = /[←-⇿⌀-⏿☀-➿⭐⭕\uD83C-\uD83E]/;

  function svg(name) {
    return '<svg class="ico" viewBox="0 0 24 24" aria-hidden="true" focusable="false">' + P[name] + '</svg>';
  }
  window.yahyaIcon = svg;

  var SKIP = { SCRIPT: 1, STYLE: 1, TEXTAREA: 1, INPUT: 1, TITLE: 1, SVG: 1, NOSCRIPT: 1, IFRAME: 1, CODE: 1 };
  function skippable(node) {
    for (var n = node.parentNode; n && n.nodeType === 1; n = n.parentNode) {
      if (SKIP[n.nodeName.toUpperCase()]) return true;
      if (n.isContentEditable) return true;
    }
    return false;
  }

  function convertText(node) {
    var s = node.nodeValue;
    if (!s || !QUICK.test(s)) return;
    var parent = node.parentNode;
    if (!parent || skippable(node)) return;
    var inOption = parent.nodeName === 'OPTION';
    var parts = [], last = 0, m, changed = false, hasIcon = false;
    RE.lastIndex = 0;
    while ((m = RE.exec(s))) {
      var name = MAP[m[1] || ''] || MAP[m[0].replace(/[︎️]$/, '')] || '';
      if (m.index > last) parts.push(s.slice(last, m.index));
      if (name && !inOption) { parts.push({ icon: name }); hasIcon = true; }
      last = m.index + m[0].length;
      changed = true;
    }
    if (!changed) return;
    if (last < s.length) parts.push(s.slice(last));
    if (!hasIcon) {                       // только декоративные эмодзи без аналога: убираем
      var txt = parts.join('');
      node.nodeValue = (inOption || !node.previousSibling) ? txt.replace(/^\s+(?=\S)/, '') : txt;
      return;
    }
    var frag = document.createDocumentFragment();
    parts.forEach(function (p) {
      if (typeof p === 'string') frag.appendChild(document.createTextNode(p));
      else { var t = document.createElement('template'); t.innerHTML = svg(p.icon); frag.appendChild(t.content); }
    });
    parent.replaceChild(frag, node);
  }

  function walk(root) {
    if (!root) return;
    if (root.nodeType === 3) { convertText(root); return; }
    if (root.nodeType !== 1 || SKIP[root.nodeName.toUpperCase()]) return;
    var w = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, null), n, list = [];
    while ((n = w.nextNode())) { if (QUICK.test(n.nodeValue)) list.push(n); }
    list.forEach(convertText);
  }

  var pending = new Set(), scheduled = false;
  function flush() {
    scheduled = false;
    var items = Array.from(pending); pending.clear();
    items.forEach(function (n) { if (n.isConnected) walk(n); });
  }
  function queue(n) {
    pending.add(n);
    if (!scheduled) { scheduled = true; (window.requestAnimationFrame || setTimeout)(flush); }
  }

  /* ── Шторка (оборот карточки на мобильном) ── */
  var sheetEl = null, lastFocus = null;
  function buildSheet() {
    var ov = document.createElement('div');
    ov.className = 'sheet-overlay';
    ov.innerHTML = '<div class="sheet" role="dialog" aria-modal="true" aria-labelledby="sheetTitle">' +
      '<div class="sheet-grab" aria-hidden="true"></div>' +
      '<div class="sheet-head"><div style="flex:1"><div class="sheet-title" id="sheetTitle"></div><div class="sheet-sub"></div></div>' +
      '<button class="sheet-close" type="button" aria-label="Закрыть">' + svg('x') + '</button></div>' +
      '<div class="sheet-body"></div></div>';
    document.body.appendChild(ov);
    ov.addEventListener('click', function (e) { if (e.target === ov) closeSheet(); });
    ov.querySelector('.sheet-close').addEventListener('click', closeSheet);
    // свайп вниз: за «ручку» и шапку; из тела — только когда оно прокручено в самый верх
    var sheet = ov.querySelector('.sheet'), body = ov.querySelector('.sheet-body');
    var y0 = null, dy = 0, fromBody = false;
    function start(e) { y0 = e.touches[0].clientY; dy = 0; fromBody = !!e.target.closest('.sheet-body'); }
    function move(e) {
      if (y0 === null) return;
      var d = e.touches[0].clientY - y0;
      if (d <= 0 || (fromBody && body.scrollTop > 0)) return;
      dy = d; sheet.classList.add('dragging');
      sheet.style.transform = 'translateY(' + d + 'px)';
      if (e.cancelable) e.preventDefault();
    }
    function end() {
      if (y0 === null) return;
      sheet.classList.remove('dragging'); sheet.style.transform = '';
      var close = dy > 90; y0 = null; dy = 0;
      if (close) closeSheet();
    }
    sheet.addEventListener('touchstart', start, { passive: true });
    sheet.addEventListener('touchmove', move, { passive: false });
    sheet.addEventListener('touchend', end);
    sheet.addEventListener('touchcancel', end);
    return ov;
  }
  window.openCardSheet = function (id) {
    var w = document.getElementById('cw-' + id);
    var back = w && w.querySelector('.card-back');
    if (!back) return;
    if (!sheetEl) sheetEl = buildSheet();
    lastFocus = document.activeElement;
    var name = back.querySelector('.back-name'), label = back.querySelector('.back-label'), bb = back.querySelector('.back-body'), aud = back.querySelector('.audience-chip');
    sheetEl.querySelector('.sheet-title').textContent = name ? name.textContent : '';
    sheetEl.querySelector('.sheet-sub').textContent = label ? label.textContent : '';
    var body = sheetEl.querySelector('.sheet-body');
    body.innerHTML = bb ? bb.innerHTML : '';
    if (!body.textContent.trim()) body.innerHTML = '<div class="sheet-foot">Для этой позиции пока нет скриптов.</div>';
    if (aud && aud.textContent.trim()) {
      var f = document.createElement('div'); f.className = 'sheet-foot'; f.textContent = aud.textContent; body.appendChild(f);
    }
    body.scrollTop = 0;
    walk(sheetEl);
    document.body.classList.add('sheet-open');
    sheetEl.classList.add('active');
    setTimeout(function () { var c = sheetEl.querySelector('.sheet-close'); if (c) c.focus({ preventScroll: true }); }, 50);
  };
  function closeSheet() {
    if (!sheetEl || !sheetEl.classList.contains('active')) return;
    sheetEl.classList.remove('active');
    document.body.classList.remove('sheet-open');
    if (lastFocus && lastFocus.focus) { try { lastFocus.focus({ preventScroll: true }); } catch (e) {} }
  }
  window.closeCardSheet = closeSheet;
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') closeSheet();
    if ((e.key === 'Enter' || e.key === ' ') && e.target.classList && e.target.classList.contains('card-wrap')) {
      e.preventDefault(); e.target.click();
    }
  });
  window.addEventListener('resize', function () { if (window.innerWidth > 768) closeSheet(); });

  /* ── Фото на тёмном фоне: полноформатная подложка вместо «тёмного прямоугольника» на креме ── */
  function probeDark(img) {
    var area = img.closest && img.closest('.card-img-area');
    if (!area || area.dataset.probed) return;
    area.dataset.probed = '1';
    var p = new Image();
    p.crossOrigin = 'anonymous';
    p.onload = function () {
      try {
        var c = document.createElement('canvas'); c.width = 16; c.height = 12;
        var x = c.getContext('2d'); x.drawImage(p, 0, 0, 16, 12);
        var pts = [[0, 0], [15, 0], [0, 11], [15, 11]], lum = 0, opaque = 0;
        pts.forEach(function (q) {
          var d = x.getImageData(q[0], q[1], 1, 1).data;
          if (d[3] > 200) { opaque++; lum += 0.2126 * d[0] + 0.7152 * d[1] + 0.0722 * d[2]; }
        });
        if (opaque >= 3 && lum / opaque < 80) area.classList.add('is-dark');
      } catch (e) { /* CORS закрыт — оставляем крем */ }
    };
    p.src = img.currentSrc || img.src;
  }
  document.addEventListener('load', function (e) {
    if (e.target && e.target.tagName === 'IMG') probeDark(e.target);
  }, true);

  /* ── «Принципы работы с гостем»: свёрнуто по умолчанию, выбор запоминается ── */
  function initPrinciples() {
    var box = document.getElementById('scriptsPrinciples');
    if (!box || box.dataset.dsInit) return;
    box.dataset.dsInit = '1';
    var open = false;
    try { open = localStorage.getItem('yahya.principles') === 'open'; } catch (e) {}
    if (!open) box.classList.add('collapsed');
    var head = box.querySelector('.scripts-principles-header');
    if (head) head.addEventListener('click', function () {
      setTimeout(function () { try { localStorage.setItem('yahya.principles', box.classList.contains('collapsed') ? 'closed' : 'open'); } catch (e) {} }, 0);
    });
  }

  function init() {
    walk(document.body);
    initPrinciples();
    new MutationObserver(function (list) {
      list.forEach(function (r) {
        if (r.type === 'characterData') { if (QUICK.test(r.target.nodeValue || '')) queue(r.target); }
        else r.addedNodes.forEach(function (n) { if (n.nodeType === 1 || (n.nodeType === 3 && QUICK.test(n.nodeValue))) queue(n); });
      });
    }).observe(document.body, { childList: true, subtree: true, characterData: true });
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init); else init();
})();
