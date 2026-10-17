'use strict';

/* MADRIGAL · фронтенд лаборатории протоколов (без внешних зависимостей) */

const PAGE = 4096;

const S = {
  info: null,          // последняя открытая запись
  sessions: [],
  session: null,       // детали выбранной сессии
  dir: 'a2b',
  offset: 0,           // начало текущей страницы
  cells: [],
  total: 0,
  stats: null,
  anchor: null,        // выделение: первая точка
  focus: null,         // выделение: вторая точка
  matches: [],
  matchIdx: -1,
  matchLen: 0,
  hl: null,            // подсветка найденного {start,end}
  pane: 'stream',
  schema: null,        // текущая схема интерпретации (ответ /api/schema)
  interp: null,        // последний результат применения схемы
  interpStamp: null,   // {schemaSha, fileSha} — штампы применённой схемы
  corpus: null,        // последний отчёт проверки корпуса (R4)
  corpusStamp: null,   // {schemaSha} — схема, с которой прогнан корпус
  journal: null,       // результат корреляции журнала действий (R2)
  journalSel: null,    // id выбранного действия для панели сверки
};

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s).replace(/[&<>"]/g, (c) =>
  ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
const hex2 = (v) => v.toString(16).toUpperCase().padStart(2, '0');
const hexn = (v) => '0x' + v.toString(16).toUpperCase();

async function api(url, opts) {
  const res = await fetch(url, opts);
  let data = null;
  try { data = await res.json(); } catch (e) { /* пусто */ }
  if (!res.ok) {
    let msg;
    if (data && data.detail !== undefined) {
      msg = typeof data.detail === 'string' ? data.detail : JSON.stringify(data.detail);
    } else {
      msg = res.statusText || ('HTTP ' + res.status);
    }
    throw new Error(msg);
  }
  return data;
}

const post = (url, body) => api(url, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(body),
});

/* ==================== фоновые задачи: ход и отмена (раздел 10) ===== */

const JOB = { id: null, timer: null, finish: null };

function jobShow(title) {
  if (JOB.timer) { clearInterval(JOB.timer); JOB.timer = null; }
  $('job-progress').hidden = false;
  $('job-progress').classList.add('busy');
  $('job-title').textContent = title;
  $('job-label').textContent = '';
  $('job-fill').style.width = '0';
}

function jobHide() {
  if (JOB.timer) { clearInterval(JOB.timer); JOB.timer = null; }
  JOB.id = null;
  $('job-progress').hidden = true;
  $('job-progress').classList.remove('busy');
}

function jobRender(d) {
  const p = d.progress || {};
  $('job-title').textContent = `${d.title} [${d.status}]`;
  $('job-label').textContent = p.total
    ? `${p.label} · ${p.current}/${p.total}`
    : (p.label || '');
  if (p.total) {
    $('job-progress').classList.remove('busy');
    $('job-fill').style.width = Math.round(100 * p.current / p.total) + '%';
  }
}

/**
 * Запустить задачу и поллить её ход до завершения.
 * Разрешается объектом: {done: result} | {cancelled: true} | {failed: error}.
 * Ошибка запуска (HTTP) бросается, чтобы вызывающий код показал её.
 */
async function runJob(body, title) {
  jobShow(title);
  const j = await post('/api/jobs', body);
  JOB.id = j.id;
  return new Promise((resolve) => {
    JOB.finish = resolve;
    JOB.timer = setInterval(pollJob, 250);
    pollJob();
  });
}

async function pollJob() {
  if (!JOB.id) return;
  let d;
  try { d = await api('/api/jobs/' + JOB.id); }
  catch (e) { jobHide(); showError(e.message); return; }
  jobRender(d);
  if (d.status === 'running' || d.status === 'queued') return;
  // завершено: done | failed | cancelled
  clearInterval(JOB.timer); JOB.timer = null;
  const finish = JOB.finish; JOB.finish = null;
  jobHide();
  if (d.status === 'cancelled') finish({ cancelled: true });
  else if (d.status === 'failed') finish({ failed: d.error });
  else finish({ done: d.result });
}

async function cancelJob() {
  if (!JOB.id) return;
  $('job-label').textContent = 'отменяю…';
  try { await post(`/api/jobs/${JOB.id}/cancel`, {}); }
  catch (e) { showError(e.message); }
}

function showError(msg) {
  const bar = $('error-bar');
  bar.textContent = '⚠ ' + msg;
  bar.hidden = false;
}
function clearError() { $('error-bar').hidden = true; }

/* ======================================================== открытие файла */

async function openPath(path) {
  clearError();
  try {
    const info = await post('/api/open', { path });
    afterOpen(info);
  } catch (e) {
    showError(e.message);
  }
}

function afterOpen(info) {
  S.info = info;
  S.sessions = info.sessions || [];
  S.session = null;
  S.anchor = S.focus = null;
  S.matches = [];
  S.hl = null;

  $('path-input').value = info.path;
  $('file-info').innerHTML =
    `<b>${esc(info.name)}</b> · ${info.fmt} · пакетов: ${info.packets}` +
    ` · сессий: ${S.sessions.length} · sha256 ${esc(info.sha256.slice(0, 12))}…`;

  renderSessions();
  renderNotes();
  fillCompareSelects();

  // результаты прошлой записи больше не действительны (не «оставшееся»)
  S.interp = null;
  S.interpStamp = null;
  $('interp-summary').innerHTML = '';
  $('interp-hypotheses').innerHTML = '';
  $('interp-messages').innerHTML = '';
  updateStaleness();

  S.journal = null;
  S.journalSel = null;
  $('journal-summary').innerHTML = '';
  $('journal-table').innerHTML = '';
  $('journal-detail').innerHTML =
    '<div class="muted">выберите действие слева, чтобы увидеть сверку ' +
    'полей и перейти к исходным байтам</div>';
  $('journal-compare-out').innerHTML = '';
  $('journal-compare').innerHTML = '';
  $('journal-status').textContent = '';

  $('session-view').hidden = true;
  $('empty-state').hidden = S.sessions.length > 0;
  if (!S.sessions.length) {
    showError('в записи не найдено ни одной TCP-сессии');
  }
}

function renderSessions() {
  const body = $('sessions-body');
  $('sessions-count').textContent = S.sessions.length
    ? `(${S.sessions.length})` : '';
  if (!S.sessions.length) {
    body.innerHTML = '<tr><td colspan="5" class="muted">нет данных</td></tr>';
    return;
  }
  body.innerHTML = S.sessions.map((s) => {
    const warn = s.midstream ? '<span class="warn" title="запись без рукопожатия">◐</span>' : '';
    return `<tr class="row" data-sid="${s.id}">
      <td>${s.id}</td>
      <td title="${esc(s.a.label)}">${esc(shortEp(s.a))} ${warn}</td>
      <td title="${esc(s.b.label)}">${esc(shortEp(s.b))}</td>
      <td>${s.packets}</td>
      <td>${s.payload_bytes}</td>
    </tr>`;
  }).join('');
}

const shortEp = (e) => {
  const parts = e.ip.split('.');
  const ip = parts.length === 4 && parts.every((p) => p === '0' || p === '127')
    ? e.ip : parts.slice(-1).join('.');
  return `${ip}:${e.port}`;
};

function renderNotes() {
  const notes = [];
  for (const n of (S.info.notes || [])) notes.push(esc(n));
  if (S.info.errors) notes.push(`пакетов с ошибками разбора: ${S.info.errors}`);
  if (S.info.warnings) notes.push(`пакетов с предупреждениями: ${S.info.warnings}`);
  $('file-notes').innerHTML = notes.map((n) => `<div>${n}</div>`).join('');
}

/* ========================================================== сессии и UI */

async function selectSession(id) {
  clearError();
  try {
    S.session = await api(`/api/session/${id}`);
  } catch (e) {
    showError(e.message);
    return;
  }
  S.anchor = S.focus = null;
  S.matches = [];
  S.matchIdx = -1;
  S.hl = null;
  $('search-info').textContent = '';
  $('search-input').value = '';
  $('match-prev').disabled = true;
  $('match-next').disabled = true;

  $('empty-state').hidden = true;
  $('session-view').hidden = false;

  renderSessionMeta();
  const st = S.session.streams;
  S.dir = (st.a2b.length > 0) ? 'a2b' : 'b2a';
  renderTabs();
  showPane('stream');
  await loadChunk(0);
  updateSelection();
}

function renderSessionMeta() {
  const s = S.session;
  const badges = [
    `<span class="badge">сессия #${s.id}</span>`,
    `<span class="badge">A: ${esc(s.a.label)}</span>`,
    `<span class="badge">B: ${esc(s.b.label)}</span>`,
    `<span class="badge">пакетов: ${s.packets}</span>`,
    `<span class="badge">байт: ${s.payload_bytes}</span>`,
    s.closed ? '<span class="badge ok">закрыта</span>' : '<span class="badge">не закрыта</span>',
    s.saw_syn ? '<span class="badge ok">рукопожатие есть</span>'
              : '<span class="badge warn">нет рукопожатия</span>',
    s.saw_rst ? '<span class="badge warn">RST</span>' : '',
    s.parse_errors ? `<span class="badge warn">ошибок разбора: ${s.parse_errors}</span>` : '',
    `<span class="badge">время: ${s.start.toFixed(3)}…${s.end.toFixed(3)}</span>`,
  ];
  $('session-meta').innerHTML = badges.join(' ');
}

function renderTabs() {
  const s = S.session;
  const st = S.session.streams;
  const fmt = (d) => {
    const x = st[d];
    let tail = `${x.length} Б`;
    if (x.gap_count) tail += ` · ? ${x.gap_bytes}`;
    if (x.ambiguities) tail += ` · ⚠ ${x.ambiguities}`;
    return tail;
  };
  $('tab-a2b').textContent = `${s.a.label} → ${s.b.label} (${fmt('a2b')})`;
  $('tab-b2a').textContent = `${s.b.label} → ${s.a.label} (${fmt('b2a')})`;
  $('tab-a2b').classList.toggle('active', S.pane === 'stream' && S.dir === 'a2b');
  $('tab-b2a').classList.toggle('active', S.pane === 'stream' && S.dir === 'b2a');
  $('tab-compare').classList.toggle('active', S.pane === 'compare');
  $('tab-interpret').classList.toggle('active', S.pane === 'interpret');
  $('tab-journal').classList.toggle('active', S.pane === 'journal');
}

function showPane(pane) {
  S.pane = pane;
  $('stream-pane').hidden = pane !== 'stream';
  $('compare-pane').hidden = pane !== 'compare';
  $('interpret-pane').hidden = pane !== 'interpret';
  $('journal-pane').hidden = pane !== 'journal';
  renderTabs();
}

async function setDir(dir) {
  if (S.dir === dir && S.pane === 'stream') return;
  S.dir = dir;
  S.anchor = S.focus = null;
  S.matches = [];
  S.matchIdx = -1;
  S.hl = null;
  $('search-info').textContent = '';
  $('match-prev').disabled = true;
  $('match-next').disabled = true;
  showPane('stream');
  await loadChunk(0);
  updateSelection();
}

/* =========================================================== hex-представление */

async function loadChunk(offset) {
  if (!S.session) return;
  offset = Math.max(0, offset);
  try {
    const d = await api(
      `/api/stream/${S.session.id}/${S.dir}?offset=${offset}&length=${PAGE}`);
    if (!d.cells.length && d.total > 0 && d.offset >= d.total) {
      // страница за концом потока — вернуться на последнюю
      return loadChunk(Math.max(0, d.total - PAGE));
    }
    S.offset = d.offset;
    S.cells = d.cells;
    S.total = d.total;
    S.stats = d.stats;
    $('jump-offset').value = S.offset;
    $('page-info').textContent =
      `страница ${S.offset}…${S.offset + S.cells.length} из ${S.total} Б`;
    renderHex();
    renderStats();
  } catch (e) {
    showError(e.message);
  }
}

function selRange() {
  if (S.anchor === null || S.focus === null) return null;
  const a = Math.min(S.anchor, S.focus);
  const b = Math.max(S.anchor, S.focus);
  return [a, b];
}

function inSel(o) {
  const r = selRange();
  return r && o >= r[0] && o <= r[1];
}

function renderHex() {
  const cells = S.cells;
  if (!cells.length) {
    $('hexview').innerHTML = '<div class="muted pad">в потоке нет данных</div>';
    return;
  }
  let html = '';
  for (let i = 0; i < cells.length; i += 16) {
    const chunk = cells.slice(i, i + 16);
    let hex = '';
    let asc = '';
    for (const [o, v, pkt, amb] of chunk) {
      const cls = [];
      if (v === null) cls.push('gap');
      if (amb) cls.push('amb');
      if (S.hl && o >= S.hl.start && o < S.hl.end) cls.push('found');
      if (inSel(o)) cls.push('sel');
      const label = v === null ? '??' : hex2(v);
      hex += `<i class="byte ${cls.join(' ')}" data-o="${o}" data-p="${pkt}">${label}</i>`;
      const acls = [];
      if (v === null) acls.push('gap');
      if (inSel(o)) acls.push('sel');
      const ch = v === null ? '?' : (v >= 32 && v < 127 ? String.fromCharCode(v) : '.');
      asc += `<i class="a ${acls.join(' ')}">${ch}</i>`;
    }
    html += `<div class="row"><span class="off">${chunk[0][0].toString(16).padStart(8, '0')}</span>` +
            `${hex}<span class="ascii">${asc}</span></div>`;
  }
  html += `<div class="legend">обозначения:` +
    `<i class="l-gap"></i>неизвестные байты (не подменяются)` +
    `<i class="l-amb"></i>неоднозначность (first-seen)` +
    `<i class="l-found"></i>совпадение поиска` +
    `<i class="l-sel"></i>выделение</div>`;
  $('hexview').innerHTML = html;
}

function renderStats() {
  const st = S.stats;
  if (!st) { $('stats').innerHTML = ''; $('diagnostics').innerHTML = ''; return; }
  const chips = [];
  chips.push(['поток: ' + st.length + ' Б', '']);
  chips.push(['достоверно: ' + st.data_length + ' Б', st.complete ? 'ok' : 'bad']);
  chips.push(['сегментов: ' + st.segments, '']);
  if (st.gap_count) chips.push([`неизвестных участков: ${st.gap_count} (${st.gap_bytes} Б)`, 'bad']);
  else chips.push(['пропусков нет', 'ok']);
  if (st.retransmissions) chips.push(['ретрансмиссий: ' + st.retransmissions, 'ok']);
  if (st.ambiguities) chips.push(['неоднозначностей: ' + st.ambiguities, 'warn']);
  if (st.midstream) chips.push(['midstream', 'warn']);
  $('stats').innerHTML = chips.map(([t, c]) => `<span class="chip ${c}">${t}</span>`).join('');

  let d = '';
  for (const g of st.gaps) {
    d += `<div class="diag">неизвестный участок [${hexn(g.start)}..${hexn(g.end)}) — ${g.length} Б ` +
         `<button class="jump" data-off="${g.start}">перейти</button></div>`;
  }
  for (const a of st.ambiguity_list) {
    d += `<div class="diag">неоднозначность [${hexn(a.start)}..${hexn(a.end)}): ` +
         `pkt#${a.kept} против pkt#${a.alt} ` +
         `<button class="jump" data-off="${a.start}">перейти</button></div>`;
  }
  for (const line of st.diagnostics) {
    d += `<div class="diag">${esc(line)}</div>`;
  }
  $('diagnostics').innerHTML = d;
}

/* ============================================================ выделение */

async function updateSelection() {
  const r = selRange();
  if (!r || !S.session) {
    $('sel-pos').textContent = '—';
    $('sel-hex').textContent = '';
    $('sel-ascii').textContent = '';
    $('sel-packets').innerHTML = '';
    return;
  }
  const [a, b] = r;
  $('sel-pos').textContent = `${hexn(a)}…${hexn(b)} (${b - a + 1} Б)`;
  try {
    const d = await api(
      `/api/stream/${S.session.id}/${S.dir}/text?offset=${a}&length=${Math.min(b - a + 1, 1024)}`);
    $('sel-hex').textContent = fmtHex(d.hex);
    $('sel-ascii').textContent = d.ascii +
      (d.unknown ? `  [неизвестно: ${d.unknown} Б — не подменяется]` : '');
    $('sel-packets').innerHTML = 'источник: ' + (d.packets.length
      ? d.packets.map((p) => `<button class="pkt-link" data-pkt="${p}">пакет #${p}</button>`).join('')
      : '<span class="muted">нет данных</span>');
  } catch (e) {
    showError(e.message);
  }
}

function fmtHex(hex) {
  const parts = [];
  for (let i = 0; i < hex.length; i += 32) {
    const chunk = hex.slice(i, i + 32);
    const bytes = chunk.match(/../g) || [];
    parts.push(bytes.join(' '));
  }
  return parts.join('  ');
}

/* ================================================================ поиск */

async function doSearch() {
  if (!S.session) return;
  const pattern = $('search-input').value;
  const mode = $('search-mode').value;
  clearError();
  try {
    const d = await post('/api/search', {
      session: S.session.id,
      direction: S.dir,
      pattern,
      mode,
    });
    S.matches = d.matches;
    S.matchLen = mode === 'hex'
      ? Math.max(1, Math.floor(pattern.replace(/[\s:]/g, '').length / 2))
      : new TextEncoder().encode(pattern).length;
    if (d.truncated) {
      showError('поиск остановлен по защитному пределу (первые 8 МиБ потока)');
    }
    if (!d.matches.length) {
      S.hl = null;
      S.matchIdx = -1;
      $('search-info').textContent = 'нет совпадений';
      $('match-prev').disabled = true;
      $('match-next').disabled = true;
      renderHex();
      return;
    }
    $('search-info').textContent = `1 / ${d.matches.length}`;
    $('match-prev').disabled = d.matches.length < 2;
    $('match-next').disabled = d.matches.length < 2;
    jumpToMatch(0);
  } catch (e) {
    showError(e.message);
  }
}

async function jumpToMatch(idx) {
  if (!S.matches.length) return;
  S.matchIdx = ((idx % S.matches.length) + S.matches.length) % S.matches.length;
  const m = S.matches[S.matchIdx];
  S.hl = { start: m, end: m + S.matchLen };
  $('search-info').textContent = `${S.matchIdx + 1} / ${S.matches.length}`;
  const page = Math.floor(m / PAGE) * PAGE;
  await loadChunk(page);   // перерисует с подсветкой
}

/* ============================================================== пакеты */

async function openPacket(index) {
  clearError();
  try {
    const d = await api(`/api/packet/${index}`);
    renderPacket(d);
    $('modal-packet').hidden = false;
  } catch (e) {
    showError(e.message);
  }
}

function renderPacket(d) {
  $('pkt-title').textContent = `Пакет #${d.index}`;
  const rows = [];
  rows.push(['время', d.timestamp.toFixed(6)]);
  rows.push(['размер', `${d.size} Б` + (d.truncated ? ` (усечён, orig ${d.orig_len})` : '')]);
  rows.push(['linktype', d.linktype]);
  if (d.error) rows.push(['ошибка', esc(d.error)]);
  for (const w of d.warnings) rows.push(['предупреждение', esc(w)]);

  let html = '<table>' + rows.map(([k, v]) => `<tr><td>${k}</td><td>${v}</td></tr>`).join('') + '</table>';

  if (d.ethernet) {
    html += '<table>' +
      `<tr><td>Ethernet</td><td>${esc(d.ethernet.src)} → ${esc(d.ethernet.dst)}</td></tr>` +
      `<tr><td>ethertype</td><td>${d.ethernet.ethertype}` +
      (d.ethernet.vlan.length ? ` · VLAN ${d.ethernet.vlan.join(',')}` : '') + '</td></tr>' +
      '</table>';
  }
  if (d.ip) {
    html += '<table>' +
      `<tr><td>IPv4</td><td>${esc(d.ip.src)} → ${esc(d.ip.dst)} · ttl ${d.ip.ttl} · id ${d.ip.id}</td></tr>` +
      `<tr><td>фрагментация</td><td>offset ${d.ip.frag_offset} · MF ${d.ip.more_fragments}</td></tr>` +
      '</table>';
  }
  if (d.tcp) {
    html += '<table>' +
      `<tr><td>TCP</td><td>${d.tcp.src_port} → ${d.tcp.dst_port} · seq ${d.tcp.seq} · ack ${d.tcp.ack}</td></tr>` +
      `<tr><td>флаги</td><td>${esc(d.tcp.flags)} · окно ${d.tcp.window} · заголовок ${d.tcp.header_len} Б</td></tr>` +
      `<tr><td>payload</td><td>${d.payload_len} Б` +
      (d.payload_offset >= 0 ? ` (начинается со смещения ${d.payload_offset} в кадре)` : '') +
      '</td></tr>' +
      '</table>';
  }

  html += `<div class="muted" style="margin-bottom:4px">кадр (первые ${d.hex_limit} Б, полезная нагрузка подсвечена):</div>`;
  html += '<div class="pkthex">';
  for (let i = 0; i < d.hex.length; i += 16) {
    const chunk = d.hex.slice(i, i + 16);
    let hex = '';
    let asc = '';
    for (const [off, v, pl] of chunk) {
      hex += `<i class="byte ${pl ? 'pl' : ''}">${hex2(v)}</i>`;
      asc += `<i class="a">${v >= 32 && v < 127 ? String.fromCharCode(v) : '.'}</i>`;
    }
    html += `<div class="row"><span class="off">${chunk[0][0].toString(16).padStart(8, '0')}</span>${hex}<span class="ascii">${asc}</span></div>`;
  }
  html += '</div>';

  $('pkt-body').innerHTML = html;
}

/* ============================================================== сравнение */

function fillCompareSelects() {
  const opts = S.sessions.map((s) =>
    `<option value="${s.id}">#${s.id} ${esc(shortEp(s.a))}↔${esc(shortEp(s.b))}</option>`).join('');
  $('cmp-a-sid').innerHTML = opts;
  $('cmp-b-sid').innerHTML = opts;
  if (S.sessions.length > 1) $('cmp-b-sid').value = '1';
  if (S.session) {
    $('cmp-a-sid').value = String(S.session.id);
    $('cmp-b-sid').value = String(S.session.id);
    $('cmp-a-dir').value = S.dir;
  }
}

async function doCompare() {
  clearError();
  const side = (p) => ({
    session: parseInt($(p + '-sid').value, 10),
    direction: $(p + '-dir').value,
    offset: Math.max(0, parseInt($(p + '-off').value, 10) || 0),
    length: Math.min(4096, Math.max(8, parseInt($(p + '-len').value, 10) || 256)),
  });
  try {
    const d = await post('/api/compare', { a: side('cmp-a'), b: side('cmp-b') });
    renderCompare(d);
  } catch (e) {
    showError(e.message);
  }
}

function cmpCells(cells, flags) {
  return cells.map(([o, v], i) => {
    const cls = [];
    if (v === null) cls.push('gap');
    else if (flags && flags[i] === 0) cls.push('diff');
    const label = v === null ? '??' : hex2(v);
    return `<span class="byte ${cls.join(' ')}">${label}</span>`;
  }).join('');
}

function renderCompare(d) {
  const s = d.summary;
  const pct = s.compared ? Math.round(100 * s.same / s.compared) : 0;
  let html = `<div class="compare-summary">` +
    `сравнено байтов: <b>${s.compared}</b> · совпало: <b>${s.same}</b> (${pct}%) · ` +
    `<span style="color:var(--warn)">различий: <b>${s.diff}</b></span> · ` +
    `неизвестно: <b>${s.unknown}</b>` +
    (d.truncated ? ' · <span class="muted">показано меньше запрошенного (короче поток)</span>' : '') +
    `</div>`;

  if (!d.rows.length) {
    html += '<div class="muted">нет данных для сравнения</div>';
  }
  html += '<div style="overflow:auto">';
  for (const row of d.rows) {
    html += `<div class="compare-row">` +
      `<span class="off">${row.off_a.toString(16).padStart(6, '0')}</span>` +
      cmpCells(row.a, row.same) +
      `<span class="mid">|</span>` +
      cmpCells(row.b, row.same) +
      `<span class="off">${row.off_b.toString(16).padStart(6, '0')}</span>` +
      `</div>`;
  }
  html += '</div>';
  $('compare-result').innerHTML = html;
}

/* ========================================================== интерпретация */

async function loadSchemaState() {
  try {
    const d = await api('/api/schema');
    S.schema = d;
    if (d.text) $('schema-text').value = d.text;
    renderSchemaStatus();
    renderSchemaErrors(d);
  } catch (e) { /* сервер не отвечает — показать стартовый экран */ }
}

function renderSchemaStatus(extra) {
  const st = $('schema-status');
  const d = S.schema;
  if (!d) { st.textContent = ''; return; }
  if (d.present) {
    st.className = 'schema-ok';
    st.innerHTML = `схема <b>${esc(d.name)}</b> · sha256 ${esc(d.sha256.slice(0, 12))}…` +
      ` · правил: ${d.messages.length} · гипотез: ${d.hypotheses.length}` +
      (extra ? ` · <b>${esc(extra)}</b>` : '');
  } else if (d.errors && d.errors.length) {
    st.className = 'schema-bad';
    st.textContent = `схема не активна: ошибок ${d.errors.length}`;
  } else {
    st.className = 'muted';
    st.textContent = 'схема не загружена';
  }
}

function renderSchemaErrors(d) {
  const box = $('schema-errors');
  if (!d || !d.errors || !d.errors.length) {
    box.innerHTML = d && d.present
      ? '<div class="diag ok">схема валидна — можно применять</div>' : '';
    return;
  }
  box.innerHTML = d.errors.map((e) => `<div class="diag">✕ ${esc(e)}</div>`).join('');
}

async function postSchema(text) {
  const d = await post('/api/schema', { text });
  S.schema = d;
  $('schema-text').value = d.text;
  renderSchemaErrors(d);
  renderSchemaStatus();
  updateStaleness();          // схема могла измениться после применения
  return d;
}

async function checkSchema() {
  clearError();
  try {
    const d = await postSchema($('schema-text').value);
    if (!d.present) showError('схема не прошла валидацию — см. список ошибок');
  } catch (e) {
    showError(e.message);
  }
}

async function loadSchemaFile() {
  clearError();
  const path = $('schema-path').value.trim();
  if (!path) { showError('укажите путь к файлу схемы (.yaml/.json)'); return; }
  try {
    const d = await post('/api/schema', { path });
    S.schema = d;
    $('schema-text').value = d.text;
    renderSchemaErrors(d);
    renderSchemaStatus();
    if (!d.present) showError('файл схемы не прошёл валидацию');
  } catch (e) {
    showError(e.message);
  }
}

async function applySchema(scope) {
  clearError();
  if (!S.session) { showError('сперва выберите сессию'); return; }
  if (!S.schema || !S.schema.present) {
    showError('сперва загрузите и проверьте схему');
    return;
  }
  // текст в редакторе могли изменить после проверки — применяем только валидный
  if ($('schema-text').value !== S.schema.text) {
    const d = await postSchema($('schema-text').value);
    if (!d.present) {
      showError('схема изменена и не прошла проверку — результат не получен');
      return;
    }
  }
  const scopeAll = scope === 'all';
  const body = scopeAll
    ? { op: 'apply', scope: 'all' }
    : { scope: 'session', session: S.session.id };
  $('interp-summary').innerHTML = '';
  $('interp-hypotheses').innerHTML = '';
  $('interp-messages').innerHTML = '<div class="pad muted">применяю схему…</div>';
  try {
    let d;
    if (scopeAll) {
      // ко всей записи — длительная операция: ход и отмена (раздел 10)
      const out = await runJob(body, 'применение схемы ко всей записи');
      if (out.cancelled || out.failed) {
        S.interp = null;
        $('interp-messages').innerHTML = '';
        showError(out.cancelled
          ? 'применение отменено — неполный результат не показан'
          : `применение прервано: ${out.failed}`);
        return;
      }
      d = out.done;
    } else {
      d = await post('/api/schema/apply', body);
    }
    S.interp = d;
    S.interpStamp = { schemaSha: d.schema.sha256, fileSha: d.file.sha256 };
    renderInterp();
    renderSchemaStatus(scope === 'all'
      ? `применено ко всей записи (${d.sessions.length} сессий)`
      : `применено к сессии ${d.sessions[0].index}`);
    updateStaleness();
  } catch (e) {
    S.interp = null;
    $('interp-messages').innerHTML = '';
    showError(e.message);
  }
}

const HYP_RANK = { not_applicable: 1, not_checked: 1, pass: 2, incomplete: 3, fail: 4 };

/** Гипотезы из нескольких сессий сводятся: худший результат побеждает. */
function mergeHypotheses() {
  const byId = new Map();
  for (const sess of (S.interp ? S.interp.sessions : [])) {
    for (const h of sess.hypotheses) {
      const ce = h.counterexamples.map((x) => Object.assign({ sess: sess.index }, x));
      if (!byId.has(h.id)) {
        byId.set(h.id, {
          id: h.id, statement: h.statement, basis: h.basis,
          status_before: h.status_before, status_after: h.status_after,
          result: h.result, note: h.note,
          pairs: Object.assign({}, h.pairs),
          counterexamples: ce,
          sessions: [sess.index],
        });
      } else {
        const m = byId.get(h.id);
        m.pairs.total += h.pairs.total;
        m.pairs.ok += h.pairs.ok;
        m.pairs.unknown += h.pairs.unknown;
        m.counterexamples = m.counterexamples.concat(ce);
        m.sessions.push(sess.index);
        if (HYP_RANK[h.result] > HYP_RANK[m.result]) {
          m.result = h.result;
          m.note = h.note;
          m.status_after = h.status_after;
        }
      }
    }
  }
  return Array.from(byId.values());
}

function fmtFieldVal(f) {
  if (!f.known) return '<span class="fv-unknown" title="байты недоступны — значение не подменяется">?</span>';
  const v = f.value;
  if (typeof v === 'number') return esc(String(v));
  if (typeof v === 'string') {
    const cut = f.type === 'bytes' ? v.slice(0, 32) : v.slice(0, 20);
    const more = (f.type === 'bytes' ? v.length > 32 : v.length > 20) ? '…' : '';
    return `<code title="${esc(v.length / (f.type === 'bytes' ? 2 : 1))} Б">${esc(cut)}${more}</code>`;
  }
  return '?';
}

function msgRow(m, sid) {
  const flags = [];
  if (m.id === null) {
    flags.push('<span class="badge warn" title="не подошло ни одно правило — это неохват, а не догадка">неопознано</span>');
  }
  if (m.partial) {
    flags.push(`<span class="badge warn" title="${esc(m.note || 'в сообщении есть недоступные байты')}">частичное</span>`);
  }
  if (m.match_unknown) {
    flags.push('<span class="badge warn" title="условие сопоставления не проверяемо из-за пропусков">условие ?</span>');
  }
  const fields = Object.entries(m.fields)
    .map(([name, f]) => `<span class="fv"><b>${esc(name)}</b>=${fmtFieldVal(f)}</span>`)
    .join(' ') || '<span class="muted">поля не описаны</span>';
  return `<tr class="row msg-row" data-sid="${sid}" data-dir="${m.direction}"` +
    ` data-start="${m.start}" data-end="${m.end}">` +
    `<td>${m.index}</td>` +
    `<td class="mono">${hexn(m.start)}…${hexn(m.end - 1)}</td>` +
    `<td>${m.id === null ? '<span class="muted">?</span>' : `<b>${esc(m.id)}</b>`}</td>` +
    `<td>${m.size}</td>` +
    `<td>${fields}</td>` +
    `<td>${flags.join(' ')}</td></tr>`;
}

function renderInterp() {
  const d = S.interp;
  if (!d) return;
  const agg = { messages: 0, unmatched: 0, partial: 0, framing: 0, unframed: 0 };

  const blocks = d.sessions.map((sess) => {
    const dirs = Object.entries(sess.directions).map(([dir, r]) => {
      const st = r.stats;
      agg.messages += st.messages;
      agg.unmatched += st.unmatched;
      agg.partial += st.partial;
      agg.framing += st.framing_errors;
      agg.unframed += st.unframed_bytes;
      const labels = dir === 'a2b'
        ? `${esc(sess.endpoints.a)} → ${esc(sess.endpoints.b)}`
        : `${esc(sess.endpoints.b)} → ${esc(sess.endpoints.a)}`;
      const matched = Object.entries(st.matched)
        .map(([k, v]) => `${esc(k)} ×${v}`).join(', ') || '—';
      let html = `<div class="interp-block">` +
        `<h4>сессия ${sess.index} · ${dir} <span class="muted">${labels}</span>` +
        (sess.midstream ? ' <span class="badge warn">midstream</span>' : '') + '</h4>' +
        `<div class="chips-row">` +
        `<span class="chip">сообщений: ${st.messages}</span>` +
        `<span class="chip ${st.unmatched ? 'warn' : 'ok'}">неопознано: ${st.unmatched}</span>` +
        `<span class="chip ${st.partial ? 'warn' : 'ok'}">частичных: ${st.partial}</span>` +
        `<span class="chip ${st.framing_errors ? 'bad' : 'ok'}">ошибок фрейминга: ${st.framing_errors}</span>` +
        `<span class="chip">вне сообщений: ${st.unframed_bytes} Б</span>` +
        `<span class="chip">распознано: ${matched}</span>` +
        `</div>`;
      for (const fe of r.framing_errors) {
        html += `<div class="diag">фрейминг: смещение ${fe.start} — ${esc(fe.reason)}` +
          ` <button class="jump" data-jump-sid="${sess.index}" data-jump-dir="${dir}" data-jump-off="${fe.start}">перейти</button></div>`;
      }
      for (const u of r.unframed) {
        html += `<div class="diag">вне сообщений: [${hexn(u.start)}..${hexn(u.start + u.length)}) — ${u.length} Б` +
          ` <button class="jump" data-jump-sid="${sess.index}" data-jump-dir="${dir}" data-jump-off="${u.start}">перейти</button></div>`;
      }
      if (!r.messages.length) {
        html += '<div class="muted pad">сообщений не выделено</div>';
      } else {
        html += '<table class="msg-table"><thead><tr>' +
          '<th>#</th><th>диапазон</th><th>тип</th><th>Б</th><th>поля</th><th>флаги</th>' +
          '</tr></thead><tbody>' +
          r.messages.map((m) => msgRow(m, sess.index)).join('') +
          '</tbody></table>';
        if (r.messages_truncated) {
          html += `<div class="muted pad">показано ${r.messages.length} из ${r.messages_total} (лимит ответа)</div>`;
        }
      }
      return html + '</div>';
    }).join('');
    return dirs;
  }).join('');

  // сводка
  const chip = (t, c) => `<span class="chip ${c}">${t}</span>`;
  $('interp-summary').innerHTML = '<div class="chips-row">' +
    chip(`схема: ${esc(d.schema.name)}`, '') +
    chip(`sha256 ${esc(d.schema.sha256.slice(0, 12))}…`, '') +
    chip(`сессий: ${d.sessions.length}`, '') +
    chip(`сообщений: ${agg.messages}`, '') +
    chip(`неопознано: ${agg.unmatched}`, agg.unmatched ? 'warn' : 'ok') +
    chip(`частичных: ${agg.partial}`, agg.partial ? 'warn' : 'ok') +
    chip(`ошибок фрейминга: ${agg.framing}`, agg.framing ? 'bad' : 'ok') +
    chip(`вне сообщений: ${agg.unframed} Б`, '') +
    '</div>';

  // гипотезы
  const hyps = mergeHypotheses();
  if (hyps.length) {
    $('interp-hypotheses').innerHTML =
      '<div class="interp-block"><h4>гипотезы</h4>' +
      hyps.map(hypCard).join('') + '</div>';
  } else {
    $('interp-hypotheses').innerHTML = '';
  }

  $('interp-messages').innerHTML = blocks;
}

function hypCard(h) {
  const cls = { pass: 'ok', fail: 'bad', incomplete: 'warn' }[h.result] || '';
  let html = `<div class="hyp-card">` +
    `<div class="hyp-head"><b>${esc(h.id)}</b>` +
    `<span class="badge ${cls}">${esc(h.result)}</span>` +
    `<span class="muted">статус: ${esc(h.status_before)}` +
    (h.status_before !== h.status_after ? ` → ${esc(h.status_after)}` : '') + '</span></div>' +
    `<div class="hyp-statement">${esc(h.statement)}</div>` +
    `<div class="muted">основания: ${h.basis.length ? h.basis.map(esc).join(' · ') : 'не указаны'}</div>` +
    `<div>пар: ${h.pairs.total} · совпало: ${h.pairs.ok}` +
    (h.pairs.unknown ? ` · неизвестно: ${h.pairs.unknown}` : '') +
    (h.note ? ` — ${esc(h.note)}` : '') + '</div>';
  if (h.counterexamples.length) {
    const pk = (x) => (x.packets && x.packets.length)
      ? ` [пакеты ${x.packets.join(', ')}]` : '';
    html += h.counterexamples.map((ce) =>
      `<div class="diag">контрпример: ${esc(ce.a.message)}#${ce.a.index} = ${esc(String(ce.a.value))}` +
      `${pk(ce.a)}` +
      ` <button class="jump" data-jump-sid="${ce.sess}" data-jump-dir="${ce.a.direction}" data-jump-off="${ce.a.offset}" data-jump-end="${ce.a.offset + (ce.a.size || 16)}">→</button>` +
      ` против ${esc(ce.b.message)}#${ce.b.index} = ${esc(String(ce.b.value))}` +
      `${pk(ce.b)}` +
      ` <button class="jump" data-jump-sid="${ce.sess}" data-jump-dir="${ce.b.direction}" data-jump-off="${ce.b.offset}" data-jump-end="${ce.b.offset + (ce.b.size || 16)}">→</button></div>`
    ).join('');
  }
  return html + '</div>';
}

/* =========================================== проверка корпуса (R4) === */

const CROWP = [
  ['violations', 'нарушения'], ['coverage', 'неохват'],
  ['ambiguities', 'неоднозначности'], ['not_applicable', 'неприменимые'],
  ['unknown', 'неизвестные'],
];

async function verifyCorpus() {
  clearError();
  const path = $('corpus-path').value.trim();
  if (!path) { showError('укажите путь к манифесту корпуса (.yaml)'); return; }
  $('corpus-status').textContent = 'проверяю корпус…';
  $('corpus-result').innerHTML = '';
  try {
    // корпус сверяем с активной схемой редактора: правка интерпретации
    // должна сразу отражаться на перепроверке (сценарий защиты)
    const out = await runJob({
      op: 'verify',
      path,
      schema_text: (S.schema && S.schema.present) ? S.schema.text : '',
    }, 'проверка корпуса');
    if (out.cancelled) {
      // отмена явная: частичный отчёт не выдаётся за полный
      S.corpus = null;
      S.corpusStamp = null;
      $('corpus-status').textContent =
        'проверка отменена — отчёт не построен, исходные записи не изменены';
      updateStaleness();
      return;
    }
    if (out.failed) {
      S.corpus = null;
      S.corpusStamp = null;
      $('corpus-status').textContent = '';
      showError(`проверка корпуса прервана: ${out.failed}`);
      updateStaleness();
      return;
    }
    const d = out.done;
    if (d.corpus_error) {
      // ошибка корпуса — результат проверки, не сбой UI
      S.corpus = null;
      S.corpusStamp = null;
      $('corpus-status').textContent = '';
      showError('корпус не прошёл проверку: ' + d.corpus_error);
      updateStaleness();
      return;
    }
    S.corpus = d;
    S.corpusStamp = { schemaSha: d.schema.sha256 };
    $('corpus-status').textContent =
      `корпус ${d.corpus.name} · схема ${d.schema.name}` +
      (d.schema.overridden ? ' [переопределена]' : '') +
      ` · sha256 ${d.schema.sha256.slice(0, 12)}… · ${d.generated_at}`;
    renderCorpus();
  } catch (e) {
    S.corpus = null;
    S.corpusStamp = null;
    $('corpus-status').textContent = '';
    showError(e.message);
  }
  updateStaleness();
}

function renderCorpus() {
  const d = S.corpus;
  if (!d) return;
  const sc = d.summary_counts;
  const chip = (t, c) => `<span class="chip ${c || ''}">${t}</span>`;
  let html = '<div class="corpus-summary chips-row">' +
    chip(`файлов: ${d.totals.files}`) +
    chip(`ожидания выполнены: ${d.totals.ok}`,
      d.totals.mismatched ? 'bad' : 'ok') +
    chip(`нарушения: ${sc.violations}`, sc.violations ? 'bad' : 'ok') +
    chip(`неохват: ${sc.coverage}`, sc.coverage ? 'warn' : 'ok') +
    chip(`неоднозначности: ${sc.ambiguities}`, sc.ambiguities ? 'warn' : 'ok') +
    chip(`неприменимые: ${sc.not_applicable}`, '') +
    chip(`неизвестные: ${sc.unknown}`, sc.unknown ? 'warn' : 'ok') +
    '</div>';

  html += d.files.map((f) => {
    const mark = f.ok
      ? '<span class="mark-ok">OK</span>'
      : '<span class="mark-bad">FAIL</span>';
    let block = `<div class="corpus-file ${f.ok ? 'ok' : 'bad'}">` +
      `<h5>${mark} ${esc(f.path)}` +
      ` <span class="muted">sha256 ${esc(f.sha256.slice(0, 12))}…` +
      ` · сессий ${f.sessions}</span></h5>`;
    if (f.note) block += `<div class="muted">${esc(f.note)}</div>`;
    block += ['b2a', 'a2b'].map((dir) => {
      const agg = f.directions[dir];
      if (!agg) return '';
      if (!agg.scope_ok) {
        return `<div class="cf-dir"><b>${dir}</b>: схемой не применялось</div>`;
      }
      const matched = Object.entries(agg.matched)
        .map(([k, v]) => `${esc(k)} ×${v}`).join(', ') || '—';
      return `<div class="cf-dir"><b>${dir}</b>: сообщений ${agg.messages}` +
        `, распознано ${matched} · неопознано ${agg.unmatched}` +
        ` · частичных ${agg.partial} · вне сообщений ${agg.unframed_bytes} Б</div>`;
    }).join('');
    if (f.hypotheses.length) {
      block += '<div class="cf-hyps">' + f.hypotheses.map((h) => {
        const cls = { pass: 'ok', fail: 'bad', incomplete: 'warn' }[h.result] || '';
        return `<span class="chip ${cls}" title="${esc(h.note)}">` +
          `${esc(h.id)}: ${esc(h.result)}</span>`;
      }).join('') + '</div>';
    }
    if (f.violations.length) {
      block += f.violations.map((v) =>
        `<div class="diag bad">нарушение: ${esc(v)}</div>`).join('');
    }
    for (const [key, label] of CROWP) {
      if (key === 'violations') continue;
      const items = f.findings[key];
      if (items.length) {
        block += `<div class="cf-find"><b>${label}</b> (${items.length}): ` +
          items.map((x) => esc(x)).join(' · ') + '</div>';
      }
    }
    return block + '</div>';
  }).join('');

  $('corpus-result').innerHTML = html;
}

/** Устаревание (R4): результаты, полученные по другой схеме или записи,
 *  видимо отличимы — приглушаются и получают предупреждение. */
function updateStaleness() {
  const banner = $('interp-stale');
  let reason = null;
  if (S.interp && S.interpStamp) {
    if (!S.schema || !S.schema.present) {
      reason = 'схема после применения была снята (не прошла валидацию)';
    } else if (S.schema.sha256 !== S.interpStamp.schemaSha) {
      reason = 'схема изменилась после применения — результаты получены по прежней версии';
    } else if (S.info && S.info.sha256 !== S.interpStamp.fileSha) {
      reason = 'открыта другая запись — результаты получены по прежней';
    }
  }
  banner.hidden = !reason;
  banner.textContent = reason
    ? `⚠ результаты устарели: ${reason}. Перепримените схему.` : '';
  $('interp-results').classList.toggle('stale', !!reason);

  const cstale = !!(S.corpus && S.corpusStamp && S.schema && S.schema.present
    && S.schema.sha256 !== S.corpusStamp.schemaSha);
  $('corpus-stale').hidden = !cstale;
  $('corpus-stale').textContent = cstale
    ? '⚠ сводка корпуса получена по другой схеме — проверьте корпус повторно' : '';
  $('corpus-result').classList.toggle('stale', cstale);
}

/** Переход из результата интерпретации к байтам в hex-представлении. */
/* ================================================================ журнал (R2) */

function verdictBadge(v) {
  const cls = v === 'matched' ? 'ok' : (v === 'mismatch' ? 'bad' : 'warn');
  return `<span class="badge ${cls}">${esc(v)}</span>`;
}

function fmtZulu(t) {
  return new Date(t * 1000).toISOString().slice(11, 23) + 'Z';
}

async function runJournal() {
  clearError();
  if (!S.session) { showError('сперва выберите сессию'); return; }
  if (!S.schema || !S.schema.present) {
    showError('сперва загрузите схему (нужна секция journal)'); return;
  }
  const path = $('journal-path').value.trim();
  if (!path) { showError('укажите путь к журналу действий (.csv)'); return; }
  $('journal-status').textContent = 'сопоставляю…';
  $('journal-detail').innerHTML =
    '<div class="muted">выберите действие слева, чтобы увидеть сверку ' +
    'полей и перейти к исходным байтам</div>';
  try {
    const d = await post('/api/journal', { path });
    S.journal = d;
    S.journalSel = null;
    $('journal-status').textContent = '';
    renderJournal();
  } catch (e) {
    $('journal-status').textContent = '';
    showError(e.message);
  }
}

function renderJournal() {
  const d = S.journal;
  if (!d) return;
  const t = d.totals;
  const warn = (d.journal.warnings || []).map(
    (w) => `<div class="diag">журнал: ${esc(w)}</div>`).join('');
  $('journal-summary').innerHTML =
    '<div class="chips-row">' +
    `<span class="chip">действий: ${d.matches.length}</span>` +
    `<span class="chip ${t.matched ? 'ok' : ''}">сверено: ${t.matched}</span>` +
    `<span class="chip ${t.mismatch ? 'bad' : 'ok'}">расхождений: ${t.mismatch}</span>` +
    `<span class="chip ${t.missing ? 'bad' : 'ok'}">не найдено: ${t.missing}</span>` +
    `<span class="chip ${t.incomplete ? 'warn' : 'ok'}">неполных: ${t.incomplete}</span>` +
    `<span class="chip ${t.uncovered ? 'warn' : 'ok'}">вне интерпретации: ${t.uncovered}</span>` +
    '</div>' +
    `<div class="muted">журнал: ${esc(d.journal.path)} — действий этой записи ` +
    `${d.journal.actions}` +
    (d.journal.total !== d.journal.actions ? ` (из ${d.journal.total} в файле)` : '') +
    '</div>' + warn;

  $('journal-compare').innerHTML = (d.action_types || []).map(
    (a) => `<option value="${esc(a)}">${esc(a)}</option>`).join('');

  const rows = d.matches.map((m, i) => {
    const req = m.request ? (m.request.id || 'вне инт.') : '—';
    const resp = m.response ? (m.response.id || 'вне инт.') : '—';
    return `<tr class="row journal-row" data-idx="${i}">` +
      `<td class="mono">${esc(m.action_id)}</td>` +
      `<td>${esc(m.action)}</td>` +
      `<td>${esc(m.session)}${m.session_index != null ? ` (#${m.session_index})` : ''}</td>` +
      `<td>${verdictBadge(m.verdict)}</td>` +
      `<td class="mono">${esc(req)}</td>` +
      `<td class="mono">${esc(resp)}</td>` +
      `<td>${esc(m.note || '')}</td></tr>`;
  }).join('');
  $('journal-table').innerHTML =
    '<table class="msg-table"><thead><tr>' +
    '<th>действие</th><th>тип</th><th>сессия</th><th>вердикт</th>' +
    '<th>запрос</th><th>ответ</th><th>примечание</th>' +
    `</tr></thead><tbody>${rows}</tbody></table>` +
    '<div class="muted pad">клик по строке — сверка полей и переход к байтам</div>';
}

function renderJournalDetail(idx) {
  const d = S.journal;
  if (!d) return;
  const m = d.matches[idx];
  if (!m) return;
  S.journalSel = idx;
  const rows = document.querySelectorAll('#journal-table .journal-row');
  rows.forEach((r) => r.classList.toggle(
    'active', parseInt(r.dataset.idx, 10) === idx));

  const refLine = (label, ref) => {
    if (!ref) return `<div class="muted">${label}: не найден в записи</div>`;
    const jump = `<button class="jump" data-jump-sid="${ref.session}"` +
      ` data-jump-dir="${esc(ref.direction)}" data-jump-off="${ref.start}"` +
      ` data-jump-end="${ref.end}">к байтам</button>`;
    const kind = ref.id ? `<b>${esc(ref.id)}</b>`
      : '<span class="muted">вне интерпретации</span>';
    return `<div>${label}: ${kind} · ${esc(ref.direction)} #${ref.index} · ` +
      `байты ${ref.start}…${ref.end} · ${fmtZulu(ref.t0)} ${jump}</div>`;
  };

  const checks = (m.checks || []).length
    ? (m.checks).map((c) => {
        const ok = c.equal === true;
        const bad = c.equal === false;
        const cls = ok ? 'ok' : (bad ? 'bad' : '');
        const mark = ok ? 'OK' : (bad ? 'FAIL' : '—');
        return '<tr class="row">' +
          `<td><span class="badge ${cls}">${mark}</span></td>` +
          `<td class="mono">${esc(c.path)}</td>` +
          `<td class="mono">${esc(JSON.stringify(c.observed))}</td>` +
          `<td class="mono">${esc(JSON.stringify(c.decoded))}</td>` +
          `<td class="muted">${esc(c.note || '')}</td></tr>`;
      }).join('')
    : '<tr><td colspan="5" class="muted">поля не сверялись ' +
      '(привязки отсутствуют либо обмен вне интерпретации)</td></tr>';

  $('journal-detail').innerHTML =
    `<h4>${esc(m.action_id)} · ${esc(m.action)} ${verdictBadge(m.verdict)}</h4>` +
    (m.note ? `<div class="diag">${esc(m.note)}</div>` : '') +
    `<div class="muted">сессия журнала ${esc(m.session)}` +
    (m.session_index != null ? ` → сессия записи #${m.session_index}` : '') +
    ` · строка ${m.row}</div>` +
    `<div class="mono pad">параметры: ${esc(JSON.stringify(m.parameters))}</div>` +
    `<div class="mono pad">наблюдено: ${esc(JSON.stringify(m.observed_result))}</div>` +
    refLine('запрос', m.request) + refLine('ответ', m.response) +
    '<table class="msg-table"><thead><tr><th></th><th>поле (журнал)</th>' +
    '<th>журнал</th><th>запись</th><th></th></tr></thead>' +
    `<tbody>${checks}</tbody></table>`;
}

function renderJournalCompare() {
  const d = S.journal;
  if (!d) return;
  const action = $('journal-compare').value;
  const text = (d.compare || {})[action];
  $('journal-compare-out').innerHTML = text
    ? `<h4>сопоставление примеров: ${esc(action)}</h4>` +
      `<pre class="mono journal-cmp">${esc(text)}</pre>`
    : '<div class="muted pad">нет примеров для этого действия</div>';
}

async function jumpToMessage(sid, dir, start, end) {
  clearError();
  if (!S.session || S.session.id !== sid) {
    try {
      S.session = await api(`/api/session/${sid}`);
    } catch (e) {
      showError(e.message);
      return;
    }
    renderSessionMeta();
  }
  S.dir = dir;
  S.anchor = null;
  S.focus = null;
  S.matches = [];
  S.matchIdx = -1;
  S.hl = { start, end };
  showPane('stream');
  const page = Math.floor(start / PAGE) * PAGE;
  await loadChunk(page);
  S.anchor = start;
  S.focus = Math.max(start, end - 1);
  renderHex();
  updateSelection();
}

/* =============================================================== браузер файлов */

function joinPath(dir, name) {
  return (dir.endsWith('/') || dir.endsWith('\\')) ? dir + name : dir + '/' + name;
}

async function browse(path) {
  try {
    const d = await api('/api/browse?path=' + encodeURIComponent(path));
    if (d.type === 'file') {
      $('path-input').value = d.path;
      closeModal('modal-browse');
      return;
    }
    $('browse-current').textContent = d.path;
    let html = '';
    if (d.parent) {
      html += `<button class="browse-item dir" data-dir="${esc(d.parent)}">📁 ..</button>`;
    }
    for (const dir of d.dirs) {
      html += `<button class="browse-item dir" data-dir="${esc(joinPath(d.path, dir))}">📁 ${esc(dir)}</button>`;
    }
    for (const f of d.files) {
      html += `<button class="browse-item file" data-file="${esc(joinPath(d.path, f))}">📄 ${esc(f)}</button>`;
    }
    $('browse-list').innerHTML = html ||
      '<div class="pad muted">нет ни каталогов, ни записей (.pcap/.pcapng)</div>';
    $('modal-browse').hidden = false;
  } catch (e) {
    showError(e.message);
  }
}

/* =============================================================== модальные окна */

function closeModal(id) { $(id).hidden = true; }

/* =================================================================== init */

function init() {
  $('btn-open').addEventListener('click', () => openPath($('path-input').value));
  $('path-input').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') openPath($('path-input').value);
  });
  $('btn-browse').addEventListener('click', () => {
    const v = $('path-input').value.trim().replace(/["']/g, '');
    const looksFile = /\.(pcap|pcapng|cap|dmp|trace)$/i.test(v);
    const base = looksFile ? v.replace(/[\\/][^\\/]+$/, '') : v;
    browse(base || '');
  });

  $('sessions-body').addEventListener('click', (e) => {
    const row = e.target.closest('tr[data-sid]');
    if (row) selectSession(parseInt(row.dataset.sid, 10));
  });

  $('tab-a2b').addEventListener('click', () => setDir('a2b'));
  $('tab-b2a').addEventListener('click', () => setDir('b2a'));
  $('tab-compare').addEventListener('click', () => { fillCompareSelects(); showPane('compare'); });
  $('tab-interpret').addEventListener('click', () => showPane('interpret'));
  $('tab-journal').addEventListener('click', () => showPane('journal'));

  $('btn-schema-check').addEventListener('click', checkSchema);
  $('btn-schema-load').addEventListener('click', loadSchemaFile);
  $('btn-schema-apply').addEventListener('click', () => applySchema('session'));
  $('btn-schema-apply-all').addEventListener('click', () => applySchema('all'));
  $('schema-path').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') loadSchemaFile();
  });
  $('schema-text').addEventListener('keydown', (e) => {
    if (e.key === 'Tab') {          // Tab внутри редактора — отступ, не уход
      e.preventDefault();
      const el = e.target;
      const { selectionStart: a, selectionEnd: b } = el;
      el.value = el.value.slice(0, a) + '  ' + el.value.slice(b);
      el.selectionStart = el.selectionEnd = a + 2;
    }
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') checkSchema();
  });

  $('btn-corpus-verify').addEventListener('click', verifyCorpus);
  $('btn-job-cancel').addEventListener('click', cancelJob);
  $('corpus-path').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') verifyCorpus();
  });

  const jumpFromResults = (e) => {
    const btn = e.target.closest('.jump');
    if (!btn) return false;
    const off = parseInt(btn.dataset.jumpOff, 10);
    const end = parseInt(btn.dataset.jumpEnd, 10) || off + 16;
    jumpToMessage(parseInt(btn.dataset.jumpSid, 10), btn.dataset.jumpDir, off, end);
    return true;
  };
  $('interp-messages').addEventListener('click', (e) => {
    if (jumpFromResults(e)) return;
    const row = e.target.closest('tr.msg-row');
    if (row) {
      jumpToMessage(parseInt(row.dataset.sid, 10), row.dataset.dir,
        parseInt(row.dataset.start, 10), parseInt(row.dataset.end, 10));
    }
  });
  $('interp-hypotheses').addEventListener('click', jumpFromResults);

  $('btn-journal-run').addEventListener('click', runJournal);
  $('btn-journal-compare').addEventListener('click', renderJournalCompare);
  $('journal-path').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') runJournal();
  });
  $('journal-table').addEventListener('click', (e) => {
    const row = e.target.closest('tr.journal-row');
    if (row) renderJournalDetail(parseInt(row.dataset.idx, 10));
  });
  $('journal-detail').addEventListener('click', jumpFromResults);

  $('prev-page').addEventListener('click', () => loadChunk(S.offset - PAGE));
  $('next-page').addEventListener('click', () => loadChunk(S.offset + PAGE));
  $('btn-jump').addEventListener('click', () => {
    const v = Math.max(0, parseInt($('jump-offset').value, 10) || 0);
    loadChunk(v - (v % 16));
  });
  $('jump-offset').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') $('btn-jump').click();
  });

  $('hexview').addEventListener('click', (e) => {
    const el = e.target.closest('i.byte');
    if (!el || el.classList.contains('gap')) return;
    const o = parseInt(el.dataset.o, 10);
    if (e.shiftKey && S.anchor !== null) S.focus = o;
    else { S.anchor = o; S.focus = o; }
    renderHex();
    updateSelection();
  });

  $('btn-search').addEventListener('click', doSearch);
  $('search-input').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') doSearch();
    if (e.key === 'Escape') {
      S.hl = null; S.matches = []; S.matchIdx = -1;
      $('search-info').textContent = '';
      renderHex();
    }
  });
  $('match-prev').addEventListener('click', () => jumpToMatch(S.matchIdx - 1));
  $('match-next').addEventListener('click', () => jumpToMatch(S.matchIdx + 1));

  $('diagnostics').addEventListener('click', (e) => {
    const btn = e.target.closest('.jump');
    if (btn) {
      const off = parseInt(btn.dataset.off, 10);
      loadChunk(off - (off % 16));
    }
  });

  document.addEventListener('click', (e) => {
    const pkt = e.target.closest('.pkt-link');
    if (pkt) openPacket(parseInt(pkt.dataset.pkt, 10));
    const close = e.target.closest('[data-close]');
    if (close) closeModal(close.dataset.close);
    if (e.target.classList && e.target.classList.contains('modal')) {
      e.target.hidden = true;
    }
  });

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      $('modal-packet').hidden = true;
      $('modal-browse').hidden = true;
    }
  });

  $('browse-up').addEventListener('click', () => {
    const cur = $('browse-current').textContent;
    if (cur) browse(cur.replace(/[\\/][^\\/]+$/, '') || cur);
  });
  $('browse-list').addEventListener('click', (e) => {
    const item = e.target.closest('.browse-item');
    if (!item) return;
    if (item.dataset.dir !== undefined) browse(item.dataset.dir);
    else if (item.dataset.file !== undefined) {
      $('path-input').value = item.dataset.file;
      closeModal('modal-browse');
    }
  });

  $('btn-compare').addEventListener('click', doCompare);

  // восстановление состояния после перезагрузки страницы
  api('/api/state').then((d) => {
    if (d.loaded) afterOpen(d);
  }).catch(() => { /* сервер не отвечает — показать стартовый экран */ });
  loadSchemaState();
}

document.addEventListener('DOMContentLoaded', init);
