/* Тарих Race KZ — админ беті.
   Кіру: email + құпиясөз, содан кейін міндетті түрде TOTP коды (екі сатылы қорғаныс).
   Деректерді база өзі тек админге және тек 2-сатылы кіруден кейін (aal2) береді;
   бұл бет тек соларды көрсетеді. Барлық мәтін textContent арқылы шығарылады. */
(() => {
'use strict';
// Басқа сайттың ішіне (iframe) салынса, бет бос қалады: clickjacking-тен қорғаныс.
if (window.top !== window.self) return;
document.body.classList.remove('locked');

const CFG = window.TARIH_CONFIG, DATA = window.TARIH_DATA;
const $ = id => document.getElementById(id);
const el = (tag, cls, txt) => { const e = document.createElement(tag); if (cls) e.className = cls; if (txt !== undefined) e.textContent = txt; return e; };
const STORAGE_KEY = 'tarih-admin';
const IDLE_MS = 15 * 60 * 1000;

/* Session lives in sessionStorage: closing the tab ends it. */
const memStore = {};
const store = (() => {
  try { const s = window.sessionStorage; s.setItem('__t', '1'); s.removeItem('__t'); return s; }
  catch (e) { return { getItem: k => (k in memStore ? memStore[k] : null), setItem: (k, v) => { memStore[k] = String(v); }, removeItem: k => { delete memStore[k]; } }; }
})();
function wipeStorage() {
  try { for (let i = store.length - 1; i >= 0; i--) { const k = store.key(i); if (k && k.startsWith(STORAGE_KEY)) store.removeItem(k); } } catch (e) {}
  for (const k of Object.keys(memStore)) delete memStore[k];
}

let sb = null;
try {
  sb = window.supabase.createClient(CFG.url, CFG.key, {
    auth: { storage: store, storageKey: STORAGE_KEY, persistSession: true, autoRefreshToken: true, detectSessionInUrl: false }
  });
} catch (e) { sb = null; }

const VIEWS = ['vLoading', 'vLogin', 'vEnroll', 'vVerify', 'vData'];
function view(name) {
  VIEWS.forEach(id => { $(id).hidden = id !== name; });
  const inside = name === 'vEnroll' || name === 'vVerify' || name === 'vData';
  $('bLogout').hidden = !inside;
  if (!inside) $('whoEmail').textContent = '';
}
function busy(form, on) { form.querySelectorAll('button,input').forEach(x => { x.disabled = on; }); }

function authMessage(error) {
  const status = error && error.status, code = String((error && (error.code || error.name)) || '');
  if (status === 429 || code.includes('rate_limit') || code.includes('over_request')) return 'Тым көп әрекет жасалды. Бірнеше минуттан кейін қайталаңыз.';
  if (!status || code === 'AuthRetryableFetchError') return 'Серверге қосылу мүмкін болмады. Интернетті тексеріңіз.';
  if (status === 400 || status === 401 || code.includes('invalid_credentials')) return 'Email немесе құпиясөз қате.';
  return 'Кіру мүмкін болмады. Қайталап көріңіз.';
}
function codeMessage(error) {
  const status = error && error.status;
  if (status === 429) return 'Тым көп әрекет жасалды. Бірнеше минуттан кейін қайталаңыз.';
  if (!status) return 'Серверге қосылу мүмкін болмады. Интернетті тексеріңіз.';
  return 'Код қате немесе мерзімі өтті. Қолданбадағы жаңа кодты жазыңыз.';
}

/* ---------------- routing ---------------- */
let routing = false;
async function route(message) {
  if (!sb) { view('vLogin'); $('loginErr').textContent = 'Бет дұрыс жүктелмеді. Бетті жаңартыңыз.'; return; }
  if (routing) return; routing = true;
  try {
    view('vLoading');
    const { data: { session } } = await sb.auth.getSession();
    if (!session) { view('vLogin'); $('loginErr').textContent = message || ''; return; }
    $('whoEmail').textContent = (session.user && session.user.email) || '';
    const { data: aal, error } = await sb.auth.mfa.getAuthenticatorAssuranceLevel();
    if (error || !aal) { await logout('Сессияны тексеру мүмкін болмады. Қайта кіріңіз.'); return; }
    if (aal.currentLevel === 'aal2') { await loadData(); return; }
    if (aal.nextLevel === 'aal2') { await startVerify(); return; }
    await startEnroll();
  } finally { routing = false; }
}

/* ---------------- login ---------------- */
let fails = 0, lockUntil = 0;
$('fLogin').addEventListener('submit', async e => {
  e.preventDefault();
  const f = e.currentTarget, err = $('loginErr');
  const wait = Math.ceil((lockUntil - Date.now()) / 1000);
  if (wait > 0) { err.textContent = 'Қайта көру үшін ' + wait + ' секунд күтіңіз.'; return; }
  const email = $('email').value.trim(), password = $('pass').value;
  if (!email || !password) { err.textContent = 'Email мен құпиясөзді жазыңыз.'; return; }
  err.textContent = ''; busy(f, true);
  let res;
  try { res = await sb.auth.signInWithPassword({ email, password }); } catch (x) { res = { error: { status: 0 } }; }
  $('pass').value = ''; busy(f, false);
  if (res.error) {
    fails++;
    if (fails >= 3) lockUntil = Date.now() + Math.min(300, 15 * Math.pow(2, fails - 3)) * 1000;
    err.textContent = authMessage(res.error);
    return;
  }
  fails = 0; lockUntil = 0; $('email').value = '';
  route();
});

/* ---------------- TOTP enrolment (first login) ---------------- */
let enrollId = null, qrUrl = null;
function clearQr() { if (qrUrl) { URL.revokeObjectURL(qrUrl); qrUrl = null; } $('qrImg').removeAttribute('src'); $('qrImg').hidden = true; $('secret').textContent = ''; }
function setQr(raw) {
  clearQr();
  let svg = String(raw || '');
  if (svg.startsWith('data:')) svg = svg.slice(svg.indexOf(',') + 1);
  if (!svg.trimStart().startsWith('<')) { try { svg = decodeURIComponent(svg); } catch (e) { svg = ''; } }
  if (!/^\s*(<\?xml[^>]*>\s*)?<svg[\s>]/i.test(svg)) return; // only an SVG image is accepted
  qrUrl = URL.createObjectURL(new Blob([svg], { type: 'image/svg+xml' }));
  $('qrImg').src = qrUrl; $('qrImg').hidden = false;
}
async function startEnroll() {
  view('vLoading');
  const lf = await sb.auth.mfa.listFactors();
  if (lf.error) { await logout('Сессия жарамсыз. Қайта кіріңіз.'); return; }
  for (const f of (lf.data.all || [])) {
    if (f.factor_type === 'totp' && f.status !== 'verified') { try { await sb.auth.mfa.unenroll({ factorId: f.id }); } catch (e) {} }
  }
  const { data, error } = await sb.auth.mfa.enroll({ factorType: 'totp', friendlyName: 'Tarih admin ' + new Date().toISOString().slice(0, 16) });
  view('vEnroll'); $('enrollErr').textContent = '';
  if (error || !data || !data.totp) {
    clearQr(); enrollId = null;
    $('enrollErr').textContent = error && error.status === 422 ? 'Supabase-те TOTP қосылмаған: Authentication → Multi-Factor бөлімінде TOTP-ті қосыңыз.' : 'Екі сатылы қорғанысты бастау мүмкін болмады. Бетті жаңартыңыз.';
    return;
  }
  enrollId = data.id; setQr(data.totp.qr_code); $('secret').textContent = data.totp.secret || '';
  $('code1').value = ''; $('code1').focus();
}
$('fEnroll').addEventListener('submit', async e => {
  e.preventDefault();
  const f = e.currentTarget, err = $('enrollErr'), code = $('code1').value.replace(/\s/g, '');
  if (!enrollId) { err.textContent = 'Бетті жаңартып, қайта бастаңыз.'; return; }
  if (!/^\d{6}$/.test(code)) { err.textContent = '6 цифрдан тұратын кодты жазыңыз.'; return; }
  err.textContent = ''; busy(f, true);
  let res; try { res = await sb.auth.mfa.challengeAndVerify({ factorId: enrollId, code }); } catch (x) { res = { error: { status: 0 } }; }
  $('code1').value = ''; busy(f, false);
  if (res.error) { err.textContent = codeMessage(res.error); return; }
  enrollId = null; clearQr(); route();
});

/* ---------------- TOTP check (every login) ---------------- */
let verifyId = null, codeFails = 0, codeLock = 0;
async function startVerify() {
  const { data, error } = await sb.auth.mfa.listFactors();
  if (error) { await logout('Сессия жарамсыз. Қайта кіріңіз.'); return; }
  const f = (data.totp || []).find(x => x.status === 'verified');
  if (!f) { await startEnroll(); return; }
  verifyId = f.id; view('vVerify'); $('verifyErr').textContent = ''; $('code2').value = ''; $('code2').focus();
}
$('fVerify').addEventListener('submit', async e => {
  e.preventDefault();
  const f = e.currentTarget, err = $('verifyErr'), code = $('code2').value.replace(/\s/g, '');
  const wait = Math.ceil((codeLock - Date.now()) / 1000);
  if (wait > 0) { err.textContent = 'Қайта көру үшін ' + wait + ' секунд күтіңіз.'; return; }
  if (!/^\d{6}$/.test(code)) { err.textContent = '6 цифрдан тұратын кодты жазыңыз.'; return; }
  err.textContent = ''; busy(f, true);
  let res; try { res = await sb.auth.mfa.challengeAndVerify({ factorId: verifyId, code }); } catch (x) { res = { error: { status: 0 } }; }
  $('code2').value = ''; busy(f, false);
  if (res.error) {
    codeFails++; if (codeFails >= 3) codeLock = Date.now() + Math.min(300, 15 * Math.pow(2, codeFails - 3)) * 1000;
    if (codeFails >= 8) { await logout('Код тым көп рет қате жазылды. Қайта кіріңіз.'); codeFails = 0; return; }
    err.textContent = codeMessage(res.error); return;
  }
  codeFails = 0; route();
});

/* ---------------- data ---------------- */
const ERAS = DATA.eras.map(e => e.n), CHARS = DATA.chars;
let rows = [], mode = 'games', shown = 200, sortKey = 'created_at', sortDir = -1;
const dtf = (() => { try { return new Intl.DateTimeFormat('kk-KZ', { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' }); } catch (e) { return new Intl.DateTimeFormat(undefined, { dateStyle: 'short', timeStyle: 'short' }); } })();
const fmtDate = s => { const d = new Date(s); return isNaN(d) ? '' : dtf.format(d); };
const fmtTime = t => { if (!Number.isFinite(t)) return ''; const m = Math.floor(t / 60), s = t - m * 60; return m + ':' + (s < 10 ? '0' : '') + s.toFixed(1); };
const qOf = r => (r.coins === null || r.coins === undefined) ? 4 : 5; // results saved before the 5-question update had 4 questions
const norm = s => String(s || '').toLocaleLowerCase('kk').normalize('NFC').trim();

$('fEra').appendChild(new Option('Барлық дәуір', ''));
ERAS.forEach((n, i) => $('fEra').appendChild(new Option(String(i + 1).padStart(2, '0') + ' · ' + n, String(i))));

async function fetchAll() {
  const out = [], page = 1000;
  for (let from = 0; from < 100000; from += page) {
    const { data, error } = await sb.from(CFG.table)
      .select('id,created_at,uid,name,track,time_s,place,correct,coins,arts,score,ch')
      .order('id', { ascending: false }).range(from, from + page - 1);
    if (error) throw error;
    out.push(...data); if (data.length < page) break;
  }
  return out;
}
let loading = false;
async function loadData() {
  if (loading) return; loading = true;
  view('vData'); setNote('Деректер жүктеліп жатыр…');
  try { rows = await fetchAll(); setNote(''); }
  catch (e) {
    rows = [];
    if (e && (e.status === 401 || e.code === 'PGRST301' || e.code === 'PGRST303')) { loading = false; await logout('Сессия мерзімі бітті. Қайта кіріңіз.'); return; }
    setNote('Деректерді жүктеу мүмкін болмады. «Жаңарту» басып көріңіз.', true);
  }
  loading = false; render();
}
function setNote(t, bad) { $('dataNote').textContent = t; $('dataNote').classList.toggle('bad', !!bad); }

function filtered() {
  const era = $('fEra').value, period = $('fPeriod').value, q = norm($('fName').value);
  const since = period === 'all' ? 0 : Date.now() - Number(period) * 864e5;
  return rows.filter(r => (era === '' || r.track === Number(era)) && (!since || new Date(r.created_at).getTime() >= since) && (!q || norm(r.name).includes(q)));
}
function players(list) {
  const m = new Map();
  for (const r of list) {
    const k = norm(r.name);
    let p = m.get(k);
    if (!p) { p = { name: r.name, games: 0, best: 0, correct: 0, total: 0, eras: new Set(), last: r.created_at }; m.set(k, p); }
    p.games++; p.best = Math.max(p.best, r.score || 0); p.correct += r.correct || 0; p.total += qOf(r); p.eras.add(r.track);
    if (r.created_at > p.last) p.last = r.created_at;
  }
  return [...m.values()].map(p => ({ name: p.name, games: p.games, best: p.best, pct: p.total ? Math.round(p.correct / p.total * 100) : 0, eras: p.eras.size, last: p.last }));
}
const COLS = {
  games: [
    { k: 'created_at', t: 'Күні', f: r => fmtDate(r.created_at), cls: 'dim' },
    { k: 'name', t: 'Аты', f: r => r.name, cls: 'nm' },
    { k: 'track', t: 'Дәуір', f: r => ERAS[r.track] || '–' },
    { k: 'ch', t: 'Кейіпкер', f: r => CHARS[r.ch] || '–', cls: 'dim wrap' },
    { k: 'place', t: 'Орын', f: r => r.place, pill: true, cls: 'r' },
    { k: 'time_s', t: 'Уақыт', f: r => fmtTime(r.time_s), cls: 'r' },
    { k: 'correct', t: 'Дұрыс', f: r => r.correct + '/' + qOf(r), cls: 'r' },
    { k: 'coins', t: 'Монета', f: r => r.coins ?? '–', cls: 'r' },
    { k: 'arts', t: 'Артефакт', f: r => r.arts ?? '–', cls: 'r' },
    { k: 'score', t: 'Ұпай', f: r => r.score, cls: 'r' },
    { k: 'uid', t: 'Құрылғы', f: r => String(r.uid || '').slice(0, 6), cls: 'dim' }
  ],
  players: [
    { k: 'name', t: 'Аты', f: p => p.name, cls: 'nm' },
    { k: 'games', t: 'Ойындар', f: p => p.games, cls: 'r' },
    { k: 'best', t: 'Ең жоғары ұпай', f: p => p.best, cls: 'r' },
    { k: 'pct', t: 'Дұрыс жауаптар', f: p => p.pct + '%', cls: 'r' },
    { k: 'eras', t: 'Өткен дәуірлер', f: p => p.eras + '/10', cls: 'r' },
    { k: 'last', t: 'Соңғы ойын', f: p => fmtDate(p.last), cls: 'dim' }
  ]
};
function currentList() {
  const base = filtered();
  const list = mode === 'players' ? players(base) : base.slice();
  const k = sortKey;
  list.sort((a, b) => { const x = a[k], y = b[k]; if (x === y) return 0; if (x === null || x === undefined) return 1; if (y === null || y === undefined) return -1; return (typeof x === 'string' ? x.localeCompare(y, 'kk') : x - y) * sortDir; });
  return { base, list };
}
function render() {
  const { base, list } = currentList();
  // tiles reflect the filtered games
  $('tGames').textContent = String(base.length);
  $('tPlayers').textContent = String(new Set(base.map(r => norm(r.name))).size);
  const tq = base.reduce((s, r) => s + qOf(r), 0), tc = base.reduce((s, r) => s + (r.correct || 0), 0);
  $('tCorrect').textContent = (tq ? Math.round(tc / tq * 100) : 0) + '%';
  $('tBest').textContent = String(base.reduce((m, r) => Math.max(m, r.score || 0), 0));
  // header
  const cols = COLS[mode], thead = $('thead'), tbody = $('tbody');
  thead.textContent = ''; tbody.textContent = '';
  const hr = el('tr');
  cols.forEach(c => { const th = el('th', c.cls === 'r' ? 'r' : ''); const b = el('button', '', c.t); b.type = 'button'; b.setAttribute('aria-sort', sortKey === c.k ? (sortDir > 0 ? 'ascending' : 'descending') : 'none'); b.addEventListener('click', () => { if (sortKey === c.k) sortDir = -sortDir; else { sortKey = c.k; sortDir = (c.k === 'name' || c.k === 'track') ? 1 : -1; } render(); }); th.appendChild(b); hr.appendChild(th); });
  if (mode === 'games') hr.appendChild(el('th', '', ''));
  thead.appendChild(hr);
  if (!list.length) {
    const tr = el('tr'), td = el('td', 'empty'); td.colSpan = cols.length + 1;
    td.textContent = rows.length ? 'Сүзгіге сәйкес нәтиже жоқ.' : 'Әзірге нәтиже жоқ. Ойыншылар ойнағаннан кейін осында шығады. Ойнағандар болса да кесте бос тұрса, SQL-дегі админ email-ін тексеріңіз.';
    tr.appendChild(td); tbody.appendChild(tr); $('bMore').hidden = true; return;
  }
  const frag = document.createDocumentFragment();
  list.slice(0, shown).forEach(r => {
    const tr = el('tr');
    cols.forEach(c => { const td = el('td', c.cls || ''); const v = c.f(r); if (c.pill) td.appendChild(el('span', 'pill p' + Math.min(4, Number(v) || 4), v + '-орын')); else td.textContent = String(v); tr.appendChild(td); });
    if (mode === 'games') { const td = el('td', 'r'); const b = el('button', 'del', 'Өшіру'); b.type = 'button'; b.addEventListener('click', () => removeRow(r)); td.appendChild(b); tr.appendChild(td); }
    frag.appendChild(tr);
  });
  tbody.appendChild(frag);
  $('bMore').hidden = list.length <= shown;
}
['fEra', 'fPeriod'].forEach(id => $(id).addEventListener('change', () => { shown = 200; render(); }));
let searchT = 0; $('fName').addEventListener('input', () => { clearTimeout(searchT); searchT = setTimeout(() => { shown = 200; render(); }, 150); });
document.querySelectorAll('.seg button').forEach(b => b.addEventListener('click', () => {
  mode = b.dataset.view; shown = 200; sortKey = mode === 'players' ? 'best' : 'created_at'; sortDir = -1;
  document.querySelectorAll('.seg button').forEach(x => { const on = x === b; x.classList.toggle('on', on); x.setAttribute('aria-selected', String(on)); });
  render();
}));
$('bMore').addEventListener('click', () => { shown += 300; render(); });
$('bRefresh').addEventListener('click', () => loadData());

/* ---------------- delete one result ---------------- */
function confirmDlg(text) {
  return new Promise(resolve => {
    const d = $('dlg'), yes = $('dlgYes'), no = $('dlgNo'), prev = document.activeElement;
    $('dlgP').textContent = text; d.hidden = false; no.focus();
    const done = v => { d.hidden = true; yes.removeEventListener('click', onYes); no.removeEventListener('click', onNo); document.removeEventListener('keydown', onKey); if (prev && prev.focus) prev.focus(); resolve(v); };
    const onYes = () => done(true), onNo = () => done(false), onKey = e => { if (e.key === 'Escape') done(false); };
    yes.addEventListener('click', onYes); no.addEventListener('click', onNo); document.addEventListener('keydown', onKey);
  });
}
async function removeRow(r) {
  const ok = await confirmDlg('«' + r.name + '» · ' + (ERAS[r.track] || '') + ' · ' + r.score + ' ұпай (' + fmtDate(r.created_at) + '). Бұл жазба біржола өшіріледі.');
  if (!ok) return;
  const { data, error } = await sb.from(CFG.table).delete().eq('id', r.id).select('id');
  if (error || !data || !data.length) { setNote('Жазбаны өшіру мүмкін болмады. Бетті жаңартып, қайталаңыз.', true); return; }
  rows = rows.filter(x => x.id !== r.id); setNote('Жазба өшірілді.'); render();
}

/* ---------------- CSV export (protected against spreadsheet formula injection) ---------------- */
function csvCell(v) { let s = v === null || v === undefined ? '' : String(v); if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; return '"' + s.replace(/"/g, '""') + '"'; }
$('bCsv').addEventListener('click', () => {
  const { list } = currentList();
  const cols = COLS[mode];
  const lines = [cols.map(c => csvCell(c.t)).join(';')];
  for (const r of list) lines.push(cols.map(c => csvCell(c.k === 'uid' ? r.uid : c.f(r))).join(';'));
  const blob = new Blob(['﻿' + lines.join('\r\n')], { type: 'text/csv;charset=utf-8' });
  const url = URL.createObjectURL(blob), a = document.createElement('a');
  a.href = url; a.download = 'tarih-race-' + (mode === 'players' ? 'oiynshylar' : 'natizheler') + '-' + new Date().toISOString().slice(0, 10) + '.csv';
  document.body.appendChild(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(url), 2000);
});

/* ---------------- logout, idle timeout ---------------- */
function wipeView() {
  rows = []; $('thead').textContent = ''; $('tbody').textContent = ''; setNote('');
  ['tGames', 'tPlayers', 'tBest'].forEach(id => { $(id).textContent = '0'; }); $('tCorrect').textContent = '0%';
  enrollId = null; verifyId = null; clearQr(); $('fName').value = '';
}
let loggingOut = false;
async function logout(message) {
  if (loggingOut) return; loggingOut = true;
  try { await sb.auth.signOut(); } catch (e) {}
  wipeStorage(); wipeView(); view('vLogin'); $('loginErr').textContent = message || '';
  loggingOut = false;
}
$('bLogout').addEventListener('click', () => logout('Сіз жүйеден шықтыңыз.'));
if (sb) sb.auth.onAuthStateChange(event => { if (event === 'SIGNED_OUT' && !loggingOut) { wipeStorage(); wipeView(); view('vLogin'); } });

let lastAct = Date.now();
['pointerdown', 'keydown', 'wheel', 'touchstart'].forEach(ev => addEventListener(ev, () => { lastAct = Date.now(); }, { passive: true }));
async function idleCheck() {
  if (Date.now() - lastAct < IDLE_MS) return;
  if (!sb) return;
  const { data: { session } } = await sb.auth.getSession();
  if (session) await logout('Қауіпсіздік үшін 15 минут әрекетсіздіктен кейін жүйеден шықтыңыз.');
}
setInterval(idleCheck, 20000);
document.addEventListener('visibilitychange', () => { if (!document.hidden) idleCheck(); });

route();
})();
