'use strict';
/* The app's pages. UI (kit/renderer/ui.js) gives the helpers, the router and the shared pages; Dash the
   dashboard; SB (util.js, lock.js) the vault-specific helpers. One function per page in UI.views, each
   wrapped in guard() so a locked vault shows the unlock screen instead of an error. */
const { $, $$, esc, tile, linkTile, toast, openModal, closeModal, fmtDate, fmtAgo, store, views, pages, sections, isAdmin } = UI;
const api = window.api;
const SB = window.SB;

// ---------- glossary ---------------------------------------------------------------------------------
Glossary.add({
  'key-file': { term: 'Key file', short: 'A small file that is half of the lock on the vault.',
    long: 'Created when you set the vault up (or change its unlock method). It holds 32 random bytes. The vault key is derived from your passphrase **and** these bytes, so neither alone opens it.\n\nKeep it on a USB stick or another computer, never on the Pi. The Pi only sees it while you unlock.',
    healthy: 'Stored away from the Pi, with a copy somewhere safe.', fix: 'Lost it? Use the [[recovery-key|recovery key]], then change the unlock method to make a new one.', related: ['recovery-key'] },
  'recovery-key': { term: 'Recovery key', short: 'A 40-character code that opens the vault if the other factors are lost.',
    long: 'Shown once when it is made. It wraps the same vault key as your passphrase and key file do, so it is as powerful as both together: keep it on paper in a safe place, not in a file on a computer.\n\nMaking a new one cancels the old one.',
    healthy: 'Printed or written down and stored away from the Pi.', fix: 'Not sure it still exists? Settings → Make a new recovery key.', related: ['key-file'] },
  'auto-lock': { term: 'Auto-lock', short: 'The vault locks itself after a period with no activity.',
    long: 'The vault key lives in the Pi\'s memory only while the vault is unlocked. After the idle time set under Settings (default 15 minutes) it is wiped and everyone must unlock again. A restart of the Pi also locks it.',
    healthy: '5–15 minutes.', related: ['key-file'] },
  'unlock-method': { term: 'Unlock method', short: 'What it takes to open the vault: passphrase, key file or both.',
    long: 'Chosen when the vault is created. **Passphrase + key file** is the strongest: a stolen backup or SD card is useless without both. You can change it later without re-encrypting the entries.', related: ['key-file', 'recovery-key'] },
});

// ---------- helpers -----------------------------------------------------------------------------------
const DAY = 86400000;
const guard = (fn) => async (arg) => {
  const lock = async () => { try { SB.status = await api.vault.status(); } catch { /* keep */ } if (SB.refreshStatus) SB.refreshStatus(); return SB.lockScreen(SB.status, async () => { await SB.refreshStatus(); await loadSettings(); UI.route(); }); };
  const st = await api.vault.status(); SB.status = st;
  if (st.state !== 'unlocked') return lock();
  try { return await fn(arg); } catch (e) { if (/vault is locked/i.test(e.message)) return lock(); throw e; }
};
async function loadSettings() { try { const s = await api.settings.get(); SB.settings = s.vault; SB.allSettings = s; } catch { /* standard accounts may lack it */ } }
const safeUrl = (u) => (/^https?:\/\//i.test(u) ? u : null);
const tabBadge = (t) => `<span class="badge">${esc(t.icon)} ${esc(t.name)}</span>`;
const pwAge = (ts) => { if (!ts) return ''; const d = Math.floor((Date.now() - ts) / DAY), lim = Number((SB.settings || {}).staleDays) || 0; return `<span class="tiny ${lim && d > lim ? 'warn' : 'muted'}">changed ${d < 1 ? 'today' : d + ' day' + (d === 1 ? '' : 's') + ' ago'}</span>`; };
const link = (id, title) => `<a href="#entry/${id}">${esc(title)}</a>`;
const confirmWord = (msg) => confirm(msg);

// ---------- dashboard ---------------------------------------------------------------------------------
const rowsList = (title, href, items, fmt) => `<div class="card"><h3>${title} ${href ? `<a class="right" href="${href}">all →</a>` : ''}</h3><table>${items.map(fmt).join('') || '<tr><td class="muted">Nothing here.</td></tr>'}</table></div>`;
Dash.mount({
  title: 'Dashboard',
  header: ({ d }) => `<div class="livebar"><span class="dot ok"></span>${d.total} entries · ${d.health.passwords} passwords${d.lockInMs != null ? ` · ${UI.term('auto-lock', 'auto-locks')} after ${Math.round(d.lockInMs / 60000)} min of no activity` : ''}</div>`,
  load: async () => ({ d: await api.data.dashboard() }),
  catalog: [
    { type: 'total', group: 'Vault', label: 'Entries', help: 'How many entries the vault holds', sizes: ['s', 'm'], def: 's', render: ({ d }) => linkTile('#vault', tile('', 'Entries', d.total, `${d.perTab.length} tabs`)) },
    { type: 'weak', group: 'Health', label: 'Weak passwords', help: 'Passwords with low estimated strength', sizes: ['s', 'm'], def: 's', rule: { warn: 1, bad: 5 }, render: ({ d, rule }) => linkTile('#health', tile(Cards.colorFor(d.health.weak, rule), 'Weak passwords', d.health.weak, 'low entropy')) },
    { type: 'reused', group: 'Health', label: 'Reused passwords', help: 'The same password used by more than one entry', sizes: ['s', 'm'], def: 's', rule: { warn: 1, bad: 4 }, render: ({ d, rule }) => linkTile('#health', tile(Cards.colorFor(d.health.reused, rule), 'Reused passwords', d.health.reused, 'shared between entries')) },
    { type: 'stale', group: 'Health', label: 'Old passwords', help: 'Passwords not changed for longer than the limit in Settings', sizes: ['s', 'm'], def: 's', rule: { warn: 3, bad: 15 }, render: ({ d, rule }) => linkTile('#health', tile(Cards.colorFor(d.health.stale, rule), 'Old passwords', d.health.stale, `unchanged for ${(SB.settings || {}).staleDays || '∞'} days`)) },
    { type: 'expiring', group: 'Health', label: 'Expiring soon', help: 'Warranties, licences and keys that expire soon', sizes: ['s', 'm'], def: 's', rule: { warn: 1, bad: 3 }, render: ({ d, rule }) => linkTile('#health', tile(Cards.colorFor(d.health.expiring, rule), 'Expiring soon', d.health.expiring, 'dates to watch')) },
    { type: 'trash', group: 'Vault', label: 'Trash', help: 'Deleted entries waiting to be purged', sizes: ['s'], def: 's', render: ({ d }) => linkTile('#trash', tile('', 'In the trash', d.trash, 'restorable')) },
    { type: 'bytab', group: 'Charts', label: 'Entries by tab', help: 'Share of entries per tab', sizes: ['m', 'l', 'xl'], def: 'l', render: ({ d }) => Cards.bars(d.perTab.map(t => ({ k: t.name, n: t.n })), 'Entries by tab', { drill: false }) },
    { type: 'recent', group: 'Lists', label: 'Recently changed', help: 'The entries edited last', sizes: ['l', 'xl'], def: 'l', list: true, render: ({ d, o }) => rowsList('Recently changed', '#vault', d.recent.slice(0, o.limit || 8), r => `<tr><td class="muted nowrap">${fmtAgo(r.updated)}</td><td class="wrap">${link(r.id, r.title)}</td></tr>`) },
    { type: 'favorites', group: 'Lists', label: 'Favorites', help: 'Entries you starred', sizes: ['l', 'xl'], def: 'l', list: true, render: ({ d }) => rowsList('Favorites', '', d.favorites, r => `<tr><td class="wrap">★ ${link(r.id, r.title)}</td></tr>`) },
    { type: 'expirelist', group: 'Lists', label: 'Dates to watch', help: 'Expiring warranties, licences and keys, soonest first', sizes: ['l', 'xl'], def: 'l', render: ({ d }) => rowsList('Dates to watch', '#health', d.expiring, r => `<tr><td class="wrap">${link(r.id, r.title)} <span class="muted">${esc(r.label)}</span></td><td class="nowrap ${r.days < 0 ? 'bad' : r.days < 30 ? 'warn' : 'muted'}">${r.days < 0 ? `expired ${-r.days} d ago` : `in ${r.days} d`}</td></tr>`) },
  ],
  defaults: ['total', 'weak', 'reused', 'stale', 'expiring', { type: 'bytab', size: 'l' }, { type: 'recent', size: 'l' }, 'favorites'],
});
views.dashboard = guard(Dash.render);

// ---------- the vault list: tabs, search, a tree of entries -------------------------------------------------
const openSet = new Set(JSON.parse(store.get('open', '[]') || '[]'));
const saveOpen = () => store.set('open', JSON.stringify([...openSet].slice(-500)));
views.vault = guard(async (arg) => {
  const v = UI.view();
  const [tabs, list] = await Promise.all([api.tabs.list(), api.entries.list()]);
  const tabOf = new Map(tabs.map(t => [t.id, t])), byId = new Map(list.map(e => [e.id, e])), kids = new Map();
  for (const e of list) if (e.parentId && byId.has(e.parentId)) (kids.get(e.parentId) || kids.set(e.parentId, []).get(e.parentId)).push(e);
  const sel = arg === undefined ? store.get('vaultTab', 'all') : arg;
  const tabId = sel === 'all' || !tabOf.has(Number(sel)) ? 'all' : Number(sel);
  store.set('vaultTab', String(tabId));
  const byTitle = (a, b) => (b.favorite - a.favorite) || a.title.localeCompare(b.title, undefined, { numeric: true, sensitivity: 'base' });
  const roots = list.filter(e => !e.parentId || !byId.has(e.parentId) || (tabId !== 'all' && byId.get(e.parentId).tabId !== tabId)).filter(e => tabId === 'all' || e.tabId === tabId).sort(byTitle);
  const detail = (e) => { const t = tabOf.get(e.tabId); const vals = (t ? t.fields : []).filter(f => !['date', 'multiline'].includes(f.type) && e.fields[f.key]).slice(0, 2).map(f => e.fields[f.key]); return vals.join(' · '); };
  const rowHtml = (e, depth, flat) => {
    const t = tabOf.get(e.tabId) || { icon: '?', name: '?' }, k = kids.get(e.id) || [], isOpen = openSet.has(e.id);
    const path = flat ? (() => { const parts = []; let p = byId.get(e.parentId); for (let i = 0; p && i < 20; i++) { parts.unshift(p.title); p = byId.get(p.parentId); } return parts.length ? `<span class="tiny muted">${esc(parts.join(' › '))} › </span>` : ''; })() : '';
    return `<div class="erow" data-id="${e.id}" style="padding-left:${8 + depth * 22}px">
      ${k.length && !flat ? `<button class="caret small" data-toggle="${e.id}" title="${isOpen ? 'Collapse' : 'Expand'}">${isOpen ? '▾' : '▸'}</button>` : '<span class="caret-gap"></span>'}
      <span class="eicon" title="${esc(t.name)}">${esc(t.icon)}</span>
      <div class="emain">${path}<a class="etitle" href="#entry/${e.id}">${esc(e.title)}</a>${e.favorite ? ' <span class="warn">★</span>' : ''}${e.subtitle ? ` <span class="muted">${esc(e.subtitle)}</span>` : ''}
        <div class="tiny muted">${esc(detail(e))}</div></div>
      <div class="ebadges">${(tabId === 'all' || flat || e.tabId !== tabId) ? tabBadge(t) : ''}${e.tags.slice(0, 3).map(x => `<span class="badge">${esc(x)}</span>`).join('')}${k.length ? `<span class="badge c1">${k.length} nested</span>` : ''}</div>
      <div class="eact">${e.quick ? `<button class="small" data-quick="${e.id}" data-ref="${esc(e.quick)}" title="Copy the password">⧉</button>` : ''}<a class="small" href="#new/${e.tabId}/${e.id}" title="Add a nested entry"><button class="small">＋</button></a></div></div>`;
  };
  const tree = (items, depth = 0) => items.sort(byTitle).map(e => rowHtml(e, depth, false) + (openSet.has(e.id) && kids.get(e.id) ? tree([...kids.get(e.id)], depth + 1) : '')).join('');
  const newTab = tabId === 'all' ? (tabs[0] && tabs[0].id) : tabId;
  v.innerHTML = `<h1>Vault</h1>
    <div class="tabbar"><a class="tabbtn ${tabId === 'all' ? 'on' : ''}" href="#vault/all">All <span class="count">${list.length}</span></a>${tabs.map(t => `<a class="tabbtn ${t.id === tabId ? 'on' : ''}" href="#vault/${t.id}">${esc(t.icon)} ${esc(t.name)} <span class="count">${t.count}</span></a>`).join('')}${isAdmin() ? '<a class="tabbtn plus" href="#tabs" title="Manage tabs">⚙</a>' : ''}</div>
    <div class="toolbar"><input type="search" id="q" placeholder="Search titles, fields, notes, tags (never secrets)" autocomplete="off"><span class="muted small" id="qcount"></span><span class="grow"></span>${isAdmin() ? `<button class="small" id="expand">Expand all</button><button class="small" id="collapse">Collapse</button><a href="#new/${newTab}"><button class="primary">New entry</button></a>` : ''}</div>
    <div class="card elist" id="elist"></div>`;
  const box = $('#elist');
  const draw = (ids) => {
    if (ids) { const rows = list.filter(e => ids.has(e.id)).sort(byTitle); box.innerHTML = rows.map(e => rowHtml(e, 0, true)).join('') || '<div class="empty">No entry matches.</div>'; $('#qcount').textContent = `${rows.length} match${rows.length === 1 ? '' : 'es'} in all tabs`; }
    else { box.innerHTML = tree(roots) || `<div class="empty">${list.length ? 'Nothing in this tab yet.' : 'The vault is empty.'}${isAdmin() ? ` <a href="#new/${newTab}">Add the first entry</a>.` : ''}</div>`; $('#qcount').textContent = ''; }
  };
  draw();
  let timer = null;
  $('#q').oninput = (ev) => { clearTimeout(timer); const q = ev.target.value.trim(); timer = setTimeout(async () => { try { draw(q ? new Set(await api.entries.search(q)) : null); } catch (e) { toast(e.message, true); } }, 180); };
  box.onclick = (ev) => {
    const tg = ev.target.closest('[data-toggle]'), qk = ev.target.closest('[data-quick]');
    if (tg) { const id = Number(tg.dataset.toggle); openSet.has(id) ? openSet.delete(id) : openSet.add(id); saveOpen(); draw(); }
    else if (qk) SB.withSecret(Number(qk.dataset.quick), qk.dataset.ref, val => SB.copy(val, 'Password copied'));
    else if (!ev.target.closest('a,button') && ev.target.closest('.erow')) location.hash = '#entry/' + ev.target.closest('.erow').dataset.id;
  };
  if ($('#expand')) { $('#expand').onclick = () => { for (const id of kids.keys()) openSet.add(id); saveOpen(); draw(); }; $('#collapse').onclick = () => { openSet.clear(); saveOpen(); draw(); }; }
});

// ---------- one entry ---------------------------------------------------------------------------------------
let totpTimer = null;
views.entry = guard(async (id) => {
  const v = UI.view();
  clearInterval(totpTimer);
  const [e, tabs, all] = await Promise.all([api.entries.get(Number(id)), api.tabs.list(), api.entries.list()]);
  const tab = tabs.find(t => t.id === e.tabId) || { name: '?', icon: '?', fields: [] };
  const kids = all.filter(x => x.parentId === e.id).sort((a, b) => a.title.localeCompare(b.title));
  const fieldRows = tab.fields.map(fd => {
    if (['password', 'secret', 'totp'].includes(fd.type)) {
      const s = e.secrets[fd.key] || {};
      if (!s.set) return `<tr><td>${esc(fd.label)}</td><td class="muted">—</td></tr>`;
      if (fd.type === 'totp') return `<tr><td>${esc(fd.label)}</td><td><div class="srow"><span class="val mono totp" data-key="${esc(fd.key)}">••• •••</span> <button class="small" data-totp="${esc(fd.key)}">Show code</button> <button class="small" data-totpcopy="${esc(fd.key)}" hidden>Copy</button> <span class="tiny muted totp-left"></span></div></td></tr>`;
      return `<tr><td>${esc(fd.label)}</td><td><div class="srow"><span class="val mono ${fd.multiline ? 'pre' : ''}" data-mask="${SB.MASK}">${SB.MASK}</span> <button class="small" data-reveal="field:${esc(fd.key)}">Show</button> <button class="small" data-copy="field:${esc(fd.key)}" data-what="Copied">Copy</button>${s.history.length ? ` <button class="small" data-hist="${esc(fd.key)}" data-label="${esc(fd.label)}">History (${s.history.length})</button>` : ''} ${fd.type === 'password' ? pwAge(s.changed) : ''}</div>${fd.type === 'password' && s.bits != null ? `<div class="pwmeter">${SB.meterHtml(s.bits)}</div>` : ''}</td></tr>`;
    }
    const val = e.fields[fd.key];
    if (!val) return `<tr><td>${esc(fd.label)}</td><td class="muted">—</td></tr>`;
    let html;
    if (fd.type === 'url') html = safeUrl(val) ? `<a href="${esc(val)}" target="_blank" rel="noopener noreferrer">${esc(val)}</a>` : esc(val);
    else if (fd.type === 'date') { const d = Math.ceil((Date.parse(val + 'T00:00:00') - Date.now()) / DAY); html = `${esc(val)}${fd.expiry ? ` <span class="badge ${d < 0 ? 'bad' : d <= 60 ? 'warn' : ''}">${d < 0 ? `expired ${-d} d ago` : `in ${d} d`}</span>` : ''}`; }
    else html = `<span class="${fd.type === 'multiline' ? 'pre' : ''}">${esc(val)}</span>`;
    return `<tr><td>${esc(fd.label)}</td><td>${html} ${fd.type !== 'date' ? `<button class="small ghost" data-plain="${esc(fd.key)}" title="Copy">⧉</button>` : ''}</td></tr>`;
  }).join('');
  v.innerHTML = `<div class="crumbs"><a href="#vault/${e.tabId}">${esc(tab.icon)} ${esc(tab.name)}</a>${e.path.map(p => ` › <a href="#entry/${p.id}">${esc(p.title)}</a>`).join('')}</div>
    <div class="detail-head"><h1>${esc(e.title)} ${e.favorite ? '<span class="warn">★</span>' : ''}</h1>${e.subtitle ? `<span class="muted">${esc(e.subtitle)}</span>` : ''}<span class="grow"></span>
      ${isAdmin() ? `<a href="#edit/${e.id}"><button class="primary">Edit</button></a><a href="#new/${e.tabId}/${e.id}"><button>Add nested</button></a><button id="eMove">Move</button><button class="danger" id="eDel">Delete</button>` : ''}</div>
    <div class="tiny muted" style="margin:-4px 0 10px">${e.tags.map(t => `<span class="badge">${esc(t)}</span>`).join('')} created ${fmtDate(e.created)} · edited ${fmtAgo(e.updated)}</div>
    <div class="grid2">
      <div>
        <div class="card"><h3>Details</h3><table class="kv dtl">${fieldRows || '<tr><td class="muted">This tab has no fields.</td></tr>'}</table></div>
        ${e.creds.length ? `<div class="card" style="margin-top:14px"><h3>More logins</h3><table class="kv dtl">${e.creds.map(c => `<tr><td>${esc(c.label || 'Login')}${c.url ? `<div class="tiny">${safeUrl(c.url) ? `<a href="${esc(c.url)}" target="_blank" rel="noopener noreferrer">${esc(c.url)}</a>` : esc(c.url)}</div>` : ''}</td><td>${c.user ? `<div>${esc(c.user)} <button class="small ghost" data-user="${esc(c.user)}" title="Copy user name">⧉</button></div>` : ''}${c.set ? `<div class="srow"><span class="val mono" data-mask="${SB.MASK}">${SB.MASK}</span> <button class="small" data-reveal="cred:${c.id}">Show</button> <button class="small" data-copy="cred:${c.id}">Copy</button>${c.history.length ? ` <button class="small" data-hist="cred:${c.id}" data-label="${esc(c.label || 'Login')}">History (${c.history.length})</button>` : ''} ${pwAge(c.changed)}</div>` : '<span class="muted">no password</span>'}</td></tr>`).join('')}</table></div>` : ''}
      </div>
      <div>
        ${e.specs.length ? `<div class="card"><h3>Specs</h3><table class="kv">${e.specs.map(s => `<tr><td>${esc(s.k)}</td><td>${esc(s.v)}</td></tr>`).join('')}</table></div>` : ''}
        ${e.notes ? `<div class="card" style="margin-top:${e.specs.length ? 14 : 0}px"><h3>Notes</h3><div class="pre">${esc(e.notes)}</div></div>` : ''}
        <div class="card" style="margin-top:${e.specs.length || e.notes ? 14 : 0}px"><h3>Nested under this ${isAdmin() ? `<a class="right" href="#new/${e.tabId}/${e.id}">＋ add</a>` : ''}</h3><table>${kids.map(k => `<tr><td class="wrap">${(tabs.find(t => t.id === k.tabId) || {}).icon || ''} ${link(k.id, k.title)}${k.subtitle ? ` <span class="muted">${esc(k.subtitle)}</span>` : ''}</td><td class="nowrap">${k.tabId !== e.tabId ? tabBadge(tabs.find(t => t.id === k.tabId) || { icon: '', name: '?' }) : ''}</td></tr>`).join('') || '<tr><td class="muted">Nothing nested here. A server can hold its VMs and services, a NAS its shares.</td></tr>'}</table></div>
      </div>
    </div>`;
  SB.wireSecrets(v, e.id);
  $$('[data-plain]', v).forEach(b => { b.onclick = () => SB.copy(e.fields[b.dataset.plain], 'Copied', false); });
  $$('[data-user]', v).forEach(b => { b.onclick = () => SB.copy(b.dataset.user, 'Copied', false); });
  $$('[data-hist]', v).forEach(b => { b.onclick = () => {
    const key = b.dataset.hist, s = key.startsWith('cred:') ? e.creds.find(c => 'cred:' + c.id === key) : e.secrets[key];
    const card = openModal(`<h2>Earlier values</h2><div class="path">${esc(b.dataset.label)} · the last ${s.history.length} before the current one</div><table class="kv">${s.history.map((h, i) => `<tr><td>${fmtDate(h.t)}<div class="tiny muted">until it was replaced</div></td><td><div class="srow"><span class="val mono" data-mask="${SB.MASK}">${SB.MASK}</span> <button class="small" data-reveal="hist:${esc(key)}:${i}">Show</button> <button class="small" data-copy="hist:${esc(key)}:${i}">Copy</button></div></td></tr>`).join('')}</table><div class="actions"><span class="grow"></span><button id="hClose">Close</button></div>`);
    $('#hClose', card).onclick = closeModal; SB.wireSecrets(card, e.id);
  }; });
  // authenticator code: fetched on demand, refreshed at each 30-second boundary while it is showing
  const totpRow = (key) => $(`.totp[data-key="${key}"]`, v);
  $$('[data-totp]', v).forEach(b => { b.onclick = async () => {
    const key = b.dataset.totp, out = totpRow(key), left = out.parentElement.querySelector('.totp-left'), cp = out.parentElement.querySelector('[data-totpcopy]');
    clearInterval(totpTimer);
    let remaining = 0, code = '';
    const fetchCode = async () => { try { const r = await api.entries.totp(e.id, key); code = r.code; remaining = r.remaining; out.textContent = `${code.slice(0, 3)} ${code.slice(3)}`; cp.hidden = false; } catch (ex) { toast(ex.message, true); clearInterval(totpTimer); } };
    await fetchCode(); b.textContent = 'Refresh';
    cp.onclick = () => SB.copy(code, 'Code copied');
    totpTimer = setInterval(() => { if (!document.body.contains(out) || UI.current() !== 'entry') return clearInterval(totpTimer); remaining--; left.textContent = `${Math.max(remaining, 0)} s`; if (remaining <= 0) fetchCode(); }, 1000);
    left.textContent = `${remaining} s`;
  }; });
  if ($('#eDel')) $('#eDel').onclick = async () => { if (!confirmWord(`Move "${e.title}"${kids.length ? ` and its ${kids.length} nested entr${kids.length === 1 ? 'y' : 'ies'}` : ''} to the trash? You can restore it from the Trash page.`)) return; try { await api.entries.delete(e.id); toast('Moved to the trash'); location.hash = '#vault/' + e.tabId; } catch (ex) { toast(ex.message, true); } };
  if ($('#eMove')) $('#eMove').onclick = () => {
    const banned = new Set([e.id]); (function walk(id) { for (const k of all.filter(x => x.parentId === id)) { banned.add(k.id); walk(k.id); } })(e.id);
    const card = openModal(`<h2>Move "${esc(e.title)}"</h2><div class="field"><label>Tab</label><select id="mvTab">${tabs.map(t => `<option value="${t.id}" ${t.id === e.tabId ? 'selected' : ''}>${esc(t.icon)} ${esc(t.name)}</option>`).join('')}</select></div>
      <div class="field"><label>Nested under</label><select id="mvParent"><option value="">(top level)</option>${all.filter(x => !banned.has(x.id)).sort((a, b) => a.title.localeCompare(b.title)).map(x => `<option value="${x.id}" ${x.id === e.parentId ? 'selected' : ''}>${esc(x.title)}</option>`).join('')}</select></div>
      <div class="actions"><span class="grow"></span><button id="mvCancel">Cancel</button><button class="primary" id="mvGo">Move</button></div>`);
    $('#mvCancel', card).onclick = closeModal;
    $('#mvGo', card).onclick = async () => { try { await api.entries.move(e.id, { tabId: Number($('#mvTab', card).value), parentId: $('#mvParent', card).value ? Number($('#mvParent', card).value) : null }); closeModal(); toast('Moved'); UI.route(); } catch (ex) { toast(ex.message, true); } };
  };
});

// ---------- add / edit an entry ----------------------------------------------------------------------------
const SPEC_PRESETS = ['CPU', 'RAM', 'Storage', 'GPU', 'OS', 'Network', 'Power', 'Firmware', 'Ports', 'Form factor', 'Capacity', 'Serial'];
async function editor(mode, arg) {
  const v = UI.view();
  const tabs = await api.tabs.list();
  let existing = null, draft;
  if (mode === 'edit') {
    existing = await api.entries.get(Number(arg));
    draft = { id: existing.id, tabId: existing.tabId, parentId: existing.parentId, title: existing.title, subtitle: existing.subtitle, favorite: existing.favorite, tags: existing.tags.join(', '), fields: { ...existing.fields }, secrets: {}, creds: existing.creds.map(c => ({ id: c.id, label: c.label, user: c.user, url: c.url, has: c.set })), specs: existing.specs.map(s => ({ ...s })), notes: existing.notes };
  } else {
    const [tabId, parentId] = String(arg || '').split('/').map(Number);
    draft = { id: null, tabId: tabs.find(t => t.id === tabId) ? tabId : tabs[0].id, parentId: parentId || null, title: '', subtitle: '', favorite: false, tags: '', fields: {}, secrets: {}, creds: [], specs: [], notes: '' };
  }
  const parent = draft.parentId ? await api.entries.get(draft.parentId).catch(() => null) : null;
  const collect = () => {
    draft.tabId = Number($('#eTab').value); draft.title = $('#eTitle').value; draft.subtitle = $('#eSub').value; draft.favorite = $('#eFav').checked; draft.tags = $('#eTags').value; draft.notes = $('#eNotes').value;
    const tab = tabs.find(t => t.id === draft.tabId);
    for (const fd of tab.fields) {
      const el = $(`[data-f="${fd.key}"]`); if (!el) continue;
      if (el.dataset.secret) { if (el.dataset.dirty) draft.secrets[fd.key] = el.value; } else draft.fields[fd.key] = el.value;
    }
    draft.creds = $$('.credrow').map(r => { const c = { id: r.dataset.id || undefined, label: $('.cl', r).value, user: $('.cu', r).value, url: $('.cr', r).value, has: r.dataset.has === '1' }; const sec = $('.cs', r); if (sec.dataset.dirty) c.secret = sec.value; return c; });
    draft.specs = $$('.specrow').map(r => ({ k: $('.sk', r).value, v: $('.sv', r).value }));
  };
  const render = () => {
    const tab = tabs.find(t => t.id === draft.tabId);
    const input = (fd) => {
      const val = draft.fields[fd.key] ?? '';
      if (['password', 'secret', 'totp'].includes(fd.type)) {
        const had = existing && existing.secrets[fd.key] && existing.secrets[fd.key].set && existing.tabId === draft.tabId, dirty = fd.key in draft.secrets;
        const common = `data-f="${esc(fd.key)}" data-secret="1" ${dirty ? 'data-dirty="1"' : ''} placeholder="${had && !dirty ? '•••••• unchanged (type to replace)' : fd.type === 'totp' ? 'base32 seed or otpauth:// link' : ''}" autocomplete="new-password" spellcheck="false"`;
        return `<div class="secretin">${fd.multiline ? `<textarea rows="3" ${common}>${esc(draft.secrets[fd.key] || '')}</textarea>` : `<input type="password" ${common} value="${esc(draft.secrets[fd.key] || '')}">`}
          <div class="inline">${fd.multiline ? '' : '<button type="button" class="small" data-eye>Show</button>'}${fd.type === 'password' ? '<button type="button" class="small" data-gen>Generate</button>' : ''}${had && dirty ? '<button type="button" class="small" data-undo>Keep the old one</button>' : ''}<span class="meterwrap tiny"></span></div></div>`;
      }
      if (fd.type === 'select') return `<select data-f="${esc(fd.key)}"><option value=""></option>${(fd.options || []).map(o => `<option ${o === val ? 'selected' : ''}>${esc(o)}</option>`).join('')}</select>`;
      if (fd.type === 'multiline' || fd.multiline) return `<textarea rows="3" data-f="${esc(fd.key)}">${esc(val)}</textarea>`;
      return `<input type="${fd.type === 'date' ? 'date' : fd.type === 'number' ? 'number' : 'text'}" data-f="${esc(fd.key)}" value="${esc(val)}" ${fd.type === 'url' ? 'placeholder="https://"' : ''} autocomplete="off">`;
    };
    v.innerHTML = `<div class="crumbs">${parent ? `Nested under <a href="#entry/${parent.id}">${esc(parent.title)}</a>` : '<a href="#vault">Vault</a>'}</div>
      <h1>${mode === 'edit' ? 'Edit entry' : 'New entry'}</h1>
      <form class="form" id="eForm">
        <div class="card">
          <div class="field"><label>Tab</label><select id="eTab">${tabs.map(t => `<option value="${t.id}" ${t.id === draft.tabId ? 'selected' : ''}>${esc(t.icon)} ${esc(t.name)}</option>`).join('')}</select></div>
          <div class="field"><label>Title</label><input type="text" id="eTitle" value="${esc(draft.title)}" required autocomplete="off"></div>
          <div class="field"><label>Subtitle</label><input type="text" id="eSub" value="${esc(draft.subtitle)}" placeholder="optional: a short description" autocomplete="off"></div>
          <div class="field"><label>Tags</label><input type="text" id="eTags" value="${esc(draft.tags)}" placeholder="comma separated" autocomplete="off"></div>
          <div class="field"><label>Favorite</label><input type="checkbox" id="eFav" ${draft.favorite ? 'checked' : ''}></div>
        </div>
        <div class="section-head"><h2>${esc(tab.name)} details</h2></div>
        <div class="card">${tab.fields.map(fd => `<div class="field"><label>${esc(fd.label)}</label>${input(fd)}</div>`).join('') || '<div class="muted">This tab has no fields; add some under Tabs.</div>'}</div>
        <div class="section-head"><h2>More logins</h2><span class="muted small">other accounts on the same thing: IPMI, a web UI, SSH…</span><span class="grow"></span><button type="button" class="small" id="addCred">＋ Add login</button></div>
        <div id="creds">${draft.creds.map(c => `<div class="card credrow" data-id="${esc(c.id || '')}" data-has="${c.has ? 1 : 0}"><div class="grid2"><input class="cl" placeholder="Label (IPMI, web UI…)" value="${esc(c.label)}"><input class="cu" placeholder="User name" value="${esc(c.user)}" autocomplete="off"></div><div class="grid2" style="margin-top:8px"><input class="cr" placeholder="Address (optional)" value="${esc(c.url)}"><div class="inline"><input type="password" class="cs" data-secret="1" ${c.secret !== undefined ? 'data-dirty="1"' : ''} placeholder="${c.has && c.secret === undefined ? '•••••• unchanged' : 'Password'}" value="${esc(c.secret || '')}" autocomplete="new-password" style="flex:1"><button type="button" class="small" data-eye>Show</button><button type="button" class="small" data-gen>Generate</button><button type="button" class="small danger" data-rm>✕</button></div></div></div>`).join('')}</div>
        <div class="section-head"><h2>Specs</h2><span class="muted small">hardware details and any other facts</span><span class="grow"></span><select id="specPreset" class="small"><option value="">＋ add spec…</option>${SPEC_PRESETS.map(p => `<option>${p}</option>`).join('')}<option value="__other">Other…</option></select></div>
        <div class="card" id="specs">${draft.specs.map(s => `<div class="specrow inline" style="margin-bottom:6px"><input class="sk" placeholder="Name" value="${esc(s.k)}" style="width:34%"><input class="sv" placeholder="Value" value="${esc(s.v)}" style="flex:1"><button type="button" class="small danger" data-rm>✕</button></div>`).join('') || '<div class="muted small">No specs yet.</div>'}</div>
        <div class="section-head"><h2>Notes</h2></div>
        <div class="card"><textarea id="eNotes" rows="6" style="width:100%" placeholder="Anything else. Notes are encrypted like the rest, but are searchable, so keep passwords in the fields above.">${esc(draft.notes)}</textarea></div>
        <div class="inline" style="margin:14px 0 40px"><button class="primary" id="eSave">${mode === 'edit' ? 'Save changes' : 'Create entry'}</button><button type="button" id="eCancel">Cancel</button><span class="bad small" id="eErr"></span></div>
      </form>`;
    wire();
  };
  const wire = () => {
    $('#eTab').onchange = () => { collect(); render(); };
    $('#eCancel').onclick = () => { location.hash = existing ? '#entry/' + existing.id : '#vault'; };
    const meter = (inp) => { const w = inp.closest('.secretin') && inp.closest('.secretin').querySelector('.meterwrap'); if (w && inp.type !== 'textarea' && inp.dataset.f && /password/i.test((tabs.find(t => t.id === draft.tabId).fields.find(f => f.key === inp.dataset.f) || {}).type || '')) w.innerHTML = inp.value ? SB.meterHtml(window.strengthBits(inp.value)) : ''; };
    $$('[data-secret]').forEach(inp => { inp.addEventListener('input', () => { inp.dataset.dirty = '1'; meter(inp); }); });
    $$('[data-eye]').forEach(b => { b.onclick = () => { const i = b.closest('.secretin, .inline').querySelector('input'); i.type = i.type === 'password' ? 'text' : 'password'; b.textContent = i.type === 'password' ? 'Show' : 'Hide'; }; });
    $$('[data-gen]').forEach(b => { b.onclick = () => SB.generatorModal((pw) => { const i = b.closest('.secretin, .inline').querySelector('input'); i.value = pw; i.dataset.dirty = '1'; i.type = 'text'; meter(i); const eye = b.closest('.secretin, .inline').querySelector('[data-eye]'); if (eye) eye.textContent = 'Hide'; }); });
    $$('[data-undo]').forEach(b => { b.onclick = () => { collect(); const key = b.closest('.secretin').querySelector('[data-f]').dataset.f; delete draft.secrets[key]; render(); }; });
    $$('[data-rm]').forEach(b => { b.onclick = () => { collect(); const row = b.closest('.credrow, .specrow'); const rows = row.classList.contains('credrow') ? draft.creds : draft.specs; const idx = [...row.parentElement.children].indexOf(row); rows.splice(idx, 1); render(); }; });
    $('#addCred').onclick = () => { collect(); draft.creds.push({ label: '', user: '', url: '', has: false }); render(); };
    $('#specPreset').onchange = (ev) => { collect(); const val = ev.target.value; if (!val) return; draft.specs.push({ k: val === '__other' ? '' : val, v: '' }); render(); const rows = $$('.specrow'); const last = rows[rows.length - 1]; if (last) $(val === '__other' ? '.sk' : '.sv', last).focus(); };
    $('#eForm').onsubmit = async (ev) => {
      ev.preventDefault(); collect();
      const payload = { id: draft.id, tabId: draft.tabId, title: draft.title, subtitle: draft.subtitle, favorite: draft.favorite, tags: draft.tags.split(','), fields: draft.fields, secrets: draft.secrets, creds: draft.creds.map(c => ({ id: c.id, label: c.label, user: c.user, url: c.url, secret: c.secret })), specs: draft.specs, notes: draft.notes };
      if (mode === 'new' || draft.parentId !== (existing && existing.parentId)) payload.parentId = draft.parentId;
      $('#eSave').disabled = true;
      try { const saved = await api.entries.save(payload); toast('Saved'); location.hash = '#entry/' + saved.id; } catch (e) { $('#eSave').disabled = false; $('#eErr').textContent = e.message; }
    };
    $('#eTitle').focus();
  };
  render();
}
views.edit = guard((id) => editor('edit', id));
views.new = guard((arg) => editor('new', arg));

// ---------- tabs ---------------------------------------------------------------------------------------------
const TYPE_LABEL = { text: 'Text', url: 'Link', multiline: 'Several lines', number: 'Number', date: 'Date', select: 'Choice', password: 'Password (tracked)', secret: 'Secret (hidden)', totp: 'Authenticator seed' };
views.tabs = guard(async () => {
  const v = UI.view();
  const tabs = await api.tabs.list();
  v.innerHTML = `<h1>Tabs</h1><p class="lead">A tab is a kind of thing you keep: its name, icon and the fields every entry in it has. Change a template whenever you like; entries keep their values by field.</p>
    <div class="toolbar"><button class="primary" id="tNew">New tab</button></div>
    <div class="grid2">${tabs.map((t, i) => `<div class="card"><h3>${esc(t.icon)} ${esc(t.name)} <span class="right muted">${t.count} entr${t.count === 1 ? 'y' : 'ies'}</span></h3><div class="tiny muted" style="margin-bottom:8px">${t.fields.map(f => esc(f.label)).join(' · ') || 'no fields'}</div><div class="inline"><button class="small" data-edit="${t.id}">Edit fields</button><button class="small" data-up="${t.id}" ${i === 0 ? 'disabled' : ''}>↑</button><button class="small" data-down="${t.id}" ${i === tabs.length - 1 ? 'disabled' : ''}>↓</button><span class="grow"></span><button class="small danger" data-del="${t.id}">Delete</button></div></div>`).join('')}</div>`;
  $('#tNew').onclick = () => tabEditor({ name: '', icon: '☰', fields: [{ label: 'Username', type: 'text' }, { label: 'Password', type: 'password' }] });
  $$('[data-edit]', v).forEach(b => { b.onclick = () => tabEditor(structuredClone(tabs.find(t => t.id === Number(b.dataset.edit)))); });
  const move = async (id, d) => { const ids = tabs.map(t => t.id), i = ids.indexOf(id); ids.splice(i + d, 0, ids.splice(i, 1)[0]); await api.tabs.reorder(ids); UI.route(); };
  $$('[data-up]', v).forEach(b => { b.onclick = () => move(Number(b.dataset.up), -1); });
  $$('[data-down]', v).forEach(b => { b.onclick = () => move(Number(b.dataset.down), 1); });
  $$('[data-del]', v).forEach(b => { b.onclick = async () => {
    const t = tabs.find(x => x.id === Number(b.dataset.del));
    let to = null;
    if (t.count || true) { const others = tabs.filter(x => x.id !== t.id); if (!others.length) return toast('Keep at least one tab', true); const ans = prompt(`Delete the "${t.name}" tab.${t.count ? ` Its ${t.count} entries move to another tab. ` : ' '}Type the name of the tab that receives them (or leave empty if it is empty):\n${others.map(o => o.name).join(', ')}`, ''); if (ans === null) return; if (ans) { const hit = others.find(o => o.name.toLowerCase() === ans.trim().toLowerCase()); if (!hit) return toast('No tab with that name', true); to = hit.id; } }
    try { await api.tabs.delete(t.id, to); toast('Tab deleted'); UI.route(); } catch (e) { toast(e.message, true); }
  }; });
});
function tabEditor(tab) {
  const ICONS = ['▦', '◍', '✉', '⚿', '☰', '⌂', '☁', '⚙', '$', '★', '♥', '⚑', '✈', '☎', '▶', '◆'];
  tab.fields = (tab.fields || []).map(f => ({ ...f, options: Array.isArray(f.options) ? f.options.join(', ') : f.options || '' }));
  const draw = () => {
    const card = openModal(`<h2>${tab.id ? 'Edit tab' : 'New tab'}</h2>
      <div class="field"><label>Name</label><input type="text" id="tnName" value="${esc(tab.name)}" autocomplete="off"></div>
      <div class="field"><label>Icon</label><div class="inline">${ICONS.map(i => `<span class="chip ${i === tab.icon ? '' : 'off'}" data-icon="${i}" style="text-decoration:none">${i}</span>`).join('')}</div></div>
      <h3 style="margin:14px 0 6px">Fields</h3>
      <div id="tnFields">${tab.fields.map((f, i) => `<div class="tfrow" data-i="${i}"><input class="fl" placeholder="Label" value="${esc(f.label)}"><select class="ft">${Object.entries(TYPE_LABEL).map(([k, l]) => `<option value="${k}" ${k === f.type ? 'selected' : ''}>${l}</option>`).join('')}</select>
        <span class="fx">${f.type === 'select' ? `<input class="fo" placeholder="options, comma separated" value="${esc(f.options)}">` : f.type === 'date' ? `<label class="inline small"><input type="checkbox" class="fe" ${f.expiry ? 'checked' : ''}> warns when it expires</label>` : (f.type === 'text' || f.type === 'secret') ? `<label class="inline small"><input type="checkbox" class="fm" ${f.multiline ? 'checked' : ''}> several lines</label>` : ''}</span>
        <button class="small" data-fup="${i}" ${i === 0 ? 'disabled' : ''}>↑</button><button class="small" data-fdown="${i}" ${i === tab.fields.length - 1 ? 'disabled' : ''}>↓</button><button class="small danger" data-frm="${i}">✕</button></div>`).join('')}</div>
      <div class="inline" style="margin-top:8px"><button class="small" id="tnAdd">＋ Add field</button></div>
      <div class="actions"><span class="grow"></span><button id="tnCancel">Cancel</button><button class="primary" id="tnSave">Save</button></div><div class="bad small" id="tnErr"></div>`);
    const sync = () => {
      tab.name = $('#tnName', card).value;
      $$('.tfrow', card).forEach(r => { const f = tab.fields[Number(r.dataset.i)]; f.label = $('.fl', r).value; f.type = $('.ft', r).value; if ($('.fo', r)) f.options = $('.fo', r).value; if ($('.fe', r)) f.expiry = $('.fe', r).checked; if ($('.fm', r)) f.multiline = $('.fm', r).checked; });
    };
    $$('[data-icon]', card).forEach(c => { c.onclick = () => { sync(); tab.icon = c.dataset.icon; draw(); }; });
    $$('.ft', card).forEach(s => { s.onchange = () => { sync(); draw(); }; });
    $('#tnAdd', card).onclick = () => { sync(); tab.fields.push({ label: '', type: 'text', options: '' }); draw(); };
    $$('[data-frm]', card).forEach(b => { b.onclick = () => { sync(); tab.fields.splice(Number(b.dataset.frm), 1); draw(); }; });
    $$('[data-fup]', card).forEach(b => { b.onclick = () => { sync(); const i = Number(b.dataset.fup); tab.fields.splice(i - 1, 0, tab.fields.splice(i, 1)[0]); draw(); }; });
    $$('[data-fdown]', card).forEach(b => { b.onclick = () => { sync(); const i = Number(b.dataset.fdown); tab.fields.splice(i + 1, 0, tab.fields.splice(i, 1)[0]); draw(); }; });
    $('#tnCancel', card).onclick = closeModal;
    $('#tnSave', card).onclick = async () => { sync(); try { await api.tabs.save(tab); closeModal(); toast('Tab saved'); UI.route(); } catch (e) { $('#tnErr', card).textContent = e.message; } };
  };
  draw();
}

// ---------- health -----------------------------------------------------------------------------------------------
views.health = guard(async () => {
  const v = UI.view();
  const h = await api.vault.health();
  const sec = (title, help, rows, cols) => `<div class="section-head"><h2>${title}</h2><span class="muted small">${help}</span></div><div class="card scroll-x"><table><tbody>${rows.map(cols).join('') || '<tr><td class="muted">Nothing to fix. ✓</td></tr>'}</tbody></table></div>`;
  v.innerHTML = `<h1>Health</h1><p class="lead">Checked on the Pi while the vault is open: nothing here leaves the server and no password is shown.</p>
    <div class="tiles">${tile(Cards.colorFor(h.weak.length, { warn: 1, bad: 5 }), 'Weak', h.weak.length, `of ${h.passwords} passwords`)}${tile(Cards.colorFor(h.reused.length, { warn: 1, bad: 4 }), 'Reused', h.reused.length, 'sharing a password')}${tile(Cards.colorFor(h.stale.length, { warn: 3, bad: 15 }), 'Old', h.stale.length, `unchanged > ${(SB.settings || {}).staleDays || '∞'} days`)}${tile(Cards.colorFor(h.expiring.length, { warn: 1, bad: 3 }), 'Expiring', h.expiring.length, 'dates to watch')}</div>
    ${sec('Expiring and expired', 'warranties, licences, keys', h.expiring, r => `<tr><td class="wrap">${link(r.id, r.title)} <span class="muted">${esc(r.label)}</span></td><td class="nowrap">${esc(r.date)}</td><td class="nowrap ${r.days < 0 ? 'bad' : r.days < 30 ? 'warn' : 'muted'}">${r.days < 0 ? `expired ${-r.days} d ago` : `in ${r.days} d`}</td></tr>`)}
    ${sec('Weak passwords', 'estimated entropy below the limit in Settings', h.weak, r => `<tr><td class="wrap">${link(r.id, r.title)} <span class="muted">${esc(r.label)}</span></td><td class="nowrap bad">~${r.bits} bits</td><td class="nowrap"><a href="#edit/${r.id}">change</a></td></tr>`)}
    ${sec('Reused passwords', 'the same password in more than one place; entries with the same group number share one', h.reused, r => `<tr><td class="wrap">${link(r.id, r.title)} <span class="muted">${esc(r.label)}</span></td><td class="nowrap">group ${r.group}</td><td class="nowrap warn">shared with ${r.with} other${r.with === 1 ? '' : 's'}</td></tr>`)}
    ${sec('Old passwords', 'not changed for a long time', h.stale, r => `<tr><td class="wrap">${link(r.id, r.title)} <span class="muted">${esc(r.label)}</span></td><td class="nowrap warn">${r.days} days</td><td class="nowrap"><a href="#edit/${r.id}">change</a></td></tr>`)}`;
});

// ---------- trash ---------------------------------------------------------------------------------------------------
views.trash = guard(async () => {
  const v = UI.view();
  const rows = await api.entries.trash();
  v.innerHTML = `<h1>Trash</h1><p class="lead">Deleted entries stay here, still encrypted, for ${(SB.settings || {}).trashDays || 'ever'}${(SB.settings || {}).trashDays ? ' days' : ''}. Restoring brings back everything that was nested inside too.</p>
    ${isAdmin() && rows.length ? '<div class="toolbar"><button class="danger" id="trEmpty">Empty the trash</button></div>' : ''}
    <div class="card scroll-x"><table><thead><tr><th>Entry</th><th>Tab</th><th>Deleted</th><th>Items</th><th></th></tr></thead><tbody>${rows.map(r => `<tr><td class="wrap"><b>${esc(r.title)}</b>${r.subtitle ? ` <span class="muted">${esc(r.subtitle)}</span>` : ''}</td><td>${esc(r.tabName)}</td><td class="muted">${fmtAgo(r.deleted)}</td><td>${r.items}</td><td class="nowrap">${isAdmin() ? `<button class="small" data-restore="${r.id}">Restore</button> <button class="small danger" data-purge="${r.id}">Delete forever</button>` : ''}</td></tr>`).join('') || '<tr><td colspan="5" class="muted">The trash is empty.</td></tr>'}</tbody></table></div>`;
  $$('[data-restore]', v).forEach(b => { b.onclick = async () => { try { await api.entries.restore(Number(b.dataset.restore)); toast('Restored'); UI.route(); } catch (e) { toast(e.message, true); } }; });
  $$('[data-purge]', v).forEach(b => { b.onclick = async () => { if (!confirm('Delete this for good? It cannot be restored.')) return; try { await api.entries.purge([Number(b.dataset.purge)]); toast('Deleted for good'); UI.route(); } catch (e) { toast(e.message, true); } }; });
  if ($('#trEmpty')) $('#trEmpty').onclick = async () => { if (!confirm(`Permanently delete all ${rows.length} item(s) in the trash?`)) return; try { await api.entries.purge(null); toast('Trash emptied'); UI.route(); } catch (e) { toast(e.message, true); } };
});

// ---------- activity (the vault's own audit trail) ----------------------------------------------------------------------
const ACTIONS = { vault_created: 'Vault created', unlock: 'Unlocked', unlock_failed: 'Failed unlock', unlock_blocked: 'Unlock blocked (too many failures)', lock: 'Locked', autolock: 'Auto-locked (idle)', reveal: 'Secret shown or copied', totp: 'Authenticator code shown', entry_created: 'Entry created', entry_saved: 'Entry edited', entry_moved: 'Entry moved', entry_trashed: 'Moved to trash', entry_restored: 'Restored from trash', entries_purged: 'Deleted for good', csv_import: 'CSV imported', tab_created: 'Tab created', tab_saved: 'Tab edited', tab_deleted: 'Tab deleted', unlock_method_changed: 'Unlock method changed', recovery_key_renewed: 'New recovery key', backup_downloaded: 'Backup downloaded', vault_reset: 'Empty vault reset' };
views.activity = guard(async () => {
  const v = UI.view();
  const rows = await api.vault.audit(500);
  const cls = (a) => (/failed|blocked/.test(a) ? 'bad' : /reveal|totp|method|recovery|purged|backup|reset|csv/.test(a) ? 'warn' : '');
  v.innerHTML = `<h1>Activity</h1><p class="lead">Who unlocked the vault and who looked at which secret. Entry names are shown only while the vault is open; the log itself never holds a secret.</p>
    <div class="card scroll-x"><table><thead><tr><th>When</th><th>What</th><th>Entry</th><th>Who</th><th>Address</th><th>Detail</th></tr></thead><tbody>${rows.map(r => `<tr><td class="muted nowrap">${fmtDate(r.ts)}</td><td class="${cls(r.action)}">${esc(ACTIONS[r.action] || r.action)}</td><td class="wrap">${r.entry ? (r.entry.tab ? link(r.entry_id, r.entry.title) : esc(r.entry.title)) : ''}</td><td>${esc(r.actor || '')}</td><td class="muted">${esc(r.ip || '')}</td><td class="muted tiny">${esc(r.detail || '')}</td></tr>`).join('') || '<tr><td colspan="6" class="muted">Nothing yet.</td></tr>'}</tbody></table></div>`;
});

// ---------- settings -------------------------------------------------------------------------------------------------------
views.settings = guard(async () => {
  const v = UI.view();
  const [s, st, tabs, stats] = await Promise.all([api.settings.get(), api.vault.status(), api.tabs.list(), api.db.stats()]);
  SB.settings = s.vault;
  const notif = sections.notifications(s, { unlockFailed: 'Several unlock attempts fail in a row', dailySummary: 'A summary of weak, reused and expiring items each morning (counts only)' });
  const ha = sections.homeAssistant('Read-only status JSON for REST sensors: entry count, weak / reused / old / expiring counts and whether the vault is locked. Never any content:');
  const look = sections.appearance();
  const n = (id, val, min, max, w = 80) => `<input type="number" id="${id}" min="${min}" max="${max}" value="${val}" style="width:${w}px">`;
  v.innerHTML = `<h1>Settings</h1><div class="form">
    <div class="section-head"><h2>Vault</h2></div>
    <div class="card">
      <div class="field"><label>${UI.term('unlock-method', 'Unlock method')}</label><div><b>${esc(SB.modeName(st.mode))}</b>${st.keyFileId ? ` · key file <span class="mono">${esc(st.keyFileId)}</span>` : ''} · ${st.hasRecovery ? 'recovery key set' : '<span class="warn">no recovery key</span>'}
        <div class="inline" style="margin-top:8px"><button id="sChange">Change unlock method…</button><button id="sRecovery">Make a new recovery key</button></div></div></div>
      <div class="field"><label>${UI.term('auto-lock', 'Auto-lock')} after</label><div class="inline">${n('vAuto', s.vault.autoLockMinutes, 0, 1440)} minutes without activity (0 = never; not advised)</div></div>
      <div class="field"><label>Clipboard clears after</label><div class="inline">${n('vClip', s.vault.clipboardClearSeconds, 0, 600)} seconds (0 = leave it)</div></div>
      <div class="field"><label>Shown secrets hide after</label><div class="inline">${n('vReveal', s.vault.revealSeconds, 3, 300)} seconds</div></div>
      <div class="field"><label>Password is "old" after</label><div class="inline">${n('vStale', s.vault.staleDays, 0, 3650, 90)} days (0 = never)</div></div>
      <div class="field"><label>Password is "weak" below</label><div class="inline">${n('vWeak', s.vault.weakBits, 20, 128)} bits</div></div>
      <div class="field"><label>Expiry warning</label><div class="inline">${n('vExp', s.vault.expiringDays, 0, 730)} days ahead</div></div>
      <div class="field"><label>Trash is emptied after</label><div class="inline">${n('vTrash', s.vault.trashDays, 0, 3650, 90)} days (0 = keep forever)</div></div>
      <div class="field"><label>Nightly backup at</label><input type="time" id="gBackup" value="${esc(s.backup.time)}" style="width:120px"><div class="hint">An encrypted copy next to the database; the newest 10 are kept. Copy them off the Pi too.</div></div>
      <div class="inline"><button class="primary" id="vSave">Save</button></div>
    </div>
    <div class="section-head"><h2>Backup and import</h2></div>
    <div class="card">
      <div class="field"><label>Encrypted backup</label><div><button id="sBackup">Download a backup</button><div class="hint">A complete copy of the database. It is still encrypted: restoring it needs the same passphrase and key file (or the recovery key). To restore, stop the service and replace <span class="mono">strongbox.db</span>.</div></div></div>
      <div class="field"><label>Import a CSV</label><div><div class="inline"><select id="iTab">${tabs.map(t => `<option value="${t.id}">${esc(t.icon)} ${esc(t.name)}</option>`).join('')}</select><input type="file" id="iFile" accept=".csv,text/csv"><button id="iGo">Import</button></div><div class="hint">From Chrome, Edge, Firefox, Bitwarden, 1Password or KeePass exports (name, url, username, password, notes). <b>Delete the CSV afterwards</b>: it holds every password in clear text.</div></div></div>
      ${stats.entries === 0 ? '<div class="field"><label>Start over</label><div><button class="danger" id="sReset">Reset the empty vault</button><div class="hint">Only offered while the vault holds no entries: lets you choose a different unlock method from scratch.</div></div></div>' : ''}
    </div>
    ${notif.html}${ha.html}${look.html}</div>`;
  const save = async (patch, msg = 'Saved') => { try { const r = await api.settings.set(patch); SB.settings = r.vault; toast(msg); } catch (e) { toast(e.message, true); } };
  $('#vSave').onclick = () => save({ vault: { autoLockMinutes: Number($('#vAuto').value), clipboardClearSeconds: Number($('#vClip').value), revealSeconds: Number($('#vReveal').value), staleDays: Number($('#vStale').value), weakBits: Number($('#vWeak').value), expiringDays: Number($('#vExp').value), trashDays: Number($('#vTrash').value) }, backup: { time: $('#gBackup').value } });
  notif.wire(save); ha.wire(); look.wire();
  $('#sChange').onclick = () => { const card = openModal('<div id="wizBox"></div>'); SB.wizard($('#wizBox', card), { change: true, hasRecovery: st.hasRecovery, cancel: closeModal, run: (o) => api.vault.rewrap(o), done: () => { closeModal(); toast('Unlock method changed'); UI.route(); } }); };
  $('#sRecovery').onclick = async () => { if (!confirm('Make a new recovery key? The old one stops working.')) return; try { const key = await api.vault.newRecovery(); const card = openModal(`<h2>New recovery key</h2><p class="warnbox">Shown once. The old key no longer works.</p><div class="secret" style="word-break:break-all">${esc(key)}</div><div class="inline" style="margin-top:10px"><button id="rkCopy">Copy</button><button id="rkPrint">Print</button></div><div class="actions"><span class="grow"></span><button class="primary" id="rkDone">I have saved it</button></div>`); $('#rkCopy', card).onclick = () => SB.writeClipboard(key).then(ok => toast(ok ? 'Copied' : 'Copy blocked', !ok)); $('#rkPrint', card).onclick = () => { const w = window.open('', '_blank', 'width=520,height=380'); if (!w) return toast('Allow pop-ups to print', true); w.document.write(`<pre style="font:18px Consolas,monospace;padding:24px">Strongbox recovery key\n${new Date().toDateString()}\n\n${key}\n\nKeep this paper somewhere safe.</pre>`); w.document.close(); w.print(); }; $('#rkDone', card).onclick = () => { closeModal(); UI.route(); }; } catch (e) { toast(e.message, true); } };
  $('#sBackup').onclick = async () => { try { const b = await api.vault.backup(); SB.download(b.name, b.base64, 'application/octet-stream', true); toast('Backup downloaded'); } catch (e) { toast(e.message, true); } };
  $('#iGo').onclick = async () => { const f = $('#iFile').files[0]; if (!f) return toast('Choose a CSV file first', true); if (f.size > 5e6) return toast('That file is too large', true); if (!confirm(`Import "${f.name}" into the chosen tab?`)) return; try { const r = await api.entries.importCsv(Number($('#iTab').value), await f.text()); toast(`${r.added} imported${r.skipped ? `, ${r.skipped} skipped` : ''}. Now delete that CSV file.`); } catch (e) { toast(e.message, true); } };
  if ($('#sReset')) $('#sReset').onclick = async () => { if (!confirm('Reset the vault? There is nothing in it, so nothing is lost.')) return; try { await api.vault.resetEmpty(); toast('Vault reset'); location.hash = '#dashboard'; UI.route(); } catch (e) { toast(e.message, true); } };
});

// ---------- kit pages ---------------------------------------------------------------------------------------------------------
views.system = pages.system;
views.log = pages.log;
views.security = pages.security;
views.about = pages.about({ blurb: 'A password and credential vault for the home lab: hardware logins, website and e-mail accounts, hardware and software keys, nested items and your own tabs. Everything is encrypted on the Pi with a key that only exists in memory while the vault is unlocked.', credits: [['Cryptography', "Node's built-in crypto: scrypt, HKDF, AES-256-GCM"]] });

// ---------- boot ---------------------------------------------------------------------------------------------------------------
window.addEventListener('hashchange', () => { SB.wizardActive = false; });
api.vault.onLocked(() => { if (SB.status) SB.status.state = 'locked'; if (SB.refreshStatus) SB.refreshStatus(); if (SB.wizardActive) return; toast('The vault locked'); UI.route(); });
api.vault.onChanged(() => { if (SB.refreshStatus) SB.refreshStatus(); if (SB.wizardActive) return; if (['vault', 'dashboard', 'trash', 'health', 'activity', 'tabs'].includes(UI.current()) && !Dash.editing()) UI.route(); });
UI.init({
  home: 'dashboard',
  nav: [
    { group: 'Vault', items: [
      { view: 'dashboard', label: 'Dashboard', icon: '◧' },
      { view: 'vault', label: 'Vault', icon: '⚿' },
      { view: 'health', label: 'Health', icon: '♥' },
      { view: 'trash', label: 'Trash', icon: '⌫' },
    ] },
    { group: 'Manage', items: [
      { view: 'tabs', label: 'Tabs', icon: '▤', roles: ['admin'] },
      { view: 'activity', label: 'Activity', icon: '≣', roles: ['admin'] },
    ] },
    { group: 'System', items: [
      { view: 'system', label: 'System', icon: '☰', pill: 'sysPill' },
      { view: 'log', label: 'Log', icon: '≣', roles: ['admin'] },
      { view: 'security', label: 'Security', icon: '⛨', pill: 'secPill', pillClass: 'bad' },
      { view: 'settings', label: 'Settings', icon: '⚙', roles: ['admin'] },
      { view: 'about', label: 'About', icon: 'ⓘ', pill: 'updatePill', pillClass: 'accent' },
    ] },
  ],
  // `entry`, `edit` and `new` are pages reached from lists, not sidebar items; this keeps their routes allowed for the roles that may see them.
  standardRoleText: 'open the vault and read it (every look at a secret is logged), but not add, edit or delete.',
  logHint: 'on the Pi also: journalctl -u strongbox -f',
  onReady: async () => { await loadSettings(); SB.lockBox(); },
});
