'use strict';
// The app's core: tabs, entries, the vault lock and everything that happens to them. Both shells host this;
// nothing in here may require Electron or HTTP.
//
// Every handler is registered through `api(channel, fn)`: `fn(actor, ...args)` where actor is
// { user, ip } (the web shell passes the signed-in account and client address; the core alone passes
// nulls). Data handlers also check that the vault is unlocked. Nothing secret is ever put in a log line,
// a notification, an audit row or a list: secrets leave this file only through entries:reveal / entries:totp.
const crypto = require('crypto');
const fs = require('fs');
const { createCore } = require('../../kit/main/core');
const { totp, base32Decode } = require('../../kit/server/totp');
const meta = require('../app.json');
const { Vault } = require('./vault');
const T = require('./templates');
const { parseCsv, mapHeaders } = require('./csvin');

const DAY = 86400000;
const LOCKED = 'The vault is locked';
const SCHEMA = `
CREATE TABLE IF NOT EXISTS vault_meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS tabs (
  id    INTEGER PRIMARY KEY,
  sort  INTEGER NOT NULL DEFAULT 0,
  blob  BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS entries (
  id        INTEGER PRIMARY KEY,
  tab_id    INTEGER NOT NULL,
  parent_id INTEGER,
  created   INTEGER NOT NULL,
  updated   INTEGER NOT NULL,
  deleted   INTEGER,
  blob      BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS entries_parent ON entries(parent_id);
CREATE INDEX IF NOT EXISTS entries_tab ON entries(tab_id);
CREATE TABLE IF NOT EXISTS prefs (
  k     TEXT PRIMARY KEY,
  blob  BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS vault_audit (
  id        INTEGER PRIMARY KEY,
  ts        INTEGER NOT NULL,
  action    TEXT NOT NULL,
  entry_id  INTEGER,
  detail    TEXT,
  actor     TEXT,
  ip        TEXT
);
`;
// Append-only: never edit an old entry, add a new { version, name, sql }.
const MIGRATIONS = [];

const DEFAULTS = {
  vault: { autoLockMinutes: 15, clipboardClearSeconds: 30, revealSeconds: 20, staleDays: 365, weakBits: 50, expiringDays: 60, trashDays: 30, kdfLog2N: 17, genPresets: [] },
  backup: { time: '03:30' },
  notify: { events: { unlockFailed: true, dailySummary: false } },
};

const clip = (v, n) => String(v == null ? '' : v).slice(0, n);
const EMPTY = Buffer.alloc(0);

function createService({ dataDir, log = () => {}, send = () => {} }) {
  const core = createCore({ app: meta, dataDir, log, send, defaults: DEFAULTS, schema: SCHEMA, migrations: MIGRATIONS, counts: ['entries', 'tabs'] });
  const { db, settings, notify } = core;
  const cfg = () => settings.get().vault;
  const vault = new Vault({ db, log, send, settings: cfg });
  const API = {};
  /** Register a channel. `data: true` wraps it in the unlocked check. */
  const api = (ch, fn, { data = true } = {}) => {
    API[ch] = data ? (a, ...args) => { vault.require(); return fn(a, ...args); } : fn;
    core.h(ch, (...args) => API[ch]({ user: null, ip: null }, ...args));
  };
  const audit = (a, action, entryId = null, detail = null) => {
    try { db.run('INSERT INTO vault_audit(ts, action, entry_id, detail, actor, ip) VALUES(?,?,?,?,?,?)', Date.now(), action, entryId, detail, (a && a.user) || null, (a && a.ip) || null); } catch (e) { log('audit: ' + e.message); }
  };
  const changed = (extra = {}) => send('vault:changed', extra);

  // ---- reading -----------------------------------------------------------------------------
  const openTab = (r) => ({ id: r.id, sort: r.sort, ...vault.open(r.blob, `tab/${r.id}`) });
  const tabList = () => db.all('SELECT id, sort, blob FROM tabs ORDER BY sort, id').map(openTab);
  const tabMap = () => new Map(tabList().map(t => [t.id, t]));
  const rowOf = (id) => db.get('SELECT * FROM entries WHERE id=?', Number(id));
  const openEntry = (r) => vault.open(r.blob, `entry/${r.id}`);
  const blank = () => ({ title: '', subtitle: '', fields: {}, creds: [], specs: [], nics: [], notes: '', tags: [], favorite: false, changed: {}, hist: {} });
  /** Everything not in the trash, decrypted: [{ row, e }]. */
  const everything = (trash = false) => db.all(`SELECT * FROM entries WHERE deleted IS ${trash ? 'NOT ' : ''}NULL ORDER BY id`).map(row => ({ row, e: { ...blank(), ...openEntry(row) } }));
  const tabOfRow = (row, tabs) => tabs.get(row.tab_id) || { id: row.tab_id, name: '(missing tab)', icon: '?', fields: [] };

  const plainFields = (e, tab, full) => {
    const out = {};
    for (const fd of tab.fields) {
      if (T.SECRET_TYPES.has(fd.type)) continue;
      const v = e.fields[fd.key];
      if (v === undefined || v === '') continue;
      out[fd.key] = !full && (fd.type === 'multiline' || fd.multiline) ? String(v).slice(0, 200) : v;
    }
    return out;
  };
  // The secret a row's copy button copies: the first password that is set, else the first login's.
  const quickRef = (e, tab) => { const fd = tab.fields.find(f => f.type === 'password' && e.fields[f.key]); if (fd) return 'field:' + fd.key; const c = e.creds.find(x => x.secret); return c ? 'cred:' + c.id : null; };
  const light = (row, e, tab) => ({ id: row.id, tabId: row.tab_id, parentId: row.parent_id, title: e.title, subtitle: e.subtitle, tags: e.tags, favorite: !!e.favorite, created: row.created, updated: row.updated, fields: plainFields(e, tab, false), accounts: e.creds.length, quick: quickRef(e, tab) });
  function full(row, e, tab) {
    const secrets = {};
    for (const fd of tab.fields) {
      if (!T.SECRET_TYPES.has(fd.type)) continue;
      const v = e.fields[fd.key];
      secrets[fd.key] = { set: !!v, changed: e.changed[fd.key] || null, bits: fd.type === 'password' && v ? T.strengthBits(v) : undefined, history: (e.hist[fd.key] || []).map(h => ({ t: h.t })) };
    }
    const path = []; let p = row.parent_id;
    for (let i = 0; p && i < 50; i++) { const pr = rowOf(p); if (!pr) break; path.unshift({ id: pr.id, title: openEntry(pr).title }); p = pr.parent_id; }
    return {
      ...light(row, e, tab), deleted: row.deleted || null, fields: plainFields(e, tab, true), secrets, path,
      creds: e.creds.map(c => ({ id: c.id, label: c.label, user: c.user, url: c.url, note: c.note || '', hasTotp: !!c.totp, set: !!c.secret, changed: e.changed['cred:' + c.id] || null, bits: c.secret ? T.strengthBits(c.secret) : undefined, history: (e.hist['cred:' + c.id] || []).map(h => ({ t: h.t })) })),
      specs: e.specs, nics: e.nics, notes: e.notes,
    };
  }
  const present = (id) => { const row = rowOf(id); if (!row) throw new Error('No such entry'); const tabs = tabMap(); return full(row, { ...blank(), ...openEntry(row) }, tabOfRow(row, tabs)); };

  // ---- writing -----------------------------------------------------------------------------
  function descendants(id, deleted = false) {
    const out = []; const queue = [Number(id)];
    while (queue.length) { const pid = queue.shift(); for (const r of db.all(`SELECT id FROM entries WHERE parent_id=? AND deleted IS ${deleted ? 'NOT ' : ''}NULL`, pid)) { out.push(r.id); queue.push(r.id); } }
    return out;
  }
  function checkParent(id, parentId) {
    if (!parentId) return null;
    const pr = rowOf(parentId);
    if (!pr || pr.deleted) throw new Error('That parent entry does not exist');
    if (id && (Number(parentId) === Number(id) || descendants(id).includes(Number(parentId)))) throw new Error('An entry cannot sit inside itself');
    return pr.id;
  }
  const cleanValue = (fd, v) => {
    if (fd.type === 'date') return /^\d{4}-\d{2}-\d{2}$/.test(String(v)) ? String(v) : '';
    if (fd.type === 'select') return (fd.options || []).includes(v) ? v : '';
    if (fd.type === 'ip') return T.normIp(v);
    if (fd.type === 'mac') return T.normMac(v);
    if (fd.type === 'port') return T.normPort(v);
    return clip(v, fd.type === 'multiline' || fd.multiline ? 20000 : 500).trim();
  };
  function cleanSecret(fd, v) {
    let s = clip(v, fd.multiline ? 20000 : 2000);
    if (fd.type === 'totp') {
      const m = /[?&]secret=([A-Za-z2-7=]+)/i.exec(s); if (m) s = m[1];
      s = s.replace(/[\s-]/g, '').toUpperCase();
      if (s && (!/^[A-Z2-7]+=*$/.test(s) || s.length < 8)) throw new Error('That is not a valid authenticator seed (base32 letters and digits, or an otpauth:// link)');
    }
    return s;
  }
  /** Moves the old value into the history and stamps the change time; the caller stores the new value. */
  function rotate(e, ck, oldV, newV, now, row, track) {
    if (oldV === newV) return false;
    if (track && oldV) { const h = (e.hist[ck] = e.hist[ck] || []); h.unshift({ v: oldV, t: e.changed[ck] || (row ? row.created : now) }); h.length = Math.min(h.length, 5); }
    e.changed[ck] = now;
    return true;
  }
  function saveEntry(a, input = {}, { audited = true, inTx = false } = {}) {
    const now = Date.now(), tabs = tabMap();
    const title = clip(input.title, 200).trim();
    if (!title) throw new Error('An entry needs a title');
    const id = Number(input.id) || null;
    const old = id ? rowOf(id) : null;
    if (id && !old) throw new Error('No such entry');
    const tabId = Number(input.tabId || (old && old.tab_id));
    const tab = tabs.get(tabId);
    if (!tab) throw new Error('Choose a type for this entry');
    const parentId = checkParent(id, 'parentId' in input ? input.parentId : (old && old.parent_id));
    const prev = old ? { ...blank(), ...openEntry(old) } : blank();
    const e = { ...prev, title, subtitle: clip(input.subtitle, 200).trim(), fields: { ...prev.fields }, notes: clip(input.notes, 100000), favorite: !!input.favorite, changed: { ...prev.changed }, hist: structuredClone(prev.hist), creds: [] };
    e.tags = [...new Set((Array.isArray(input.tags) ? input.tags : []).map(t => clip(t, 40).trim().toLowerCase()).filter(Boolean))].slice(0, 30);
    e.specs = (Array.isArray(input.specs) ? input.specs : []).map(s => ({ k: clip(s.k, 60).trim(), v: clip(s.v, 300).trim() })).filter(s => s.k || s.v).slice(0, 100);
    e.nics = (Array.isArray(input.nics) ? input.nics : []).map(n => ({ label: clip(n.label, 60).trim(), ip: T.normIp(n.ip), mac: T.normMac(n.mac) })).filter(n => n.label || n.ip || n.mac).slice(0, 30);
    for (const fd of tab.fields) {
      if (T.SECRET_TYPES.has(fd.type)) {
        if (input.secrets && typeof input.secrets[fd.key] === 'string') {
          const nv = cleanSecret(fd, input.secrets[fd.key]);
          if (rotate(e, fd.key, prev.fields[fd.key] || '', nv, now, old, fd.type === 'password')) e.fields[fd.key] = nv;
        }
      } else if (input.fields && fd.key in input.fields) e.fields[fd.key] = cleanValue(fd, input.fields[fd.key]);
    }
    const prevCreds = new Map(prev.creds.map(c => [c.id, c]));
    for (const c of (Array.isArray(input.creds) ? input.creds : []).slice(0, 50)) {
      const pc = c.id && prevCreds.get(c.id);
      const cid = pc ? pc.id : crypto.randomBytes(6).toString('hex');
      const out = { id: cid, label: clip(c.label, 80).trim(), user: clip(c.user, 200).trim(), url: clip(c.url, 300).trim(), note: clip(c.note, 300).trim(), secret: pc ? pc.secret : '', totp: pc ? pc.totp || '' : '' };
      if (typeof c.totp === 'string') { const nt = cleanSecret({ type: 'totp' }, c.totp); if (nt !== out.totp) { out.totp = nt; e.changed['cred:' + cid + ':totp'] = now; } }
      if (typeof c.secret === 'string') { const nv = clip(c.secret, 2000); if (rotate(e, 'cred:' + cid, out.secret, nv, now, old, true)) out.secret = nv; }
      e.creds.push(out);
    }
    for (const k of Object.keys(e.changed)) if (k.startsWith('cred:') && !e.creds.some(c => k === 'cred:' + c.id || k === 'cred:' + c.id + ':totp')) { delete e.changed[k]; delete e.hist[k]; }
    if (JSON.stringify(e).length > 400000) throw new Error('That entry is too large');
    const write = () => {
      let eid = id;
      if (!eid) eid = Number(db.run('INSERT INTO entries(tab_id, parent_id, created, updated, blob) VALUES(?,?,?,?,?)', tabId, parentId, now, now, EMPTY).lastInsertRowid);
      else db.run('UPDATE entries SET tab_id=?, parent_id=?, updated=? WHERE id=?', tabId, parentId, now, eid);
      db.run('UPDATE entries SET blob=? WHERE id=?', vault.seal(e, `entry/${eid}`), eid);
      if (audited) audit(a, id ? 'entry_saved' : 'entry_created', eid);
      return eid;
    };
    return inTx ? write() : db.transaction(write);
  }

  // ---- tabs --------------------------------------------------------------------------------
  function writeTab(tab, id = null, sort = null) {
    const clean = T.cleanTab(tab);
    if (!id) {
      const max = db.get('SELECT COALESCE(MAX(sort), -1) m FROM tabs').m;
      id = Number(db.run('INSERT INTO tabs(sort, blob) VALUES(?, ?)', sort == null ? max + 1 : sort, EMPTY).lastInsertRowid);
    }
    db.run('UPDATE tabs SET blob=? WHERE id=?', vault.seal(clean, `tab/${id}`), id);
    return id;
  }
  const seedTabs = () => { db.transaction(() => { T.DEFAULT_TABS.forEach((t, i) => writeTab(t, null, i)); }); db.kvSet('seededTabs', T.DEFAULT_TABS.map(t => t.builtin)); };
  /** Default types added in later versions appear once in an existing vault, right after the type that precedes them in the defaults. */
  function ensureDefaultTabs() {
    if (!db.kvGet('portFieldMigrated', false)) { // v0.5: Services > Port is a port field (it can say "behind Caddy")
      db.transaction(() => { for (const t of tabList()) if (t.builtin === 'services' && t.fields.some(fd => fd.key === 'port' && fd.type === 'text')) writeTab({ ...t, fields: t.fields.map(fd => (fd.key === 'port' && fd.type === 'text' ? { ...fd, type: 'port' } : fd)) }, t.id); db.kvSet('portFieldMigrated', true); });
    }
    const done = new Set(db.kvGet('seededTabs', []));
    if (T.DEFAULT_TABS.every(d => done.has(d.builtin))) return false;
    let added = false;
    db.transaction(() => {
      for (const [i, d] of T.DEFAULT_TABS.entries()) {
        if (done.has(d.builtin)) continue;
        done.add(d.builtin);
        const list = tabList();
        if (list.some(t => t.builtin === d.builtin)) continue;
        const id = writeTab(d, null, 1e6), prevKey = i ? T.DEFAULT_TABS[i - 1].builtin : null;
        const order = list.map(t => t.id), at = prevKey ? list.findIndex(t => t.builtin === prevKey) : -1;
        order.splice(at + 1, 0, id);
        order.forEach((tid, k) => db.run('UPDATE tabs SET sort=? WHERE id=?', k, tid));
        added = true;
      }
      db.kvSet('seededTabs', [...done]);
    });
    return added;
  }

  api('tabs:list', () => {
    const counts = new Map(db.all('SELECT tab_id, COUNT(*) n FROM entries WHERE deleted IS NULL GROUP BY tab_id').map(r => [r.tab_id, r.n]));
    return tabList().map(t => ({ ...t, count: counts.get(t.id) || 0 }));
  });
  api('tabs:save', (a, tab = {}) => {
    const id = Number(tab.id) || null;
    if (id && !db.get('SELECT id FROM tabs WHERE id=?', id)) throw new Error('No such type');
    const prev = id ? tabMap().get(id) : null;
    const newId = writeTab({ ...tab, builtin: prev && prev.builtin }, id);
    audit(a, id ? 'tab_saved' : 'tab_created', null, `tab ${newId}`); changed();
    return tabList().find(t => t.id === newId);
  });
  api('tabs:reorder', (a, ids) => { db.transaction(() => { (ids || []).forEach((id, i) => db.run('UPDATE tabs SET sort=? WHERE id=?', i, Number(id))); }); changed(); return true; });
  api('tabs:delete', (a, id, moveTo = null) => {
    id = Number(id);
    const n = db.get('SELECT COUNT(*) n FROM entries WHERE tab_id=?', id).n;
    if (n && !(moveTo && Number(moveTo) !== id && db.get('SELECT id FROM tabs WHERE id=?', Number(moveTo)))) throw new Error(`This type holds ${n} entr${n === 1 ? 'y' : 'ies'} (counting the trash); choose another type to move them to`);
    if (db.get('SELECT COUNT(*) n FROM tabs').n <= 1) throw new Error('Keep at least one type');
    db.transaction(() => { if (n) db.run('UPDATE entries SET tab_id=? WHERE tab_id=?', Number(moveTo), id); db.run('DELETE FROM tabs WHERE id=?', id); });
    audit(a, 'tab_deleted', null, `tab ${id}, ${n} entries moved`); changed();
    return true;
  });

  // ---- entries -----------------------------------------------------------------------------
  api('entries:list', () => { const tabs = tabMap(); return everything().map(({ row, e }) => light(row, e, tabOfRow(row, tabs))); });
  api('entries:search', (a, q) => {
    const words = String(q || '').toLowerCase().split(/\s+/).filter(Boolean);
    if (!words.length) return [];
    const tabs = tabMap();
    return everything().filter(({ row, e }) => {
      const tab = tabOfRow(row, tabs);
      const hay = [e.title, e.subtitle, e.tags.join(' '), e.notes, e.specs.map(s => `${s.k} ${s.v}`).join(' '), e.creds.map(c => `${c.label} ${c.user} ${c.url} ${c.note || ''}`).join(' '), e.nics.map(n => `${n.label} ${n.ip} ${n.mac}`).join(' '), tab.name, ...tab.fields.filter(fd => !T.SECRET_TYPES.has(fd.type)).map(fd => e.fields[fd.key] || '')].join('\n').toLowerCase();
      return words.every(w => hay.includes(w));
    }).map(({ row }) => row.id);
  });
  api('entries:get', (a, id) => present(id));
  api('entries:save', (a, input) => { const id = saveEntry(a, input); changed({ id }); return present(id); });
  api('entries:move', (a, id, to = {}) => {
    const row = rowOf(id); if (!row) throw new Error('No such entry');
    const tabId = Number(to.tabId || row.tab_id);
    if (!db.get('SELECT id FROM tabs WHERE id=?', tabId)) throw new Error('No such type');
    const parentId = checkParent(row.id, 'parentId' in to ? to.parentId : row.parent_id);
    db.run('UPDATE entries SET tab_id=?, parent_id=?, updated=? WHERE id=?', tabId, parentId, Date.now(), row.id);
    audit(a, 'entry_moved', row.id); changed({ id: row.id });
    return present(row.id);
  });
  api('entries:reveal', (a, id, ref) => {
    const row = rowOf(id); if (!row) throw new Error('No such entry');
    const e = { ...blank(), ...openEntry(row) };
    const m = /^(field|cred|hist):(.+)$/.exec(String(ref || '')); if (!m) throw new Error('Nothing to reveal');
    let value, detail = String(ref);
    if (m[1] === 'field') value = e.fields[m[2]];
    else if (m[1] === 'cred') { const c = e.creds.find(x => x.id === m[2]); value = c && c.secret; }
    else { const cut = m[2].lastIndexOf(':'); const h = (e.hist[m[2].slice(0, cut)] || [])[Number(m[2].slice(cut + 1))]; value = h && h.v; detail = 'hist:' + m[2]; }
    if (!value) throw new Error('That value is empty');
    audit(a, 'reveal', row.id, detail);
    return value;
  });
  api('entries:totp', (a, id, key) => {
    const row = rowOf(id); if (!row) throw new Error('No such entry');
    const e = openEntry(row), ck = String(key);
    const seed = ck.startsWith('cred:') ? ((e.creds || []).find(x => 'cred:' + x.id === ck) || {}).totp : (e.fields || {})[ck];
    if (!seed) throw new Error('No authenticator seed set');
    const now = Date.now();
    const recent = db.get("SELECT id FROM vault_audit WHERE action='totp' AND entry_id=? AND ts>? LIMIT 1", row.id, now - 120000);
    if (!recent) audit(a, 'totp', row.id, String(key));
    if (!base32Decode(seed).length) throw new Error('The stored seed is not valid');
    return { code: totp(seed, now), remaining: 30 - Math.floor(now / 1000) % 30 };
  });
  api('entries:delete', (a, id) => {
    const row = rowOf(id); if (!row || row.deleted) throw new Error('No such entry');
    const ids = [row.id, ...descendants(row.id)], ts = Date.now();
    db.transaction(() => { for (const i of ids) db.run('UPDATE entries SET deleted=? WHERE id=?', ts, i); });
    audit(a, 'entry_trashed', row.id, `${ids.length} item(s)`); changed({ id: row.id, deleted: true });
    return ids.length;
  });
  api('entries:trash', () => {
    const tabs = tabMap(), rows = everything(true), at = new Map(rows.map(r => [r.row.id, r.row.deleted]));
    return rows.filter(({ row }) => !row.parent_id || at.get(row.parent_id) !== row.deleted).map(({ row, e }) => ({ ...light(row, e, tabOfRow(row, tabs)), deleted: row.deleted, tabName: tabOfRow(row, tabs).name, items: 1 + rows.filter(r => r.row.deleted === row.deleted && r.row.id !== row.id && descendants(row.id, true).includes(r.row.id)).length }));
  });
  api('entries:restore', (a, id) => {
    const row = rowOf(id); if (!row || !row.deleted) throw new Error('That entry is not in the trash');
    const ids = [row.id, ...descendants(row.id, true).filter(i => rowOf(i).deleted === row.deleted)];
    const parent = row.parent_id && rowOf(row.parent_id);
    db.transaction(() => { for (const i of ids) db.run('UPDATE entries SET deleted=NULL WHERE id=?', i); if (!parent || parent.deleted) db.run('UPDATE entries SET parent_id=NULL WHERE id=?', row.id); });
    audit(a, 'entry_restored', row.id, `${ids.length} item(s)`); changed({ id: row.id });
    return ids.length;
  });
  function purge(ids) {
    const all = new Set();
    for (const id of ids) { const row = rowOf(id); if (!row || !row.deleted) continue; all.add(row.id); for (const d of descendants(row.id, true)) if (rowOf(d).deleted === row.deleted) all.add(d); }
    db.transaction(() => { for (const i of all) db.run('DELETE FROM entries WHERE id=?', i); });
    return all.size;
  }
  api('entries:purge', (a, ids = null) => {
    const list = ids && ids.length ? ids : db.all('SELECT id FROM entries WHERE deleted IS NOT NULL').map(r => r.id);
    const n = purge(list); audit(a, 'entries_purged', null, `${n} item(s)`); changed();
    return n;
  });
  api('entries:importCsv', (a, tabId, text) => {
    const tab = tabMap().get(Number(tabId)); if (!tab) throw new Error('Choose a type to import into');
    const rows = parseCsv(text);
    if (rows.length < 2) throw new Error('The file has no rows');
    if (rows.length > 5001) throw new Error('At most 5000 rows per import');
    const h = mapHeaders(rows[0]);
    if (h.title === undefined && h.url === undefined) throw new Error('No name or url column found in the first row');
    const find = (pred) => tab.fields.find(pred);
    const target = {
      url: find(fd => fd.type === 'url'), user: find(fd => fd.key === 'user') || find(fd => /user|login|address/i.test(fd.label) && fd.type === 'text'),
      pass: find(fd => fd.type === 'password'), totp: find(fd => fd.type === 'totp'),
    };
    let added = 0, skipped = 0;
    db.transaction(() => {
      for (const r of rows.slice(1)) {
        const val = (k) => (h[k] === undefined ? '' : String(r[h[k]] || '').trim());
        let title = val('title') || val('url').replace(/^https?:\/\//, '').replace(/\/.*$/, '');
        if (!title) { skipped++; continue; }
        const input = { title, tabId: tab.id, notes: val('notes'), fields: {}, secrets: {} };
        if (target.url && val('url')) input.fields[target.url.key] = val('url');
        if (target.user && val('user')) input.fields[target.user.key] = val('user');
        if (target.pass && val('pass')) input.secrets[target.pass.key] = val('pass');
        if (target.totp && val('totp')) { try { input.secrets[target.totp.key] = cleanSecret(target.totp, val('totp')); } catch { /* skip an unreadable seed */ } }
        saveEntry(a, input, { audited: false, inTx: true }); added++;
      }
    });
    audit(a, 'csv_import', null, `${added} added, ${skipped} skipped`); changed();
    return { added, skipped, mapped: Object.fromEntries(Object.entries(target).filter(([, v]) => v).map(([k, v]) => [k, v.label])) };
  });

  // ---- tags, entry templates, network overview (small encrypted preferences) ----------------------
  const getPref = (k, dflt) => { const r = db.get('SELECT blob FROM prefs WHERE k=?', k); return r ? vault.open(r.blob, `pref/${k}`) : dflt; };
  const setPref = (k, v) => db.run('INSERT INTO prefs(k, blob) VALUES(?, ?) ON CONFLICT(k) DO UPDATE SET blob=excluded.blob', k, vault.seal(v, `pref/${k}`));
  /** Re-seals every entry (trash included) that `fn(e)` changed in place; returns how many. */
  function mutateEntries(fn) {
    let n = 0;
    db.transaction(() => { for (const { row, e } of everything().concat(everything(true))) if (fn(e)) { db.run('UPDATE entries SET blob=? WHERE id=?', vault.seal(e, `entry/${row.id}`), row.id); n++; } });
    return n;
  }
  const listTags = () => {
    const reg = getPref('tags', {}), counts = new Map();
    for (const { e } of everything()) for (const t of e.tags) counts.set(t, (counts.get(t) || 0) + 1);
    return [...new Set([...Object.keys(reg), ...counts.keys()])].sort().map(name => ({ name, color: (reg[name] && reg[name].color) || '', count: counts.get(name) || 0 }));
  };
  api('tags:list', () => listTags());
  api('tags:save', (a, t = {}) => {
    const name = clip(t.name, 40).trim().toLowerCase(), to = clip(t.newName, 40).trim().toLowerCase();
    if (!name) throw new Error('A tag needs a name');
    const reg = getPref('tags', {});
    let target = name;
    if (to && to !== name) { // rename, or merge into an existing tag
      target = to;
      mutateEntries(e => { if (!e.tags.includes(name)) return false; e.tags = [...new Set(e.tags.map(x => (x === name ? to : x)))]; return true; });
      delete reg[name];
    }
    reg[target] = { color: T.TAB_COLORS.includes(t.color) ? t.color : '' };
    setPref('tags', reg); audit(a, 'tag_saved'); changed();
    return listTags();
  });
  api('tags:delete', (a, name) => {
    name = clip(name, 40).trim().toLowerCase();
    const reg = getPref('tags', {}); delete reg[name]; setPref('tags', reg);
    mutateEntries(e => { if (!e.tags.includes(name)) return false; e.tags = e.tags.filter(x => x !== name); return true; });
    audit(a, 'tag_deleted'); changed();
    return listTags();
  });

  const builtinTemplates = (tabs) => T.BUILTIN_TEMPLATES.map(b => {
    const all = [...tabs.values()], tab = all.find(t => t.builtin === b.tabKey) || all[0];
    return { id: b.id, builtin: true, name: b.name, icon: b.icon, tabId: tab ? tab.id : null, subtitle: '', tags: b.tags, fields: b.fields, specs: b.specs.map(k => ({ k, v: '' })), creds: b.creds.map(label => ({ label, user: '', url: '' })), nics: b.nics.map(label => ({ label })) };
  });
  const listTemplates = () => { const tabs = tabMap(); return [...getPref('templates', []).map(t => ({ ...t, builtin: false })), ...builtinTemplates(tabs)]; };
  api('templates:list', () => listTemplates());
  api('templates:save', (a, t = {}) => {
    let body = t;
    if (t.fromEntry) { // a blueprint from an existing entry: structure always, values only when asked
      const row = rowOf(t.fromEntry); if (!row) throw new Error('No such entry');
      const e = { ...blank(), ...openEntry(row) }, tab = tabOfRow(row, tabMap()), keep = !!t.keepValues;
      const plain = plainFields(e, tab, true), fields = {};
      for (const fd of tab.fields) if (plain[fd.key] !== undefined && (keep || fd.type === 'select')) fields[fd.key] = plain[fd.key];
      body = { name: t.name, icon: tab.icon, tabId: row.tab_id, subtitle: keep ? e.subtitle : '', tags: e.tags, fields, specs: e.specs.map(s => ({ k: s.k, v: keep ? s.v : '' })), creds: e.creds.map(c => ({ label: c.label, user: keep ? c.user : '', url: keep ? c.url : '' })), nics: e.nics.map(n => ({ label: n.label })) };
    }
    const clean = T.cleanTemplate(body);
    if (clean.tabId && !tabMap().has(clean.tabId)) clean.tabId = null;
    const list = getPref('templates', []);
    const at = t.id && String(t.id).startsWith('c:') ? list.findIndex(x => x.id === t.id) : -1;
    if (at >= 0) list[at] = { id: t.id, ...clean }; else list.push({ id: 'c:' + crypto.randomBytes(5).toString('hex'), ...clean });
    setPref('templates', list); audit(a, 'template_saved');
    return listTemplates();
  });
  api('templates:delete', (a, id) => { setPref('templates', getPref('templates', []).filter(x => x.id !== id)); audit(a, 'template_deleted'); return listTemplates(); });

  // Every IP and MAC address in the vault in one table (IP / MAC fields and the extra network interfaces).
  api('network:list', () => {
    const tabs = tabMap(), rows = [];
    for (const { row, e } of everything()) {
      const tab = tabOfRow(row, tabs), base = { id: row.id, title: e.title, tabId: row.tab_id, tab: tab.name };
      const ips = tab.fields.filter(fd => fd.type === 'ip'), macs = tab.fields.filter(fd => fd.type === 'mac');
      for (let i = 0; i < Math.max(ips.length, macs.length); i++) {
        const ip = ips[i] ? e.fields[ips[i].key] || '' : '', mac = macs[i] ? e.fields[macs[i].key] || '' : '';
        if (ip || mac) rows.push({ ...base, label: (ips[i] || macs[i]).label, ip, mac });
      }
      for (const n of e.nics) if (n.ip || n.mac) rows.push({ ...base, label: n.label || 'Interface', ip: n.ip, mac: n.mac });
    }
    return rows;
  });

  // ---- health, dashboard, audit ------------------------------------------------------------
  function health() {
    const c = cfg(), now = Date.now(), tabs = tabMap(), staleMs = (Number(c.staleDays) || 0) * DAY;
    const out = { weak: [], reused: [], stale: [], expiring: [], total: 0, passwords: 0, at: now };
    const groups = new Map();
    for (const { row, e } of everything()) {
      out.total++;
      const tab = tabOfRow(row, tabs), base = { id: row.id, title: e.title, tabId: row.tab_id };
      const checks = [...tab.fields.filter(fd => fd.type === 'password').map(fd => ({ label: fd.label, v: e.fields[fd.key], at: e.changed[fd.key] })), ...e.creds.map(cr => ({ label: cr.label || 'Login', v: cr.secret, at: e.changed['cred:' + cr.id] }))];
      for (const { label, v, at } of checks) {
        if (!v) continue;
        out.passwords++;
        const bits = T.strengthBits(v);
        if (bits < (Number(c.weakBits) || 50)) out.weak.push({ ...base, label, bits });
        if (staleMs && now - (at || row.created) > staleMs) out.stale.push({ ...base, label, days: Math.floor((now - (at || row.created)) / DAY) });
        const hk = crypto.createHmac('sha256', vault.ek).update(v).digest('hex');
        (groups.get(hk) || groups.set(hk, []).get(hk)).push({ ...base, label });
      }
      for (const fd of tab.fields) if (fd.type === 'date' && fd.expiry && e.fields[fd.key]) {
        const days = Math.ceil((Date.parse(e.fields[fd.key] + 'T00:00:00') - now) / DAY);
        if (days <= (Number(c.expiringDays) || 60)) out.expiring.push({ ...base, label: fd.label, date: e.fields[fd.key], days });
      }
    }
    let g = 0;
    for (const members of groups.values()) if (members.length > 1) { g++; for (const m of members) out.reused.push({ ...m, group: g, with: members.length - 1 }); }
    out.expiring.sort((x, y) => x.days - y.days); out.weak.sort((x, y) => x.bits - y.bits); out.stale.sort((x, y) => y.days - x.days);
    db.kvSet('healthCache', { at: now, total: out.total, weak: out.weak.length, reused: out.reused.length, stale: out.stale.length, expiring: out.expiring.length });
    return out;
  }
  api('vault:health', () => health());
  api('data:dashboard', () => {
    const st = vault.status(), cache = db.kvGet('healthCache', null);
    if (st.state !== 'unlocked') return { state: st.state, mode: st.mode, health: cache };
    vault.touch();
    const tabs = tabList(), list = everything(), h = health();
    const brief = ({ row, e }) => ({ id: row.id, title: e.title, tabId: row.tab_id, updated: row.updated });
    return {
      state: 'unlocked', mode: st.mode, lockInMs: vault.lockInMs(), total: list.length,
      perTab: tabs.map(t => ({ id: t.id, name: t.name, icon: t.icon, n: list.filter(x => x.row.tab_id === t.id).length })),
      health: { weak: h.weak.length, reused: h.reused.length, stale: h.stale.length, expiring: h.expiring.length, passwords: h.passwords },
      expiring: h.expiring.slice(0, 8),
      recent: [...list].sort((x, y) => y.row.updated - x.row.updated).slice(0, 8).map(brief),
      favorites: list.filter(x => x.e.favorite).slice(0, 12).map(brief),
      trash: db.get('SELECT COUNT(*) n FROM entries WHERE deleted IS NOT NULL').n,
    };
  }, { data: false });
  // Home Assistant status: counts only, from the last time the vault was open. Never any content.
  api('data:status', () => { const st = vault.status(), c = db.kvGet('healthCache', {}) || {}; return { app: meta.name, state: st.state, entries: c.total ?? null, weak: c.weak ?? null, reused: c.reused ?? null, stale: c.stale ?? null, expiring: c.expiring ?? null, checked_at: c.at ? new Date(c.at).toISOString() : null }; }, { data: false });
  api('vault:audit', (a, limit = 300) => {
    const titles = new Map(); const tabs = tabMap();
    for (const { row, e } of everything().concat(everything(true))) titles.set(row.id, { title: e.title, tab: tabOfRow(row, tabs).name });
    return db.all('SELECT * FROM vault_audit ORDER BY id DESC LIMIT ?', Math.min(Number(limit) || 300, 2000)).map(r => ({ ...r, entry: r.entry_id ? (titles.get(r.entry_id) || { title: `#${r.entry_id} (removed)`, tab: '' }) : null }));
  });

  // ---- the vault itself --------------------------------------------------------------------
  api('vault:status', () => vault.status(), { data: false });
  api('vault:touch', () => { if (vault.unlocked) vault.touch(); return vault.status(); }, { data: false });
  api('vault:create', async (a, opts = {}) => {
    const r = await vault.create({ mode: opts.mode, password: opts.password, recovery: opts.recovery !== false });
    seedTabs(); audit(a, 'vault_created', null, opts.mode); changed();
    return r;
  }, { data: false });
  api('vault:unlock', async (a, creds = {}) => {
    try { await vault.unlock(creds); } catch (e) {
      if (e.code === 'wrong') {
        audit(a, 'unlock_failed', null, `${e.fails} in a row`);
        if (e.fails % 3 === 0) notify('unlockFailed', 'Strongbox: failed unlock attempts', `${e.fails} failed attempts to unlock the vault in a row${a && a.ip ? ' (last from ' + a.ip + ')' : ''}.`);
      } else if (e.code === 'throttled') audit(a, 'unlock_blocked', null, null);
      throw e;
    }
    if (ensureDefaultTabs()) log('added the new default types');
    audit(a, 'unlock', null, creds.recoveryKey ? 'recovery key' : null); changed();
    return vault.status();
  }, { data: false });
  api('vault:lock', (a) => { if (vault.lock('manual')) audit(a, 'lock'); return vault.status(); }, { data: false });
  api('vault:rewrap', async (a, opts = {}) => { const r = await vault.rewrap({ mode: opts.mode, password: opts.password, recovery: opts.recovery || 'keep' }); audit(a, 'unlock_method_changed', null, opts.mode); changed(); return r; }, { data: false });
  api('vault:newRecovery', async (a) => { const r = await vault.newRecovery(); audit(a, 'recovery_key_renewed'); return r; }, { data: false });
  api('vault:resetEmpty', (a) => {
    if (db.get('SELECT COUNT(*) n FROM entries').n) throw new Error('The vault holds entries; a reset would destroy them. Restore from a backup instead.');
    db.transaction(() => { db.run('DELETE FROM tabs'); db.run('DELETE FROM prefs'); db.run('DELETE FROM vault_meta'); db.run("DELETE FROM kv WHERE k='seededTabs'"); });
    vault.lock('reset'); audit(a, 'vault_reset'); changed();
    return true;
  }, { data: false });
  api('vault:backup', (a) => {
    const file = db.backup('manual'), stamp = new Date().toISOString().replace(/[-:]/g, '').slice(0, 13).replace('T', '-');
    audit(a, 'backup_downloaded');
    return { name: `strongbox-${stamp}.db`, base64: fs.readFileSync(file).toString('base64') };
  }, { data: false });

  // ---- jobs --------------------------------------------------------------------------------
  core.every('autolock', 15000, () => { if (vault.unlocked && vault.lockInMs() === 0) { vault.lock('idle'); audit(null, 'autolock'); } });
  core.daily('backup', () => settings.get().backup.time, () => { const dest = db.backup('nightly'); log('backup: ' + dest); });
  core.daily('trash', () => '04:10', () => { const days = Number(cfg().trashDays) || 0; if (!days) return; const old = db.all('SELECT id FROM entries WHERE deleted IS NOT NULL AND deleted < ?', Date.now() - days * DAY).map(r => r.id); if (old.length) log(`trash: purged ${purge(old)} item(s) older than ${days} days`); });
  core.daily('summary', () => settings.get().notify.dailyTime, () => {
    if (!settings.get().notify.events.dailySummary) return;
    const c = db.kvGet('healthCache', null); if (!c) return;
    notify('dailySummary', 'Strongbox summary', `${c.total} entries · ${c.weak} weak, ${c.reused} reused, ${c.stale} old passwords · ${c.expiring} expiring soon (as of the last time the vault was open).`);
  });

  const shutdown = () => { vault.lock('shutdown'); core.shutdown(); };
  return { ...core, shutdown, vault, api: API, LOCKED };
}

module.exports = { createService, LOCKED, DEFAULTS };
