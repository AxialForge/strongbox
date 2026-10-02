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
const path = require('path');
const { DatabaseSync } = require('node:sqlite');
const { createCore } = require('../../kit/main/core');
const { totp, base32Decode } = require('../../kit/server/totp');
const meta = require('../app.json');
const { Vault } = require('./vault');
const T = require('./templates');
const { parseCsv, mapHeaders, detectFormat } = require('./csvin');
const { csv } = require('../../kit/main/csv');
const { suggest, hostOf: siteOf } = require('./suggest');

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
CREATE TABLE IF NOT EXISTS inbox (
  id      INTEGER PRIMARY KEY,
  created INTEGER NOT NULL,
  status  TEXT NOT NULL DEFAULT 'pending',
  blob    BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS inbox_status ON inbox(status);
CREATE TABLE IF NOT EXISTS files (
  id        INTEGER PRIMARY KEY,
  entry_id  INTEGER NOT NULL,
  created   INTEGER NOT NULL,
  size      INTEGER NOT NULL,
  meta      BLOB NOT NULL,
  data      BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS files_entry ON files(entry_id);
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
  vault: { autoLockMinutes: 15, clipboardClearSeconds: 30, revealSeconds: 20, staleDays: 365, weakBits: 50, expiringDays: 60, trashDays: 30, lowCodes: 2, kdfLog2N: 17, genPresets: [], noReveal: [], emergencyNote: '' },
  backup: { time: '03:30' },
  notify: { events: { unlockFailed: true, dailySummary: false } },
};

const clip = (v, n) => String(v == null ? '' : v).slice(0, n);
const EMPTY = Buffer.alloc(0);

function createService({ dataDir, log = () => {}, send = () => {} }) {
  const core = createCore({ app: meta, dataDir, log, send, defaults: DEFAULTS, schema: SCHEMA, migrations: MIGRATIONS, counts: ['entries', 'tabs', 'files'] });
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
  const blank = () => ({ title: '', subtitle: '', fields: {}, creds: [], specs: [], nics: [], notes: '', tags: [], favorite: false, rotateDays: 0, visibleTo: [], codeSets: [], questions: [], archived: null, changed: {}, hist: {} });
  /** Everything not in the trash, decrypted: [{ row, e }]. */
  // Archived entries are left out unless asked for (opts.archived): they are kept, but out of every list, search and count.
  const everything = (trash = false, a = null, opts = {}) => db.all(`SELECT * FROM entries WHERE deleted IS ${trash ? 'NOT ' : ''}NULL ORDER BY id`).map(row => ({ row, e: { ...blank(), ...openEntry(row) } })).filter(x => !a || canSee(a, x.e)).filter(x => opts.archived || !x.e.archived);
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
  const light = (row, e, tab) => ({ id: row.id, tabId: row.tab_id, parentId: row.parent_id, title: e.title, subtitle: e.subtitle, tags: e.tags, favorite: !!e.favorite, created: row.created, updated: row.updated, fields: plainFields(e, tab, false), accounts: e.creds.length, rotateDays: e.rotateDays || 0, restricted: !!(e.visibleTo && e.visibleTo.length), archived: e.archived || null, quick: quickRef(e, tab) });
  function full(row, e, tab, a = null) {
    const secrets = {};
    for (const fd of tab.fields) {
      if (!T.SECRET_TYPES.has(fd.type)) continue;
      const v = e.fields[fd.key];
      secrets[fd.key] = { set: !!v, changed: e.changed[fd.key] || null, bits: fd.type === 'password' && v ? T.strengthBits(v) : undefined, history: (e.hist[fd.key] || []).map(h => ({ t: h.t })) };
    }
    const path = []; let p = row.parent_id;
    for (let i = 0; p && i < 50; i++) { const pr = rowOf(p); if (!pr) break; const pe = { ...blank(), ...openEntry(pr) }; if (!canSee(a, pe)) break; path.unshift({ id: pr.id, title: pe.title }); p = pr.parent_id; }
    return {
      ...light(row, e, tab), deleted: row.deleted || null, fields: plainFields(e, tab, true), secrets, path,
      creds: e.creds.map(c => ({ id: c.id, label: c.label, kind: c.kind || 'password', link: c.link || null, linkInfo: c.link ? linkInfo(c.link, a) : null, user: c.user, url: c.url, note: c.note || '', hasTotp: !!c.totp, set: !!c.secret, changed: e.changed['cred:' + c.id] || null, bits: c.secret ? T.strengthBits(c.secret) : undefined, history: (e.hist['cred:' + c.id] || []).map(h => ({ t: h.t })) })),
      specs: e.specs, nics: e.nics, notes: e.notes, visibleTo: e.visibleTo || [],
      codeSets: (e.codeSets || []).map(cs => ({ id: cs.id, label: cs.label, created: cs.created, total: cs.codes.length, left: cs.codes.filter(c => !c.used).length })),
      questions: (e.questions || []).map(q => ({ id: q.id, q: q.q, set: !!q.a })),
    };
  }
  // Standard accounts listed in settings may see entries but never passwords, keys, 2FA codes or attachments.
  const canReveal = (a) => !(a && a.user && a.role && a.role !== 'admin' && (cfg().noReveal || []).includes(a.user));
  // An entry can be limited to some accounts: visibleTo is empty (everyone who can sign in), ['@admins'] (admins only),
  // or a list of user names. Admins and the core itself (no account) see everything.
  const canSee = (a, e) => !a || !a.role || a.role === 'admin' || !(e.visibleTo && e.visibleTo.length) || e.visibleTo.includes(a.user);
  const denyReveal = (a) => { if (!canReveal(a)) throw new Error('Your account can see entries but not their passwords'); };
  const filesOf = (entryId) => db.all('SELECT id, created, size, meta FROM files WHERE entry_id=? ORDER BY id', entryId).map(r => ({ id: r.id, created: r.created, size: r.size, ...vault.open(r.meta, `filemeta/${r.id}`) }));
  // What an account that points at another entry may show: its title and user name, never the secret.
  const userFieldOf = (tab) => tab.fields.find(fd => fd.key === 'user') || tab.fields.find(fd => /user|login|address/i.test(fd.label) && fd.type === 'text');
  function linkInfo(id, a) {
    const row = rowOf(id); if (!row || row.deleted) return { missing: true };
    const le = { ...blank(), ...openEntry(row) }; if (!canSee(a, le)) return { missing: true };
    const tab = tabOfRow(row, tabMap()), uf = userFieldOf(tab);
    return { id: row.id, title: le.title, user: uf ? le.fields[uf.key] || '' : '', hasSecret: !!quickRef(le, tab) };
  }
  const present = (id, a) => { const row = rowOf(id); if (!row) throw new Error('No such entry'); const tabs = tabMap(); const e0 = { ...blank(), ...openEntry(row) }; if (!canSee(a, e0)) throw new Error('No such entry'); const f = full(row, e0, tabOfRow(row, tabs), a); f.canReveal = canReveal(a); f.files = filesOf(row.id); return f; };

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
    e.rotateDays = 'rotateDays' in input ? Math.max(0, Math.min(3650, Math.floor(Number(input.rotateDays)) || 0)) : prev.rotateDays || 0;
    e.visibleTo = 'visibleTo' in input ? [...new Set((Array.isArray(input.visibleTo) ? input.visibleTo : []).map(u => clip(u, 40).trim()).filter(Boolean))].slice(0, 50) : prev.visibleTo || [];
    if ('questions' in input) {
      const prevQ = new Map((prev.questions || []).map(q => [q.id, q]));
      e.questions = (Array.isArray(input.questions) ? input.questions : []).slice(0, 30).map(q => { const pq = q.id && prevQ.get(q.id); return { id: pq ? pq.id : crypto.randomBytes(6).toString('hex'), q: clip(q.q, 200).trim(), a: typeof q.a === 'string' ? clip(q.a, 500) : pq ? pq.a : '' }; }).filter(q => q.q || q.a);
    }
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
      const kind = T.KIND_IDS.includes(c.kind) ? c.kind : (pc && pc.kind) || 'password';
      let link = 'link' in c ? (Number(c.link) || null) : (pc && pc.link) || null;
      if (link && (link === id || !rowOf(link))) link = null;
      const out = { id: cid, kind, link, label: clip(c.label, 80).trim(), user: clip(c.user, 200).trim(), url: clip(c.url, 300).trim(), note: clip(c.note, 300).trim(), secret: pc ? pc.secret : '', totp: pc ? pc.totp || '' : '' };
      if (typeof c.totp === 'string') { const nt = cleanSecret({ type: 'totp' }, c.totp); if (nt !== out.totp) { out.totp = nt; e.changed['cred:' + cid + ':totp'] = now; } }
      if (typeof c.secret === 'string') { const nv = clip(c.secret, 2000); if (rotate(e, 'cred:' + cid, out.secret, nv, now, old, true)) out.secret = nv; }
      if (!T.SECRET_KINDS.has(kind)) { out.secret = ''; out.totp = ''; } // a fingerprint or a hardware key has nothing to store
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
  const seedTabs = () => { db.transaction(() => { T.DEFAULT_TABS.forEach((t, i) => writeTab(t, null, i)); }); db.kvSet('seededTabs', T.DEFAULT_TABS.map(t => t.builtin)); db.kvSet('tabsRev', 2); };
  /** Default types added in later versions appear once in an existing vault, right after the type that precedes them in the defaults. */
  function ensureDefaultTabs() {
    if ((db.kvGet('tabsRev', 0) || 0) < 2) { // v0.11: default types gain the fields and choices added since (nothing is ever removed or changed)
      db.transaction(() => {
        for (const t of tabList()) {
          const d = t.builtin && T.DEFAULT_TABS.find(x => x.builtin === t.builtin); if (!d) continue;
          const have = new Set(t.fields.map(fd => T.slug(fd.key))); let ch = false; // keys are stored slugged (lower-case), so compare slugged
          const fields = t.fields.map(fd => { const df = d.fields.find(x => T.slug(x.key) === fd.key); if (df && df.type === 'select' && fd.type === 'select') { const miss = (df.options || []).filter(o => !(fd.options || []).includes(o)); if (miss.length) { ch = true; return { ...fd, options: [...(fd.options || []), ...miss] }; } } return fd; });
          for (const df of d.fields) if (!have.has(T.slug(df.key))) { fields.push(df); ch = true; }
          if (ch) writeTab({ ...t, fields }, t.id);
        }
        db.kvSet('tabsRev', 2);
      });
    }
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
  api('entries:list', (a) => { const tabs = tabMap(), ok = canReveal(a); return everything(false, a).map(({ row, e }) => { const l = light(row, e, tabOfRow(row, tabs)); if (!ok) l.quick = null; return l; }); });
  api('entries:search', (a, q) => {
    const words = String(q || '').toLowerCase().split(/\s+/).filter(Boolean);
    if (!words.length) return [];
    const tabs = tabMap();
    return everything(false, a).filter(({ row, e }) => {
      const tab = tabOfRow(row, tabs);
      const hay = [e.title, e.subtitle, e.tags.join(' '), e.notes, e.specs.map(s => `${s.k} ${s.v}`).join(' '), e.creds.map(c => `${c.label} ${c.user} ${c.url} ${c.note || ''}`).join(' '), e.nics.map(n => `${n.label} ${n.ip} ${n.mac}`).join(' '), (e.codeSets || []).map(s => s.label).join(' '), (e.questions || []).map(q => q.q).join(' '), tab.name, ...tab.fields.filter(fd => !T.SECRET_TYPES.has(fd.type)).map(fd => e.fields[fd.key] || '')].join('\n').toLowerCase();
      return words.every(w => hay.includes(w));
    }).map(({ row }) => row.id);
  });
  api('entries:get', (a, id) => present(id, a));
  api('entries:save', (a, input) => { const id = saveEntry(a, input); changed({ id }); return present(id, a); });
  api('entries:move', (a, id, to = {}) => {
    const row = rowOf(id); if (!row) throw new Error('No such entry');
    const tabId = Number(to.tabId || row.tab_id);
    if (!db.get('SELECT id FROM tabs WHERE id=?', tabId)) throw new Error('No such type');
    const parentId = checkParent(row.id, 'parentId' in to ? to.parentId : row.parent_id);
    db.run('UPDATE entries SET tab_id=?, parent_id=?, updated=? WHERE id=?', tabId, parentId, Date.now(), row.id);
    audit(a, 'entry_moved', row.id); changed({ id: row.id });
    return present(row.id, a);
  });
  api('entries:reveal', (a, id, ref) => {
    denyReveal(a);
    const row = rowOf(id); if (!row) throw new Error('No such entry');
    const e = { ...blank(), ...openEntry(row) };
    if (!canSee(a, e)) throw new Error('No such entry');
    const m = /^(field|cred|hist|lnk|qa):(.+)$/.exec(String(ref || '')); if (!m) throw new Error('Nothing to reveal');
    let value, detail = String(ref);
    if (m[1] === 'lnk') { // the password of the entry this account signs in with
      const c = e.creds.find(x => x.id === m[2]), lrow = c && c.link && rowOf(c.link); if (!lrow || lrow.deleted) throw new Error('That linked entry is gone');
      const le = { ...blank(), ...openEntry(lrow) }; if (!canSee(a, le)) throw new Error('No such entry');
      const q = quickRef(le, tabOfRow(lrow, tabMap())); if (!q) throw new Error('The linked entry has no password');
      const [kind, key] = [q.slice(0, q.indexOf(':')), q.slice(q.indexOf(':') + 1)];
      value = kind === 'field' ? le.fields[key] : (le.creds.find(x => x.id === key) || {}).secret;
      audit(a, 'reveal', row.id, `lnk:${m[2]} -> #${lrow.id}`);
      if (!value) throw new Error('That value is empty'); return value;
    }
    if (m[1] === 'field') value = e.fields[m[2]];
    else if (m[1] === 'cred') { const c = e.creds.find(x => x.id === m[2]); value = c && c.secret; }
    else if (m[1] === 'qa') { const q = (e.questions || []).find(x => x.id === m[2]); value = q && q.a; }
    else { const cut = m[2].lastIndexOf(':'); const h = (e.hist[m[2].slice(0, cut)] || [])[Number(m[2].slice(cut + 1))]; value = h && h.v; detail = 'hist:' + m[2]; }
    if (!value) throw new Error('That value is empty');
    audit(a, 'reveal', row.id, detail);
    return value;
  });
  api('entries:totp', (a, id, key) => {
    denyReveal(a);
    const row = rowOf(id); if (!row) throw new Error('No such entry');
    const e = openEntry(row), ck = String(key);
    if (!canSee(a, { ...blank(), ...e })) throw new Error('No such entry');
    const seed = ck.startsWith('cred:') ? ((e.creds || []).find(x => 'cred:' + x.id === ck) || {}).totp : (e.fields || {})[ck];
    if (!seed) throw new Error('No authenticator seed set');
    const now = Date.now();
    const recent = db.get("SELECT id FROM vault_audit WHERE action='totp' AND entry_id=? AND ts>? LIMIT 1", row.id, now - 120000);
    if (!recent) audit(a, 'totp', row.id, String(key));
    if (!base32Decode(seed).length) throw new Error('The stored seed is not valid');
    return { code: totp(seed, now), remaining: 30 - Math.floor(now / 1000) % 30 };
  });
  // Everything needed to print entries: structure and values, with secrets only when asked (each print is audited as a whole).
  api('entries:print', (a, ids, opts = {}) => {
    if (opts.secrets) denyReveal(a);
    const withSecrets = !!opts.secrets, tabs = tabMap(), docs = [], seen = new Set();
    const kidsOf = (id) => db.all('SELECT id FROM entries WHERE parent_id=? AND deleted IS NULL ORDER BY id', id).map(r => r.id);
    const mask = (v) => (v ? (withSecrets ? v : '••••••••') : '');
    const visit = (id, depth) => {
      if (seen.has(id) || docs.length >= 500) return;
      seen.add(id);
      const row = rowOf(id); if (!row || row.deleted) return;
      const e = { ...blank(), ...openEntry(row) }, tab = tabOfRow(row, tabs);
      if (!canSee(a, e)) return;
      const fields = [];
      for (const fd of tab.fields) {
        const v = e.fields[fd.key]; if (!v) continue;
        const secret = T.SECRET_TYPES.has(fd.type);
        fields.push({ label: fd.label, value: secret ? mask(v) : fd.type === 'port' && v === 'caddy' ? 'via Caddy' : v, secret, mono: secret || ['ip', 'mac', 'port'].includes(fd.type) });
      }
      const path = []; let p = row.parent_id;
      for (let i = 0; p && i < 20; i++) { const pr = rowOf(p); if (!pr) break; path.unshift(openEntry(pr).title); p = pr.parent_id; }
      docs.push({ id: row.id, depth, title: e.title, subtitle: e.subtitle, type: tab.name, path, tags: e.tags, fields, notes: opts.notes === false ? '' : e.notes, specs: opts.notes === false ? [] : e.specs, nics: e.nics,
        codeSets: (e.codeSets || []).map(cs => ({ label: cs.label, total: cs.codes.length, left: cs.codes.filter(c => !c.used).length, codes: withSecrets ? cs.codes.map(c => ({ c: c.c, used: !!c.used })) : null })), questions: (e.questions || []).map(q => ({ q: q.q, a: mask(q.a) })),
        accounts: e.creds.map(c => ({ label: c.label, kind: (T.ACCOUNT_KINDS.find(k => k.id === (c.kind || 'password')) || {}).label || 'Password', user: c.user, url: c.url, note: c.note || '', password: mask(c.secret), totp: mask(c.totp) })), created: row.created, updated: row.updated });
      if (opts.children) for (const k of kidsOf(row.id)) visit(k, depth + 1);
    };
    for (const id of (Array.isArray(ids) ? ids : [ids]).slice(0, 500)) visit(Number(id), 0);
    audit(a, 'print', docs[0] ? docs[0].id : null, `${docs.length} entr${docs.length === 1 ? 'y' : 'ies'}${withSecrets ? ', with secrets' : ''}`);
    return { docs, secrets: withSecrets, at: Date.now() };
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
    db.transaction(() => { for (const i of all) { db.run('DELETE FROM files WHERE entry_id=?', i); db.run('DELETE FROM entries WHERE id=?', i); } });
    return all.size;
  }
  api('entries:purge', (a, ids = null) => {
    const list = ids && ids.length ? ids : db.all('SELECT id FROM entries WHERE deleted IS NOT NULL').map(r => r.id);
    const n = purge(list); audit(a, 'entries_purged', null, `${n} item(s)`); changed();
    return n;
  });
  // CSV in: one planning pass (format, mapping, duplicates), then either a preview or the writes.
  const hostOf = siteOf;
  function planImport(tab, text, skipDuplicates) {
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
    const sig = (title, url, user) => (hostOf(url) || String(title).toLowerCase()) + '|' + String(user || '').toLowerCase();
    const have = new Set(everything(false, null, { archived: true }).filter(x => x.row.tab_id === tab.id).map(({ e }) => sig(e.title, target.url && e.fields[target.url.key], target.user && e.fields[target.user.key])));
    const out = { format: detectFormat(rows[0]), total: rows.length - 1, items: [], duplicates: 0, noName: 0, otherKinds: 0, mapped: Object.fromEntries(Object.entries(target).filter(([, v]) => v).map(([k, v]) => [k, v.label])), sample: [] };
    for (const r of rows.slice(1)) {
      const val = (k) => (h[k] === undefined ? '' : String(r[h[k]] || '').trim());
      if (h.kind !== undefined && val('kind') && val('kind').toLowerCase() !== 'login') { out.otherKinds++; continue; } // Bitwarden notes, cards, identities
      const title = val('title') || hostOf(val('url'));
      if (!title) { out.noName++; continue; }
      const s = sig(title, val('url'), val('user'));
      if (skipDuplicates && have.has(s)) { out.duplicates++; continue; }
      have.add(s);
      const input = { title, tabId: tab.id, notes: val('notes'), fields: {}, secrets: {}, tags: val('folder') ? [val('folder')] : [] };
      if (target.url && val('url')) input.fields[target.url.key] = val('url');
      if (target.user && val('user')) input.fields[target.user.key] = val('user');
      if (target.pass && val('pass')) input.secrets[target.pass.key] = val('pass');
      if (target.totp && val('totp')) { try { input.secrets[target.totp.key] = cleanSecret(target.totp, val('totp')); } catch { /* skip an unreadable seed */ } }
      out.items.push(input);
      if (out.sample.length < 6) out.sample.push({ title, url: val('url'), user: val('user'), password: !!val('pass') });
    }
    return out;
  }
  api('entries:importCsv', (a, tabId, text, opts = {}) => {
    const tab = tabMap().get(Number(tabId)); if (!tab) throw new Error('Choose a type to import into');
    const p = planImport(tab, text, opts.skipDuplicates !== false);
    const summary = { format: p.format, total: p.total, willAdd: p.items.length, duplicates: p.duplicates, noName: p.noName, otherKinds: p.otherKinds, mapped: p.mapped, sample: p.sample };
    if (opts.dryRun) return { ...summary, dryRun: true };
    db.transaction(() => { for (const input of p.items) saveEntry(a, input, { audited: false, inTx: true }); });
    audit(a, 'csv_import', null, `${p.items.length} added, ${p.duplicates} duplicates skipped, ${p.noName + p.otherKinds} other rows skipped (${p.format})`); changed();
    return { ...summary, added: p.items.length, skipped: p.noName + p.otherKinds };
  });
  // CSV out, in the shape browsers and password managers import: name, url, username, password, note. One row per
  // account (the main login first, then each extra account). Passwords are in clear text, so this is SENSITIVE and audited.
  api('entries:exportCsv', (a, tabId) => {
    const tabs = tabMap(), tab = tabs.get(Number(tabId)); if (!tab) throw new Error('Choose a type to export');
    const urlF = tab.fields.find(fd => fd.type === 'url'), userF = tab.fields.find(fd => fd.key === 'user') || tab.fields.find(fd => /user|login|address/i.test(fd.label) && fd.type === 'text'), passF = tab.fields.filter(fd => fd.type === 'password');
    const rows = [];
    for (const { row, e } of everything().filter(x => x.row.tab_id === tab.id)) {
      const url = urlF ? e.fields[urlF.key] || '' : '';
      const main = passF.map(fd => e.fields[fd.key]).find(Boolean);
      if (main) rows.push({ name: e.title, url, user: userF ? e.fields[userF.key] || '' : '', pass: main, note: e.notes });
      for (const c of e.creds) if (c.secret && ['password', 'other'].includes(c.kind || 'password')) rows.push({ name: `${e.title} (${c.label || c.user || 'account'})`, url: c.url || url, user: c.user, pass: c.secret, note: c.note || '' });
    }
    audit(a, 'csv_export', null, `${rows.length} rows from one type`);
    return { name: `strongbox-${T.slug ? T.slug(tab.name) : 'export'}-passwords.csv`, rows: rows.length, text: csv(rows, [['name', r => r.name], ['url', r => r.url], ['username', r => r.user], ['password', r => r.pass], ['note', r => r.note]]).replace(/^\uFEFF/, '') };
  });
  // A copy of an entry. Passwords are left empty unless asked for, so a copy never silently creates a reused password.
  api('entries:duplicate', (a, id, opts = {}) => {
    const row = rowOf(id); if (!row || row.deleted) throw new Error('No such entry');
    const tab = tabOfRow(row, tabMap()), e = { ...blank(), ...openEntry(row) }, now = Date.now();
    const copy = structuredClone(e); copy.title = `Copy of ${e.title}`.slice(0, 200); copy.changed = {}; copy.hist = {}; copy.favorite = false;
    if (!opts.secrets) { copy.codeSets = []; for (const q of copy.questions || []) q.a = ''; } else for (const cs of copy.codeSets || []) cs.id = crypto.randomBytes(6).toString('hex');
    if (opts.secrets) { for (const k of Object.keys(copy.fields)) if (copy.fields[k]) copy.changed[k] = now; for (const c of copy.creds) { c.id = crypto.randomBytes(6).toString('hex'); if (c.secret) copy.changed['cred:' + c.id] = now; } }
    else { for (const fd of tab.fields) if (T.SECRET_TYPES.has(fd.type)) delete copy.fields[fd.key]; for (const c of copy.creds) { c.id = crypto.randomBytes(6).toString('hex'); c.secret = ''; c.totp = ''; } }
    const id2 = db.transaction(() => { const n = Number(db.run('INSERT INTO entries(tab_id, parent_id, created, updated, blob) VALUES(?,?,?,?,?)', row.tab_id, row.parent_id, now, now, EMPTY).lastInsertRowid); db.run('UPDATE entries SET blob=? WHERE id=?', vault.seal(copy, `entry/${n}`), n); return n; });
    audit(a, 'entry_created', id2, `copy of #${row.id}${opts.secrets ? ' with passwords' : ''}`); changed({ id: id2 });
    return present(id2, a);
  });

  // ---- tags, entry templates, network overview (small encrypted preferences) ----------------------
  const getPref = (k, dflt) => { const r = db.get('SELECT blob FROM prefs WHERE k=?', k); return r ? vault.open(r.blob, `pref/${k}`) : dflt; };
  const setPref = (k, v) => db.run('INSERT INTO prefs(k, blob) VALUES(?, ?) ON CONFLICT(k) DO UPDATE SET blob=excluded.blob', k, vault.seal(v, `pref/${k}`));
  /** Re-seals every entry (trash included) that `fn(e)` changed in place; returns how many. */
  function mutateEntries(fn) {
    let n = 0;
    db.transaction(() => { for (const { row, e } of everything(false, null, { archived: true }).concat(everything(true, null, { archived: true }))) if (fn(e)) { db.run('UPDATE entries SET blob=? WHERE id=?', vault.seal(e, `entry/${row.id}`), row.id); n++; } });
    return n;
  }
  const listTags = (a = null) => {
    const reg = getPref('tags', {}), counts = new Map();
    for (const { e } of everything(false, a)) for (const t of e.tags) counts.set(t, (counts.get(t) || 0) + 1);
    return [...new Set([...Object.keys(reg), ...counts.keys()])].sort().map(name => ({ name, color: (reg[name] && reg[name].color) || '', count: counts.get(name) || 0 }));
  };
  api('tags:list', (a) => listTags(a));
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
    return { id: b.id, builtin: true, name: b.name, icon: b.icon, tabId: tab ? tab.id : null, subtitle: '', tags: b.tags, fields: b.fields, specs: b.specs.map(k => ({ k, v: '' })), creds: b.creds.map(c => (typeof c === 'string' ? { label: c, user: '', url: '', kind: 'password' } : { label: c.label, user: '', url: '', kind: c.kind || 'password' })), nics: b.nics.map(label => ({ label })) };
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
      body = { name: t.name, icon: tab.icon, tabId: row.tab_id, subtitle: keep ? e.subtitle : '', tags: e.tags, fields, specs: e.specs.map(s => ({ k: s.k, v: keep ? s.v : '' })), creds: e.creds.map(c => ({ label: c.label, kind: c.kind || 'password', user: keep ? c.user : '', url: keep ? c.url : '' })), nics: e.nics.map(n => ({ label: n.label })) };
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
  api('network:list', (a) => {
    const tabs = tabMap(), rows = [];
    for (const { row, e } of everything(false, a)) {
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
  // ---- breached passwords: a built-in list of the most common ones, plus an optional list you load ----
  const COMMON = ['123456','password','12345678','qwerty','123456789','12345','1234','111111','1234567','dragon','123123','baseball','abc123','football','monkey','letmein','696969','shadow','master','666666','qwertyuiop','123321','mustang','1234567890','michael','654321','superman','1qaz2wsx','7777777','121212','000000','qazwsx','123qwe','killer','trustno1','jordan','jennifer','zxcvbnm','asdfgh','hunter','buster','soccer','harley','batman','andrew','tigger','sunshine','iloveyou','2000','charlie','robert','thomas','hockey','ranger','daniel','starwars','112233','george','computer','michelle','jessica','pepper','1111','zxcvbn','555555','11111111','131313','freedom','777777','pass','maggie','159753','aaaaaa','ginger','princess','joshua','cheese','amanda','summer','love','ashley','nicole','chelsea','biteme','matthew','access','yankees','987654321','dallas','austin','thunder','taylor','matrix','admin','welcome','login','passw0rd','password1','password123','admin123','root','toor','changeme','default','qwerty123','letmein123','football1','iloveyou1','ubnt','raspberry','administrator','guest','user','test','1q2w3e4r','1q2w3e','abcd1234','p@ssw0rd','Password1','Welcome1','Passw0rd','P@ssw0rd','admin1234','12341234','password12','qwer1234','sunshine1','master123','superman1','trustno1!','raspberrypi','homeassistant','synology','ubiquiti','netgear','linksys','cisco','public','private','secret'];
  const sha8 = (pw) => crypto.createHash('sha1').update(String(pw)).digest().readBigUInt64BE(0);
  const commonSet = new Set(COMMON.map(sha8));
  const breachFile = path.join(dataDir, 'breached.bin');
  let breachCache = null;
  const loadBreach = () => {
    if (breachCache) return breachCache;
    try { const b = fs.readFileSync(breachFile), ab = new ArrayBuffer(b.length - (b.length % 8)); new Uint8Array(ab).set(b.subarray(0, ab.byteLength)); breachCache = new BigUint64Array(ab); } catch { breachCache = new BigUint64Array(0); }
    return breachCache;
  };
  function isBreached(pw) {
    const h = sha8(pw); if (commonSet.has(h)) return true;
    const arr = loadBreach(); let lo = 0, hi = arr.length - 1;
    while (lo <= hi) { const mid = (lo + hi) >> 1; if (arr[mid] === h) return true; if (arr[mid] < h) lo = mid + 1; else hi = mid - 1; }
    return false;
  }
  // Accepts a list of passwords, or Have I Been Pwned style lines (SHA-1:count). Only 64 bits of each hash are kept, in a sorted file.
  const breach = {
    load(a, buf) {
      let cap = 1 << 20, arr = new BigUint64Array(cap), n = 0;
      const text = Buffer.from(buf).toString('utf8');
      for (let start = 0; start < text.length;) {
        let end = text.indexOf('\n', start); if (end < 0) end = text.length;
        const line = text.slice(start, end).replace(/\r$/, ''); start = end + 1;
        if (!line) continue;
        const m = /^([0-9a-fA-F]{40})(?::\d+)?$/.exec(line);
        let h; if (m) h = BigInt('0x' + m[1].slice(0, 16)); else if (line.length <= 128) h = sha8(line); else continue;
        if (n === cap) { cap *= 2; if (cap > 2 ** 25) throw new Error('That list is too long (the limit is about 30 million entries)'); const g = new BigUint64Array(cap); g.set(arr); arr = g; }
        arr[n++] = h;
      }
      if (!n) throw new Error('No passwords or hashes found in that file');
      const sorted = arr.slice(0, n).sort(); let u = 0;
      for (let i = 0; i < sorted.length; i++) if (i === 0 || sorted[i] !== sorted[i - 1]) sorted[u++] = sorted[i];
      const out = sorted.slice(0, u);
      fs.writeFileSync(breachFile + '.tmp', Buffer.from(out.buffer, out.byteOffset, out.byteLength), { mode: 0o600 }); fs.renameSync(breachFile + '.tmp', breachFile);
      breachCache = out; audit(a, 'breach_list_loaded', null, `${u} entries`);
      return { count: u };
    },
  };
  api('breach:status', () => ({ builtin: COMMON.length, custom: loadBreach().length, at: (() => { try { return fs.statSync(breachFile).mtimeMs; } catch { return null; } })() }), { data: false });
  api('breach:clear', (a) => { try { fs.unlinkSync(breachFile); } catch { /* none */ } breachCache = null; audit(a, 'breach_list_cleared'); return { builtin: COMMON.length, custom: 0, at: null }; }, { data: false });

  function health(a = null) {
    const c = cfg(), now = Date.now(), tabs = tabMap(), staleMs = (Number(c.staleDays) || 0) * DAY;
    const out = { weak: [], reused: [], stale: [], expiring: [], due: [], breached: [], lowCodes: [], total: 0, passwords: 0, at: now };
    const groups = new Map();
    for (const { row, e } of everything(false, a)) {
      out.total++;
      const tab = tabOfRow(row, tabs), base = { id: row.id, title: e.title, tabId: row.tab_id };
      const checks = [...tab.fields.filter(fd => fd.type === 'password').map(fd => ({ label: fd.label, v: e.fields[fd.key], at: e.changed[fd.key] })), ...e.creds.map(cr => ({ label: cr.label || 'Login', v: cr.secret, at: e.changed['cred:' + cr.id], kind: cr.kind || 'password' }))];
      for (const { label, v, at, kind = 'password' } of checks) {
        if (!v) continue;
        out.passwords++;
        const strong = ['password', 'other'].includes(kind); // a PIN is short by nature and a recovery key is random: neither is judged on strength or reuse
        if (['password', 'pin', 'other'].includes(kind) && isBreached(v)) out.breached.push({ ...base, label });
        if (strong) { const bits = T.strengthBits(v); if (bits < (Number(c.weakBits) || 50)) out.weak.push({ ...base, label, bits }); }
        if (['password', 'pin', 'other', 'apppass', 'token'].includes(kind) && staleMs && now - (at || row.created) > staleMs) out.stale.push({ ...base, label, days: Math.floor((now - (at || row.created)) / DAY) });
        if (strong) { const hk = crypto.createHmac('sha256', vault.ek).update(v).digest('hex'); (groups.get(hk) || groups.set(hk, []).get(hk)).push({ ...base, label }); }
      }
      for (const cs of e.codeSets || []) { const left = cs.codes.filter(x => !x.used).length; if (cs.codes.length && left <= (Number(c.lowCodes) >= 0 ? Number(c.lowCodes) : 2)) out.lowCodes.push({ ...base, label: cs.label, left, total: cs.codes.length }); }
      if (e.rotateDays && checks.some(c => c.v)) { // passwords the owner wants changed on a schedule
        const last = Math.max(row.created, ...checks.filter(c => c.v).map(c => c.at || row.created)), age = Math.floor((now - last) / DAY);
        if (age >= e.rotateDays) out.due.push({ ...base, label: 'passwords', days: age, every: e.rotateDays });
      }
      for (const fd of tab.fields) if (fd.type === 'date' && fd.expiry && e.fields[fd.key]) {
        const days = Math.ceil((Date.parse(e.fields[fd.key] + 'T00:00:00') - now) / DAY);
        if (days <= (Number(c.expiringDays) || 60)) out.expiring.push({ ...base, label: fd.label, date: e.fields[fd.key], days });
      }
    }
    let g = 0;
    for (const members of groups.values()) if (members.length > 1) { g++; for (const m of members) out.reused.push({ ...m, group: g, with: members.length - 1 }); }
    out.expiring.sort((x, y) => x.days - y.days); out.weak.sort((x, y) => x.bits - y.bits); out.stale.sort((x, y) => y.days - x.days); out.due.sort((x, y) => y.days - x.days);
    if (!a || !a.role || a.role === 'admin') db.kvSet('healthCache', { at: now, total: out.total, weak: out.weak.length, reused: out.reused.length, stale: out.stale.length, expiring: out.expiring.length, due: out.due.length, breached: out.breached.length, lowCodes: out.lowCodes.length });
    return out;
  }
  api('vault:health', (a) => health(a));
  api('data:dashboard', (a) => {
    const st = vault.status(), cache = db.kvGet('healthCache', null);
    if (st.state !== 'unlocked') return { state: st.state, mode: st.mode, health: cache };
    vault.touch();
    const tabs = tabList(), list = everything(false, a), h = health(a);
    const brief = ({ row, e }) => ({ id: row.id, title: e.title, tabId: row.tab_id, updated: row.updated });
    return {
      state: 'unlocked', mode: st.mode, lockInMs: vault.lockInMs(), total: list.length,
      perTab: tabs.map(t => ({ id: t.id, name: t.name, icon: t.icon, n: list.filter(x => x.row.tab_id === t.id).length })),
      health: { weak: h.weak.length, reused: h.reused.length, stale: h.stale.length, expiring: h.expiring.length, due: h.due.length, breached: h.breached.length, lowCodes: h.lowCodes.length, passwords: h.passwords },
      expiring: h.expiring.slice(0, 8),
      recent: [...list].sort((x, y) => y.row.updated - x.row.updated).slice(0, 8).map(brief),
      favorites: list.filter(x => x.e.favorite).slice(0, 12).map(brief),
      trash: a && a.role && a.role !== 'admin' ? 0 : db.get('SELECT COUNT(*) n FROM entries WHERE deleted IS NOT NULL').n,
      archived: everything(false, a, { archived: true }).filter(x => x.e.archived).length,
      review: a && a.role && a.role !== 'admin' ? 0 : db.get("SELECT COUNT(*) n FROM inbox WHERE status='pending'").n,
    };
  }, { data: false });
  // Home Assistant status: counts only, from the last time the vault was open. Never any content.
  api('data:status', () => { const st = vault.status(), c = db.kvGet('healthCache', {}) || {}; return { app: meta.name, state: st.state, entries: c.total ?? null, weak: c.weak ?? null, reused: c.reused ?? null, stale: c.stale ?? null, expiring: c.expiring ?? null, due: c.due ?? null, breached: c.breached ?? null, low_codes: c.lowCodes ?? null, review_pending: db.get("SELECT COUNT(*) n FROM inbox WHERE status='pending'").n, checked_at: c.at ? new Date(c.at).toISOString() : null }; }, { data: false });
  api('vault:audit', (a, limit = 300) => {
    const titles = new Map(); const tabs = tabMap();
    for (const { row, e } of everything(false, null, { archived: true }).concat(everything(true, null, { archived: true }))) titles.set(row.id, { title: e.title, tab: tabOfRow(row, tabs).name });
    return db.all('SELECT * FROM vault_audit ORDER BY id DESC LIMIT ?', Math.min(Number(limit) || 300, 2000)).map(r => ({ ...r, entry: r.entry_id ? (titles.get(r.entry_id) || { title: `#${r.entry_id} (removed)`, tab: '' }) : null }));
  });

  // ---- the vault itself --------------------------------------------------------------------
  api('vault:status', () => vault.status(), { data: false });
  api('vault:touch', () => { if (vault.unlocked) vault.touch(); return vault.status(); }, { data: false });
  api('vault:create', async (a, opts = {}) => {
    const r = await vault.create({ mode: opts.mode, password: opts.password, recovery: opts.recovery !== false, securityKey: opts.securityKey });
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
  api('vault:rewrap', async (a, opts = {}) => { const r = await vault.rewrap({ mode: opts.mode, password: opts.password, recovery: opts.recovery || 'keep', securityKey: opts.securityKey }); audit(a, 'unlock_method_changed', null, opts.mode); changed(); return r; }, { data: false });
  api('vault:newRecovery', async (a) => { const r = await vault.newRecovery(); audit(a, 'recovery_key_renewed'); return r; }, { data: false });
  api('vault:resetEmpty', (a) => {
    if (db.get('SELECT COUNT(*) n FROM entries').n) throw new Error('The vault holds entries; a reset would destroy them. Restore from a backup instead.');
    db.transaction(() => { db.run('DELETE FROM tabs'); db.run('DELETE FROM inbox'); db.run("DELETE FROM kv WHERE k='inboxStats'"); db.run('DELETE FROM files'); db.run('DELETE FROM prefs'); db.run('DELETE FROM vault_meta'); db.run("DELETE FROM kv WHERE k='seededTabs'"); });
    vault.lock('reset'); audit(a, 'vault_reset'); changed();
    return true;
  }, { data: false });
  api('vault:backup', (a) => {
    const file = db.backup('manual'), stamp = new Date().toISOString().replace(/[-:]/g, '').slice(0, 13).replace('T', '-');
    audit(a, 'backup_downloaded');
    return { name: `strongbox-${stamp}.db`, base64: fs.readFileSync(file).toString('base64') };
  }, { data: false });

  // ---- backup codes: sets of one-time codes you tick off as you use them ---------------------------------
  // A set is { id, label, created, codes: [{ c, used: null | time }] }. The page sees a set's size and how many are left,
  // never the codes, until codes:reveal (which is logged like any other look at a secret).
  const parseCodes = (text) => {
    const t = String(text || '');
    const parts = /[\r\n,;]/.test(t) ? t.split(/[\r\n,;]+/) : t.split(/\s+/); // one per line; a single line is split on spaces
    const seen = new Set(), out = [];
    for (let c of parts) { c = c.trim(); if (!c || c.length > 128 || seen.has(c)) continue; seen.add(c); out.push({ c, used: null }); }
    return out.slice(0, 200);
  };
  function withEntry(a, id, fn, action) {
    const row = rowOf(id); if (!row || row.deleted) throw new Error('No such entry');
    const e = { ...blank(), ...openEntry(row) }; if (!canSee(a, e)) throw new Error('No such entry');
    const r = fn(e, row);
    db.run('UPDATE entries SET blob=?, updated=? WHERE id=?', vault.seal(e, `entry/${row.id}`), Date.now(), row.id);
    audit(a, action, row.id); changed({ id: row.id });
    return r === undefined ? present(row.id, a) : r;
  }
  const setOf = (e, setId) => { const cs = (e.codeSets || []).find(x => x.id === setId); if (!cs) throw new Error('No such set of codes'); return cs; };
  api('codes:add', (a, id, label, text) => withEntry(a, id, (e) => {
    const codes = parseCodes(text); if (!codes.length) throw new Error('No codes found. Paste them one per line.');
    if ((e.codeSets || []).length >= 20) throw new Error('An entry can hold 20 sets of codes');
    (e.codeSets = e.codeSets || []).push({ id: crypto.randomBytes(6).toString('hex'), label: clip(label, 80).trim() || 'Backup codes', created: Date.now(), codes });
  }, 'codes_added'));
  api('codes:replace', (a, id, setId, text) => withEntry(a, id, (e) => { const cs = setOf(e, setId), codes = parseCodes(text); if (!codes.length) throw new Error('No codes found. Paste them one per line.'); cs.codes = codes; cs.created = Date.now(); }, 'codes_replaced'));
  api('codes:rename', (a, id, setId, label) => withEntry(a, id, (e) => { setOf(e, setId).label = clip(label, 80).trim() || 'Backup codes'; }, 'codes_renamed'));
  api('codes:delete', (a, id, setId) => withEntry(a, id, (e) => { setOf(e, setId); e.codeSets = e.codeSets.filter(x => x.id !== setId); }, 'codes_deleted'));
  api('codes:mark', (a, id, setId, index, used) => withEntry(a, id, (e) => { const cs = setOf(e, setId), cd = cs.codes[Number(index)]; if (!cd) throw new Error('No such code'); cd.used = used ? Date.now() : null; return { left: cs.codes.filter(x => !x.used).length, total: cs.codes.length }; }, 'codes_marked'));
  api('codes:reveal', (a, id, setId) => {
    denyReveal(a);
    const row = rowOf(id); if (!row || row.deleted) throw new Error('No such entry');
    const e = { ...blank(), ...openEntry(row) }; if (!canSee(a, e)) throw new Error('No such entry');
    const cs = setOf(e, setId); audit(a, 'reveal', row.id, `codes:${setId}`);
    return { label: cs.label, codes: cs.codes.map(x => ({ c: x.c, used: x.used })) };
  });
  // The first unused code, copied by the page and ticked off in one step.
  api('codes:next', (a, id, setId) => {
    denyReveal(a);
    return withEntry(a, id, (e) => { const cs = setOf(e, setId), cd = cs.codes.find(x => !x.used); if (!cd) throw new Error('Every code in this set is used up'); cd.used = Date.now(); return { code: cd.c, left: cs.codes.filter(x => !x.used).length, total: cs.codes.length }; }, 'codes_used');
  });

  // ---- archive: kept, but out of the way ----------------------------------------------------------
  function setArchived(id, on, now = Date.now()) {
    const row = rowOf(id); if (!row) return false;
    const e = { ...blank(), ...openEntry(row) }; e.archived = on ? now : null;
    db.run('UPDATE entries SET blob=?, updated=? WHERE id=?', vault.seal(e, `entry/${row.id}`), now, row.id);
    return true;
  }
  api('entries:archive', (a, ids, on = true) => {
    const all = new Set(); for (const id of (Array.isArray(ids) ? ids : [ids]).slice(0, 2000)) { const row = rowOf(id); if (!row || row.deleted) continue; all.add(row.id); for (const d of descendants(row.id)) all.add(d); }
    db.transaction(() => { for (const i of all) setArchived(i, !!on); });
    audit(a, on ? 'entries_archived' : 'entries_unarchived', null, `${all.size} entr${all.size === 1 ? 'y' : 'ies'}`); changed();
    return all.size;
  });
  api('entries:archived', (a) => { const tabs = tabMap(); return everything(false, a, { archived: true }).filter(x => x.e.archived).map(({ row, e }) => light(row, e, tabOfRow(row, tabs))); });

  // ---- the review queue: imported logins wait here, outside the vault, until you decide about each one ------------
  // inbox(id, created, status 'pending' | 'skipped', blob) where blob = { title, url, user, pass, totp, notes, folder }.
  // Decisions: keep, archive (no longer in use), delete (to the trash, so it can be undone) or skip (later). The queue persists, so a
  // review can stop and resume across days. Order: the riskiest passwords first, then by site.
  const ibStats = () => db.kvGet('inboxStats', null) || { done: 0, kept: 0, archived: 0, deleted: 0 };
  const inboxStatus = () => ({ pending: db.get("SELECT COUNT(*) n FROM inbox WHERE status='pending'").n, skipped: db.get("SELECT COUNT(*) n FROM inbox WHERE status='skipped'").n, ...ibStats() });
  const importTarget = (tab) => {
    const find = (pred) => tab.fields.find(pred);
    return { url: find(fd => fd.type === 'url'), user: find(fd => fd.key === 'user') || find(fd => /user|login|address/i.test(fd.label) && fd.type === 'text'), pass: find(fd => fd.type === 'password'), totp: find(fd => fd.type === 'totp') };
  };
  const pwHash = (v) => crypto.createHmac('sha256', vault.ek).update(String(v)).digest('hex');
  function queueRows() { return db.all('SELECT id, created, status, blob FROM inbox ORDER BY id').map(r => ({ row: r, item: vault.open(r.blob, `inbox/${r.id}`) })); }
  api('inbox:add', (a, text, opts = {}) => {
    const rows = parseCsv(text);
    if (rows.length < 2) throw new Error('The file has no rows');
    if (rows.length > 5001) throw new Error('At most 5000 rows at a time: split the file');
    const h = mapHeaders(rows[0]);
    if (h.title === undefined && h.url === undefined) throw new Error('No name or url column found in the first row');
    const sig = (it) => (siteOf(it.url) || String(it.title).toLowerCase()) + '|' + String(it.user || '').toLowerCase();
    const tabsNow = tabMap();
    const have = new Set(everything(false, null, { archived: true }).map(({ row, e }) => { const tab = tabOfRow(row, tabsNow), urlF = tab.fields.find(fd => fd.type === 'url'), uf = userFieldOf(tab); return sig({ title: e.title, url: urlF ? e.fields[urlF.key] : '', user: uf ? e.fields[uf.key] : '' }); }));
    for (const q of queueRows()) have.add(sig(q.item));
    const res = { format: detectFormat(rows[0]), total: rows.length - 1, added: 0, duplicates: 0, noName: 0, otherKinds: 0 };
    const skipDup = opts.skipDuplicates !== false, now = Date.now();
    db.transaction(() => {
      for (const r of rows.slice(1)) {
        const val = (k) => (h[k] === undefined ? '' : String(r[h[k]] || '').trim());
        if (h.kind !== undefined && val('kind') && val('kind').toLowerCase() !== 'login') { res.otherKinds++; continue; }
        const item = { url: clip(val('url'), 500), user: clip(val('user'), 200), pass: clip(val('pass'), 2000), totp: clip(val('totp'), 400), notes: clip(val('notes'), 20000), folder: clip(val('folder'), 40).trim().toLowerCase() };
        item.title = clip(val('title') || (/^android:\/\//i.test(item.url) ? siteOf(item.url) : siteOf(item.url)), 200);
        if (!item.title) { res.noName++; continue; }
        const s = sig(item); if (skipDup && have.has(s)) { res.duplicates++; continue; } have.add(s);
        const id = Number(db.run('INSERT INTO inbox(created, status, blob) VALUES(?,?,?)', now, 'pending', EMPTY).lastInsertRowid);
        db.run('UPDATE inbox SET blob=? WHERE id=?', vault.seal(item, `inbox/${id}`), id); res.added++;
      }
    });
    audit(a, 'review_queued', null, `${res.added} queued, ${res.duplicates} duplicates skipped (${res.format})`); changed();
    return { ...res, status: inboxStatus() };
  });
  api('inbox:status', () => inboxStatus());
  api('inbox:clear', (a) => { const n = db.get('SELECT COUNT(*) n FROM inbox').n; db.run('DELETE FROM inbox'); db.kvSet('inboxStats', { done: 0, kept: 0, archived: 0, deleted: 0 }); audit(a, 'review_cleared', null, `${n} item(s) discarded`); changed(); return inboxStatus(); });
  api('inbox:reveal', (a, id) => {
    denyReveal(a);
    const r = db.get('SELECT id, blob FROM inbox WHERE id=?', Number(id)); if (!r) throw new Error('That item is already done');
    const it = vault.open(r.blob, `inbox/${r.id}`); if (!it.pass) throw new Error('That item has no password');
    audit(a, 'reveal', null, 'inbox item'); return it.pass;
  });
  api('inbox:next', (a, opts = {}) => {
    const tabs = tabMap(), tabList_ = [...tabs.values()], learned = (getPref('domainRules', {}) || {});
    const queue = queueRows(), vaultAll = everything(false, null, { archived: true });
    const vh = new Map(), qh = new Map(), byHost = new Map();
    for (const { row, e } of vaultAll) {
      const tab = tabOfRow(row, tabs);
      for (const fd of tab.fields) if (fd.type === 'password' && e.fields[fd.key]) { const k = pwHash(e.fields[fd.key]); vh.set(k, (vh.get(k) || 0) + 1); }
      for (const c of e.creds) if (c.secret && ['password', 'other'].includes(c.kind || 'password')) { const k = pwHash(c.secret); vh.set(k, (vh.get(k) || 0) + 1); }
      const uf = userFieldOf(tab), urlF = tab.fields.find(fd => fd.type === 'url'), host = urlF ? siteOf(e.fields[urlF.key]) : '';
      if (host) (byHost.get(host) || byHost.set(host, []).get(host)).push({ kind: 'vault', id: row.id, title: e.title, user: uf ? e.fields[uf.key] || '' : '', tab: tab.name, archived: !!e.archived });
    }
    for (const { item } of queue) if (item.pass) { const k = pwHash(item.pass); qh.set(k, (qh.get(k) || 0) + 1); }
    const qHost = new Map();
    for (const q of queue) { const h = siteOf(q.item.url); if (h) (qHost.get(h) || qHost.set(h, []).get(h)).push(q); }
    const weakBits = Number(cfg().weakBits) || 50;
    const scored = queue.map(q => {
      const it = q.item, bits = it.pass ? T.strengthBits(it.pass) : 0, k = it.pass ? pwHash(it.pass) : null;
      const reusedWith = k ? (vh.get(k) || 0) + (qh.get(k) || 1) - 1 : 0, breached = it.pass ? isBreached(it.pass) : false, weak = !!it.pass && bits < weakBits;
      return { q, bits, reusedWith, breached, weak, noPass: !it.pass, risk: (breached ? 4 : 0) + (weak ? 2 : 0) + (reusedWith > 0 ? 2 : 0) };
    });
    const rank = (x) => [x.q.row.status === 'skipped' ? 1 : 0, -x.risk, siteOf(x.q.item.url) || x.q.item.title.toLowerCase(), x.q.item.title.toLowerCase(), x.q.row.id];
    scored.sort((x, y) => { const rx = rank(x), ry = rank(y); for (let i = 0; i < rx.length; i++) { if (rx[i] < ry[i]) return -1; if (rx[i] > ry[i]) return 1; } return 0; });
    const status = inboxStatus();
    const first = scored[0]; if (!first) return { done: true, status };
    const it = first.q.item, host = siteOf(it.url), sg = suggest(it, learned);
    const wanted = sg.learned ? tabs.get(sg.learned.tabId) : tabList_.find(t => t.builtin === sg.builtin);
    const suggestion = { tabId: (wanted || tabList_.find(t => t.builtin === 'websites') || tabList_[0] || {}).id || null, tags: sg.tags, reason: sg.reason };
    const siblings = [
      ...(qHost.get(host) || []).filter(x => x.row.id !== first.q.row.id).map(x => ({ kind: 'queue', id: x.row.id, title: x.item.title, user: x.item.user, sameUser: (x.item.user || '').toLowerCase() === (it.user || '').toLowerCase() })),
      ...(byHost.get(host) || []).map(x => ({ ...x, sameUser: (x.user || '').toLowerCase() === (it.user || '').toLowerCase() })),
    ].slice(0, 12);
    return { done: false, status, card: { id: first.q.row.id, skipped: first.q.row.status === 'skipped', title: it.title, url: it.url, host, user: it.user, notes: it.notes, folder: it.folder, hasPass: !!it.pass, hasTotp: !!it.totp, bits: it.pass ? first.bits : null, flags: { weak: first.weak, breached: first.breached, reusedWith: first.reusedWith, noPass: first.noPass }, suggestion, siblings } };
  });
  api('inbox:decide', (a, id, d = {}) => {
    const row = db.get('SELECT id, blob FROM inbox WHERE id=?', Number(id)); if (!row) throw new Error('That item is already done');
    const item = vault.open(row.blob, `inbox/${row.id}`), action = d.action;
    if (action === 'skip') { db.run("UPDATE inbox SET status='skipped' WHERE id=?", row.id); return inboxStatus(); }
    if (!['keep', 'archive', 'delete'].includes(action)) throw new Error('Unknown decision');
    const tabs = tabMap(), tab = tabs.get(Number(d.tabId)) || [...tabs.values()].find(t => t.builtin === 'websites') || [...tabs.values()][0];
    if (!tab) throw new Error('Choose a type');
    const t = importTarget(tab), url = d.url ?? item.url, user = d.user ?? item.user, pw = typeof d.password === 'string' && d.password !== '' ? d.password : item.pass;
    const input = { tabId: tab.id, title: clip(d.title ?? item.title, 200).trim() || siteOf(url) || 'Untitled', notes: clip(d.notes ?? item.notes, 100000), favorite: !!d.favorite, tags: [...(Array.isArray(d.tags) ? d.tags : [])], fields: {}, secrets: {}, creds: [] };
    if (item.folder && !input.tags.includes(item.folder)) input.tags.push(item.folder);
    if (t.url && url) input.fields[t.url.key] = url; else if (url) input.notes = `${input.notes}${input.notes ? '\n' : ''}Address: ${url}`;
    if (t.user && user) input.fields[t.user.key] = user;
    if (pw) { if (t.pass) input.secrets[t.pass.key] = pw; else input.creds.push({ label: 'Login', kind: 'password', user, secret: pw }); }
    else if (user && !t.user) input.notes = `${input.notes}${input.notes ? '\n' : ''}User: ${user}`;
    if (item.totp && t.totp) { try { input.secrets[t.totp.key] = cleanSecret(t.totp, item.totp); } catch { /* an unreadable seed is dropped */ } }
    let eid;
    db.transaction(() => {
      eid = saveEntry(a, input, { audited: false, inTx: true });
      if (action === 'archive') setArchived(eid, true); else if (action === 'delete') db.run('UPDATE entries SET deleted=? WHERE id=?', Date.now(), eid);
      db.run('DELETE FROM inbox WHERE id=?', row.id);
    });
    const st = ibStats(); st.done++; st[action === 'keep' ? 'kept' : action === 'archive' ? 'archived' : 'deleted']++; db.kvSet('inboxStats', st);
    const host = siteOf(url);
    if (host && action !== 'delete') { const rules = getPref('domainRules', {}) || {}; rules[host] = { tabId: tab.id, tags: input.tags.filter(x => x !== item.folder) }; const keys = Object.keys(rules); if (keys.length > 3000) delete rules[keys[0]]; setPref('domainRules', rules); }
    audit(a, 'review_' + action, eid); changed({ id: eid });
    return inboxStatus();
  });

  // ---- bulk actions ------------------------------------------------------------------------
  api('entries:bulk', (a, ids, action, arg) => {
    ids = [...new Set((Array.isArray(ids) ? ids : []).map(Number))].slice(0, 1000);
    const tabs = tabMap(), now = Date.now(); let n = 0;
    const tag = clip(arg, 40).trim().toLowerCase();
    if (action === 'move' && !tabs.has(Number(arg && arg.tabId))) throw new Error('No such type');
    if (!['delete', 'move', 'addTag', 'removeTag', 'favorite'].includes(action)) throw new Error('Unknown bulk action');
    db.transaction(() => {
      for (const id of ids) {
        const row = rowOf(id); if (!row || row.deleted) continue;
        if (action === 'delete') { for (const i of [row.id, ...descendants(row.id)]) db.run('UPDATE entries SET deleted=? WHERE id=?', now, i); n++; continue; }
        if (action === 'move') { db.run('UPDATE entries SET tab_id=?, updated=? WHERE id=?', Number(arg.tabId), now, row.id); n++; continue; }
        const e = { ...blank(), ...openEntry(row) }; let ch = false;
        if (action === 'addTag' && tag && !e.tags.includes(tag) && e.tags.length < 30) { e.tags.push(tag); ch = true; }
        else if (action === 'removeTag' && e.tags.includes(tag)) { e.tags = e.tags.filter(x => x !== tag); ch = true; }
        else if (action === 'favorite' && e.favorite !== !!arg) { e.favorite = !!arg; ch = true; }
        if (ch) { db.run('UPDATE entries SET blob=?, updated=? WHERE id=?', vault.seal(e, `entry/${row.id}`), now, row.id); n++; }
      }
    });
    audit(a, 'bulk_' + action, null, `${n} entr${n === 1 ? 'y' : 'ies'}`); changed();
    return n;
  });

  // ---- attachments (encrypted like everything else; uploaded and downloaded through raw routes) ---
  const MAX_FILE = 10 * 1024 * 1024, MAX_FILES = 30;
  const files = {
    add(a, entryId, name, type, buf) {
      vault.require();
      const row = rowOf(entryId); if (!row || row.deleted) throw new Error('No such entry');
      if (!buf || !buf.length) throw new Error('That file is empty');
      if (buf.length > MAX_FILE) throw new Error('Attachments can be at most 10 MB');
      if (db.get('SELECT COUNT(*) n FROM files WHERE entry_id=?', row.id).n >= MAX_FILES) throw new Error(`An entry can hold ${MAX_FILES} attachments`);
      const id = db.transaction(() => {
        const n = Number(db.run('INSERT INTO files(entry_id, created, size, meta, data) VALUES(?,?,?,?,?)', row.id, Date.now(), buf.length, EMPTY, EMPTY).lastInsertRowid);
        db.run('UPDATE files SET meta=?, data=? WHERE id=?', vault.seal({ name: clip(name, 200) || 'file', type: clip(type, 100) || 'application/octet-stream' }, `filemeta/${n}`), vault.sealBytes(buf, `file/${n}`), n);
        return n;
      });
      audit(a, 'file_added', row.id, `file ${id}, ${buf.length} bytes`); changed({ id: row.id });
      return filesOf(row.id);
    },
    read(a, id) {
      vault.require(); denyReveal(a);
      const r = db.get('SELECT * FROM files WHERE id=?', Number(id)); if (!r) throw new Error('No such file');
      const owner = rowOf(r.entry_id); if (owner && !canSee(a, { ...blank(), ...openEntry(owner) })) throw new Error('No such file');
      audit(a, 'file_downloaded', r.entry_id, `file ${r.id}`);
      return { ...vault.open(r.meta, `filemeta/${r.id}`), data: vault.openBytes(r.data, `file/${r.id}`) };
    },
  };
  api('files:delete', (a, id) => {
    const r = db.get('SELECT entry_id FROM files WHERE id=?', Number(id)); if (!r) throw new Error('No such file');
    db.run('DELETE FROM files WHERE id=?', Number(id)); audit(a, 'file_deleted', r.entry_id, `file ${id}`); changed({ id: r.entry_id });
    return filesOf(r.entry_id);
  });

  // ---- restore a backup, rotate the data key ----------------------------------------------------
  api('vault:restoreCheck', () => true, { data: false }); // SENSITIVE: makes the browser ask for the account password before the upload
  function restoreFile(a, buf) {
    if (!buf || buf.length < 4096 || buf.subarray(0, 15).toString('latin1') !== 'SQLite format 3') throw new Error('That is not a Strongbox backup (it is not a database file)');
    const tmp = path.join(dataDir, `restore-${Date.now()}.db`);
    fs.writeFileSync(tmp, buf, { mode: 0o600 });
    let info;
    try {
      const probe = new DatabaseSync(tmp, { readOnly: true });
      try {
        const have = new Set(probe.prepare("SELECT name FROM sqlite_master WHERE type='table'").all().map(r => r.name));
        for (const t of ['vault_meta', 'tabs', 'entries']) if (!have.has(t)) throw new Error('That is not a Strongbox backup (no ' + t + ' table)');
        const row = probe.prepare("SELECT v FROM vault_meta WHERE k='header'").get();
        const header = row ? JSON.parse(row.v) : null;
        if (!header || !header.dk || !header.kdf) throw new Error('That backup has no vault in it');
        info = { have, mode: header.mode, keyFileId: header.kf || null, securityKey: !!header.sk, entries: probe.prepare('SELECT COUNT(*) n FROM entries').get().n, tabs: probe.prepare('SELECT COUNT(*) n FROM tabs').get().n };
      } finally { probe.close(); }
      db.backup('pre-restore');
      vault.lock('restore');
      db.exec(`ATTACH DATABASE '${tmp.replace(/'/g, "''")}' AS bk`);
      try {
        db.transaction(() => {
          for (const t of ['tabs', 'entries', 'vault_meta', 'files', 'prefs', 'inbox']) db.exec(`DELETE FROM ${t}`);
          db.exec('INSERT INTO vault_meta SELECT k, v FROM bk.vault_meta');
          db.exec('INSERT INTO tabs SELECT id, sort, blob FROM bk.tabs');
          db.exec('INSERT INTO entries SELECT id, tab_id, parent_id, created, updated, deleted, blob FROM bk.entries');
          if (info.have.has('prefs')) db.exec('INSERT INTO prefs SELECT k, blob FROM bk.prefs');
          if (info.have.has('inbox')) db.exec('INSERT INTO inbox SELECT id, created, status, blob FROM bk.inbox');
          if (info.have.has('files')) db.exec('INSERT INTO files SELECT id, entry_id, created, size, meta, data FROM bk.files');
          db.exec("DELETE FROM kv WHERE k IN ('seededTabs', 'portFieldMigrated')");
          if (info.have.has('kv')) db.exec("INSERT INTO kv SELECT k, v FROM bk.kv WHERE k IN ('seededTabs', 'portFieldMigrated')");
        });
      } finally { db.exec('DETACH DATABASE bk'); }
    } finally { try { fs.unlinkSync(tmp); } catch { /* ignore */ } }
    audit(a, 'backup_restored', null, `${info.entries} entries, ${info.tabs} types`); changed();
    return { entries: info.entries, tabs: info.tabs, mode: info.mode, keyFileId: info.keyFileId, securityKey: info.securityKey };
  }
  api('vault:rotate', async (a, opts = {}) => {
    db.backup('pre-rotate');
    const r = await vault.rotate({ mode: opts.mode, password: opts.password, recovery: opts.recovery === 'none' ? 'none' : 'new', securityKey: opts.securityKey }, (open, seal) => {
      for (const t of db.all('SELECT id, blob FROM tabs')) db.run('UPDATE tabs SET blob=? WHERE id=?', seal(open(t.blob, `tab/${t.id}`), `tab/${t.id}`), t.id);
      for (const e of db.all('SELECT id, blob FROM entries')) db.run('UPDATE entries SET blob=? WHERE id=?', seal(open(e.blob, `entry/${e.id}`), `entry/${e.id}`), e.id);
      for (const p of db.all('SELECT k, blob FROM prefs')) db.run('UPDATE prefs SET blob=? WHERE k=?', seal(open(p.blob, `pref/${p.k}`), `pref/${p.k}`), p.k);
      for (const q of db.all('SELECT id, blob FROM inbox')) db.run('UPDATE inbox SET blob=? WHERE id=?', seal(open(q.blob, `inbox/${q.id}`), `inbox/${q.id}`), q.id);
      for (const f of db.all('SELECT id, meta, data FROM files')) db.run('UPDATE files SET meta=?, data=? WHERE id=?', seal(open(f.meta, `filemeta/${f.id}`), `filemeta/${f.id}`), seal(open(f.data, `file/${f.id}`), `file/${f.id}`), f.id);
    });
    audit(a, 'data_key_rotated', null, opts.mode); changed();
    return r;
  }, { data: false });

  // ---- jobs --------------------------------------------------------------------------------
  core.every('autolock', 15000, () => { if (vault.unlocked && vault.lockInMs() === 0) { vault.lock('idle'); audit(null, 'autolock'); } });
  core.daily('backup', () => settings.get().backup.time, () => { const dest = db.backup('nightly'); log('backup: ' + dest); });
  core.daily('trash', () => '04:10', () => { const days = Number(cfg().trashDays) || 0; if (!days) return; const old = db.all('SELECT id FROM entries WHERE deleted IS NOT NULL AND deleted < ?', Date.now() - days * DAY).map(r => r.id); if (old.length) log(`trash: purged ${purge(old)} item(s) older than ${days} days`); });
  core.daily('summary', () => settings.get().notify.dailyTime, () => {
    if (!settings.get().notify.events.dailySummary) return;
    const c = db.kvGet('healthCache', null); if (!c) return;
    notify('dailySummary', 'Strongbox summary', `${c.total} entries · ${c.weak} weak, ${c.reused} reused, ${c.stale} old passwords · ${c.expiring} expiring soon${c.due ? ` · ${c.due} due to be changed` : ''}${c.breached ? ` · ${c.breached} known-breached` : ''} (as of the last time the vault was open).`);
  });

  const shutdown = () => { vault.lock('shutdown'); core.shutdown(); };
  return { ...core, shutdown, vault, api: API, LOCKED, files, restoreFile, breach };
}

module.exports = { createService, LOCKED, DEFAULTS };
