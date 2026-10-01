'use strict';
// Strongbox's crypto and lock state. Nothing here knows about HTTP, tabs or entries.
//
//   unlock factors     a passphrase, a key file, or both (the mode is chosen when the vault is created)
//   key derivation     scrypt(passphrase) ‖ key-file secret  →  HKDF-SHA256  →  KEK (32 bytes)
//   data key (DK)      32 random bytes, stored only wrapped (AES-256-GCM) under the KEK, and again under the
//                      recovery key when one was made; held in memory only while the vault is unlocked
//   records            AES-256-GCM under a subkey of the DK, one random nonce each, the table and row id
//                      bound in as additional data so a ciphertext cannot be moved to another row
//
// The header (mode, scrypt parameters, wrapped keys) lives in the vault_meta table, so a copy of the
// database file is a complete, still-encrypted backup.
const crypto = require('crypto');
const { promisify } = require('util');
const { base32Encode, base32Decode } = require('../../kit/server/totp');

const scrypt = promisify(crypto.scrypt);
const MODES = { password: { pw: true, kf: false }, 'password+keyfile': { pw: true, kf: true }, keyfile: { pw: false, kf: true } };
const MIN_PASSWORD = 12;
const KF_HEAD = '-----BEGIN STRONGBOX KEY FILE-----', KF_FOOT = '-----END STRONGBOX KEY FILE-----';
const b64 = (buf) => Buffer.from(buf).toString('base64');
const unb64 = (s) => Buffer.from(String(s), 'base64');
const norm = (s) => String(s || '').normalize('NFKC');

// ---- key file and recovery key ----------------------------------------------------------------
const keyId = (secret) => crypto.createHash('sha256').update(secret).digest('hex').slice(0, 8).toUpperCase().replace(/^(.{4})/, '$1-');
function newKeyFile() {
  const secret = crypto.randomBytes(32), id = keyId(secret);
  return { secret, id, text: [KF_HEAD, `Id: ${id}`, b64(secret), KF_FOOT, ''].join('\n') };
}
/** The 32-byte secret inside a key file's text; throws a readable error for anything else. */
function parseKeyFile(text) {
  const lines = String(text || '').split(/\r?\n/).map(s => s.trim());
  const body = lines.find(l => /^[A-Za-z0-9+/]{43}=?$/.test(l));
  if (!lines.includes(KF_HEAD) || !body) throw new Error('That is not a Strongbox key file');
  const secret = unb64(body);
  if (secret.length !== 32) throw new Error('That key file is damaged');
  return secret;
}
const recoveryText = (bytes) => base32Encode(bytes).match(/.{1,5}/g).join('-');
function parseRecovery(text) {
  const bytes = base32Decode(String(text || '').replace(/[\s-]/g, ''));
  if (bytes.length !== 25) throw new Error('A recovery key is 40 letters and digits');
  return bytes;
}

// ---- primitives -------------------------------------------------------------------------------
function wrap(key, plain, aad) {
  const n = crypto.randomBytes(12), c = crypto.createCipheriv('aes-256-gcm', key, n);
  c.setAAD(Buffer.from(aad));
  return { n: b64(n), c: b64(Buffer.concat([c.update(plain), c.final(), c.getAuthTag()])) };
}
function unwrap(key, w, aad) {
  const all = unb64(w.c), d = crypto.createDecipheriv('aes-256-gcm', key, unb64(w.n));
  d.setAAD(Buffer.from(aad));
  d.setAuthTag(all.subarray(all.length - 16));
  return Buffer.concat([d.update(all.subarray(0, all.length - 16)), d.final()]);
}
const hkdf = (ikm, salt, info) => Buffer.from(crypto.hkdfSync('sha256', ikm, salt, info, 32));
async function deriveKek({ mode, password, keySecret }, kdf) {
  const m = MODES[mode], parts = [];
  if (m.pw) parts.push(await scrypt(norm(password), unb64(kdf.salt), 32, { N: kdf.N, r: kdf.r, p: kdf.p, maxmem: 256 * kdf.N * kdf.r }));
  if (m.kf) parts.push(keySecret);
  return hkdf(Buffer.concat(parts), unb64(kdf.salt), 'strongbox/kek/v1');
}

class Vault {
  /** @param {{db, log, send, settings}} o  db: kit Db with the vault_meta table; settings: () => the vault settings block */
  constructor({ db, log = () => {}, send = () => {}, settings = () => ({}) }) {
    Object.assign(this, { db, log, send, settings });
    this.dk = null; this.ek = null;
    this.lastTouch = 0; this.fails = 0; this.blockedUntil = 0;
  }

  header() { const r = this.db.get("SELECT v FROM vault_meta WHERE k='header'"); return r ? JSON.parse(r.v) : null; }
  saveHeader(h) { this.db.run("INSERT INTO vault_meta(k, v) VALUES('header', ?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", JSON.stringify(h)); }
  get unlocked() { return !!this.dk; }
  state() { return !this.header() ? 'uninitialized' : this.dk ? 'unlocked' : 'locked'; }
  status() {
    const h = this.header();
    return { state: this.state(), mode: h ? h.mode : null, keyFileId: h ? h.kf : null, hasRecovery: !!(h && h.rk), blockedMs: Math.max(0, this.blockedUntil - Date.now()), minPassword: MIN_PASSWORD, autoLockMinutes: Number(this.settings().autoLockMinutes) || 0, lockInMs: this.dk ? this.lockInMs() : null };
  }
  touch() { this.lastTouch = Date.now(); }
  lockInMs() { const m = Number(this.settings().autoLockMinutes) || 0; return m > 0 ? Math.max(0, this.lastTouch + m * 60000 - Date.now()) : null; }
  require() { if (!this.dk) { const e = new Error('The vault is locked'); e.code = 'locked'; throw e; } this.touch(); }

  // ---- records ------------------------------------------------------------------------------
  seal(obj, aad) {
    this.require();
    const n = crypto.randomBytes(12), c = crypto.createCipheriv('aes-256-gcm', this.ek, n);
    c.setAAD(Buffer.from(aad));
    return Buffer.concat([Buffer.from([1]), n, c.update(JSON.stringify(obj), 'utf8'), c.final(), c.getAuthTag()]);
  }
  open(blob, aad) {
    this.require();
    const b = Buffer.from(blob);
    if (b[0] !== 1) throw new Error('Unknown record format');
    const d = crypto.createDecipheriv('aes-256-gcm', this.ek, b.subarray(1, 13));
    d.setAAD(Buffer.from(aad));
    d.setAuthTag(b.subarray(b.length - 16));
    return JSON.parse(Buffer.concat([d.update(b.subarray(13, b.length - 16)), d.final()]).toString('utf8'));
  }

  // ---- lifecycle ----------------------------------------------------------------------------
  setKeys(dk) { this.dk = dk; this.ek = hkdf(dk, Buffer.alloc(0), 'strongbox/records/v1'); this.touch(); }
  lock(reason = 'manual') {
    if (!this.dk) return false;
    this.dk.fill(0); this.ek.fill(0); this.dk = null; this.ek = null;
    this.log(`vault locked (${reason})`); this.send('vault:locked', { reason });
    return true;
  }
  kdfParams() {
    const log2 = Math.min(20, Math.max(14, Number(this.settings().kdfLog2N) || 17));
    return { alg: 'scrypt', N: 2 ** log2, r: 8, p: 1, salt: b64(crypto.randomBytes(16)) };
  }
  checkNew({ mode, password }) {
    if (!MODES[mode]) throw new Error('Unknown unlock mode');
    if (MODES[mode].pw && norm(password).length < MIN_PASSWORD) throw new Error(`The passphrase needs at least ${MIN_PASSWORD} characters`);
  }
  /** Builds a header around `dk` for the chosen factors. Returns { header, keyFile, recoveryKey }. */
  async wrapFor(dk, { mode, password, recovery = true }) {
    this.checkNew({ mode, password });
    const kdf = this.kdfParams(), kf = MODES[mode].kf ? newKeyFile() : null;
    const kek = await deriveKek({ mode, password, keySecret: kf && kf.secret }, kdf);
    const header = { v: 1, mode, created: Date.now(), kdf, kf: kf ? kf.id : null, dk: wrap(kek, dk, 'strongbox/dk/v1'), rk: null };
    let recoveryKey = null;
    if (recovery) {
      const rb = crypto.randomBytes(25), salt = crypto.randomBytes(16);
      header.rk = { salt: b64(salt), ...wrap(hkdf(rb, salt, 'strongbox/recovery/v1'), dk, 'strongbox/rk/v1') };
      recoveryKey = recoveryText(rb);
    }
    return { header, keyFile: kf ? kf.text : null, keyFileId: kf ? kf.id : null, recoveryKey };
  }
  async create(opts) {
    if (this.header()) throw new Error('The vault already exists');
    const dk = crypto.randomBytes(32);
    const out = await this.wrapFor(dk, opts);
    this.saveHeader(out.header); this.setKeys(dk);
    this.log(`vault created (${opts.mode}${out.header.rk ? ', recovery key' : ''})`);
    return { keyFile: out.keyFile, keyFileId: out.keyFileId, recoveryKey: out.recoveryKey };
  }
  /** Unlocks with { password, keyFile } or { recoveryKey }. Failures are throttled and never say which factor was wrong. */
  async unlock({ password, keyFile, recoveryKey } = {}) {
    const h = this.header(); if (!h) throw new Error('The vault has not been set up yet');
    if (this.dk) return true;
    const wait = this.blockedUntil - Date.now();
    if (wait > 0) { const e = new Error(`Too many failed attempts; try again in ${Math.ceil(wait / 1000)} s`); e.code = 'throttled'; throw e; }
    let dk;
    try {
      if (recoveryKey) {
        if (!h.rk) throw new Error('no recovery key');
        dk = unwrap(hkdf(parseRecovery(recoveryKey), unb64(h.rk.salt), 'strongbox/recovery/v1'), h.rk, 'strongbox/rk/v1');
      } else {
        const m = MODES[h.mode];
        if (m.pw && !password) throw new Error('The passphrase is required');
        if (m.kf && !keyFile) throw new Error('The key file is required');
        const keySecret = m.kf ? parseKeyFile(keyFile) : null;
        dk = unwrap(await deriveKek({ mode: h.mode, password, keySecret }, h.kdf), h.dk, 'strongbox/dk/v1');
      }
    } catch (e) {
      if (/required|not a Strongbox|damaged|40 letters/.test(e.message)) throw e; // input problems, not guesses
      this.fails++;
      if (this.fails >= 5) this.blockedUntil = Date.now() + Math.min(15 * 60000, 30000 * 2 ** (this.fails - 5));
      const err = new Error('Wrong passphrase, key file or recovery key'); err.code = 'wrong'; err.fails = this.fails; throw err;
    }
    this.fails = 0; this.blockedUntil = 0;
    this.setKeys(dk); this.log('vault unlocked' + (recoveryKey ? ' (recovery key)' : ''));
    return true;
  }
  /** Re-wraps the data key under new factors (the data itself is untouched). Needs the vault unlocked. */
  async rewrap({ mode, password, recovery = 'keep' }) {
    this.require();
    const old = this.header();
    const out = await this.wrapFor(Buffer.from(this.dk), { mode, password, recovery: recovery === 'new' });
    if (recovery === 'keep') out.header.rk = old.rk;
    else if (recovery === 'none') out.header.rk = null;
    this.saveHeader(out.header);
    this.log(`vault unlock method changed (${mode})`);
    return { keyFile: out.keyFile, keyFileId: out.keyFileId, recoveryKey: out.recoveryKey };
  }
  /** A fresh recovery key; the old one stops working. */
  async newRecovery() {
    this.require();
    const h = this.header(), rb = crypto.randomBytes(25), salt = crypto.randomBytes(16);
    h.rk = { salt: b64(salt), ...wrap(hkdf(rb, salt, 'strongbox/recovery/v1'), this.dk, 'strongbox/rk/v1') };
    this.saveHeader(h);
    return recoveryText(rb);
  }
}

module.exports = { Vault, MODES, MIN_PASSWORD, newKeyFile, parseKeyFile, parseRecovery, keyId };
