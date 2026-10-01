#!/usr/bin/env node
'use strict';
// The web shell for Strongbox: the kit does the serving, this file says what is specific.
//
//   node app/server/server.js [--data=<dir>] [--port=8083] [--host=0.0.0.0]
//   node app/server/server.js --set-password        (create/reset the "admin" account; reads STRONGBOX_PASSWORD or prompts)
const path = require('path');
const { createWebShell, resolveOptions } = require('../../kit/server/shell');
const { createService } = require('../main/service');
const app = require('../app.json');

// What each role may call. Admins get everything. Guests get nothing: there is no guest mode in a vault.
// Standard accounts can open the vault and read (reveal included, which is audited), never change it.
const ROLES = {
  GUEST: [],
  STANDARD: ['vault:status', 'vault:touch', 'vault:unlock', 'vault:lock', 'vault:health', 'data:dashboard', 'tabs:list', 'entries:list', 'entries:search', 'entries:get', 'entries:reveal', 'entries:totp', 'entries:print', 'codes:reveal', 'tags:list', 'templates:list', 'network:list'],
  // Ask for the account password again (within 5 minutes) before these.
  SENSITIVE: ['vault:create', 'vault:rewrap', 'vault:rotate', 'vault:restoreCheck', 'vault:newRecovery', 'vault:resetEmpty', 'vault:backup', 'entries:purge', 'entries:exportCsv', 'tabs:delete'],
};

const LIMITS = { file: 10 * 1024 * 1024, backup: 64 * 1024 * 1024, breach: 100 * 1024 * 1024 };
async function readRaw(req, max) {
  const chunks = []; let n = 0;
  for await (const c of req) { n += c.length; if (n > max) { req.destroy(); throw new Error(`That file is too large (the limit is ${Math.round(max / 1048576)} MB)`); } chunks.push(c); }
  return Buffer.concat(chunks);
}

/**
 * Raw routes for binary bodies the JSON API cannot carry: attachments, backups to restore, breached-password lists.
 *   POST /upload/file?entry=<id>&name=<n>&type=<mime>   (admin)      GET /download/file/<id>   (any signed-in account that may reveal)
 *   POST /upload/restore                                 (admin, asks for the account password again)
 *   POST /upload/breach                                  (admin)
 */
async function fileRoutes(req, res, url, t) {
  const upload = url.pathname.startsWith('/upload/'), download = url.pathname.startsWith('/download/file/');
  if (!upload && !download) return false;
  const { svc, sec, session, role, ip, json } = t;
  const actor = { user: session ? session.user : null, ip, role };
  if (!session) { json(res, 401, { ok: false, reason: 'login', error: 'sign in required' }); return true; }
  try {
    if (download) {
      if (req.method !== 'GET') { json(res, 405, { ok: false, error: 'GET only' }); return true; }
      const f = svc.files.read(actor, decodeURIComponent(url.pathname.slice('/download/file/'.length)));
      const safe = encodeURIComponent(f.name).replace(/['()]/g, escape);
      res.writeHead(200, { 'content-type': 'application/octet-stream', 'content-disposition': `attachment; filename*=UTF-8''${safe}`, 'x-content-type-options': 'nosniff', 'cache-control': 'no-store', 'content-length': f.data.length, 'x-file-type': f.type });
      res.end(f.data); return true;
    }
    if (req.method !== 'POST') { json(res, 405, { ok: false, error: 'POST only' }); return true; }
    const origin = req.headers.origin;
    if (origin && new URL(origin).host !== req.headers.host) { sec.audit('cross_origin_refused', ip, origin); json(res, 403, { ok: false, error: 'cross-origin request refused' }); return true; }
    if (role !== 'admin') { sec.audit('forbidden', ip, url.pathname, session.user); json(res, 403, { ok: false, reason: 'forbidden', error: 'Only admins can do that' }); return true; }
    if (url.pathname === '/upload/restore') {
      if (sec.needsReauth(session)) { json(res, 401, { ok: false, reason: 'reauth', error: 'Please re-enter your password for this action' }); return true; }
      sec.audit('sensitive_action', ip, 'restore', session.user);
      json(res, 200, { ok: true, result: svc.restoreFile(actor, await readRaw(req, LIMITS.backup)) }); return true;
    }
    if (url.pathname === '/upload/breach') { json(res, 200, { ok: true, result: svc.breach.load(actor, await readRaw(req, LIMITS.breach)) }); return true; }
    if (url.pathname === '/upload/file') {
      const buf = await readRaw(req, LIMITS.file);
      json(res, 200, { ok: true, result: svc.files.add(actor, Number(url.searchParams.get('entry')), url.searchParams.get('name'), url.searchParams.get('type'), buf) }); return true;
    }
    json(res, 404, { ok: false, error: 'unknown upload' }); return true;
  } catch (e) { json(res, e.code === 'locked' ? 423 : 400, { ok: false, error: e.message }); return true; }
}

function buildShell(opts, overrides = {}) {
  return createWebShell({
    app, createService, rootDir: path.join(__dirname, '..', '..'),
    dataDir: opts.dataDir, port: opts.port, host: opts.host, roles: ROLES,
    secrets: ['notify.email.pass', 'githubToken'],
    // Every vault channel is re-registered here so the audit log learns who (account and address) did it.
    webHandlers: ({ svc }) => new Map(Object.keys(svc.api).map(ch => [ch, (ctx, ...args) => svc.api[ch]({ user: ctx.session ? ctx.session.user : null, ip: ctx.ip, role: ctx.role }, ...args)])),
    routes: [fileRoutes],
    statusChannel: 'data:status',
    ...overrides,
  });
}

if (require.main === module) {
  const opts = resolveOptions({ app, defaultPort: app.port });
  const shell = buildShell(opts);
  if (opts.setPassword) shell.setPasswordCli(); else shell.start();
}

module.exports = { buildShell, ROLES, fileRoutes };
