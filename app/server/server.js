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
  STANDARD: ['vault:status', 'vault:touch', 'vault:unlock', 'vault:lock', 'vault:health', 'data:dashboard', 'tabs:list', 'entries:list', 'entries:search', 'entries:get', 'entries:reveal', 'entries:totp', 'tags:list', 'templates:list', 'network:list'],
  // Ask for the account password again (within 5 minutes) before these.
  SENSITIVE: ['vault:create', 'vault:rewrap', 'vault:newRecovery', 'vault:resetEmpty', 'vault:backup', 'entries:purge', 'tabs:delete'],
};

function buildShell(opts, overrides = {}) {
  return createWebShell({
    app, createService, rootDir: path.join(__dirname, '..', '..'),
    dataDir: opts.dataDir, port: opts.port, host: opts.host, roles: ROLES,
    secrets: ['notify.email.pass', 'githubToken'],
    // Every vault channel is re-registered here so the audit log learns who (account and address) did it.
    webHandlers: ({ svc }) => new Map(Object.keys(svc.api).map(ch => [ch, (ctx, ...args) => svc.api[ch]({ user: ctx.session ? ctx.session.user : null, ip: ctx.ip }, ...args)])),
    statusChannel: 'data:status',
    ...overrides,
  });
}

if (require.main === module) {
  const opts = resolveOptions({ app, defaultPort: app.port });
  const shell = buildShell(opts);
  if (opts.setPassword) shell.setPasswordCli(); else shell.start();
}

module.exports = { buildShell, ROLES };
