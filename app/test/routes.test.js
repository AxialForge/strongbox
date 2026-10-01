'use strict';
// The raw routes over real HTTP: attachments, restore, breached-password lists, and who may use them.
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { buildShell } = require('../server/server');

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sb-http-'));
const shell = buildShell({ dataDir, port: 0, host: '127.0.0.1' });
shell.svc.settings.set({ vault: { kdfLog2N: 14 } });

(async () => {
  shell.sec.setPassword('admin-password-for-tests');
  shell.sec.addUser('amy', 'amy-password-for-tests', 'standard', '127.0.0.1', 'test');
  await new Promise(r => { shell.server.listen(0, '127.0.0.1', r); });
  const base = `http://127.0.0.1:${shell.server.address().port}`;
  const login = async (username, password) => {
    const r = await fetch(base + '/api/login', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ username, password }) });
    assert.strictEqual(r.status, 200, 'login ' + username);
    return r.headers.get('set-cookie').split(';')[0];
  };
  const api = (cookie) => async (ch, ...args) => { const r = await fetch(`${base}/api/${ch}`, { method: 'POST', headers: { 'content-type': 'application/json', cookie }, body: JSON.stringify(args) }); return { status: r.status, body: await r.json() }; };
  const raw = (cookie, method, p, body) => fetch(base + p, { method, headers: { cookie, 'content-type': 'application/octet-stream' }, body });

  const admin = await login('admin', 'admin-password-for-tests'), amy = await login('amy', 'amy-password-for-tests');
  const A = api(admin), U = api(amy);

  assert.strictEqual((await raw('', 'POST', '/upload/file?entry=1', Buffer.from('x'))).status, 401, 'no session, no upload');
  assert.strictEqual((await A('vault:create', { mode: 'password', password: 'a long test passphrase', recovery: true })).status, 200);
  const tab = (await A('tabs:list')).body.result[0];
  const entry = (await A('entries:save', { tabId: tab.id, title: 'Router', secrets: { pass: 'router-pass-12345' } })).body.result;

  // attachments
  const png = Buffer.from([0x89, 0x50, 0x4e, 0x47, 1, 2, 3, 4, 5, 6, 7, 8]);
  const up = await raw(admin, 'POST', `/upload/file?entry=${entry.id}&name=${encodeURIComponent('serial plate.png')}&type=image%2Fpng`, png);
  assert.strictEqual(up.status, 200); const files = (await up.json()).result; assert.strictEqual(files[0].name, 'serial plate.png');
  const dl = await raw(admin, 'GET', `/download/file/${files[0].id}`);
  assert.strictEqual(dl.status, 200); assert.ok(Buffer.from(await dl.arrayBuffer()).equals(png)); assert.match(dl.headers.get('content-disposition'), /attachment; filename\*=UTF-8''serial%20plate\.png/); assert.strictEqual(dl.headers.get('x-file-type'), 'image/png');
  assert.strictEqual((await raw(amy, 'POST', `/upload/file?entry=${entry.id}&name=x`, png)).status, 403, 'standard accounts cannot upload');
  assert.strictEqual((await raw(amy, 'GET', `/download/file/${files[0].id}`)).status, 200, 'but may download');
  shell.svc.settings.set({ vault: { noReveal: ['amy'] } });
  assert.strictEqual((await raw(amy, 'GET', `/download/file/${files[0].id}`)).status, 400, 'unless their account may not reveal');
  assert.strictEqual((await U('entries:reveal', entry.id, 'field:pass')).body.ok, false);
  shell.svc.settings.set({ vault: { noReveal: [] } });
  assert.strictEqual((await raw(admin, 'POST', '/upload/file?entry=999&name=x', png)).status, 400);
  const cross = await fetch(base + `/upload/file?entry=${entry.id}&name=x`, { method: 'POST', headers: { cookie: admin, origin: 'http://evil.example' }, body: png });
  assert.strictEqual(cross.status, 403, 'another origin is refused');

  // restore: needs a fresh password check, replaces the vault, leaves it locked
  const backup = Buffer.from((await A('vault:backup')).body.result.base64, 'base64');
  await A('entries:save', { tabId: tab.id, title: 'Newer than the backup' });
  shell.sec.state.sessions && Object.values(shell.sec.state.sessions).forEach(s => { s.reauthAt = 0; }); // as if five minutes passed
  const noAuth = await raw(admin, 'POST', '/upload/restore', backup);
  if (noAuth.status === 401) assert.strictEqual((await noAuth.json()).reason, 'reauth');
  else assert.strictEqual(noAuth.status, 200, 'the session was freshly signed in, so its re-authentication window is still open');
  const re = await fetch(base + '/api/reauth', { method: 'POST', headers: { 'content-type': 'application/json', cookie: admin }, body: JSON.stringify({ password: 'admin-password-for-tests' }) });
  assert.strictEqual(re.status, 200);
  const ok = noAuth.status === 200 ? noAuth : await raw(admin, 'POST', '/upload/restore', backup);
  assert.strictEqual(ok.status, 200); assert.strictEqual((await ok.json()).result.entries, 1);
  assert.strictEqual((await raw(admin, 'POST', '/upload/restore', Buffer.from('junk'))).status, 400);
  assert.strictEqual((await A('vault:status')).body.result.state, 'locked');
  assert.strictEqual((await A('vault:unlock', { password: 'a long test passphrase' })).status, 200);
  assert.strictEqual((await A('entries:list')).body.result.length, 1);

  // breached-password list upload
  const bl = await raw(admin, 'POST', '/upload/breach', Buffer.from('router-pass-12345\nanother\n'));
  assert.strictEqual(bl.status, 200); assert.strictEqual((await bl.json()).result.count, 2);
  assert.strictEqual((await A('vault:health')).body.result.breached.length, 1);
  assert.strictEqual((await raw(amy, 'POST', '/upload/breach', Buffer.from('x\n'))).status, 403);

  shell.server.close(); shell.svc.shutdown();
  console.log('routes tests passed');
})().catch(e => { console.error(e); process.exit(1); });
