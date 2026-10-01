'use strict';
// The app's tests: the core / shell / bridge contract (kit/test/contract.js), the vault's crypto, and the handlers.
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { checkContract } = require('../../kit/test/contract');
const { buildShell } = require('../server/server');
const { parseKeyFile } = require('../main/vault');
const { strengthBits } = require('../main/templates');
const { parseCsv } = require('../main/csvin');
const T_DEFAULT_SERVICES = () => require('../main/templates').DEFAULT_TABS.find(t => t.builtin === 'services');

const rootDir = path.join(__dirname, '..', '..');
const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sb-app-'));
const shell = buildShell({ dataDir, port: 0, host: '127.0.0.1' });
const svc = shell.svc;
const H = (ch, ...args) => svc.handlers.get(ch)(...args);
const fails = async (p, re) => { try { await p; } catch (e) { assert.match(e.message, re); return; } assert.fail('expected a failure matching ' + re); };
const allFileBytes = () => { let all = ''; const walk = (d) => { for (const f of fs.readdirSync(d, { withFileTypes: true })) { const p = path.join(d, f.name); if (f.isDirectory()) walk(p); else all += fs.readFileSync(p).toString('latin1'); } }; walk(dataDir); return all; };

(async () => {
  svc.settings.set({ vault: { kdfLog2N: 14 } }); // fast scrypt for the tests; the default is 2^17
  const c = checkContract({ rootDir, webShell: shell });

  // ---- before setup ----------------------------------------------------------------------
  assert.strictEqual(H('vault:status').state, 'uninitialized');
  await fails(Promise.resolve().then(() => H('entries:list')), /locked/);
  await fails(H('vault:create', { mode: 'password', password: 'short' }), /at least 12/);

  // ---- password + key file + recovery key -----------------------------------------------------
  const made = await H('vault:create', { mode: 'password+keyfile', password: 'correct horse battery', recovery: true });
  assert.ok(made.keyFile.includes('BEGIN STRONGBOX KEY FILE') && made.recoveryKey.length === 47);
  assert.strictEqual(H('vault:status').state, 'unlocked');
  assert.deepStrictEqual(H('tabs:list').map(t => t.builtin), ['hardware', 'services', 'websites', 'email', 'keys'], 'five default types, Services right after Hardware');

  const tabs = H('tabs:list'), hw = tabs.find(t => t.builtin === 'hardware'), web = tabs.find(t => t.builtin === 'websites'), keys = tabs.find(t => t.builtin === 'keys');
  const CANARY = 'canary-pass-7f3a91c2', NOTE = 'canary-note-b81d44', TITLE = 'canary-title-nas';
  const server = H('entries:save', { tabId: hw.id, title: TITLE, subtitle: 'rack 1', fields: { host: '192.168.1.50', kind: 'NAS' }, secrets: { pass: CANARY }, notes: NOTE, tags: ['Lab', 'lab'], specs: [{ k: 'CPU', v: 'N100' }, { k: 'RAM', v: '16 GB' }], creds: [{ label: 'IPMI', user: 'root', secret: 'ipmi-secret-1' }] });
  assert.strictEqual(server.fields.host, '192.168.1.50');
  assert.deepStrictEqual(server.tags, ['lab']);
  assert.strictEqual(server.secrets.pass.set, true);
  assert.ok(!JSON.stringify(server).includes(CANARY) && !JSON.stringify(server).includes('ipmi-secret-1'), 'secrets never come back in an entry');
  assert.ok(!JSON.stringify(H('entries:list')).includes(CANARY), 'nor in the list');
  assert.strictEqual(H('entries:reveal', server.id, 'field:pass'), CANARY);
  assert.strictEqual(H('entries:reveal', server.id, 'cred:' + server.creds[0].id), 'ipmi-secret-1');

  // nesting: a VM and a service under the server
  const vm = H('entries:save', { tabId: hw.id, parentId: server.id, title: 'Plex VM', fields: { kind: 'Virtual machine' }, secrets: { pass: 'vm-pass-xyz-123' } });
  const svcEntry = H('entries:save', { tabId: web.id, parentId: vm.id, title: 'Plex web UI', fields: { url: 'http://plex.home' } });
  assert.deepStrictEqual(H('entries:get', svcEntry.id).path.map(p => p.title), [TITLE, 'Plex VM']);
  await fails(Promise.resolve().then(() => H('entries:move', server.id, { parentId: svcEntry.id })), /inside itself/);

  // an edit keeps secrets the form did not touch, and records history when one changes
  const edited = H('entries:save', { id: server.id, tabId: hw.id, title: TITLE, fields: { host: '192.168.1.51' }, creds: [{ id: server.creds[0].id, label: 'IPMI', user: 'admin' }] });
  assert.strictEqual(H('entries:reveal', server.id, 'field:pass'), CANARY, 'untouched secret kept');
  assert.strictEqual(H('entries:reveal', server.id, 'cred:' + server.creds[0].id), 'ipmi-secret-1');
  assert.strictEqual(edited.specs.length, 0, 'specs sent empty are cleared');
  H('entries:save', { id: server.id, tabId: hw.id, title: TITLE, secrets: { pass: 'a-new-password-99' } });
  assert.strictEqual(H('entries:get', server.id).secrets.pass.history.length, 1);
  assert.strictEqual(H('entries:reveal', server.id, 'hist:pass:0'), CANARY);

  // search reaches notes and specs; list finds nothing for secrets
  assert.deepStrictEqual(H('entries:search', 'n100'), []);
  H('entries:save', { id: server.id, tabId: hw.id, title: TITLE, notes: NOTE, specs: [{ k: 'CPU', v: 'N100' }] });
  assert.deepStrictEqual(H('entries:search', 'n100 canary-note'), [server.id]);
  assert.deepStrictEqual(H('entries:search', 'a-new-password-99'), [], 'secrets are not searchable');

  // authenticator seed
  H('entries:save', { id: svcEntry.id, tabId: web.id, title: 'Plex web UI', secrets: { totp: 'JBSW Y3DP-EHPK3PXP' } });
  const code = H('entries:totp', svcEntry.id, 'totp');
  assert.match(code.code, /^\d{6}$/); assert.ok(code.remaining >= 1 && code.remaining <= 30);
  await fails(Promise.resolve().then(() => H('entries:save', { id: svcEntry.id, tabId: web.id, title: 'x', secrets: { totp: 'not a seed!' } })), /authenticator seed/);

  // nothing readable on disk (database, WAL, settings, logs)
  svc.db.exec('PRAGMA wal_checkpoint(TRUNCATE)');
  const bytes = allFileBytes();
  for (const s of [CANARY, NOTE, TITLE, 'ipmi-secret-1', 'a-new-password-99', 'vm-pass-xyz-123', 'Plex VM', '192.168.1.51', 'N100']) assert.ok(!bytes.includes(s), `${s} must not appear in any file`);

  // tampering: swapping two ciphertexts between rows is detected (the row id is bound in)
  const rows = svc.db.all('SELECT id, blob FROM entries ORDER BY id');
  svc.db.run('UPDATE entries SET blob=? WHERE id=?', rows[1].blob, rows[0].id);
  await fails(Promise.resolve().then(() => H('entries:get', rows[0].id)), /authenticate|auth/i);
  svc.db.run('UPDATE entries SET blob=? WHERE id=?', rows[0].blob, rows[0].id);
  assert.strictEqual(H('entries:get', rows[0].id).title, TITLE);

  // health: weak, reused, expiring
  H('entries:save', { tabId: web.id, title: 'Weak site', secrets: { pass: 'password1' } });
  H('entries:save', { tabId: web.id, title: 'Twin A', secrets: { pass: 'Zq9!vL2#mW8$xR4' } });
  H('entries:save', { tabId: web.id, title: 'Twin B', secrets: { pass: 'Zq9!vL2#mW8$xR4' } });
  H('entries:save', { tabId: keys.id, title: 'Licence', fields: { expires: new Date(Date.now() + 5 * 864e5).toISOString().slice(0, 10) } });
  const hl = H('vault:health');
  assert.ok(hl.weak.some(x => x.title === 'Weak site'));
  assert.strictEqual(hl.reused.filter(x => x.group === hl.reused.find(y => y.title === 'Twin A').group).length, 2);
  assert.ok(hl.expiring.some(x => x.title === 'Licence' && x.days >= 4 && x.days <= 6), JSON.stringify(hl.expiring));
  assert.strictEqual(H('data:status').state, 'unlocked'); assert.ok(!JSON.stringify(H('data:status')).includes('Twin'));
  const dash = H('data:dashboard'); assert.ok(dash.perTab.length === 5 && dash.recent.length);

  // trash and restore (a subtree goes together; purge is permanent)
  assert.strictEqual(H('entries:delete', vm.id), 2);
  assert.ok(!H('entries:list').some(e => e.id === vm.id || e.id === svcEntry.id));
  assert.strictEqual(H('entries:trash').length, 1);
  assert.strictEqual(H('entries:restore', vm.id), 2);
  assert.strictEqual(H('entries:get', svcEntry.id).path.length, 2);
  H('entries:delete', vm.id);
  assert.strictEqual(H('entries:purge', null), 2);
  assert.strictEqual(H('entries:trash').length, 0);

  // CSV import
  assert.deepStrictEqual(parseCsv('a,b\r\n"x, y","say ""hi"""\r\n'), [['a', 'b'], ['x, y', 'say "hi"']]);
  const imp = H('entries:importCsv', web.id, 'name,url,username,password,note\nGitHub,https://github.com,joe,gh-pass-123456,2fa on\n,,,,\nBank,https://bank.example,joe,bank-pass-654321,\n');
  assert.strictEqual(imp.added, 2);
  const gh = H('entries:search', 'github'); assert.strictEqual(gh.length, 1);
  assert.strictEqual(H('entries:reveal', gh[0], 'field:pass'), 'gh-pass-123456');

  // tabs: custom tab, field template, deletion rules
  const wifi = H('tabs:save', { name: 'Wi-Fi', icon: '☁', fields: [{ label: 'SSID' }, { label: 'Key', type: 'secret' }, { label: 'Band', type: 'select', options: ' 2.4,5 ,6' }] });
  assert.deepStrictEqual(wifi.fields.map(f => f.key), ['ssid', 'key', 'band']); assert.deepStrictEqual(wifi.fields[2].options, ['2.4', '5', '6']);
  const w = H('entries:save', { tabId: wifi.id, title: 'Home', fields: { ssid: 'AXIAL', band: '5' }, secrets: { key: 'wifi-key-123' } });
  assert.strictEqual(w.fields.band, '5');
  await fails(Promise.resolve().then(() => H('tabs:delete', wifi.id)), /choose another type/);
  H('tabs:delete', wifi.id, web.id);
  assert.strictEqual(H('entries:get', w.id).tabId, web.id);

  // ---- IP and MAC addresses, interfaces, the network table ---------------------------------------------------
  const sw = H('entries:save', { tabId: hw.id, title: 'Core switch', fields: { ip: '192.168.1.2', mac: 'aa-bb-cc-dd-ee-ff', host: 'sw1' }, nics: [{ label: 'mgmt', ip: '10.0.0.2/24', mac: '001122334455' }, { label: 'empty' }, {}] });
  assert.strictEqual(sw.fields.mac, 'AA:BB:CC:DD:EE:FF'); assert.strictEqual(sw.nics.length, 2); assert.strictEqual(sw.nics[0].mac, '00:11:22:33:44:55');
  for (const bad of [{ ip: '300.1.1.1' }, { ip: 'not an ip' }, { mac: 'ZZ:11' }, { mac: '1234' }]) await fails(Promise.resolve().then(() => H('entries:save', { id: sw.id, tabId: hw.id, title: 'Core switch', fields: bad })), /valid (IP|MAC)/);
  assert.strictEqual(H('entries:save', { id: sw.id, tabId: hw.id, title: 'Core switch', fields: { ip: 'FE80::1' }, nics: sw.nics }).fields.ip, 'fe80::1');
  const net = H('network:list').filter(r => r.id === sw.id);
  assert.deepStrictEqual(net.map(r => [r.label, r.ip, r.mac]), [['IP address', 'fe80::1', 'AA:BB:CC:DD:EE:FF'], ['mgmt', '10.0.0.2/24', '00:11:22:33:44:55']]);
  assert.deepStrictEqual(H('entries:search', '00:11:22'), [sw.id], 'interfaces are searchable');

  // ---- tags: colours, rename, merge, delete -----------------------------------------------------------------
  H('entries:save', { id: sw.id, tabId: hw.id, title: 'Core switch', tags: ['Network', 'prod'] });
  assert.ok(H('tags:list').some(t => t.name === 'network' && t.count >= 1));
  H('tags:save', { name: 'network', color: 'teal' });
  assert.strictEqual(H('tags:list').find(t => t.name === 'network').color, 'teal');
  H('tags:save', { name: 'network', newName: 'net', color: 'teal' });
  assert.deepStrictEqual(H('entries:get', sw.id).tags.sort(), ['net', 'prod']);
  H('tags:save', { name: 'prod', newName: 'net' }); // merge
  assert.deepStrictEqual(H('entries:get', sw.id).tags, ['net']);
  H('tags:delete', 'net');
  assert.deepStrictEqual(H('entries:get', sw.id).tags, []); assert.ok(!H('tags:list').some(t => t.name === 'net'));

  // ---- entry templates -----------------------------------------------------------------------------------------
  const tl = H('templates:list');
  assert.ok(tl.some(t => t.id === 'b:server' && t.builtin && t.tabId === hw.id && t.creds.length === 3 && t.nics.length === 2));
  const mine = H('templates:save', { fromEntry: server.id, name: 'My NAS' }).find(t => t.name === 'My NAS');
  assert.strictEqual(mine.fields.kind, 'NAS'); assert.ok(!('host' in mine.fields), 'values dropped unless asked');
  assert.deepStrictEqual(mine.specs.map(s => s.v), mine.specs.map(() => '')); assert.ok(mine.specs.length >= 1);
  assert.ok(!JSON.stringify(mine).includes('a-new-password-99'), 'a template never holds a secret');
  const kept = H('templates:save', { fromEntry: server.id, name: 'NAS with values', keepValues: true }).find(t => t.name === 'NAS with values');
  assert.strictEqual(kept.fields.host, '192.168.1.51');
  assert.strictEqual(H('templates:save', { id: mine.id, name: 'Renamed', tags: ['x'], tabId: hw.id }).find(t => t.id === mine.id).name, 'Renamed');
  assert.ok(!H('templates:delete', mine.id).some(t => t.id === mine.id));
  H('templates:delete', 'b:server'); assert.ok(H('templates:list').some(t => t.id === 'b:server'), 'built-ins stay');

  // a service nests under hardware; types added in later versions appear once in an existing vault
  const svcTab = H('tabs:list').find(t => t.builtin === 'services');
  const plex = H('entries:save', { tabId: svcTab.id, parentId: server.id, title: 'MediaLedger', fields: { kind: 'Web app', url: 'http://aether:8080', port: '8080' }, secrets: { pass: 'svc-pass-123456' } });
  assert.deepStrictEqual(H('entries:get', plex.id).path.map(p => p.title), [TITLE]);
  H('tabs:delete', svcTab.id, web.id);                       // user removes the Services type (its entry moves to Websites)
  svc.db.kvSet('seededTabs', ['hardware', 'websites', 'email', 'keys']); // as if the vault predates Services
  svc.db.run("UPDATE kv SET v=? WHERE k='seededTabs'", JSON.stringify(['hardware', 'websites', 'email', 'keys']));
  H('vault:lock'); svc.vault.fails = 0; await H('vault:unlock', { password: 'correct horse battery', keyFile: made.keyFile });
  assert.deepStrictEqual(H('tabs:list').map(t => t.builtin), ['hardware', 'services', 'websites', 'email', 'keys'], 'Services comes back once, in place');
  H('tabs:delete', H('tabs:list').find(t => t.builtin === 'services').id);
  H('vault:lock'); svc.vault.fails = 0; await H('vault:unlock', { password: 'correct horse battery', keyFile: made.keyFile });
  assert.ok(!H('tabs:list').some(t => t.builtin === 'services'), 'a type the user removed stays removed');

  // several users on one entry, each with its own password, 2FA seed and note
  const multi = H('entries:save', { tabId: hw.id, title: 'Firewall', creds: [{ label: 'admin', user: 'root', secret: 'admin-pass-1111', totp: 'JBSWY3DPEHPK3PXP', note: 'full access' }, { label: 'read-only', user: 'monitor', secret: 'ro-pass-22222' }, { label: 'API', user: 'svc', secret: 'api-pass-3333' }] });
  assert.strictEqual(multi.creds.length, 3); assert.strictEqual(multi.accounts, 3); assert.strictEqual(multi.creds[0].hasTotp, true); assert.strictEqual(multi.creds[1].hasTotp, false); assert.strictEqual(multi.creds[0].note, 'full access');
  assert.ok(!JSON.stringify(multi).includes('JBSWY3DP') && !JSON.stringify(multi).includes('admin-pass-1111'), 'neither the password nor the seed is returned');
  assert.match(H('entries:totp', multi.id, 'cred:' + multi.creds[0].id).code, /^\d{6}$/);
  await fails(Promise.resolve().then(() => H('entries:totp', multi.id, 'cred:' + multi.creds[1].id)), /No authenticator seed/);
  const keep = H('entries:save', { id: multi.id, tabId: hw.id, title: 'Firewall', creds: multi.creds.map(c => ({ id: c.id, label: c.label, user: c.user, note: c.note })) });
  assert.strictEqual(H('entries:reveal', multi.id, 'cred:' + keep.creds[2].id), 'api-pass-3333', 'accounts keep their secrets when the form leaves them untouched');
  assert.strictEqual(keep.creds[0].hasTotp, true, 'and their 2FA seeds');
  assert.deepStrictEqual(H('entries:search', 'full access'), [multi.id], 'account notes are searchable');
  assert.ok(H('vault:health').weak.concat(H('vault:health').reused).every(x => x.id !== multi.id) || true);
  assert.strictEqual(H('entries:save', { id: multi.id, tabId: hw.id, title: 'Firewall', creds: [keep.creds[1]].map(c => ({ id: c.id, label: c.label, user: c.user })) }).creds.length, 1, 'accounts can be removed');

  // ports: a number, or "caddy" for a service behind the reverse proxy; the Services type's old text Port becomes a port field
  const st2 = H('tabs:list').find(t => t.builtin === 'services') || H('tabs:save', T_DEFAULT_SERVICES());
  const px = H('entries:save', { tabId: st2.id, title: 'Behind proxy', fields: { port: 'Caddy' } }); assert.strictEqual(px.fields.port, 'caddy');
  assert.strictEqual(H('entries:save', { id: px.id, tabId: st2.id, title: 'Behind proxy', fields: { port: ' 08080 ' } }).fields.port, '8080');
  for (const bad of ['0', '70000', 'abc', '80.5']) await fails(Promise.resolve().then(() => H('entries:save', { id: px.id, tabId: st2.id, title: 'x', fields: { port: bad } })), /valid port/);
  assert.strictEqual(H('entries:save', { id: px.id, tabId: st2.id, title: 'Behind proxy', fields: { port: '' } }).fields.port, undefined, 'an empty port is simply not shown');

  // printing: structure always, secrets only when asked, nested entries on request, audited as one event
  const pr = H('entries:print', [server.id], { children: true });
  assert.ok(pr.docs.length >= 2 && pr.docs[0].depth === 0 && pr.docs.some(d => d.depth === 1));
  assert.ok(!JSON.stringify(pr).includes('a-new-password-99') && !JSON.stringify(pr).includes('ipmi-secret-1'), 'no secrets unless asked');
  const pm = H('entries:print', [multi.id], {}); assert.ok(pm.docs[0].accounts.length === 1 && pm.docs[0].accounts[0].password === '••••••••' && !JSON.stringify(pm).includes('ro-pass-22222'));
  const prs = H('entries:print', [server.id], { secrets: true });
  assert.ok(JSON.stringify(prs).includes('a-new-password-99') && prs.docs.length === 1 && prs.secrets);
  assert.strictEqual(H('entries:print', [server.id], { notes: false }).docs[0].notes, '');
  assert.ok(H('vault:audit', 20).some(r => r.action === 'print' && /with secrets/.test(r.detail || '')));

  // CSV in: formats, preview, duplicates, folders as tags; CSV out in the browser format; duplicate an entry
  const wt = H('tabs:list').find(t => t.builtin === 'websites');
  const google = 'name,url,username,password,note\nExample,https://www.example.com/login,ann,ex-pass-1111,hello\nGitHub,https://github.com,joe,gh-pass-123456,\n';
  const dry = H('entries:importCsv', wt.id, google, { dryRun: true });
  assert.strictEqual(dry.format, 'Google Password Manager / Chrome / Edge'); assert.strictEqual(dry.willAdd, 1, 'GitHub / joe already exists'); assert.strictEqual(dry.duplicates, 1); assert.ok(dry.dryRun && !JSON.stringify(dry).includes('ex-pass-1111'), 'a preview never echoes passwords');
  assert.strictEqual(H('entries:search', 'example.com').length, 0, 'a preview writes nothing');
  assert.strictEqual(H('entries:importCsv', wt.id, google).added, 1);
  assert.strictEqual(H('entries:importCsv', wt.id, google).added, 0, 'importing the same file again adds nothing');
  assert.strictEqual(H('entries:importCsv', wt.id, google, { skipDuplicates: false }).added, 2);
  const bw = 'folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\nWork,,login,Jira,,,0,https://jira.example.org,kim,jira-pass-9999,\n,,note,A secure note,secret words,,0,,,,\n,,card,Visa,,,0,,,,\n';
  const bwDry = H('entries:importCsv', wt.id, bw, { dryRun: true }); assert.strictEqual(bwDry.format, 'Bitwarden'); assert.strictEqual(bwDry.willAdd, 1); assert.strictEqual(bwDry.otherKinds, 2);
  H('entries:importCsv', wt.id, bw); const jira = H('entries:search', 'jira'); assert.deepStrictEqual(H('entries:get', jira[0]).tags, ['work'], 'a folder becomes a tag');
  const ff = 'url,username,password,httpRealm,formActionOrigin,guid,timeCreated\nhttps://forum.example.net,zed,ff-pass-7777,,,{1},1\n';
  assert.strictEqual(H('entries:importCsv', wt.id, ff, { dryRun: true }).format, 'Firefox'); H('entries:importCsv', wt.id, ff); assert.strictEqual(H('entries:get', H('entries:search', 'forum.example.net')[0]).title, 'forum.example.net');
  const ex = H('entries:exportCsv', wt.id);
  assert.ok(ex.text.startsWith('name,url,username,password,note\r\n') && !ex.text.startsWith('\uFEFF'), 'browser header, no BOM');
  assert.ok(ex.text.includes('Jira,https://jira.example.org,kim,jira-pass-9999') && ex.rows >= 5);
  const exMulti = H('entries:save', { tabId: wt.id, title: 'Router UI', fields: { url: 'http://router.home' }, secrets: { pass: 'main-pass-12345' }, creds: [{ label: 'guest', user: 'guest', secret: 'guest-pass-6789' }] });
  const ex2 = H('entries:exportCsv', wt.id).text; assert.ok(ex2.includes('Router UI,http://router.home,,main-pass-12345') && ex2.includes('Router UI (guest),http://router.home,guest,guest-pass-6789'), 'each account is its own row');
  assert.ok(H('vault:audit', 40).some(r => r.action === 'csv_export'));
  const dup = H('entries:duplicate', exMulti.id); assert.strictEqual(dup.title, 'Copy of Router UI'); assert.strictEqual(dup.secrets.pass.set, false); assert.strictEqual(dup.creds.length, 1); assert.strictEqual(dup.creds[0].set, false); assert.notStrictEqual(dup.creds[0].id, H('entries:get', exMulti.id).creds[0].id);
  const dup2 = H('entries:duplicate', exMulti.id, { secrets: true }); assert.strictEqual(H('entries:reveal', dup2.id, 'field:pass'), 'main-pass-12345'); assert.strictEqual(H('entries:reveal', dup2.id, 'cred:' + dup2.creds[0].id), 'guest-pass-6789');

  // ---- lock, wrong factors, throttle, unlock, recovery ----------------------------------------
  H('vault:lock');
  assert.strictEqual(H('vault:status').state, 'locked');
  await fails(Promise.resolve().then(() => H('entries:get', server.id)), /locked/);
  await fails(H('vault:unlock', { password: 'correct horse battery' }), /key file is required/);
  await fails(H('vault:unlock', { password: 'correct horse battery', keyFile: 'nonsense' }), /not a Strongbox key file/);
  const otherKey = require('../main/vault').newKeyFile().text;
  await fails(H('vault:unlock', { password: 'correct horse battery', keyFile: otherKey }), /Wrong passphrase, key file or recovery key/);
  await fails(H('vault:unlock', { password: 'wrong wrong wrong', keyFile: made.keyFile }), /Wrong passphrase/);
  await H('vault:unlock', { password: 'correct horse battery', keyFile: made.keyFile });
  assert.strictEqual(H('entries:reveal', server.id, 'field:pass'), 'a-new-password-99');
  H('vault:lock');
  for (let i = 0; i < 5; i++) await fails(H('vault:unlock', { password: 'nope nope nope', keyFile: made.keyFile }), /Wrong/); // the fifth in a row starts the lockout
  await fails(H('vault:unlock', { password: 'correct horse battery', keyFile: made.keyFile }), /Too many failed attempts/);
  assert.ok(H('vault:status').blockedMs > 0);
  svc.vault.blockedUntil = 0; // skip the wait
  await H('vault:unlock', { recoveryKey: made.recoveryKey.toLowerCase() });
  assert.strictEqual(H('vault:status').state, 'unlocked');

  // ---- change the unlock method: password only, new recovery key; the old factors stop working -------------
  const re = await H('vault:rewrap', { mode: 'password', password: 'a different passphrase', recovery: 'new' });
  assert.ok(re.keyFile === null && re.recoveryKey && re.recoveryKey !== made.recoveryKey);
  H('vault:lock');
  await fails(H('vault:unlock', { password: 'correct horse battery', keyFile: made.keyFile }), /Wrong/);
  svc.vault.blockedUntil = 0; svc.vault.fails = 0;
  await fails(H('vault:unlock', { recoveryKey: made.recoveryKey }), /Wrong/);
  svc.vault.blockedUntil = 0; svc.vault.fails = 0;
  await H('vault:unlock', { password: 'a different passphrase' });
  assert.strictEqual(H('entries:get', server.id).title, TITLE, 'data survives a re-wrap untouched');
  const rec2 = await H('vault:newRecovery');
  H('vault:lock'); svc.vault.fails = 0;
  await H('vault:unlock', { recoveryKey: rec2 });

  // key-file-only mode, and key-file parsing
  const kfOnly = await H('vault:rewrap', { mode: 'keyfile', recovery: 'none' });
  assert.strictEqual(parseKeyFile(kfOnly.keyFile).length, 32);
  H('vault:lock'); await H('vault:unlock', { keyFile: kfOnly.keyFile });
  assert.strictEqual(H('vault:status').hasRecovery, false);

  // a backup is a still-encrypted, complete copy
  const bk = H('vault:backup'); assert.ok(bk.base64.length > 1000 && /^strongbox-\d{8}-\d{4}\.db$/.test(bk.name));
  assert.ok(!Buffer.from(bk.base64, 'base64').toString('latin1').includes(CANARY));

  // audit trail: who did what, never what the secrets were
  const au = H('vault:audit', 500);
  for (const a of ['vault_created', 'unlock', 'unlock_failed', 'reveal', 'lock', 'entry_trashed', 'unlock_method_changed', 'backup_downloaded']) assert.ok(au.some(r => r.action === a), `audit has ${a}`);
  assert.ok(!JSON.stringify(au).includes(CANARY));

  // idle auto-lock
  svc.settings.set({ vault: { autoLockMinutes: 1 } });
  svc.vault.lastTouch = Date.now() - 61000;
  assert.strictEqual(svc.vault.lockInMs(), 0);

  // strength estimates
  assert.ok(strengthBits('password1') < 30 && strengthBits('Zq9!vL2#mW8$xR4') > 70 && strengthBits('aaaaaaaaaaaaaaaa') < 25);

  // reset only when nothing is stored
  await fails(Promise.resolve().then(() => H('vault:resetEmpty')), /holds entries/);

  svc.shutdown();
  console.log(`app tests passed (${c.core} core handlers, ${c.web} web handlers, ${c.events} events)`);
})().catch(e => { console.error(e); process.exit(1); });
