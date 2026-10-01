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
  assert.deepStrictEqual(H('tabs:list').map(t => t.builtin), ['hardware', 'services', 'websites', 'email', 'wifi', 'mobile', 'keys'], 'seven default types, Services right after Hardware');

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
  const dash = H('data:dashboard'); assert.ok(dash.perTab.length === 7 && dash.recent.length);

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
  assert.deepStrictEqual(H('tabs:list').map(t => t.builtin), ['hardware', 'services', 'websites', 'email', 'wifi', 'mobile', 'keys'], 'Services comes back once, in place');
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

  // ---- Wi-Fi type, rotation reminders, known-breached passwords, bulk actions ------------------------------
  const wifiTab = H('tabs:list').find(t => t.builtin === 'wifi');
  assert.ok(wifiTab && wifiTab.fields.some(f => f.key === 'ssid') && H('templates:list').some(t => t.id === 'b:wifi' && t.tabId === wifiTab.id));
  const wnet = H('entries:save', { tabId: wifiTab.id, title: 'Home Wi-Fi', fields: { ssid: 'AXIAL', security: 'WPA2/WPA3' }, secrets: { pass: 'wifi-secret-pass-1' }, rotateDays: 1 });
  assert.strictEqual(wnet.rotateDays, 1);
  assert.ok(!H('vault:health').due.some(d => d.id === wnet.id), 'not due yet');
  const realNow = Date.now; Date.now = () => realNow() + 3 * 864e5;
  try { const due = H('vault:health').due.find(d => d.id === wnet.id); assert.ok(due && due.days >= 3 && due.every === 1, 'due after three days'); } finally { Date.now = realNow; }
  assert.strictEqual(H('entries:save', { id: wnet.id, tabId: wifiTab.id, title: 'Home Wi-Fi', rotateDays: 0 }).rotateDays, 0);

  const weakKnown = H('entries:save', { tabId: web.id, title: 'Known bad', secrets: { pass: 'password123' } });
  assert.ok(H('vault:health').breached.some(b => b.id === weakKnown.id), 'built-in common passwords are flagged');
  const sha1 = (x) => require('crypto').createHash('sha1').update(x).digest('hex').toUpperCase();
  const leaked = H('entries:save', { tabId: web.id, title: 'Leaked', secrets: { pass: 'Zq9!custom-leaked-pass' } });
  assert.ok(!H('vault:health').breached.some(b => b.id === leaked.id));
  assert.strictEqual(svc.breach.load({ user: 'a' }, Buffer.from(`${sha1('Zq9!custom-leaked-pass')}:1234\r\nsome-other-leak\r\n\r\n`)).count, 2);
  assert.ok(H('vault:health').breached.some(b => b.id === leaked.id), 'a loaded list flags matching passwords');
  assert.strictEqual(H('breach:status').custom, 2);
  assert.strictEqual(H('breach:clear').custom, 0); assert.ok(!H('vault:health').breached.some(b => b.id === leaked.id));
  assert.strictEqual(H('vault:health').breached.some(b => b.id === weakKnown.id), true);

  const bulkA = H('entries:save', { tabId: web.id, title: 'Bulk A' }), bulkB = H('entries:save', { tabId: web.id, title: 'Bulk B', tags: ['keep'] });
  assert.strictEqual(H('entries:bulk', [bulkA.id, bulkB.id], 'addTag', 'Batch'), 2);
  assert.deepStrictEqual(H('entries:get', bulkB.id).tags.sort(), ['batch', 'keep']);
  assert.strictEqual(H('entries:bulk', [bulkA.id, bulkB.id], 'addTag', 'batch'), 0, 'already tagged');
  assert.strictEqual(H('entries:bulk', [bulkA.id, bulkB.id], 'removeTag', 'batch'), 2);
  assert.strictEqual(H('entries:bulk', [bulkA.id], 'favorite', true), 1); assert.strictEqual(H('entries:get', bulkA.id).favorite, true);
  assert.strictEqual(H('entries:bulk', [bulkA.id, bulkB.id], 'move', { tabId: hw.id }), 2); assert.strictEqual(H('entries:get', bulkB.id).tabId, hw.id);
  await fails(Promise.resolve().then(() => H('entries:bulk', [bulkA.id], 'move', { tabId: 99999 })), /No such type/);
  await fails(Promise.resolve().then(() => H('entries:bulk', [bulkA.id], 'explode')), /Unknown bulk action/);
  assert.strictEqual(H('entries:bulk', [bulkA.id, bulkB.id], 'delete'), 2); assert.ok(!H('entries:list').some(e => e.id === bulkA.id));
  H('entries:purge', null);

  // ---- accounts that may see entries but not passwords ---------------------------------------------------------
  svc.settings.set({ vault: { noReveal: ['bob'] } });
  const bob = { user: 'bob', ip: '10.0.0.9', role: 'standard' }, admin = { user: 'bob', ip: '10.0.0.9', role: 'admin' };
  const call = (a, ch, ...args) => svc.api[ch](a, ...args);
  assert.strictEqual(call(bob, 'entries:get', multi.id).canReveal, false); assert.strictEqual(call(admin, 'entries:get', multi.id).canReveal, true, 'admins are never restricted');
  assert.ok(call(bob, 'entries:list').every(e => e.quick === null)); assert.ok(call({ user: 'amy', role: 'standard' }, 'entries:list').some(e => e.quick));
  for (const [ch, args] of [['entries:reveal', [server.id, 'field:pass']], ['entries:totp', [svcEntry.id, 'totp']], ['entries:print', [[server.id], { secrets: true }]]]) assert.throws(() => call(bob, ch, ...args), /not their passwords/, ch);
  assert.ok(call(bob, 'entries:print', [server.id], {}).docs.length, 'printing without secrets is fine');
  assert.strictEqual(call({ user: 'amy', role: 'standard' }, 'entries:reveal', server.id, 'field:pass'), 'a-new-password-99');
  svc.settings.set({ vault: { noReveal: [] } });

  // ---- entries limited to some accounts -------------------------------------------------------------------------
  const onlyAdmins = H('entries:save', { tabId: hw.id, title: 'Only the admins', tags: ['hush'], fields: { ip: '10.9.9.9' }, secrets: { pass: 'adm-only-pass-1' }, visibleTo: ['@admins'] });
  const forAmy = H('entries:save', { tabId: hw.id, title: 'For Amy', fields: { ip: '10.9.9.10' }, secrets: { pass: 'amy-only-pass-2' }, visibleTo: ['amy'] });
  const openKid = H('entries:save', { tabId: hw.id, parentId: onlyAdmins.id, title: 'Open child of a hidden parent' });
  const [amyU, benU, adm] = [{ user: 'amy', role: 'standard' }, { user: 'ben', role: 'standard' }, { user: 'root', role: 'admin' }];
  const ids = (a) => call(a, 'entries:list').map(e => e.id);
  assert.ok(ids(adm).includes(onlyAdmins.id) && ids(adm).includes(forAmy.id) && ids(null === 0 ? adm : { role: undefined }).includes(onlyAdmins.id), 'admins and the core see everything');
  assert.ok(ids(amyU).includes(forAmy.id) && !ids(amyU).includes(onlyAdmins.id));
  assert.ok(!ids(benU).includes(forAmy.id) && !ids(benU).includes(onlyAdmins.id) && ids(benU).includes(openKid.id));
  assert.strictEqual(call(adm, 'entries:list').find(e => e.id === forAmy.id).restricted, true);
  assert.throws(() => call(benU, 'entries:get', forAmy.id), /No such entry/); assert.throws(() => call(amyU, 'entries:get', onlyAdmins.id), /No such entry/); assert.ok(call(amyU, 'entries:get', forAmy.id).visibleTo[0] === 'amy');
  assert.throws(() => call(benU, 'entries:reveal', forAmy.id, 'field:pass'), /No such entry/); assert.strictEqual(call(amyU, 'entries:reveal', forAmy.id, 'field:pass'), 'amy-only-pass-2');
  assert.deepStrictEqual(call(benU, 'entries:search', 'only').filter(i => [onlyAdmins.id, forAmy.id].includes(i)), [], JSON.stringify(call(benU, 'entries:search', 'only'))); assert.ok(call(amyU, 'entries:search', 'For Amy').includes(forAmy.id));
  assert.ok(!call(benU, 'entries:print', [forAmy.id, onlyAdmins.id], {}).docs.length, 'hidden entries are not printed');
  assert.deepStrictEqual(call(benU, 'entries:get', openKid.id).path, [], 'a hidden parent does not show in the breadcrumb'); assert.strictEqual(call(adm, 'entries:get', openKid.id).path[0].title, 'Only the admins');
  assert.ok(!call(benU, 'network:list').some(r => r.ip === '10.9.9.9' || r.ip === '10.9.9.10') && call(adm, 'network:list').some(r => r.ip === '10.9.9.9') && call(amyU, 'network:list').some(r => r.ip === '10.9.9.10'));
  assert.ok(call(benU, 'vault:health').total < call(adm, 'vault:health').total, 'health counts only what the account can see');
  assert.ok(call(benU, 'data:dashboard').total < call(adm, 'data:dashboard').total && call(benU, 'data:dashboard').trash === 0);
  assert.ok(!call(benU, 'tags:list').some(t => t.name === 'hush') && call(adm, 'tags:list').some(t => t.name === 'hush'));
  const hiddenFile = svc.files.add({}, onlyAdmins.id, 'x.txt', 'text/plain', Buffer.from('hidden file'));
  assert.throws(() => svc.files.read(benU, hiddenFile[0].id), /No such file/); assert.strictEqual(svc.files.read(adm, hiddenFile[0].id).data.toString(), 'hidden file');
  assert.deepStrictEqual(H('entries:save', { id: forAmy.id, tabId: hw.id, title: 'For Amy', visibleTo: ['amy', 'ben', ' '] }).visibleTo, ['amy', 'ben']);
  assert.deepStrictEqual(H('entries:save', { id: forAmy.id, tabId: hw.id, title: 'For Amy', visibleTo: [] }).visibleTo, []); assert.ok(ids(benU).includes(forAmy.id), 'back to everyone');
  assert.deepStrictEqual(H('entries:save', { id: forAmy.id, tabId: hw.id, title: 'For Amy' }).visibleTo, [], 'an edit that says nothing keeps the setting');

  // ---- account kinds (PIN, fingerprint, hardware key…), links between entries, the Mobile type ------------------
  const mobileTab = H('tabs:list').find(t => t.builtin === 'mobile');
  assert.ok(mobileTab && mobileTab.fields.some(f => f.key === 'pin' && f.type === 'secret') && mobileTab.fields.some(f => f.key === 'imei'));
  assert.ok(['b:pc', 'b:phone', 'b:sso'].every(id => H('templates:list').some(t => t.id === id)));
  const tpc = H('templates:list').find(t => t.id === 'b:pc'); assert.deepStrictEqual(tpc.creds.map(c => c.kind), ['password', 'pin', 'biometric', 'hwkey', 'recovery']); assert.strictEqual(H('templates:list').find(t => t.id === 'b:phone').tabId, mobileTab.id);
  const yubi = H('entries:save', { tabId: keys.id, title: 'YubiKey 5C', fields: { kind: 'Hardware security key', serial: '19283746' }, secrets: { pin: '482915' } });
  const gmail = H('entries:save', { tabId: H('tabs:list').find(t => t.builtin === 'email').id, title: 'Gmail login', fields: { address: 'me@gmail.test' }, secrets: { pass: 'Gm4!kP8#xN2$vL6m' } });
  const pc = H('entries:save', { tabId: hw.id, title: 'Desktop PC', fields: { kind: 'PC' }, creds: [
    { label: 'Windows password', kind: 'password', user: 'joe', secret: 'Wn7!qZ2#mK9$xT4p' }, { label: 'Hello PIN', kind: 'pin', secret: '2468' }, { label: 'Fingerprint', kind: 'biometric', note: 'right index, left thumb', secret: 'ignored' },
    { label: 'Security key', kind: 'hwkey', link: yubi.id, note: 'desk drawer' }, { label: 'BitLocker', kind: 'recovery', secret: '123456-234567-345678' }] });
  assert.deepStrictEqual(pc.creds.map(c => c.kind), ['password', 'pin', 'biometric', 'hwkey', 'recovery']);
  assert.strictEqual(pc.creds[2].set, false, 'a fingerprint stores nothing, whatever was sent'); assert.strictEqual(pc.creds[3].linkInfo.title, 'YubiKey 5C'); assert.strictEqual(pc.creds[3].linkInfo.user, '');
  assert.strictEqual(H('entries:reveal', pc.id, 'cred:' + pc.creds[1].id), '2468');
  const hh = H('vault:health');
  assert.ok(!hh.weak.some(x => x.id === pc.id && x.label === 'Hello PIN') && !hh.weak.some(x => x.id === pc.id && x.label === 'BitLocker'), 'a PIN or a recovery key is not judged on strength');
  assert.ok(hh.breached.some(x => x.id === pc.id && x.label === 'Hello PIN') === false, '2468 is not in the common list');
  const pin1234 = H('entries:save', { tabId: hw.id, title: 'Weak PIN box', creds: [{ label: 'PIN', kind: 'pin', secret: '1234' }] }); assert.ok(H('vault:health').breached.some(x => x.id === pin1234.id), 'but a famous PIN is flagged');
  const plexApp = H('entries:save', { tabId: hw.id, title: 'Plex app', creds: [{ label: 'Sign-in', kind: 'linked', link: gmail.id }, { label: 'Local admin', kind: 'password', user: 'admin', secret: 'Px8!wE5#nQ7rTz2k' }] });
  assert.deepStrictEqual([plexApp.creds[0].kind, plexApp.creds[0].linkInfo.title, plexApp.creds[0].linkInfo.user, plexApp.creds[0].linkInfo.hasSecret], ['linked', 'Gmail login', 'me@gmail.test', true]);
  assert.strictEqual(H('entries:reveal', plexApp.id, 'lnk:' + plexApp.creds[0].id), 'Gm4!kP8#xN2$vL6m', 'the linked entry password, through the account');
  assert.ok(!JSON.stringify(plexApp).includes('Gm4!kP8'), 'never in the entry itself');
  assert.strictEqual(H('entries:save', { id: plexApp.id, tabId: plexApp.tabId, title: 'Plex app', creds: plexApp.creds.map(c => ({ id: c.id, label: c.label, user: c.user })) }).creds[0].link, gmail.id, 'an edit that sends no link keeps it');
  const hiddenLogin = H('entries:save', { tabId: gmail.tabId, title: 'Hidden login', fields: { address: 'secret@x.test' }, secrets: { pass: 'Hd5!rT9#qW3$zC7b' }, visibleTo: ['@admins'] });
  const sso = H('entries:save', { tabId: plexApp.tabId, title: 'Uses hidden login', creds: [{ label: 'Sign-in', kind: 'linked', link: hiddenLogin.id }] });
  assert.strictEqual(call({ user: 'ben', role: 'standard' }, 'entries:get', sso.id).creds[0].linkInfo.missing, true, 'a link to a hidden entry shows nothing');
  assert.throws(() => call({ user: 'ben', role: 'standard' }, 'entries:reveal', sso.id, 'lnk:' + sso.creds[0].id), /No such entry|gone/);
  assert.strictEqual(call({ user: 'amy', role: 'admin' }, 'entries:reveal', sso.id, 'lnk:' + sso.creds[0].id), 'Hd5!rT9#qW3$zC7b');
  H('entries:delete', gmail.id); assert.strictEqual(H('entries:get', plexApp.id).creds[0].linkInfo.missing, true, 'a link to a deleted entry says so'); H('entries:restore', gmail.id);
  const exp = H('entries:exportCsv', plexApp.tabId).text; assert.ok(exp.includes('admin,Px8!wE5#nQ7rTz2k') && !exp.includes('Gm4!kP8'), 'CSV export takes password accounts, never a link');
  assert.ok(H('entries:print', [pc.id], {}).docs[0].accounts.map(c => c.kind).includes('PIN'));
  const fromPc = H('templates:save', { fromEntry: pc.id, name: 'My PC shape' }).find(t => t.name === 'My PC shape'); assert.deepStrictEqual(fromPc.creds.map(c => c.kind), ['password', 'pin', 'biometric', 'hwkey', 'recovery']); assert.ok(fromPc.creds.every(c => c.user === ''));

  // ---- backup codes, security questions, the other kinds of secret ---------------------------------------------------
  const igTab = H('tabs:list').find(t => t.builtin === 'websites');
  const ig = H('entries:save', { tabId: igTab.id, title: 'Instagram', fields: { url: 'https://instagram.com', user: 'joe.maker' }, secrets: { pass: 'Ig7!kQ2#pLs9vW3z' } });
  const added = H('codes:add', ig.id, 'Instagram backup codes', '12345678\n23456789\n  34567890 \n\n45678901\n56789012\n12345678');
  assert.deepStrictEqual(added.codeSets.map(s => [s.label, s.total, s.left]), [['Instagram backup codes', 5, 5]], 'blank lines and repeats are dropped');
  assert.ok(!JSON.stringify(added).includes('23456789') && !JSON.stringify(H('entries:list')).includes('23456789'), 'the codes are never in an entry or a list');
  const setId = added.codeSets[0].id;
  assert.deepStrictEqual(H('codes:reveal', ig.id, setId).codes.map(c => c.c), ['12345678', '23456789', '34567890', '45678901', '56789012']);
  assert.deepStrictEqual(H('codes:mark', ig.id, setId, 1, true), { left: 4, total: 5 });
  assert.strictEqual(H('codes:next', ig.id, setId).code, '12345678'); assert.strictEqual(H('codes:next', ig.id, setId).code, '34567890', 'the next unused one, and a used one is skipped');
  assert.strictEqual(H('entries:get', ig.id).codeSets[0].left, 2);
  assert.ok(H('vault:health').lowCodes.some(x => x.id === ig.id && x.left === 2), 'two left is low');
  H('codes:mark', ig.id, setId, 1, false); assert.ok(!H('vault:health').lowCodes.some(x => x.id === ig.id), 'three left is fine'); H('codes:mark', ig.id, setId, 1, true);
  H('codes:next', ig.id, setId); H('codes:next', ig.id, setId); assert.throws(() => H('codes:next', ig.id, setId), /used up/);
  assert.strictEqual(H('codes:reveal', ig.id, setId).codes.every(c => c.used), true);
  const oneLine = H('codes:add', ig.id, '', 'aaaa-1111 bbbb-2222 cccc-3333'); assert.strictEqual(oneLine.codeSets[1].total, 3); assert.strictEqual(oneLine.codeSets[1].label, 'Backup codes', 'a single line is split on spaces');
  H('codes:replace', ig.id, setId, 'new-code-1\nnew-code-2\nnew-code-3'); assert.strictEqual(H('entries:get', ig.id).codeSets[0].left, 3);
  H('codes:rename', ig.id, setId, 'IG codes (Oct 2026)'); assert.strictEqual(H('entries:get', ig.id).codeSets[0].label, 'IG codes (Oct 2026)');
  assert.deepStrictEqual(H('entries:search', 'IG codes'), [ig.id], 'a set is found by its label, never by a code'); assert.deepStrictEqual(H('entries:search', 'new-code-1'), []);
  assert.throws(() => H('codes:add', ig.id, 'x', ' \n , '), /No codes found/); assert.throws(() => H('codes:reveal', ig.id, 'nope'), /No such set/);
  const igEdit = H('entries:save', { id: ig.id, tabId: igTab.id, title: 'Instagram', fields: { user: 'joe.maker' } }); assert.strictEqual(igEdit.codeSets.length, 2, 'editing the entry keeps its codes');
  const pr2 = H('entries:print', [ig.id], {}).docs[0]; assert.ok(pr2.codeSets[0].codes === null && pr2.codeSets[0].left === 3); assert.ok(H('entries:print', [ig.id], { secrets: true }).docs[0].codeSets[0].codes.length === 3);
  assert.throws(() => call({ user: 'bob', role: 'standard' }, 'codes:reveal', ig.id, setId) && (svc.settings.set({ vault: { noReveal: ['bob'] } }), call({ user: 'bob', role: 'standard' }, 'codes:reveal', ig.id, setId)), /not their passwords/); svc.settings.set({ vault: { noReveal: [] } });
  const dupIg = H('entries:duplicate', ig.id); assert.strictEqual(dupIg.codeSets.length, 0, 'a copy leaves the codes behind'); assert.strictEqual(H('entries:duplicate', ig.id, { secrets: true }).codeSets.length, 2);
  svc.db.exec('PRAGMA wal_checkpoint(TRUNCATE)'); assert.ok(!allFileBytes().includes('new-code-2') && !allFileBytes().includes('aaaa-1111'), 'codes are encrypted on disk');

  const bank = H('entries:save', { tabId: igTab.id, title: 'First Bank', questions: [{ q: 'First pet?', a: 'Rex the dog' }, { q: 'Street you grew up on', a: 'Maple Ave' }] });
  assert.deepStrictEqual(bank.questions.map(q => [q.q, q.set]), [['First pet?', true], ['Street you grew up on', true]]); assert.ok(!JSON.stringify(bank).includes('Rex'), 'answers never come back');
  assert.strictEqual(H('entries:reveal', bank.id, 'qa:' + bank.questions[0].id), 'Rex the dog');
  const qKept = H('entries:save', { id: bank.id, tabId: igTab.id, title: 'First Bank', questions: [{ id: bank.questions[0].id, q: 'First pet? (edited)' }, { id: bank.questions[1].id, q: 'Street', a: 'Oak Ln' }] });
  assert.strictEqual(H('entries:reveal', bank.id, 'qa:' + qKept.questions[0].id), 'Rex the dog', 'an untouched answer is kept'); assert.strictEqual(H('entries:reveal', bank.id, 'qa:' + qKept.questions[1].id), 'Oak Ln');
  assert.strictEqual(H('entries:save', { id: bank.id, tabId: igTab.id, title: 'First Bank' }).questions.length, 2, 'an edit that says nothing keeps them');
  assert.ok(H('entries:print', [bank.id], {}).docs[0].questions.every(q => q.a === '••••••••') && !JSON.stringify(H('entries:print', [bank.id], {})).includes('Oak Ln'));
  assert.ok(H('entries:search', 'First pet').includes(bank.id), 'question texts are searchable');

  const kindsEntry = H('entries:save', { tabId: hw.id, title: 'Dev laptop', creds: [
    { label: 'Gmail app password', kind: 'apppass', secret: 'abcd efgh ijkl mnop' }, { label: 'GitHub token', kind: 'token', secret: 'ghp_exampletoken1234567890' },
    { label: 'Deploy key', kind: 'sshkey', secret: '-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----' }, { label: 'Wallet', kind: 'seed', secret: 'abandon ability able about above absent absorb abstract absurd abuse access accident' }] });
  assert.deepStrictEqual(kindsEntry.creds.map(c => [c.kind, c.set]), [['apppass', true], ['token', true], ['sshkey', true], ['seed', true]]);
  assert.ok(H('entries:reveal', kindsEntry.id, 'cred:' + kindsEntry.creds[2].id).includes('\nAAAA\n'), 'a multi-line key survives');
  const hk = H('vault:health'); assert.ok(!hk.weak.some(x => x.id === kindsEntry.id) && !hk.reused.some(x => x.id === kindsEntry.id) && !hk.breached.some(x => x.id === kindsEntry.id), 'tokens, keys and seed phrases are not judged like passwords');
  assert.ok(!H('entries:exportCsv', hw.id).text.includes('ghp_example'), 'and are not exported as browser passwords');
  assert.ok(require('../main/templates').MULTILINE_KINDS.has('seed') && require('../main/templates').ACCOUNT_KINDS.length >= 13);
  assert.ok(['b:wallet', 'b:ssh'].every(id => H('templates:list').some(t => t.id === id)));

  // an older vault gains the fields and choices added since, once, without losing anything
  const wsTab = H('tabs:list').find(t => t.builtin === 'websites'), keysTab = H('tabs:list').find(t => t.builtin === 'keys');
  H('tabs:save', { ...wsTab, fields: wsTab.fields.filter(f => f.key !== 'recoveryto') }); H('tabs:save', { ...keysTab, fields: keysTab.fields.map(f => (f.key === 'kind' ? { ...f, options: ['Hardware security key', 'Other'] } : f)) });
  svc.db.kvSet('tabsRev', 1); H('vault:lock'); svc.vault.fails = 0; await H('vault:unlock', { keyFile: kfOnly.keyFile });
  assert.ok(H('tabs:list').find(t => t.builtin === 'websites').fields.some(f => f.key === 'recoveryto'), 'a missing default field comes back once');
  assert.ok(H('tabs:list').find(t => t.builtin === 'keys').fields.find(f => f.key === 'kind').options.includes('Backup codes'), 'and new choices are added to a list');
  assert.ok(H('tabs:list').find(t => t.builtin === 'keys').fields.find(f => f.key === 'kind').options.includes('Hardware security key'));
  assert.strictEqual(H('tabs:list').find(t => t.builtin === 'email').fields.filter(f => f.key.startsWith('recoveryto')).length, 1, 'the migration never duplicates a field that is already there');

  // ---- attachments: encrypted, searchable by nobody, gone with the entry ---------------------------------------
  const FILE_MARK = 'canary-file-bytes-5d2e', FILE_NAME = 'canary-name-serial-plate.png';
  const fl = svc.files.add({ user: 'joe' }, server.id, FILE_NAME, 'image/png', Buffer.from('PNGDATA ' + FILE_MARK));
  assert.strictEqual(fl.length, 1); assert.strictEqual(fl[0].name, FILE_NAME); assert.strictEqual(H('entries:get', server.id).files[0].size, 8 + FILE_MARK.length);
  assert.strictEqual(svc.files.read({ user: 'joe', role: 'admin' }, fl[0].id).data.toString(), 'PNGDATA ' + FILE_MARK);
  svc.settings.set({ vault: { noReveal: ['bob'] } });
  assert.throws(() => svc.files.read({ user: 'bob', role: 'standard' }, fl[0].id), /not their passwords/);
  svc.settings.set({ vault: { noReveal: [] } });
  svc.db.exec('PRAGMA wal_checkpoint(TRUNCATE)');
  assert.ok(!allFileBytes().includes(FILE_MARK) && !allFileBytes().includes(FILE_NAME), 'attachments and their names are not readable on disk');
  assert.throws(() => svc.files.add({}, server.id, 'big.bin', 'x', Buffer.alloc(10 * 1024 * 1024 + 1)), /at most 10 MB/);
  assert.throws(() => svc.files.add({}, server.id, 'empty', 'x', Buffer.alloc(0)), /empty/);
  const rowId = svc.db.get('SELECT id FROM files WHERE entry_id=?', server.id).id;
  const tampered = svc.db.get('SELECT data FROM files WHERE id=?', rowId).data; svc.db.run('UPDATE files SET data=? WHERE id=?', Buffer.concat([Buffer.from(tampered.subarray(0, 20)), Buffer.from([tampered[20] ^ 1]), Buffer.from(tampered.subarray(21))]), rowId);
  assert.throws(() => svc.files.read({ role: 'admin' }, rowId), /authenticate/i, 'a changed attachment is detected'); svc.db.run('UPDATE files SET data=? WHERE id=?', tampered, rowId);
  const scratch = H('entries:save', { tabId: hw.id, title: 'Scratch' }); svc.files.add({}, scratch.id, 'a.txt', 'text/plain', Buffer.from('hello'));
  H('entries:delete', scratch.id); H('entries:purge', [scratch.id]); assert.strictEqual(svc.db.get('SELECT COUNT(*) n FROM files WHERE entry_id=?', scratch.id).n, 0, 'purging an entry removes its attachments');
  assert.strictEqual(H('files:delete', fl[0].id).length, 0);

  // ---- restore a backup -----------------------------------------------------------------------------------------
  const snapshot = Buffer.from(H('vault:backup').base64, 'base64');
  const keepCount = H('entries:list').length;
  const lateEntry = H('entries:save', { tabId: web.id, title: 'Added after the backup' });
  assert.throws(() => svc.restoreFile({}, Buffer.from('not a database at all'.repeat(400))), /not a Strongbox backup/);
  const rs = svc.restoreFile({ user: 'joe', ip: '10.0.0.1' }, snapshot);
  assert.strictEqual(rs.entries, keepCount); assert.strictEqual(H('vault:status').state, 'locked', 'a restore leaves the vault locked');
  assert.ok(fs.readdirSync(svc.db.file + '.backups').some(f => /pre-restore/.test(f)), 'the current database is kept first');
  await H('vault:unlock', { keyFile: kfOnly.keyFile });
  assert.strictEqual(H('entries:list').length, keepCount); assert.ok(!H('entries:list').some(e => e.id === lateEntry.id), 'entries added after the backup are gone');
  assert.strictEqual(H('entries:reveal', server.id, 'field:pass'), 'a-new-password-99'); assert.ok(H('vault:audit', 30).some(r => r.action === 'backup_restored'));

  // ---- a hardware security key as a factor (the browser supplies a 32-byte secret; here a fixed one) --------------
  const skSecret = require('crypto').randomBytes(32).toString('base64'), skMeta = { secret: skSecret, credId: 'Y3JlZA', salt: 'c2FsdA', rpId: 'strongbox.home' };
  await fails(H('vault:rewrap', { mode: 'password+securitykey', password: 'security key passphrase', securityKey: { ...skMeta, secret: 'AAAA' } }), /usable secret/);
  const sk = await H('vault:rewrap', { mode: 'password+securitykey', password: 'security key passphrase', securityKey: skMeta });
  assert.ok(sk.recoveryKey && sk.keyFile === null, 'a security key always comes with a recovery key');
  assert.deepStrictEqual(H('vault:status').securityKey, { credId: 'Y3JlZA', salt: 'c2FsdA', rpId: 'strongbox.home' });
  H('vault:lock'); svc.vault.fails = 0;
  await fails(H('vault:unlock', { password: 'security key passphrase' }), /security key is required/);
  await fails(H('vault:unlock', { password: 'security key passphrase', securityKey: require('crypto').randomBytes(32).toString('base64') }), /Wrong/);
  svc.vault.fails = 0;
  await H('vault:unlock', { password: 'security key passphrase', securityKey: skSecret });
  assert.strictEqual(H('entries:reveal', server.id, 'field:pass'), 'a-new-password-99');
  H('vault:lock'); await H('vault:unlock', { recoveryKey: sk.recoveryKey });

  // ---- rotate the data key: everything re-encrypted, old recovery key dead, nothing lost ----------------------------
  svc.files.add({}, server.id, 'plate.txt', 'text/plain', Buffer.from('rotate me'));
  const before = svc.db.get('SELECT blob FROM entries WHERE id=?', server.id).blob;
  await fails(H('vault:rotate', { mode: 'password', password: 'short', recovery: 'new' }), /at least 12/);
  const rot = await H('vault:rotate', { mode: 'password', password: 'a rotated passphrase', recovery: 'new' });
  assert.ok(rot.recoveryKey && rot.recoveryKey !== sk.recoveryKey);
  assert.ok(!Buffer.from(before).equals(Buffer.from(svc.db.get('SELECT blob FROM entries WHERE id=?', server.id).blob)), 'the ciphertext changed');
  assert.strictEqual(H('entries:reveal', server.id, 'field:pass'), 'a-new-password-99'); assert.strictEqual(svc.files.read({ role: 'admin' }, svc.db.get('SELECT id FROM files WHERE entry_id=?', server.id).id).data.toString(), 'rotate me');
  assert.ok(fs.readdirSync(svc.db.file + '.backups').some(f => /pre-rotate/.test(f)));
  H('vault:lock'); svc.vault.fails = 0;
  await fails(H('vault:unlock', { recoveryKey: sk.recoveryKey }), /Wrong/); svc.vault.fails = 0;
  await fails(H('vault:unlock', { password: 'security key passphrase', securityKey: skSecret }), /Wrong|usable|required|damaged/); svc.vault.fails = 0;
  await H('vault:unlock', { password: 'a rotated passphrase' });
  assert.strictEqual(H('entries:get', server.id).title, TITLE); assert.strictEqual(H('tabs:list').length >= 4, true); assert.ok(H('tags:list'), 'preferences survive too'); assert.ok(H('templates:list').length);

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
