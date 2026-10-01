'use strict';
// What a tab is: a name, an icon, a colour and a template of fields. Entries keep their values by field key, so a
// template can change later without losing anything. Also the entry blueprints ("templates" in the UI) and the
// value checks for IP and MAC addresses.
//
// Field types
//   text       plain value (shown and searchable)           url       text that opens as a link
//   multiline  several lines of plain text                  number    a number
//   date       a calendar date; `expiry: true` puts it on the expiring-soon list
//   select     one of `options`
//   ip         an IPv4 / IPv6 address (optionally /prefix), checked on save
//   mac        a MAC address, stored as AA:BB:CC:DD:EE:FF whatever separators were typed
//   port       a TCP/UDP port (1-65535), or the word `caddy`: the service sits behind the reverse proxy and no port is shown
//   password   masked, copy-only; history, age, strength and reuse are tracked
//   secret     masked, copy-only, nothing tracked (licence keys, PINs, recovery codes); `multiline: true` allowed
//   totp       a base32 authenticator seed; the page shows the live six-digit code
// Password and single-line secret fields may carry `gen`: the id of the generator preset their Generate button starts from.
const FIELD_TYPES = ['text', 'url', 'multiline', 'number', 'date', 'select', 'ip', 'mac', 'port', 'password', 'secret', 'totp'];
const SECRET_TYPES = new Set(['password', 'secret', 'totp']);
const TAB_COLORS = ['blue', 'violet', 'pink', 'red', 'amber', 'green', 'teal', 'slate'];

const f = (key, label, type = 'text', extra = {}) => ({ key, label, type, ...extra });

const DEFAULT_TABS = [
  { builtin: 'hardware', name: 'Hardware', icon: '▦', color: 'blue', fields: [
    f('kind', 'Kind', 'select', { options: ['Server', 'Virtual machine', 'Router', 'Switch', 'Access point', 'NAS', 'PC', 'Printer', 'Camera', 'Controller', 'IoT device', 'Other'] }),
    f('model', 'Make / model'), f('host', 'Hostname'), f('ip', 'IP address', 'ip'), f('mac', 'MAC address', 'mac'), f('serial', 'Serial number'), f('location', 'Location'), f('firmware', 'Firmware / OS'),
    f('user', 'Admin username'), f('pass', 'Admin password', 'password', { gen: 'device' }), f('bought', 'Purchased', 'date'), f('warranty', 'Warranty until', 'date', { expiry: true }),
  ] },
  { builtin: 'services', name: 'Services', icon: '⚙', color: 'teal', fields: [
    f('kind', 'Kind', 'select', { options: ['Web app', 'Database', 'Container', 'Daemon / system service', 'Media server', 'Home automation', 'API', 'Other'] }),
    f('url', 'Address', 'url'), f('port', 'Port', 'port'), f('version', 'Version'), f('user', 'Username'), f('pass', 'Password', 'password', { gen: 'strong' }),
    f('token', 'API key / token', 'secret'), f('totp', 'Authenticator seed', 'totp'), f('unit', 'Service / unit name'), f('path', 'Install path / data folder'), f('repo', 'Source / docs', 'url'),
  ] },
  { builtin: 'websites', name: 'Websites', icon: '◍', color: 'violet', fields: [
    f('url', 'Address', 'url'), f('user', 'Username'), f('email', 'E-mail used'), f('pass', 'Password', 'password', { gen: 'strong' }), f('totp', 'Authenticator seed', 'totp'), f('recovery', 'Recovery codes', 'secret', { multiline: true }),
  ] },
  { builtin: 'email', name: 'E-mail', icon: '✉', color: 'amber', fields: [
    f('address', 'Address'), f('provider', 'Provider'), f('pass', 'Password', 'password', { gen: 'strong' }), f('app', 'App password', 'password', { gen: 'alnum' }), f('totp', 'Authenticator seed', 'totp'),
    f('imap', 'Incoming server (IMAP)'), f('smtp', 'Outgoing server (SMTP)'), f('recoveryTo', 'Recovery e-mail / phone'),
  ] },
  { builtin: 'keys', name: 'Keys & licences', icon: '⚿', color: 'green', fields: [
    f('kind', 'Kind', 'select', { options: ['Hardware security key', 'Software licence', 'SSH key', 'API key', 'GPG key', 'Wi-Fi', 'Certificate', 'Other'] }),
    f('vendor', 'Vendor / product'), f('serial', 'Serial / key ID'), f('key', 'Key / secret', 'secret', { multiline: true }), f('pin', 'PIN / passphrase', 'secret', { gen: 'pin6' }),
    f('owner', 'Registered to'), f('bought', 'Purchased', 'date'), f('expires', 'Expires', 'date', { expiry: true }),
  ] },
];

// Entry blueprints that ship with the app. `tabKey` names the default tab they belong to. Custom ones are saved
// in the vault (prefs: templates) and can be made from any entry with "Save as template".
const BUILTIN_TEMPLATES = [
  { id: 'b:server', name: 'Server', icon: '▦', tabKey: 'hardware', tags: ['server'], fields: { kind: 'Server' }, specs: ['CPU', 'RAM', 'Storage', 'OS', 'Power supply'], creds: ['IPMI / iDRAC', 'SSH', 'Web UI'], nics: ['eth0', 'IPMI'] },
  { id: 'b:vm', name: 'VM / container', icon: '▦', tabKey: 'hardware', tags: ['vm'], fields: { kind: 'Virtual machine' }, specs: ['vCPU', 'RAM', 'Disk', 'OS'], creds: ['Console'], nics: ['eth0'] },
  { id: 'b:nas', name: 'NAS', icon: '▦', tabKey: 'hardware', tags: ['storage'], fields: { kind: 'NAS' }, specs: ['Bays', 'Capacity', 'RAID', 'Firmware'], creds: ['Web UI', 'SSH', 'Share user'], nics: ['LAN 1', 'LAN 2'] },
  { id: 'b:router', name: 'Router / firewall', icon: '▦', tabKey: 'hardware', tags: ['network'], fields: { kind: 'Router' }, specs: ['Firmware', 'Ports', 'Uplink'], creds: ['Web UI', 'SSH / console'], nics: ['LAN', 'WAN'] },
  { id: 'b:switch', name: 'Switch / access point', icon: '▦', tabKey: 'hardware', tags: ['network'], fields: { kind: 'Switch' }, specs: ['Ports', 'PoE budget', 'Firmware'], creds: ['Web UI', 'SSH / console'], nics: ['Management'] },
  { id: 'b:service', name: 'Service / app', icon: '⚙', tabKey: 'services', tags: ['service'], fields: { kind: 'Web app' }, specs: ['Data folder'], creds: ['Admin', 'API'], nics: [] },
  { id: 'b:website', name: 'Website login', icon: '◍', tabKey: 'websites', tags: [], fields: {}, specs: [], creds: [], nics: [] },
  { id: 'b:key', name: 'Hardware security key', icon: '⚿', tabKey: 'keys', tags: ['2fa'], fields: { kind: 'Hardware security key' }, specs: ['Protocols'], creds: [], nics: [] },
  { id: 'b:licence', name: 'Software licence', icon: '⚿', tabKey: 'keys', tags: ['licence'], fields: { kind: 'Software licence' }, specs: ['Seats', 'Version'], creds: [], nics: [] },
];

const TAB_ICONS = ['▦', '◍', '✉', '⚿', '☰', '⌂', '☁', '⚙', '$', '★', '♥', '⚑', '✈', '☎', '▶', '◆'];
const slug = (s) => String(s || '').toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '').slice(0, 24);
const clip = (v, n) => String(v == null ? '' : v).slice(0, n);

/** Validates and normalises a tab as the editor sends it. Throws a readable error. */
function cleanTab(t = {}) {
  const name = String(t.name || '').trim().slice(0, 40);
  if (!name) throw new Error('A type needs a name');
  const seen = new Set(), fields = [];
  for (const raw of Array.isArray(t.fields) ? t.fields : []) {
    const label = String(raw.label || '').trim().slice(0, 60);
    if (!label) continue;
    const type = FIELD_TYPES.includes(raw.type) ? raw.type : 'text';
    let key = slug(raw.key) || slug(label) || 'field';
    for (let i = 2; seen.has(key); i++) key = `${slug(raw.key) || slug(label) || 'field'}_${i}`;
    seen.add(key);
    const out = { key, label, type };
    if (type === 'select') out.options = (Array.isArray(raw.options) ? raw.options : String(raw.options || '').split(',')).map(s => String(s).trim()).filter(Boolean).slice(0, 40);
    if (type === 'date' && raw.expiry) out.expiry = true;
    if ((type === 'secret' || type === 'text') && raw.multiline) out.multiline = true;
    if ((type === 'password' || (type === 'secret' && !raw.multiline)) && raw.gen) out.gen = clip(raw.gen, 40);
    fields.push(out);
  }
  return { name, icon: String(t.icon || '☰').slice(0, 4), color: TAB_COLORS.includes(t.color) ? t.color : 'blue', fields, builtin: t.builtin || undefined };
}

/** A custom entry template as the editor sends it. */
function cleanTemplate(t = {}) {
  const name = clip(t.name, 60).trim();
  if (!name) throw new Error('A template needs a name');
  const fields = {};
  for (const [k, v] of Object.entries(t.fields && typeof t.fields === 'object' ? t.fields : {})) if (v !== '' && v != null) fields[slug(k)] = clip(v, 500);
  return {
    name, icon: clip(t.icon || '☰', 4), tabId: Number(t.tabId) || null, subtitle: clip(t.subtitle, 200).trim(),
    tags: [...new Set((Array.isArray(t.tags) ? t.tags : []).map(x => clip(x, 40).trim().toLowerCase()).filter(Boolean))].slice(0, 30),
    fields,
    specs: (Array.isArray(t.specs) ? t.specs : []).map(s => ({ k: clip(s.k, 60).trim(), v: clip(s.v, 300).trim() })).filter(s => s.k || s.v).slice(0, 100),
    creds: (Array.isArray(t.creds) ? t.creds : []).map(c => ({ label: clip(c.label, 80).trim(), user: clip(c.user, 200).trim(), url: clip(c.url, 300).trim() })).filter(c => c.label || c.user).slice(0, 50),
    nics: (Array.isArray(t.nics) ? t.nics : []).map(n => ({ label: clip(n.label, 60).trim() })).filter(n => n.label).slice(0, 30),
  };
}

// ---- address checks ---------------------------------------------------------------------------
/** An IPv4 or IPv6 address, optionally with /prefix. Empty stays empty; anything else throws. */
function normIp(v) {
  const s = String(v == null ? '' : v).trim();
  if (!s) return '';
  const [addr, prefix] = s.split('/');
  const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(addr);
  if (v4 && v4.slice(1).every(n => Number(n) <= 255) && (prefix === undefined || (/^\d{1,2}$/.test(prefix) && Number(prefix) <= 32))) return s;
  if (addr.includes(':') && /^[0-9a-fA-F:]+$/.test(addr) && addr.length <= 39 && (addr.match(/::/g) || []).length <= 1 && (prefix === undefined || (/^\d{1,3}$/.test(prefix) && Number(prefix) <= 128))) return s.toLowerCase();
  throw new Error(`"${clip(s, 40)}" is not a valid IP address`);
}
/** A port number (1-65535), or `caddy` for a service behind the reverse proxy. Empty stays empty. */
function normPort(v) {
  const s = String(v == null ? '' : v).trim().toLowerCase();
  if (!s) return '';
  if (s === 'caddy') return 'caddy';
  if (/^\d{1,5}$/.test(s) && Number(s) >= 1 && Number(s) <= 65535) return String(Number(s));
  throw new Error(`"${clip(s, 20)}" is not a valid port (1-65535)`);
}
/** A MAC address in any common notation → AA:BB:CC:DD:EE:FF. */
function normMac(v) {
  const s = String(v == null ? '' : v).trim();
  if (!s) return '';
  const hex = s.replace(/[:.\-\s]/g, '');
  if (!/^[0-9a-fA-F]{12}$/.test(hex)) throw new Error(`"${clip(s, 40)}" is not a valid MAC address (12 hex digits)`);
  return hex.toUpperCase().match(/../g).join(':');
}

const { strengthBits } = require('../renderer/strength');

module.exports = { FIELD_TYPES, SECRET_TYPES, TAB_COLORS, DEFAULT_TABS, BUILTIN_TEMPLATES, TAB_ICONS, cleanTab, cleanTemplate, normIp, normMac, normPort, strengthBits };
