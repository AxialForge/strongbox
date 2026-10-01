'use strict';
// What a tab is: a name, an icon and a template of fields. Entries keep their values by field key, so a
// template can change later without losing anything.
//
// Field types
//   text       plain value (shown and searchable)           url       text that opens as a link
//   multiline  several lines of plain text                  number    a number
//   date       a calendar date; `expiry: true` puts it on the expiring-soon list
//   select     one of `options`
//   password   masked, copy-only; history, age, strength and reuse are tracked
//   secret     masked, copy-only, nothing tracked (licence keys, PINs, recovery codes); `multiline: true` allowed
//   totp       a base32 authenticator seed; the page shows the live six-digit code
const FIELD_TYPES = ['text', 'url', 'multiline', 'number', 'date', 'select', 'password', 'secret', 'totp'];
const SECRET_TYPES = new Set(['password', 'secret', 'totp']);

const f = (key, label, type = 'text', extra = {}) => ({ key, label, type, ...extra });

const DEFAULT_TABS = [
  { builtin: 'hardware', name: 'Hardware', icon: '▦', fields: [
    f('kind', 'Kind', 'select', { options: ['Server', 'Virtual machine', 'Router', 'Switch', 'Access point', 'NAS', 'PC', 'Printer', 'Camera', 'Controller', 'IoT device', 'Other'] }),
    f('model', 'Make / model'), f('host', 'Hostname / IP'), f('mac', 'MAC address'), f('serial', 'Serial number'), f('location', 'Location'), f('firmware', 'Firmware / OS'),
    f('user', 'Admin username'), f('pass', 'Admin password', 'password'), f('bought', 'Purchased', 'date'), f('warranty', 'Warranty until', 'date', { expiry: true }),
  ] },
  { builtin: 'websites', name: 'Websites', icon: '◍', fields: [
    f('url', 'Address', 'url'), f('user', 'Username'), f('email', 'E-mail used'), f('pass', 'Password', 'password'), f('totp', 'Authenticator seed', 'totp'), f('recovery', 'Recovery codes', 'secret', { multiline: true }),
  ] },
  { builtin: 'email', name: 'E-mail', icon: '✉', fields: [
    f('address', 'Address'), f('provider', 'Provider'), f('pass', 'Password', 'password'), f('app', 'App password', 'password'), f('totp', 'Authenticator seed', 'totp'),
    f('imap', 'Incoming server (IMAP)'), f('smtp', 'Outgoing server (SMTP)'), f('recoveryTo', 'Recovery e-mail / phone'),
  ] },
  { builtin: 'keys', name: 'Keys & licences', icon: '⚿', fields: [
    f('kind', 'Kind', 'select', { options: ['Hardware security key', 'Software licence', 'SSH key', 'API key', 'GPG key', 'Wi-Fi', 'Certificate', 'Other'] }),
    f('vendor', 'Vendor / product'), f('serial', 'Serial / key ID'), f('key', 'Key / secret', 'secret', { multiline: true }), f('pin', 'PIN / passphrase', 'secret'),
    f('owner', 'Registered to'), f('bought', 'Purchased', 'date'), f('expires', 'Expires', 'date', { expiry: true }),
  ] },
];

const TAB_ICONS = ['▦', '◍', '✉', '⚿', '☰', '⌂', '☁', '⚙', '$', '★', '♥', '⚑', '✈', '☎', '▶', '◆'];
const slug = (s) => String(s || '').toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '').slice(0, 24);

/** Validates and normalises a tab as the editor sends it. Throws a readable error. */
function cleanTab(t = {}) {
  const name = String(t.name || '').trim().slice(0, 40);
  if (!name) throw new Error('A tab needs a name');
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
    fields.push(out);
  }
  return { name, icon: String(t.icon || '☰').slice(0, 4), fields, builtin: t.builtin || undefined };
}

const { strengthBits } = require('../renderer/strength');

module.exports = { FIELD_TYPES, SECRET_TYPES, DEFAULT_TABS, TAB_ICONS, cleanTab, strengthBits };
