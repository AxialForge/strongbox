'use strict';
// A small RFC 4180 reader for importing a password manager's CSV export (Chrome, Bitwarden, 1Password, KeePass…).
// Quoted fields may hold commas, quotes ("") and line breaks; a leading BOM is ignored.
function parseCsv(text) {
  const s = String(text || '').replace(/^﻿/, '');
  const rows = [];
  let row = [], field = '', quoted = false;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (quoted) {
      if (c === '"') { if (s[i + 1] === '"') { field += '"'; i++; } else quoted = false; } else field += c;
    } else if (c === '"' && field === '') quoted = true;
    else if (c === ',') { row.push(field); field = ''; }
    else if (c === '\n' || c === '\r') { if (c === '\r' && s[i + 1] === '\n') i++; row.push(field); field = ''; if (row.some(x => x !== '')) rows.push(row); row = []; }
    else field += c;
  }
  row.push(field);
  if (row.some(x => x !== '')) rows.push(row);
  return rows;
}

// Header names the common exporters use, mapped to what Strongbox calls them.
const ROLES = {
  title: ['name', 'title', 'login_name', 'account'],
  url: ['url', 'login_uri', 'website', 'web site', 'login url', 'uri'],
  user: ['username', 'login_username', 'user', 'login', 'user name', 'login name', 'email'],
  pass: ['password', 'login_password', 'pass'],
  totp: ['totp', 'login_totp', 'otpauth', 'one-time password', 'otp'],
  notes: ['note', 'notes', 'extra', 'comments', 'notesplain'],
  folder: ['folder', 'grouping', 'group'],
  kind: ['type'],
};
function mapHeaders(headers) {
  const out = {};
  headers.forEach((h, i) => { const k = String(h).trim().toLowerCase(); for (const [role, names] of Object.entries(ROLES)) if (names.includes(k) && out[role] === undefined) out[role] = i; });
  return out;
}

/** Names the program a CSV came from, by its header row (informational: the mapping works from the headers themselves). */
function detectFormat(headers) {
  const h = new Set(headers.map(x => String(x).trim().toLowerCase()));
  if (h.has('login_uri') && h.has('login_username')) return 'Bitwarden';
  if (h.has('otpauth') && h.has('title')) return '1Password';
  if (h.has('grouping') && h.has('extra')) return 'LastPass';
  if (h.has('httprealm') || h.has('formactionorigin')) return 'Firefox';
  if (h.has('login name') && h.has('web site')) return 'KeePass';
  if (h.has('name') && h.has('url') && h.has('username') && h.has('password')) return 'Google Password Manager / Chrome / Edge';
  return 'a generic CSV';
}

module.exports = { parseCsv, mapHeaders, detectFormat };
