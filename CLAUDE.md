# Strongbox — project guide for Claude Code

Strongbox is a LAN-only credential vault that runs on the home Raspberry Pi (`aether`, behind Caddy, port 8083,
`https://strongbox.home`). It keeps hardware logins, website and e-mail accounts, hardware and software keys and
licences, in user-defined **types** (called tabs in the code and the API) with their own field templates, with **nested entries** (a server holds its VMs and
services), specs, notes, history and a health report. It is built on Bracket (`kit/`) and is web-only: there is
deliberately no desktop shell, so decrypted data only ever lives in the Pi's memory and in a browser tab. It is not a
sync service, a browser extension or a password-sharing tool.

## Non-negotiables (don't regress these)

- **Nothing secret outside the vault key.** Passwords, secret fields, authenticator seeds, login passwords, notes,
  titles, tab definitions and field values are encrypted before they reach SQLite. Plaintext columns are only ids,
  tab id, parent id and timestamps. `app/test/app.test.js` greps every file in the data folder (database, WAL,
  settings, logs, backups) for canary strings; keep that test passing.
- **Secrets leave the server only through `entries:reveal` and `entries:totp`**, one value at a time, each audited.
  Lists, entry pages, search results, health, dashboard, notifications, the Home Assistant status and every log line
  carry no secret and no entry title. Search covers notes and specs but never secrets.
- **The data key is memory-only.** It is wrapped (AES-256-GCM) under the unlock factors and, optionally, a recovery
  key. It is wiped on lock, on auto-lock, on shutdown and on restart. Never persist it, log it or send it anywhere.
- **Unlock factors** are chosen at creation: passphrase, passphrase + key file, key file only. KDF is
  scrypt (N = 2^17 default, stored in the header) → HKDF-SHA256. Do not add a second KDF without a header version.
- **Re-wrapping never re-encrypts entries.** Changing the unlock method only replaces the header.
- **Zero runtime dependencies** (Bracket's rule): `node:crypto`, `node:sqlite`, `node:http`. No native addons, no CDN.
- **`kit/` is never edited here.** Fixes go to the Bracket repo and arrive with `npm run kit:upgrade`.
- **Guests have no access**, the Caddy block is https-only, and standard accounts can read but never change anything.
- Global rules from `~/.claude/CLAUDE.md`: AxialForge identity, no Claude attribution, imperative commit messages,
  version bump and CHANGELOG in one commit, tag → CI builds. No paid services, no certificates to buy.

## Commands

```bash
npm test                    # kit tests + vault crypto, handlers, on-disk canary and tamper checks (plain node)
npm run dev                 # http://localhost:8083, data in ./.devdata (gitignored)
STRONGBOX_PASSWORD=... node app/server/server.js --data=.devdata --set-password   # the web account, not the vault
npm run pack:server         # dist/strongbox-server.tar.gz + .sha256 (what CI attaches)
npm run icons               # regenerate icons from tools/make-icon.js (then delete the build/ folder it writes: web-only)
bash -n server/install.sh
```

## Architecture

```
app/main/vault.js        Vault: key derivation, wrap/unwrap, seal/open records, lock state, unlock throttle, rewrap, recovery
app/main/templates.js    field types, the five default types, cleanTab(), strengthBits
app/main/service.js      createService: schema, every handler (via api(channel, fn(actor, ...args))), health, audit, jobs
app/main/csvin.js        CSV reader + header mapping for password-manager exports
app/server/server.js     roles, SENSITIVE list, and the wrapper that passes { user, ip } to every vault handler for the audit trail
app/renderer/            strength.js (shared with the server), util.js (clipboard, the generator engine and its presets, tag badges, reveal), lock.js (setup wizard,
                         unlock screen, sidebar lock box), app.js (all pages), bridge-shape.js (the API contract), app.css
```

### Data model

- `vault_meta(k, v)`: one row, `header` = `{ v, mode, kdf, kf (key file id), dk (wrapped data key), rk (wrapped under the recovery key) }`.
  A copy of the database is a complete, still-encrypted backup.
- `tabs(id, sort, blob)`: blob = `{ name, icon, fields: [{ key, label, type, options?, expiry?, multiline? }], builtin? }`.
- `entries(id, tab_id, parent_id, created, updated, deleted, blob)`: blob = `{ title, subtitle, fields{key: value}, creds[{id, label, user, url, secret}], specs[{k, v}], nics[{label, ip, mac}], notes, tags, favorite, changed{key: ms}, hist{key: [{v, t}]} }`.
  Every blob is `[1][nonce 12][ciphertext][tag 16]`, AES-256-GCM under a subkey of the data key, with `tab/<id>` or `entry/<id>` as additional data so a ciphertext cannot be moved to another row (tested).
- `prefs(k, blob)`: small encrypted records (`pref/<k>` is the additional data): `tags` = `{ name: { color } }`, `templates` = custom entry templates.
  Built-in templates live in `templates.js` (`BUILTIN_TEMPLATES`); a template never holds a secret (`templates:save` with `fromEntry` strips them).
- `vault_audit(ts, action, entry_id, detail, actor, ip)`: who unlocked, revealed, exported, changed. Never a secret or a title.
- Soft delete: `deleted` = timestamp on the entry and its subtree; Trash restores the subtree; the `trash` daily job purges after `vault.trashDays`.

### Field types (templates.js)

`text url multiline number date select ip mac password secret totp`. `ip` and `mac` are validated on save (`normIp`, `normMac`; MACs are stored as `AA:BB:CC:DD:EE:FF`). `password` is tracked (age, history of the last 5, strength, reuse);
`secret` is masked with nothing tracked; `totp` shows a live code (server-side, `entries:totp`); a `date` with `expiry: true` feeds the expiring list.
Entries keep values by field key, so a template can change freely; values of removed fields stay in the blob.

### Types added later

`ensureDefaultTabs()` (called after every unlock) adds a default type that an older vault lacks, once, right after the default that precedes it; `kv.seededTabs`
remembers which defaults were already offered, so a type the user deleted never comes back. Add a new default type to `DEFAULT_TABS` and it reaches existing vaults this way.

### Generator, tags, templates, network

- The generator is browser-only (`util.js`: `generate()` + `generatorPanel()`, tested by `app/test/generator.test.js`): presets plus requirements (length, minimum upper/digits/symbols, allowed symbol set, excluded characters, start with a letter, passphrase / PIN / hex modes). It never repeats a character three times in a row and raises the length when the minimums need it. Custom presets are saved in `settings.vault.genPresets`; a password field's `gen` is the preset its Generate button starts from.
- Tags are free text on entries; colours and renames live in `prefs.tags`. Renaming or merging re-seals every entry that carries the tag (`mutateEntries`).
- `#newt/<templateId>[/<parentId>]` opens the editor pre-filled from a template (ids: `b:*` built in, `c:*` custom).
- `network:list` flattens every ip/mac field and every `nics` row into one table; the page flags duplicate IPs and MACs.

### Adding a channel

1. `api('area:name', (actor, ...args) => ...)` in `service.js` (wrapped in the unlocked check unless `{ data: false }`).
2. List it in `app/renderer/bridge-shape.js`.
3. Add it to `ROLES` in `app/server/server.js` if standard accounts may call it; to `SENSITIVE` if it should re-ask for the account password.
4. Never return a secret from anything but reveal/totp. Add a canary to the on-disk test if it stores a new kind of text.

## Gotchas / constraints

- **A vault event must not re-draw the page during setup.** Symptom: after "Create the vault" the dashboard appeared and the key file and
  recovery key (shown once, on step 3) were lost for ever. Cause: `vault:create` sends `vault:changed`, and the global listener re-routes. The wizard sets
  `SB.wizardActive` and `onChanged` / `onLocked` return early while it is set; a hash change clears it. Any new "shown once" screen needs the same flag.
- **`db.transaction` does not nest.** `entries:importCsv` saves many entries inside one transaction; `saveEntry(..., { inTx: true })` joins it. Calling the
  default form inside a transaction throws "cannot start a transaction within a transaction".
- **Secrets in an edit form are never sent to the browser.** The form shows "unchanged" and only sends a value the user typed (`data-dirty`); the server
  keeps the old one when the key is absent. Do not "fix" this by prefilling the field.
- **Expiry maths uses local midnight.** `Date.parse('YYYY-MM-DD' + 'T00:00:00')` is local; a test built from `toISOString()` (UTC) can be off by a day. The expiry test allows ±1.
- **Failed unlocks are counted, input mistakes are not.** A missing key file or a malformed recovery key is a readable error; only a failed GCM authentication counts toward
  the throttle (5 in a row → 30 s, doubling, max 15 min). The message never says which factor was wrong.
- **`vault:status` and the 30-second resync do not count as activity**, or the auto-lock would never fire. Only real handler use (`require()`) and the throttled `vault:touch` from pointer/key events reset the idle clock.
- **The Caddy block is https-only on purpose** (the other apps also allow plain http for guests). Never add an `http://` name for this app.
- **scrypt runs in the thread pool** (`crypto.scrypt` async, `maxmem` raised). The sync form would freeze every request for a second on a Pi.
- **`vault.kdfLog2N`** (clamped 14–20) exists for tests only; it is read when a vault or unlock method is created and stored in the header, so older headers keep unlocking.
- **The browser clipboard needs HTTPS.** `navigator.clipboard` is undefined on plain http (a bare IP); `util.js` falls back to `execCommand('copy')`, but behind Caddy with `tls internal` the real API works. Phones need the Caddy root certificate installed.
- **Passwords typed into the browser pass through the Pi in the clear (inside TLS).** Crypto is server-side by design (search, health, authenticator codes). The cost is that root on the Pi while the vault is unlocked can read it; the mitigations are auto-lock, swap off, LAN-only and a short idle time.

- **The entry editor redraws the whole form** (adding a row, changing the type) from a `draft` object. Symptom: the page jumped to the top on every "Add login". Cause: the redraw replaced the content and `render()` focused the title field each time. It now keeps `scrollTop`, focuses the title only on the first draw, and focuses the new row. Any new redraw path must go through `render()`.

- **Editor buttons find their input through `boxOf(b)`** (`.secretin`, else `.inline`). Symptom: Show and Generate did nothing on the main password fields. Cause: `closest('.secretin, .inline')` returns the nearest of the two, and in a main field the button's own `.inline` row holds no input. Never use a combined selector for this.
- **Printing goes through `entries:print`, never through the page.** The server decides what is in the document (secrets masked unless `secrets: true`, the whole print audited once); the browser only formats it (`SB.printHtml`) and prints it in a hidden iframe.

- **Binary bodies never go through the JSON API.** `app/server/server.js` `fileRoutes` serves attachments (`/upload/file`, `/download/file/<id>`), backups to restore (`/upload/restore`, admin, re-asks for the password) and breached-password lists (`/upload/breach`). They check the session, the same-origin header and the role themselves; the kit's JSON limit is 4 MB, these allow 10 / 64 / 100 MB.
- **A restore copies tables, it does not swap the file.** `restoreFile` ATTACHes the uploaded database, copies `vault_meta`, `tabs`, `entries`, `prefs`, `files` and two `kv` keys in one transaction, and locks the vault first, because the header (and so the key) changes. ATTACH cannot run inside a transaction. Older backups lack `prefs` / `files`; those copies are conditional.
- **Rotating the data key re-encrypts inside one transaction** (`Vault.rotate` with a callback), and the recovery key cannot be kept (it wraps the old data key). The AAD strings (`tab/<id>`, `entry/<id>`, `pref/<k>`, `filemeta/<id>`, `file/<id>`) must stay in step between `service.js` and the rotate loop, or a rotation corrupts that table.
- **A security-key unlock needs a recovery key, always** (`wrapFor` refuses otherwise): the credential is tied to the host name the browser saw (`rpId`), so opening the app from another address cannot use it. Registration reads the PRF secret twice and compares before anything is wrapped. This path is tested with a fixed 32-byte secret, not with a physical key.
- **Breached-password matching keeps 64 bits of each SHA-1** in a sorted `BigUint64Array` (`breached.bin`), not the passwords. A copy made with `Buffer` must be re-aligned before it becomes a typed array (`byteOffset` is not always a multiple of 8).
- **Who may reveal is decided by the server** (`canReveal(actor)` from `settings.vault.noReveal` and the actor's role); the page only hides the buttons. Anything new that returns a secret must call `denyReveal(a)`.
- **`rewrap` for a security-key mode forces a fresh recovery key**; applying "keep the old one" afterwards replaced the new record and made the shown recovery key useless. Fixed in 0.8.0 and covered by a test.

- **Visibility is filtered where entries are decrypted** (`everything(trash, actor)` and `canSee(actor, entry)`), not in the page. Any new handler that lists, counts, searches or returns entries for an account must pass the actor through; `healthCache` is only written by admin / core runs so a restricted account's smaller numbers never reach Home Assistant. The editor sends `visibleTo` always; an edit that omits it keeps the old value.

## Roadmap (unbuilt)

- "Remember this key file on this device" (an opt-in convenience; weakens the second factor).
- Test the security-key unlock with real hardware (YubiKey 5 with a recent firmware) and add a second key as a spare.

## Release

Bump `package.json` and add a `CHANGELOG.md` entry in one commit, then `git tag vX.Y.Z && git push origin main --tags`.
CI runs the tests, packs the server and attaches it to the GitHub Release.
