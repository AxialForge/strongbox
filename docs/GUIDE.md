# Building on Bracket

Bracket is two things in one repository: a **kit** (`kit/`, code every app vendors and never edits)
and a **starter app** (`app/`, the thing you rename and replace). The kit gives you the app frame,
themes, tables, cards, the editable dashboard, accounts and roles, sessions, two-factor codes, the
web server, the Electron window, the Pi installer, notifications and the Home Assistant status URL.
You write the core (what the app does), the pages, and the card catalog.

## Start a new app

```bash
gh repo create AxialForge/<slug> --template AxialForge/bracket --public --clone
cd <slug>
node tools/new-app.js --name "My App" --slug myapp --port 8083        # add --web-only or --desktop-only
npm test
npm run dev                                                           # http://localhost:8083
node app/server/server.js --data=.devdata --set-password
```

Then work through `SETUP.md`. Ports on the home server so far: 8080 MediaLedger, 8081 Linewatch,
8082 PiPulse; pick the next free one.

## How a request travels

```
page (app.js) ── window.api.notes.save({…}) ──▶ bridge-shape.js names the channel 'notes:save'
                                                   │
        web:  webbridge.js  POST /api/notes:save ──┤──▶ kit/server/shell.js: session, role, re-auth, then
     desktop: preload.js    ipc 'notes:save'      ─┘    core.handlers.get('notes:save')(...args)  in app/main/service.js
events:  core.send('notes:changed', {…}) ──▶ SSE (web) or webContents.send (desktop) ──▶ api.notes.onChanged(fn)
```

The **contract** is `app/renderer/bridge-shape.js`: every leaf is a channel; a leaf starting with
`!` is an event. `app/test/app.test.js` (through `kit/test/contract.js`) fails when a channel is
listed but nothing serves it, served but not listed, or sent but not listened for.

## The core: app/main/service.js

```js
const core = createCore({ app, dataDir, log, send, defaults, schema, migrations, counts });
core.h('items:list', () => core.db.all('SELECT * FROM items'));          // a handler
core.every('poll', () => settings.get().pollSeconds * 1000, () => …);      // an interval job
core.daily('backup', () => settings.get().backup.time, () => …);           // once a day at HH:MM (remembered in kv)
core.onSettings((before, after) => { if (…) core.restart('poll'); });      // react to saved settings
core.notify('itemDone', 'Title', 'Text', { id });                          // webhook + e-mail, per-event switch
return { ...core, CSV_SETS };
```

- **Storage**: `core.db` is `kit/main/db.js` on `node:sqlite`. Put the base schema in `schema`;
  every later change is a new entry in `migrations` (append-only; a backup is taken first).
  `db.kvGet/kvSet` remembers small values, `db.jobDone/jobs` tracks named jobs.
- **Settings**: `defaults` is the whole tree; `settings.json` overrides it. Secrets live in it too;
  the web shell blanks the paths you list in `secrets` and maps the placeholder back on save.
- **Kit handlers** you get for free: `settings:get/set/replace`, `sys:stats`, `db:stats`,
  `log:tail`, `notify:test`, `prefs:get/set`.
- **Never** require Electron or `http` here. The tests check.

## The web shell: app/server/server.js

```js
createWebShell({ app, createService, rootDir, dataDir, port, host,
  roles: { GUEST: [...], STANDARD: [...], SENSITIVE: [...] },   // admins get everything
  secrets: ['notify.email.pass'],
  webHandlers: ({ svc }) => new Map([ ['data:dashboard', (ctx) => …] ]),  // overrides that need the session
  routes: [ async (req, res, url, t) => { … return true; } ],           // raw routes (uploads, streams)
  csvSets: CSV_SETS, statusChannel: 'data:status' });
```

Roles: **guest** (no account, only when guest access is on) may call the GUEST list; **standard**
the STANDARD list plus their own password and preferences; **admin** everything. Channels in
SENSITIVE ask for the password again within five minutes. The shell also serves `/api/status?key=`
(the `statusChannel` result, for Home Assistant), `/csv/<set>?from=&to=`, `/exports/*.zip`, the
event stream, sign-in, TLS, and static files (the app's `renderer/`, the kit's under
`/kit/renderer/`). Behind a reverse proxy on the same machine it reads `X-Forwarded-For` /
`X-Forwarded-Proto` from loopback connections only.

## The desktop shell: app/electron/main.js

```js
createDesktopShell({ app, createService, rootDir, window: { width, height }, screenshots: [['dashboard', '#dashboard'], …],
  handlers: () => new Map([ ['files:reveal', (p) => shell.showItemInFolder(p)] ]) });
```

Desktop-only channels (dialogs, the shell, updates, security stubs) are answered by the kit; add
your own in `handlers` and give the web shell an answer for them too. `electron . --screenshots=dir`
renders every listed page and exits 3 on any renderer error: that is the release gate.

## Pages: app/renderer/app.js

```js
const { $, esc, tile, makeTable, searchToolbar, toast, openModal, closeModal, fmtDate, fmtAgo, store, views, pages, sections } = UI;
views.items = async (arg) => { const v = UI.view(); const rows = await api.items.list(); v.innerHTML = `<h1>Items</h1><div id="t"></div>`;
  const t = makeTable(rows, [{ key: 'name', label: 'Name' }, { key: 'n', label: 'Count', num: true }], { defaultSort: { key: 'name' }, search: r => r.name, onRow: r => … });
  $('#t').append(searchToolbar(t, rows.length), t.node); };
views.system = pages.system; views.log = pages.log; views.security = pages.security; views.about = pages.about({ blurb, credits });
UI.init({ home: 'dashboard', nav: [{ group: 'App', items: [{ view: 'items', label: 'Items', icon: '▤', roles: ['admin', 'standard'], pill: 'itemsPill' }] }] });
```

- The route is the hash: `#items` calls `views.items()`, `#items/42` calls `views.items('42')`.
- `nav` items carry `roles`; pages a role cannot see are hidden and redirected to `home`.
- `UI.setPill('itemsPill', 3)` shows a count on a nav item; `UI.toast(msg, bad)` a message;
  `UI.openModal(html)` a dialog (returns the card element).
- Settings pages compose kit sections: `sections.notifications(s, events)`, `sections.homeAssistant(text)`,
  `sections.appearance()`; each returns `{ html, wire(save) }`.
- App styles go in `app/renderer/app.css`; the kit's `kit.css` defines the tokens (`--bg`, `--panel`,
  `--accent`, `--c1`…`--c3`) and the eight themes.

## Glossary: definitions on hover and click

Load `kit/renderer/glossary.js` after `ui.js`, then add your app's terms and mark them in pages:

```js
Glossary.add({
  queue: { term: 'Queue', short: 'Jobs waiting to run.',                     // the hover line
           long: 'Paragraphs separated by a blank line. [[load]] links a term; [[load|label]] too.',
           healthy: 'Usually empty.', fix: 'What to do when it is not.',      // the two coloured boxes
           related: ['load'] },                                              // chips at the bottom
});
tile('', UI.term('queue', 'Queue'), n)            // labels, headings, sentences: anywhere HTML goes
```

A marked term gets a dotted underline. Hovering shows the one-line `short`; clicking (or Enter,
or a tap on a phone) opens a side panel with the whole entry, and related terms open in the same
panel. Esc, a click outside, or changing page closes it. The kit ships entries for the words on
its own System and Security pages (`cpu`, `load`, `memory`, `swap`, `soc-temp`, `throttling`,
`disk`, `session`, `two-factor`, `lan-only`, …); an app's entry with the same key replaces the
kit's. Text is escaped; the only markup is `[[key]]`, `[[key|label]]`, `**bold**` and blank-line
paragraphs. `UI.term` of an unknown key renders plain text, so a typo never breaks a page, and
without `glossary.js` loaded the kit pages fall back to plain labels.

## Cards and the dashboard

`Cards.number / bars / donut / trend / series / columns` return HTML; hover details come from
`data-tip`. The dashboard is a catalog:

```js
Dash.mount({
  load: async ({ range }) => ({ d: await api.data.dashboard(), S: memoised(range) }),   // what renders need
  catalog: [{ type: 'open', group: 'Status', label: 'Open items', help: '…', sizes: ['s', 'm'], def: 's', rule: { warn: 5, bad: 10 }, guest: true,
              render: ({ d, rule }) => tile(Cards.colorFor(d.open, rule), 'Open items', d.open, 'not yet done') },
            { type: 'chart', group: 'Charts', label: 'Items per day', sizes: ['m', 'l', 'xl'], def: 'l', period: true, render: async ({ S, range }) => Cards.series(…) }],
  defaults: ['open', { type: 'chart', size: 'xl' }],
});
views.dashboard = Dash.render;
```

Users add, remove, resize, drag and configure cards (title, period, colour thresholds, row count);
the layout is saved per account. `guest: true` makes a card visible to guests; keep the data behind
it guest-safe in a `webHandlers` override.

## Deploying

- **Pi behind Caddy**: `docs/RASPBERRY-PI.md` (installer, Caddy site block, DNS record, hosts line).
  The installer is named after the app on download so two apps' installers cannot be confused.
- **Desktop**: `npm run build:win` locally or the tag-triggered CI job; the silent updater needs
  `latest.yml` and the `.blockmap` in the release, which the workflow uploads.
- **Release**: bump `package.json` and `CHANGELOG.md` in one commit, tag `vX.Y.Z`, push the tag.

## Python apps

`kit/python/bracket_fastapi.py` speaks the same contract from FastAPI: mount it, register handlers
with `@bk.handler('items:list')`, push events with `bk.send(...)`, and serve the same `app/renderer`
files. Two-factor codes and the self-signed HTTPS switch are not available there; put Caddy in front.
`python kit/python/test_bracket_fastapi.py` exercises the whole contract (needs `fastapi` and `httpx`).

## Upgrading the kit

```bash
npm run kit:upgrade                       # shows what changed between your kit/ and AxialForge/bracket@main
npm run kit:upgrade -- --apply            # replaces kit/ (a backup folder is kept), then run npm test
```

`kit/` is replaced as a whole, which is why nothing of yours may live there.
