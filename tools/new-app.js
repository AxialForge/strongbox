#!/usr/bin/env node
'use strict';
// Turn this checkout of the Bracket template into a new app, in place.
//
//   node tools/new-app.js --name "Wing Flow" --slug wingflow --port 8083 [--repo AxialForge/wingflow]
//                         [--tagline "…"] [--web-only | --desktop-only]
//
// What it does:
//   - app/app.json, app/renderer/app-meta.js, index.html, manifest: the app's identity
//   - package.json, electron-builder.yml, server/install.sh, docs: names, slug, port, repository
//   - README.md and CLAUDE.md become skeletons for the new app (Bracket's own are for the template)
//   - CHANGELOG.md restarts at 0.1.0; SETUP.md lists what is left to do by hand
//   - --web-only removes the desktop shell (Electron files, dependencies, CI job);
//     --desktop-only removes the web shell files, the installer and the Pi docs
// The kit/ folder is never touched: it is upgraded as a whole with tools/kit-upgrade.js.
const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');
// `--name=X`, `--name X` and bare `--web-only` all work.
const args = {};
for (let i = 2, av = process.argv; i < av.length; i++) {
  const m = /^--([^=]+)(?:=(.*))?$/.exec(av[i]);
  if (!m) continue;
  if (m[2] !== undefined) args[m[1]] = m[2];
  else if (av[i + 1] !== undefined && !av[i + 1].startsWith('--')) args[m[1]] = av[++i];
  else args[m[1]] = true;
}
const need = (k) => { if (!args[k] || args[k] === true) { console.error(`--${k} is required`); process.exit(2); } return String(args[k]); };
const name = need('name');
const slug = String(args.slug || name).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
const port = Number(args.port || 8090);
const repo = String(args.repo || `AxialForge/${slug}`).replace(/^https:\/\/github\.com\//, '').replace(/\.git$/, '');
const tagline = String(args.tagline || `${name}, built on Bracket`);
const shells = args['web-only'] ? ['web'] : args['desktop-only'] ? ['desktop'] : ['web', 'desktop'];
const year = new Date().getFullYear();
if (!/^[a-z][a-z0-9-]{1,30}$/.test(slug)) { console.error('slug must be 2–31 chars: letters, digits, dashes'); process.exit(2); }

const read = (rel) => fs.readFileSync(path.join(root, rel), 'utf8');
const write = (rel, text) => { fs.mkdirSync(path.dirname(path.join(root, rel)), { recursive: true }); fs.writeFileSync(path.join(root, rel), text); console.log('wrote', rel); };
const edit = (rel, fn) => { if (!fs.existsSync(path.join(root, rel))) return; write(rel, fn(read(rel))); };
const remove = (rel) => { const p = path.join(root, rel); if (fs.existsSync(p)) { fs.rmSync(p, { recursive: true, force: true }); console.log('removed', rel); } };
const jsonEdit = (rel, fn) => edit(rel, s => JSON.stringify(fn(JSON.parse(s)), null, 2) + '\n');

// ---- identity ---------------------------------------------------------------------------------
jsonEdit('app/app.json', j => ({ ...j, name, slug, tagline, repo: `https://github.com/${repo}`, port, shells }));
write('app/renderer/app-meta.js', `// Who this app is, for the renderer (loaded first; the server side reads app/app.json).\nwindow.APP = ${JSON.stringify({ name, slug, tagline, bridge: 'api', logo: 'logo.svg', author: 'AxialForge (Joseph Costarella)', license: 'MIT' })};\n`);
edit('app/renderer/index.html', s => s.replace(/<title>[^<]*<\/title>/, `<title>${name}</title>`));
jsonEdit('app/renderer/manifest.webmanifest', j => ({ ...j, name, short_name: name.length > 12 ? slug : name }));
jsonEdit('package.json', j => {
  const out = { ...j, name: slug, productName: name, version: '0.1.0', description: tagline, repository: { type: 'git', url: `https://github.com/${repo}.git` } };
  out.scripts = { ...j.scripts, dev: `node app/server/server.js --data=.devdata --port=${port}` };
  delete out.scripts.new;
  if (!shells.includes('desktop')) { delete out.main; delete out.devDependencies; delete out.dependencies; delete out.scripts.start; delete out.scripts['build:win']; delete out.scripts.screenshots; }
  if (!shells.includes('web')) { delete out.scripts.web; delete out.scripts.dev; delete out.scripts['pack:server']; }
  return out;
});
edit('electron-builder.yml', s => s.replace(/appId: .*/, `appId: com.axialforge.${slug}`).replace(/productName: .*/, `productName: ${name}`));
edit('server/install.sh', s => s.replace(/__NAME__/g, name).replace(/__SLUG__/g, slug).replace(/__PORT__/g, String(port)).replace(/__GITHUB__/g, repo));
edit('docs/RASPBERRY-PI.md', s => s.replace(/__NAME__/g, name).replace(/__SLUG__/g, slug).replace(/__PORT__/g, String(port)).replace(/__GITHUB__/g, repo));
edit('kit/ops/caddy-site.txt', s => s); // kept generic on purpose (the docs carry the filled-in copy)
edit('app/renderer/app.js', s => s.replace(/journalctl -u bracket -f/g, `journalctl -u ${slug} -f`));
edit('LICENSE', s => s.replace(/\{\{YEAR\}\}/g, String(year)));

// ---- shells -------------------------------------------------------------------------------------
if (!shells.includes('desktop')) {
  remove('app/electron'); remove('app/preload.js'); remove('kit/electron'); remove('electron-builder.yml'); remove('build');
  edit('.github/workflows/release.yml', s => s.replace(/\n  build-win:[\s\S]*$/, '\n'));
}
if (!shells.includes('web')) {
  remove('app/server'); remove('server'); remove('docs/RASPBERRY-PI.md'); remove('kit/python'); remove('kit/ops/caddy-site.txt');
  edit('.github/workflows/release.yml', s => s.replace(/      - name: Check the installer parses\n        run: bash -n server\/install\.sh\n/, '').replace(/      - name: Build server package[\s\S]*?path: dist\/\*-server\*\n/, '').replace(/      - name: Attach to release\n        if: startsWith\(github\.ref, 'refs\/tags\/'\)\n        uses: softprops\/action-gh-release@v2\n        with:\n          files: \|\n            dist\/\*-server-\*\.tar\.gz\n            dist\/\*-server\.tar\.gz\n            dist\/\*-server\.tar\.gz\.sha256\n          generate_release_notes: true\n/, ''));
}

// ---- docs ---------------------------------------------------------------------------------------
write('README.md', `# ${name}

${tagline}

Built on [Bracket](https://github.com/AxialForge/bracket): one core, ${shells.includes('web') && shells.includes('desktop') ? 'a web shell for a Raspberry Pi behind Caddy and an Electron desktop shell' : shells.includes('web') ? 'a web shell for a Raspberry Pi behind Caddy' : 'an Electron desktop shell'}, with the shared security model, themes, cards and the editable dashboard.

## Requirements

- Node 22.5 or newer (the core uses \`node:sqlite\`; nothing to \`npm install\` for the web server).
${shells.includes('desktop') ? '- For the desktop app: `npm install` (Electron and electron-builder).\n' : ''}
## Run

\`\`\`bash
${shells.includes('web') ? `npm run dev                                   # web server on http://localhost:${port}, data in ./.devdata\nnode app/server/server.js --data=.devdata --set-password\n` : ''}${shells.includes('desktop') ? 'npm start                                     # desktop app\n' : ''}npm test
\`\`\`
${shells.includes('web') ? `
## Install on the Pi

\`\`\`bash
curl -fsSL https://raw.githubusercontent.com/${repo}/main/server/install.sh -o ${slug}-install.sh
sudo bash ${slug}-install.sh
\`\`\`

Then add the Caddy site block from [docs/RASPBERRY-PI.md](docs/RASPBERRY-PI.md).
` : ''}
## Development

Architecture, the extension points and the gotchas are in [CLAUDE.md](CLAUDE.md). The kit under \`kit/\` is
Bracket's and is never edited here; \`npm run kit:upgrade\` brings in a newer kit and shows the diff.

## License

MIT. See [LICENSE](LICENSE).
`);
write('CLAUDE.md', `# ${name} — project guide for Claude Code

${tagline}

<!-- One paragraph: what this is, how it's shipped, and what it deliberately isn't. -->

Built on Bracket (\`kit/\`): the core in \`app/main/service.js\` is hosted by ${shells.includes('web') ? 'the web shell (`app/server/server.js`, Pi behind Caddy, port ' + port + ')' : ''}${shells.length === 2 ? ' and ' : ''}${shells.includes('desktop') ? 'the desktop shell (`app/electron/main.js`)' : ''}. The renderer is \`app/renderer/\` on top of the kit's \`ui.js\`, \`cards.js\` and \`dash.js\`. See \`docs/GUIDE.md\` for how the pieces fit.

## Non-negotiables (don't regress these)

- **Zero dependencies in the core and the web server.** \`node:sqlite\`, \`node:http\`; no native addons; no CDN assets.
- **\`kit/\` is never edited here.** Fixes go to the Bracket repo and arrive with \`npm run kit:upgrade\`. App code lives in \`app/\`.
- Author and commit rules from the global \`~/.claude/CLAUDE.md\` apply: AxialForge identity, no Claude attribution, imperative commit messages.

## Commands

\`\`\`bash
npm test                         # kit tests + app contract and handler tests (plain node)
${shells.includes('web') ? `npm run dev                      # web server on :${port}, data in ./.devdata\nnode app/server/server.js --data=.devdata --set-password\nnpm run pack:server              # dist/${slug}-server.tar.gz + .sha256 (what CI attaches)\n` : ''}${shells.includes('desktop') ? 'npm start                        # desktop app\nnpm run screenshots              # the release gate: renders every page, exits 3 on a renderer error\n' : ''}npm run kit:upgrade              # compare kit/ with the Bracket repo; --apply to take the new one
\`\`\`

## Architecture

<!-- The handlers Map in app/main/service.js is the API; app/renderer/bridge-shape.js describes it for the browser; app/test/app.test.js keeps the two in step. -->

### Directory map

| Path | Owns |
|---|---|
| \`app/app.json\` | Identity: name, slug, port, repository, shells |
| \`app/main/service.js\` | The core: schema, settings defaults, jobs, handlers, CSV sets |
| \`app/renderer/app.js\` | The pages (\`UI.views.<name>\`), the dashboard catalog (\`Dash.mount\`), the nav (\`UI.init\`) |
| \`app/renderer/bridge-shape.js\` | The one description of \`window.api\` |
${shells.includes('web') ? '| `app/server/server.js` | Roles, secrets, web-only handlers, CSV sets |\n| `server/install.sh` | Pi installer |\n' : ''}${shells.includes('desktop') ? '| `app/electron/main.js` | Window options, screenshot list, desktop-only handlers |\n' : ''}| \`kit/\` | Bracket (read-only here) |

## The extension points

See \`docs/GUIDE.md\`: a page, a handler, a role, a card, a settings section, a job, a CSV set, a notification event.

## Gotchas / constraints

<!-- Leave empty until something bites. Then: symptom → cause → why the obvious fix is wrong. The kit's own gotchas are in Bracket's CLAUDE.md. -->

## Roadmap (unbuilt)

## Release

Bump \`package.json\` and add a \`CHANGELOG.md\` entry in one commit, then \`git tag vX.Y.Z && git push origin main --tags\`. CI runs the tests${shells.includes('web') ? ', packs the server' : ''}${shells.includes('desktop') ? ', builds the Windows installer' : ''} and attaches everything to the GitHub Release.
`);
write('CHANGELOG.md', `# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - ${new Date().toISOString().slice(0, 10)}

### Added

- Started from the Bracket template (kit ${read('kit/VERSION').trim()}).
`);
write('SETUP.md', `# Setup checklist — delete this file when you're done

You made **${name}** from the Bracket template. Work down this list, then \`git rm SETUP.md\`.

1. **Git identity.** \`git config --local --get-regexp "^user\\."\` must print nothing (a stale local override shadows the AxialForge identity).
2. **Icons.** Edit the glyph in \`tools/make-icon.js\` and run \`npm run icons\`${shells.includes('desktop') ? '; the desktop build also wants `build/icon.ico` and `build/icon.png` (copied there by the script).' : '.'}
3. **The app.** Replace the notes sample in \`app/main/service.js\` and \`app/renderer/app.js\`; keep the shapes. \`docs/GUIDE.md\` explains each extension point.
4. **Roles and secrets** in ${shells.includes('web') ? '`app/server/server.js`' : 'the web shell (if you add one)'}.
5. **CLAUDE.md.** Fill the architecture map from the real code; leave Gotchas empty until something bites.
6. **Repository.** \`gh repo create ${repo} --public --source=. --push\`, then \`gh repo edit --description "${tagline}"\`.
${shells.includes('web') ? `7. **Pi.** \`docs/RASPBERRY-PI.md\` has the installer command, the Caddy block and the DNS step for \`${slug}.home\`.\n` : ''}
`);
console.log(`\n${name} (${slug}) is ready: port ${port}, shells ${shells.join(' + ')}, repository ${repo}.`);
console.log('Next: npm test, then work through SETUP.md.');
