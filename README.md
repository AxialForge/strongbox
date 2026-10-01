<p align="center"><img src="docs/logo.png" width="96" alt="Strongbox logo"></p>

# Strongbox

A LAN-only, locally encrypted vault for hardware, website, e-mail and key credentials on a Raspberry Pi.

- **Tabs you define**: Hardware, Websites, E-mail and Keys & licences to start; add your own with their own fields.
- **Nested entries**: a server holds its VMs and services, a NAS its shares.
- **Templates** (built in, or saved from any entry), **coloured tags**, **IP and MAC addresses** with extra network interfaces and a network table.
- **Password generator** with presets and requirements (length, required kinds of characters, the symbols a device allows).
- **Specs and notes** on every entry, tags, favorites, extra logins, password history, live authenticator codes.
- **Unlock like a Synology volume**: a passphrase, a key file, or both, plus an optional recovery key. Auto-locks when idle; a reboot locks it.
- **Encrypted at rest** (scrypt → AES-256-GCM, every record separately). Secrets are shown only on request and logged. A health report flags weak, reused, old and expiring items. Trash, activity log, encrypted backups.

Built on [Bracket](https://github.com/AxialForge/bracket): one core, a web shell for a Raspberry Pi behind Caddy, with the shared security model, themes, cards and the editable dashboard.

## Requirements

- Node 22.5 or newer (the core uses `node:sqlite`; nothing to `npm install` for the web server).

## Run

```bash
npm run dev                                   # web server on http://localhost:8083, data in ./.devdata
node app/server/server.js --data=.devdata --set-password
npm test
```

## Install on the Pi

```bash
curl -fsSL https://raw.githubusercontent.com/AxialForge/strongbox/main/server/install.sh -o strongbox-install.sh
sudo bash strongbox-install.sh
```

Then add the Caddy site block from [docs/RASPBERRY-PI.md](docs/RASPBERRY-PI.md).

## Development

Architecture, the extension points and the gotchas are in [CLAUDE.md](CLAUDE.md). The kit under `kit/` is
Bracket's and is never edited here; `npm run kit:upgrade` brings in a newer kit and shows the diff.

## License

MIT. See [LICENSE](LICENSE).
