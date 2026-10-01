# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.5.1] - 2026-10-01

### Fixed

- The "Behind Caddy" checkbox next to a port now enables and disables the port box as it should (it did nothing on 0.5.0).

## [0.5.0] - 2026-10-01

### Added

- **Port** is its own field type: a number (1-65535) or **Behind Caddy**, which shows a "via Caddy" badge instead of a port and keeps the port out of the vault list. The Services type uses it (existing vaults are upgraded once). Any type can use it from the Types editor.
- **Empty fields are hidden** on the entry page; a link in the Details card shows or hides them (remembered per browser).

## [0.4.0] - 2026-10-01

### Added

- **Accounts**: any entry, in any type (hardware, services, websites…), can hold as many users as it needs. Each account has a name (admin, read-only, SSH, deploy…), user name, password with history and strength, an optional 2FA seed with a live code, an address and a note. The old "More logins" section is now Accounts, shown as a card per account on the entry page; the vault list shows "N accounts"; templates carry account names; account notes are searchable; account passwords count in the weak, reused and old reports.

## [0.3.1] - 2026-10-01

### Fixed

- Adding a login, interface, spec or changing the type in the entry editor no longer jumps back to the top of the page. The page keeps its scroll position and the new row gets the cursor.

## [0.3.0] - 2026-10-01

### Added

- A **Services** type (web apps, databases, containers, daemons, media servers…) with address, port, version, login, API key, unit name and data folder, plus a "Service / app" template. A new entry nested under a Hardware entry starts as a service. Existing vaults get the type once, after Hardware, the next time they are unlocked.

### Changed

- "Tab" is now called "Type" everywhere in the app.

## [0.2.0] - 2026-10-01

### Added

- Password generator with presets (strong, very long, letters and digits, router / device, Wi-Fi key, passphrase, PINs, hex key) and requirements: length, minimum upper-case / digits / symbols, the symbols a device accepts, characters never to use, start with a letter. Your own presets can be saved; each password field can start from a preset. Also a Generator page.
- IP address and MAC address field types with validation and normalisation; extra network interfaces (name, IP, MAC) on any entry; a Network page listing every address with duplicate detection.
- Entry templates: built-ins (server, VM, NAS, router, switch / AP, website, security key, licence), "Save as template" from any entry, a Templates page and "New entry from template".
- Coloured tags with a Tags page (colour, rename, merge, remove) and tag filters in the vault list; colour for each tab.
- A more modern look: depth, gradients, rounded cards, coloured icon bubbles, motion; all themes still work.

### Changed

- The Hardware tab now has separate Hostname, IP address and MAC address fields.

## [0.1.0] - 2026-10-01

### Added

- Started from the Bracket template (kit 0.2.2), web-only.
- The vault: passphrase, key file or both (scrypt → HKDF → AES-256-GCM), optional recovery key, auto-lock, unlock throttling, changing the unlock method without re-encrypting.
- Tabs with user-defined field templates (text, link, several lines, number, date with expiry, choice, password, secret, authenticator seed); four default tabs.
- Entries with nesting, specs, notes, tags, favorites, extra logins, password history, live authenticator codes, move, trash and restore.
- Health report (weak, reused, old, expiring), dashboard cards, activity log, CSV import, encrypted backup download, nightly backup.
- Password generator, clipboard auto-clear, shown secrets hide again, glossary entries.
