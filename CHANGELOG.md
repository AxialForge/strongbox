# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-10-01

### Added

- Started from the Bracket template (kit 0.2.2), web-only.
- The vault: passphrase, key file or both (scrypt → HKDF → AES-256-GCM), optional recovery key, auto-lock, unlock throttling, changing the unlock method without re-encrypting.
- Tabs with user-defined field templates (text, link, several lines, number, date with expiry, choice, password, secret, authenticator seed); four default tabs.
- Entries with nesting, specs, notes, tags, favorites, extra logins, password history, live authenticator codes, move, trash and restore.
- Health report (weak, reused, old, expiring), dashboard cards, activity log, CSV import, encrypted backup download, nightly backup.
- Password generator, clipboard auto-clear, shown secrets hide again, glossary entries.
