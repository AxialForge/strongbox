# The non-password things worth keeping, and where each goes in Strongbox

A password is the easy part. The things that save you at 2 a.m. when a phone dies are the **backups and recovery
material**: codes, keys, phrases, questions. This is a survey of the common ones and how Strongbox stores each.

## At a glance

| What | Typical sources | How Strongbox stores it |
|---|---|---|
| **Backup / recovery codes** (one-time) | Instagram, Facebook, Google (10), GitHub (16), Microsoft, Discord, Dropbox, X, Epic Games | **Backup codes** card on any entry: paste once, tick each off as used, "Use next", low-stock warning |
| **Authenticator seeds** (TOTP) | Any site that shows a QR code for an authenticator app | *Authenticator seed* field, or the 2FA seed on an account; live six-digit code on request |
| **Security questions** | Banks, older sites, some email providers | **Security questions** section: question in plain sight to you, answer encrypted |
| **App passwords** | Google, Microsoft, iCloud, Yahoo (for mail clients, printers, old apps) | Account kind **App password** |
| **API tokens / access keys** | GitHub personal access tokens, AWS keys, Cloudflare, webhooks, OAuth client secrets, database URLs | Account kind **API token / access key** (stale after a year, like a password) |
| **SSH / PGP private keys** | `~/.ssh/id_ed25519`, GPG exports | Account kind **SSH / PGP private key** (multi-line), passphrase as a second account; or attach the key file |
| **Recovery phrases (seed words)** | Crypto wallets (12 or 24 words), Ledger, Trezor, some password managers | Account kind **Recovery phrase**; the *Crypto wallet* template |
| **PINs and passcodes** | Phone lock, SIM PIN and PUK, bank card, Windows Hello, door lock, alarm panel, garage | Account kind **PIN**, or the *Screen lock PIN* / *SIM PIN* fields on Mobile devices |
| **Disk and device recovery keys** | BitLocker (48 digits), FileVault, LUKS, Apple ID recovery key, Microsoft account recovery code | Account kind **Recovery key** (the *PC / laptop* template has a BitLocker one) |
| **Hardware keys, passkeys, fingerprints** | YubiKey, Windows Hello, Face ID | Account kinds **Hardware key** (link to the YubiKey entry), **Passkey**, **Fingerprint / face** (a note of what is enrolled) |
| **Sign-in with another account** | Plex with Google, anything "Sign in with Apple / Google" | Account kind **Signs in with another entry**: links to the entry, shows its user, reveals its password without storing it twice |
| **Account recovery details** | Recovery e-mail and phone, trusted contacts, legacy / inactive-account contacts, verbal passwords, account and customer numbers | *Recovery e-mail / phone* field, notes, security questions |
| **Wi-Fi** | SSID, password, WPS PIN, guest network | **Wi-Fi** type, plus a QR code a phone can scan |
| **Network gear secrets** | PPPoE login, SNMP community, RADIUS or VPN shared secret, WireGuard keys, IPMI / iDRAC | Accounts on the hardware entry (token kind for secrets); attach `.conf` files |
| **Software licences and serials** | Autodesk, Adobe, Office, game keys | **Keys & licences** type, with an expiry that warns you |
| **Certificates and key stores** | `.pem`, `.pfx`, `.jks` and their passwords | **Attachments** for the file, an account for the password |
| **Printed one-time lists, RSA tokens** | Older bank lists, SecurID seed files | Attachment (a photo or file) and a note |

## Backup codes in detail

Sites give you a handful of single-use codes **once**. Lose the phone and these are the way back in, so:

1. Open the site's security settings and generate a set. Generating a new set usually **cancels the old one**.
2. In Strongbox open the entry (or make one), choose **＋ add a set** in the *Backup codes* card, name it ("Instagram backup
   codes"), and paste the codes **one per line**. A single line is split on spaces.
3. The codes are encrypted like a password. Lists, search and the page never show them; **Show codes** asks the server and is
   logged in Activity.
4. When you use one, press **Use next** (copies the first unused code and ticks it off) or tick it yourself with ✓. The badge
   shows "3 of 10 left" and turns amber at or below the warning level (Settings → Backup codes warning, default 2).
5. **Health** and the dashboard list sets that are running low, so you replace them before you are locked out. **Replace…** pastes
   a fresh set.

Why track "used"? Most sites burn a code the moment it works; knowing which are left is the whole point of the list.

## Security questions

Add them in the editor under *Security questions*. The question is searchable; the answer is encrypted and shown only on request.
Tip: a long random answer is better than the true one. Treat the answer like a second password and store it, since you will not
remember it.

## What is deliberately not judged like a password

Health checks (weak, reused, old, breached) apply to **passwords**. They skip:

- **PINs**: short by nature (a famous PIN such as 1234 is still flagged as known-breached).
- **Recovery keys, recovery phrases, SSH keys**: random, machine-made, and not changed on a schedule.
- **Tokens and app passwords**: checked for age, not strength.

## What not to put in the vault

- The vault's own **passphrase, key file and recovery key**. Keep those apart (a safe, a USB stick, paper). The **Emergency
  sheet** prints the how-to and leaves the recovery key for you to write by hand.
- Anything you would not want printed if you tick *include passwords* on a print.
