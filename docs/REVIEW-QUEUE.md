# Reviewing a big import (hundreds or thousands of logins)

A Google Password Manager export can hold fifteen years of accounts. Importing them all straight in puts a pile of dead logins,
duplicates and weak passwords in your vault. The **review queue** is a holding area: nothing goes into the vault until you decide
about it, and you can stop and carry on any day.

## Start

1. Export from Google: passwords.google.com → Settings → **Export passwords**.
2. In Strongbox: **Settings → Backup and import → Import a CSV**, choose the file, press **Preview…**.
3. Press **Add to the review queue** (it is the highlighted button for big files). Duplicates of what you already have are skipped.
4. Delete the CSV file and empty the recycle bin: it holds every password in clear text.
5. Open **Review** in the sidebar.

Queued logins are encrypted like everything else. They are **not** in the vault: they do not appear in lists, search, Health, the
network table or the Home Assistant counts until you keep them.

## One card at a time

Each card shows one login with everything editable: title, address, user name, password, type, tags, notes, favorite.

| Button | Key | What happens |
|---|---|---|
| **Keep** | Enter | Saved in the vault with the type and tags you chose |
| **No longer used: archive** | A | Saved, but **archived**: kept, out of every list, search and count, findable under **Archive** |
| **Delete** | D | Saved into the **Trash** (so it can be undone for the trash period), then gone |
| **Skip for now** | S | Put at the back of the queue; it comes round again after the rest |
| **Pause** | P | Leave. Progress is saved on the server: **Resume review** appears on the Vault page and the sidebar shows the count |

Press Enter in any text box to keep. The keys work when you are not typing in a box.

## What the card helps with

- **Order.** The riskiest passwords come first: known-leaked, weak, or reused (also against what is already in your vault), then
  everything else by site. If you stop early, the important fixes are already done.
- **Type and tags are suggested** from the site: banks, shopping, social, streaming, developer, gaming, e-mail, utilities, travel,
  health, software, education and government. A **local address** (a router, NAS or device such as `192.168.1.1`) is suggested as
  **Hardware**, and an **Android app** entry is tagged `android-app`. Strongbox **learns**: whatever you choose for a site is
  suggested the next time that site comes up. No site is ever contacted.
- **Several accounts for one site** appear in the *Same site* box: other logins waiting in the queue (with Keep / Archive / Delete
  buttons using the suggested type and tags) and entries already in the vault. A *same user* badge marks likely duplicates.
- **Password problems** are shown as badges. **Generate a new one** sets a fresh password that is saved instead of the old one
  (then change it on the site).
- **Show** and **Copy** reveal the imported password on request; each look is logged.

## Tips for 1,500 logins

- Do the first screens slowly to teach the suggestions (type and tags), then go fast: the same site is pre-filled the way you
  chose last time.
- Use **Archive** for "I might need it" and **Delete** for "good riddance": archived entries cost nothing in lists or Health.
- Work in sessions. Close the tab any time; nothing is lost and the next card is the one you were on.
- A bank, e-mail or anything with money or recovery rights deserves a proper pass: change the password, add its backup codes and
  a security question, and set "change passwords every N days".
- When the queue is empty you get a summary (kept / archived / deleted). **Health** then shows what is left to fix.

## Housekeeping

- **Settings → Review queue** shows how many are waiting and has **Clear the queue** (discards the unreviewed ones; they were never
  in the vault).
- The queue is part of backups, restores and key rotation like any other data.
- Importing the same file again skips logins already in the vault, the archive or the queue.
