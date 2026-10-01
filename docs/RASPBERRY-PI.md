# Strongbox on a Raspberry Pi behind Caddy

Strongbox runs as its own service on the home server (`aether`, 192.168.1.203), next to the other
Bracket apps. Each has its own user, data folder and port; Caddy owns 80/443 and routes by name.

| | This app |
|---|---|
| Web page | `https://strongbox.home` (Caddy) → port **8083** (plain HTTP on the Pi) |
| Service user | `strongbox` |
| Data | `/var/lib/strongbox` (`strongbox.db`, `settings.json`, `web.json`, `strongbox.log`) |
| Commands | `strongbox`, `strongbox-update` |

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/AxialForge/strongbox/main/server/install.sh -o strongbox-install.sh
sudo bash strongbox-install.sh
```

Save it under the app's name: every Bracket app ships an `install.sh` with the same flags, and running
another app's copy would configure that app instead. The installer prints which app it is first thing.

Flags: `--port=<n>`, `--auto-update` (nightly at 04:45), `--share=//host/share --folder=Name` to
mount a NAS share at `/mnt/strongbox` (only touches `/etc/fstab` once the mount is proven; refuses to
unmount a busy share), `--branch=main` to track a branch instead of releases.

## Caddy, DNS, hosts (the five steps)

1. Install the app on its port (above). Leave the app's own HTTPS switch off: Caddy terminates TLS.
2. Add the site block and reload Caddy. Unlike the other apps this one lists **https only**: a vault
   should never be reachable over plain http, so there is no http:// fallback for guests (guest access is off anyway):

   ```bash
   sudo tee -a /etc/caddy/Caddyfile >/dev/null <<'EOF'

   strongbox.home {
       tls internal
       encode zstd gzip
       reverse_proxy 127.0.0.1:8083 {
           flush_interval -1
           transport http {
               read_timeout 0
               write_timeout 0
           }
       }
   }
   EOF
   sudo caddy validate --config /etc/caddy/Caddyfile && sudo systemctl reload caddy
   ```

   `flush_interval -1` keeps the live event stream flowing; the zero timeouts let long downloads finish.
3. UniFi Network → Settings → Policy Table → DNS Records: Host (A) `strongbox.home` → `192.168.1.203`.
4. On a PC with NordVPN, add `192.168.1.203  strongbox.home` to `C:\Windows\System32\drivers\etc\hosts`
   (elevated editor). Phones use the router's DNS and need nothing.
5. Open `https://strongbox.home`, sign in as `admin` with the password the installer asked for.

Behind the proxy every connection reaches the app from 127.0.0.1, so it reads the real client
address from `X-Forwarded-For` and the scheme from `X-Forwarded-Proto`, but only when the connection
itself comes from loopback. The Security page reports "HTTPS: terminated by the reverse proxy".

## Update

```bash
sudo strongbox-update
```

Installs the latest verified release and restarts the service. Data in `/var/lib/strongbox` is untouched.

## Home Assistant

Settings → Home Assistant shows a read-only status URL with a key. It reports **counts only** (entries, weak,
reused, old, expiring) and whether the vault is locked, never any content. A REST sensor:

```yaml
rest:
  - resource: "https://strongbox.home/api/status?key=YOUR_KEY"
    scan_interval: 60
    sensor:
      - name: "Strongbox status"
        value_template: "{{ value_json.app }}"
```

Notifications can also go to a Home Assistant webhook: Settings → Notifications → Webhook URL
`http://homeassistant.local:8123/api/webhook/strongbox`.

## Hardening the Pi (do these once)

The vault key exists in the Pi's memory while the vault is unlocked, and the data is only as safe as the box.

- **Turn swap off**, so the key can never be paged out to the SD card: `sudo dphys-swapfile swapoff && sudo systemctl disable dphys-swapfile`
  (on images that use zram, `sudo systemctl disable --now systemd-zram-setup@zram0`). Check with `free -h`: the Swap row should read 0.
  This affects every service on the Pi; if memory is tight, skip it and keep the auto-lock short instead.
- **Keep the key file off the Pi.** Put it on a USB stick or another computer. Keep the recovery key on paper.
- **Auto-lock** (Settings, default 15 minutes) wipes the key from memory; a reboot or a service restart locks the vault too.
- **Keep it LAN-only.** Leave Security → LAN only on, never publish Strongbox with Tailscale Funnel or a port forward, turn on two-factor codes for the admin, and
  give each person their own account (standard accounts can read but not change).
- The service runs as the `strongbox` user with core dumps disabled. Full-disk encryption of the Pi's SD card or SSD is a good extra layer if you can set it up.
- **Back up** the encrypted database off the Pi (Settings → Download a backup, or copy `/var/lib/strongbox/strongbox.db.backups/`). A backup is useless without the passphrase and key file (or the recovery key), so keep those separate from it.

## Restore a backup

The easy way: Settings → Safety net → **Restore a backup**, then choose the file. The manual way, if you cannot sign in:

```bash
sudo systemctl stop strongbox
sudo cp <backup>.db /var/lib/strongbox/strongbox.db
sudo rm -f /var/lib/strongbox/strongbox.db-wal /var/lib/strongbox/strongbox.db-shm
sudo chown strongbox:strongbox /var/lib/strongbox/*
sudo systemctl start strongbox
```

The vault then starts locked, and opens with the same passphrase and key file (or the recovery key) it had when the backup was made.

## Troubleshooting

- **"No account exists yet"**: `sudo strongbox --set-password`.
- **The page loads but every call fails with 401**: the session cookie is per app name; sign in again.
- **Logs**: `journalctl -u strongbox -f`, or the Log page in the app.
