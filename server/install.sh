#!/usr/bin/env bash
# Strongbox installer for Raspberry Pi OS (64-bit) and other Debian-family systems.
# Built to sit next to other Bracket apps on the same machine: its own user, data folder and port,
# optionally its own NAS mount, all behind Caddy (see docs/RASPBERRY-PI.md).
#
#   sudo bash strongbox-install.sh                    install or upgrade to the latest release
#   sudo bash strongbox-install.sh --share=//192.168.1.204/Share --folder=Strongbox
#                                                  mount a NAS share (asked once if --nas is given without them)
#   sudo bash strongbox-install.sh --port=8083     web port
#   sudo bash strongbox-install.sh --branch=main       track a git branch instead of releases (development)
#   sudo bash strongbox-install.sh --auto-update | --no-auto-update   nightly update timer on / off
#   sudo bash strongbox-install.sh --update-only       used by strongbox-update
#
# What it does, idempotently:
#   1. installs Node 22 (only if missing), curl, openssl (+ cifs-utils when a share is given)
#   2. creates the `strongbox` system user and /var/lib/strongbox
#   3. downloads the verified server package into /opt/strongbox
#   4. optionally mounts a NAS share at /mnt/strongbox via fstab (asks once for credentials)
#   5. installs a systemd service and the `strongbox` / `strongbox-update` commands
#   6. asks for the admin password if none is set
set -euo pipefail

APP="Strongbox"
SLUG="strongbox"
REPO="https://github.com/AxialForge/strongbox.git"
RAW="https://raw.githubusercontent.com/AxialForge/strongbox/main"
REL="https://github.com/AxialForge/strongbox/releases/latest/download"
APP_DIR="/opt/$SLUG"
DATA_DIR="/var/lib/$SLUG"
SVC_USER="$SLUG"
MOUNT="/mnt/$SLUG"
CREDS="/etc/$SLUG-cifs.cred"
PORT="${PORT_OVERRIDE:-8083}"
SHARE=""; FOLDER=""; BRANCH=""; DOMAIN=""
UPDATE_ONLY=0; AUTO_UPDATE=0; PORT_GIVEN=0; WANT_NAS=0
for a in "$@"; do case "$a" in
  --share=*) SHARE="${a#--share=}"; WANT_NAS=1;; --folder=*) FOLDER="${a#--folder=}";; --nas) WANT_NAS=1;; --port=*) PORT="${a#--port=}"; PORT_GIVEN=1;;
  --domain=*) DOMAIN="${a#--domain=}";; --branch=*) BRANCH="${a#--branch=}";; --update-only) UPDATE_ONLY=1;;
  --auto-update) AUTO_UPDATE=1;; --no-auto-update) AUTO_UPDATE=-1;;
esac; done

[[ $EUID -eq 0 ]] || { echo "Run with sudo."; exit 1; }
say() { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
# Say which app this is first: several Bracket apps share this installer's shape and flags.
say "$APP installer (data $DATA_DIR, port $PORT)"
[[ -n "$DOMAIN" ]] && echo "$DOMAIN" > "/etc/$SLUG-domain"
[[ -f "/etc/$SLUG-port" && $PORT_GIVEN -eq 0 ]] && PORT="$(cat "/etc/$SLUG-port")"
echo "$PORT" > "/etc/$SLUG-port"

# ---- application ------------------------------------------------------------------------------
fetch_release() {
  local tmp; tmp="$(mktemp -d)"
  curl -fsSL "$REL/$SLUG-server.tar.gz" -o "$tmp/pkg.tar.gz"
  curl -fsSL "$REL/$SLUG-server.tar.gz.sha256" -o "$tmp/pkg.sha256"
  (cd "$tmp" && sed "s/$SLUG-server.tar.gz/pkg.tar.gz/" pkg.sha256 | sha256sum -c --quiet -) || { echo "Checksum mismatch; refusing to install."; rm -rf "$tmp"; exit 1; }
  tar -xzf "$tmp/pkg.tar.gz" -C "$tmp"
  rm -rf "$APP_DIR.new"; mv "$tmp/$SLUG-server" "$APP_DIR.new"; rm -rf "$tmp"
  rm -rf "$APP_DIR.old"; [[ -d "$APP_DIR" ]] && mv "$APP_DIR" "$APP_DIR.old"; mv "$APP_DIR.new" "$APP_DIR"; rm -rf "$APP_DIR.old"
}
install_app() {
  say "Application at $APP_DIR"
  if [[ -n "$BRANCH" ]]; then
    command -v git >/dev/null || apt-get install -y git >/dev/null
    if [[ ! -d "$APP_DIR/.git" ]]; then rm -rf "$APP_DIR"; git clone -q "$REPO" "$APP_DIR"; fi
    git -C "$APP_DIR" fetch -q origin && git -C "$APP_DIR" checkout -q "$BRANCH" && git -C "$APP_DIR" pull -q --ff-only origin "$BRANCH" || true
  else
    fetch_release
  fi
  chown -R root:root "$APP_DIR"
  echo "version $(node -p "require('$APP_DIR/package.json').version")${BRANCH:+ ($BRANCH)}"
}

if [[ $UPDATE_ONLY -eq 1 ]]; then install_app; systemctl restart "$SLUG"; echo "$APP updated to $(node -p "require('$APP_DIR/package.json').version")"; exit 0; fi

# ---- packages ---------------------------------------------------------------------------------
say "Packages"
if ! command -v node >/dev/null || [[ "$(node -v | cut -d. -f1)" != "v22" ]]; then
  curl -fsSL https://deb.nodesource.com/setup_22.x | bash -
  apt-get install -y nodejs >/dev/null
fi
DEBIAN_FRONTEND=noninteractive apt-get install -y curl openssl $([[ $WANT_NAS -eq 1 ]] && echo cifs-utils) >/dev/null
echo "node $(node -v)"
# Unprivileged ICMP for any app that pings (NoNewPrivileges blocks the ping binary's file capability).
echo "net.ipv4.ping_group_range = 0 2147483647" > /etc/sysctl.d/90-bracket.conf
sysctl -q -p /etc/sysctl.d/90-bracket.conf || true

# ---- user, app --------------------------------------------------------------------------------
say "Service user and data folder"
id -u "$SVC_USER" >/dev/null 2>&1 || useradd --system --home-dir "$DATA_DIR" --shell /usr/sbin/nologin "$SVC_USER"
install -d -o "$SVC_USER" -g "$SVC_USER" -m 0750 "$DATA_DIR"
getent group video >/dev/null && usermod -aG video "$SVC_USER"   # vcgencmd: throttling flags on the System page
install_app

# ---- NAS (optional) ------------------------------------------------------------------------------
if [[ $WANT_NAS -eq 1 ]]; then
  say "NAS share at $MOUNT"
  if [[ -z "$SHARE" ]] && grep -qF " $MOUNT cifs " /etc/fstab; then SHARE="$(awk -v m="$MOUNT" '$2==m{print $1}' /etc/fstab)"; fi
  if [[ -z "$SHARE" ]]; then read -r -p "NAS share for $APP files (for example //192.168.1.204/Backups): " SHARE; fi
  if [[ -z "$FOLDER" ]]; then read -r -p "Folder inside that share [$APP]: " FOLDER; FOLDER="${FOLDER:-$APP}"; fi
  install -d "$MOUNT"
  if [[ ! -f "$CREDS" ]]; then
    read -r -p "Share username for $SHARE: " SU
    read -r -s -p "Share password: " SP; echo
    ( umask 077; printf 'username=%s\npassword=%s\n' "$SU" "$SP" > "$CREDS" ); chmod 600 "$CREDS"
  fi
  UID_N="$(id -u "$SVC_USER")"; GID_N="$(id -g "$SVC_USER")"
  FSTAB_LINE="$SHARE $MOUNT cifs credentials=$CREDS,uid=$UID_N,gid=$GID_N,file_mode=0660,dir_mode=0770,vers=3.0,iocharset=utf8,_netdev,nofail,x-systemd.automount 0 0"
  # Only touch fstab once the mount is proven, and never unmount a share something else is using.
  OLD_LINE="$(grep -F " $MOUNT cifs " /etc/fstab || true)"
  if mountpoint -q "$MOUNT"; then
    CUR="$(findmnt -n -o SOURCE "$MOUNT" || true)"
    if [[ -n "$CUR" && "$CUR" != "$SHARE" ]]; then echo "$MOUNT already has $CUR mounted; unmount it first (sudo umount $MOUNT) or pick another share."; exit 1; fi
    umount "$MOUNT" || { echo "$MOUNT is busy; stop whatever uses it and run again."; exit 1; }
  fi
  if [[ -n "$OLD_LINE" ]]; then sed -i "\| $MOUNT cifs |c\\$FSTAB_LINE" /etc/fstab; else echo "$FSTAB_LINE" >> /etc/fstab; fi
  systemctl daemon-reload
  if ! mount "$MOUNT"; then
    if [[ -n "$OLD_LINE" ]]; then sed -i "\| $MOUNT cifs |c\\$OLD_LINE" /etc/fstab; else sed -i "\| $MOUNT cifs |d" /etc/fstab; fi
    systemctl daemon-reload; echo "Mount failed; fstab restored. Check $CREDS and: dmesg | tail"; exit 1
  fi
  sudo -u "$SVC_USER" mkdir -p "$MOUNT/$FOLDER" && sudo -u "$SVC_USER" touch "$MOUNT/$FOLDER/.write-test" && rm -f "$MOUNT/$FOLDER/.write-test" \
    && echo "writable: $SHARE/$FOLDER" || { echo "The share mounted but $FOLDER is not writable with those credentials."; exit 1; }
  sudo -u "$SVC_USER" node -e "
const fs=require('fs');const f='$DATA_DIR/settings.json';let s={};try{s=JSON.parse(fs.readFileSync(f,'utf8'))}catch{}
s.nas=Object.assign({},s.nas,{dir:'$MOUNT/$FOLDER'});fs.writeFileSync(f,JSON.stringify(s,null,2),{mode:0o600});"
  cat > "/usr/local/sbin/$SLUG-mount-check" <<EOF
#!/usr/bin/env bash
mountpoint -q "$MOUNT" && exit 0
HOST="\$(awk '\$2=="$MOUNT"{print \$1}' /etc/fstab | sed -E 's#^//([^/]+)/.*#\\1#')"
if [[ -n "\$HOST" ]] && ! timeout 3 bash -c "exec 3<>/dev/tcp/\$HOST/445" 2>/dev/null; then exit 0; fi
mount "$MOUNT" && logger -t $SLUG "re-mounted $MOUNT"
EOF
  chmod 755 "/usr/local/sbin/$SLUG-mount-check"
  cat > "/etc/systemd/system/$SLUG-mount.service" <<EOF
[Unit]
Description=Re-mount the $APP NAS share if it dropped
After=network-online.target
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/$SLUG-mount-check
EOF
  cat > "/etc/systemd/system/$SLUG-mount.timer" <<EOF
[Unit]
Description=Check the $APP NAS mount every minute
[Timer]
OnBootSec=50s
OnUnitActiveSec=60s
AccuracySec=10s
[Install]
WantedBy=timers.target
EOF
  systemctl daemon-reload; systemctl enable -q --now "$SLUG-mount.timer"
fi

# ---- commands, service, timers ------------------------------------------------------------------
say "Commands and service"
P_ENV="$(echo "$SLUG" | tr '[:lower:]-' '[:upper:]_')"
cat > "/usr/local/bin/$SLUG" <<EOF
#!/usr/bin/env bash
# $SLUG --set-password   (or any server flag); runs as the service user against its data folder
exec sudo -u $SVC_USER ${P_ENV}_PASSWORD="\${${P_ENV}_PASSWORD:-}" NODE_OPTIONS=--disable-warning=ExperimentalWarning /usr/bin/node $APP_DIR/app/server/server.js --data=$DATA_DIR --port=\$(cat /etc/$SLUG-port) "\$@"
EOF
cat > "/usr/local/bin/$SLUG-update" <<EOF
#!/usr/bin/env bash
# Install the latest release package (verified) and restart the service. Data in $DATA_DIR is untouched.
set -e
if [[ -d $APP_DIR/.git ]]; then git -C $APP_DIR pull -q --ff-only; systemctl restart $SLUG; else
  curl -fsSL $RAW/server/install.sh -o /tmp/$SLUG-install.sh && bash /tmp/$SLUG-install.sh --update-only
fi
echo "$APP now at \$(node -p "require('$APP_DIR/package.json').version")"
EOF
chmod 755 "/usr/local/bin/$SLUG" "/usr/local/bin/$SLUG-update"

cat > "/etc/systemd/system/$SLUG.service" <<EOF
[Unit]
Description=$APP
After=network-online.target remote-fs.target
Wants=network-online.target

[Service]
User=$SVC_USER
Group=$SVC_USER
WorkingDirectory=$APP_DIR
ExecStart=/usr/bin/node $APP_DIR/app/server/server.js --data=$DATA_DIR --port=$PORT
Restart=always
RestartSec=5
Environment=NODE_ENV=production
Environment=NODE_OPTIONS=--disable-warning=ExperimentalWarning
Environment=PATH=/opt/$SLUG-tools:/usr/local/bin:/usr/bin:/bin
NoNewPrivileges=true
LimitCORE=0
ProtectSystem=full
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
if [[ $AUTO_UPDATE -eq 1 ]]; then
cat > "/etc/systemd/system/$SLUG-update.service" <<EOF
[Unit]
Description=Update $APP to the latest release
[Service]
Type=oneshot
ExecStart=/usr/local/bin/$SLUG-update
EOF
cat > "/etc/systemd/system/$SLUG-update.timer" <<EOF
[Unit]
Description=Nightly $APP update
[Timer]
OnCalendar=*-*-* 04:45:00
RandomizedDelaySec=900
Persistent=true
[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload; systemctl enable -q --now "$SLUG-update.timer"; echo "Nightly auto-update enabled (04:45)."
elif [[ $AUTO_UPDATE -eq -1 ]]; then
systemctl disable --now "$SLUG-update.timer" >/dev/null 2>&1 || true; rm -f "/etc/systemd/system/$SLUG-update".{timer,service}; echo "Nightly auto-update removed."
fi
systemctl daemon-reload
systemctl enable -q "$SLUG"

has_admin() { node -e "const s=require(process.argv[1]);process.exit(Object.values(s.users||{}).some(u=>u.role==='admin')?0:1)" "$DATA_DIR/web.json" 2>/dev/null; }
if ! has_admin; then say "Admin password for the $APP web page"; "/usr/local/bin/$SLUG" --set-password; fi

systemctl restart "$SLUG"
sleep 2
systemctl --no-pager --lines=3 status "$SLUG" || true
IP="$(hostname -I | awk '{print $1}')"
[[ -z "$DOMAIN" && -f "/etc/$SLUG-domain" ]] && DOMAIN="$(cat "/etc/$SLUG-domain")"
say "Done. Open ${DOMAIN:+https://$DOMAIN  or  }http://$IP:$PORT"
echo "Behind Caddy: add the site block from docs/RASPBERRY-PI.md, reload Caddy, add the DNS record."
echo "Logs: journalctl -u $SLUG -f     Update: sudo $SLUG-update     Password: sudo $SLUG --set-password"
