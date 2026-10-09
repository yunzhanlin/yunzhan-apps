#!/usr/bin/env bash
set -euo pipefail
# The caller may use a restrictive root umask. Public executable and web
# directories must remain traversable by the unprivileged panel service.
# Credentials and private state below are created with explicit restrictive modes.
umask 022
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_ROOT=/
NO_SERVICES=0
PREFLIGHT_ONLY=0
while (($#)); do case "$1" in --root) TARGET_ROOT="${2:?}";shift 2;;--no-services) NO_SERVICES=1;shift;;--preflight-only) PREFLIGHT_ONLY=1;shift;;*) echo "unknown argument: $1" >&2;exit 2;;esac;done
"$HERE/verify-release.sh" "$HERE"
# Values were validated by verify-release.sh.
source "$HERE/RELEASE"
[[ "$(id -u)" == 0 ]] || { echo 'installer must run as root' >&2; exit 1; }
[[ -d "$TARGET_ROOT" && ! -L "$TARGET_ROOT" ]] || { echo 'target root must be an existing ordinary directory' >&2; exit 1; }
if [[ "$TARGET_ROOT" == / ]]; then
  [[ -f /etc/os-release ]] || { echo 'os-release missing' >&2; exit 1; }
  source /etc/os-release
  case "${ID:-}-${VERSION_ID:-}" in
    debian-12|debian-13|ubuntu-22.04|ubuntu-24.04|ubuntu-26.04) ;;
    *) echo 'this release supports Debian 12/13 and Ubuntu 22.04/24.04/26.04 only' >&2; exit 1;;
  esac
  PANEL_PLATFORM="$ID-$VERSION_ID"
  MACHINE="$(dpkg --print-architecture)"
  [[ "$MACHINE" == "$PANEL_ARCH" ]] || { echo "release architecture $PANEL_ARCH does not match $MACHINE" >&2; exit 1; }
fi
prefix(){ printf '%s%s' "${TARGET_ROOT%/}" "$1"; }
if ((NO_SERVICES==0)); then
  command -v python3 >/dev/null || { echo 'python3 is required for read-only install preflight; no host changes made' >&2; exit 1; }
  python3 "$HERE/waf-state-directory.py" check --root "$TARGET_ROOT"
  python3 "$HERE/native-build-directories.py" check --root "$TARGET_ROOT"
fi
RELEASE_DIR="$(prefix "/opt/panel/releases/$PANEL_VERSION")"
CURRENT="$(prefix /opt/panel/current)"
MARKER="$(prefix /etc/panel-release)"
FRESH=1;[[ -f "$MARKER" ]]&&FRESH=0
if ((FRESH)) && { ((NO_SERVICES==0)) || ((PREFLIGHT_ONLY)); };then
  for existing in /etc/nginx/nginx.conf /etc/systemd/system/panel.service /opt/panel/current /var/lib/panel/panel.db /etc/panel/firewall.nft;do
    candidate="$(prefix "$existing")"
    if [[ -e "$candidate" || -L "$candidate" ]];then
      echo "existing host configuration blocks first install: $existing; inspect and migrate it before retrying" >&2
      exit 1
    fi
  done
fi
if ((NO_SERVICES==0))&&((FRESH))&&[[ "$TARGET_ROOT" == / ]];then
  command -v ss >/dev/null || { echo 'ss is required for port preflight' >&2;exit 1; }
  for port in 80 443 19100 19101 19102 19443;do
    ss -H -ltn "sport = :$port" | grep -q . && { echo "port $port is already occupied" >&2;exit 1; } || true
  done
fi
# Updating the panel is not authorization to upgrade host libraries. In
# particular, needrestart may restart live PHP workers after an APT library
# update. Check the existing dependency set before any upgrade-side writes,
# including preflight-only runs; missing packages require deliberate host prep.
check_upgrade_dependencies(){
  local package
  local missing=()
  for package in "$@"; do
    [[ "$(dpkg-query -W -f='${db:Status-Status}' "$package" 2>/dev/null)" == installed ]] || missing+=("$package")
  done
  if ((${#missing[@]})); then
    printf '%s\n' "panel upgrade requires installed dependencies: ${missing[*]}; no APT or service changes made; prepare the host separately" >&2
    return 1
  fi
}
if ((NO_SERVICES==0)); then
  AIO_PACKAGE=libaio1t64
  JPEG_PACKAGE=libjpeg62-turbo-dev
  FREETYPE_PACKAGE=libfreetype-dev
  if [[ "$PANEL_PLATFORM" == debian-12 || "$PANEL_PLATFORM" == ubuntu-22.04 ]]; then
    AIO_PACKAGE=libaio1
    FREETYPE_PACKAGE=libfreetype6-dev
  fi
  [[ "$ID" == ubuntu ]] && JPEG_PACKAGE=libjpeg-turbo8-dev
  REQUIRED_PACKAGES=(ca-certificates curl nginx sqlite3 nftables openssh-server fail2ban python3-systemd acl unzip xz-utils build-essential autoconf pkg-config libxml2-dev libsqlite3-dev libssl-dev libcurl4-openssl-dev libonig-dev libzip-dev zlib1g-dev libpng-dev "$JPEG_PACKAGE" "$FREETYPE_PACKAGE" libicu-dev libpcre2-dev libapr1-dev libaprutil1-dev libnghttp2-dev bison flex re2c gpg gpg-agent "$AIO_PACKAGE" libnuma1 libncurses6 libtinfo6)
  if ((FRESH==0)); then check_upgrade_dependencies "${REQUIRED_PACKAGES[@]}"; fi
fi
if ((PREFLIGHT_ONLY));then echo "panel $PANEL_VERSION preflight passed without changes";exit 0;fi
if ((NO_SERVICES==0)); then
  if ((FRESH)); then
    export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l
    apt-get update
    apt-get install -y --no-upgrade --no-install-recommends "${REQUIRED_PACKAGES[@]}"
  fi
  getent group panel >/dev/null || groupadd --system panel
  id panel >/dev/null 2>&1 || useradd --system --gid panel --home-dir /var/lib/panel --shell /usr/sbin/nologin panel
  id panel-build >/dev/null 2>&1 || useradd --system --home-dir /var/cache/panel-build --shell /usr/sbin/nologin panel-build
  id panel-import >/dev/null 2>&1 || useradd --system --user-group --home-dir /nonexistent --shell /usr/sbin/nologin panel-import
  id panel-task >/dev/null 2>&1 || useradd --system --user-group --home-dir /var/lib/panel-tasks --shell /usr/sbin/nologin panel-task
  id panel-redis >/dev/null 2>&1 || useradd --system --user-group --home-dir /srv/panel/redis --shell /usr/sbin/nologin --comment panel-redis panel-redis
	  id panel-mariadb >/dev/null 2>&1 || useradd --system --user-group --home-dir /srv/panel/mariadb --shell /usr/sbin/nologin --comment panel-mariadb panel-mariadb
fi
mkdir -p "$(dirname "$RELEASE_DIR")" "$(prefix /opt/panel/runtimes)" "$(prefix /opt/panel/php-extensions)" "$(prefix /etc/panel/sites-enabled)" "$(prefix /etc/panel/mysql)" "$(prefix /etc/panel/redis)" "$(prefix /etc/panel/mariadb)" "$(prefix /etc/panel/node)" "$(prefix /etc/panel/compose)" "$(prefix /var/lib/panel)" "$(prefix /var/lib/panel-executor)" "$(prefix /var/lib/panel-executor/admin-scripts)" "$(prefix /var/lib/panel-executor/sftp-jobs)" "$(prefix /var/lib/panel-executor/sftp-users)" "$(prefix /var/lib/panel-executor/docker-jobs)" "$(prefix /var/lib/panel-tasks/jobs)" "$(prefix /var/lib/panel-tasks/work)" "$(prefix /var/lib/panel-build-deps)" "$(prefix /var/backups/panel/system)" "$(prefix /var/backups/panel/mysql)" "$(prefix /var/backups/panel/mariadb)" "$(prefix /var/backups/panel/sites)" "$(prefix /srv/panel/sites)" "$(prefix /srv/panel/mysql)" "$(prefix /srv/panel/redis)" "$(prefix /srv/panel/mariadb)" "$(prefix /srv/panel/sftp)" "$(prefix /var/cache/panel-build)" "$(prefix /var/cache/panel-nginx)" "$(prefix /var/log/apache2)"
chmod 0700 "$(prefix /var/lib/panel-executor/admin-scripts)"
install -d -m 0750 "$(prefix /etc/panel/security-apps)" "$(prefix /etc/panel/waf)" "$(prefix /etc/panel/waf/http.d)" "$(prefix /etc/panel/waf/server.d)"
command -v flock >/dev/null || { echo 'flock is required for release updates' >&2; exit 1; }
if ((NO_SERVICES==0)); then
  python3 "$HERE/waf-state-directory.py" create --root "$TARGET_ROOT"
  python3 "$HERE/native-build-directories.py" create --root "$TARGET_ROOT"
fi
exec 9>"$(prefix /opt/panel/releases/.release.lock)"
flock -x 9
install -d -m 0700 "$(prefix /etc/panel/sites-archive)" "$(prefix /srv/panel/sites/.archives)"
chmod 0700 "$(prefix /var/backups/panel/system)"
for sub in client proxy fastcgi uwsgi scgi;do mkdir -p "$(prefix "/var/cache/panel-nginx/$sub")";done
if ((NO_SERVICES==0));then
  chown -R www-data:www-data /var/cache/panel-nginx
  chown -R panel-build:panel-build /var/cache/panel-build
  chmod 0755 /var/cache/panel-build
  dpkg-query -W -f='${binary:Package}\t${Version}\n' > /var/lib/panel-build-deps/debian-packages.tsv
  chown -R root:panel /var/lib/panel-executor
  chmod 0750 /var/lib/panel-executor
  chown root:root /var/lib/panel-executor/sftp-jobs /var/lib/panel-executor/sftp-users /srv/panel/sftp
  chmod 0700 /var/lib/panel-executor/sftp-jobs /var/lib/panel-executor/sftp-users
  chown root:root /var/lib/panel-executor/docker-jobs
  chmod 0700 /var/lib/panel-executor/docker-jobs
  chown root:root /etc/panel/compose
  chmod 0700 /etc/panel/compose
  chmod 0755 /srv/panel/sftp
  touch /var/lib/panel-executor/runtime-lifecycle.lock
  chown root:root /var/lib/panel-executor/runtime-lifecycle.lock
  chmod 0600 /var/lib/panel-executor/runtime-lifecycle.lock
  chown -R root:panel-task /var/lib/panel-tasks
  chown -R panel-task:panel-task /var/lib/panel-tasks/work
fi
PREVIOUS="";[[ -L "$CURRENT" ]]&&PREVIOUS="$(readlink "$CURRENT")"
OLD_MARKER="";[[ -f "$MARKER" ]]&&OLD_MARKER="$(cat "$MARKER")"
if [[ "$PREVIOUS" == "$RELEASE_DIR" ]];then
  if ((NO_SERVICES));then echo "panel $PANEL_VERSION is already staged";exit 0;fi
  curl -fsS --max-time 3 http://127.0.0.1:19100/api/ready >/dev/null || { echo 'same version is installed but unhealthy; use a newer repair release' >&2;exit 1; }
  echo "panel $PANEL_VERSION is already installed and healthy"
  exit 0
fi
ROLLBACK_DB=""
rm -rf "$RELEASE_DIR.tmp"
mkdir -p "$RELEASE_DIR.tmp"
cp -a "$HERE/bin" "$HERE/web" "$HERE/systemd" "$HERE/config" "$HERE/RELEASE" "$HERE/SHA256SUMS" "$HERE/prune-releases.sh" "$HERE/install.sh" "$HERE/verify-release.sh" "$HERE/first-install.py" "$HERE/waf-state-directory.py" "$HERE/native-build-directories.py" "$RELEASE_DIR.tmp/"
for metadata in SOURCE_INPUTS.json BUILD_CHECKS.txt; do
  [[ ! -f "$HERE/$metadata" ]] || cp -a "$HERE/$metadata" "$RELEASE_DIR.tmp/"
done
"$RELEASE_DIR.tmp/verify-release.sh" "$RELEASE_DIR.tmp"
# Copy/integrity failures must not stop the still healthy previous services.
if ((NO_SERVICES==0))&&[[ -f "$(prefix /var/lib/panel/panel.db)" ]];then
  ROLLBACK_DB="$(prefix "/var/backups/panel/system/pre-update-$PANEL_VERSION.db")"
  sqlite3 "$(prefix /var/lib/panel/panel.db)" ".backup '$ROLLBACK_DB'"
  chmod 0600 "$ROLLBACK_DB"
  systemctl stop panel panel-executor panel-terminal panel-terminal-root || true
fi
rm -rf "$RELEASE_DIR"
mv "$RELEASE_DIR.tmp" "$RELEASE_DIR"
ln -sfn "$RELEASE_DIR" "$CURRENT.new"
mv -Tf "$CURRENT.new" "$CURRENT"
printf 'version=%s\narch=%s\n' "$PANEL_VERSION" "$PANEL_ARCH" > "$MARKER"
if ((NO_SERVICES));then echo "isolated install ready: $CURRENT";exit 0;fi
chown -R panel:panel "$(prefix /var/lib/panel)"
chmod 0750 "$(prefix /var/lib/panel)"
# The WAF compiler has an independent root-managed cache. Do not grant its
# parent to panel-build or reuse the older runtime compiler cache as trust.
mkdir -p "$(prefix /opt/panel/app-modules)" "$(prefix /var/cache/panel-waf-build)" "$(prefix /var/cache/panel-waf-body)"
# Already checked/provisioned before the release symlink changed; never chmod
# or chown an existing foreign state directory during an update.
# Production units use the atomic current release symlink.
for unit in "$HERE/systemd/"*.service "$HERE/systemd/"*.timer;do
  name="$(basename "$unit")"
  sed 's#/opt/panel/bin/#/opt/panel/current/bin/#g;s#/opt/panel/web#/opt/panel/current/web#g;s/development //g' "$unit" > "/etc/systemd/system/$name"
done
if ((FRESH));then
  install -m 0644 "$HERE/config/nginx.conf" /etc/nginx/nginx.conf
  if [[ "$PANEL_PLATFORM" == ubuntu-22.04 ]]; then
    # Jammy's supported distribution Nginx is 1.18, predating
    # ssl_reject_handshake. Unknown SNI must never receive a site's certificate
    # or content: use a dedicated invalid self-signed certificate and close HTTP.
    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj /CN=default.invalid -addext subjectAltName=DNS:default.invalid -keyout /etc/panel/default-ssl.key -out /etc/panel/default-ssl.crt >/dev/null 2>&1
    chmod 0600 /etc/panel/default-ssl.key
    chmod 0644 /etc/panel/default-ssl.crt
    sed 's#ssl_reject_handshake on;#ssl_certificate /etc/panel/default-ssl.crt; ssl_certificate_key /etc/panel/default-ssl.key; return 444;#g' "$HERE/config/nginx.conf" > /etc/nginx/nginx.conf
  fi
  install -d -m 0755 /etc/systemd/system/nginx.service.d
  sed 's#/opt/panel/bin/#/opt/panel/current/bin/#g' "$HERE/config/nginx-panel.conf" > /etc/systemd/system/nginx.service.d/panel.conf
  chmod 0644 /etc/systemd/system/nginx.service.d/panel.conf
  install -m 0640 -o root -g panel /dev/null /etc/panel/panel-access.conf
  cat > /etc/panel/firewall.nft <<'EOF'
# managed by panel; revision=1; enabled=false
table inet panel {
  chain input {
    type filter hook input priority filter; policy accept;
    iifname "lo" accept comment "panel rescue loopback"
    ct state established,related accept comment "panel established traffic"
    meta l4proto { icmp, ipv6-icmp } accept comment "panel network control"
    tcp dport { 22, 80, 443, 19443 } accept comment "panel fixed access ports"
  }
}
EOF
  chmod 0640 /etc/panel/firewall.nft
  # Capture sshd's complete output before parsing it.  With pipefail enabled,
  # exiting awk early can SIGPIPE sshd and abort a fresh install halfway through.
  SSHD_EFFECTIVE_CONFIG="$(/usr/sbin/sshd -T 2>/dev/null)"
  SSH_LISTEN_PORT="$(awk '$1=="port" {print $2; exit}' <<< "$SSHD_EFFECTIVE_CONFIG")"
  [[ "$SSH_LISTEN_PORT" =~ ^[0-9]{1,5}$ ]] || SSH_LISTEN_PORT=22
  install -d -m 0755 /etc/fail2ban/jail.d
  printf '[sshd]\nbackend = systemd\nport = %s\n' "$SSH_LISTEN_PORT" > /etc/fail2ban/jail.d/panel-sshd.local
  chmod 0644 /etc/fail2ban/jail.d/panel-sshd.local
fi
systemctl daemon-reload
FAILED=0
systemctl enable nginx panel-terminal panel-terminal-root panel-executor panel panel-nginx-recovery panel-firewall-recovery panel-firewall
if systemctl cat docker.service >/dev/null 2>&1; then
  systemctl enable panel-compose-recovery
else
  systemctl disable panel-compose-recovery >/dev/null 2>&1 || true
fi
systemctl enable --now panel-mysql-overwrite-recovery.timer || FAILED=1
install -d -m 0755 /run/panel-nginx
/usr/sbin/nginx -t || FAILED=1
systemctl restart panel-nginx-recovery panel-firewall-recovery panel-firewall || FAILED=1
if systemctl cat docker.service >/dev/null 2>&1; then
  systemctl restart panel-compose-recovery || FAILED=1
fi
systemctl restart panel-terminal panel-terminal-root panel-executor panel nginx || FAILED=1
if ((FRESH));then systemctl enable --now fail2ban || FAILED=1;fi
for _ in {1..30};do curl -fsS --max-time 2 http://127.0.0.1:19100/api/ready >/dev/null 2>&1&&break;sleep 1;done
curl -fsS --max-time 3 http://127.0.0.1:19100/api/ready >/dev/null||FAILED=1
if ((FRESH))&&((FAILED==0));then
  python3 "$HERE/first-install.py" || FAILED=1
fi
if ((FAILED));then
  systemctl stop panel panel-executor panel-terminal panel-terminal-root || true
  if [[ -n "$PREVIOUS" ]];then ln -sfn "$PREVIOUS" "$CURRENT.new";mv -Tf "$CURRENT.new" "$CURRENT";fi
  if [[ -n "$OLD_MARKER" ]];then printf '%s\n' "$OLD_MARKER" > "$MARKER";else rm -f "$MARKER";fi
  if [[ -n "$ROLLBACK_DB" ]];then rm -f /var/lib/panel/panel.db-wal /var/lib/panel/panel.db-shm;install -m 0600 -o panel -g panel "$ROLLBACK_DB" /var/lib/panel/panel.db;fi
  if [[ -n "$PREVIOUS" ]];then systemctl restart panel-terminal panel-terminal-root panel-executor panel nginx || true;else rm -f "$CURRENT";systemctl stop panel panel-executor panel-terminal panel-terminal-root nginx || true;fi
  echo 'install/update health check failed; previous release restored' >&2
  exit 1
fi
echo "panel $PANEL_VERSION installed successfully"
if ((FRESH));then
  echo 'First-login details (root only): sudo cat /etc/panel/first-login.json'
  if [[ -t 1 ]];then
    python3 - <<'PY'
import json
from pathlib import Path

record = json.loads(Path('/etc/panel/first-login.json').read_text())
entry = record['entry']
print(f'Local panel: http://127.0.0.1:19100/{entry}/')
print('Remote access: forward 127.0.0.1:19110 to server 127.0.0.1:19100 over SSH, then open')
print(f'  http://127.0.0.1:19110/{entry}/')
print('For direct IP:port access, enable the public HTTP entry in Panel Settings after login.')
PY
    printf 'SSH tunnel command: ssh -p %s -N -L 127.0.0.1:19110:127.0.0.1:19100 SSH_USER@SERVER_IP\n' "$SSH_LISTEN_PORT"
  fi
fi
