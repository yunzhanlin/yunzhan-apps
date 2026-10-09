#!/usr/bin/env bash
# Upgrade only the original /opt/panel/bin development layout, preserving host
# ingress, firewall, credentials, sites and runtimes. Production uses install.sh.
set -euo pipefail
umask 022
RELEASE_PATH="${1:?usage: upgrade-running-development.sh VERIFIED_RELEASE_DIRECTORY}"
[[ $(id -u) == 0 ]] || { echo 'run this migration as root' >&2; exit 1; }
"$RELEASE_PATH/verify-release.sh" "$RELEASE_PATH" >/dev/null
python3 "$RELEASE_PATH/waf-state-directory.py" check
python3 "$RELEASE_PATH/native-build-directories.py" check
source "$RELEASE_PATH/RELEASE"
[[ $(dpkg --print-architecture) == "$PANEL_ARCH" ]] || { echo 'architecture mismatch' >&2; exit 1; }
[[ ! -e /etc/panel-release && ! -e /opt/panel/current && ! -L /opt/panel/current ]] || { echo 'use the production installer for this layout' >&2; exit 1; }
[[ -f /opt/panel/bin/panel && -f /opt/panel/bin/panel-executor && -d /opt/panel/web && ! -L /opt/panel/web ]] || { echo 'not the original development layout' >&2; exit 1; }
[[ $(systemctl show panel -p User --value) == panel ]] || { echo 'unexpected panel service owner' >&2; exit 1; }
systemctl is-active --quiet panel panel-executor
[[ $(sqlite3 /var/lib/panel/panel.db 'PRAGMA integrity_check;') == ok ]] || { echo 'database integrity check failed' >&2; exit 1; }
[[ $(sqlite3 /var/lib/panel/panel.db 'SELECT count(*) FROM jobs WHERE state IN ("queued","running");') == 0 ]] || { echo 'wait for active panel jobs before updating' >&2; exit 1; }
nginx -t
exec 9>/opt/panel/.development-update.lock
flock -n 9 || { echo 'another development update is running' >&2; exit 1; }
BACKUP="/var/backups/panel/system/development-$PANEL_VERSION"
[[ ! -e "$BACKUP" ]] || { echo 'backup already exists; select a new release' >&2; exit 1; }
install -d -m 0700 "$BACKUP" "$BACKUP/units"
cp -a /opt/panel/bin "$BACKUP/bin"
cp -a /opt/panel/web "$BACKUP/web"
[[ ! -f /opt/panel/DEVELOPMENT_RELEASE ]] || cp -a /opt/panel/DEVELOPMENT_RELEASE "$BACKUP/DEVELOPMENT_RELEASE"
for unit in "$RELEASE_PATH/systemd/"*.service "$RELEASE_PATH/systemd/"*.timer; do
  name=$(basename "$unit")
  [[ ! -f "/etc/systemd/system/$name" ]] || cp -a "/etc/systemd/system/$name" "$BACKUP/units/"
done
CHANGED=0
rollback() {
  result=$?
  if ((result != 0 && CHANGED)); then
    systemctl stop panel panel-executor || true
    cp -a "$BACKUP/bin/." /opt/panel/bin/
    # Keep the failed frontend as evidence; never delete existing user files.
    mv /opt/panel/web "$BACKUP/failed-web"
    cp -a "$BACKUP/web" /opt/panel/web
    for unit in "$RELEASE_PATH/systemd/"*.service "$RELEASE_PATH/systemd/"*.timer; do
      name=$(basename "$unit")
      if [[ -f "$BACKUP/units/$name" ]]; then cp -a "$BACKUP/units/$name" "/etc/systemd/system/$name";
      else rm -f "/etc/systemd/system/$name"; fi
    done
    # Database migrations are rolled back only while both writers are stopped.
    rm -f /var/lib/panel/panel.db-wal /var/lib/panel/panel.db-shm
    install -m 0600 -o panel -g panel "$BACKUP/panel.db" /var/lib/panel/panel.db
    systemctl daemon-reload
    systemctl restart panel-executor panel || true
    echo "update failed; development program and database restored from $BACKUP" >&2
  fi
  return "$result"
}
trap rollback EXIT
python3 "$RELEASE_PATH/waf-state-directory.py" create
python3 "$RELEASE_PATH/native-build-directories.py" create
install -d -m 0755 /opt/panel/php-extensions /etc/panel/mysql /etc/panel/redis /etc/panel/mariadb /etc/panel/node /var/log/apache2 /srv/panel/mysql /srv/panel/redis /srv/panel/mariadb /srv/panel/sftp
install -d -m 0700 /etc/panel/compose /var/lib/panel-executor/docker-jobs /var/lib/panel-executor/admin-scripts /var/lib/panel-executor/sftp-jobs /var/lib/panel-executor/sftp-users
install -d -m 0750 /etc/panel/security-apps /etc/panel/waf /etc/panel/waf/http.d /etc/panel/waf/server.d
install -d -m 0755 /var/cache/panel-waf-build
install -d -m 0750 /var/cache/panel-waf-body
install -d -m 0750 /var/backups/panel/mysql /var/backups/panel/mariadb /var/backups/panel/sites
id panel-mariadb >/dev/null 2>&1 || useradd --system --user-group --home-dir /srv/panel/mariadb --shell /usr/sbin/nologin --comment panel-mariadb panel-mariadb
systemctl stop panel panel-executor
sqlite3 /var/lib/panel/panel.db ".backup '$BACKUP/panel.db'"
chmod 0600 "$BACKUP/panel.db"
CHANGED=1
for name in panel panel-executor; do
  install -m 0755 "$RELEASE_PATH/bin/$name" "/opt/panel/bin/$name.new"
  mv -f "/opt/panel/bin/$name.new" "/opt/panel/bin/$name"
done
install -d -m 0755 /opt/panel/web.new
cp -a "$RELEASE_PATH/web/." /opt/panel/web.new/
mv /opt/panel/web "$BACKUP/previous-web"
mv /opt/panel/web.new /opt/panel/web
for unit in "$RELEASE_PATH/systemd/"*.service "$RELEASE_PATH/systemd/"*.timer; do
  install -m 0644 "$unit" "/etc/systemd/system/$(basename "$unit")"
done
systemctl daemon-reload
systemctl restart panel-executor panel
for _ in {1..30}; do
  if curl -fsS --max-time 2 http://127.0.0.1:19100/api/ready >/dev/null 2>&1; then break; fi
  sleep 1
done
curl -fsS --max-time 3 http://127.0.0.1:19100/api/ready >/dev/null
[[ $(curl -s -o /dev/null -w '%{http_code}' --max-time 3 http://127.0.0.1:19100/api/app-registry) == 401 ]] || { echo 'application registry route is missing' >&2; exit 1; }
[[ $(sqlite3 /var/lib/panel/panel.db 'PRAGMA integrity_check;') == ok ]] || { echo 'post-update database check failed' >&2; exit 1; }
nginx -t
install -m 0644 "$RELEASE_PATH/RELEASE" /opt/panel/DEVELOPMENT_RELEASE
CHANGED=0
echo "development panel upgraded to $PANEL_VERSION; rollback backup: $BACKUP"
