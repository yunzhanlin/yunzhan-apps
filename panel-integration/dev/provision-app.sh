#!/usr/bin/env bash
set -euo pipefail
if [[ "$(id -u)" != 0 || ! -f /workspace/.build/panel || ! -d /workspace/web/dist ]]; then
  echo 'Run this deployment script as root inside the dedicated panel VM, after building.' >&2
  exit 1
fi
PANEL_NATIVE_BUILD_PREPARER="$(cd "$(dirname "${BASH_SOURCE[0]}")/../packaging" && pwd)/native-build-directories.py"
python3 "$PANEL_NATIVE_BUILD_PREPARER" check
if [[ ! -f /etc/panel-development-vm ]]; then
  if [[ "$(hostname)" != lima-panel-dev ]]; then echo 'Unexpected VM hostname; refusing to manage services.' >&2; exit 1; fi
  touch /etc/panel-development-vm
fi
python3 /workspace/scripts/check-ingress-ports.py
if [[ ! -f /var/lib/panel-build-deps/debian-packages.tsv || ! -x /usr/bin/autoconf ]]; then /bin/bash /workspace/dev/provision-build-deps.sh; fi
if [[ ! -x /usr/sbin/nft || ! -x /usr/bin/setfacl || ! -x /usr/sbin/sshd ]]; then apt-get update; DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends nftables openssh-server acl; fi
id panel-import >/dev/null 2>&1 || useradd --system --user-group --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin --comment panel-sql-import panel-import
id panel-build >/dev/null 2>&1 || useradd --system --home-dir /var/cache/panel-build --shell /usr/sbin/nologin panel-build
id panel-task >/dev/null 2>&1 || useradd --system --user-group --home-dir /var/lib/panel-tasks --shell /usr/sbin/nologin --comment panel-scheduled-task panel-task
id panel-redis >/dev/null 2>&1 || useradd --system --user-group --home-dir /srv/panel/redis --shell /usr/sbin/nologin --comment panel-redis panel-redis
install -d -m 0755 /var/cache/panel-build /opt/panel/runtimes /opt/panel/php-extensions
install -d -m 0755 /srv/panel/mysql /etc/panel/mysql
# systemd requires every path named by panel-executor.service ReadWritePaths
# to exist, including paths for optional runtimes which are not installed yet.
install -d -m 0755 /etc/fail2ban /etc/apache2 /srv/panel/mariadb /var/log/apache2
install -d -m 0755 /srv/panel/redis /etc/panel/redis
install -d -m 0755 /etc/panel/node
install -d -m 0700 /var/backups/panel/mysql
install -d -m 0700 /var/backups/panel/mariadb
install -d -m 0700 /var/backups/panel/sites
install -d -m 0700 /var/backups/panel/system
install -d -m 0750 -o root -g panel-task /var/lib/panel-tasks /var/lib/panel-tasks/jobs
install -d -m 0750 -o panel-task -g panel-task /var/lib/panel-tasks/work
install -d -m 0755 /opt/panel/app-modules /var/cache/panel-waf-build /var/cache/panel-waf-body
install -d -m 0750 -o root -g www-data /var/lib/panel-waf
python3 "$PANEL_NATIVE_BUILD_PREPARER" create
for unit in panel-install@ panel-docker-install@ panel-docker-job@ panel-compose-job@ panel-site-user@ panel-php@ panel-mysql@ panel-mysql-user@ panel-mysql-job@ panel-sftp-job@ panel-redis@ panel-node@ panel-pm2@ panel-pm2-deploy@ panel-app-dependencies@ panel-waf-engine-build@ panel-analytics-html-build@ panel-network-rulefeed-install@ panel-pure-ftpd panel-pure-ftpd-recover panel-nfs@ panel-nfs-server panel-nfs-server-recover; do
 install -m 0644 /workspace/dev/$unit.service /etc/systemd/system/$unit.service
done
systemctl stop panel.service panel-executor.service 2>/dev/null || true
install -d -m 0755 /opt/panel/bin /opt/panel/web /etc/panel/sites-enabled /srv/panel/sites
install -d -m 0700 /etc/panel/sites-archive /srv/panel/sites/.archives
if [[ ! -f /etc/panel/panel-access.conf ]]; then install -m 0640 -o root -g panel /dev/null /etc/panel/panel-access.conf; fi
if [[ ! -f /etc/panel/firewall.nft ]]; then
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
fi
chown root:root /etc/panel/firewall.nft
chmod 0640 /etc/panel/firewall.nft
install -d -m 0750 -o root -g panel /var/lib/panel-executor
install -d -m 0700 -o root -g root /var/lib/panel-executor/admin-scripts
install -d -m 0700 -o root -g root /var/lib/panel-executor/sftp-jobs /var/lib/panel-executor/sftp-users
install -d -m 0700 -o root -g root /var/lib/panel-executor/docker-jobs
install -d -m 0700 -o root -g root /etc/panel/compose
install -d -m 0755 -o root -g root /srv/panel/sftp
touch /var/lib/panel-executor/runtime-lifecycle.lock
chown root:root /var/lib/panel-executor/runtime-lifecycle.lock
chmod 0600 /var/lib/panel-executor/runtime-lifecycle.lock
install -d -m 0750 -o panel -g panel /var/lib/panel
install -m 0755 /workspace/.build/panel /opt/panel/bin/panel
install -m 0755 /workspace/.build/panel-executor /opt/panel/bin/panel-executor
# All assets are built output in this dedicated VM. Old hash assets are retained
# until the next development rebuild cleanup to avoid interrupting open clients.
cp -R /workspace/web/dist/. /opt/panel/web/
if [[ ! -f /etc/nginx/nginx.conf.before-panel ]]; then cp -p /etc/nginx/nginx.conf /etc/nginx/nginx.conf.before-panel; fi
if [[ "$(systemctl show -p PIDFile --value nginx)" == /run/nginx.pid ]]; then systemctl stop nginx; fi
install -d -m 0755 /run/panel-nginx
install -d -m 0755 /var/cache/panel-nginx
for sub in client proxy fastcgi uwsgi scgi; do install -d -m 0700 -o www-data -g www-data /var/cache/panel-nginx/$sub; done
install -m 0644 /workspace/dev/nginx.conf /etc/nginx/nginx.conf
/usr/sbin/nginx -t
install -m 0644 /workspace/dev/panel.service /etc/systemd/system/panel.service
install -m 0644 /workspace/dev/panel-executor.service /etc/systemd/system/panel-executor.service
for unit in panel-terminal.service panel-terminal-root.service; do install -m 0644 /workspace/dev/$unit /etc/systemd/system/$unit; done
install -d -m 0755 /etc/systemd/system/nginx.service.d /var/cache/panel-nginx
for sub in client proxy fastcgi uwsgi scgi; do install -d -m 0700 -o www-data -g www-data /var/cache/panel-nginx/$sub; done
install -m 0644 /workspace/dev/nginx-panel.conf /etc/systemd/system/nginx.service.d/panel.conf
for unit in panel-nginx-recovery.service panel-nginx-rollback@.service panel-nginx-rollback@.timer; do install -m 0644 /workspace/dev/$unit /etc/systemd/system/$unit; done
for unit in panel-firewall.service panel-firewall-recovery.service panel-firewall-rollback@.service panel-firewall-rollback@.timer; do install -m 0644 /workspace/dev/$unit /etc/systemd/system/$unit; done
for unit in panel-mysql-overwrite-recovery.service panel-mysql-overwrite-recovery.timer; do install -m 0644 /workspace/dev/$unit /etc/systemd/system/$unit; done
install -m 0644 /workspace/dev/panel-compose-recovery.service /etc/systemd/system/panel-compose-recovery.service
systemctl daemon-reload
systemctl enable --now panel-mysql-overwrite-recovery.timer
if systemctl cat docker.service >/dev/null 2>&1; then
  systemctl enable panel-compose-recovery
  systemctl restart panel-compose-recovery
else
  # Docker is an optional panel runtime. A PHP/MySQL-only VM must still deploy
  # and recover the panel successfully when docker.service is absent.
  systemctl disable --now panel-compose-recovery 2>/dev/null || true
fi
systemctl enable --now panel-nginx-recovery
systemctl enable panel-firewall-recovery panel-firewall
systemctl restart panel-firewall-recovery
systemctl restart panel-firewall
systemctl enable nginx panel-terminal panel-terminal-root panel-executor panel
systemctl restart panel-terminal panel-terminal-root
systemctl restart nginx panel-executor panel
for _ in {1..20}; do
  if systemctl is-active --quiet nginx panel-executor panel && curl --silent --fail --max-time 3 http://127.0.0.1:19100/api/ready; then printf '\n'; exit 0; fi
  sleep 1
done
journalctl -u panel -u panel-executor -n 30 --no-pager
exit 1
