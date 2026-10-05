#!/usr/bin/env bash
set -euo pipefail
[[ "$(id -u)" == 0 && -f /etc/panel-development-vm && -x /workspace/.build/pebble ]]
if ss -ltn | awk '{print $4}' | grep -Eq ':(14000|15000)$' && ! systemctl is-active --quiet panel-pebble; then
  echo 'ACME test ports are already occupied' >&2; exit 1
fi
id panel-pebble >/dev/null 2>&1 || useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin panel-pebble
install -d -m 0755 /opt/panel/test-tools /etc/panel/acme
install -d -m 0750 -o root -g panel-pebble /etc/panel/acme-test
install -m 0755 /workspace/.build/pebble /opt/panel/test-tools/pebble
install -m 0755 /workspace/.build/pebble-challtestsrv /opt/panel/test-tools/pebble-challtestsrv
install -m 0644 /workspace/.local/pebble-tls/ca.pem /etc/panel/acme/pebble-ca.pem
install -m 0640 -o root -g panel-pebble /workspace/.local/pebble-tls/first.pem /etc/panel/acme-test/server.pem
install -m 0640 -o root -g panel-pebble /workspace/.local/pebble-tls/first.key /etc/panel/acme-test/server.key
python3 - <<'PY'
import json,pathlib
config={'pebble':{'listenAddress':'127.0.0.1:14000','managementListenAddress':'127.0.0.1:15000','certificate':'/etc/panel/acme-test/server.pem','privateKey':'/etc/panel/acme-test/server.key','httpPort':19101,'tlsPort':19102,'externalAccountBindingRequired':False,'domainBlocklist':['blocked-domain.example'],'retryAfter':{'authz':1,'order':1},'keyAlgorithm':'ecdsa','profiles':{'default':{'description':'Local seven-day acceptance certificates','validityPeriod':604800}}}}
p=pathlib.Path('/etc/panel/acme-test/pebble.json');p.write_text(json.dumps(config));p.chmod(0o644)
PY
install -m 0644 /workspace/dev/panel-pebble.service /etc/systemd/system/panel-pebble.service
install -m 0644 /workspace/dev/panel-pebble-dns.service /etc/systemd/system/panel-pebble-dns.service
systemctl daemon-reload
systemctl enable --now panel-pebble-dns
systemctl reset-failed panel-pebble 2>/dev/null || true
systemctl enable panel-pebble
systemctl restart panel-pebble
curl --retry 10 --retry-connrefused --retry-delay 1 --fail --silent --show-error --cacert /etc/panel/acme/pebble-ca.pem https://localhost:14000/dir >/dev/null
printf 'Local Pebble directory passed CA-verified HTTPS; real HTTP-01 uses Nginx port 19101\n'
