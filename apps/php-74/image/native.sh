#!/usr/bin/env bash
set -euo pipefail

cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
case "$(uname -m)" in
  x86_64) architecture=amd64 ;;
  aarch64) architecture=arm64 ;;
  *) exit 1 ;;
esac
out="$1"
mkdir -m 700 "$out"
docker build --pull --platform "linux/$architecture" --iidfile "$out/image-id" -t panel-php7433-native:qa .
test "$(docker image inspect -f '{{.Os}}/{{.Architecture}}' panel-php7433-native:qa)" = "linux/$architecture"
docker run --rm --network none panel-php7433-native:qa php -v > "$out/php-version.txt"
docker run --rm --network none panel-php7433-native:qa php -m > "$out/php-modules.txt"
grep -Fqx 'mysqli' "$out/php-modules.txt"
grep -Fqx 'pdo_mysql' "$out/php-modules.txt"

cat > "$out/compose.yaml" <<'YAML'
services:
  php:
    image: panel-php7433-native:qa
    entrypoint: ["/bin/sh", "-ec"]
    command:
      - |
        mkdir /tmp/cloudstack-ini
        cp /usr/local/etc/php/conf.d/*.ini /tmp/cloudstack-ini/
        printf '%s\n' 'expose_php=Off' 'allow_url_include=Off' 'disable_functions=exec,passthru,shell_exec,system,proc_open,popen' 'memory_limit=128M' 'max_execution_time=30' > /tmp/cloudstack-ini/zz-cloudstack.ini
        if [ ! -e /var/www/html/index.php ]; then
          cat > /var/www/html/index.php <<'PHP'
        <?php
        header("Content-Type: application/json");
        echo json_encode([
          "version" => PHP_VERSION, "sapi" => PHP_SAPI, "mysqli" => extension_loaded("mysqli"),
          "pdo_mysql" => in_array("mysql", PDO::getAvailableDrivers(), true),
          "shell_exec" => function_exists("shell_exec"), "integer" => bcadd("123456789", "10"),
          "persisted" => is_file(__DIR__ . "/retained.txt") ? file_get_contents(__DIR__ . "/retained.txt") : null
        ]);
        PHP
          chown 1000:1000 /var/www/html /var/www/html/index.php
          chmod 755 /var/www/html
          chmod 644 /var/www/html/index.php
        fi
        exec /usr/local/sbin/php-fpm
    environment:
      PHP_INI_SCAN_DIR: /tmp/cloudstack-ini
    read_only: true
    tmpfs: [/tmp, /var/run]
    security_opt: [no-new-privileges:true]
    mem_limit: 256m
    pids_limit: 96
    volumes: [site-data:/var/www/html]
    healthcheck:
      test: ["CMD-SHELL", "php -r '$$s=@fsockopen(\"127.0.0.1\",9000);exit($$s?0:1);'"]
      interval: 2s
      timeout: 3s
      retries: 15
  web:
    image: nginx:1.30.6-alpine@sha256:970364228b1e4f932abc22d321932816782cca8a20b85a77552a7cfe9acfb3b5
    user: "101:101"
    networks: [default, edge]
    entrypoint: ["/bin/sh", "-ec"]
    command:
      - |
        cat > /tmp/cloudstack-nginx.conf <<'CONF'
        pid /tmp/nginx.pid;
        error_log /dev/stderr warn;
        events { worker_connections 256; }
        http {
          client_body_temp_path /tmp/client;
          fastcgi_temp_path /tmp/fastcgi;
          proxy_temp_path /tmp/proxy;
          uwsgi_temp_path /tmp/uwsgi;
          scgi_temp_path /tmp/scgi;
          server {
            listen 8080;
            root /var/www/html;
            location ~ /\. { deny all; }
            location = / { include /etc/nginx/fastcgi_params; fastcgi_pass php:9000; fastcgi_param SCRIPT_FILENAME /var/www/html/index.php; }
          }
        }
        CONF
        exec nginx -c /tmp/cloudstack-nginx.conf -g 'daemon off;'
    read_only: true
    tmpfs: [/tmp]
    cap_drop: [ALL]
    security_opt: [no-new-privileges:true]
    depends_on:
      php:
        condition: service_healthy
    ports: ["127.0.0.1:26779:8080"]
    volumes: [site-data:/var/www/html:ro]
volumes:
  site-data: {}
networks:
  default:
    internal: true
  edge: {}
YAML
compose=(docker compose --project-name panel-c83-php74-fixture -f "$out/compose.yaml")
collect() {
  "${compose[@]}" ps -a > "$out/compose-ps.txt" || true
  "${compose[@]}" logs --no-color > "$out/compose-logs.txt" || true
}
trap collect EXIT
"${compose[@]}" up -d --wait --wait-timeout 120
origin=http://127.0.0.1:26779
curl --noproxy '*' --fail --silent --show-error --max-time 15 "$origin/" -o "$out/before.json"
php_id="$("${compose[@]}" ps -q php)"
web_id="$("${compose[@]}" ps -q web)"
docker inspect "$php_id" "$web_id" > "$out/containers.json"
"${compose[@]}" exec -T php sh -ec 'printf kept > /var/www/html/retained.txt; printf private > /var/www/html/.private.php'
test "$(curl --noproxy '*' --silent --show-error --max-time 15 --output /dev/null --write-out '%{http_code}' "$origin/.private.php")" = 403
"${compose[@]}" stop
"${compose[@]}" up -d --no-recreate --wait --wait-timeout 120
curl --noproxy '*' --fail --silent --show-error --max-time 15 "$origin/" -o "$out/after.json"
test "$("${compose[@]}" ps -q php)" = "$php_id"

python3 -I -B - "$out" "$architecture" <<'PY'
import json
from pathlib import Path
import sys

out, arch = Path(sys.argv[1]), sys.argv[2]
def read(name):
    return json.loads((out / name).read_bytes())

before = read('before.json')
after = read('after.json')
assert before == {'version': '7.4.33', 'sapi': 'fpm-fcgi', 'mysqli': True, 'pdo_mysql': True,
                  'shell_exec': False, 'integer': '123456799', 'persisted': None}
assert after == {**before, 'persisted': 'kept'}
php, web = read('containers.json')
assert php['HostConfig']['ReadonlyRootfs'] and web['HostConfig']['ReadonlyRootfs']
assert not php['HostConfig']['PortBindings']
assert web['HostConfig']['PortBindings'] == {'8080/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '26779'}]}
assert all('no-new-privileges:true' in c['HostConfig']['SecurityOpt'] for c in (php, web))
assert web['HostConfig']['CapDrop'] == ['ALL']
php_mount, = [v for v in php['Mounts'] if v['Destination'] == '/var/www/html']
web_mount, = [v for v in web['Mounts'] if v['Destination'] == '/var/www/html']
assert php_mount['Type'] == web_mount['Type'] == 'volume' and php_mount['Name'] == web_mount['Name']
assert php_mount['RW'] and not web_mount['RW']
assert len(php['NetworkSettings']['Networks']) == 1 and len(web['NetworkSettings']['Networks']) == 2
proof = {'ok': True, 'architecture': arch, 'version': before['version'], 'real_fpm_http': True,
         'mysqli_and_pdo_mysql': True, 'hidden_path_http403': True, 'persistent_named_volume': True,
         'app_store_install_completed': False}
(out / 'original-proof.json').write_text(json.dumps(proof) + '\n')
print(json.dumps(proof))
PY
