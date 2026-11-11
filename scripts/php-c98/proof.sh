#!/bin/bash
set -euo pipefail
test "$GITHUB_ACTIONS" = true
test "$GITHUB_REPOSITORY" = yunzhanlin/yunzhan-apps
case "$(uname -m)" in
    x86_64) arch=amd64 ;;
    aarch64) arch=arm64 ;;
    *) exit 1 ;;
esac
out="$RUNNER_TEMP/c98-php-proof"
mkdir -m 0700 "$out"
slot="$1"
version="$2"
case "$slot:$version" in
    54:5.4.45|55:5.5.38|56:5.6.40) ;;
    *) exit 1 ;;
esac
src="scripts/php-c98/$slot"
image="local/c98-php$slot:verified"
if [[ ${C98_VERIFY_EXISTING_IMAGE:-0} == 1 ]]; then
    test "$(cat /etc/hostname)" = lima-panel-openlitespeed-c92r2-arm64-qa
    image="local/c98-php$slot:qa-r4"
else
    if [[ $slot == 56 ]]; then
        docker build --pull --platform "linux/$arch" -t "$image" "$src"
    else
        source_sha="$(python3 -I -B -c 'import json,sys; print(json.load(open(sys.argv[1]))["source_sha256"])' "$src/php-build-pins.json")"
        [[ $source_sha =~ ^[a-f0-9]{64}$ ]]
        docker build --pull --platform "linux/$arch" --build-arg "PHP_VERSION=$version" \
            --build-arg "PHP_SOURCE_SHA256=$source_sha" -t "$image" "$src"
    fi
fi
test "$(docker image inspect --format '{{.Os}}/{{.Architecture}}' "$image")" = "linux/$arch"
docker network create c98-php-private >/dev/null
docker volume create c98-php-site >/dev/null
docker run -d --name c98-php --network c98-php-private \
    --mount type=volume,src=c98-php-site,dst=/var/www/html \
    "$image" php-fpm -F >/dev/null
docker exec -i c98-php /bin/sh -c 'umask 022; cat > /var/www/html/index.php' <<'PHP'
<?php
header("Content-Type: application/json");
echo json_encode([
    "version" => PHP_VERSION,
    "sapi" => PHP_SAPI,
    "modules" => extension_loaded("mysql") && extension_loaded("mysqli") && extension_loaded("pdo_mysql"),
    "posted" => isset($_POST["name"]) ? $_POST["name"] : "",
    "upload_sha256" => isset($_FILES["upload"]) ? hash_file("sha256", $_FILES["upload"]["tmp_name"]) : "",
]);
PHP
cat > "$out/nginx.conf" <<'NGINX'
events {}
http {
    server {
        listen 8080;
        location = / {
            include /etc/nginx/fastcgi_params;
            fastcgi_param SCRIPT_FILENAME /var/www/html/index.php;
            fastcgi_pass c98-php:9000;
        }
    }
}
NGINX
docker run -d --name c98-php-web --network c98-php-private \
    --publish 127.0.0.1::8080 \
    --mount "type=bind,src=$out/nginx.conf,dst=/etc/nginx/nginx.conf,readonly" \
    nginx:1.30.6-alpine@sha256:970364228b1e4f932abc22d321932816782cca8a20b85a77552a7cfe9acfb3b5 >/dev/null
binding="$(docker port c98-php-web 8080/tcp)"
[[ $binding =~ ^127\.0\.0\.1:[0-9]+$ ]]
uri="http://$binding/"
curl --silent --show-error --fail --retry 8 --retry-all-errors --retry-delay 1 --max-time 12 "$uri" > "$out/original-get.json"
printf 'independent legacy PHP FastCGI upload fixture\n' > "$out/upload.txt"
curl --silent --show-error --fail --max-time 12 -F name=native -F "upload=@$out/upload.txt" "$uri" > "$out/original-post.json"
docker restart c98-php >/dev/null
curl --silent --show-error --fail --retry 8 --retry-all-errors --retry-delay 1 --max-time 12 "$uri" > "$out/original-restart.json"
python3 -I -B - "$out" "$arch" "$version" <<'PY'
import hashlib, json, pathlib, sys
root, arch, version = pathlib.Path(sys.argv[1]), sys.argv[2], sys.argv[3]
baseline = {"version":version,"sapi":"fpm-fcgi","modules":True,"posted":"","upload_sha256":""}
assert json.loads((root / "original-get.json").read_bytes()) == baseline
assert json.loads((root / "original-restart.json").read_bytes()) == baseline
upload = hashlib.sha256((root / "upload.txt").read_bytes()).hexdigest()
assert json.loads((root / "original-post.json").read_bytes()) == dict(baseline, posted="native", upload_sha256=upload)
(root / "original-proof.json").write_text(json.dumps({
    "ok":True,"architecture":arch,"php":version,"php_fpm_http":True,"multipart_upload":True,
    "restart_data_preserved":True,"legacy_and_current_mysql_drivers_loaded":True,"Main_changed":False
}, indent=2) + "\n")
PY
