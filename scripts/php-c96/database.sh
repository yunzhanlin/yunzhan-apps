#!/bin/bash
set -euo pipefail
test "$GITHUB_ACTIONS" = true
test "$GITHUB_REPOSITORY" = yunzhanlin/yunzhan-apps
umask 077
out="$RUNNER_TEMP/c96-php-proof"
version="$1"
case "$version" in 7.0.33|7.1.33|7.2.34|7.3.33) ;; *) exit 1 ;; esac
db_env="$(mktemp "$RUNNER_TEMP/c96-mariadb-env.XXXXXXXX")"
trap 'rm -f -- "$db_env"' EXIT
db_secret="$(openssl rand -hex 24)"
{
    printf 'MARIADB_ROOT_PASSWORD=%s\n' "$(openssl rand -hex 24)"
    printf 'MARIADB_DATABASE=panelqa\nMARIADB_USER=panelqa\nMARIADB_PASSWORD=%s\n' "$db_secret"
} > "$db_env"
docker run --detach --name c96-mariadb --network c96-php-private --network-alias db --env-file "$db_env" \
    mariadb:11.8.9@sha256:c4124d1afa875e47f2892edf26b482fa54f796e2f342d3717a04ca091a22a9bd >/dev/null
ready=0
for _ in $(seq 1 50); do
    if docker exec c96-mariadb healthcheck.sh --connect --innodb_initialized >/dev/null 2>&1; then
        ready=1
        break
    fi
    sleep 2
done
test "$ready" = 1
docker exec -i c96-php /bin/sh -c 'umask 077; cat > /tmp/c96-password' <<< "$db_secret"
docker exec -i c96-php /bin/sh -c 'umask 077; cat > /tmp/c96-database.php' <<'PHP'
<?php
$password = trim(file_get_contents('/tmp/c96-password'));
$pdo = new PDO('mysql:host=db;dbname=panelqa', 'panelqa', $password, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
$pdo->exec('CREATE TABLE state (id INTEGER PRIMARY KEY, value VARCHAR(40) NOT NULL)');
$pdo->exec("INSERT INTO state VALUES (7, 'pdo-written')");
$mysqli = new mysqli('db', 'panelqa', $password, 'panelqa');
if ($mysqli->query('SELECT value FROM state WHERE id=7')->fetch_row()[0] !== 'pdo-written') exit(1);
if (!$mysqli->query("UPDATE state SET value='mysqli-updated' WHERE id=7")) exit(1);
if ($pdo->query('SELECT value FROM state WHERE id=7')->fetchColumn() !== 'mysqli-updated') exit(1);
echo json_encode(['php'=>PHP_VERSION, 'pdo_write_mysqli_read'=>true, 'mysqli_update_pdo_read'=>true]);
PHP
docker exec c96-php php /tmp/c96-database.php > "$out/original-database.json"
docker exec c96-php rm -f -- /tmp/c96-password /tmp/c96-database.php
python3 -I -B - "$out/original-database.json" "$version" <<'PY'
import json, pathlib, sys
data = json.loads(pathlib.Path(sys.argv[1]).read_bytes())
assert data == {'php':sys.argv[2],'pdo_write_mysqli_read':True,'mysqli_update_pdo_read':True}
PY
