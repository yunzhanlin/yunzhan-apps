#!/usr/bin/env bash
set -euo pipefail

umask 077
out="$1"
network=panel-c87-legacy-php-fixture_default
test "$(docker network inspect --format '{{.Internal}}' "$network")" = true
php="$(docker compose --project-name panel-c87-legacy-php-fixture -f "$out/compose.yaml" ps -q php)"
test -n "$php"
db_secret="$(openssl rand -hex 24)"
db_env="$(mktemp)"
db=""
cleanup() {
    if [[ -n "$db" ]]; then docker stop "$db" >/dev/null 2>&1 || true; fi
    rm -f -- "$db_env"
}
trap cleanup EXIT
{
    printf 'MARIADB_ROOT_PASSWORD=%s\n' "$(openssl rand -hex 24)"
    printf 'MARIADB_DATABASE=panelqa\nMARIADB_USER=panelqa\nMARIADB_PASSWORD=%s\n' "$db_secret"
} > "$db_env"
db="$(docker run --detach --rm --network "$network" --network-alias db --env-file "$db_env" 'mariadb:11.8.9@sha256:c4124d1afa875e47f2892edf26b482fa54f796e2f342d3717a04ca091a22a9bd')"
rm -f -- "$db_env"
for ((i=0; i<45; i++)); do
    if docker exec "$db" healthcheck.sh --connect --innodb_initialized >/dev/null 2>&1; then break; fi
    sleep 2
done
docker exec "$db" healthcheck.sh --connect --innodb_initialized
ports="$(docker inspect -f '{{json .HostConfig.PortBindings}}' "$db")"
[[ "$ports" = '{}' || "$ports" = null ]]
docker exec --interactive -e "QA_DB_PASSWORD=$db_secret" "$php" php > "$out/original-db.json" <<'PHP'
<?php
$password = getenv('QA_DB_PASSWORD');
$pdo = new PDO('mysql:host=db;dbname=panelqa', 'panelqa', $password, array(PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION));
$pdo->exec('CREATE TABLE state (id INT PRIMARY KEY, value VARCHAR(32) NOT NULL)');
$write = $pdo->prepare('INSERT INTO state VALUES (?, ?)');
$write->execute(array(7, 'verified-legacy-client'));
$object = new mysqli('db', 'panelqa', $password, 'panelqa');
$result = $object->query('SELECT value FROM state WHERE id = 7');
$row = $result->fetch_row();
if ($row[0] !== 'verified-legacy-client') exit(1);
$link = mysqli_init();
if (!mysqli_real_connect($link, 'db', 'panelqa', $password, 'panelqa')) exit(1);
if (!mysqli_query($link, "UPDATE state SET value = 'mysqli-updated' WHERE id = 7")) exit(1);
if ($pdo->query('SELECT value FROM state WHERE id = 7')->fetchColumn() !== 'mysqli-updated') exit(1);
echo json_encode(array('php' => PHP_VERSION, 'pdo_write_mysqli_read' => true, 'mysqli_update_pdo_read' => true));
PHP
python3 -I -B - "$out" <<'PYDB'
import json, pathlib, sys
out = pathlib.Path(sys.argv[1])
db = json.loads((out/'original-db.json').read_bytes())
smoke = json.loads((out/'original-proof.json').read_bytes())
assert db == {'php':smoke['version'], 'pdo_write_mysqli_read':True, 'mysqli_update_pdo_read':True}
PYDB
