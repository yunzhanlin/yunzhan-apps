"""Install two reviewed MySQL versions and verify the original instance survives."""

import contextlib
import http.cookiejar
import json
import os
import pathlib
import platform
import re
import secrets
import sqlite3
import subprocess
import sys
import time
import urllib.error
import urllib.request


os.umask(0o077)
assert os.geteuid() == 0 and os.environ['GITHUB_ACTIONS'] == 'true'
assert os.environ['GITHUB_REPOSITORY'] == 'yunzhanlin/yunzhan-apps'
private = pathlib.Path(sys.argv[1])
owner = private.stat()
assert owner.st_uid > 0
base = private / 'business-phase1'
base.mkdir(mode=0o700)
arch = {'x86_64': 'amd64', 'aarch64': 'arm64'}[platform.machine()]
plan = json.loads((pathlib.Path(__file__).resolve().parent / 'cohort.json').read_bytes())
assert json.loads(pathlib.Path('/opt/panel/current/SOURCE_INPUTS.json').read_bytes())['inputs_sha256'] == plan['source_inputs_sha256']
origin = 'http://127.0.0.1:19100'
csrf = ''


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise AssertionError('Unexpected local redirect')


client = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
                                    urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))


def save(path, value):
    with path.open('x') as f:
        json.dump(value, f, indent=2)


def api(path, data=None, expected=200, key=None):
    headers = {'Origin': origin, 'Content-Type': 'application/json', 'X-CSRF-Token': csrf}
    if key:
        headers['Idempotency-Key'] = key
    body = json.dumps(data).encode() if data is not None else None
    with client.open(urllib.request.Request(origin + '/api' + path, body, headers), timeout=65) as r:
        assert r.status == expected
        return json.loads(r.read(6 << 20)), r.headers


def initial_catalogue():
    for attempt, delay in enumerate((10, 65, 65, 0), 1):
        try:
            data = api('/app-registry?refresh=1')[0]
            assert not data['source']['stale'] and data['host'] == {'platform': 'ubuntu-24.04', 'architecture': arch}
            return data
        except urllib.error.HTTPError as e:
            save(base / f'original-catalogue-read-{attempt}.json', {'status': e.code, 'body': e.read(4096).decode(errors='replace')})
            if e.code != 503 or not delay:
                raise
            time.sleep(delay)


def queue(table, label, route, data, target=None):
    assert table in ('runtime_jobs', 'mysql_jobs')
    key = secrets.token_hex(16)
    save(base / (label + '-intent.json'), {'route': route, 'key': key, 'data': data, 'maximum_posts': 1})
    response, _ = api(route, data, 202, key)
    job = response['job_id']
    assert re.fullmatch('[0-9a-f]{32}', job)
    deadline = time.monotonic() + 1200
    while True:
        with contextlib.closing(sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro', uri=True)) as db:
            db.execute('PRAGMA query_only=ON')
            row = db.execute('SELECT target_id,state,error,idempotency_key FROM ' + table + ' WHERE id=?', (job,)).fetchone()
        assert row and row[3] == key
        if row[1] not in ('queued', 'running'):
            break
        assert time.monotonic() < deadline, 'MySQL job exceeded native fixture time budget'
        time.sleep(2)
    save(base / (label + '-outcome.json'), {'job': job, 'target': row[0], 'state': row[1], 'error': row[2]})
    assert row[1] == 'succeeded' and not row[2], label + ' failed'
    if target is not None:
        assert row[0] == target
    return job, row[0]



def mysql_query(server, database, sql):
    result = subprocess.run(['/opt/panel/current/bin/panel-executor', '--database-cli', server,
                             '--', '--batch', '--skip-column-names', database], input=sql + '\n', text=True,
                            capture_output=True, timeout=30)
    assert result.returncode == 0, 'Native MySQL query refused'
    return result.stdout.strip()


def instance(release, label, port):
    server_job, server = queue('mysql_jobs', label + '-instance', '/databases/instances',
                              {'name': 'C78 MySQL ' + label, 'release_id': release, 'port': port})
    database = 'c78_' + label
    database_job, _ = queue('mysql_jobs', label + '-database', f'/databases/instances/{server}/databases',
                            {'name': database}, server)
    state, _ = api('/databases')
    row, = [v for v in state['actual']['servers'] if v['id'] == server]
    assert row['authenticated'] and row['version'] == release.removeprefix('mysql-') and row['port'] == port
    mysql_query(server, database, "CREATE TABLE proof (id INT PRIMARY KEY, marker VARCHAR(32) NOT NULL); "
                "INSERT INTO proof VALUES (1,'" + label + "');")
    return {'id': server, 'database': database, 'release': release, 'port': port,
            'server_job': server_job, 'database_job': database_job}


def original_state(server):
    id = server['id']
    unit = 'panel-mysql@' + id + '.service'
    stdout = subprocess.check_output(['/usr/bin/systemctl', 'show', unit, '-p',
                                      'MainPID,InvocationID,ActiveState'], text=True, timeout=10)
    state = dict(line.split('=', 1) for line in stdout.splitlines())
    assert int(state['MainPID']) > 1 and state['ActiveState'] == 'active'
    st = pathlib.Path('/srv/panel/mysql/' + id + '/data').stat()
    socket = pathlib.Path('/run/panel-mysql-' + id + '/mysql.sock').lstat()
    listeners = subprocess.check_output(['/usr/bin/ss', '-H', '-ltn', 'sport = :' + str(server['port'])], text=True)
    addresses = [row.split()[3] for row in listeners.splitlines()]
    assert addresses == ['127.0.0.1:' + str(server['port'])]
    return {'service': state, 'data': [st.st_dev, st.st_ino], 'socket': [socket.st_dev, socket.st_ino],
            'sql': mysql_query(id, server['database'], 'SELECT id, marker, @@version FROM proof WHERE id=1;')}


proof = {'ok': False, 'architecture': arch, 'source_inputs_sha256': plan['source_inputs_sha256'],
         'Main_changed': False, 'all50_commercial': False}
try:
    login = json.loads(pathlib.Path('/etc/panel/first-login.json').read_bytes())
    csrf = api('/login', {k: login[k] for k in ('username', 'password')})[0]['csrf']
    login.clear()
    catalogue = initial_catalogue()
    item, = [v for v in catalogue['catalog']['apps'] if v['id'] == 'mysql']
    assert all(item[k] == v for k, v in plan['old_mysql'].items())
    old_release = item['target']
    old_job, _ = queue('runtime_jobs', 'original-signed-runtime', '/app-registry/mysql/install',
                       {'expected_version': item['version'], 'expected_sha256': item['sha256']}, old_release)
    old = instance(old_release, 'original', 13478)
    before = original_state(old)
    assert before['sql'] == '1\toriginal\t8.4.11'
    new_release = 'mysql-8.4.13'
    candidate_job, _ = queue('runtime_jobs', 'new-runtime', '/runtimes/install', {'release_id': new_release}, new_release)
    assert original_state(old) == before
    new = instance(new_release, 'new', 13479)
    current = original_state(new)
    assert current['sql'] == '1\tnew\t8.4.13'
    assert current['data'] != before['data'] and current['service']['MainPID'] != before['service']['MainPID']
    assert original_state(old) == before
    with contextlib.closing(sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro', uri=True)) as db:
        db.execute('PRAGMA query_only=ON')
        rows = db.execute(
            'SELECT i.id, i.status FROM runtime_installations i '
            'JOIN runtime_versions v ON i.version_id = v.id WHERE v.family = ? ORDER BY i.id',
            ('mysql',),
        ).fetchall()
    assert rows == [(old_release, 'installed'), (new_release, 'installed')]
    save(base / 'original-preserved-instances.json', {'old': old, 'before': before, 'new': new, 'current': current})
    proof.update(ok=True, original_signed_install_job=old_job, precise_new_install_job=candidate_job,
                 native_versions=['8.4.11', '8.4.13'], original_mysql_process_socket_data_and_sql_preserved=True,
                 new_mysql_independent_database_and_real_sql=True, both_loopback_only=True)
except BaseException as error:
    import traceback
    proof['failure'] = traceback.format_exc()
finally:
    if csrf:
        with contextlib.suppress(Exception):
            api('/logout', {})
    save(base / 'original-proof.json', proof)
sys.exit(0 if proof['ok'] else 1)
