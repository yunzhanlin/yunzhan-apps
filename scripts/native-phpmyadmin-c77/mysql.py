"""Create a disposable managed MySQL instance from the original signed store."""

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
base = private / 'business-mysql'
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


try:
    login = json.loads(pathlib.Path('/etc/panel/first-login.json').read_bytes())
    csrf = api('/login', {k: login[k] for k in ('username', 'password')})[0]['csrf']
    login.clear()
    page = initial_catalogue()
    item, = [v for v in page['catalog']['apps'] if v['id'] == 'mysql']
    assert all(item[k] == v for k, v in plan['mysql'].items())
    assert not next(s for s in page['status'] if s['id'] == 'mysql')['installed']
    runtime_job, release = queue('runtime_jobs', 'original-runtime', '/app-registry/mysql/install',
                                 {'expected_version': item['version'], 'expected_sha256': item['sha256']}, item['target'])
    server_job, server_id = queue('mysql_jobs', 'original-instance', '/databases/instances',
                                 {'name': 'C77 managed MySQL', 'release_id': release, 'port': 13477})
    db_job, _ = queue('mysql_jobs', 'original-database', f'/databases/instances/{server_id}/databases', {'name': 'c77fixture'}, server_id)
    state, _ = api('/databases')
    database, = [v for v in state['databases'] if v['server_id'] == server_id and v['name'] == 'c77fixture']
    server, = [v for v in state['servers'] if v['id'] == server_id]
    assert database['status'] == 'ready' and server['status'] == 'running' and server['port'] == 13477
    creds, headers = api('/databases/items/' + database['id'] + '/credentials', {})
    assert headers['Cache-Control'] == 'no-store' and creds['username'] == database['username']
    assert creds['database'] == 'c77fixture' and creds['host'] == '127.0.0.1'
    run = subprocess.run(['/opt/panel/current/bin/panel-executor', '--database-cli', server_id,
                          '--', '--batch', '--skip-column-names', 'c77fixture'],
                         input="CREATE TABLE proof (id INT PRIMARY KEY, value VARCHAR(30) NOT NULL); INSERT INTO proof VALUES (1,'before-ui');\n",
                         text=True, capture_output=True, timeout=30)
    assert run.returncode == 0, 'Unable to seed owned database fixture'
    record = private / 'owned-mysql-browser.json'
    save(record, {'server_id': server_id, 'database_id': database['id'], 'name': database['name'],
                  'username': creds['username'], 'password': creds['password'], 'original_runtime_job': runtime_job,
                  'original_server_job': server_job, 'original_database_job': db_job})
    os.chown(record, owner.st_uid, owner.st_gid)
finally:
    if csrf:
        api('/logout', {})
