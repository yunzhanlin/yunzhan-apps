"""Exercise the signed Redis patch and preserve the original native instance."""

import contextlib
import http.cookiejar
import json
import os
import pathlib
import platform
import re
import secrets
import sqlite3
import socket
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
    assert table == 'runtime_jobs'
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
        assert time.monotonic() < deadline, 'Redis build exceeded the native fixture time budget'
        time.sleep(2)
    save(base / (label + '-outcome.json'), {'job': job, 'target': row[0], 'state': row[1], 'error': row[2]})
    assert row[1] == 'succeeded' and not row[2], label + ' failed'
    if target is not None:
        assert row[0] == target
    return job, row[0]



def redis_command(connection, stream, *items):
    payload = [f'*{len(items)}\r\n'.encode()]
    for item in items:
        raw = item.encode('utf8')
        payload += [f'${len(raw)}\r\n'.encode(), raw, b'\r\n']
    connection.sendall(b''.join(payload))
    line = stream.readline(1024)
    assert line.endswith(b'\r\n')
    value = line[1:-2]
    if line.startswith(b'$'):
        count = int(value)
        assert 0 <= count < 1024
        raw = stream.read(count + 2)
        assert len(raw) == count + 2 and raw.endswith(b'\r\n')
        return '$', raw[:-2]
    assert line[:1] in (b'+', b'-')
    return line[:1].decode(), value


def assert_unauthenticated(port):
    with socket.create_connection(('127.0.0.1', port), timeout=5) as c, c.makefile('rb') as f:
        kind, data = redis_command(c, f, 'GET', 'c81:proof')
        assert kind == '-' and data.startswith(b'NOAUTH')


def redis_read(instance, credentials, marker=None):
    with socket.create_connection(('127.0.0.1', instance['port']), timeout=5) as c, c.makefile('rb') as f:
        assert redis_command(c, f, 'AUTH', credentials['username'], credentials['password']) == ('+', b'OK')
        if marker:
            assert redis_command(c, f, 'SET', 'c81:proof', marker) == ('+', b'OK')
        kind, data = redis_command(c, f, 'GET', 'c81:proof')
        assert kind == '$'
        return data.decode()


def instance(release, marker, port):
    response, _ = api('/redis/instances', {'name': 'c81-' + marker, 'release_id': release,
                                          'port': port, 'max_memory_mb': 64}, 201)
    assert response['release_id'] == release and response['port'] == port
    id = response['id']
    assert re.fullmatch('[0-9a-f]{32}', id)
    credentials, headers = api(f'/redis/instances/{id}/credentials', {})
    assert headers.get('Cache-Control') == 'no-store'
    assert credentials['host'] == '127.0.0.1' and credentials['port'] == port
    assert credentials['username'] == 'app-' + id[:12]
    assert re.fullmatch('[0-9a-f]{64}', credentials['password'])
    assert_unauthenticated(port)
    assert redis_read(response, credentials, marker) == marker
    return response, credentials


def observe(instance, credentials):
    id, port = instance['id'], instance['port']
    state = subprocess.check_output(['/usr/bin/systemctl', 'show', f'panel-redis@{id}.service',
                                     '-p', 'MainPID,InvocationID,ActiveState'], text=True, timeout=10)
    props = dict(line.split('=', 1) for line in state.splitlines())
    assert props['ActiveState'] == 'active' and int(props['MainPID']) > 1
    st = pathlib.Path('/srv/panel/redis', id).stat()
    listeners = subprocess.check_output(['/usr/bin/ss', '-H', '-ltn', 'sport = :' + str(port)], text=True)
    assert [line.split()[3] for line in listeners.splitlines()] == ['127.0.0.1:' + str(port)]
    with contextlib.closing(sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro', uri=True)) as db:
        row = db.execute('SELECT binary_path,status FROM runtime_installations WHERE id=?', (instance['release_id'],)).fetchone()
    assert row and row[1] == 'installed'
    version = subprocess.check_output([row[0], '--version'], timeout=5, text=True)
    assert 'v=' + instance['release_id'].removeprefix('redis-') + ' ' in version
    return {'process': props, 'data': [st.st_dev, st.st_ino], 'value': redis_read(instance, credentials)}


proof = {'ok': False, 'architecture': arch, 'source_inputs_sha256': plan['source_inputs_sha256'],
         'Main_changed': False, 'all50_commercial': False}
try:
    login = json.loads(pathlib.Path('/etc/panel/first-login.json').read_bytes())
    csrf = api('/login', {k: login[k] for k in ('username', 'password')})[0]['csrf']
    login.clear()
    catalogue = initial_catalogue()
    item, = [a for a in catalogue['catalog']['apps'] if a['id'] == 'redis']
    assert all(item[k] == v for k, v in plan['old_redis'].items())
    old_id, _ = queue('runtime_jobs', 'original-signed-redis-runtime', '/app-registry/redis/install',
                      {'expected_version': item['version'], 'expected_sha256': item['sha256']}, item['target'])
    old, old_credentials = instance(item['target'], 'original', 16481)
    original = observe(old, old_credentials)
    new_release = 'redis-8.2.11'
    new_id, _ = queue('runtime_jobs', 'precise-redis-runtime', '/runtimes/install', {'release_id': new_release}, new_release)
    assert observe(old, old_credentials) == original
    new, new_credentials = instance(new_release, 'new', 16482)
    current = observe(new, new_credentials)
    assert current['value'] == 'new' and original['value'] == 'original'
    assert current['data'] != original['data']
    assert current['process']['MainPID'] != original['process']['MainPID']
    api(f"/redis/instances/{new['id']}/restart", {})
    restarted = observe(new, new_credentials)
    assert restarted['data'] == current['data'] and restarted['value'] == current['value']
    assert restarted['process']['InvocationID'] != current['process']['InvocationID']
    assert observe(old, old_credentials) == original
    proof.update(ok=True, original_signed_redis_job=old_id, precise_new_redis_job=new_id,
                 original_process_and_data_preserved=True, new_acl_required=True,
                 new_aof_data_survived_restart=True, both_loopback_only=True)
except BaseException:
    import traceback
    proof['failure'] = traceback.format_exc()
finally:
    if csrf:
        with contextlib.suppress(Exception):
            api('/logout', {})
    save(base / 'original-proof.json', proof)
sys.exit(0 if proof['ok'] else 1)
