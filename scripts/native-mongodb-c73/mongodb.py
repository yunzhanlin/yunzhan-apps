"""Verify signed installation and actual MongoDB persistence on a compatible kernel."""

import contextlib
import hashlib
import http.cookiejar
import json
import os
import pathlib
import platform
import secrets
import socket
import subprocess
import sys
import time
import traceback
import urllib.request


os.umask(0o077)
assert os.geteuid() == 0 and os.environ.get('GITHUB_ACTIONS') == 'true'
assert os.environ.get('GITHUB_REPOSITORY') == 'yunzhanlin/yunzhan-apps'
work = pathlib.Path(sys.argv[1]) / 'business-phase1'
work.mkdir(mode=0o700)
source = pathlib.Path(__file__).resolve().parent
plan = json.loads((source / 'cohort.json').read_bytes())
arch = {'x86_64': 'amd64', 'aarch64': 'arm64'}[platform.machine()]
kernel = platform.release()
app = plan['application']
port = 26573
origin = 'http://127.0.0.1:19100'
proof = {'ok': False, 'architecture': arch, 'kernel': kernel, 'os': 'ubuntu-22.04',
         'Main_changed': False, 'all50_commercial': False}
secret = ''
csrf = ''


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise AssertionError('Unexpected localhost redirect')


client = urllib.request.build_opener(
    urllib.request.ProxyHandler({}), NoRedirect(),
    urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
)


def save(name, data):
    with (work / (name + '.json')).open('x') as file:
        json.dump(data, file, indent=2)


def api(path, payload=None, status=200, idempotency=None):
    headers = {'Origin': origin, 'Content-Type': 'application/json', 'X-CSRF-Token': csrf}
    if idempotency:
        headers['Idempotency-Key'] = idempotency
    body = json.dumps(payload).encode() if payload is not None else None
    with client.open(urllib.request.Request(origin + '/api' + path, body, headers), timeout=65) as reply:
        assert reply.status == status
        raw = reply.read(6 << 20)
        return json.loads(raw) if raw else {}, reply.headers


def wait(read, predicate, timeout):
    until = time.monotonic() + timeout
    while True:
        item = read()
        if predicate(item):
            return item
        if time.monotonic() >= until:
            raise AssertionError('Timed out observing the original MongoDB operation')
        time.sleep(2)


def original_job(accepted, project):
    job_id = accepted['job_id']
    assert len(job_id) == 32 and accepted['project_id'] == project
    job = wait(lambda: api('/docker/job-observations/' + job_id)[0],
               lambda item: item['state'] in ('succeeded', 'failed'), 600)
    assert job['state'] == 'succeeded' and job['project_id'] == project
    return job_id


def project_state(project, running):
    def read():
        values = api('/docker/projects')[0]['projects']
        return next((v for v in values if v['id'] == project), None)
    return wait(read, lambda v: v and (v['state'], v['healthy']) ==
                (('running', 1) if running else ('stopped', 0)), 240)


def docker(*args, script=None):
    return subprocess.run(['/usr/bin/docker', *args], input=script, capture_output=True,
                          text=True, timeout=75)


def mongo_eval(script):
    script = 'function equal(actual, expected) { if (actual !== expected) throw new Error(JSON.stringify({actual, expected})); }\n' + script
    command = docker('run', '--rm', '-i', '--pull=never', '--network=host',
                     '--entrypoint', 'mongosh', plan['image'], '--host', '127.0.0.1',
                     '--port', str(port), '--norc', '--quiet', '--file', '/dev/stdin',
                     script=script)
    output = command.stdout.replace(secret, '[private]') if secret else command.stdout
    error = command.stderr.replace(secret, '[private]') if secret else command.stderr
    assert command.returncode == 0, error[-700:]
    return output


def volume_state(project):
    result = docker('ps', '-aq', '--filter', 'label=com.docker.compose.project=panel_' + project[:12])
    assert result.returncode == 0
    cid, = result.stdout.splitlines()
    raw = docker('inspect', cid)
    assert raw.returncode == 0
    container, = json.loads(raw.stdout)
    assert container['Config']['Image'] == plan['image']
    assert container['HostConfig']['PortBindings'] == {
        '27017/tcp': [{'HostIp': '127.0.0.1', 'HostPort': str(port)}],
    }
    assert container['HostConfig']['Privileged'] is False
    mounts = [m for m in container['Mounts'] if m['Destination'] == '/data/db']
    mount, = mounts
    assert mount['Type'] == 'volume' and mount['RW']
    st = pathlib.Path(mount['Source']).lstat()
    image = docker('image', 'inspect', container['Image'])
    image_metadata, = json.loads(image.stdout)
    assert image.returncode == 0 and image_metadata['Architecture'] == arch
    return {'volume': mount['Name'], 'device': st.st_dev, 'inode': st.st_ino,
            'image': container['Image'], 'architecture': arch}


try:
    version = tuple(map(int, kernel.split('-')[0].split('.')[:3]))
    assert version < (6, 19, 0) or version >= (7, 0, 14), 'Runner kernel still in MongoDB incompatibility range'
    installed = pathlib.Path('/opt/panel/current').resolve(strict=True)
    assert installed.name == plan['version']
    assert json.loads((installed / 'SOURCE_INPUTS.json').read_bytes())['inputs_sha256'] == plan['source_inputs_sha256']
    assert docker('info', '--format', '{{.OSType}}').stdout.strip() == 'linux'
    access = json.loads(pathlib.Path('/etc/panel/first-login.json').read_bytes())
    csrf = api('/login', {k: access[k] for k in ('username', 'password')})[0]['csrf']
    access.clear()
    catalog, _ = api('/app-registry?refresh=1')
    assert catalog['host'] == {'platform': 'ubuntu-22.04', 'architecture': arch}
    assert not catalog['source']['stale'] and len(catalog['catalog']['apps']) == 50
    item = next(v for v in catalog['catalog']['apps'] if v['id'] == 'mongodb')
    assert all(item[k] == v for k, v in app.items())
    status = next(s for s in catalog['status'] if s['id'] == 'mongodb')
    assert status['supported'] and not status['installed']
    token = secrets.token_hex(16)
    response, _ = api('/app-registry/mongodb/install', {
        'expected_version': app['version'], 'expected_sha256': app['sha256'],
        'name': 'mongo-native-' + token[:8], 'host_port': port,
    }, 202, token)
    project = response['project_id']
    proof['signed_install_job'] = original_job(response, project)
    project_state(project, True)
    credentials, headers = api('/docker/projects/' + project + '/credentials', {})
    assert headers['Cache-Control'] == 'no-store' and credentials['project_id'] == project
    username = credentials['credentials']['MONGO_INITDB_ROOT_USERNAME']
    secret = credentials['credentials']['MONGO_INITDB_ROOT_PASSWORD']
    assert username == 'paneladmin' and len(secret) >= 24
    initial = volume_state(project)
    database = 'qa_' + token[:12]
    unauth = 'const target=db.getSiblingDB(' + json.dumps(database) + ');'
    assert 'unauthenticated read denied' in mongo_eval(unauth + """
let code;
try { target.runCommand({find:'events'}); } catch (error) { code=error.code; }
equal(code, 13);
print('unauthenticated read denied');
""")
    auth = 'const admin=db.getSiblingDB("admin"); assert(admin.auth(' + json.dumps(username) + ',' + json.dumps(secret) + '));\n'
    database_setup = 'const collection=db.getSiblingDB(' + json.dumps(database) + ').events;\n'
    assert 'verified read/write' in mongo_eval(auth + database_setup + """
equal(db.version(), '8.0.32');
equal(collection.createIndex({identity:1},{unique:true}), 'identity_1');
assert(collection.insertOne({identity:'original',revision:1}).acknowledged);
equal(collection.updateOne({identity:'original'},{$set:{revision:2}}).modifiedCount, 1);
equal(collection.findOne({identity:'original'}).revision, 2);
print('verified read/write');
""")
    proof['stop_job'] = original_job(api('/docker/projects/' + project + '/stop', {}, 202)[0], project)
    project_state(project, False)
    assert volume_state(project) == initial
    try:
        with socket.create_connection(('127.0.0.1', port), timeout=2):
            raise AssertionError('MongoDB host port stayed open after stop')
    except OSError:
        pass
    proof['start_job'] = original_job(api('/docker/projects/' + project + '/start', {}, 202)[0], project)
    project_state(project, True)
    assert volume_state(project) == initial
    assert 'original data verified' in mongo_eval(auth + database_setup + """
equal(collection.findOne({identity:'original'}).revision, 2);
equal(collection.getIndexes().filter(item=>item.name==='identity_1').length, 1);
print('original data verified');
""")
    catalog, _ = api('/app-registry')
    status = next(s for s in catalog['status'] if s['id'] == 'mongodb')
    assert status['installed'] and status['healthy'] and status['installed_version'] == app['version']
    proof.update(ok=True, original_project=project, pinned_volume=initial, signed_package=app['version'],
                 actual_mongodb_version='8.0.32', anonymous_read_denied=True,
                 authenticated_index_write_and_query=True, data_and_index_persisted=True)
except BaseException:
    failure = traceback.format_exc()
    proof['failure'] = failure.replace(secret, '[private]') if secret else failure
finally:
    if csrf:
        with contextlib.suppress(Exception):
            api('/logout', {})
    save('original-proof', proof)
sys.exit(0 if proof['ok'] else 1)
