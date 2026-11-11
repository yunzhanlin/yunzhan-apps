"""Exercise authenticated Elasticsearch through the signed store and real HTTP API."""

import base64
import contextlib
import hashlib
import http.client
import http.cookiejar
import json
import os
import pathlib
import platform
import re
import secrets
import stat
import subprocess
import sys
import time
import traceback
import urllib.error
import urllib.request


os.umask(0o077)
assert os.geteuid() == 0 and os.environ.get('GITHUB_ACTIONS') == 'true'
assert os.environ.get('GITHUB_REPOSITORY') == 'yunzhanlin/yunzhan-apps'
private, upgrade_assets = map(pathlib.Path, sys.argv[1:])
work = private / 'business-phase1'
work.mkdir(mode=0o700)
source = pathlib.Path(__file__).resolve().parent
plan = json.loads((source / 'cohort.json').read_bytes())
upgrade = json.loads((source / 'upgrade.json').read_bytes())
arch = {'x86_64': 'amd64', 'aarch64': 'arm64'}[platform.machine()]
origin = 'http://127.0.0.1:19100'
legacy_port, new_port = 26578, 26579
csrf, initial, rotated = '', '', ''
proof = {'ok': False, 'architecture': arch, 'kernel': platform.release(),
         'Main_changed': False, 'all50_commercial': False}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise AssertionError('Unexpected local panel redirect')


client = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
                                    urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))


def save(name, value):
    with (work / (name + '.json')).open('x') as f:
        json.dump(value, f, indent=2)


def api(path, payload=None, expected=200, idempotency=None):
    headers = {'Origin': origin, 'Content-Type': 'application/json', 'X-CSRF-Token': csrf}
    if idempotency:
        headers['Idempotency-Key'] = idempotency
    body = json.dumps(payload).encode() if payload is not None else None
    with client.open(urllib.request.Request(origin + '/api' + path, body, headers), timeout=65) as response:
        assert response.status == expected
        return json.loads(response.read(6 << 20)), response.headers


def login():
    data = json.loads(pathlib.Path('/etc/panel/first-login.json').read_bytes())
    return api('/login', {k: data[k] for k in ('username', 'password')})[0]['csrf']


def wait(read, condition, label, limit):
    deadline = time.monotonic() + limit
    while True:
        value = read()
        if condition(value):
            return value
        if time.monotonic() >= deadline:
            raise AssertionError(label + ' did not reach its expected state')
        time.sleep(2)


def job(response, project):
    job_id = response['job_id']
    assert re.fullmatch('[a-f0-9]{32}', job_id) and response['project_id'] == project
    state = wait(lambda: api('/docker/job-observations/' + job_id)[0],
                 lambda v: v['state'] in ('succeeded', 'failed'), 'original Compose job', 720)
    assert state['state'] == 'succeeded' and state['project_id'] == project
    return job_id


def ready(project, running=True):
    def read():
        return next((v for v in api('/docker/projects')[0]['projects'] if v['id'] == project), None)
    expect = ('running', 1) if running else ('stopped', 0)
    return wait(read, lambda v: v and (v['state'], v['healthy']) == expect, 'Elasticsearch health', 360)


def docker(*args):
    result = subprocess.run(['/usr/bin/docker', *args], capture_output=True, timeout=45)
    assert result.returncode == 0, 'Docker observation failed'
    return result.stdout


def state(project, port):
    cid, = docker('ps', '-aq', '--filter', 'label=com.docker.compose.project=panel_' + project[:12]).decode().splitlines()
    record, = json.loads(docker('inspect', cid))
    assert record['State']['Running'] and record['State']['Health']['Status'] == 'healthy'
    assert record['Config']['Image'] == plan['image'] and not record['HostConfig']['Privileged']
    assert record['HostConfig']['PortBindings'] == {'9200/tcp': [{'HostIp': '127.0.0.1', 'HostPort': str(port)}]}
    image, = json.loads(docker('image', 'inspect', record['Image']))
    assert image['Architecture'] == arch
    mount, = [v for v in record['Mounts'] if v['Destination'] == '/usr/share/elasticsearch/data']
    assert mount['Type'] == 'volume' and mount['RW']
    file = pathlib.Path(mount['Source']).lstat()
    assert stat.S_ISDIR(file.st_mode)
    return {'container': cid, 'pid': record['State']['Pid'], 'image': record['Image'],
            'volume': {'name': mount['Name'], 'device': file.st_dev, 'inode': file.st_ino}}


def elastic(port, method, path, expected, body=None, password=None):
    headers = {'Accept': 'application/json'}
    if body is not None:
        headers['Content-Type'] = 'application/json'
    if password is not None:
        token = base64.b64encode(('elastic:' + password).encode()).decode('ascii')
        headers['Authorization'] = 'Basic ' + token
    with contextlib.closing(http.client.HTTPConnection('127.0.0.1', port, timeout=20)) as conn:
        conn.request(method, path, json.dumps(body) if body is not None else None, headers)
        response = conn.getresponse()
        assert response.status == expected, (method, path, response.status, expected)
        return json.loads(response.read(1 << 20))


def catalogue(legacy_id):
    for attempt, delay in enumerate((10, 65, 65, 0), 1):
        try:
            value = api('/app-registry?refresh=1')[0]
            assert value['host'] == {'platform': 'ubuntu-24.04', 'architecture': arch}
            assert not value['source']['stale'] and len(value['catalog']['apps']) == 50
            item, = [v for v in value['catalog']['apps'] if v['id'] == 'elasticsearch']
            status, = [v for v in value['status'] if v['id'] == item['id']]
            assert status['supported'] and status['installed']
            assert [v['id'] for v in status['instances']] == [legacy_id]
            assert all(item[k] == v for k, v in plan['application'].items())
            return item
        except urllib.error.HTTPError as error:
            body = error.read(4096).decode(errors='replace')
            save('original-catalogue-read-failure-' + str(attempt), {'status': error.code, 'body': body})
            if error.code != 503 or not delay:
                raise
            time.sleep(delay)


def apply_signed_upgrade():
    files = upgrade['release_assets']
    archive = upgrade['cohorts'][arch]['archive']
    expected = [archive + suffix for suffix in ('', '.manifest', '.sig')] + ['release-signing-dev.pub']
    assert {p.name for p in upgrade_assets.iterdir()} == set(expected)
    owned = pathlib.Path('/var/lib') / ('c75-release-' + secrets.token_hex(16))
    owned.mkdir(mode=0o700)
    for name in expected:
        data = (upgrade_assets / name).read_bytes()
        assert len(data) == files[name]['bytes'] and hashlib.sha256(data).hexdigest() == files[name]['sha256']
        with (owned / name).open('xb') as f:
            f.write(data)
    verifier = source / 'original-signed-release.py'
    signer = ['/usr/bin/python3', '-I', '-B', str(verifier), 'install', str(owned / archive),
              '--public-key', str(owned / 'release-signing-dev.pub')]
    apt = json.loads((private / 'isolated-ubuntu-apt-config.json').read_bytes())['path']
    for name, args in (('preflight', ['--preflight-only']), ('upgrade', [])):
        with (work / (name + '.stdout')).open('xb') as out, (work / (name + '.stderr')).open('xb') as err:
            outcome = subprocess.run(signer + args, stdout=out, stderr=err, timeout=900,
                                     env={**os.environ, 'APT_CONFIG': apt})
        save('original-' + name + '-exit', {'exit': outcome.returncode, 'submissions': 1})
        assert outcome.returncode == 0, name + ' refused'
    live = pathlib.Path('/opt/panel/current').resolve(strict=True)
    assert live.name == upgrade['version']
    assert json.loads((live / 'SOURCE_INPUTS.json').read_bytes())['inputs_sha256'] == upgrade['source_inputs_sha256']


try:
    assert pathlib.Path('/opt/panel/current').resolve(strict=True).name == plan['version']
    csrf = login()
    key = secrets.token_hex(16)
    legacy, _ = api('/docker/projects', {'name': 'c75-existing-' + key[:8],
        'template_id': 'elasticsearch', 'host_port': legacy_port}, 202, key)
    legacy_id = legacy['project_id']
    proof['legacy_original_install_job'] = job(legacy, legacy_id)
    ready(legacy_id)
    before = state(legacy_id, legacy_port)
    legacy_index = 'original-' + key[:10]
    document = {'title': 'persistent exact index', 'counter': 77}
    assert elastic(legacy_port, 'PUT', '/' + legacy_index + '/_doc/1?refresh=true', 201, document)['result'] == 'created'
    compose = pathlib.Path('/etc/panel/compose') / legacy_id / 'compose.yaml'
    compose_sha = hashlib.sha256(compose.read_bytes()).hexdigest()
    api('/logout', {})
    csrf = ''
    apply_signed_upgrade()
    assert state(legacy_id, legacy_port) == before
    assert hashlib.sha256(compose.read_bytes()).hexdigest() == compose_sha
    assert elastic(legacy_port, 'GET', '/' + legacy_index + '/_doc/1', 200)['_source'] == document
    csrf = login()
    assert not ready(legacy_id).get('initial_credentials', False)
    item = catalogue(legacy_id)
    key = secrets.token_hex(16)
    result, _ = api('/app-registry/elasticsearch/install', {'name': 'c75-store-' + key[:8], 'host_port': new_port,
        'expected_version': item['version'], 'expected_sha256': item['sha256']}, 202, key)
    project = result['project_id']
    proof['signed_install_job'] = job(result, project)
    assert ready(project)['initial_credentials'] is True
    fresh = state(project, new_port)
    assert fresh['volume']['name'] != before['volume']['name']
    data, headers = api('/docker/projects/' + project + '/credentials', {})
    assert data['project_id'] == project and data['template_id'] == 'elasticsearch' and data['host_port'] == new_port
    assert headers['Cache-Control'] == 'no-store' and set(data['credentials']) == {'ELASTIC_PASSWORD'}
    initial = data['credentials']['ELASTIC_PASSWORD']
    assert re.fullmatch('[a-f0-9]{32,}', initial)
    assert elastic(new_port, 'GET', '/', 401)['status'] == 401
    assert elastic(new_port, 'GET', '/', 401, password=secrets.token_hex(32))['status'] == 401
    cluster = elastic(new_port, 'GET', '/', 200, password=initial)
    assert cluster['version']['number'] == '9.1.4'
    index = 'signed-' + key[:10]
    assert elastic(new_port, 'PUT', '/' + index, 200, {'settings': {'number_of_replicas': 0},
        'mappings': {'properties': {'title': {'type': 'text'}, 'counter': {'type': 'integer'}}}}, initial)['acknowledged']
    assert elastic(new_port, 'PUT', '/' + index + '/_doc/1?refresh=true', 201, document, initial)['result'] == 'created'
    assert elastic(new_port, 'GET', '/' + index + '/_doc/1', 401)['status'] == 401
    query = {'query': {'match': {'title': 'persistent'}}}
    def search(password):
        hits = elastic(new_port, 'POST', '/' + index + '/_search', 200, query, password)['hits']['hits']
        return [v['_source'] for v in hits]
    assert search(initial) == [document]
    rotated = secrets.token_urlsafe(30)
    elastic(new_port, 'POST', '/_security/user/elastic/_password', 200, {'password': rotated}, initial)
    assert elastic(new_port, 'GET', '/', 401, password=initial)['status'] == 401 and search(rotated) == [document]
    for action, running in (('stop', False), ('start', True)):
        outcome, _ = api('/docker/projects/' + project + '/' + action, {}, 202)
        proof[action + '_job'] = job(outcome, project)
        ready(project, running)
    final = state(project, new_port)
    assert final['container'] == fresh['container'] and final['pid'] != fresh['pid'] and final['volume'] == fresh['volume']
    assert search(rotated) == [document] and elastic(new_port, 'GET', '/', 401, password=initial)['status'] == 401
    assert state(legacy_id, legacy_port) == before
    assert hashlib.sha256(compose.read_bytes()).hexdigest() == compose_sha
    assert elastic(legacy_port, 'GET', '/' + legacy_index + '/_doc/1', 200)['_source'] == document
    save('original-service-state', {'old': before, 'fresh': fresh, 'after_restart': final})
    proof.update(ok=True, legacy_id=legacy_id, project_id=project,
                 existing_unauthenticated_project_preserved=True, native_image_version=cluster['version']['number'],
                 unauthorized_requests_refused=True, authenticated_index_write_and_search=True,
                 credential_rotation_and_data_preserved=True, original_volumes_retained=True)
except BaseException:
    failure = traceback.format_exc()
    for secret in (initial, rotated):
        if secret:
            failure = failure.replace(secret, '[private]')
    proof['failure'] = failure
finally:
    if csrf:
        with contextlib.suppress(Exception):
            api('/logout', {})
    save('original-proof', proof)
sys.exit(0 if proof['ok'] else 1)
