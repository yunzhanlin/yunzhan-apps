"""Exercise PHP 8.1 on a disposable native host through the real panel."""
import contextlib
import http.cookiejar
import json
import os
from pathlib import Path
import platform
import re
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.request

os.umask(0o077)
assert os.geteuid() == 0 and os.environ['GITHUB_ACTIONS'] == 'true'
assert os.environ['GITHUB_REPOSITORY'] == 'yunzhanlin/yunzhan-apps'
evidence = Path(sys.argv[1])
out = evidence / 'business-phase1'
out.mkdir(mode=0o700)
plan = json.loads((Path(__file__).resolve().parent / 'cohort.json').read_bytes())
arch = {'x86_64': 'amd64', 'aarch64': 'arm64'}[platform.machine()]
assert json.loads(Path('/opt/panel/current/SOURCE_INPUTS.json').read_bytes())['inputs_sha256'] == plan['source_inputs_sha256']
origin = 'http://127.0.0.1:19100'
target = 'php-legacy-81-bookworm'
csrf = ''


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise AssertionError('Unexpected local redirect')


client = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
                                    urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))


def save(name, value):
    with (out / name).open('x') as f:
        json.dump(value, f, indent=2)
        f.write('\n')


def api(path, data=None, expected=200):
    headers = {'Origin': origin, 'Content-Type': 'application/json', 'X-CSRF-Token': csrf}
    if data is not None:
        headers['Idempotency-Key'] = secrets.token_hex(16)
    body = None if data is None else json.dumps(data).encode()
    try:
        with client.open(urllib.request.Request(origin + '/api' + path, body, headers), timeout=65) as response:
            assert response.status == expected
            return json.loads(response.read(6 << 20))
    except urllib.error.HTTPError as error:
        if error.code == expected:
            return json.loads(error.read(4096))
        raise


def wait(read, valid, limit=600):
    cutoff = time.monotonic() + limit
    while time.monotonic() < cutoff:
        v = read()
        if valid(v):
            return v
        time.sleep(2)
    raise TimeoutError('Panel job or Docker health did not settle')


def lifecycle(label, route, data):
    save(label + '-original-request.json', {'path': route, 'payload': data, 'maximum_posts': 1})
    answer = api(route, data, 202)
    id = answer['job_id']
    assert re.fullmatch('[0-9a-f]{32}', id)
    row = wait(lambda: api('/docker/job-observations/' + id),
               lambda row: row['state'] in ('succeeded', 'failed', 'needs_attention'))
    save(label + '-original-outcome.json', row)
    assert row['state'] == 'succeeded', label
    assert row['project_id'] == answer['project_id']
    return answer


def project(id):
    return next((x for x in api('/docker/projects')['projects'] if x['id'] == id), None)


def compose_live(id):
    return wait(lambda: project(id),
                lambda p: p and p['state'] == 'running' and p['services'] == p['healthy'] == p['running'] == 2)


def docker(*args, input=None):
    return subprocess.check_output(['/usr/bin/docker', *args], input=input, text=True, timeout=35).strip()


def inspect(p):
    ids = docker('ps', '-aq', '--filter', 'label=com.docker.compose.project=' + p['engine_name']).splitlines()
    assert len(ids) == 2 and all(re.fullmatch('[0-9a-f]{12,64}', id) for id in ids)
    records = json.loads(docker('inspect', *ids))
    return {r['Config']['Labels']['com.docker.compose.service']: r for r in records}


def http(port, path='/', expected=200):
    assert isinstance(port, int) and port in (26778, 26779)
    try:
        with client.open(f'http://127.0.0.1:{port}{path}', timeout=25) as response:
            assert response.status == expected
            return response.read(1 << 20)
    except urllib.error.HTTPError as error:
        assert error.code == expected
        return error.read(4096)


def site_file(record, name, contents):
    assert name in ('retained.txt', '.private.php') and contents in ('original', 'retained')
    command = 'printf %s "$1" > "/var/www/html/$2"'
    docker('exec', record['Id'], 'sh', '-c', command, '--', contents, name)


def current_catalogue():
    for delay in (15, 60, 60, 0):
        try:
            data = api('/app-registry?refresh=1')
            assert not data['source']['stale'] and data['host'] == {'platform': 'ubuntu-24.04', 'architecture': arch}
            return data
        except urllib.error.HTTPError as error:
            if error.code != 503 or not delay:
                raise
            time.sleep(delay)


proof = {'ok': False, 'architecture': arch, 'source_inputs_sha256': plan['source_inputs_sha256'],
         'Main_changed': False, 'all50_commercial': False}
try:
    login = json.loads(Path('/etc/panel/first-login.json').read_bytes())
    csrf = api('/login', {k: login[k] for k in ('username', 'password')})['csrf']
    login.clear()
    original = None
    if arch == 'amd64':
        job = lifecycle('old-amd64-template', '/docker/projects',
                        {'name': 'c79-php81-original', 'template_id': 'php-legacy-81', 'host_port': 26778, 'compose': ''})
        original = compose_live(job['project_id'])
        before = inspect(original)
        assert json.loads(http(26778))['version'] == '8.1.15'
        site_file(before['php'], 'retained.txt', 'original')
        assert http(26778, '/retained.txt') == b'original'
    else:
        refusal = api('/docker/projects', {'name': 'c79-php81-original', 'template_id': 'php-legacy-81',
                                          'host_port': 26778, 'compose': ''}, 400)
        assert refusal['request_not_accepted'] is True
        proof['original_amd64_only_template_refused_on_arm64'] = True

    templates = api('/docker/templates')['templates']
    offered, = [v for v in templates if v['id'] == target]
    assert offered['image'] == plan['image']
    if plan['mode'] == 'signed-store':
        data = current_catalogue()
        assert data['source']['resolved_commit'] == plan['served_head']
        item, = [v for v in data['catalog']['apps'] if v['id'] == 'php-81']
        status, = [v for v in data['status'] if v['id'] == 'php-81']
        assert item == plan['app'] and status['supported'] and status['state_known']
        if arch == 'amd64':
            assert status['installed'] and status['update_available'] and status['update_supported']
            assert status['update_kind'] == 'compose-parallel'
        else:
            assert not status['installed']
        job = lifecycle('signed-php81-install', '/app-registry/php-81/install',
                        {'expected_version': item['version'], 'expected_sha256': item['sha256'],
                         'name': 'c79-php8134-native', 'host_port': 26779})
    else:
        job = lifecycle('reviewed-native-template', '/docker/projects',
                        {'name': 'c79-php8134-native', 'template_id': target, 'host_port': 26779, 'compose': ''})
    id = job['project_id']
    owned = compose_live(id)
    running = inspect(owned)
    assert owned['template_id'] == target
    php, web = running['php'], running['web']
    assert php['Config']['Image'] == plan['image']
    assert docker('image', 'inspect', '-f', '{{.Os}}/{{.Architecture}}', php['Image']) == 'linux/' + arch
    assert php['HostConfig']['ReadonlyRootfs'] and web['HostConfig']['ReadonlyRootfs']
    assert not php['HostConfig']['PortBindings']
    assert web['HostConfig']['PortBindings'] == {'8080/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '26779'}]}
    assert all(not v['HostConfig']['Privileged'] for v in running.values())
    result = json.loads(http(26779))
    assert result['version'] == '8.1.34' and result['sapi'] == 'fpm-fcgi' and result['mysqli'] and result['pdo_mysql']
    site_file(php, 'retained.txt', 'retained')
    site_file(php, '.private.php', 'retained')
    http(26779, '/.private.php', 403)
    lifecycle('stop', f'/docker/projects/{id}/stop', {})
    lifecycle('start', f'/docker/projects/{id}/start', {})
    latest = inspect(compose_live(id))
    assert latest['php']['Id'] == php['Id'] and latest['web']['Id'] == web['Id']
    assert http(26779, '/retained.txt') == b'retained'
    assert json.loads(http(26779)) == result
    if original:
        current = inspect(compose_live(original['id']))
        assert all(before[name]['Id'] == current[name]['Id'] and before[name]['State']['StartedAt'] == current[name]['State']['StartedAt']
                   and before[name]['Mounts'] == current[name]['Mounts'] for name in ('php', 'web'))
        assert http(26778, '/retained.txt') == b'original'
        proof['amd64_original_php_instance_and_volume_preserved'] = True
    if plan['mode'] == 'signed-store':
        fresh = current_catalogue()
        final, = [v for v in fresh['status'] if v['id'] == 'php-81']
        assert final['installed'] and final['installed_version'] == '8.1.34-compat1' and not final['update_available']
    proof.update(ok=True, actual_fpm_http=True, mysql_drivers=True, hidden_file_denied=True,
                 native_host_only=True, retained_new_named_volume=True, original_job=job['job_id'],
                 signed_store_install=plan['mode'] == 'signed-store')
except BaseException:
    import traceback
    proof['failure'] = traceback.format_exc()
finally:
    if csrf:
        with contextlib.suppress(Exception):
            api('/logout', {})
    save('original-proof.json', proof)
sys.exit(0 if proof['ok'] else 1)
