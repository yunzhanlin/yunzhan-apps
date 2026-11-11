"""Test the exact patched phpMyAdmin recipe on a native, disposable runner."""
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
import urllib.request

os.umask(0o077)
assert os.geteuid() == 0 and os.environ['GITHUB_ACTIONS'] == 'true'
assert os.environ['GITHUB_REPOSITORY'] == 'yunzhanlin/yunzhan-apps'
out = Path(sys.argv[1]) / 'business-phase1'
out.mkdir(mode=0o700)
cohort = json.loads(Path(__file__).with_name('cohort.json').read_bytes())
arch = {'x86_64': 'amd64', 'aarch64': 'arm64'}[platform.machine()]
source = json.loads(Path('/opt/panel/current/SOURCE_INPUTS.json').read_bytes())['inputs_sha256']
assert source == cohort['source_inputs_sha256']
origin = 'http://127.0.0.1:19100'
client = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                     urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
csrf = ''
proof = {'ok': False, 'architecture': arch, 'source_inputs_sha256': source,
         'Main_changed': False, 'all50_commercial': False}


def api(path, data=None, status=200):
    headers = {'Origin': origin, 'Content-Type': 'application/json', 'X-CSRF-Token': csrf}
    if data is not None:
        headers['Idempotency-Key'] = secrets.token_hex(16)
    body = None if data is None else json.dumps(data).encode()
    with client.open(urllib.request.Request(origin + '/api' + path, body, headers), timeout=45) as response:
        assert response.status == status
        return json.loads(response.read(4 << 20))


def wait(read, ready, timeout=500):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = read()
        if ready(value):
            return value
        time.sleep(2)
    raise TimeoutError('Managed application did not reach a healthy native state')


def docker(*arguments):
    return subprocess.check_output(['/usr/bin/docker', *arguments], timeout=45, text=True).strip()


def inspect(project):
    container = docker('ps', '-aq', '--filter', 'label=com.docker.compose.project=' + project['engine_name'])
    assert re.fullmatch('[a-f0-9]{12,64}', container)
    record, = json.loads(docker('inspect', container))
    return record


def install(template, port, image, version):
    result = api('/docker/projects', {'name': template, 'template_id': template, 'host_port': port, 'compose': ''}, 202)
    job = wait(lambda: api('/docker/job-observations/' + result['job_id']),
               lambda x: x['state'] in ('succeeded', 'failed', 'needs_attention'))
    assert job['state'] == 'succeeded', job.get('error')
    project = wait(lambda: next((p for p in api('/docker/projects')['projects'] if p['id'] == result['project_id']), None),
                   lambda p: p and p['state'] == 'running' and p['services'] == p['healthy'] == 1)
    record = inspect(project)
    assert record['Config']['Image'] == image
    assert record['HostConfig']['PortBindings'] == {'80/tcp': [{'HostIp': '127.0.0.1', 'HostPort': str(port)}]}
    assert not record['HostConfig']['Privileged'] and not record['Mounts']
    assert 'PMA_ARBITRARY=1' in record['Config']['Env']
    assert docker('image', 'inspect', '-f', '{{.Os}}/{{.Architecture}}', record['Image']) == 'linux/' + arch
    assert docker('exec', record['Id'], 'php', '-r', 'echo PHP_VERSION;') == version
    with client.open(f'http://127.0.0.1:{port}/', timeout=25) as response:
        assert response.status == 200
        body = response.read(1 << 20)
        assert b'phpMyAdmin' in body and b'input_username' in body and b'serverNameInput' in body
    return project, record, result['job_id']


try:
    login = json.loads(Path('/etc/panel/first-login.json').read_bytes())
    csrf = api('/login', {name: login[name] for name in ('username', 'password')})['csrf']
    login.clear()
    previous, old, old_job = install('phpmyadmin', 26580, cohort['previous_image'], '8.2.29')
    new, _, new_job = install('phpmyadmin-523', 26581, cohort['image'], '8.3.36')
    retained = inspect(previous)
    assert retained['Id'] == old['Id'] and retained['State']['StartedAt'] == old['State']['StartedAt']
    assert new['id'] != previous['id']
    proof.update(ok=True, old_job=old_job, new_job=new_job, native_php_version='8.3.36',
                 actual_phpmyadmin_http=True, native_loopback_only=True, old_project_retained=True)
finally:
    if csrf:
        api('/logout', {})
    with (out / 'original-proof.json').open('x') as report:
        json.dump(proof, report, indent=2)
        report.write('\n')
assert proof['ok']
