"""Exercise the real Docker Engine and its signed management package."""
import contextlib
import hashlib
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
import urllib.parse

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
    raise TimeoutError('Panel job did not settle')



def job(label, route, payload, limit=2400):
    save(label + "-original-request.json", {"path": route, "payload": payload, "maximum_posts": 1})
    response = api(route, payload, 202)
    identifier = response["job_id"]
    assert re.fullmatch("[0-9a-f]{32}", identifier)
    row = wait(lambda: api("/jobs/" + identifier),
               lambda value: value["state"] in ("succeeded", "failed", "needs_attention"), limit)
    save(label + "-original-outcome.json", row)
    assert row["state"] == "succeeded", label
    return response, row


registry = '/app-registry/docker-manager'
runtime_id = 'docker-ce-29.8.2-noble'
proof = {'ok': False, 'architecture': arch, 'source_inputs_sha256': plan['source_inputs_sha256'],
         'Main_changed': False, 'all50_commercial': False}


def catalogue():
    for delay in (10, 30, 60, 0):
        try:
            data = api('/app-registry?refresh=1')
            break
        except urllib.error.HTTPError as error:
            if error.code != 503 or not delay:
                raise
            time.sleep(delay)
    assert not data['source']['stale'] and data['source']['resolved_commit'] == plan['served_head']
    assert data['host'] == {'platform': 'ubuntu-24.04', 'architecture': arch}
    item, = [app for app in data['catalog']['apps'] if app['id'] == 'docker-manager']
    status, = [app for app in data['status'] if app['id'] == 'docker-manager']
    assert item == plan['items']['docker-manager'] and status['state_known'] and status['supported']
    return item, status


def docker_job(label, payload):
    save(label + '-request.json', {'payload': payload, 'maximum_posts': 1})
    submitted = api('/docker/jobs', payload, 202)
    identifier = submitted['job_id']
    assert re.fullmatch('[a-f0-9]{32}', identifier)
    result = wait(lambda: api('/docker/jobs/' + identifier),
                  lambda row: row['state'] in ('succeeded', 'failed', 'needs_attention'), 500)
    save(label + '-result.json', result)
    assert result['state'] == 'succeeded', label
    return result


def command(*args):
    return subprocess.check_output(args, text=True, timeout=25).strip()


def identity(container):
    return {'daemon': command('/usr/bin/systemctl', 'show', 'docker.service',
                              '--property=MainPID,InvocationID,ExecMainStartTimestampMonotonic'),
            'container': command('/usr/bin/docker', 'inspect', '--format',
                                 '{{.Id}} {{.Image}} {{.State.StartedAt}} {{.RestartCount}}', container),
            'runtime': hashlib.sha256(Path('/opt/panel/runtimes/docker/29.8.2/.panel-runtime.json').read_bytes()).hexdigest()}


def validate_stats(stats, container):
    assert stats['id'] == container and stats['observed_at']
    assert type(stats['memory_bytes']) is int and stats['memory_bytes'] > 0
    assert type(stats['memory_limit_bytes']) is int and stats['memory_limit_bytes'] >= stats['memory_bytes']
    assert type(stats['pids']) is int and stats['pids'] > 0
    assert type(stats['cpu_percent']) in (float, int) and stats['cpu_percent'] >= 0
    assert type(stats['network_rx_bytes']) is int and type(stats['network_tx_bytes']) is int
    assert stats['network_rx_bytes'] > 0 and stats['network_tx_bytes'] > 0
    assert not (set(stats) - {'id','observed_at','cpu_percent','memory_bytes','memory_limit_bytes',
                             'pids','network_rx_bytes','network_tx_bytes','block_read_bytes','block_written_bytes'})


def request_site():
    with client.open('http://127.0.0.1:18226/', timeout=5) as reply:
        assert reply.status == 200
        return hashlib.sha256(reply.read(1 << 20)).hexdigest()


try:
    login = json.loads(Path('/etc/panel/first-login.json').read_bytes())
    csrf = api('/login', {key: login[key] for key in ('username', 'password')})['csrf']
    login.clear()
    item, status = catalogue()
    assert not status['installed']
    update = plan['mode'] == 'signed-docker-metrics-review'
    if update:
        assert item['version'] == '1-compat2'
        _, installed = job('install-existing-runtime', '/runtimes/install', {'release_id': runtime_id}, 2400)
    else:
        assert item['version'] == '1-compat1' and plan['mode'] == 'old-docker-package-real-stats'
        _, installed = job('install-signed-docker', registry + '/install',
                           {'expected_version': item['version'], 'expected_sha256': item['sha256']}, 2400)
    active = api('/docker')
    assert active['available'] and active['active'] and active['version'] == '29.8.2'
    image, = [x['image'] for x in api('/docker/templates')['templates'] if x['id'] == 'nginx-static']
    assert re.fullmatch(r'[a-z0-9./:_-]+@sha256:[a-f0-9]{64}', image)
    docker_job('pull-owned-image', {'action': 'pull', 'image': image})
    created = docker_job('create-owned-container', {'action': 'create', 'image': image, 'name': 'c106r2-native-stats',
                                                       'restart': 'no', 'ports': [{'host_port': 18226, 'container_port': 80, 'protocol': 'tcp'}]})
    container = created['container_id']
    assert re.fullmatch('[a-f0-9]{64}', container)
    deadline = time.monotonic() + 25
    while True:
        try:
            content_sha = request_site()
            break
        except urllib.error.URLError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.25)
    metrics_route = '/docker/containers/' + container + '/stats'
    prior = api(metrics_route)
    validate_stats(prior, container)
    save('original-sample.json', prior)
    assert api('/docker/containers/' + container[:12] + '/stats', expected=400)['error']
    before = identity(container)
    if update:
        _, eligible = catalogue()
        assert eligible['installed'] and eligible['update_available'] and eligible['update_supported']
        assert eligible['update_kind'] == 'docker-metrics-review'
        _, updated = job('update-docker-dashboard', registry + '/update',
                         {'expected_version': item['version'], 'expected_sha256': item['sha256']})
        assert updated['kind'] == 'docker_metrics_review' and updated['target_id'] == runtime_id
        _, latest = catalogue()
        assert latest['installed_version'] == '1-compat2' and not latest['update_available']
        assert latest['version_source'] == 'application-receipt'
        proof['signed_update'] = {'job': updated['id'], 'version': item['version'], 'manifest_sha256': item['sha256']}
    assert identity(container) == before and request_site() == content_sha
    after = api(metrics_route)
    validate_stats(after, container)
    assert after['network_rx_bytes'] >= prior['network_rx_bytes']
    save('actual-final-sample.json', after)
    proof.update(ok=True, registry_version=item['version'], installed_job=installed['id'],
                 actual_docker_metrics=True, original_daemon_and_container_preserved=True,
                 package_only_review=update, exact_container_id_enforced=True)
except BaseException:
    import traceback
    proof['failure'] = traceback.format_exc()
finally:
    if csrf:
        with contextlib.suppress(Exception):
            api('/logout', {})
    save('original-proof.json', proof)
sys.exit(0 if proof['ok'] else 1)
