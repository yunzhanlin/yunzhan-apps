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
    update = plan['mode'] == 'signed-docker-state'
    if update:
        assert item['version'] == '1-compat2'
        _, installed = job('install-existing-runtime', '/runtimes/install', {'release_id': runtime_id}, 2400)
    else:
        assert item['version'] == '1-compat1' and plan['mode'] == 'old-docker-package-real-stats'
        _, installed = job('install-signed-docker', registry + '/install',
                           {'expected_version': item['version'], 'expected_sha256': item['sha256']}, 2400)
    active = api('/docker')
    assert active['available'] and active['active'] and active['version'] == '29.8.2'
    assert active['images'] == 0 and active['running'] == 0
    image, = [x['image'] for x in api('/docker/templates')['templates'] if x['id'] == 'nginx-static']
    assert re.fullmatch(r'[a-z0-9./:_-]+@sha256:[a-f0-9]{64}', image)
    docker_job('pull-owned-image', {'action': 'pull', 'image': image})
    digests = json.loads(command('/usr/bin/docker', 'image', 'inspect', '--format', '{{json .RepoDigests}}', image))
    assert isinstance(digests, list) and all(isinstance(digest, str) for digest in digests)
    exact_reference = image in digests or ('docker.io/library/' + image) in digests
    if active['storage_driver'] == 'overlayfs':
        assert exact_reference, 'Fresh containerd store must return the tagged pinned reference'
    save('original-cold-image-digests.json', {'storage_driver': active['storage_driver'], 'requested': image,
         'repo_digests': digests, 'tagged_digest_observed': exact_reference})
    created = docker_job('create-owned-container', {'action': 'create', 'image': image, 'name': 'c161-native-diagnostics',
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
    after=api(metrics_route)
    validate_stats(after,container)
    save('actual-final-sample.json',after)
    state_route='/docker/containers/'+container+'/state'
    running=api(state_route)
    assert running['id']==container and running['status']=='running' and running['started_at']
    assert running['exit_code'] is None and not running['oom_killed'] and running['restart_policy']=='no'
    assert running['restart_count']==0 and running['finished_at'] is None
    save('running-container-state.json',running)
    assert api('/docker/containers/'+container[:12]+'/state',expected=400)['error']
    assert api('/docker/containers/'+'e'*64+'/state',expected=409)['error']
    fixture_name='c161-native-exit-'+secrets.token_hex(5)
    marker='private-test-value-'+secrets.token_hex(16)
    exiting=docker_job('create-owned-exit-container',{'action':'create','image':image,'name':fixture_name,
        'restart':'on-failure','command':['sh','-c','sleep 12; exit 73'],
        'environment':[{'name':'PANEL_C161_TEST_SECRET','value':marker}]})['container_id']
    assert re.fullmatch('[a-f0-9]{64}',exiting) and exiting!=container
    route='/docker/containers/'+exiting+'/state'
    original=wait(lambda:api(route),lambda row:row['status']=='running',35)
    assert original['id']==exiting and original['restart_policy']=='on-failure' and original['exit_code'] is None
    deadline=time.monotonic()+40
    while time.monotonic()<deadline:
        observed=api(route)
        if (observed['status']=='restarting' and observed['exit_code']==73 and
                observed['restart_count']>0 and observed['restart_policy']=='on-failure'):
            break
        time.sleep(0.04)
    else:
        raise TimeoutError('No real Docker retry with the original exit code')
    assert observed['exit_code']==73 and observed['finished_at'] and not observed['oom_killed']
    assert marker not in json.dumps(observed) and 'environment' not in observed and 'error' not in observed
    save('restarting-exit-code-state.json',observed)
    api('/docker/containers/'+exiting+'/stop',{})
    stopped=wait(lambda:api(route),lambda row:row['status']=='exited',30)
    assert stopped['id']==exiting and stopped['finished_at'] and stopped['exit_code'] is not None
    save('stopped-container-state.json',stopped)
    tested=[]
    try:
        check_name='c161-health-'+secrets.token_hex(5)
        health_container=command('/usr/bin/docker','run','--detach','--name',check_name,
            '--network','none','--pids-limit','16','--memory','64m','--security-opt','no-new-privileges',
            '--cap-drop','ALL','--health-cmd','exit 1','--health-interval','1s','--health-timeout','1s',
            '--health-retries','2','--entrypoint','/bin/sh',image,'-c','sleep 60')
        assert re.fullmatch('[a-f0-9]{64}',health_container)
        tested.append(health_container)
        health=wait(lambda:api('/docker/containers/'+health_container+'/state'),
            lambda row:row['health']=='unhealthy',35)
        assert health['health_failure_count']>=2 and health['status']=='running'
        save('unhealthy-container-state.json',health)
        oom_name='c161-oom-'+secrets.token_hex(5)
        oom_container=command('/usr/bin/docker','run','--detach','--name',oom_name,
            '--network','none','--pids-limit','16','--memory','24m','--memory-swap','24m',
            '--security-opt','no-new-privileges','--cap-drop','ALL','--tmpfs','/scratch:size=64m',
            '--entrypoint','/bin/sh',image,'-c','exec dd if=/dev/zero of=/scratch/payload bs=1M count=48')
        assert re.fullmatch('[a-f0-9]{64}',oom_container)
        tested.append(oom_container)
        oom=wait(lambda:api('/docker/containers/'+oom_container+'/state'),
            lambda row:row['status']=='exited',35)
        assert oom['oom_killed'] and oom['exit_code']==137 and oom['finished_at']
        save('oom-container-state.json',oom)
    finally:
        for fixture in tested:
            command('/usr/bin/docker','rm','--force',fixture)
    assert identity(container)==before and request_site()==content_sha
    proof.update(ok=True,registry_version=item['version'],installed_job=installed['id'],
                 actual_docker_metrics=True,original_daemon_and_container_preserved=True,
                 package_only_review=update,exact_container_id_enforced=True,
                 original_cold_image_pull_passed=True,containerd_tagged_digest_observed=exact_reference,
                 observed_known_exit_code_and_real_restart=True,stopped_container_readable=True,
                 excluded_private_inspect_fields=True,actual_health_failure_and_oom_observed=True)
except BaseException:
    import traceback
    proof['failure'] = traceback.format_exc()
finally:
    if csrf:
        with contextlib.suppress(Exception):
            api('/logout', {})
    save('original-proof.json', proof)
sys.exit(0 if proof['ok'] else 1)
