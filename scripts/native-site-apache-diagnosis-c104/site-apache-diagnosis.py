"""Diagnose actual managed websites through the signed panel."""
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
    for app, item in plan['items'].items():
        assert next(x for x in data['catalog']['apps'] if x['id'] == app) == item
    return {entry['id']: entry for entry in data['status']}


module = '/app-modules/site-diagnosis'
registry = '/app-registry/site-diagnosis'
path = '/c104.txt'
checks_base = {'binding', 'http', 'dns', 'tls_certificate', 'nginx', 'files'}
checks_apache = {'apache_config', 'apache_listener'}
proof = {'ok': False, 'architecture': arch, 'source_inputs_sha256': plan['source_inputs_sha256'],
         'Main_changed': False, 'all50_commercial': False}


def create_site(server):
    slug = 'c104-' + server
    domain = slug + '.example.test'
    _, created = job('create-' + server, '/sites', {'name': slug, 'slug': slug, 'domain': domain}, 300)
    site = created['site_id']
    assert re.fullmatch('[a-f0-9]{32}', site)
    route = '/sites/' + site
    body = 'Apache diagnosis test site ' + server + '\n'
    result = api(route + '/files/action', {'action': 'create', 'path': path[1:], 'content': body})
    assert result['sha256'] == hashlib.sha256(body.encode()).hexdigest()
    if server == 'apache':
        current = api(route + '/settings')
        settings = {**current['settings'], 'web_server': 'apache'}
        request = {'settings': settings, 'expected_revision': current['settings_revision']}
        preview = api(route + '/settings/preview', request)
        _, changed = job('switch-apache', route + '/settings',
                         {**request, 'expected_config_sha': preview['config_sha']}, 300)
        assert changed['site_id'] == site
        assert api(route + '/settings')['settings']['web_server'] == 'apache'
    req = urllib.request.Request('http://127.0.0.1:19101' + path, headers={'Host': domain})
    with client.open(req, timeout=15) as reply:
        assert reply.status == 200 and reply.read(65536) == body.encode()
    return {'id': site, 'domain': domain, 'body_hash': hashlib.sha256(body.encode()).hexdigest()}


def diagnose(site, *, apache=False, status=200, config='pass', listener='pass'):
    report = api(module + '/run', {'site_id': site['id'], 'path': path,
                                  'diagnosis_apache_sites': {site['id']: 'forged.example.test'}})
    assert report['site_id'] == site['id'] and report['domain'] == site['domain'] and report['path'] == path
    checks = report['checks']
    assert set(checks) == (checks_base | checks_apache if apache else checks_base)
    assert checks['binding']['verdict'] == checks['nginx']['verdict'] == 'pass'
    assert checks['http']['status'] == status
    if apache:
        assert checks['apache_config']['verdict'] == config
        assert checks['apache_listener']['verdict'] == listener
    assert report['total_checks'] == len(checks)
    assert report['passed_checks'] == sum(v['verdict'] == 'pass' for v in checks.values())
    return report


def systemctl(action):
    subprocess.run(['/usr/bin/systemctl', action, 'panel-apache.service'], check=True, timeout=45)


def replace_config(conf, body, mode):
    pending = conf.with_name('.c104-diagnosis-native-test.conf')
    with pending.open('xb') as file:
        file.write(body)
        file.flush()
        os.fsync(file.fileno())
    pending.chmod(mode)
    pending.replace(conf)


try:
    login = json.loads(Path('/etc/panel/first-login.json').read_bytes())
    csrf = api('/login', {key: login[key] for key in ('username', 'password')})['csrf']
    login.clear()
    original = catalogue()
    apache_item = plan['items']['apache']
    item = plan['items']['site-diagnosis']
    assert not original['apache']['installed'] and not original['site-diagnosis']['installed']
    _, apache_job = job('install-apache', '/app-registry/apache/install',
                        {'expected_version': apache_item['version'], 'expected_sha256': apache_item['sha256']}, 3050)
    update = plan['mode'] == 'signed-apache-diagnosis-update'
    if update:
        assert item['version'] == '1.3.1'
        _, installed = job('install-legacy-diagnosis', '/software/site-diagnosis/install', {})
    else:
        assert plan['mode'] == 'ingress-diagnosis-compat' and item['version'] == '1.3.0'
        _, installed = job('install-ingress-diagnosis', registry + '/install',
                           {'expected_version': item['version'], 'expected_sha256': item['sha256']})
    version_before = '1.2.0' if update else '1.3.0'
    assert api(module)['status']['version'] == version_before
    marker = Path('/etc/panel/security-apps/modules/site-diagnosis/installed.json')
    receipt = json.loads(marker.read_bytes())
    assert receipt['version'] == version_before
    nginx, apache = [create_site(server) for server in ('nginx', 'apache')]
    save('original-old-apache-report.json', diagnose(apache))
    save('original-old-nginx-report.json', diagnose(nginx))
    history = api(module + '/history')
    assert len(history['history']) >= 2
    if update:
        eligible = catalogue()['site-diagnosis']
        assert eligible['installed_version'] == version_before and eligible['update_available'] and eligible['update_supported']
        _, updated = job('update-diagnosis', registry + '/update',
                         {'expected_version': item['version'], 'expected_sha256': item['sha256']})
        assert api(module)['status']['version'] == '1.3.1'
        latest = catalogue()['site-diagnosis']
        assert latest['installed_version'] == '1.3.1' and not latest['update_available']
        new = json.loads(marker.read_bytes())
        assert new.pop('version') == '1.3.1' and new.pop('updated_at')
        assert receipt.pop('version') == version_before and receipt == new
        assert api(module + '/history') == history
        conf = Path('/etc/panel/apache/httpd.conf')
        old = conf.read_bytes()
        mode = conf.stat().st_mode & 0o777
        assert conf.is_file() and not conf.is_symlink() and conf.stat().st_uid == 0
        save('actual-apache-and-nginx-healthy.json', [diagnose(apache, apache=True), diagnose(nginx)])
        batch = api(module + '/diagnosis-batch', {'site_ids': [nginx['id'], apache['id']], 'path': path,
                                                  'diagnosis_apache_sites': {nginx['id']: nginx['domain']}})
        assert batch['site_count'] == 2
        nginx_row, apache_row = batch['diagnoses']
        assert set(nginx_row['report']['checks']) == checks_base
        assert set(apache_row['report']['checks']) == checks_base | checks_apache
        save('actual-batch-apache-and-nginx.json', batch)
        try:
            systemctl('stop')
            save('actual-stopped-apache-report.json', diagnose(apache, apache=True, status=502, listener='fail'))
            diagnose(nginx)
        finally:
            systemctl('start')
        deadline = time.monotonic() + 15
        while True:
            try:
                req = urllib.request.Request('http://127.0.0.1:19101' + path, headers={'Host': apache['domain']})
                with client.open(req, timeout=3) as reply:
                    assert reply.status == 200
                break
            except urllib.error.URLError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.25)
        save('actual-restarted-apache-report.json', diagnose(apache, apache=True))
        try:
            replace_config(conf, old + b'\nC104InvalidDirective\n', mode)
            save('actual-invalid-apache-config-report.json', diagnose(apache, apache=True, config='fail'))
        finally:
            replace_config(conf, old, mode)
        save('actual-restored-apache-config-report.json', diagnose(apache, apache=True))
        assert conf.read_bytes() == old and conf.stat().st_uid == 0 and conf.stat().st_mode & 0o777 == mode
        for site in (nginx, apache):
            assert api('/sites/' + site['id'] + '/files/text?path=' + path[1:])['sha256'] == site['body_hash']
        proof.update(signed_update={'job': updated['id'], 'version': item['version'], 'manifest_sha256': item['sha256']},
                     healthy_and_failed_apache_independent=True, stored_nginx_scope_preserved=True,
                     original_installation_retained=True, history_retained=True, original_site_files_retained=True)
    proof.update(ok=True, previous_ingress_compatibility=True, registry_version=item['version'],
                 installed_job=installed['id'], apache_runtime_job=apache_job['id'])
except BaseException:
    import traceback
    proof['failure'] = traceback.format_exc()
finally:
    if csrf:
        with contextlib.suppress(Exception):
            api('/logout', {})
    save('original-proof.json', proof)
sys.exit(0 if proof['ok'] else 1)
