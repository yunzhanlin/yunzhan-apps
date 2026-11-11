"""Verify real Task Manager and Linux inventories through the signed panel."""
import contextlib
import hashlib
import http.cookiejar
import json
import os
from pathlib import Path
import platform
import re
import secrets
import socket
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
            source = data['source']
            assert not source['stale'] and source['resolved_commit'] == plan['served_head'], (
                source['resolved_commit'], plan['served_head'], source['stale'])
            assert data['host'] == {'platform': 'ubuntu-24.04', 'architecture': arch}
            item, = [row for row in data['catalog']['apps'] if row['id'] == 'task-manager']
            status, = [row for row in data['status'] if row['id'] == 'task-manager']
            assert item == plan['items']['task-manager'] and status['supported'] and status['state_known']
            return item, status
        except urllib.error.HTTPError as error:
            if error.code != 503 or not delay:
                raise
            time.sleep(delay)



module = '/app-modules/task-manager'
registry = '/app-registry/task-manager'
proof = {'ok': False, 'architecture': arch, 'source_inputs_sha256': plan['source_inputs_sha256'],
         'Main_changed': False, 'all50_commercial': False}

def inventory(view):
    report = api(module + '/inventory/' + view)
    assert report['view'] == view and report['available'], report.get('detail')
    assert re.fullmatch(r'\d{4}-\d{2}-\d{2}T.+Z', report['checked_at'])
    assert isinstance(report['partial'], bool) and len(report['rows']) <= 256
    return report['rows']

def processes():
    sample = api(module + '/run', {})
    rows = sample['processes']
    assert rows and len(rows) <= 500
    assert all(row['pid'] > 0 and row['start_time'] > 0 and isinstance(row['can_terminate'], bool) for row in rows)
    return len(rows)

def panel_ready():
    try:
        return api('/health')['status'] == 'ok'
    except urllib.error.URLError:
        return False

try:
    login = json.loads(Path('/etc/panel/first-login.json').read_bytes())
    csrf = api('/login', {key: login[key] for key in ('username', 'password')})['csrf']
    login.clear()
    item, status = catalogue()
    assert not status['installed']
    upgrade = plan['mode'] == 'signed-update'
    if upgrade:
        _, installed = job('install-legacy', '/software/task-manager/install', {})
    else:
        _, installed = job('install-signed-legacy', registry + '/install',
                           {'expected_version': item['version'], 'expected_sha256': item['sha256']})
    assert api(module)['status']['version'] == '1.2.1'
    install_path = Path('/etc/panel/security-apps/modules/task-manager/installed.json')
    old_receipt = json.loads(install_path.read_bytes())
    assert old_receipt['id'] == 'task-manager' and old_receipt['version'] == '1.2.1'
    assert api(module + '/inventory/invalid', expected=404)['error']
    assert api(module + '/inventory/services', expected=409)['error']
    count = processes()
    proof.update(legacy_snapshot_count=count, legacy_version_gated=True,
                 registry_version=item['version'], installed_job=installed['id'])
    if upgrade:
        _, current = catalogue()
        assert current['installed_version'] == '1.2.1' and current['update_available']
        assert current['update_supported'] and current['update_kind'] == 'module'
        _, updated = job('update-signed', registry + '/update',
                         {'expected_version': item['version'], 'expected_sha256': item['sha256']})
        assert api(module)['status']['version'] == '1.3.0'
        assert processes() > 0
        new = json.loads(install_path.read_bytes())
        assert new.pop('version') == '1.3.0' and new.pop('updated_at')
        assert old_receipt.pop('version') == '1.2.1' and old_receipt == new
        assert any(row['name'] == 'panel.service' and row['active_state'] == 'active' for row in inventory('services'))
        assert any(row['name'] == 'panel.service' and row['startup_state'] == 'enabled' for row in inventory('startup'))
        assert any(row['name'] == 'root' and row['uid'] == '0' for row in inventory('accounts'))
        assert all(set(row) == {'name', 'uid', 'gid', 'home', 'shell'} for row in inventory('accounts'))
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            tcp.bind(('127.0.0.1', 0))
            tcp.listen(1)
            udp.bind(('127.0.0.1', 0))
            observed = inventory('network')
            for sock, protocol, state in ((tcp, 'tcp', 'LISTEN'), (udp, 'udp', 'UNCONN')):
                addr = '127.0.0.1:' + str(sock.getsockname()[1])
                assert any(row['protocol'] == protocol and row['state'] == state and row['local'] == addr for row in observed)
        cron = Path('/etc/cron.d/c100_inventory_fixture')
        f = cron.open('x')
        try:
            with f:
                f.write('C100_TOKEN=fixture-private-value\n59 23 31 12 * root /bin/true fixture-private-argument\n')
            relevant = [row for row in inventory('cron') if row['source'] == str(cron)]
            assert relevant == [{'source': str(cron), 'timing': '59 23 31 12 *', 'account': 'root'}]
        finally:
            cron.unlink()
        sessions = inventory('ssh')
        assert all(set(row) == {'name', 'session', 'remote_host', 'terminal', 'state', 'started_at'} for row in sessions)
        exact = install_path.read_bytes()
        subprocess.run(['/usr/bin/systemctl', 'restart', 'panel.service'], check=True, timeout=50, capture_output=True)
        wait(panel_ready, bool, 60)
        assert any(row['name'] == 'panel.service' for row in inventory('services')) and install_path.read_bytes() == exact
        proof.update(signed_update={'job': updated['id'], 'manifest_sha256': item['sha256'], 'version': '1.3.0',
                                    'original_installation_retained': True},
                     service_startup_and_local_accounts=True, actual_tcp_and_udp=True,
                     cron_times_only=True, ssh_inventory_read=True, observed_ssh_sessions=len(sessions),
                     panel_restart_preserved_application=True)
    proof['ok'] = True
except BaseException:
    import traceback
    proof['failure'] = traceback.format_exc()
finally:
    if csrf:
        with contextlib.suppress(Exception):
            api('/logout', {})
    save('original-proof.json', proof)
sys.exit(0 if proof['ok'] else 1)
