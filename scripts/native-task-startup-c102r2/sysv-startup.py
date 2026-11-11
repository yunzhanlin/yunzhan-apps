"""Verify the signed SysV boot script inventory through the signed panel."""
import contextlib
import hashlib
import http.cookiejar
import json
import os
from pathlib import Path
import platform
import re
import secrets
import stat
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

def boot_inventory(view):
    report = api(module + '/inventory/' + view)
    assert report['view'] == view and report['available']
    assert isinstance(report['partial'], bool) and len(report['rows']) <= 256
    return report

try:
    assert plan['mode'] == 'signed-sysv-update'
    login = json.loads(Path('/etc/panel/first-login.json').read_bytes())
    csrf = api('/login', {key: login[key] for key in ('username', 'password')})['csrf']
    login.clear()
    item, status = catalogue()
    assert item['version'] == '1.3.1' and not status['installed']
    _, original = job('install-legacy', '/software/task-manager/install', {})
    path = Path('/etc/panel/security-apps/modules/task-manager/installed.json')
    before = json.loads(path.read_bytes())
    assert before['id'] == 'task-manager' and before['version'] == '1.2.1'
    assert api(module + '/inventory/sysv-startup', expected=409)['error']
    _, status = catalogue()
    assert status['installed_version'] == '1.2.1' and status['update_available']
    assert status['update_supported'] and status['update_kind'] == 'module'
    _, updated = job('update-signed', registry + '/update',
                     {'expected_version': item['version'], 'expected_sha256': item['sha256']})
    assert api(module)['status']['version'] == '1.3.1'
    after = json.loads(path.read_bytes())
    assert after.pop('version') == '1.3.1' and after.pop('updated_at')
    assert before.pop('version') == '1.2.1' and before == after
    systemd = boot_inventory('startup')
    assert any(row['name'] == 'panel.service' and row['startup_state'] == 'enabled' for row in systemd['rows'])
    sysv_before = boot_inventory('sysv-startup')
    real_paths = {p.name for p in Path('/etc/init.d').iterdir()
                  if not p.is_symlink() and stat.S_ISREG(p.stat().st_mode) and p.stat().st_uid == 0}
    assert any(row['name'] in real_paths for row in sysv_before['rows'])
    fixture = 'c102-inventory-fixture'
    sentinel = Path('/run/c102-sysv-fixture-must-not-run')
    script = Path('/etc/init.d') / fixture
    link = Path('/etc/rc2.d/S97' + fixture)
    assert not sentinel.exists()
    with script.open('x') as f:
        f.write('#!/bin/sh\n/usr/bin/touch /run/c102-sysv-fixture-must-not-run\n')
    try:
        script.chmod(0o755)
        link.symlink_to('../init.d/' + fixture)
        try:
            verified = boot_inventory('sysv-startup')
            assert verified['view'] != systemd['view']
            row, = [row for row in verified['rows'] if row['name'] == fixture]
            assert row == {'name': fixture, 'source': 'SysV', 'startup_state': '已登记启动链接',
                           'preset': '', 'runlevels': '2'}
            assert not sentinel.exists()
        finally:
            link.unlink()
    finally:
        script.unlink()
    assert not any(row['name'] == fixture for row in boot_inventory('sysv-startup')['rows'])
    proof.update(ok=True, actual_original_sysv_entries=len(sysv_before['rows']),
                 actual_root_startup_link_and_runlevel=True, execution_sentinel_absent=True,
                 separate_systemd_inventory=True, original_installation_retained=True,
                 registry_version=item['version'], installed_job=original['id'],
                 signed_update={'job': updated['id'], 'manifest_sha256': item['sha256'], 'version': item['version']})
except BaseException:
    import traceback
    proof['failure'] = traceback.format_exc()
finally:
    if csrf:
        with contextlib.suppress(Exception):
            api('/logout', {})
    save('original-proof.json', proof)
sys.exit(0 if proof['ok'] else 1)
