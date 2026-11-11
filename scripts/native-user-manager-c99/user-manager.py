"""Verify real managed account and site access through the signed panel."""
import contextlib
import hashlib
import http.cookiejar
import json
import os
from pathlib import Path
import platform
import re
import secrets
import sqlite3
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
            assert not data['source']['stale'] and data['source']['resolved_commit'] == plan['served_head']
            assert data['host'] == {'platform': 'ubuntu-24.04', 'architecture': arch}
            item, = [row for row in data['catalog']['apps'] if row['id'] == 'user-manager']
            status, = [row for row in data['status'] if row['id'] == 'user-manager']
            assert item == plan['items']['user-manager'] and status['supported'] and status['state_known']
            return item, status
        except urllib.error.HTTPError as error:
            if error.code != 503 or not delay:
                raise
            time.sleep(delay)


def reader(report, name):
    assert 'password' not in report and report['menu_catalog']
    account, = [row for row in report['users'] if row['username'] == name]
    assert 'password' not in account and 'password_hash' not in account
    assert re.fullmatch('[a-f0-9]{32}', account['id'])
    return account


def session():
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
                                       urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))


module = '/app-modules/user-manager'
registry = '/app-registry/user-manager'
username = 'c99-readonly-fixture'
dbfile = '/var/lib/panel/panel.db'
proof = {'ok': False, 'architecture': arch, 'source_inputs_sha256': plan['source_inputs_sha256'],
         'Main_changed': False, 'all50_commercial': False}
try:
    login = json.loads(Path('/etc/panel/first-login.json').read_bytes())
    csrf = api('/login', {key: login[key] for key in ('username', 'password')})['csrf']
    login.clear()
    admin_client, admin_csrf = client, csrf
    item, status = catalogue()
    assert not status['installed']
    upgrade = plan['mode'] == 'signed-update'
    if upgrade:
        _, installation = job('install-original', '/software/user-manager/install', {})
    else:
        _, installation = job('install-signed-original', registry + '/install',
                              {'expected_version': item['version'], 'expected_sha256': item['sha256']})
    assert api(module)['status']['version'] == '1.3.1'
    install_file = Path('/etc/panel/security-apps/modules/user-manager/installed.json')
    original_install = json.loads(install_file.read_bytes())
    assert original_install['id'] == 'user-manager' and original_install['installed_at']

    sites = {}
    for label in ('allowed', 'other'):
        slug = 'c99-' + label
        _, created = job('create-' + label, '/sites',
                         {'name': slug, 'slug': slug, 'domain': slug + '.example.test'}, 300)
        sites[label] = created['site_id']
    password = secrets.token_hex(24)
    grants = ['overview', 'sites', 'files']
    created = api(module + '/create', {'username': username, 'password': password,
                  'role': 'viewer', 'site_ids': [], 'menu_ids': grants})
    assert created == {'ok': True, 'username': username, 'action': 'create'}
    before = reader(api(module + '/run', {}), username)
    assert before['site_ids'] == [] and set(before['menu_ids']) == set(grants) and before['revision'] == 1
    with contextlib.closing(sqlite3.connect(dbfile, timeout=10)) as db:
        with db:
            updated = db.execute("UPDATE app_user_roles SET site_ids='null' WHERE user_id=? AND role='viewer' AND site_ids='[]'",
                                 (before['id'],))
            assert updated.rowcount == 1
    historical = reader(api(module + '/run', {}), username)
    assert historical == before
    with contextlib.closing(sqlite3.connect('file:' + dbfile + '?mode=ro', uri=True)) as db:
        assert db.execute('SELECT site_ids FROM app_user_roles WHERE user_id=?', (before['id'],)).fetchone() == ('null',)

    if upgrade:
        _, update_status = catalogue()
        assert update_status['installed_version'] == '1.3.1' and update_status['update_available']
        assert update_status['update_supported'] and update_status['update_kind'] == 'module'
        _, result = job('update-signed', registry + '/update',
                        {'expected_version': item['version'], 'expected_sha256': item['sha256']})
        assert api(module)['status']['version'] == '1.3.2'
        actual_install = json.loads(install_file.read_bytes())
        assert actual_install.pop('version') == '1.3.2' and actual_install.pop('updated_at')
        assert original_install.pop('version') == '1.3.1' and actual_install == original_install
        assert reader(api(module + '/run', {}), username) == historical
        proof['signed_update'] = {'job': result['id'], 'version': '1.3.2',
                                  'manifest_sha256': item['sha256'], 'original_account_and_installation_retained': True}

    client = session()
    csrf = api('/login', {'username': username, 'password': password})['csrf']
    assert api('/sites') == []
    viewer_client, viewer_csrf = client, csrf
    client, csrf = admin_client, admin_csrf
    assert reader(api(module + '/run', {}), username)['sessions'] >= 1
    payload = {'username': username, 'role': 'viewer', 'site_ids': [sites['allowed']],
               'menu_ids': grants, 'expected_revision': historical['revision']}
    result = api(module + '/update', payload)
    assert result == {'ok': True, 'username': username, 'action': 'update'}
    account = reader(api(module + '/run', {}), username)
    assert account['revision'] == historical['revision'] + 1 and account['site_ids'] == [sites['allowed']]
    assert account['sessions'] == 0 and set(account['menu_ids']) == set(grants)
    stale = api(module + '/update', {**payload, 'site_ids': [sites['other']]}, 409)
    assert stale.get('error') and reader(api(module + '/run', {}), username) == account
    client, csrf = viewer_client, viewer_csrf
    assert api('/me', expected=401).get('error')
    client = session()
    csrf = api('/login', {'username': username, 'password': password})['csrf']
    password = ''
    visible = api('/sites')
    assert [row['id'] for row in visible] == [sites['allowed']]
    assert api('/sites/' + sites['other'] + '/files', expected=403).get('error')
    assert api('/sites/' + sites['allowed'] + '/files/action',
               {'action': 'create', 'path': 'denied.txt', 'content': 'test'}, 403).get('error')
    api('/logout', {})
    client, csrf = admin_client, admin_csrf
    proof.update(ok=True, legacy_null_scope_read_without_rewrite=True, actual_site_scope_enforced=True,
                 stale_revision_refused=True, original_session_revoked=True, viewer_write_denied=True,
                 installed_job=installation['id'], registry_version=item['version'])
except BaseException:
    import traceback
    proof['failure'] = traceback.format_exc()
finally:
    if csrf:
        with contextlib.suppress(Exception):
            api('/logout', {})
    save('original-proof.json', proof)
sys.exit(0 if proof['ok'] else 1)
