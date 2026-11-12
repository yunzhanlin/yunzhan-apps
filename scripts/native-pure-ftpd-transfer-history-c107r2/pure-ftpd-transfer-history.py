"""Exercise real FTPS and the signed, scoped history reader."""
import contextlib
import ftplib
import io
import hashlib
import http.cookiejar
import json
import os
from pathlib import Path
import platform
import re
import secrets
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
from urllib.parse import urlencode

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


module = '/app-modules/pure-ftpd'
registry = '/app-registry/pure-ftpd'
unit = 'panel-pure-ftpd.service'
private = Path('/etc/panel/security-apps/modules/pure-ftpd')
version = '1.0.54-compat7'
proof = {'ok': False, 'architecture': arch, 'source_inputs_sha256': plan['source_inputs_sha256'],
         'Main_changed': False, 'all50_commercial': False}


def identities(site, filename):
    state = subprocess.check_output(['/usr/bin/systemctl', 'show', unit,
        '--property=MainPID,InvocationID,ExecMainStartTimestampMonotonic'], text=True, timeout=12)
    assert re.search(r'^MainPID=[1-9][0-9]*$', state, re.M)
    files = {name: hashlib.sha256((private / name).read_bytes()).hexdigest()
        for name in ('users.passwd', 'users.pdb', 'server.pem', 'runtime.json')}
    content = Path('/srv/panel/sites') / site / 'public' / filename
    assert content.is_file() and not content.is_symlink()
    return {'daemon': state, 'files': files, 'site_sha256': hashlib.sha256(content.read_bytes()).hexdigest()}


def real_journal(filename):
    raw = subprocess.check_output(['/usr/bin/journalctl', '--quiet', '--no-pager', '--reverse', '--output=json',
        '--output-fields=__REALTIME_TIMESTAMP,_SYSTEMD_UNIT,_EXE,SYSLOG_IDENTIFIER,_TRANSPORT,MESSAGE',
        '-n', '120', '_SYSTEMD_UNIT=' + unit, '_TRANSPORT=syslog', 'SYSLOG_IDENTIFIER=pure-ftpd', 'PRIORITY=5'],
        timeout=10)
    assert len(raw) < 1 << 20
    result = [json.loads(line) for line in raw.splitlines()]
    return [row for row in result if isinstance(row.get('MESSAGE'), str) and filename in row['MESSAGE']]


try:
    login = json.loads(Path('/etc/panel/first-login.json').read_bytes())
    csrf = api('/login', {key: login[key] for key in ('username', 'password')})['csrf']
    login.clear()
    item = plan['items']['pure-ftpd']
    baseline = catalogue()['pure-ftpd']
    assert baseline['state_known'] and baseline['supported'] and not baseline['installed']
    update = plan['mode'] == 'signed-ftp-history-update'
    if update:
        assert item['version'] == version
        _, installed = job('install-legacy-pure-ftpd', '/software/pure-ftpd/install', {})
    else:
        assert plan['mode'] == 'old-signed-ftps-transfer' and item['version'] == '1.0.54-compat6'
        _, installed = job('install-signed-pure-ftpd', registry + '/install',
                           {'expected_version': item['version'], 'expected_sha256': item['sha256']})
    prior_version = api(module)['status']['version']
    assert prior_version == '1.0.54-compat6'
    _, created = job('create-ftp-site', '/sites',
                     {'name': 'C107 FTPS history fixture', 'slug': 'c107-ftp', 'domain': 'c107-ftp.example.test'}, 300)
    site = created['site_id']
    assert re.fullmatch('[a-f0-9]{32}', site)
    user = 'qa-ftp-' + secrets.token_hex(4)
    password = 'C107-' + secrets.token_urlsafe(28)
    api(module + '/create', {'site_id': site, 'username': user, 'password': password})
    pem, = re.findall(r'-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----', (private / 'server.pem').read_text())
    tls = ssl.create_default_context(cadata=pem)
    filename = 'c107-owned-report.txt'
    payload = b'Signed FTPS dual channel transfer fixture\n' * 451
    sha = hashlib.sha256(payload).hexdigest()
    with ftplib.FTP_TLS(context=tls, timeout=20) as ftp:
        ftp.connect('127.0.0.1', 2121)
        ftp.login(user, password)
        password = ''
        ftp.prot_p()
        ftp.storbinary('STOR ' + filename, io.BytesIO(payload))
        original = io.BytesIO()
        ftp.retrbinary('RETR ' + filename, original.write)
        assert original.getvalue() == payload
        observed = wait(lambda: real_journal(filename), lambda rows: len(rows) == 2, 15)
        assert all(row['_EXE'] == '/opt/panel/app-modules/pure-ftpd/1.0.54-yz1/pure-ftpd' for row in observed)
        save('original-live-ftps-journal.json', observed)
        expected = {'site_id': site, 'username': user, 'minutes': 60}
        assert api(module + '/transfers?' + urlencode(expected), expected=409)['error']
        identity = identities(site, filename)
        assert identity['site_sha256'] == sha
        old_receipt = json.loads((private / 'installed.json').read_bytes())
        if update:
            eligible = catalogue()['pure-ftpd']
            assert eligible['installed_version'] == prior_version and eligible['update_available'] and eligible['update_supported']
            _, updated = job('update-ftp-history', registry + '/update',
                             {'expected_version': item['version'], 'expected_sha256': item['sha256']})
            assert updated['kind'] == 'software_update'
            new_receipt = json.loads((private / 'installed.json').read_bytes())
            assert new_receipt.pop('version') == version and new_receipt.pop('updated_at')
            assert old_receipt.pop('version') == prior_version and new_receipt == old_receipt
            assert identities(site, filename) == identity and ftp.pwd() == '/'
            old_range = api(module + '/transfers?' + urlencode(expected))
            assert len(old_range['events']) == 2 and not old_range['has_more']
            assert {row['direction'] for row in old_range['events']} == {'upload', 'download'}
            for row in old_range['events']:
                assert row['site_id'] == site and row['username'] == user and row['client_ip'] == '127.0.0.1'
                assert row['path'] == '/' + filename and int(row['bytes']) == len(payload)
            read_one = api(module + '/transfers?' + urlencode({**expected, 'direction': 'upload', 'limit': 1}))
            assert len(read_one['events']) == 1 and read_one['events'][0]['direction'] == 'upload'
            no_match = api(module + '/transfers?' + urlencode({**expected, 'username': 'other-test-account'}))
            assert no_match['events'] == []
            assert api(module + '/transfers?limit=999', expected=400)['error']
            save('original-app-transfer-report.json', old_range)
            assert not catalogue()['pure-ftpd']['update_available']
            proof['signed_update'] = {'job': updated['id'], 'version': version, 'manifest_sha256': item['sha256']}
            proof['actual_retained_journal_history'] = True
            proof['exact_account_site_direction_filters'] = True
            proof['original_ftps_connection_and_data_preserved'] = True
        ftp.quit()
    proof.update(ok=True, registry_version=item['version'], installed_job=installed['id'],
                 original_actual_ftps=True, previous_version_history_guard_verified=True)
except BaseException:
    import traceback
    proof['failure'] = traceback.format_exc()
finally:
    if csrf:
        with contextlib.suppress(Exception):
            api('/logout', {})
    save('original-proof.json', proof)
sys.exit(0 if proof['ok'] else 1)
