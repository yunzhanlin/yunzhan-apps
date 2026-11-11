"""Prove existing OpenLiteSpeed WebAdmin rotation and data survive a signed upgrade."""

import contextlib
import hashlib
import http.client
import http.cookiejar
import http.cookies
import json
import os
import pathlib
import platform
import re
import secrets
import socket
import ssl
import stat
import subprocess
import sys
import time
import traceback
import urllib.parse
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
web, admin = 26574, 26575
origin = 'http://127.0.0.1:19100'
csrf = ''
generated, rotated, fresh_password = '', '', ''
proof = {'ok': False, 'architecture': arch, 'kernel': platform.release(),
         'Main_changed': False, 'all50_commercial': False}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise AssertionError('Unexpected local panel redirect')


client = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
                                    urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))


def save(name, value):
    with (work / (name + '.json')).open('x') as file:
        json.dump(value, file, indent=2)


def api(path, payload=None, expected=200, idempotency=None):
    headers = {'Origin': origin, 'Content-Type': 'application/json', 'X-CSRF-Token': csrf}
    if idempotency:
        headers['Idempotency-Key'] = idempotency
    body = json.dumps(payload).encode() if payload is not None else None
    with client.open(urllib.request.Request(origin + '/api' + path, body, headers), timeout=65) as response:
        assert response.status == expected
        raw = response.read(6 << 20)
        return json.loads(raw) if raw else {}, response.headers


def login():
    a = json.loads(pathlib.Path('/etc/panel/first-login.json').read_bytes())
    return api('/login', {k: a[k] for k in ('username', 'password')})[0]['csrf']


def signed_catalogue():
    for attempt, delay in enumerate((10, 65, 65, 0), 1):
        try:
            catalog, _ = api('/app-registry?refresh=1')
            assert catalog['host'] == {'platform': 'ubuntu-24.04', 'architecture': arch}
            assert not catalog['source']['stale'] and len(catalog['catalog']['apps']) == 50
            return catalog
        except urllib.error.HTTPError as error:
            body = error.read(4096).decode(errors='replace')
            save('original-catalogue-read-failure-' + str(attempt), {'status': error.code, 'body': body})
            if error.code != 503 or not delay:
                raise
            time.sleep(delay)


def wait(label, read, condition, limit=240):
    until = time.monotonic() + limit
    while True:
        value = read()
        if condition(value):
            return value
        if time.monotonic() >= until:
            raise AssertionError(label + ' did not reach its expected state')
        time.sleep(2)


def job(accepted, project):
    job_id = accepted['job_id']
    assert re.fullmatch('[a-f0-9]{32}', job_id) and accepted['project_id'] == project
    current = wait('original Compose job', lambda: api('/docker/job-observations/' + job_id)[0],
                   lambda v: v['state'] in ('succeeded', 'failed'), 600)
    assert current['state'] == 'succeeded' and current['project_id'] == project
    return job_id


def project_ready(project):
    def read():
        return next((v for v in api('/docker/projects')[0]['projects'] if v['id'] == project), None)
    return wait('original OpenLiteSpeed project', read, lambda v: v and v['state'] == 'running' and v['healthy'] == 1)


def docker(*args, stdin=None):
    result = subprocess.run(['/usr/bin/docker', *args], input=stdin, capture_output=True, timeout=60)
    assert result.returncode == 0, 'Docker observation or test command failed'
    return result.stdout


def file_state(path):
    f = pathlib.Path(path)
    info = f.lstat()
    assert stat.S_ISREG(info.st_mode) and info.st_nlink == 1
    return {'sha256': hashlib.sha256(f.read_bytes()).hexdigest(), 'device': info.st_dev,
            'inode': info.st_ino, 'mode': stat.S_IMODE(info.st_mode), 'uid': info.st_uid}


def container_state(project):
    ids = docker('ps', '-aq', '--filter', 'label=com.docker.compose.project=panel_' + project[:12]).decode().splitlines()
    cid, = ids
    assert re.fullmatch('[a-f0-9]{12,64}', cid)
    c, = json.loads(docker('inspect', cid))
    assert c['State']['Running'] and c['State']['Health']['Status'] == 'healthy'
    assert c['Config']['Image'] == plan['image'] and c['HostConfig']['Privileged'] is False
    assert c['HostConfig']['PortBindings'] == {
        '8088/tcp': [{'HostIp': '127.0.0.1', 'HostPort': str(web)}],
        '7080/tcp': [{'HostIp': '127.0.0.1', 'HostPort': str(admin)}],
    }
    image, = json.loads(docker('image', 'inspect', c['Image']))
    assert image['Architecture'] == arch
    volumes = {}
    for mount in c['Mounts']:
        assert mount['Type'] == 'volume' and mount['RW']
        st = pathlib.Path(mount['Source']).lstat()
        assert stat.S_ISDIR(st.st_mode)
        volumes[mount['Destination']] = {
            'name': mount['Name'], 'device': st.st_dev, 'inode': st.st_ino, 'source': mount['Source'],
        }
    for target in ('/usr/local/lsws/conf', '/usr/local/lsws/admin/conf', '/var/www/vhosts'):
        assert target in volumes
    passwd = pathlib.Path(volumes['/usr/local/lsws/admin/conf']['source']) / 'htpasswd'
    return {'container': c['Id'], 'pid': c['State']['Pid'], 'image': c['Image'],
            'volumes': volumes, 'credential_file': file_state(passwd)}


def public_page(path, expected):
    with contextlib.closing(http.client.HTTPConnection('127.0.0.1', web, timeout=10)) as conn:
        conn.request('GET', path)
        response = conn.getresponse()
        assert response.status == 200 and response.read(65536) == expected


def webadmin_login(container, password, success):
    pem = docker('exec', container, '/bin/cat', '/usr/local/lsws/admin/conf/webadmin.crt')
    # This test trusts only the original public certificate from its own
    # container. Connections are forced to the original local Docker port.
    cert = subprocess.run(['/usr/bin/openssl', 'x509', '-noout', '-subject', '-nameopt', 'RFC2253'],
                          input=pem, capture_output=True, check=True, timeout=10).stdout.decode()
    match = re.search(r'(?:^|[=,])\s*CN=([A-Za-z0-9.-]+)(?:,|\s|$)', cert)
    assert match, 'Cannot identify the WebAdmin certificate DNS name'
    host = match.group(1)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cadata=pem.decode('ascii'))
    cert_der = ssl.PEM_cert_to_DER_cert(pem.decode('ascii'))

    class WebAdminHTTPS(http.client.HTTPSConnection):
        def connect(self):
            raw = socket.create_connection(('127.0.0.1', self.port), timeout=10)
            self.sock = context.wrap_socket(raw, server_hostname=host)
            assert self.sock.getpeercert(binary_form=True) == cert_der

    jar = http.cookies.SimpleCookie()
    referer = f'https://{host}:{admin}/login.php'

    def request(method, path, data=None):
        headers = {'Referer': referer, 'Host': f'{host}:{admin}'}
        if data is not None:
            headers['Content-Type'] = 'application/x-www-form-urlencoded'
        if jar:
            headers['Cookie'] = '; '.join(f'{k}={v.coded_value}' for k, v in jar.items())
        with contextlib.closing(WebAdminHTTPS(host, admin, timeout=10, context=context)) as conn:
            conn.request(method, path, data, headers)
            response = conn.getresponse()
            for name, value in response.getheaders():
                if name.lower() == 'set-cookie':
                    jar.load(value)
            return response.status, response.getheader('Location'), response.read(1 << 20)

    code, _, raw = request('GET', '/login.php')
    assert code == 200 and b'name="userid"' in raw
    form = urllib.parse.urlencode({'userid': 'admin', 'pass': password}).encode()
    code, location, raw = request('POST', '/login.php', form)
    if success:
        assert code in (301, 302, 303) and location
        destination = urllib.parse.urlsplit(urllib.parse.urljoin(referer, location))
        assert (destination.scheme, destination.netloc, destination.path, destination.query) == (
            'https', f'{host}:{admin}', '/index.php', '')
        index, _, html = request('GET', destination.path)
        assert index == 200 and b'name="userid"' not in html
    else:
        assert code == 200 and b'name="userid"' in raw
    return hashlib.sha256(cert_der).hexdigest()


def apply_signed_upgrade():
    files = upgrade['release_assets']
    archive = upgrade['cohorts'][arch]['archive']
    expected = [archive + suffix for suffix in ('', '.manifest', '.sig')] + ['release-signing-dev.pub']
    assert {p.name for p in upgrade_assets.iterdir()} == set(expected)
    owned = pathlib.Path('/var/lib') / ('c74-release-' + secrets.token_hex(16))
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
    current = pathlib.Path('/opt/panel/current').resolve(strict=True)
    assert current.name == plan['version']
    csrf = login()
    catalog = signed_catalogue()
    status = next(v for v in catalog['status'] if v['id'] == 'openlitespeed')
    assert status['supported'] and not status['installed']
    item = next(v for v in catalog['catalog']['apps'] if v['id'] == 'openlitespeed')
    assert all(item[k] == v for k, v in plan['application'].items())
    key = secrets.token_hex(16)
    accepted, _ = api('/app-registry/openlitespeed/install', {
        'name': 'c74-original-ols-' + key[:8], 'host_port': web,
        'expected_version': item['version'], 'expected_sha256': item['sha256'],
    }, 202, key)
    project = accepted['project_id']
    proof['original_signed_install'] = job(accepted, project)
    project_ready(project)
    start = container_state(project)
    credentials, headers = api('/docker/projects/' + project + '/credentials', {})
    assert credentials['project_id'] == project and headers['Cache-Control'] == 'no-store'
    generated = credentials['credentials']['CLOUDSTACK_ADMIN_PASSWORD']
    assert len(generated) >= 24
    cert = webadmin_login(start['container'], generated, True)
    webadmin_login(start['container'], secrets.token_urlsafe(24), False)

    body = ('owned OpenLiteSpeed test page ' + key + '\n').encode()
    test_path = '/yunzhan-owned-' + key + '.html'
    docker('exec', '-i', start['container'], '/bin/sh', '-c',
           'umask 022; cat > /var/www/vhosts/cloudstack/html' + test_path, stdin=body)
    public_page(test_path, body)
    rotated = secrets.token_urlsafe(30)
    rotate = b"""set -eu
IFS= read -r new_password
p=/usr/local/lsws/admin
hash=$("$p/fcgi-bin/admin_php" -q "$p/misc/htpasswd.php" "$new_password")
[ -n "$hash" ]
printf 'admin:%s\n' "$hash" > "$p/conf/htpasswd"
chmod 600 "$p/conf/htpasswd"
"""
    docker('exec', '-i', start['container'], '/bin/sh', '-c', rotate.decode(), stdin=(rotated + '\n').encode())
    assert webadmin_login(start['container'], rotated, True) == cert
    webadmin_login(start['container'], generated, False)
    before = container_state(project)
    assert before['credential_file']['sha256'] != start['credential_file']['sha256']
    save('original-rotated-before-upgrade', before)

    directory = pathlib.Path('/etc/panel/compose') / project
    original = file_state(directory / 'compose.yaml')
    api('/logout', {})
    csrf = ''
    apply_signed_upgrade()
    assert container_state(project) == before
    assert file_state(directory / 'compose.yaml') == original
    csrf = login()

    restart, _ = api('/docker/projects/' + project + '/restart', {}, 202)
    proof['original_legacy_restart'] = job(restart, project)
    project_ready(project)
    applied = container_state(project)
    assert applied['container'] != before['container'] and applied['image'] == before['image']
    assert applied['volumes'] == before['volumes'] and applied['credential_file'] == before['credential_file']
    backup = file_state(directory / 'compose.before-webadmin-init.yaml')
    assert backup['sha256'] == original['sha256'] and backup['uid'] == 0 and backup['mode'] == 0o600
    actual = file_state(directory / 'compose.yaml')
    assert actual['sha256'] != original['sha256']
    assert webadmin_login(applied['container'], rotated, True) == cert
    webadmin_login(applied['container'], generated, False)
    public_page(test_path, body)

    followup, _ = api('/docker/projects/' + project + '/restart', {}, 202)
    proof['original_restart_after_migration'] = job(followup, project)
    project_ready(project)
    after = container_state(project)
    assert after['container'] == applied['container'] and after['pid'] != applied['pid']
    assert after['credential_file'] == applied['credential_file'] and after['volumes'] == applied['volumes']
    assert file_state(directory / 'compose.yaml') == actual and file_state(directory / 'compose.before-webadmin-init.yaml') == backup
    assert webadmin_login(after['container'], rotated, True) == cert
    public_page(test_path, body)
    save('original-migration-retained-state', {'before': before, 'applied': applied, 'after': after, 'original_source_backup': backup})

    web, admin = 26576, 26577
    key = secrets.token_hex(16)
    fresh, _ = api('/docker/projects', {
        'name': 'c74-new-ols-' + key[:8], 'template_id': 'openlitespeed', 'host_port': web,
    }, 202, key)
    fresh_id = fresh['project_id']
    proof['fresh_template_install'] = job(fresh, fresh_id)
    project_ready(fresh_id)
    fresh_before = container_state(fresh_id)
    assert {v['name'] for v in fresh_before['volumes'].values()}.isdisjoint(
        v['name'] for v in before['volumes'].values())
    fresh_config = pathlib.Path(fresh_before['volumes']['/usr/local/lsws/admin/conf']['source'])
    assert not os.path.lexists(fresh_config / '.yunzhan-admin-initializing')
    creds, headers = api('/docker/projects/' + fresh_id + '/credentials', {})
    assert creds['project_id'] == fresh_id and headers['Cache-Control'] == 'no-store'
    fresh_password = creds['credentials']['CLOUDSTACK_ADMIN_PASSWORD']
    assert len(fresh_password) >= 24 and fresh_password not in (generated, rotated)
    fresh_cert = webadmin_login(fresh_before['container'], fresh_password, True)
    webadmin_login(fresh_before['container'], generated, False)
    fresh_restart, _ = api('/docker/projects/' + fresh_id + '/restart', {}, 202)
    proof['fresh_restart'] = job(fresh_restart, fresh_id)
    project_ready(fresh_id)
    fresh_after = container_state(fresh_id)
    assert fresh_after['container'] == fresh_before['container'] and fresh_after['pid'] != fresh_before['pid']
    assert fresh_after['credential_file'] == fresh_before['credential_file'] and fresh_after['volumes'] == fresh_before['volumes']
    assert webadmin_login(fresh_after['container'], fresh_password, True) == fresh_cert
    proof.update(ok=True, migrated_one_legacy_container=True, original_three_named_volumes_preserved=True,
                 old_credentials_refused=True, rotated_credential_file_and_https_session_preserved=True,
                 original_website_data_unchanged=True, later_restart_does_not_repeat_migration=True,
                 fresh_webadmin_initialized_once=True)
except BaseException:
    detail = traceback.format_exc()
    for value in (generated, rotated, fresh_password):
        if value:
            detail = detail.replace(value, '[private]')
    proof['failure'] = detail
finally:
    if csrf:
        with contextlib.suppress(Exception):
            api('/logout', {})
    save('original-proof', proof)
sys.exit(0 if proof['ok'] else 1)
