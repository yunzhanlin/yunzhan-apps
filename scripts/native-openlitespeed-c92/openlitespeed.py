"""Validate the signed OpenLiteSpeed 1.9.4 app and existing project together."""
import contextlib
import hashlib
import http.client
import http.cookiejar
import http.cookies
import json
import os
from pathlib import Path
import platform
import re
import secrets
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

os.umask(0o077)
assert os.geteuid() == 0 and os.environ['GITHUB_ACTIONS'] == 'true'
assert os.environ['GITHUB_REPOSITORY'] == 'yunzhanlin/yunzhan-apps'
out = Path(sys.argv[1]) / 'business-phase1'
out.mkdir(mode=0o700)
plan = json.loads(Path(__file__).with_name('cohort.json').read_bytes())
arch = {'x86_64': 'amd64', 'aarch64': 'arm64'}[platform.machine()]
source = json.loads(Path('/opt/panel/current/SOURCE_INPUTS.json').read_bytes())['inputs_sha256']
assert source == plan['source_inputs_sha256']
origin = 'http://127.0.0.1:19100'
csrf = ''
client = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                     urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
proof = {'ok': False, 'architecture': arch, 'source_inputs_sha256': source,
         'Main_changed': False, 'all50_commercial': False}


def api(path, data=None, status=200):
    headers = {'Origin': origin, 'Content-Type': 'application/json', 'X-CSRF-Token': csrf}
    if data is not None:
        headers['Idempotency-Key'] = secrets.token_hex(16)
    body = None if data is None else json.dumps(data).encode()
    with client.open(urllib.request.Request(origin + '/api' + path, body, headers), timeout=60) as response:
        assert response.status == status
        return json.loads(response.read(5 << 20))


def wait(read, ready, timeout=660):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = read()
        if ready(value):
            return value
        time.sleep(2)
    raise TimeoutError('OpenLiteSpeed job or health did not settle')


def job(route, data):
    response = api(route, data, 202)
    id = response['job_id']
    assert re.fullmatch('[a-f0-9]{32}', id)
    result = wait(lambda: api('/docker/job-observations/' + id),
                  lambda x: x['state'] in ('succeeded', 'failed', 'needs_attention'))
    assert result['state'] == 'succeeded', result.get('error')
    return response


def project_ready(id):
    return wait(lambda: next((p for p in api('/docker/projects')['projects'] if p['id'] == id), None),
                lambda p: p and p['state'] == 'running' and p['services'] == p['healthy'] == p['running'] == 1)


def docker(*arguments, data=None):
    return subprocess.run(['/usr/bin/docker', *arguments], input=data, capture_output=True, check=True, timeout=60).stdout


def inspect(project, image, web):
    id = docker('ps', '-aq', '--filter', 'label=com.docker.compose.project=' + project['engine_name']).decode().strip()
    assert re.fullmatch('[a-f0-9]{12,64}', id)
    record, = json.loads(docker('inspect', id))
    assert record['Config']['Image'] == image and not record['HostConfig']['Privileged']
    assert docker('image', 'inspect', '-f', '{{.Os}}/{{.Architecture}}', record['Image']).strip() == ('linux/' + arch).encode()
    assert record['HostConfig']['PortBindings'] == {
        '8088/tcp': [{'HostIp': '127.0.0.1', 'HostPort': str(web)}],
        '7080/tcp': [{'HostIp': '127.0.0.1', 'HostPort': str(web + 1)}],
    }
    assert {mount['Destination'] for mount in record['Mounts']} == {
        '/usr/local/lsws/conf', '/usr/local/lsws/admin/conf', '/var/www/vhosts',
    }
    assert all(mount['Type'] == 'volume' for mount in record['Mounts'])
    return record


def file(container, name):
    return docker('exec', container, '/bin/cat', '/usr/local/lsws/admin/conf/' + name)


def webadmin(container, port, password, expect=True):
    pem = file(container, 'webadmin.crt').decode('ascii')
    subject = subprocess.check_output(['/usr/bin/openssl', 'x509', '-noout', '-subject', '-nameopt', 'RFC2253'],
                                      input=pem.encode(), timeout=10).decode()
    host = re.search(r'(?:^|[=,])\s*CN=([A-Za-z0-9.-]+)(?:,|\s|$)', subject)[1]
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    tls.load_verify_locations(cadata=pem)
    cert = ssl.PEM_cert_to_DER_cert(pem)

    class HTTPS(http.client.HTTPSConnection):
        def connect(self):
            raw = socket.create_connection(('127.0.0.1', self.port), timeout=10)
            self.sock = tls.wrap_socket(raw, server_hostname=host)
            assert self.sock.getpeercert(binary_form=True) == cert

    jar = http.cookies.SimpleCookie()
    referer = f'https://{host}:{port}/login.php'

    def request(method, path, data=None):
        headers = {'Referer': referer, 'Host': f'{host}:{port}'}
        if data is not None:
            headers['Content-Type'] = 'application/x-www-form-urlencoded'
        if jar:
            headers['Cookie'] = '; '.join(f'{key}={value.coded_value}' for key, value in jar.items())
        with contextlib.closing(HTTPS(host, port, timeout=10, context=tls)) as conn:
            conn.request(method, path, data, headers)
            r = conn.getresponse()
            for key, value in r.getheaders():
                if key.lower() == 'set-cookie':
                    jar.load(value)
            return r.status, r.getheader('Location'), r.read(1 << 20)

    code, _, body = request('GET', '/login.php')
    assert code == 200 and b'name="userid"' in body
    data = urllib.parse.urlencode({'userid': 'admin', 'pass': password}).encode()
    code, destination, body = request('POST', '/login.php', data)
    if expect:
        assert code in (301, 302, 303)
        assert urllib.parse.urljoin(referer, destination) == f'https://{host}:{port}/index.php'
        code, _, index = request('GET', '/index.php')
        assert code == 200 and b'name="userid"' not in index
    else:
        assert code == 200 and b'name="userid"' in body
    return hashlib.sha256(cert).hexdigest()


def configure_site(container, path, content):
    docker('exec', '-i', container, '/bin/sh', '-c', 'umask 022; cat > "$1"', '--',
           '/var/www/vhosts/cloudstack/html' + path, data=content)


def site(port, path, content):
    with client.open(f'http://127.0.0.1:{port}{path}', timeout=20) as response:
        assert response.status == 200 and response.read(1 << 20) == content


def read_catalogue():
    for delay in (15, 60, 0):
        try:
            return api('/app-registry?refresh=1')
        except urllib.error.HTTPError as error:
            if error.code != 503 or not delay:
                raise
            time.sleep(delay)


try:
    login = json.loads(Path('/etc/panel/first-login.json').read_bytes())
    csrf = api('/login', {key: login[key] for key in ('username', 'password')})['csrf']
    login.clear()
    old_job = job('/docker/projects', {'name': 'c92-original', 'template_id': 'openlitespeed', 'host_port': 27180, 'compose': ''})
    old_project = project_ready(old_job['project_id'])
    old = inspect(old_project, plan['previous_image'], 27180)
    old_credential = hashlib.sha256(file(old['Id'], 'htpasswd')).hexdigest()
    configure_site(old['Id'], '/retained.html', b'original-site\n')
    site(27180, '/retained.html', b'original-site\n')
    if plan['mode'] == 'signed-store':
        catalogue = read_catalogue()
        assert catalogue['source']['resolved_commit'] == plan['served_head'] and not catalogue['source']['stale']
        item, = [x for x in catalogue['catalog']['apps'] if x['id'] == 'openlitespeed']
        status, = [x for x in catalogue['status'] if x['id'] == 'openlitespeed']
        assert item == plan['item'] and status['supported'] and status['state_known'] and status['installed']
        assert status['update_available'] and status['update_supported'] and status['update_kind'] == 'compose-parallel'
        new_job = job('/app-registry/openlitespeed/install',
                      {'name': 'c92-secure', 'host_port': 27182, 'expected_version': item['version'], 'expected_sha256': item['sha256']})
    else:
        new_job = job('/docker/projects', {'name': 'c92-secure', 'template_id': 'openlitespeed-194', 'host_port': 27182, 'compose': ''})
    new = project_ready(new_job['project_id'])
    assert new['template_id'] == 'openlitespeed-194'
    current = inspect(new, plan['image'], 27182)
    paths = [set(m['Name'] for m in record['Mounts']) for record in (old, current)]
    assert len(paths[0]) == len(paths[1]) == 3 and paths[0].isdisjoint(paths[1])
    credential = api('/docker/projects/' + new['id'] + '/credentials', {})['credentials']['CLOUDSTACK_ADMIN_PASSWORD']
    assert re.fullmatch('[0-9a-f]{64}', credential)
    cert = webadmin(current['Id'], 27183, credential)
    webadmin(current['Id'], 27183, secrets.token_urlsafe(25), False)
    assert docker('exec', current['Id'], 'sha256sum', '/usr/local/lsws/admin/fcgi-bin/admin_php').split()[0].decode() == plan['admin_sha256'][arch]
    assert file(current['Id'], 'enable_webadmin') == b''
    new_credential = hashlib.sha256(file(current['Id'], 'htpasswd')).hexdigest()
    configure_site(current['Id'], '/native.php', b'<?php echo PHP_VERSION."|".PHP_SAPI;')
    site(27182, '/native.php', b'8.3.36|litespeed')
    domain = 'c92-openlitespeed.example.test'
    binding = api('/docker/projects/' + new['id'] + '/sites',
                  {'name': domain, 'slug': 'c92-openlitespeed', 'domain': domain}, 202)
    bound = wait(lambda: api('/jobs/' + binding['job_id']),
                 lambda x: x['state'] in ('succeeded', 'failed', 'needs_attention'))
    assert bound['state'] == 'succeeded' and bound['kind'] == 'create_site'
    request = urllib.request.Request('http://127.0.0.1:19101/native.php', headers={'Host': domain})
    with client.open(request, timeout=20) as response:
        assert response.status == 200 and response.read(1 << 20) == b'8.3.36|litespeed'
    def mount_identity(container):
        result = {m['Destination']: m for m in container['Mounts']}
        assert len(result) == len(container['Mounts'])
        return result

    restarted = job('/docker/projects/' + new['id'] + '/restart', {})
    after = inspect(project_ready(new['id']), plan['image'], 27182)
    identity = {
        'container_preserved': after['Id'] == current['Id'],
        'mounts_preserved': mount_identity(after) == mount_identity(current),
        'only_mount_order_differs': after['Mounts'] != current['Mounts'] and mount_identity(after) == mount_identity(current),
        'restart_observed': after['State']['StartedAt'] != current['State']['StartedAt'],
    }
    with (out / 'original-restart-identity.json').open('x') as f:
        json.dump(identity, f, indent=2)
    assert identity['container_preserved'] and identity['mounts_preserved'] and identity['restart_observed']
    assert hashlib.sha256(file(after['Id'], 'htpasswd')).hexdigest() == new_credential
    assert webadmin(after['Id'], 27183, credential) == cert
    site(27182, '/native.php', b'8.3.36|litespeed')
    retained = inspect(project_ready(old_project['id']), plan['previous_image'], 27180)
    assert retained['Id'] == old['Id'] and retained['State']['StartedAt'] == old['State']['StartedAt']
    assert mount_identity(retained) == mount_identity(old) and hashlib.sha256(file(retained['Id'], 'htpasswd')).hexdigest() == old_credential
    site(27180, '/retained.html', b'original-site\n')
    proof.update(ok=True, old_job=old_job['job_id'], new_job=new_job['job_id'], restart_job=restarted['job_id'],
                 official_admin_binary=True, actual_php_site=True, actual_https_webadmin=True,
                 actual_managed_domain_php=True, binding_job=binding['job_id'],
                 restart_retained_new_site_and_credentials=True, original_project_retained=True,
                 signed_store_install=plan['mode']=='signed-store')
finally:
    if csrf:
        api('/logout', {})
    with (out / 'original-proof.json').open('x') as f:
        json.dump(proof, f, indent=2)
        f.write('\n')
assert proof['ok']
