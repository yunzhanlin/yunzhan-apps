"""Exercise the official patched website and WebAdmin components."""
import contextlib
import hashlib
import http.client
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
import urllib.parse

assert os.environ['GITHUB_ACTIONS'] == 'true' and os.environ['GITHUB_REPOSITORY'] == 'yunzhanlin/yunzhan-apps'
arch = {'x86_64': 'amd64', 'aarch64': 'arm64'}[platform.machine()]
out = Path(os.environ['RUNNER_TEMP']) / 'c92-ols-php83-proof'
out.mkdir(mode=0o700)
image = 'local/c92-ols-php83:verified'
name = 'c92-ols-php83'
web, admin = 27081, 27082
bootstrap = Path(sys.argv[1]).read_text()
password = secrets.token_urlsafe(28)
assert 'exec /entrypoint.sh' in bootstrap and 'CLOUDSTACK_ADMIN_PASSWORD' in bootstrap
pins = {
    'amd64': ('5.6.40', 'e9716e3c929865087009bea3c922768ed9be0034eef71cc0e0925779bfb66c60',
              '66f18009f001759988bf8210bc60221d1bb6168f64b747f943e1061eac9aa307'),
    'arm64': ('7.4.30', 'b6b0c67bada79e6c38e1c7d5e91977283595d6c2e1ab7b6482bb793c9d4303c6',
              '2a00823656f6054605d1052581a0b1148e0b9a4c7954cbc5c82916a1d9d349d2'),
}
admin_version, admin_digest, server_digest = pins[arch]


def docker(*arguments, data=None, env=None):
    return subprocess.run(['/usr/bin/docker', *arguments], input=data, env=env,
                          capture_output=True, check=True, timeout=90).stdout


def get_page(path):
    with contextlib.closing(http.client.HTTPConnection('127.0.0.1', web, timeout=10)) as conn:
        conn.request('GET', path)
        response = conn.getresponse()
        return response.status, response.read(1 << 20)


def put_file(path, payload):
    docker('exec', '-i', name, '/bin/sh', '-c', 'umask 022; cat > "$1"', '--', path, data=payload)


def webadmin(password, expected, probe):
    pem = docker('exec', name, '/bin/cat', '/usr/local/lsws/admin/conf/webadmin.crt')
    subject = subprocess.run(['/usr/bin/openssl', 'x509', '-noout', '-subject', '-nameopt', 'RFC2253'],
                             input=pem, capture_output=True, check=True, timeout=10).stdout.decode()
    host = re.search(r'(?:^|[=,])\s*CN=([A-Za-z0-9.-]+)(?:,|\s|$)', subject)[1]
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cadata=pem.decode('ascii'))
    cert = ssl.PEM_cert_to_DER_cert(pem.decode('ascii'))
    authority = f'{host}:{admin}'
    referer = f'https://{authority}/login.php'
    jar = http.cookies.SimpleCookie()

    class Connection(http.client.HTTPSConnection):
        def connect(self):
            raw = socket.create_connection(('127.0.0.1', self.port), timeout=10)
            self.sock = context.wrap_socket(raw, server_hostname=host)
            assert self.sock.getpeercert(binary_form=True) == cert

    def request(method, path, data=None):
        headers = {'Referer': referer, 'Host': authority}
        if data is not None:
            headers['Content-Type'] = 'application/x-www-form-urlencoded'
        if jar:
            headers['Cookie'] = '; '.join(f'{key}={value.coded_value}' for key, value in jar.items())
        with contextlib.closing(Connection(host, admin, timeout=10, context=context)) as conn:
            conn.request(method, path, data, headers)
            response = conn.getresponse()
            for key, value in response.getheaders():
                if key.lower() == 'set-cookie':
                    jar.load(value)
            return response.status, response.getheader('Location'), response.read(1 << 20)

    code, _, body = request('GET', '/login.php')
    if expected is None:
        root_code, _, root_page = request('GET', '/')
        disabled_notice = b'webadmin console is disabled' in root_page.lower()
        assert b'name="userid"' not in body and (code in (403, 404) or disabled_notice)
        proof['disabled_admin_original_http'] = {'login': code, 'root': root_code, 'notice': disabled_notice}
        return None
    assert code == 200 and b'name="userid"' in body, (code, hashlib.sha256(body).hexdigest())
    data = urllib.parse.urlencode({'userid': 'admin', 'pass': password}).encode()
    code, location, body = request('POST', '/login.php', data)
    if not expected:
        assert code == 200 and b'name="userid"' in body
        return None
    assert code in (301, 302, 303) and location
    destination = urllib.parse.urlsplit(urllib.parse.urljoin(referer, location))
    assert (destination.scheme, destination.netloc, destination.path) == ('https', authority, '/index.php')
    index_code, _, html = request('GET', destination.path)
    assert index_code == 200 and b'name="userid"' not in html
    probe_code, _, body = request('GET', probe)
    assert probe_code == 200 and body == (admin_version + '|litespeed').encode()
    return hashlib.sha256(cert).hexdigest()


proof = {'ok': False, 'architecture': arch, 'tested_website_php': '8.3.36', 'Main_changed': False}
try:
    assert docker('image', 'inspect', '-f', '{{.Os}}/{{.Architecture}}', image).strip() == ('linux/' + arch).encode()
    docker('run', '-d', '--name', name, '--entrypoint', '/bin/sh',
           '--memory', '512m', '--publish', f'127.0.0.1:{web}:8088', '--publish', f'127.0.0.1:{admin}:7080',
           '--mount', 'type=volume,source=c92-ols-admin,target=/usr/local/lsws/admin/conf,volume-nocopy',
           '--mount', 'type=volume,source=c92-ols-server,target=/usr/local/lsws/conf',
           '--mount', 'type=volume,source=c92-ols-site,target=/var/www/vhosts',
           '--env', 'CLOUDSTACK_ADMIN_PASSWORD', image, '-c', bootstrap,
           env={**os.environ, 'CLOUDSTACK_ADMIN_PASSWORD': password})
    for _ in range(60):
        try:
            if get_page('/')[0] == 200:
                break
        except (OSError, http.client.HTTPException):
            pass
        time.sleep(1)
    else:
        raise RuntimeError('Patched image did not serve a website')
    probe = '/c92-native-' + secrets.token_hex(6) + '.php'
    payload = b'<?php header("Content-Type: text/plain"); echo PHP_VERSION."|".PHP_SAPI;'
    put_file('/var/www/vhosts/cloudstack/html' + probe, payload)
    assert get_page(probe) == (200, b'8.3.36|litespeed')
    actual_admin = docker('exec', name, 'sha256sum', '/usr/local/lsws/admin/fcgi-bin/admin_php').split()[0].decode()
    actual_server = docker('exec', name, 'sha256sum', '/usr/local/lsws/bin/openlitespeed').split()[0].decode()
    assert actual_admin == admin_digest and actual_server == server_digest, (actual_admin, actual_server)
    proof.update(official_v194_admin_sha256=admin_digest, official_v194_server_sha256=server_digest)
    assert webadmin(password, None, probe) is None
    credential_path = '/usr/local/lsws/admin/conf/htpasswd'
    credential = docker('exec', name, 'sha256sum', credential_path)
    docker('exec', name, '/bin/sh', '-c', 'set -eC; umask 077; : > /usr/local/lsws/admin/conf/enable_webadmin')
    docker('restart', name)
    assert docker('exec', name, 'sha256sum', credential_path) == credential
    for _ in range(30):
        try:
            if get_page(probe) == (200, b'8.3.36|litespeed'):
                break
        except (OSError, http.client.HTTPException):
            pass
        time.sleep(1)
    else:
        raise RuntimeError('The original site did not recover after WebAdmin activation')
    put_file('/usr/local/lsws/admin/html' + probe, payload)
    cert = webadmin(password, True, probe)
    assert webadmin(secrets.token_urlsafe(24), False, probe) is None
    assert get_page(probe) == (200, b'8.3.36|litespeed')
    proof.update(ok=True, website_http=True, actual_webadmin_https=True, webadmin_php_version=admin_version,
                 original_default_admin_disabled=True, admin_activation_retained_credential_and_site_data=True,
                 invalid_password_refused=True, webadmin_certificate_sha256=cert)
finally:
    with (out / 'original-proof.json').open('x') as f:
        json.dump(proof, f, indent=2)
        f.write('\n')
assert proof['ok']
