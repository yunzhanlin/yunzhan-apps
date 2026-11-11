"""Exercise the signed panel's actual TLS peer error with a unit-scoped CONNECT test peer."""

import contextlib
import json
import os
from pathlib import Path
import platform
import selectors
import socket
import socketserver
import ssl
import stat
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request
import sys

os.umask(0o077)
assert os.geteuid() == 0 and os.environ['GITHUB_ACTIONS'] == 'true'
assert os.environ['GITHUB_REPOSITORY'] == 'yunzhanlin/yunzhan-apps'
out = Path(sys.argv[1]) / 'business-phase1'
out.mkdir(mode=0o700)
plan = json.loads((Path(__file__).resolve().parent / 'cohort.json').read_bytes())
arch = {'x86_64': 'amd64', 'aarch64': 'arm64'}[platform.machine()]
assert json.loads(Path('/opt/panel/current/SOURCE_INPUTS.json').read_bytes())['inputs_sha256'] == plan['source_inputs_sha256']
assert plan['mode'] == 'native-reference'
origin = 'http://127.0.0.1:19100'
proof = {'ok': False, 'architecture': arch, 'source_inputs_sha256': plan['source_inputs_sha256'],
         'Main_changed': False, 'all50_commercial': False}

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise RuntimeError('Unexpected loopback redirect')

def session():
    import http.cookiejar
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
                                       urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

def api(client, path, data=None, csrf=''):
    headers = {'Origin': origin, 'Content-Type': 'application/json', 'X-CSRF-Token': csrf}
    body = None if data is None else json.dumps(data).encode()
    with client.open(urllib.request.Request(origin + '/api' + path, body, headers), timeout=45) as r:
        assert r.status == 200
        return json.loads(r.read(6 << 20))

def start_panel():
    for args in (('daemon-reload',), ('restart', 'panel.service')):
        subprocess.run(['/usr/bin/systemctl', *args], check=True, timeout=45, capture_output=True)
    cutoff = time.monotonic() + 45
    while time.monotonic() < cutoff:
        try:
            if api(session(), '/health')['status'] == 'ok':
                return
        except urllib.error.URLError:
            pass
        time.sleep(0.4)
    raise AssertionError('The signed panel did not come back online')

def check_catalogue(transport=None):
    client = session()
    csrf = ''
    try:
        access = json.loads(Path('/etc/panel/first-login.json').read_bytes())
        csrf = api(client, '/login', {k: access[k] for k in ('username','password')})['csrf']
        access.clear()
        for delay in (2, 7, 18, 0):
            try:
                catalog = api(client, '/app-registry?refresh=1')
                break
            except urllib.error.HTTPError as error:
                if error.code != 503 or not delay:
                    raise
                time.sleep(delay)
        source = catalog['source']
        assert not source['stale'] and source['resolved_commit'] == plan['served_head']
        assert catalog['host'] == {'platform': 'ubuntu-24.04', 'architecture': arch}
        assert len(catalog['catalog']['apps']) == 50
        assert catalog['catalog']['repository'] == 'https://github.com/yunzhanlin/yunzhan-apps'
        task, = [item for item in catalog['catalog']['apps'] if item['id']=='task-manager']
        assert task == plan['items']['task-manager']
        if transport:
            assert source['reference_transport'] == transport
        return {'reference_transport': source['reference_transport'], 'commit': source['resolved_commit'], 'application_count': 50}
    finally:
        if csrf:
            with contextlib.suppress(Exception):
                api(client, '/logout', {}, csrf)

unit = Path('/run/systemd/system/panel.service.d')
dropin = unit / 'zz-c101-tls-fixture.conf'
owned_dropin = False
created_directory = False
try:
    with tempfile.TemporaryDirectory(prefix='c101-official-ref-', dir='/run') as temp:
        work = Path(temp)
        cert, key = work / 'test-cert.pem', work / 'test-key.pem'
        subprocess.run(['/usr/bin/openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1',
                        '-subj','/CN=c101-fixture.invalid','-out',str(cert),'-keyout',str(key)],
                       check=True, timeout=20, capture_output=True)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(cert), str(key))
        names = []
        tunneled = set()
        def alert(connection, name, config):
            names.append(name)
            return ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME
        context.set_servername_callback(alert)

        class Proxy(socketserver.BaseRequestHandler):
            def handle(self):
                client = self.request
                client.settimeout(8)
                try:
                    headers = b''
                    while b'\r\n\r\n' not in headers:
                        chunk = client.recv(2048)
                        if not chunk:
                            return
                        headers += chunk
                        if len(headers) > 8192:
                            return
                    method, target, version = headers.split(b'\r\n', 1)[0].split()
                    if method != b'CONNECT' or version not in (b'HTTP/1.0', b'HTTP/1.1'):
                        return
                    if target == b'api.github.com:443':
                        client.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')
                        with contextlib.suppress(ssl.SSLError):
                            context.wrap_socket(client, server_side=True).close()
                        return
                    if target not in (b'github.com:443', b'raw.githubusercontent.com:443'):
                        return
                    hostname = target.decode().split(':', 1)[0]
                    with socket.create_connection((hostname, 443), timeout=12) as upstream:
                        tunneled.add(hostname)
                        upstream.settimeout(8)
                        client.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')
                        with selectors.DefaultSelector() as selector:
                            selector.register(client, selectors.EVENT_READ, upstream)
                            selector.register(upstream, selectors.EVENT_READ, client)
                            cutoff = time.monotonic() + 40
                            while time.monotonic() < cutoff:
                                for reader, _ in selector.select(timeout=2):
                                    raw = reader.fileobj.recv(65536)
                                    if not raw:
                                        return
                                    reader.data.sendall(raw)
                except (OSError, ValueError):
                    return

        class ProxyServer(socketserver.ThreadingTCPServer):
            daemon_threads = True

        server = ProxyServer(('127.0.0.1', 0), Proxy)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            original_hosts = Path('/etc/hosts').read_bytes()
            if not unit.exists():
                unit.mkdir(mode=0o755)
                created_directory = True
            status = unit.lstat()
            assert stat.S_ISDIR(status.st_mode) and status.st_uid == 0 and status.st_mode & 0o022 == 0
            with dropin.open('x') as f:
                owned_dropin = True
                f.write('[Service]\\nEnvironment=HTTPS_PROXY=http://127.0.0.1:' + str(port) +
                        '\\nEnvironment=NO_PROXY=127.0.0.1,localhost\\n')
            start_panel()
            first = check_catalogue('github-smart-http')
            second = check_catalogue('github-smart-http')
            assert first == second
            assert names == ['api.github.com'], names
            assert tunneled == {'github.com', 'raw.githubusercontent.com'}, tunneled
            assert Path('/etc/hosts').read_bytes() == original_hosts
            proof.update(actual_remote_tls_name_alert=True, cooldown_avoided_second_rest_handshake=True,
                         exact_official_commit_and_50_signed_apps=first, operating_system_hosts_unchanged=True)
        finally:
            try:
                if owned_dropin:
                    dropin.unlink()
                    if created_directory:
                        unit.rmdir()
                    start_panel()
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)
    assert not dropin.exists()
    restored = check_catalogue()
    proof.update(ok=True, scoped_fixture_removed=True, real_catalogue_after_removal=restored)
except BaseException:
    import traceback
    proof['failure'] = traceback.format_exc()
finally:
    with (out / 'original-proof.json').open('x') as f:
        json.dump(proof,f,indent=2)
        f.write('\n')
sys.exit(0 if proof['ok'] else 1)
