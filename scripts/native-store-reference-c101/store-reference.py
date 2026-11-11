"""Exercise the signed panel's actual TLS peer error with a unit-scoped test resolver."""

import contextlib
import json
import os
from pathlib import Path
import platform
import re
import socket
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
    with tempfile.TemporaryDirectory(prefix='c101-official-ref-', dir='/run') as temp, \
            socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        work = Path(temp)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(('127.0.0.77', 443))
        listener.listen(8)
        listener.settimeout(0.2)
        cert, key = work / 'test-cert.pem', work / 'test-key.pem'
        subprocess.run(['/usr/bin/openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1',
                        '-subj','/CN=c101-fixture.invalid','-out',str(cert),'-keyout',str(key)],
                       check=True, timeout=20, capture_output=True)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(cert), str(key))
        names = []
        def alert(connection, name, config):
            names.append(name)
            return ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME
        context.set_servername_callback(alert)
        done = threading.Event()
        def tls_peer():
            while not done.is_set():
                try:
                    conn, _ = listener.accept()
                except TimeoutError:
                    continue
                with conn:
                    conn.settimeout(3)
                    with contextlib.suppress(ssl.SSLError, TimeoutError):
                        context.wrap_socket(conn, server_side=True).close()
        thread = threading.Thread(target=tls_peer, daemon=True)
        thread.start()
        try:
            original_hosts = Path('/etc/hosts').read_bytes()
            assert b'api.github.com' not in original_hosts
            hosts = work / 'hosts'
            hosts.write_bytes(original_hosts + b'\n127.0.0.77 api.github.com\n')
            hosts.chmod(0o644)
            if not unit.exists():
                unit.mkdir(mode=0o755)
                created_directory = True
            status = unit.lstat()
            assert stat.S_ISDIR(status.st_mode) and status.st_uid == 0 and status.st_mode & 0o022 == 0
            with dropin.open('x') as f:
                owned_dropin = True
                f.write('[Service]\nBindReadOnlyPaths=' + str(hosts) + ':/etc/hosts\nEnvironment=GODEBUG=netdns=go\n')
            start_panel()
            first = check_catalogue('github-smart-http')
            second = check_catalogue('github-smart-http')
            assert first == second
            assert names == ['api.github.com'], names
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
                done.set()
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
