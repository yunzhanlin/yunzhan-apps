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
import socket
import ssl
import tempfile
import threading
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
            item, = [v for v in data['catalog']['apps'] if v['id'] == 'site-diagnosis']
            status, = [v for v in data['status'] if v['id'] == 'site-diagnosis']
            assert item == plan['items']['site-diagnosis'] and status['supported'] and status['state_known']
            return item, status
        except urllib.error.HTTPError as error:
            if error.code != 503 or not delay:
                raise
            time.sleep(delay)


def check_file(domain, path, status, body=None):
    request = urllib.request.Request('http://127.0.0.1:19101' + path, headers={'Host': domain})
    try:
        with client.open(request, timeout=15) as response:
            assert response.status == status and response.read(65536) == body
    except urllib.error.HTTPError as error:
        assert error.code == status
        error.close()


def validate_report(report, site, path, status):
    assert report['site_id'] == site['id'] and report['domain'] == site['domain'] and report['path'] == path
    checks = report['checks']
    assert set(checks) == {'binding', 'http', 'dns', 'tls_certificate', 'nginx', 'files'}
    assert checks['binding']['verdict'] == checks['nginx']['verdict'] == 'pass'
    assert checks['http']['status'] == status
    assert checks['http']['verdict'] == ('pass' if status == 200 else 'fail')
    assert isinstance(checks['http']['response_ms'], int)
    assert report['passed_checks'] == sum(check['verdict'] == 'pass' for check in checks.values())
    assert report['total_checks'] == len(checks)
    assert any(row['check'] == 'http' for row in report['recommendations']) == (status == 404)


proof = {'ok': False, 'architecture': arch, 'source_inputs_sha256': plan['source_inputs_sha256'],
         'Main_changed': False, 'all50_commercial': False}
module = '/app-modules/site-diagnosis'
registry = '/app-registry/site-diagnosis'
file_path = '/site-diagnosis-fixture.txt'
listener=None
thread=None
stop=threading.Event()
try:
    login = json.loads(Path('/etc/panel/first-login.json').read_bytes())
    csrf = api('/login', {key: login[key] for key in ('username', 'password')})['csrf']
    login.clear()
    item, initial = catalogue()
    assert not initial['installed']
    assert plan['mode']=='signed-site-diagnosis-tls' and item['version']=='1.3.1'
    _, installed=job('install-signed-module',registry+'/install',
                      {'expected_version':item['version'],'expected_sha256':item['sha256']})
    loaded=api(module)['status']
    assert loaded['installed'] and loaded['version']=='1.3.1'
    _, latest=catalogue()
    assert latest['installed_version']=='1.3.1' and not latest['update_available']
    sites = []
    for label in ('first', 'second'):
        slug = 'c97-' + label
        domain = slug + '.example.test'
        _, created = job('create-' + label, '/sites', {'name': slug, 'slug': slug, 'domain': domain}, 300)
        site = {'id': created['site_id'], 'domain': domain}
        assert re.fullmatch('[a-f0-9]{32}', site['id'])
        marker = f'C97 site diagnosis marker for {label}\n'
        result = api('/sites/' + site['id'] + '/files/action',
                     {'action': 'create', 'path': file_path[1:], 'content': marker})
        assert result['sha256'] == hashlib.sha256(marker.encode()).hexdigest()
        check_file(domain, file_path, 200, marker.encode())
        sites.append(site)

    def diagnose(site, path, symptom, code):
        result = api(module + '/run', {'site_id': site['id'], 'path': path, 'diagnosis_symptom': symptom})
        validate_report(result, site, path, code)
        assert result['check_order'][0] == ('tls_certificate' if symptom == 'https' else 'http')
        return result

    # This runner is disposable. Place a local trust anchor only on this runner
    # and serve the same certificate to two owned test names.
    tls_directory=tempfile.TemporaryDirectory(prefix='c163-tls-')
    certs=Path(tls_directory.name)
    hosts=Path('/etc/hosts')
    original_hosts=hosts.read_bytes()
    ca=Path('/usr/local/share/ca-certificates/c163-test-diagnosis.crt')
    assert not ca.exists() and not ca.is_symlink()
    def openssl(*args):
        subprocess.run(['/usr/bin/openssl',*args],cwd=certs,check=True,capture_output=True,timeout=30)
    openssl('req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-noenc',
            '-keyout','ca.key','-out','ca.crt','-days','90','-subj','/CN=CloudStack QA Diagnosis Root')
    openssl('req','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-noenc',
            '-keyout','server.key','-out','server.csr','-subj','/CN='+sites[0]['domain'])
    (certs/'extensions').write_text('subjectAltName=DNS:'+sites[0]['domain']+'\nextendedKeyUsage=serverAuth\n')
    openssl('x509','-req','-in','server.csr','-CA','ca.crt','-CAkey','ca.key','-CAcreateserial',
            '-out','server.crt','-days','45','-extfile','extensions')
    ca.write_bytes((certs/'ca.crt').read_bytes())
    ca.chmod(0o644)
    hosts.write_bytes(original_hosts+b'\n127.0.0.2 '+(' '.join(row['domain'] for row in sites)+'\n').encode())
    subprocess.run(['/usr/sbin/update-ca-certificates'],check=True,capture_output=True,timeout=90)
    subprocess.run(['/usr/bin/systemctl','restart','panel-executor.service'],check=True,capture_output=True,timeout=65)
    subprocess.run(['/usr/bin/systemctl','is-active','--quiet','panel-executor.service'],check=True,timeout=10)
    listener=socket.create_server(('127.0.0.2',443))
    listener.settimeout(.5)
    server=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.minimum_version=ssl.TLSVersion.TLSv1_2
    server.load_cert_chain(certs/'server.crt',certs/'server.key')
    sni=[]
    server.set_servername_callback(lambda sock,name,context:sni.append(name))
    def serve():
        while not stop.is_set():
            try:
                connection,_=listener.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            with connection:
                connection.settimeout(4)
                with contextlib.suppress(OSError):
                    with server.wrap_socket(connection,server_side=True) as secured:
                        secured.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
    thread=threading.Thread(target=serve,daemon=True)
    thread.start()
    original=diagnose(sites[0],file_path,'https',200)
    trusted=original['checks']['tls_certificate']
    assert trusted['verdict']=='pass' and trusted['valid'] and trusted['tls_version'] in ('TLS 1.2','TLS 1.3')
    assert 'CloudStack QA Diagnosis Root' in trusted['issuer'] and trusted['not_before']<trusted['not_after']
    mismatch=diagnose(sites[1],file_path,'https',200)
    untrusted=mismatch['checks']['tls_certificate']
    assert untrusted['verdict']=='fail' and not untrusted['valid'] and untrusted['reason_code']=='hostname-mismatch'
    assert 'error' not in untrusted and 'issuer' not in untrusted
    assert set(sni)=={row['domain'] for row in sites}
    save('original-verified-tls-report.json',original)
    save('original-tls-mismatch-report.json',mismatch)
    previous_history=api(module+'/history')
    assert len(previous_history['history'])>=2
    missing_path = '/c97-file-does-not-exist'
    check_file(sites[0]['domain'], missing_path, 404)
    save('original-not-found-report.json', diagnose(sites[0], missing_path, 'not-found', 404))
    batch = api(module + '/diagnosis-batch', {'site_ids': [s['id'] for s in sites], 'path': file_path})
    assert batch['site_count'] == 2
    for site, row in zip(sites, batch['diagnoses'], strict=True):
        assert row['site_id'] == site['id'] and 'error' not in row
        validate_report(row['report'], site, file_path, 200)
    save('original-batch-report.json', batch)
    invalid = api(module + '/run', {'site_id': sites[0]['id'], 'path': '//foreign.invalid/'}, 409)
    assert invalid.get('error')
    duplicate = api(module + '/diagnosis-batch', {'site_ids': [sites[0]['id']] * 2, 'path': file_path}, 409)
    assert duplicate.get('error')
    latest_history = api(module + '/history')
    assert any(event['action'] == 'diagnosis-batch' for event in latest_history['history'])
    assert previous_history['history'][0] in latest_history['history']
    save('final-history.json', latest_history)
    proof.update(ok=True, managed_http_200_and_404=True, nginx_binding_verified=True, diagnostic_order_verified=True,
                 actual_verified_trusted_and_wrong_host_tls=True, batch_sites=2, malformed_path_and_duplicate_rejected=True, persistent_history=True,
                 original_installed_job=installed['id'], registry_version=item['version'])
except BaseException:
    import traceback
    proof['failure'] = traceback.format_exc()
finally:
    if listener is not None:
        stop.set()
        listener.close()
    if thread is not None:
        thread.join(timeout=6)
    if 'ca' in locals() and 'original_hosts' in locals():
        hosts.write_bytes(original_hosts)
        if ca.is_file() and not ca.is_symlink():
            ca.unlink()
            subprocess.run(['/usr/sbin/update-ca-certificates','--fresh'],check=True,capture_output=True,timeout=90)
    if 'tls_directory' in locals():
        tls_directory.cleanup()
    if csrf:
        with contextlib.suppress(Exception):
            api('/logout', {})
    save('original-proof.json', proof)
sys.exit(0 if proof['ok'] else 1)
