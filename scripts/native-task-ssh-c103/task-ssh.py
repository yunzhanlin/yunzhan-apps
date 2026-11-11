"""Verify the signed Task Manager OpenSSH inventory through the signed panel."""
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
import tempfile
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

def ssh_inventory():
    report = api(module + '/inventory/ssh')
    assert report['view'] == 'ssh' and report['available']
    return report['rows']

def run(*argv, data=None):
    return subprocess.run(argv, input=data, capture_output=True, text=True, check=True, timeout=20).stdout

def established(port):
    return run('/usr/bin/ss','-H','-n','-t','-p','-e','state','established','sport','=',':'+str(port)).splitlines()

def socket_inode(row):
    match = re.search(r'\bino:([1-9][0-9]*)\b', row)
    return match[1] if match else None

def check_native_ssh():
    assert Path('/usr/sbin/sshd').is_file()
    username = 'c103ssh-' + secrets.token_hex(6)
    run('/usr/sbin/useradd','--no-create-home','--home-dir','/nonexistent','--shell','/bin/sh',username)
    try:
        run('/usr/sbin/chpasswd', data=username + ':' + secrets.token_urlsafe(32) + '\n')
        with tempfile.TemporaryDirectory(prefix='c103-native-ssh-',dir='/run') as temp:
            work = Path(temp)
            work.chmod(0o755)
            for key in ('host','client'):
                run('/usr/bin/ssh-keygen','-q','-t','ed25519','-N','','-f',str(work/key))
            (work/'client.pub').chmod(0o644)
            with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as available:
                available.bind(('127.0.0.1',0))
                port = available.getsockname()[1]
            (work/'known_hosts').write_text(f'[127.0.0.1]:{port} ' + ' '.join((work/'host.pub').read_text().split()[:2]) + '\n')
            config = work/'sshd_config'
            config.write_text('\n'.join([
                f'Port {port}', 'ListenAddress 127.0.0.1', 'AddressFamily inet', f'HostKey {work/"host"}',
                f'PidFile {work/"pid"}', f'AuthorizedKeysFile {work/"client.pub"}', 'StrictModes yes',
                'UsePAM no', 'UseDNS no', 'AllowUsers ' + username, 'PermitRootLogin no',
                'PasswordAuthentication no', 'KbdInteractiveAuthentication no', 'AuthenticationMethods publickey',
                'DisableForwarding yes', 'ForceCommand /usr/bin/sleep 50',
            ]) + '\n')
            run('/usr/sbin/sshd','-t','-f',str(config))
            unit = 'c103-native-ssh-' + secrets.token_hex(6)
            run('/usr/bin/systemd-run','--quiet','--unit='+unit,'--property=Type=exec','/usr/sbin/sshd','-D','-e','-f',str(config))
            client = None
            try:
                cutoff = time.monotonic() + 10
                while True:
                    try:
                        with socket.create_connection(('127.0.0.1',port),timeout=1):
                            break
                    except OSError:
                        if time.monotonic() > cutoff:
                            raise
                        time.sleep(0.2)
                log = work/'client.log'
                with log.open('xb') as capture:
                    client = subprocess.Popen([
                        '/usr/bin/ssh','-v','-n','-T','-F','/dev/null','-p',str(port),'-i',str(work/'client'),
                        '-oBatchMode=yes','-oStrictHostKeyChecking=yes','-oIdentitiesOnly=yes',
                        '-oUserKnownHostsFile='+str(work/'known_hosts'),'-oGlobalKnownHostsFile=/dev/null',
                        '-oUpdateHostKeys=no','-oConnectTimeout=5',username+'@127.0.0.1','/usr/bin/sleep 50',
                    ],stdout=capture,stderr=capture)
                    cutoff = time.monotonic() + 15
                    inode = None
                    while time.monotonic() < cutoff:
                        assert client.poll() is None, log.read_text()[-1200:]
                        rows = [row for row in established(port) if 'users:(("sshd' in row]
                        if 'Authenticated to 127.0.0.1' in log.read_text() and len(rows)==1:
                            inode = socket_inode(rows[0])
                            if inode:
                                break
                        time.sleep(0.25)
                    assert inode
                    assert username not in run('/usr/bin/loginctl','list-sessions','--no-legend','--no-pager')
                    with socket.create_connection(('127.0.0.1',port),timeout=4) as unauthed:
                        endpoint = '127.0.0.1:'+str(unauthed.getsockname()[1])
                        pending, = [row for row in established(port) if endpoint in row.split()]
                        other = socket_inode(pending)
                        assert other and other != inode
                        rows = ssh_inventory()
                        matched, = [row for row in rows if row['session'] == 'ssh:'+inode]
                        assert matched['name'] == username and matched['source'] == 'OpenSSH'
                        assert matched['remote_host'] == '127.0.0.1' and matched['terminal'] == ''
                        assert not any(row['session'] == 'ssh:'+other for row in rows)
            finally:
                if client and client.poll() is None:
                    client.terminate()
                    try:
                        client.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        client.kill()
                        client.wait(timeout=5)
                run('/usr/bin/systemctl','stop',unit+'.service')
    finally:
        run('/usr/sbin/userdel',username)

try:
    login = json.loads(Path('/etc/panel/first-login.json').read_bytes())
    csrf = api('/login', {key: login[key] for key in ('username','password')})['csrf']
    login.clear()
    item, status = catalogue()
    assert not status['installed']
    upgrade = plan['mode'] == 'signed-openssh-update'
    if not upgrade:
        assert plan['mode'] == 'native-sysv-compat' and item['version'] == '1.3.1'
        _, installed = job('install-original-signed',registry+'/install',
                           {'expected_version':item['version'],'expected_sha256':item['sha256']})
        assert api(module)['status']['version'] == '1.3.1'
        assert all('source' not in row for row in ssh_inventory())
    else:
        _, installed = job('install-legacy','/software/task-manager/install',{})
        receipt = Path('/etc/panel/security-apps/modules/task-manager/installed.json')
        before = json.loads(receipt.read_bytes())
        assert before['version'] == '1.2.1'
        _, version = catalogue()
        assert version['installed_version'] == '1.2.1' and version['update_available'] and version['update_supported']
        _, updated = job('update-signed',registry+'/update',
                         {'expected_version':item['version'],'expected_sha256':item['sha256']})
        after = json.loads(receipt.read_bytes())
        assert after.pop('version') == '1.3.2' and after.pop('updated_at')
        assert before.pop('version') == '1.2.1' and before == after
        check_native_ssh()
        proof.update(real_authenticated_notty_openssh_session=True, preauth_socket_excluded=True,
                     temporary_fixture_account_removed=True, original_installation_retained=True,
                     signed_update={'job':updated['id'],'version':item['version'],'manifest_sha256':item['sha256']})
    sysv = api(module+'/inventory/sysv-startup')
    assert sysv['available'] and sysv['view']=='sysv-startup' and sysv['rows']
    proof.update(ok=True, sysv_compatibility_preserved=True, registry_version=item['version'], installed_job=installed['id'])
except BaseException:
    import traceback
    proof['failure'] = traceback.format_exc()
finally:
    if csrf:
        with contextlib.suppress(Exception):
            api('/logout',{})
    save('original-proof.json',proof)
sys.exit(0 if proof['ok'] else 1)
