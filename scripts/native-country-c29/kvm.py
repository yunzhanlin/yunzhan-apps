"""Run trusted, once-only installation QA inside a fresh KVM guest.

Host software/configuration is inventoried, never removed or migrated. No
host mounts, agent forwarding, ambient credentials or TCG fallback are given
to the guest. Only a pinned public report and encrypted private evidence leave.
"""
import hashlib, json, os, pathlib, platform, re, shlex, shutil, socket, stat
import subprocess, sys, tempfile, time, urllib.request

os.umask(0o077)
assert os.geteuid() == 0 and platform.machine() == 'x86_64'
assert len(sys.argv) == 4
assets = pathlib.Path(sys.argv[1]).resolve(strict=True)
source = pathlib.Path(sys.argv[2]).resolve(strict=True)
public = pathlib.Path(sys.argv[3]).resolve(strict=True)
assert public.is_dir() and assets.is_dir() and source.is_dir()
public_owner = public.stat()
assert stat.S_ISCHR(pathlib.Path('/dev/kvm').stat().st_mode), 'Actual KVM required; no emulation fallback'
work = pathlib.Path(tempfile.mkdtemp(prefix='native-kvm-', dir=str(public.parent)))
private = work / 'private'; private.mkdir(mode=0o700)
IMAGE = 'https://cloud.debian.org/images/cloud/trixie/20260712-2537/debian-13-genericcloud-amd64-20260712-2537.qcow2'
IMAGE_SHA512 = '7ae53e9dbee282bfc16f289dec483dde3a8598769c38a267948310f7a2a52c662620198603bc52c142627efba379863d16079698a10b34102d55bcedd40e8d32'
CERT_SHA256 = '55ac5d4129117009583d47c47442bd07cc1de997e6a2a10b5652b3cb7fa54495'
def sha(p):
    h = hashlib.sha256()
    with pathlib.Path(p).open('rb') as f:
        for block in iter(lambda: f.read(1 << 20), b''): h.update(block)
    return h.hexdigest()
def save(name, value):
    assert re.fullmatch('[A-Za-z0-9._-]+', name)
    with (public / name).open('x') as f: json.dump(value, f, sort_keys=True, indent=2); f.write('\n')
    os.chown(public / name, public_owner.st_uid, public_owner.st_gid)
def run(args, timeout=60, data=None):
    p = subprocess.run(args, input=data, capture_output=True, timeout=timeout)
    assert len(p.stdout) + len(p.stderr) <= 4 << 20
    if p.returncode != 0:
        # Fixed infrastructure commands contain no credentials. Keep actual
        # private stderr out of public logs and retain its exact bytes locally.
        failure = private / ('command-failure-' + str(time.time_ns()) + '.log')
        failure.write_bytes(p.stdout + b'\n' + p.stderr)
        raise AssertionError('Infrastructure command failed: ' + args[0] + '; private evidence retained')
    return p.stdout
def host_state():
    paths = {}
    for name in ('/etc/nginx/nginx.conf', '/etc/panel-release', '/etc/systemd/system/panel.service', '/opt/panel', '/var/lib/panel', '/var/lib/panel-executor'):
        p = pathlib.Path(name)
        if not os.path.lexists(p): paths[name] = {'exists': False}; continue
        s = p.lstat(); paths[name] = {'exists': True, 'mode': s.st_mode, 'uid': s.st_uid, 'gid': s.st_gid, 'inode': s.st_ino}
        if stat.S_ISREG(s.st_mode): paths[name]['sha256'] = sha(p)
    return paths
before = host_state(); save('host-before.json', before)
assert sha(source / 'recipient.pem') == CERT_SHA256
assert sha(assets / 'assets.json') == '03c65d7c5c467b181ab427da6b10cf31f43f513d20546f448bd5b6fe9adba5bf'
pin = json.loads((assets / 'assets.json').read_bytes())
assert pin['architecture'] == 'amd64'
assert sha(source / 'guest.py') == pin['files']['guest.py']
for name, expected in pin['files'].items():
    assert re.fullmatch('[A-Za-z0-9._-]+', name) and sha(assets / name) == expected
disk = private / 'root.qcow2'
digest = hashlib.sha512(); size = 0
with urllib.request.urlopen(IMAGE, timeout=60) as response, disk.open('xb') as output:
    assert response.status == 200
    while block := response.read(1 << 20):
        size += len(block); assert size <= 2 << 30
        digest.update(block); output.write(block)
assert digest.hexdigest() == IMAGE_SHA512, 'Cloud image digest mismatch'
run(['qemu-img', 'resize', str(disk), '64G'])
for name in ('ssh-client', 'ssh-host'):
    run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(private / name)])
client_public = (private / 'ssh-client.pub').read_text().strip()
host_public = (private / 'ssh-host.pub').read_text().strip()
host_private = (private / 'ssh-host').read_text()
userdata = {'hostname': 'yunzhan-native-kvm', 'manage_etc_hosts': True, 'ssh_pwauth': False,
            'disable_root': True, 'users': [{'name': 'qa', 'groups': ['sudo'], 'shell': '/bin/bash',
            'sudo': ['ALL=(ALL) NOPASSWD:ALL'], 'lock_passwd': True, 'ssh_authorized_keys': [client_public]}],
            'ssh_keys': {'ed25519_private': host_private, 'ed25519_public': host_public}}
user = private / 'user-data'; user.write_text('#cloud-config\n' + json.dumps(userdata) + '\n')
metadata = private / 'meta-data'; metadata.write_text(json.dumps({'instance-id': 'yunzhan-native-' + work.name, 'local-hostname': 'yunzhan-native-kvm'}) + '\n')
seed = private / 'seed.img'; run(['cloud-localds', str(seed), str(user), str(metadata)])
firmware = pathlib.Path('/usr/share/OVMF/OVMF_CODE_4M.fd')
vars_source = pathlib.Path('/usr/share/OVMF/OVMF_VARS_4M.fd')
assert firmware.is_file() and vars_source.is_file()
variables = private / 'OVMF_VARS.fd'; shutil.copyfile(vars_source, variables)
reserve = socket.socket(); reserve.bind(('127.0.0.1', 0)); port = reserve.getsockname()[1]; reserve.close()
known = private / 'known_hosts'; known.write_text('[127.0.0.1]:' + str(port) + ' ' + host_public + '\n')
qmp_path = str(private / 'qmp.sock')
qemu_log = (private / 'qemu.log').open('xb')
qemu = subprocess.Popen(['qemu-system-x86_64', '-name', 'yunzhan-native-qa', '-machine', 'q35', '-accel', 'kvm', '-cpu', 'host',
    '-smp', '2', '-m', '4096', '-display', 'none', '-serial', 'file:' + str(private / 'serial.log'), '-no-reboot',
    '-drive', 'if=pflash,format=raw,readonly=on,file=' + str(firmware), '-drive', 'if=pflash,format=raw,file=' + str(variables),
    '-drive', 'if=virtio,format=qcow2,file=' + str(disk), '-drive', 'if=virtio,format=raw,readonly=on,file=' + str(seed),
    '-netdev', 'user,id=qa,hostfwd=tcp:127.0.0.1:' + str(port) + '-:22', '-device', 'virtio-net-pci,netdev=qa',
    '-qmp', 'unix:' + qmp_path + ',server=on,wait=off'], stdin=subprocess.DEVNULL, stdout=qemu_log, stderr=subprocess.STDOUT)
ssh = ['ssh', '-F', '/dev/null', '-i', str(private / 'ssh-client'), '-p', str(port), '-o', 'IdentitiesOnly=yes',
       '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile=' + str(known), '-o', 'GlobalKnownHostsFile=/dev/null',
       '-o', 'ConnectTimeout=5', '-o', 'BatchMode=yes', '-o', 'ForwardAgent=no', '-o', 'LogLevel=ERROR', 'qa@127.0.0.1']
scp = ['scp', '-F', '/dev/null', '-i', str(private / 'ssh-client'), '-P', str(port), '-o', 'IdentitiesOnly=yes',
       '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile=' + str(known), '-o', 'GlobalKnownHostsFile=/dev/null',
       '-o', 'BatchMode=yes', '-o', 'ForwardAgent=no', '-o', 'LogLevel=ERROR']
report = {'ok': False, 'host_architecture': platform.machine(), 'emulation_fallback': False, 'host_protected_state_unchanged': False,
          'all50_commercial': False, 'Main_changed': False, 'source_inputs_sha256': pin['source_inputs_sha256'],
          'programme_update_source_inputs_sha256': pin['programme_update_source_inputs_sha256']}
guest_evidence = None
try:
    for _ in range(100):
        assert qemu.poll() is None, 'KVM guest exited before readiness'
        if os.path.exists(qmp_path): break
        time.sleep(.1)
    with socket.socket(socket.AF_UNIX) as control:
        control.settimeout(5); control.connect(qmp_path)
        reader = control.makefile('rb'); assert 'QMP' in json.loads(reader.readline(65536))
        def qmp(command):
            control.sendall(json.dumps({'execute': command}).encode() + b'\r\n')
            for _ in range(20):
                result = json.loads(reader.readline(65536))
                if 'return' in result: return result['return']
                assert 'error' not in result, 'QMP command refused'
            raise AssertionError('QMP response bound')
        qmp('qmp_capabilities'); acceleration = qmp('query-kvm')
        assert acceleration == {'enabled': True, 'present': True}, 'Actual native KVM acceleration required'
        save('hardware-acceleration.json', {'query_kvm': acceleration, 'image_sha512': digest.hexdigest(), 'image_bytes': size,
                'CPU': 'host', 'guest_memory_MiB': 4096, 'guest_cpus': 2, 'host_mounts': [], 'TCG_fallback': False})
    ready = False
    for _ in range(90):
        assert qemu.poll() is None
        p = subprocess.run(ssh + ['true'], capture_output=True, timeout=7)
        if p.returncode == 0: ready = True; break
        time.sleep(2)
    assert ready, 'Pinned SSH did not become ready'
    run(ssh + ['sudo', '-n', 'cloud-init', 'status', '--wait'], timeout=180)
    identity = run(ssh + [shlex.join(['python3', '-c', 'import json,platform,pathlib;print(json.dumps({"architecture":platform.machine(),"boot":pathlib.Path("/proc/sys/kernel/random/boot_id").read_text().strip(),"PID1":pathlib.Path("/proc/1/comm").read_text().strip()}))'])])
    actual = json.loads(identity); assert actual['architecture'] == 'x86_64' and actual['PID1'] == 'systemd'
    save('pinned-guest-identity.json', actual)
    run(ssh + ['mkdir', '-m', '700', '/home/qa/native-input'])
    files = [str(assets / n) for n in sorted(pin['files'])] + [str(assets / 'assets.json')]
    run(scp + files + ['qa@127.0.0.1:/home/qa/native-input/'], timeout=120)
    run(scp + [str(source / 'guest.py'), 'qa@127.0.0.1:/home/qa/guest.py'], timeout=30)
    with (private / 'guest-output.log').open('xb') as output:
        result = subprocess.run(ssh + ['sudo', '-n', 'python3', '-I', '-B', '/home/qa/guest.py', '/home/qa/native-input'],
                                stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT, timeout=3300)
    lines = (private / 'guest-output.log').read_text().splitlines(); assert len(lines) < 200
    for line in reversed(lines):
        if line.startswith('{'):
            summary = json.loads(line); break
    else: raise AssertionError('Guest did not emit its final recorded result; no install or app action replayed')
    assert re.fullmatch('/opt/panel-country-native-qa-[a-f0-9]{32}', summary['base'])
    guest_evidence = summary['base'] + '/evidence'
    report['guest'] = summary; report['guest_exit'] = result.returncode
    report['ok'] = result.returncode == 0 and summary['ok'] is True
finally:
    # Read only the new QA evidence directory. No private SSH key, cloud-init
    # seed, root disk, first-login file or application credential is uploaded.
    try:
        if guest_evidence:
            with (private / 'guest-evidence.tar.gz').open('xb') as output:
                p = subprocess.run(ssh + ['sudo', '-n', 'tar', '-C', guest_evidence, '-czf', '-', '.'],
                                   stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.PIPE, timeout=90)
                assert p.returncode == 0
        envelope = private / 'private-evidence.tar.gz'
        members = [n for n in ('guest-evidence.tar.gz', 'guest-output.log', 'qemu.log', 'serial.log') if (private / n).is_file()]
        run(['tar', '-C', str(private), '-czf', str(envelope), *members], timeout=60)
        encrypted = public / 'private-evidence.cms'
        run(['openssl', 'cms', '-encrypt', '-binary', '-aes-256-gcm', '-in', str(envelope), '-outform', 'DER',
             '-out', str(encrypted), '-recip', str(source / 'recipient.pem'), '-keyopt', 'rsa_padding_mode:oaep', '-keyopt', 'rsa_oaep_md:sha256'], timeout=60)
        os.chown(encrypted, public_owner.st_uid, public_owner.st_gid)
        report['private_evidence'] = {'encrypted': True, 'certificate_sha256': CERT_SHA256, 'sha256': sha(encrypted),
                                      'plaintext_sha256': sha(envelope), 'plaintext_bytes': envelope.stat().st_size}
    except BaseException as error:
        report['evidence_collection_failure'] = type(error).__name__; report['ok'] = False
    if qemu.poll() is None:
        # Graceful shutdown of this newly owned disposable guest only; never
        # reset, replay or relabel any application/native operation inside it.
        try: subprocess.run(ssh + ['sudo', '-n', 'poweroff'], capture_output=True, timeout=15)
        except (OSError, subprocess.TimeoutExpired): report['guest_shutdown_request_uncertain'] = True; report['ok'] = False
        try: qemu.wait(timeout=45)
        except subprocess.TimeoutExpired: report['guest_shutdown_incomplete'] = True; report['ok'] = False
    qemu_log.close()
    after = host_state(); save('host-after.json', after)
    report['host_protected_state_unchanged'] = before == after
    assert before == after, 'Host protected files changed'
    save('result.json', report)
    print(json.dumps(report), flush=True)
sys.exit(0 if report['ok'] else 1)
