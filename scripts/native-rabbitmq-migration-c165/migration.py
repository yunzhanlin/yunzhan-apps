from pathlib import Path
import hashlib
import json
import os
import platform
import re
import secrets
import shutil
import stat
import subprocess
import sys
import time

os.umask(0o077)
assert os.geteuid() == 0 and sys.platform == 'linux' and len(sys.argv) == 3
assert Path('/proc/1/comm').read_text().strip() == 'systemd'
assert os.environ.get('GITHUB_ACTIONS') == 'true'
assert os.environ.get('GITHUB_REPOSITORY') == 'yunzhanlin/yunzhan-apps'
wheel = Path(sys.argv[1])
assert wheel.name == 'pika-1.3.2-py3-none-any.whl'
assert hashlib.sha256(wheel.read_bytes()).hexdigest() == '0779a7c1fafd805672796085560d290213a465e4f6f76a6fb19e378d8041a14f'
sys.path.insert(0, str(wheel))
import pika

result = Path(sys.argv[2])
result.mkdir(mode=0o700)
prefix = 'yunzhan-c165-' + secrets.token_hex(6)
hostname = 'cloudstack-rabbitmq'
node = 'rabbit@' + hostname
arch = {'aarch64': 'arm64', 'x86_64': 'amd64'}[platform.machine()]
images = {
    '4.1.4': 'rabbitmq:4.1.4-management-alpine@sha256:5cbd7145b0306399ad68422c3350b6cbd1bb95704b39f5896480e5b6d4238a04',
    '4.2.9': 'rabbitmq:4.2.9-management-alpine@sha256:77ca2ba3621a95208918e6e331199a6c81129690bf7fc570dc61b6e64726840a',
    '4.4.0': 'rabbitmq:4.4.0-management-alpine@sha256:4841f6384ef8313c3594cd3f2e9f40c10805f8a61c45f08a9a5d9ddea8199267',
}
docker = ['/usr/bin/docker', '--host', 'unix:///run/docker.sock']
env = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8',
       'RABBITMQ_DEFAULT_PASS': secrets.token_urlsafe(32)}
containers, volumes = set(), set()
proof = {'ok': False, 'architecture': arch, 'node': node, 'images': {}, 'events': [],
         'main_changed': False, 'store_changed': False, 'all50_commercial': False}

def run(args, timeout=90, require=True):
    process = subprocess.run(args, capture_output=True, env=env, timeout=timeout)
    if require and process.returncode != 0:
        error = process.stderr.decode(errors='replace').replace(env['RABBITMQ_DEFAULT_PASS'], '[redacted]')
        if 'add_user' in args:
            error = ''
        raise AssertionError(f'{args[0]} failed ({process.returncode}): {error[-2400:]}')
    return process

def d(*args, timeout=90, require=True):
    return run(docker + list(args), timeout=timeout, require=require)

def inspect(kind, name):
    rows = json.loads(d(kind, 'inspect', name).stdout)
    assert len(rows) == 1
    return rows[0]

def save(path, value):
    with path.open('x') as output:
        json.dump(value, output, indent=2, ensure_ascii=False)
        output.write('\n')
        output.flush()
        os.fsync(output.fileno())

def volume(suffix):
    name = prefix + '-' + suffix
    assert d('volume', 'inspect', name, require=False).returncode != 0
    assert d('volume', 'create', '--label', 'org.yunzhan.fixture='+prefix, name).stdout.decode().strip() == name
    volumes.add(name)
    return name

def mountpoint(name):
    details = inspect('volume', name)
    assert name in volumes and details['Name'] == name and details['Driver'] == 'local'
    assert details['Scope'] == 'local' and details['Labels'] == {'org.yunzhan.fixture': prefix}
    assert not details['Options']
    path = Path(details['Mountpoint'])
    assert path.name == '_data' and path.parent.name == name and path.resolve(strict=True) == path
    assert path.is_dir()
    return path

def disk_manifest(root):
    rows = []
    for path in sorted(root.rglob('*')):
        relative = path.relative_to(root).as_posix()
        info = path.lstat()
        assert stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode), relative
        assert info.st_nlink == 1 or stat.S_ISDIR(info.st_mode), relative
        assert not stat.S_IMODE(info.st_mode) & 0o7000, relative
        digest = None
        if stat.S_ISREG(info.st_mode):
            with path.open('rb') as data:
                digest = hashlib.file_digest(data, 'sha256').hexdigest()
        rows.append((relative, stat.S_IMODE(info.st_mode), info.st_uid, info.st_gid, digest))
    assert len(rows) < 4096
    return hashlib.sha256(json.dumps(rows, separators=(',', ':')).encode()).hexdigest()

def copy_stopped(original, destination, original_container):
    state = inspect('container', original_container)['State']
    assert state['Status'] == 'exited' and state['ExitCode'] == 0 and state['Pid'] == 0
    assert not d('ps', '-q', '--filter', 'volume='+original).stdout.strip()
    src, dst = mountpoint(original), mountpoint(destination)
    assert src != dst and src.stat().st_ino != dst.stat().st_ino and not any(dst.iterdir())
    before = disk_manifest(src)
    run(['/bin/cp', '-a', '--', str(src)+ '/.', str(dst)])
    assert disk_manifest(dst) == before == disk_manifest(src)
    assert not d('ps', '-q', '--filter', 'volume='+original).stdout.strip()
    return before

def ready(name, version, published=True):
    deadline = time.monotonic() + 175
    last = b''
    check = None
    while time.monotonic() < deadline:
        state = inspect('container', name)['State']
        if state['Status'] == 'exited':
            break
        check = d('exec', '--user', 'rabbitmq', '--env', 'HOME=/var/lib/rabbitmq', name,
                  'rabbitmq-diagnostics', '-q', 'check_running', timeout=15, require=False)
        last = check.stderr
        if check.returncode == 0:
            break
        time.sleep(2)
    else:
        raise TimeoutError(last[-800:].decode(errors='replace'))
    metadata = inspect('container', name)
    assert metadata['State']['Status'] == 'running' and check is not None and check.returncode == 0, d('logs','--tail','80',name,require=False).stdout.decode(errors='replace')[-6000:]
    assert metadata['Config']['Hostname'] == hostname and metadata['Config']['Image'] == images[version]
    assert metadata['HostConfig']['Memory'] == 512 << 20
    version_text = cli(name, 'version', json_format=False).strip()
    assert version_text.decode() == version
    connections = json.loads(cli(name, 'list_connections', 'name'))
    assert connections == [], 'entry must be checked before opening test connections'
    if not published:
        assert not metadata['HostConfig']['PortBindings']
        return None
    endpoint = metadata['NetworkSettings']['Ports']['5672/tcp']
    assert len(endpoint) == 1 and endpoint[0]['HostIp'] == '127.0.0.1'
    port = int(endpoint[0]['HostPort'])
    assert 1024 <= port <= 65535
    return port

def start(suffix, version, data, published=False, fail=False):
    name = prefix + '-' + suffix
    assert name not in containers and d('container', 'inspect', name, require=False).returncode != 0
    args = ['run', '--detach', '--no-healthcheck', '--name', name, '--hostname', hostname,
            '--label', 'org.yunzhan.fixture='+prefix, '--memory', '512m',
            '--env', 'RABBITMQ_SERVER_ADDITIONAL_ERL_ARGS=+S 2:2 +SDcpu 1 +SDio 1',
            '--env', 'RABBITMQ_DEFAULT_USER=paneladmin', '--env', 'RABBITMQ_DEFAULT_PASS',
            '--mount', 'type=volume,src='+data+',dst=/var/lib/rabbitmq,volume-nocopy']
    if published:
        args.extend(('--publish', '127.0.0.1::5672'))
    else:
        args.extend(('--network', 'none', '--add-host', hostname+':127.0.0.1'))
    if fail:
        args.extend(('--entrypoint', '/bin/false'))
    container_id = d(*args, images[version]).stdout.decode().strip()
    containers.add(name)
    assert re.fullmatch(r'[a-f0-9]{64}', container_id) and inspect('container', name)['Id'] == container_id
    if fail:
        assert d('wait', name, timeout=25).stdout.strip() == b'1'
        return name, None
    return name, ready(name, version, published)

def stop(name):
    assert inspect('container', name)['Config']['Labels']['org.yunzhan.fixture'] == prefix
    d('stop', '--time', '60', name, timeout=70)
    state = inspect('container', name)['State']
    assert state['Status'] == 'exited' and state['ExitCode'] == 0 and state['Pid'] == 0

def cli(name, *args, json_format=True):
    options = ['--quiet', '--timeout', '40']
    if json_format:
        options.extend(('--formatter', 'json'))
    return d('exec', '--user', 'rabbitmq', '--env', 'HOME=/var/lib/rabbitmq', name,
             'rabbitmqctl', *options, *args, timeout=52).stdout

def flags(name, allow_changes=False):
    if allow_changes:
        cli(name, 'enable_feature_flag', 'all', json_format=False)
    values = json.loads(cli(name, 'list_feature_flags', 'name', 'state', 'stability'))
    assert len(values) > 10 and all(row['state'] == 'enabled' for row in values
                                   if row['stability'] in ('stable', 'required'))
    return len(values)

def connect(port, vhost='/', username='paneladmin', password=None):
    return pika.BlockingConnection(pika.ConnectionParameters(host='127.0.0.1', port=port, virtual_host=vhost,
        credentials=pika.PlainCredentials(username, password or env['RABBITMQ_DEFAULT_PASS']),
        connection_attempts=1, socket_timeout=6, stack_timeout=12, blocked_connection_timeout=12, heartbeat=15))

vhost = '云栈/migration'
limited_password = secrets.token_urlsafe(24)
messages = {kind: secrets.token_bytes(2048) for kind in ('classic', 'quorum')}

def observe_messages(port, destructive):
    connection = connect(port, vhost)
    try:
        channel = connection.channel()
        for kind, expected in messages.items():
            metric = channel.queue_declare(queue='migration.' + kind, passive=True)
            assert metric.method.message_count == 1
            method, props, actual = channel.basic_get('migration.' + kind, auto_ack=False)
            assert method and actual == expected and props.delivery_mode == 2
            if destructive:
                channel.basic_ack(method.delivery_tag)
                assert channel.queue_declare(queue='migration.' + kind, passive=True).method.message_count == 0
            else:
                channel.basic_nack(method.delivery_tag, requeue=True)
    finally:
        connection.close()

try:
    for version, image in images.items():
        d('pull', '--platform', 'linux/'+arch, image, timeout=300)
        data = inspect('image', image)
        assert data['Architecture'] == arch and data['Os'] == 'linux'
        assert any(value.endswith('@'+image.split('@')[1]) for value in data['RepoDigests'])
        proof['images'][version] = {'reference': image, 'config': data['Id']}
    source_volume = volume('original')
    old, port = start('original', '4.1.4', source_volume, published=True)
    proof['original_stable_feature_flags'] = flags(old)
    cli(old, 'add_vhost', vhost, json_format=False)
    cli(old, 'set_permissions', '--vhost='+vhost, 'paneladmin', '.*', '.*', '.*', json_format=False)
    cli(old, 'add_user', 'limited-migration-user', limited_password, json_format=False)
    cli(old, 'set_permissions', '--vhost='+vhost, 'limited-migration-user', '^$', '^$', '^$', json_format=False)
    connection = connect(port, vhost)
    try:
        channel = connection.channel()
        channel.confirm_delivery()
        for kind, message in messages.items():
            name = 'migration.'+kind
            channel.queue_declare(queue=name, durable=True, arguments={'x-queue-type': kind})
            channel.basic_publish('', name, message, properties=pika.BasicProperties(delivery_mode=2), mandatory=True)
    finally:
        connection.close()
    stop(old)
    failed_volume = volume('failed-copy')
    original_digest = copy_stopped(source_volume, failed_volume, old)
    bridge, _ = start('bridge-failure', '4.2.9', failed_volume)
    proof['failed_copy_intermediate_feature_flags'] = flags(bridge, allow_changes=True)
    stop(bridge)
    start('expected-failure', '4.4.0', failed_volume, fail=True)
    assert disk_manifest(mountpoint(source_volume)) == original_digest
    d('start', old)
    restore_port = ready(old, '4.1.4')
    observe_messages(restore_port, destructive=False)
    stop(old)
    proof['events'].append('original_volume_restarted_after_candidate_failure_with_both_messages')
    target_volume = volume('successful-copy')
    source_digest = copy_stopped(source_volume, target_volume, old)
    bridge, _ = start('bridge-success', '4.2.9', target_volume)
    proof['target_intermediate_feature_flags'] = flags(bridge, allow_changes=True)
    stop(bridge)
    target, port = start('current', '4.4.0', target_volume, published=True)
    proof['target_final_feature_flags'] = flags(target, allow_changes=True)
    limited = connect(port, vhost, 'limited-migration-user', limited_password)
    try:
        try:
            limited.channel().queue_declare(queue='migration.classic', passive=True)
        except pika.exceptions.ChannelClosedByBroker as error:
            assert error.reply_code == 403, error
        else:
            raise AssertionError('Passive queue declaration accepted for user without any queue permission')
    finally:
        limited.close()
    proof['events'].append('passive_declaration_rejected_for_existing_unprivileged_user')
    observe_messages(port, destructive=True)
    proof['events'].append('old_credentials_and_classic_and_quorum_messages_restored_in_4_4')
    assert disk_manifest(mountpoint(source_volume)) == source_digest
    assert source_volume != target_volume
    proof['original_volume_untouched_during_successful_upgrade'] = True
    proof['message_sha256'] = {kind: hashlib.sha256(value).hexdigest() for kind, value in messages.items()}
    proof['ok'] = True
finally:
    for name in sorted(containers, reverse=True):
        container = inspect('container', name)
        assert container['Config']['Labels']['org.yunzhan.fixture'] == prefix
        if container['State']['Running']:
            stop(name)
        d('rm', name)
    for name in sorted(volumes):
        mountpoint(name)
        d('volume', 'rm', name)
    proof['fixture_containers_and_volumes_removed'] = True
    save(result/'migration.json', proof)
