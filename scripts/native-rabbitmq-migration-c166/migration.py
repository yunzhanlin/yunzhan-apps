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
assert os.geteuid() == 0 and sys.platform == 'linux' and len(sys.argv) == 4
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
prefix = 'yunzhan-c166-' + secrets.token_hex(6)
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
       'RABBITMQ_DEFAULT_PASS': secrets.token_hex(32)}
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

worker = Path(sys.argv[3]).resolve(strict=True)
assert worker.name == 'rabbitmq-executor.test'
base = Path('/var/lib/panel-rabbitmq-fixture')
project_id = secrets.token_hex(16)
engine = 'panel_' + project_id[:12]
original_volume = engine + '_data'
worker_dir = base / 'worker'
project = worker_dir / 'compose' / project_id
journal = worker_dir / 'journal'
original_name = prefix + '-original'
password = env['RABBITMQ_DEFAULT_PASS']
port = 25272
compose = f"""services:
  rabbitmq:
    image: {images['4.1.4']}
    restart: unless-stopped
    hostname: cloudstack-rabbitmq
    environment:
      RABBITMQ_DEFAULT_USER: paneladmin
      RABBITMQ_DEFAULT_PASS: "{password}"
      RABBITMQ_SERVER_ADDITIONAL_ERL_ARGS: "+S 2:2 +SDcpu 1 +SDio 1"
    mem_limit: 512m
    ports:
      - "127.0.0.1:{port}:15672"
      - "127.0.0.1:{port+1}:5672"
    volumes:
      - data:/var/lib/rabbitmq
    healthcheck:
      test: ["CMD", "rabbitmq-diagnostics", "-q", "check_running"]
      interval: 15s
      timeout: 20s
      retries: 20
      start_period: 120s
volumes:
  data: {{}}
"""
metadata = {'id': project_id, 'name': original_name, 'engine_name': engine,
            'template_id': 'rabbitmq', 'host_port': port, 'services': 1,
            'created_at': '2026-11-14T00:00:00Z'}

def worker_action(action, test='TestRabbitMQMigrationNativeWorker'):
    e = dict(env, GITHUB_ACTIONS='true', GITHUB_REPOSITORY='yunzhanlin/yunzhan-apps',
             PANEL_RABBITMQ_NATIVE_ACTION=action, PANEL_RABBITMQ_NATIVE_DIR=str(worker_dir))
    p = subprocess.run([str(worker), '-test.v', '-test.run', '^'+test+'$', '-test.timeout', '12m'],
                       env=e, capture_output=True, timeout=740)
    out = (p.stdout+p.stderr).decode(errors='replace').replace(password, '[redacted]')
    print(out[-5000:], flush=True)
    assert p.returncode == 0 and '--- PASS: '+test+' ' in out

def prepare(job, digest):
    (worker_dir/'request.json').write_text(json.dumps({
        'job_id': job, 'request_id': secrets.token_hex(16), 'actor_id': secrets.token_hex(16),
        'project_id': project_id, 'original_container': original_id,
        'original_config_sha256': hashlib.sha256((project/'compose.yaml').read_bytes()).hexdigest(),
        'original_metadata_sha256': hashlib.sha256((project/'metadata.json').read_bytes()).hexdigest(),
        'target_manifest_sha256': digest, 'original_volume': original_volume,
        'candidate_volume': 'panel_rabbitmq_'+job,
    }))

def phases():
    return [json.loads(p.read_text())['phase'] for p in sorted(journal.glob('event-*.json'))]

def cert_observed_no_writes():
    observation = inspect('container', original_id)
    assert observation['State']['Status'] == 'exited' and observation['State']['ExitCode'] == 0
    assert observation['Mounts'][0]['Name'] == original_volume
    assert not d('ps', '-aq', '--filter', 'label=io.yunzhan.rabbitmq-migration-job='+job).stdout.strip()
    assert (project/'compose.yaml').read_text() == compose
    assert json.loads((project/'metadata.json').read_text()) == metadata

try:
    for check in ('TestRabbitMQMigrationJournalReopensAndFencesRollbackAtEndpointPublication',
                  'TestRabbitMQMigrationJournalRejectsUnknownOriginalState'):
        worker_action('', check)

    base.mkdir(mode=0o700)
    project.mkdir(mode=0o700, parents=True)
    journal.mkdir(mode=0o700)
    (worker_dir/'state'/'docker-jobs').mkdir(mode=0o700, parents=True)
    (worker_dir/'state'/'runtime-lifecycle.lock').touch(mode=0o600)
    (project/'metadata.json').write_text(json.dumps(metadata))
    (project/'compose.yaml').write_text(compose)

    d('pull', images['4.1.4'], timeout=300)
    assert d('volume', 'create', '--label', 'com.docker.compose.project='+engine,
             '--label', 'com.docker.compose.volume=data', original_volume).stdout.decode().strip() == original_volume
    original_id = d('run', '--detach', '--name', original_name, '--hostname', hostname,
                    '--label', 'com.docker.compose.project='+engine, '--label', 'com.docker.compose.service=rabbitmq',
                    '--label', 'com.docker.compose.oneoff=False', '--restart', 'unless-stopped',
                    '--memory', '512m', '--env', 'RABBITMQ_DEFAULT_USER=paneladmin', '--env', 'RABBITMQ_DEFAULT_PASS',
                    '--env', 'RABBITMQ_SERVER_ADDITIONAL_ERL_ARGS=+S 2:2 +SDcpu 1 +SDio 1',
                    '--publish', f'127.0.0.1:{port}:15672', '--publish', f'127.0.0.1:{port+1}:5672',
                    '--mount', 'type=volume,src='+original_volume+',dst=/var/lib/rabbitmq,volume-nocopy',
                    images['4.1.4']).stdout.decode().strip()
    assert re.fullmatch('[a-f0-9]{64}', original_id)
    old_port = ready(original_id, '4.1.4')
    assert old_port == port+1
    flags(original_id)
    cli(original_id, 'add_vhost', vhost, json_format=False)
    cli(original_id, 'set_permissions', '--vhost='+vhost, 'paneladmin', '.*', '.*', '.*', json_format=False)
    cli(original_id, 'add_user', 'limited-migration-user', limited_password, json_format=False)
    cli(original_id, 'set_permissions', '--vhost='+vhost, 'limited-migration-user', '^$', '^$', '^$', json_format=False)
    digest = '3ef2fb6eb8bd0bb88f22c8d0883d794e87acd3dff4fe09234ff33b893dbabf43'
    job = secrets.token_hex(16)
    prepare(job, digest)
    conn = connect(old_port, vhost)
    initial = inspect('container', original_id)['State']['StartedAt']
    try:
        channel = conn.channel()
        channel.confirm_delivery()
        for kind, message in messages.items():
            queue = 'migration.' + kind
            channel.queue_declare(queue=queue, durable=True, arguments={'x-queue-type': kind})
            channel.basic_publish('', queue, message, properties=pika.BasicProperties(delivery_mode=2), mandatory=True)
        worker_action('reject-connected')
        assert phases() == ['prepared']
        assert inspect('container', original_id)['State']['StartedAt'] == initial
        assert channel.queue_declare(queue='migration.classic', passive=True).method.message_count == 1
    finally:
        conn.close()
    proof['events'].append('actual-client-refused-without-original-restart')
    journal.rename(worker_dir/'refused-journal')
    journal.mkdir(mode=0o700)
    job = secrets.token_hex(16)
    prepare(job, digest)
    worker_action('stage')
    assert phases() == ['prepared','quiesce-intent','stop-original-intent','original-stopped','copy-intent','copy-verified',
                        'bridge-intent','bridge-stopped','target-check-intent','target-verified-offline']
    cert_observed_no_writes()
    candidate_volume = 'panel_rabbitmq_' + job
    details = inspect('volume', candidate_volume)
    assert details['Labels'] == {'io.yunzhan.rabbitmq-migration-job': job, 'io.yunzhan.rabbitmq-migration-project': project_id}
    assert Path(details['Mountpoint']).stat().st_ino != Path(inspect('volume', original_volume)['Mountpoint']).stat().st_ino
    candidate, candidate_port = start('target-probe', '4.4.0', candidate_volume, published=True)
    try:
        observe_messages(candidate_port, False)
        restricted = connect(candidate_port, vhost, 'limited-migration-user', limited_password)
        try:
            restricted.channel().queue_declare(queue='migration.classic', passive=True)
        except pika.exceptions.ChannelClosedByBroker as error:
            assert error.reply_code == 403
        else:
            raise AssertionError('existing restricted user got queue access')
        finally:
            restricted.close()
    finally:
        stop(candidate)
        d('rm', candidate)
    proof['events'].append('actual-candidate-classic-and-quorum-messages-and-permissions')
    worker_action('prepare-interrupted-restore')
    d('start', original_id)
    assert ready(original_id, '4.1.4') == old_port
    start_after_interruption = inspect('container', original_id)['State']['StartedAt']
    worker_action('restore')
    worker_action('restore')
    assert phases()[-3:] == ['restore-original-intent','restart-original-intent','original-restored']
    assert inspect('container', original_id)['State']['StartedAt'] == start_after_interruption
    observe_messages(old_port, True)
    assert inspect('volume', original_volume)['Name'] == original_volume
    assert inspect('volume', candidate_volume)['Name'] == candidate_volume
    proof['events'].append('interrupted-original-restart-reconciled-idempotently-with-messages')
    proof['ok'] = True
finally:
    save(result/'migration.json', proof)
