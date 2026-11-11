"""Capture only containers from this native browser test's original projects."""

import json
import os
import pathlib
import re
import subprocess
import sys


os.umask(0o077)
assert os.geteuid() == 0
assert os.environ.get('SUDO_USER') == 'runner'
root = pathlib.Path(sys.argv[1]) / 'business-phase1'
proof = root / 'original-proof.json'
if not proof.is_file():
    sys.exit(0)
apps = json.loads(proof.read_bytes())['apps']


def docker(*arguments, data=None):
    return subprocess.run(
        ['/usr/bin/docker', *arguments], input=data, capture_output=True, text=True, timeout=40,
    )


for name, application in apps.items():
    assert name in ('rabbitmq', 'mongodb', 'openlitespeed')
    project = application.get('original_project', '')
    if not re.fullmatch('[a-f0-9]{32}', project):
        continue
    engine = 'panel_' + project[:12]
    matches = docker('ps', '-aq', '--filter', 'label=com.docker.compose.project=' + engine)
    records = []
    for cid in matches.stdout.splitlines():
        assert re.fullmatch('[a-f0-9]{12,64}', cid)
        inspect = docker('inspect', cid)
        if inspect.returncode:
            continue
        container, = json.loads(inspect.stdout)
        assert container['Config']['Labels']['com.docker.compose.project'] == engine
        record = {
            'image': container['Config']['Image'],
            'id': container['Id'],
            'state': container['State'],
            'ports': container['HostConfig']['PortBindings'],
            'memory': container['HostConfig']['Memory'],
            'mounts': container['Mounts'],
        }
        if name == 'mongodb':
            logs = docker('logs', '--tail', '140', cid)
            record['container_logs'] = [logs.stdout[-24000:], logs.stderr[-12000:]]
            if container['State']['Running']:
                script = '''
const admin = db.getSiblingDB('admin');
assert(admin.auth(process.env.MONGO_INITDB_ROOT_USERNAME, process.env.MONGO_INITDB_ROOT_PASSWORD));
assert.commandWorked(admin.runCommand({ping: 1}));
print('authenticated ping verified');
'''
                reply = docker('exec', '-i', cid, 'mongosh', '--host', '127.0.0.1',
                               '--norc', '--quiet', '--file', '/dev/stdin', data=script)
                record['direct_ipv4_ping'] = {'exit': reply.returncode, 'stdout': reply.stdout[-3000:],
                                              'stderr': reply.stderr[-3000:]}
        records.append(record)
    with (root / (name + '-owned-container-state.json')).open('x') as f:
        json.dump({'original_project': project, 'docker_ps_exit': matches.returncode, 'containers': records}, f)
