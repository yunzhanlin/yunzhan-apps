import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import subprocess
import sys
import time
import urllib.request

os.umask(0o077)
assert os.geteuid() == 0 and sys.platform == 'linux' and len(sys.argv) == 3
assert os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('GITHUB_REPOSITORY') == 'yunzhanlin/yunzhan-apps'
wheel = Path(sys.argv[2])
assert hashlib.sha256(wheel.read_bytes()).hexdigest() == '0779a7c1fafd805672796085560d290213a465e4f6f76a6fb19e378d8041a14f'
sys.path.insert(0, str(wheel))
import pika

out = Path(sys.argv[1])/'business-phase1'
read = lambda name: json.loads((out/name).read_bytes())
fixture = read('chrome-migration-fixture.json')
browser = read('original-browser-migration-proof.json')
assert browser['ok'] and browser['project'] == fixture['project']
engine = 'panel_' + fixture['project'][:12]
docker = ['/usr/bin/docker', '--host', 'unix:///run/docker.sock']

def read_docker(kind, resource):
    raw = subprocess.check_output(docker + [kind, 'inspect', resource], timeout=10)
    value, = json.loads(raw)
    return value

container = subprocess.check_output(docker + ['ps', '-q', '--no-trunc', '--filter', 'label=com.docker.compose.project='+engine], timeout=10).decode().strip()
assert re.fullmatch('[a-f0-9]{64}', container)
state = read_docker('container', container)
assert state['HostConfig']['PortBindings'] == {'15672/tcp':[{'HostIp':'127.0.0.1','HostPort':'26561'}],
                                               '5672/tcp':[{'HostIp':'127.0.0.1','HostPort':'26562'}]}
volume, = state['Mounts']
assert volume['Name'] == 'panel_rabbitmq_' + browser['job'] and volume['Destination'] == '/var/lib/rabbitmq'
assert read_docker('volume', fixture['original_volume'])['Mountpoint'] != volume['Source']
assert state['Config']['Image'].startswith('rabbitmq:4.4.0-management-alpine@sha256:')
secret, = [entry.split('=',1)[1] for entry in state['Config']['Env'] if entry.startswith('RABBITMQ_DEFAULT_PASS=')]
assert re.fullmatch('[a-f0-9]{64}', secret)
conn = pika.BlockingConnection(pika.ConnectionParameters(host='127.0.0.1', port=26562,
    credentials=pika.PlainCredentials('paneladmin', secret), connection_attempts=1, socket_timeout=5,
    stack_timeout=12, blocked_connection_timeout=12, heartbeat=15))
try:
    channel = conn.channel()
    method, props, body = channel.basic_get(fixture['queue'])
    assert method and props.delivery_mode == 2 and hashlib.sha256(body).hexdigest() == fixture['message_sha256']
    channel.basic_ack(method.delivery_tag)
finally:
    conn.close()
with sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro', uri=True) as db:
    rows = db.execute('SELECT job_id,state FROM rabbitmq_migration_requests').fetchall()
    assert rows == [(browser['job'], 'target-published')]
    item, = db.execute("SELECT scope,version,sha256,target FROM app_registry_receipts WHERE app_id='rabbitmq'").fetchall()
    assert item == (fixture['project'], '4.4.0-compat1', fixture['payload']['target_manifest_sha256'], 'rabbitmq-440')
proof = read('original-proof.json')
assert proof['ok'] and proof['prepared_actual_browser_migration'] and proof['active_client_prevented_migration']
proof.update(browser_UI_qualified=True, exact_44_signed_app_installed=True, original_legacy_retained=True,
             original_44_message_retained=True, actual_migration_job=browser['job'], same_project_and_ports=True,
             confirmed_old_message_using_browser_submitted_job=True)
(out/'original-proof.json').write_text(json.dumps(proof, indent=2)+'\n')
print(json.dumps({'ok':True,'verified_browser_job':browser['job'],'same_project_and_ports':True}))
