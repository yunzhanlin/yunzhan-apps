#!/usr/bin/env python3
"""Five signed legacy -> 1.3 upgrades on isolated QA; never changes settings."""
import json
import os
import pathlib
import sys
from panel_client import PanelClient

assert os.environ.get('PANEL_VM') in ('panel-compat-ubuntu24', 'panel-store-apps-debian13'), 'Isolated QA host required'
IDS = ('file-monitor', 'website-tamper-proof', 'enterprise-tamper-proof', 'files-sync', 'mobile')
state = pathlib.Path(os.environ['COMMERCIAL_UPDATE_STATE'])
p = PanelClient()

def snapshot(target):
    script = '''import hashlib,json,pathlib,sqlite3,sys
p=pathlib.Path('/etc/panel/security-apps/modules')/sys.argv[1]
v=json.loads((p/'installed.json').read_text())
files={str(f.relative_to(p)):hashlib.sha256(f.read_bytes()).hexdigest() for f in p.rglob('*') if f.is_file() and not f.is_symlink() and f.name!='installed.json' and f.stat().st_size<4194304}
active=[]
for f in (p/'baselines').glob('*/monitoring.json'):
 if json.loads(f.read_text()).get('enabled'):active.append(f.parent.name)
rows={}
if (p/'history.sqlite').is_file():
 with sqlite3.connect('file:'+str(p/'history.sqlite')+'?mode=ro',uri=True) as db:
  rows={id:hashlib.sha256(payload.encode()).hexdigest() for id,payload in db.execute('SELECT event_id,payload FROM module_events')}
print(json.dumps({'manifest':v,'files':files,'active_sites':active,'history_rows':rows}))'''
    return json.loads(p.vm('sudo', 'python3', '-c', script, target).stdout)

def save(value):
    state.parent.mkdir(parents=True, exist_ok=True)
    state.write_text(json.dumps(value, indent=2) + '\n')
    state.chmod(0o600)

def preserved(before, after, app_id):
    # Existing 60-second QA monitors continue writing scheduled reports. Never
    # pause someone else's policy or equate a legitimate append with data loss.
    dynamic = {'history.json','history.sqlite','history.sqlite-journal','last-report.json'}
    for site in before.get('active_sites', after.get('active_sites', [])):
        dynamic.update({'baselines/'+site+'/monitoring.json','baselines/'+site+'/last-check.json'})
    for name in set(before['files']) | set(after['files']):
        if name not in dynamic:
            assert before['files'].get(name) == after['files'].get(name), app_id + ': changed immutable baseline, backup, inactive policy or plan ' + name
    for row, digest in before.get('history_rows', {}).items():
        assert after['history_rows'].get(row) == digest, app_id + ': previous indexed event lost or rewritten'

try:
    if sys.argv[1] == 'prepare':
        assert not state.exists(), 'Inspect existing state before rerunning'
        catalog = p.api('/app-registry')
        apps = {a['id']:a for a in catalog['catalog']['apps']}
        original = {}
        for app_id in IDS:
            original[app_id] = snapshot(apps[app_id]['target'])
            assert original[app_id]['manifest']['version'] in ('1.0', '1.2.0'), app_id
        save({'before':original, 'checks':[], 'passed':False})
        print('PASS five existing legacy apps snapshotted without changing configuration', flush=True)
    else:
        value = json.loads(state.read_text())
        catalog = p.api('/app-registry?refresh=1')
        assert not catalog['source']['stale'], catalog['source']
        apps = {a['id']:a for a in catalog['catalog']['apps']}
        statuses = {s['id']:s for s in catalog['status']}
        for app_id in IDS:
            app, status = apps[app_id], statuses[app_id]
            assert app['version'] == '1.3.0', (app_id, app['version'])
            before = snapshot(app['target'])
            if status['update_available']:
                assert status['update_supported'], status
                p.wait(p.api('/app-registry/' + app_id + '/update', {
                    'expected_version':app['version'], 'expected_sha256':app['sha256']
                })['job_id'], timeout=90)
            else:
                # Resume an interrupted verification only after the real
                # update completed, not after changing a version by hand.
                assert status['installed_version'] == '1.3.0' and value['before'][app_id]['manifest']['version'] != '1.3.0', status
            after = snapshot(app['target'])
            original = value['before'][app_id]
            preserved(before, after, app_id)
            preserved(original, after, app_id)
            assert after['manifest'].get('settings') == original['manifest'].get('settings'), app_id + ' reset settings'
            assert after['manifest']['installed_at'] == original['manifest']['installed_at'], app_id + ' reset install time'
            assert after['manifest']['version'] == '1.3.0', app_id
            check = app_id + ': actual signed download/job; settings, install time, signed baselines, inactive policies and plans preserved; existing indexed events preserved while scheduled checks may append'
            if check not in value['checks']: value['checks'].append(check)
            save(value)
            print('PASS', app_id, 'signed GitHub update and data preservation', flush=True)
        final = p.api('/app-registry?refresh=1')
        assert not final['source']['stale'], final['source']
        statuses = {s['id']:s for s in final['status']}
        for app_id in IDS:
            assert not statuses[app_id]['update_available'] and statuses[app_id]['version_known'], statuses[app_id]
        suffix = 'arm64' if os.environ['PANEL_VM'] == 'panel-compat-ubuntu24' else 'amd64'
        fixture = json.loads(pathlib.Path('.local/commercial-foundation-'+suffix+'-v3.json').read_text())
        history = p.api('/app-modules/file-monitor/history?site_id='+fixture['sites'][0]+'&limit=20&offset=100')
        assert fixture['passed'] and history['total'] >= 105 and len(history['history']) >= 5, 'own older history lost after update'
        try:
            p.api('/app-registry/files-sync/update', {'expected_version':'1.2.0', 'expected_sha256':apps['files-sync']['sha256']})
        except RuntimeError as error:
            assert 'HTTP 409' in str(error), error
        else:
            raise AssertionError('stale update accepted')
        value['passed'] = True
        value['updated_apps'] = len(IDS)
        save(value)
        print('PASS all five badges cleared only after real updates; stale update rejected', flush=True)
finally:
    p.close()
