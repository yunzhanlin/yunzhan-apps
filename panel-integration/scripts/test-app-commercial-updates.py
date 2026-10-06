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
    script = '''import hashlib,json,pathlib,sys
p=pathlib.Path('/etc/panel/security-apps/modules')/sys.argv[1]
v=json.loads((p/'installed.json').read_text())
files={str(f.relative_to(p)):hashlib.sha256(f.read_bytes()).hexdigest() for f in p.rglob('*') if f.is_file() and not f.is_symlink() and f.name!='installed.json' and f.stat().st_size<4194304}
print(json.dumps({'manifest':v,'files':files}))'''
    return json.loads(p.vm('sudo', 'python3', '-c', script, target).stdout)

def save(value):
    state.parent.mkdir(parents=True, exist_ok=True)
    state.write_text(json.dumps(value, indent=2) + '\n')
    state.chmod(0o600)

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
            assert status['update_available'] and status['update_supported'], status
            before = snapshot(app['target'])
            p.wait(p.api('/app-registry/' + app_id + '/update', {
                'expected_version':app['version'], 'expected_sha256':app['sha256']
            })['job_id'], timeout=90)
            after = snapshot(app['target'])
            original = value['before'][app_id]
            assert before['files'] == after['files'], app_id + ' modified reports, baselines or plans during upgrade'
            assert after['manifest'].get('settings') == original['manifest'].get('settings'), app_id + ' reset settings'
            assert after['manifest']['installed_at'] == original['manifest']['installed_at'], app_id + ' reset install time'
            assert after['manifest']['version'] == '1.3.0', app_id
            value['checks'].append(app_id + ': actual signed download/job, unchanged settings, install time and all private data files')
            save(value)
            print('PASS', app_id, 'signed GitHub update and data preservation', flush=True)
        final = p.api('/app-registry?refresh=1')
        assert not final['source']['stale'], final['source']
        statuses = {s['id']:s for s in final['status']}
        for app_id in IDS:
            assert not statuses[app_id]['update_available'] and statuses[app_id]['version_known'], statuses[app_id]
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
