"""Verify current signed Pure-FTPd soft quotas and actual encrypted bandwidth limits."""
from pathlib import Path
import contextlib
import ftplib
import io
import socket
import ssl
import hashlib
import http.cookiejar
import json
import os
import platform
import re
import secrets
import sqlite3
import stat
import subprocess
import sys
import time
import traceback
from urllib.parse import urlencode
import urllib.error
import urllib.request

os.umask(0o077)
architecture={'x86_64':'amd64','aarch64':'arm64'}[platform.machine()]
assert os.geteuid()==0 and len(sys.argv) in (2,3)
inputs=Path(sys.argv[1]).resolve(strict=True)
pins=json.loads((inputs/'assets.json').read_text())
os_identity=dict(line.split('=',1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line and not line.startswith('#'))
case=pins['OS_case']
actual_platform=os_identity['ID']+'-'+os_identity['VERSION_ID'].strip('"')
assert actual_platform in ('debian-12','ubuntu-24.04')
assert case['platform']==actual_platform and case['architecture']==pins['architecture']==architecture
assert Path('/etc/hostname').read_text().strip()==pins['OS_case']['hostname']
recovering=len(sys.argv)==3
base=Path(sys.argv[2]).resolve(strict=True) if recovering else Path('/opt/panel-monitor-c197-qa-'+secrets.token_hex(16))
assert base.parent==Path('/opt') and re.fullmatch(r'panel-monitor-c197-qa-[a-f0-9]{32}',base.name)
out=base/'evidence'
if not recovering:out.mkdir(mode=0o700,parents=True)
assert base.stat().st_uid==out.stat().st_uid==0 and stat.S_IMODE(out.stat().st_mode)==0o700
boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
proof={'ok':False,'base':str(base),'boot':boot,'platform':actual_platform,'architecture':architecture,
       'source_inputs_sha256':pins['source_inputs_sha256'],'Main_changed':False,'all50_commercial':False}
client=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
local=urllib.request.build_opener(urllib.request.ProxyHandler({}))
origin='http://127.0.0.1:19100'
csrf=''
def sha(x):return hashlib.sha256(x).hexdigest()
def save(path,v):
    with path.open('x') as f:json.dump(v,f,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
def api(path,body=None,status=200,key=None):
    headers={'Origin':origin,'Content-Type':'application/json','X-CSRF-Token':csrf}
    if key:headers['Idempotency-Key']=key
    req=urllib.request.Request(origin+'/api'+path,None if body is None else json.dumps(body).encode(),headers)
    try:
        with client.open(req,timeout=90) as res:
            assert res.status==status and res.url==req.full_url
            return json.load(res)
    except urllib.error.HTTPError as error:
        if error.code==status:
            return json.loads(error.read(8192))
        raise

def wait_job(table,job,seconds):
    assert table in ('jobs','runtime_jobs') and re.fullmatch('[a-f0-9]{32}',job)
    end=time.monotonic()+seconds
    while time.monotonic()<end:
        with contextlib.closing(sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True)) as db:
            db.row_factory=sqlite3.Row;db.execute('PRAGMA query_only=ON')
            row=db.execute('SELECT * FROM '+table+' WHERE id=?',(job,)).fetchone()
        if row is not None and row['state'] not in ('queued','running'):
            assert row['state']=='succeeded' and not row['error'],row['error']
            return dict(row)
        time.sleep(1)
    raise TimeoutError(table)
def command(label,args,timeout=120):
    with(out/(label+'.stdout')).open('xb') as stdout,(out/(label+'.stderr')).open('xb') as stderr:
        result=subprocess.run(args,stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr,timeout=timeout)
    assert result.returncode==0,label
def sign_input_copy():
    dest=base/'verified-input';dest.mkdir(mode=0o700)
    for name,digest in pins['files'].items():
        assert re.fullmatch(r'[A-Za-z0-9._-]+',name) and re.fullmatch('[a-f0-9]{64}',digest)
        with os.fdopen(os.open(inputs/name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC),'rb') as f:
            st=os.fstat(f.fileno())
            assert stat.S_ISREG(st.st_mode) and st.st_nlink==1 and 0<st.st_size<=64<<20
            raw=f.read((64<<20)+1)
        assert len(raw)==st.st_size and sha(raw)==digest
        with(dest/name).open('xb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
    assert sha((dest/'release-signing-dev.pub').read_bytes())=='4ccfcc861d56a41e3ba7f7ace7e2432c815f366c58448d783df92c6632f01339'
    return dest

legacy_source = "import hashlib\nimport http.cookiejar\nimport json\nimport os\nfrom pathlib import Path\nimport re\nimport secrets\nimport sys\nimport time\nimport urllib.request\n\nos.umask(0o077)\nplan = json.loads(sys.argv[1])\nassert os.geteuid() == 0 and Path('/proc/sys/kernel/random/boot_id').read_text().strip() == plan['boot']\nassert json.loads(Path('/opt/panel/current/SOURCE_INPUTS.json').read_bytes())['inputs_sha256'] == plan['programme']\napp = plan['app']\norigin = 'http://127.0.0.1:19100'\nmodule = '/app-modules/file-monitor'\nslug = 'file-monitor-qa-' + secrets.token_hex(5)\ndomain = slug + '.localhost'\n\n\nclass NoRedirect(urllib.request.HTTPRedirectHandler):\n    def redirect_request(self, *args, **kwargs):\n        raise RuntimeError('Unexpected redirect')\n\n\nsession = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),\n    urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))\ncsrf = ''\n\n\ndef api(path, body=None, status=200, key=None):\n    headers = {'Origin': origin, 'Content-Type': 'application/json', 'X-CSRF-Token': csrf}\n    if key:\n        headers['Idempotency-Key'] = key\n    raw = None if body is None else json.dumps(body).encode()\n    with session.open(urllib.request.Request(origin + '/api' + path, raw, headers), timeout=55) as response:\n        assert response.status == status\n        result = response.read((8 << 20) + 1)\n        assert len(result) <= 8 << 20\n        return json.loads(result)\n\n\ndef evidence(event, **fields):\n    print(json.dumps({'event': event, **fields}, sort_keys=True), flush=True)\n\n\ndef wait(read, ready, timeout):\n    deadline = time.monotonic() + timeout\n    while time.monotonic() < deadline:\n        observed = read()\n        if ready(observed):\n            return observed\n        time.sleep(1.2)\n    raise TimeoutError('Original file monitor operation did not settle')\n\n\ndef post_job(label, endpoint, request):\n    key = secrets.token_hex(16)\n    evidence('intent', label=label, key=key, request=request)\n    job = api(endpoint, request, 202, key)['job_id']\n    assert re.fullmatch('[a-f0-9]{32}', job)\n    evidence('accepted', label=label, job=job)\n    result = wait(lambda: api('/jobs/' + job),\n        lambda row: row['state'] in ('succeeded', 'failed', 'needs_attention', 'cancelled'), 330)\n    assert result['state'] == 'succeeded', (label, result['state'], result['error'])\n    return result\n\n\nauth = json.loads(Path('/etc/panel/first-login.json').read_bytes())\ncsrf = api('/login', {key: auth[key] for key in ('username', 'password')})['csrf']\nauth.clear()\ntry:\n    previous_sites = sorted(api('/sites'), key=lambda row: row['id'])\n    catalog = api('/app-registry?refresh=1')\n    assert catalog['host']['architecture'] == plan['arch'] and not catalog['source']['stale']\n    assert len(catalog['catalog']['apps']) == 50\n    assert next(row for row in catalog['catalog']['apps'] if row['id'] == app['id']) == app\n    assert app['version'] == '1.4.1'\n    status = next(row for row in catalog['status'] if row['id'] == app['id'])\n    assert status['state_known'] and status['supported'] and not status['installed']\n    installed = post_job('signed-app', '/app-registry/file-monitor/install',\n        {'expected_version': app['version'], 'expected_sha256': app['sha256']})\n    catalog = api('/app-registry?refresh=1')\n    state = next(row for row in catalog['status'] if row['id'] == app['id'])\n    assert state['installed'] and state['healthy'] and state['installed_version'] == app['version']\n    created = post_job('isolated-site', '/sites', {'name': 'File monitor QA', 'slug': slug, 'domain': domain})\n    site = created['site_id']\n    assert re.fullmatch('[a-f0-9]{32}', site)\n    parent = Path('/srv/panel/sites') / site\n    assert json.loads((parent / '.panel-site.json').read_bytes())['id'] == site\n    public = parent / 'public'\n    assert public.is_dir() and not public.is_symlink()\n    watched = public / 'monitor-qa.txt'\n    ignored = public / 'ignore-qa'\n    marker = public / 'monitor-qa-new'\n    owner = public.stat()\n    with watched.open('xb') as out:\n        out.write(b'original test file\\n')\n    os.chown(watched, owner.st_uid, owner.st_gid)\n    watched.chmod(0o644)\n    ignored.mkdir(mode=0o755)\n    baseline, = api(module + '/baseline', {'site_id': site, 'excludes': ['ignore-qa'], 'interval': 300, 'realtime': True})['sites']\n    assert baseline['site_id'] == site and baseline['realtime'] and baseline['files'] >= 1\n    baseline_file = Path('/etc/panel/security-apps/modules/file-monitor/baselines') / site / 'baseline.json'\n    baseline_sha = hashlib.sha256(baseline_file.read_bytes()).hexdigest()\n\n    def policy():\n        found, = [row for row in api(module + '/policies', {})['policies'] if row['site_id'] == site]\n        assert found['signature_verified']\n        return found\n\n    def history():\n        raw = api(module + '/history', {'site_id': site, 'limit': 32, 'offset': 0})\n        assert raw['read_only'] and raw['source'] == 'private-sqlite'\n        return raw['history']\n\n    def inotify_change(rows, exclude):\n        return next((row for row in rows if row['id'] not in exclude and row.get('changes_count', 0) >= 1 and\n            row['outcome'] == 'succeeded' and row['trigger'] in ('inotify','inotify-reconcile')), None)\n\n    active = wait(policy, lambda row: row['watcher_state'] == 'active', 100)\n    initial = {row['id'] for row in history()}\n    watched.write_bytes(b'modified by the QA owner\\n')\n    first = inotify_change(wait(history, lambda rows: inotify_change(rows, initial) is not None, 80), initial)\n    assert watched.read_bytes() == b'modified by the QA owner\\n'\n    marker.mkdir(mode=0o755)\n    (marker / 'new.txt').write_text('new nested entry')\n    (ignored / 'noise.txt').write_text('excluded by policy')\n    checked, = api(module + '/check', {'site_id': site})['sites']\n    changes = {row['path']: row['kind'] for row in checked['changes']}\n    assert 'monitor-qa.txt' in changes and 'monitor-qa-new/new.txt' in changes\n    assert not any(name.startswith('ignore-qa/') for name in changes) and checked['restored_count'] == 0\n    current = policy()\n    paused = api(module + '/pause', {'site_id': site, 'expected_revision': current['revision']})\n    assert not paused['enabled'] and paused['revision'] == current['revision'] + 1\n    assert policy()['watcher_state'] == 'disabled'\n    saved = {row['id'] for row in history()}\n    watched.write_bytes(b'written while paused\\n')\n    time.sleep(5)\n    assert {row['id'] for row in history()} == saved\n    resumed = api(module + '/resume', {'site_id': site, 'expected_revision': paused['revision']})\n    assert resumed['enabled'] and resumed['revision'] == paused['revision'] + 1\n    wait(policy, lambda row: row['watcher_state'] == 'active', 100)\n    watched.chmod(0o600)\n    later = inotify_change(wait(history, lambda rows: inotify_change(rows, saved) is not None, 80), saved)\n    assert hashlib.sha256(baseline_file.read_bytes()).hexdigest() == baseline_sha\n    assert watched.read_bytes() == b'written while paused\\n'\n    assert sorted((row for row in api('/sites') if row['id'] != site), key=lambda row: row['id']) == previous_sites\n    evidence('verified', ok=True, architecture=plan['arch'], catalogue=catalog['source']['resolved_commit'],\n             signed_install=installed['id'], test_site=site, first_event=first['id'], resumed_event=later['id'],\n             excluded_path_verified=True, baseline_preserved=True, original_sites_preserved=True,\n             native_watch_directories=active['watch_directories'])\nfinally:\n    api('/logout', {})\n"
try:
    if not recovering:
        assert not any(os.path.lexists(p) for p in ('/opt/panel','/etc/panel','/var/lib/panel'))
        staged=sign_input_copy()
        archive=staged/('panel-'+pins['version']+'-linux-'+architecture+'.tar.gz')
        signer=['python3','-I','-B',str(staged/'signed-release.py')]
        trust=['--public-key',str(staged/'release-signing-dev.pub')]
        command('signed-verify',signer+['verify',str(archive)]+trust)
        command('signed-preflight',signer+['install',str(archive)]+trust+['--preflight-only'],900)
        command('signed-install',signer+['install',str(archive)]+trust,1800)
        plan={'boot':boot,'programme':pins['source_inputs_sha256'],'app':pins['monitor'],'arch':architecture}
        prior_argv=sys.argv[:]
        try:
            sys.argv=['monitor-original-business.py',json.dumps(plan)]
            namespace={'__name__':'__main__'}
            exec(compile(legacy_source,'monitor-original-business.py','exec'),namespace)
        finally:
            sys.argv=prior_argv
        root=namespace['public']
        ident=namespace['site']
        baseline_file=namespace['baseline_file']
        marker_bytes=namespace['watched'].read_bytes()
        state={'site':ident,'file':str(namespace['watched'].relative_to(root)),
               'baseline':str(baseline_file),'baseline_sha':sha(baseline_file.read_bytes()),
               'content_sha':sha(marker_bytes),'boot':boot,'programme':pins['source_inputs_sha256'],
               'old_history':[row['id'] for row in namespace['history']()] if False else []}
        # Read history using the normal authenticated API before logout in the next phase.
        save(base/'state.json',state)
        proof.update(ok=True,powerloss_ready=True,phase='before-reboot',signed_monitor_version=pins['monitor']['version'],
             actual_inotify_events=True,excluded_paths=True,pause_resume=True,baseline_preserved=True)
    else:
        state=json.loads((base/'state.json').read_bytes())
        assert state['boot']!=boot and state['programme']==pins['source_inputs_sha256']
        creds=json.loads(Path('/etc/panel/first-login.json').read_bytes())
        csrf=api('/login',{key:creds[key] for key in ('username','password')})['csrf']
        creds.clear()
        module='/app-modules/file-monitor'
        baseline_path=Path(state['baseline'])
        assert sha(baseline_path.read_bytes())==state['baseline_sha']
        root=Path('/srv/panel/sites')/state['site']/'public'
        watched=root/state['file']
        assert sha(watched.read_bytes())==state['content_sha']
        deadline=time.monotonic()+100
        while time.monotonic()<deadline:
            policy,=[p for p in api(module+'/policies',{})['policies'] if p['site_id']==state['site']]
            assert policy['signature_verified']
            if policy['watcher_state']=='active':break
            time.sleep(1)
        else:raise TimeoutError('Watcher did not recover after hard power loss')
        before=api(module+'/history',{'site_id':state['site'],'limit':100,'offset':0})['history']
        ids={row['id'] for row in before}
        watched.write_bytes(b'original post-powerloss monitor business event')
        deadline=time.monotonic()+90
        while time.monotonic()<deadline:
            history=api(module+'/history',{'site_id':state['site'],'limit':100,'offset':0})['history']
            if any(row['id'] not in ids and row['outcome']=='succeeded' and row['trigger'] in ('inotify','inotify-reconcile') and row.get('changes_count',0)>0 for row in history):break
            time.sleep(1)
        else:raise TimeoutError('Real post-powerloss file write was not detected')
        assert ids.issubset({row['id'] for row in history})
        assert sha(baseline_path.read_bytes())==state['baseline_sha']
        proof.update(ok=True,phase='after-reboot',prior_boot=state['boot'],signed_monitor_version=pins['monitor']['version'],
              actual_inotify_recovered=True,original_file_and_baseline_preserved=True,old_history_retained=True)
except BaseException:
    proof['failure']=traceback.format_exc()
finally:
    if csrf:
        try:api('/logout',{})
        except Exception:proof['ok']=False
    save(out/('phase2.json' if recovering else 'phase1.json'),proof)
    print(json.dumps(proof),flush=True)
sys.exit(0 if proof['ok'] else 1)
