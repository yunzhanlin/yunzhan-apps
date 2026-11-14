"""Verify actual disk analysis through the signed application on an owned Linux runner."""
from pathlib import Path
import contextlib
import hashlib
import http.cookiejar
import json
import os
import platform
import re
import secrets
import stat
import subprocess
import sys
import time
import traceback
import urllib.error
import urllib.request

os.umask(0o077)
assert os.geteuid()==0 and os.environ['GITHUB_ACTIONS']=='true'
assert os.environ['GITHUB_REPOSITORY']=='yunzhanlin/yunzhan-apps'
assert len(sys.argv)==2
evidence=Path(sys.argv[1])/'business-phase1'
evidence.mkdir(mode=0o700)
plan=json.loads((Path(__file__).resolve().parent/'cohort.json').read_bytes())
source=json.loads(Path('/opt/panel/current/SOURCE_INPUTS.json').read_bytes())['inputs_sha256']
assert source==plan['source_inputs_sha256']
arch={'x86_64':'amd64','aarch64':'arm64'}[platform.machine()]
app=plan['items']['disk-analysis']
origin='http://127.0.0.1:19100'
csrf=None

def save(name,data):
    with (evidence/name).open('x') as f:json.dump(data,f,indent=2);f.write('\n')

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):raise RuntimeError('Unexpected redirect')

client=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect(),
                                  urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

def api(route,payload=None,status=200,key=None):
    headers={'Origin':origin,'Content-Type':'application/json'}
    if csrf:headers['X-CSRF-Token']=csrf
    if key:headers['Idempotency-Key']=key
    req=urllib.request.Request(origin+'/api'+route,None if payload is None else json.dumps(payload).encode(),headers)
    try:
        with client.open(req,timeout=75) as r:
            assert r.status==status,(route,r.status)
            return json.loads(r.read(8<<20))
    except urllib.error.HTTPError as err:
        if err.code!=status:raise RuntimeError((route,err.code,err.read(1500).decode(errors='replace'))) from err
        return json.loads(err.read(4096))

def job(label,route,payload):
    key=secrets.token_hex(16)
    save(label+'-original-request.json',{'path':route,'body':payload,'idempotency_key':key,'maximum_submissions':1})
    accepted=api(route,payload,202,key)
    jid=accepted['job_id']
    assert re.fullmatch('[a-f0-9]{32}',jid)
    for _ in range(360):
        result=api('/jobs/'+jid)
        if result['state'] in ('succeeded','failed','needs_attention','cancelled'):
            save(label+'-original-outcome.json',result)
            assert result['id']==jid and result['state']=='succeeded',result['state']
            return result
        time.sleep(2)
    raise TimeoutError(jid)

def command(*args):
    return subprocess.check_output(args,text=True,stderr=subprocess.STDOUT,timeout=40).strip()

def mounted(source,target,executor_pid):
    assert re.fullmatch(r'[0-9]+',executor_pid)
    return ['/usr/bin/nsenter','--mount=/proc/'+executor_pid+'/ns/mnt','--',
            '/usr/bin/mount','--bind',str(source),str(target)]

proof={'ok':False,'architecture':arch,'source_inputs_sha256':source,'Main_changed':False,'all50_commercial':False}
try:
    access=json.loads(Path('/etc/panel/first-login.json').read_bytes())
    csrf=api('/login',{k:access[k] for k in ('username','password')})['csrf']
    access.clear()
    catalog=None
    for delay in (20,50,90,0):
        try:
            catalog=api('/app-registry?refresh=1')
            break
        except RuntimeError:
            if not delay:raise
            time.sleep(delay)
    assert catalog['host']['architecture']==arch and catalog['source']['resolved_commit']==plan['served_head']
    assert not catalog['source']['stale'] and len(catalog['catalog']['apps'])==50
    assert next(v for v in catalog['catalog']['apps'] if v['id']==app['id'])==app
    assert not next(v for v in catalog['status'] if v['id']==app['id'])['installed']
    install=job('disk-signed-install','/app-registry/disk-analysis/install',{'expected_version':app['version'],'expected_sha256':app['sha256']})
    appstate=api('/app-modules/disk-analysis')['status']
    assert appstate['installed'] and appstate['version']==app['version']
    prior={x['id']:x for x in api('/sites')}
    slug='c157-mount-test-'+secrets.token_hex(5)
    made=job('test-site','/sites',{'name':'C157 Disk QA','slug':slug,'domain':slug+'.localhost'})
    site=made['site_id'];assert site not in prior and re.fullmatch('[a-f0-9]{32}',site)
    root=Path('/srv/panel/sites')/site
    assert json.loads((root/'.panel-site.json').read_bytes())['id']==site
    public=root/'public'
    assert public.is_dir() and not public.is_symlink()
    executor=command('/usr/bin/systemctl','show','panel-executor.service','-p','MainPID','--value')
    assert int(executor)>1
    private=root/'c157-owned-fixture-outside-public'
    private.mkdir(mode=0o700)
    external=private/'c157-external-name.bin'
    with external.open('xb') as f:f.write(b'owned synthetic external file'*16384)
    plain=public/'c157-in-scope.txt'
    plain.write_text('reachable business data\n')
    alias=public/'c157-alias'
    alias.mkdir(mode=0o700)
    covered=public/'c157-file-alias.bin'
    covered.touch(mode=0o600)
    assert public.stat().st_dev==private.stat().st_dev
    endpoint='/app-modules/disk-analysis/run'
    baseline=api(endpoint,{'site_id':site})
    assert baseline['scan_complete'] and baseline['foreign_filesystems_skipped']==0
    first=external.stat()
    choices=((private,alias),(external,covered))
    attached=[]
    try:
        for a,b in choices:
            command(*mounted(a,b,executor))
            attached.append(b)
        scan=api(endpoint,{'site_id':site})
        assert scan['foreign_filesystems_skipped']==2 and not scan['scan_complete'] and scan['partial']
        assert scan['files']==baseline['files']-1
        assert all('c157-external-name' not in str(v) and 'c157-file-alias' not in str(v) for v in scan['largest_files'])
        rejection=api(endpoint,{'site_id':site,'path':alias.name},status=409)
        assert '跨越网站扫描根挂载边界' in rejection['error']
        assert external.stat().st_ino==first.st_ino and external.stat().st_size==first.st_size
        save('mount-scan-original-observation.json',{'skipped':scan['foreign_filesystems_skipped'],
             'baseline_files':baseline['files'],'scan_files':scan['files'],'explicit_refusal':rejection['error'],
             'owned_original_file_retained':True})
    finally:
        for b in reversed(attached):
            command('/usr/bin/nsenter','--mount=/proc/'+executor+'/ns/mnt','--','/usr/bin/umount',str(b))
    after=api(endpoint,{'site_id':site})
    assert after['scan_complete'] and after['foreign_filesystems_skipped']==0 and after['files']==baseline['files']
    assert {x['id']:x for x in api('/sites') if x['id']!=site}==prior
    proof.update(ok=True,actual_same_device_directory_and_file_binds_skipped=True,actual_explicit_drill_refused=True,
                 actual_complete_scan_after_unmount=True,site=site,signed_install=install['id'],
                 manifest_sha256=app['sha256'],source_app_version=app['version'])
except BaseException:
    proof['failure']=traceback.format_exc()
finally:
    if csrf:
        with contextlib.suppress(Exception):api('/logout',{})
    save('original-proof.json',proof)
sys.exit(0 if proof['ok'] else 1)
