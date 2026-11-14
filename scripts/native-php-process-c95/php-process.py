"""Verify PHP quarantine and restoration mount boundaries through the signed application on an owned Linux runner."""
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
app=plan['items']['php-code-security']
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
    registry=api('/app-registry?refresh=1')
    assert registry['source']['resolved_commit']==plan['served_head'] and not registry['source']['stale']
    assert registry['host']['architecture']==arch
    assert next(v for v in registry['catalog']['apps'] if v['id']==app['id'])==app
    assert not next(v for v in registry['status'] if v['id']==app['id'])['installed']
    installed=job('php-code-security-signed-install','/app-registry/php-code-security/install',
        {'expected_version':app['version'],'expected_sha256':app['sha256']})
    assert api('/app-modules/php-code-security')['status']['version']==app['version']
    prior={x['id']:x for x in api('/sites')}
    slug='c159-php-quarantine-'+secrets.token_hex(5)
    site=job('site','/sites',{'name':'C159 PHP quarantine', 'slug':slug, 'domain':slug+'.localhost'})['site_id']
    root=Path('/srv/panel/sites')/site
    assert re.fullmatch('[a-f0-9]{32}',site) and json.loads((root/'.panel-site.json').read_bytes())['id']==site
    public=root/'public'
    assert not public.is_symlink()
    # This is a dedicated test site. Set its service-owner identity without
    # depending on a long PHP build; quarantine itself never starts PHP.
    import pwd
    uid,gid=public.stat().st_uid,public.stat().st_gid
    if uid==0:
        account=pwd.getpwnam('www-data')
        uid,gid=account.pw_uid,account.pw_gid
        os.chown(public,uid,gid)
    assert uid>0
    local=public/'owned'
    outside=root/'owned-external-fixture'
    for path in (local,outside):
        path.mkdir(mode=0o750)
        os.chown(path,uid,gid)
    owned,external=local/'candidate.php',outside/'candidate.php'
    data=b"<?php /* isolated QA */ eval('return 1;');"
    sha=hashlib.sha256(data).hexdigest()
    for path in (owned,external):
        path.write_bytes(data)
        os.chown(path,uid,gid)
        path.chmod(0o640)
    assert owned.stat().st_dev==external.stat().st_dev
    executor=command('/usr/bin/systemctl','show','panel-executor.service','-p','MainPID','--value')
    base='/app-modules/php-code-security/'
    path='owned/candidate.php'
    request={'site_id':site,'path':path,'expected_sha':sha,'confirm':'QUARANTINE '+path}
    def one_mount(src,dst,action):
        command(*mounted(src,dst,executor))
        try:
            return action()
        finally:
            command('/usr/bin/nsenter','--mount=/proc/'+executor+'/ns/mnt','--','/usr/bin/umount',str(dst))
    def refused():
        return api(base+'quarantine',request,status=409)
    a=one_mount(outside,local,refused)
    b=one_mount(external,owned,refused)
    assert all('挂载' in val['error'] for val in (a,b))
    assert api(base+'quarantine-list',{'site_id':site})['total']==0
    assert owned.read_bytes()==external.read_bytes()==data
    save('mounted-source-refusals-original.json',{'directory':a,'file':b,'site_records':0})
    row=api(base+'quarantine',request)['record']
    rid=row['id']
    assert re.fullmatch('[a-f0-9]{32}',rid) and row['state']=='quarantined' and not owned.exists()
    save('isolated-original.json',row)
    backup=root/'.panel-files'/'php-quarantine'/rid/'backup.bin'
    st=backup.stat()
    original=Path('/etc/panel/security-apps/modules/php-code-security/quarantine')/(rid+'.json')
    retained=original.read_bytes()
    expected={'site_id':site,'path':path,'expected_sha':sha,'resource_id':rid,
             'expected_revision':row['revision'],'confirm':'RESTORE PHP '+rid}
    response=one_mount(outside,local,lambda: api(base+'restore-quarantine',expected,status=409))
    assert '挂载' in response['error'] and original.read_bytes()==retained
    assert external.read_bytes()==data and (backup.stat().st_ino,backup.read_bytes())==(st.st_ino,data)
    assert st.st_uid==0 and stat.S_IMODE(st.st_mode)==0o600
    restored=api(base+'restore-quarantine',expected)['record']
    assert restored['id']==rid and restored['state']=='restored' and restored['revision']>row['revision']
    assert owned.read_bytes()==data and owned.stat().st_uid==uid
    assert external.read_bytes()==data and {x['id']:x for x in api('/sites') if x['id']!=site}==prior
    save('mounted-destination-refusal-original.json',response)
    save('restored-after-unmount-original.json',restored)
    proof.update(ok=True,original_app_version=app['version'],manifest_sha256=app['sha256'],
                 original_install=installed['id'],original_quarantine_record=rid,
                 actual_file_and_parent_binds_refused_before_isolation=True,
                 restore_refused_with_independent_root_backup_preserved=True,
                 original_restoration_after_unmount_succeeded=True)
except BaseException:
    proof['failure']=traceback.format_exc()
finally:
    if csrf:
        with contextlib.suppress(Exception):api('/logout',{})
    save('original-proof.json',proof)
if not proof['ok']:
    print(proof.get('failure','actual signed app experience failed'),file=sys.stderr)
    sys.exit(1)
