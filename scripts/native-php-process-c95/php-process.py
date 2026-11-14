"""Verify site file operation mount boundaries through the signed application on an owned Linux runner."""
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
apps=plan['items']
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
    catalog=api('/app-registry?refresh=1')
    assert catalog['host']['architecture']==arch and catalog['source']['resolved_commit']==plan['served_head']
    assert not catalog['source']['stale'] and len(catalog['catalog']['apps'])==50
    receipts={}
    for id, app in apps.items():
        assert next(v for v in catalog['catalog']['apps'] if v['id']==id)==app
        assert not next(v for v in catalog['status'] if v['id']==id)['installed']
        result=job(id+'-signed-install','/app-registry/'+id+'/install',
                   {'expected_version':app['version'],'expected_sha256':app['sha256']})
        state=api('/app-modules/'+id)['status']
        assert state['installed'] and state['version']==app['version']
        receipts[id]={'job':result['id'],'version':app['version'],'sha256':app['sha256']}
    prior={x['id']:x for x in api('/sites')}
    own={}
    for label in ('source','target'):
        slug='c158-'+label+'-'+secrets.token_hex(5)
        made=job('site-'+label,'/sites',{'name':'C158 '+label,'slug':slug,'domain':slug+'.localhost'})
        site=made['site_id']
        assert site not in prior and re.fullmatch('[a-f0-9]{32}',site)
        root=Path('/srv/panel/sites')/site
        assert json.loads((root/'.panel-site.json').read_bytes())['id']==site
        public=root/'public'
        assert public.is_dir() and not public.is_symlink()
        own[label]=(site,root,public)
    site,root,public=own['source']
    target,target_root,target_public=own['target']
    executor=command('/usr/bin/systemctl','show','panel-executor.service','-p','MainPID','--value')
    assert int(executor)>1
    private=root/'c158-fixture-outside-public'
    private.mkdir(mode=0o700)
    external=private/'private.php'
    external_data=b"<?php eval('external sample');"
    external.write_bytes(external_data)
    plain=public/'in-scope.txt'
    plain.write_text('ordinary file\n')
    owned_php=public/'ordinary.php'
    owned_php.write_bytes(b'<?php echo 1;')
    alias=public/'mounted'
    alias.mkdir(mode=0o700)
    covered=public/'file-alias.php'
    covered.touch(mode=0o600)
    assert public.stat().st_dev==private.stat().st_dev
    modules=('enterprise-tamper-proof','website-tamper-proof','file-monitor')
    for id in modules:
        out=api('/app-modules/'+id+'/baseline',{'site_id':site,'auto_restore':id=='enterprise-tamper-proof'})
        assert out['sites'][0]['site_id']==site and out['sites'][0]['signature']
        save(id+'-original-baseline-response.json',out)
    dirs=[Path('/etc/panel/security-apps/modules')/id/'baselines'/site for id in modules]
    def baseline_hashes():
        return [(directory/'baseline.json').read_bytes() for directory in dirs]
    baseline=baseline_hashes()
    plain.write_text('local modification')
    first=external.stat()
    attached=[]
    errors={}
    inputs={'site_id':site,'target_site_id':target}
    try:
        for source_path,target_path in ((private,alias),(external,covered)):
            command(*mounted(source_path,target_path,executor))
            attached.append(target_path)
        operations=[(id,'check',{'site_id':site}) for id in modules]
        operations.extend([('php-code-security','run',{'site_id':site}),('files-sync','sync',inputs)])
        for id,action,payload in operations:
            reply=api('/app-modules/'+id+'/'+action,payload,status=409)
            assert '跨越网站根挂载边界' in reply['error'],(id,reply)
            errors[id]=reply
        assert baseline_hashes()==baseline and plain.read_text()=='local modification'
        for base in dirs:
            assert not (base/'blobs'/hashlib.sha256(external_data).hexdigest()).exists()
        assert not (target_public/plain.name).exists()
        safe=api('/app-modules/files-sync/sync',{**inputs,'excludes':[alias.name,covered.name]})
        assert (target_public/plain.name).read_text()=='local modification'
        assert not (target_public/alias.name).exists() and not (target_public/covered.name).exists()
        assert external.read_bytes()==external_data and external.stat().st_ino==first.st_ino
        save('mount-refusals-original.json',errors)
        save('sync-with-exclusions-original.json',safe)
    finally:
        for path in reversed(attached):
            command('/usr/bin/nsenter','--mount=/proc/'+executor+'/ns/mnt','--','/usr/bin/umount',str(path))
    restored=api('/app-modules/enterprise-tamper-proof/check',{'site_id':site})
    assert restored['sites'][0]['restored_count']==1 and plain.read_text()=='ordinary file\n'
    assert baseline_hashes()==baseline
    assert {x['id']:x for x in api('/sites') if x['id'] not in (site,target)}==prior
    save('restore-after-unmount-original.json',restored)
    proof.update(ok=True,actual_same_device_directory_and_file_binds_refused=True,
                 original_signed_baselines_and_outside_data_preserved=True,
                 normal_excluded_sync_and_post_mount_restore=True,
                 original_other_sites_preserved=True,signed_apps=receipts)
except BaseException:
    proof['failure']=traceback.format_exc()
finally:
    if csrf:
        with contextlib.suppress(Exception):
            api('/logout',{})
    save('original-proof.json',proof)
if not proof['ok']:
    print(proof.get('failure','actual signed app experience failed'),file=sys.stderr)
    sys.exit(1)
