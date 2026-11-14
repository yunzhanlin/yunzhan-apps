"""Install and exercise signed Nginx on the owned Ubuntu 26 AMD64 guest."""
from pathlib import Path
import gzip
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
import urllib.error
import urllib.request

os.umask(0o077)
assert os.geteuid()==0 and platform.machine()=='x86_64'
inputs=Path(sys.argv[1]).resolve(strict=True)
pins=json.loads((inputs/'assets.json').read_text())
case=pins['OS_case']
assert case['platform']=='ubuntu-26.04' and case['hostname']==Path('/etc/hostname').read_text().strip()
assert 'VERSION_ID="26.04"' in Path('/etc/os-release').read_text()
assert not Path('/opt/panel').exists() and not Path('/var/lib/panel').exists()
base=Path('/opt/panel-nginx-c170-qa-'+secrets.token_hex(16))
out=base/'evidence';out.mkdir(parents=True,mode=0o700)
proof={'ok':False,'base':str(base),'platform':'ubuntu-26.04','architecture':'amd64',
       'source_inputs_sha256':pins['source_inputs_sha256'],'Main_changed':False,'all50_commercial':False}
origin='http://127.0.0.1:19100'
client=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
sites=urllib.request.build_opener(urllib.request.ProxyHandler({}))
csrf=''
def sha(value):return hashlib.sha256(value).hexdigest()
def save(label,value):
    (out/label).write_text(json.dumps(value,indent=2)+'\n')
def api(path,body=None,status=200,key=None):
    h={'Origin':origin,'Content-Type':'application/json','X-CSRF-Token':csrf}
    if key:h['Idempotency-Key']=key
    req=urllib.request.Request(origin+'/api'+path,None if body is None else json.dumps(body).encode(),h)
    with client.open(req,timeout=45) as response:
        assert response.status==status and response.url==req.full_url
        return json.load(response)
def pending(table,job):
    assert table in ('jobs','runtime_jobs','schedule_runs') and re.fullmatch('[a-f0-9]{32}',job)
    deadline=time.monotonic()+900
    while time.monotonic()<deadline:
        with sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True) as con:
            con.execute('PRAGMA query_only=ON')
            row=con.execute('SELECT state,error FROM '+table+' WHERE id=?',(job,)).fetchone()
        if row and row[0] not in ('queued','running'):
            assert row[0]=='succeeded' and not row[1],row
            return
        time.sleep(1)
    raise TimeoutError(table)
def record(p):
    s=p.lstat()
    assert stat.S_ISREG(s.st_mode) and s.st_nlink==1
    return {'ino':s.st_ino,'owner':s.st_uid,'mode':stat.S_IMODE(s.st_mode),'size':s.st_size,'sha256':sha(p.read_bytes())}
def traffic(marker):
    req=urllib.request.Request('http://127.0.0.1:19101/'+marker,headers={'Host':domain})
    try:
        with sites.open(req,timeout=10) as response:return response.status
    except urllib.error.HTTPError as error:return error.code
def command(label,args,timeout=120):
    with (out/(label+'.stdout')).open('xb') as stdout,(out/(label+'.stderr')).open('xb') as stderr:
        r=subprocess.run(args,stdout=stdout,stderr=stderr,timeout=timeout)
    assert r.returncode==0,label
try:
    verified=base/'verified-input'
    verified.mkdir(mode=0o700)
    for name,digest in pins['files'].items():
        assert re.fullmatch(r'[A-Za-z0-9._-]+',name) and re.fullmatch('[a-f0-9]{64}',digest)
        p=inputs/name
        with os.fdopen(os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC),'rb') as f:
            before=os.fstat(f.fileno())
            assert stat.S_ISREG(before.st_mode) and before.st_nlink==1 and 0<before.st_size<=64<<20
            raw=f.read((64<<20)+1)
            after=os.fstat(f.fileno())
        assert (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns)
        assert len(raw)==before.st_size and sha(raw)==digest
        with (verified/name).open('xb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
    inputs=verified
    pub=inputs/'release-signing-dev.pub'
    assert pub.stat().st_uid==0 and stat.S_IMODE(pub.stat().st_mode)==0o600
    assert sha(pub.read_bytes())=='4ccfcc861d56a41e3ba7f7ace7e2432c815f366c58448d783df92c6632f01339'
    archive=inputs/('panel-'+pins['version']+'-linux-amd64.tar.gz')
    common=['python3','-I','-B',str(inputs/'signed-release.py')]
    key=['--public-key',str(inputs/'release-signing-dev.pub')]
    command('signed-verify',common+['verify',str(archive)]+key)
    command('signed-normal-preflight',common+['install',str(archive)]+key+['--preflight-only'],900)
    command('signed-normal-install',common+['install',str(archive)]+key,1800)
    assert json.loads(Path('/opt/panel/current/SOURCE_INPUTS.json').read_bytes())['inputs_sha256']==pins['source_inputs_sha256']
    data=json.loads(Path('/etc/panel/first-login.json').read_bytes())
    csrf=api('/login',{k:data[k] for k in ('username','password')})['csrf'];data.clear()
    registry=api('/app-registry?refresh=1')
    assert registry['host']=={'platform':'ubuntu-26.04','architecture':'amd64'}
    assert registry['source']['resolved_commit']==pins['served_head'] and not registry['source']['stale']
    app,=[a for a in registry['catalog']['apps']if a['id']=='nginx']
    assert app==pins['nginx'] and app['target']=='nginx-1.30.6'
    installed,=[a for a in registry['status']if a['id']=='nginx']
    if not installed['installed']:
        job=api('/app-registry/nginx/install',{'expected_version':app['version'],'expected_sha256':app['sha256']},202,secrets.token_hex(16))
        pending('runtime_jobs',job['job_id'])
    elif installed['installed_version']!=app['version']:
        assert installed['update_available']
        job=api('/app-registry/nginx/update',{'expected_version':app['version'],'expected_sha256':app['sha256']},202,secrets.token_hex(16))
        pending('runtime_jobs',job['job_id'])
    switch=api('/runtimes/nginx/switch',{'release_id':app['target']},202,secrets.token_hex(16))
    pending('runtime_jobs',switch['job_id'])
    nonce=secrets.token_hex(6);domain='c170-'+nonce+'.example.test'
    created=api('/sites',{'name':'Nginx 日志实装','slug':'c170-'+nonce,'domain':domain},202,secrets.token_hex(16))
    pending('jobs',created['job_id'])
    site,=[row for row in api('/sites')if row['domain']==domain]
    assert site['status']=='running'
    sid=site['id'];log=Path('/var/log/nginx')/('panel-'+sid+'.access.log')
    before_marker='c170-before-'+nonce
    assert traffic(before_marker) in (200,404) and before_marker.encode() in log.read_bytes()
    master=int(subprocess.check_output(['systemctl','show','nginx.service','-p','MainPID','--value']))
    exe=Path('/proc')/str(master)/'exe'
    assert os.readlink(exe)=='/opt/panel/runtimes/nginx/1.30.6/sbin/nginx'
    original=record(log)
    expired=log.with_name(log.name+'.20000101-000001.gz')
    future=log.with_name(log.name+'.20991231-235959.gz')
    for file in (expired,future):
        with file.open('xb') as f:f.write(gzip.compress(b'isolated original archive\n',mtime=0))
    retired=record(expired);kept=record(future)
    config=Path('/etc/panel/sites-enabled')/(sid+'.conf')
    untouched=record(config)
    schedule=api('/schedules',{'name':'Nginx 日志实装','kind':'log_cleanup','target_id':sid,'schedule_type':'daily',
                             'timezone':'UTC','minute':27,'hour':22,'weekday':0,'retention_count':1,'enabled':False},201)
    run=api('/schedules/'+schedule['id']+'/run',{},202)['id']
    pending('schedule_runs',run)
    result=api('/schedules/runs/'+run+'/log-cleanup')
    assert result['request_id']==run and result['site_id']==sid and result['state']=='completed'
    assert result['result']['deleted']==1 and result['result']['files']==[expired.name] and result['result']['deleted_bytes']==retired['size']
    assert result['result']['rotated']>=1 and not expired.exists() and record(future)==kept
    before_copy,=[p for p in log.parent.glob(log.name+'.*') if p.lstat().st_ino==original['ino']]
    archive_state=record(before_copy)
    assert archive_state['sha256']==original['sha256']
    after_marker='c170-after-'+nonce
    assert traffic(after_marker) in (200,404) and after_marker.encode() in log.read_bytes()
    assert record(log)['ino']!=original['ino'] and record(before_copy)==archive_state and record(config)==untouched
    assert int(subprocess.check_output(['systemctl','show','nginx.service','-p','MainPID','--value']))==master
    proof.update(ok=True,app_version=app['version'],real_site_http=True,actual_archived_original=True,
                 expired_bytes=retired['size'],signed_runtime_active=True,original_service_lifetime_preserved=True)
    save('log-result.json',result)
except BaseException:
    proof['failure']=traceback.format_exc()
finally:
    if csrf:
        try:api('/logout',{})
        except Exception:proof['ok']=False
    save('result.json',proof)
    print(json.dumps(proof),flush=True)
sys.exit(0 if proof['ok']else 1)
