"""Use the signed store to create two PM2 projects and test an actual sudden loss of power."""
from pathlib import Path
import contextlib
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
import urllib.request

os.umask(0o077)
assert os.geteuid()==0 and platform.machine()=='x86_64' and len(sys.argv) in (2,3)
inputs=Path(sys.argv[1]).resolve(strict=True)
pins=json.loads((inputs/'assets.json').read_text())
assert 'VERSION_ID="26.04"' in Path('/etc/os-release').read_text()
assert Path('/etc/hostname').read_text().strip()==pins['OS_case']['hostname']
recovering=len(sys.argv)==3
base=Path(sys.argv[2]).resolve(strict=True) if recovering else Path('/opt/panel-pm2-c171-qa-'+secrets.token_hex(16))
assert base.parent==Path('/opt') and re.fullmatch(r'panel-pm2-c171-qa-[a-f0-9]{32}',base.name)
out=base/'evidence'
if not recovering:out.mkdir(mode=0o700,parents=True)
assert base.stat().st_uid==out.stat().st_uid==0 and stat.S_IMODE(out.stat().st_mode)==0o700
boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
proof={'ok':False,'base':str(base),'boot':boot,'platform':'ubuntu-26.04','architecture':'amd64',
       'source_inputs_sha256':pins['source_inputs_sha256'],'Main_changed':False,'all50_commercial':False}
client=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
local=urllib.request.build_opener(urllib.request.ProxyHandler({}))
origin='http://127.0.0.1:19100'
module=Path('/etc/panel/security-apps/modules/pm2-manager')
csrf=''
def sha(x):return hashlib.sha256(x).hexdigest()
def save(path,v):
    with path.open('x') as f:json.dump(v,f,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
def api(path,body=None,status=200,key=None):
    headers={'Origin':origin,'Content-Type':'application/json','X-CSRF-Token':csrf}
    if key:headers['Idempotency-Key']=key
    req=urllib.request.Request(origin+'/api'+path,None if body is None else json.dumps(body).encode(),headers)
    with client.open(req,timeout=90)as res:
        assert res.status==status and res.url==req.full_url
        return json.load(res)
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
def service(app):
    assert re.fullmatch('[a-z0-9-]{3,48}',app)
    raw=subprocess.check_output(['systemctl','show','panel-pm2@'+app+'.service','-p','ActiveState,UnitFileState,MainPID,InvocationID'],text=True,timeout=20)
    return dict(line.split('=',1) for line in raw.splitlines() if '=' in line)
def file_id(p):
    st=p.lstat()
    assert stat.S_ISREG(st.st_mode) and st.st_nlink==1
    return {'uid':st.st_uid,'gid':st.st_gid,'ino':st.st_ino,'sha256':sha(p.read_bytes())}
def manifest(app):
    return file_id(module/'apps'/(app+'.json'))
def request_http(port):
    with local.open('http://127.0.0.1:'+str(port)+'/',timeout=3)as res:
        assert res.status==200
        return json.load(res)
def process_http(port,marker,seconds):
    end=time.monotonic()+seconds
    while time.monotonic()<end:
        try:body=request_http(port)
        except (OSError,urllib.error.URLError):
            time.sleep(1);continue
        assert body['marker']==marker and body['uid']>0 and body['gid']>0
        s=Path('/proc')/str(body['pid'])/'status'
        data=dict(line.split(':',1) for line in s.read_text().splitlines() if ':' in line)
        assert int(data['Uid'].split()[1])==body['uid'] and int(data['Gid'].split()[1])==body['gid']
        assert int(data['CapEff'].strip(),16)==0 and data['NoNewPrivs'].strip()=='1'
        return body
    raise TimeoutError('PM2 HTTP loopback')
def stopped(app,port):
    s=service(app)
    assert s['ActiveState']=='inactive' and s['UnitFileState']=='disabled' and s['MainPID']=='0'
    try: request_http(port)
    except urllib.error.URLError: return s
    raise AssertionError('stopped PM2 process responded')
def release_source():
    return json.loads(Path('/opt/panel/current/SOURCE_INPUTS.json').read_text())['inputs_sha256']
def project_code(marker):
    return """'use strict';
const fs=require('node:fs'),p=require('node:path'),http=require('node:http'),crypto=require('node:crypto');
const counter=p.join(process.env.HOME,'qa-c171-start-count');
const old=fs.existsSync(counter)?Number(fs.readFileSync(counter,'utf8')):0;
if(!Number.isSafeInteger(old)||old<0) throw new Error('counter');
const count=old+1, temp=counter+'.'+process.pid;
let fd=fs.openSync(temp,'wx',0o600);
fs.writeFileSync(fd,String(count)); fs.fsyncSync(fd); fs.closeSync(fd);
fs.renameSync(temp,counter);
fd=fs.openSync(p.dirname(counter),'r'); fs.fsyncSync(fd); fs.closeSync(fd);
http.createServer((req,res)=>{
 res.writeHead(200,{'Content-Type':'application/json','Cache-Control':'no-store'});
 res.end(JSON.stringify({marker:"""+json.dumps(marker)+""",pid:process.pid,uid:process.getuid(),gid:process.getgid(),count,
 env:crypto.createHash('sha256').update(process.env.QA_PM2_CANARY||'').digest('hex')}));
}).listen(Number(process.env.PORT),process.env.HOST||'127.0.0.1');
"""
try:
    if recovering:
        before=json.loads((out/'prepared.json').read_text())
        assert before['boot']!=boot and release_source()==pins['source_inputs_sha256']
        a,b=before['apps']
        restored=process_http(a['port'],a['marker'],150)
        assert restored['count']==a['http']['count']+1 and restored['uid']==a['http']['uid'] and restored['gid']==a['http']['gid']
        assert restored['env']==a['http']['env']
        after=service(a['id']);assert after['ActiveState']=='active' and after['UnitFileState']=='enabled'
        assert after['InvocationID']!=a['service']['InvocationID']
        stopped(b['id'],b['port'])
        for entry in (a,b):assert manifest(entry['id'])==entry['manifest']
        deadline=time.monotonic()+90
        samples=0
        while time.monotonic()<deadline:
            assert request_http(a['port'])==restored and service(a['id'])==after
            stopped(b['id'],b['port'])
            samples+=1
            time.sleep(5)
        assert samples>=15
        proof.update(ok=True,prior_boot=before['boot'],signed_pm2_version=before['pm2_version'],
                     active_restored_exactly_once=True,stopped_not_started=True,encrypted_manifests_unchanged=True,
                     nonroot_process_and_canary_preserved=True,post_boot_http_samples=samples)
    else:
        assert not Path('/opt/panel').exists() and not Path('/var/lib/panel').exists()
        local_inputs=sign_input_copy()
        archive=local_inputs/('panel-'+pins['version']+'-linux-amd64.tar.gz')
        signer=['python3','-I','-B',str(local_inputs/'signed-release.py')]
        trust=['--public-key',str(local_inputs/'release-signing-dev.pub')]
        command('signed-verify',signer+['verify',str(archive)]+trust)
        command('signed-preflight',signer+['install',str(archive)]+trust+['--preflight-only'],900)
        command('signed-install',signer+['install',str(archive)]+trust,1800)
        assert release_source()==pins['source_inputs_sha256']
        credentials=json.loads(Path('/etc/panel/first-login.json').read_text())
        csrf=api('/login',{k:credentials[k]for k in ('username','password')})['csrf'];credentials.clear()
        catalog=api('/app-registry?refresh=1')
        assert not catalog['source']['stale'] and catalog['source']['resolved_commit']==pins['served_head']
        assert catalog['host']=={'platform':'ubuntu-26.04','architecture':'amd64'}
        item,=[row for row in catalog['catalog']['apps'] if row['id']=='pm2-manager']
        assert item==pins['pm2'] and item['version']=='7.0.4-compat11'
        status,=[row for row in catalog['status'] if row['id']=='pm2-manager']
        assert not status['installed'] and status['supported']
        job=api('/app-registry/pm2-manager/install',{'expected_version':item['version'],'expected_sha256':item['sha256']},202,secrets.token_hex(16))
        wait_job('runtime_jobs',job['job_id'],900)
        catalog=api('/app-registry?refresh=1')
        status,=[row for row in catalog['status'] if row['id']=='pm2-manager']
        assert status['installed'] and status['installed_version']==item['version'] and not status['update_available']
        nonce=secrets.token_hex(5)
        site=api('/sites',{'name':'C171 PM2','slug':'c171-'+nonce,'domain':'c171-'+nonce+'.localhost'},202,secrets.token_hex(16))
        sid=wait_job('jobs',site['job_id'],180)['site_id']
        apps=[]
        for i in range(2):
            app='c171-'+nonce+'-'+str(i)
            entry=f'pm2-c171-{i}.js'
            marker='native-c171-'+nonce+'-'+str(i)
            port=24621+i
            secret=secrets.token_hex(28)
            code=project_code(marker)
            created=api('/sites/'+sid+'/files/action',{'action':'create','path':entry,'content':code})
            assert created['sha256']==sha(code.encode())
            result=api('/app-modules/pm2-manager/create',{'resource_id':app,'site_id':sid,'entry':entry,'port':port,
                        'instances':1,'memory_mb':128,'environment_patch':{'QA_PM2_CANARY':secret}})
            assert result['ok'] and result['app']['revision']==1 and secret not in json.dumps(result)
            observed=process_http(port,marker,45)
            assert observed['count']==1 and observed['env']==sha(secret.encode())
            assert secret.encode() not in (module/'apps'/(app+'.json')).read_bytes()
            if i:
                result=api('/app-modules/pm2-manager/stop',{'resource_id':app,'expected_revision':1})
                assert result['ok'] and not result['boot_enabled']
                state=stopped(app,port)
            else:
                state=service(app);assert state['ActiveState']=='active' and state['UnitFileState']=='enabled'
            apps.append({'id':app,'port':port,'marker':marker,'http':observed,'service':state,'manifest':manifest(app)})
        save(out/'prepared.json',{'boot':boot,'apps':apps,'pm2_version':item['version'],'site_id':sid})
        proof.update(ok=True,powerloss_ready=True,active_project_count=1,stopped_project_count=1,
                     signed_pm2_version=item['version'],both_projects_actual_nonroot=True)
except BaseException:
    proof['failure']=traceback.format_exc()
finally:
    if csrf:
        try:api('/logout',{})
        except Exception:proof['ok']=False
    save(out/('cold.json' if recovering else 'phase1.json'),proof)
    print(json.dumps(proof),flush=True)
sys.exit(0 if proof['ok'] else 1)
