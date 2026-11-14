"""Use two real Nginx sites to verify signed analytics client quota isolation."""
from pathlib import Path
import contextlib
import hashlib
import http.client
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
architecture={'x86_64':'amd64','aarch64':'arm64'}[platform.machine()]
assert os.geteuid()==0 and len(sys.argv)==2
inputs=Path(sys.argv[1]).resolve(strict=True)
pins=json.loads((inputs/'assets.json').read_text())
case=pins['OS_case']
identity=dict(line.split('=',1) for line in Path('/etc/os-release').read_text().splitlines() if line and not line.startswith('#') and '=' in line)
assert identity['ID']=='debian' and identity['VERSION_ID'].strip('"')=='13'
assert case['platform']=='debian-13' and case['architecture']==pins['architecture']==architecture
assert Path('/etc/hostname').read_text().strip()==pins['OS_case']['hostname']
base=Path('/opt/panel-analytics-c188-qa-'+secrets.token_hex(16))
assert base.parent==Path('/opt') and re.fullmatch(r'panel-analytics-c188-qa-[a-f0-9]{32}',base.name)
out=base/'evidence'
out.mkdir(mode=0o700,parents=True)
assert base.stat().st_uid==out.stat().st_uid==0 and stat.S_IMODE(out.stat().st_mode)==0o700
boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
proof={'ok':False,'base':str(base),'boot':boot,'platform':'debian-13','architecture':architecture,
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

def observe_http(cfg, host, address, path, *, bot=False, forged=False):
    body={
        'id':secrets.token_hex(16),'page_id':secrets.token_hex(16),
        'visitor':secrets.token_hex(16),'session':secrets.token_hex(16),
        'kind':'pageview','path':path,'title':'Owned C188 fixture',
    }
    headers={'Host':host,'Origin':'http://'+host,'Content-Type':'application/json',
             'User-Agent':'Yunzhan Synthetic Bot' if bot else 'Mozilla/5.0 Chrome/130.0'}
    if forged:
        headers.update({'X-Forwarded-For':'203.0.113.20','X-Real-IP':'203.0.113.21',
                        'X-Yunzhan-Analytics-Client-IP':'203.0.113.22'})
    from urllib.parse import urlencode
    endpoint='/__yunzhan/analytics/event?'+urlencode({'site':cfg['site_id'],'key':cfg['key']})
    connection=http.client.HTTPConnection('127.0.0.1',19101,source_address=(address,0),timeout=6)
    try:
        connection.request('POST',endpoint,json.dumps(body,separators=(',',':')),headers)
        response=connection.getresponse()
        data=response.read(4097)
        assert len(data)<=4096 and not response.getheader('Set-Cookie')
        return response.status,response.getheader('Retry-After')
    finally:
        connection.close()

def new_site(index):
    slug='c188-'+str(index)+'-'+secrets.token_hex(5)
    domain=slug+'.example.test'
    job=api('/sites',{'name':'C188 analytics fixture '+str(index),'slug':slug,'domain':domain},202,secrets.token_hex(16))
    site_id=wait_job('jobs',job['job_id'],180)['site_id']
    route='/analytics/sites/'+site_id+'/config'
    initial=api(route)
    job=api(route,{'enabled':True,'clicks':False,'retention_days':30,'revision':initial['revision'],
                   'auto_inject_html':False},202,secrets.token_hex(16))
    wait_job('jobs',job['job_id'],180)
    result=api(route)
    assert result['enabled'] and result['client_address_mode']=='managed_proxy'
    cfg=Path('/etc/panel/sites-enabled')/(site_id+'.conf')
    assert re.search(r'^\s*listen 127\.0\.0\.1:19101;',cfg.read_text(),re.M)
    assert '/__yunzhan/analytics/' in cfg.read_text()
    return result,domain,cfg

def stored_events(first,second):
    states={}
    with contextlib.closing(sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True)) as db:
        db.execute('PRAGMA query_only=ON')
        for cfg in (first,second):
            rows=db.execute('SELECT path,data FROM analytics_events WHERE site_id=? ORDER BY path',(cfg['site_id'],)).fetchall()
            state={}
            for path,raw in rows:
                decoded=json.loads(raw)
                assert decoded['client_address_source']=='managed_proxy'
                assert re.fullmatch('[0-9a-f]{64}',decoded['client_address_hash'])
                assert all(ip not in raw for ip in ('127.0.0.61','127.0.0.62','203.0.113.20','203.0.113.21','203.0.113.22'))
                state[path]=decoded['client_address_hash']
            states[cfg['site_id']]=state
    return states[first['site_id']],states[second['site_id']]

try:
    assert not Path('/opt/panel').exists() and not Path('/var/lib/panel').exists()
    local_inputs=sign_input_copy()
    archive=local_inputs/('panel-'+pins['version']+'-linux-'+architecture+'.tar.gz')
    signer=['python3','-I','-B',str(local_inputs/'signed-release.py')]
    trust=['--public-key',str(local_inputs/'release-signing-dev.pub')]
    command('signed-verify',signer+['verify',str(archive)]+trust)
    command('signed-preflight',signer+['install',str(archive)]+trust+['--preflight-only'],900)
    command('signed-install',signer+['install',str(archive)]+trust,1800)
    assert json.loads(Path('/opt/panel/current/SOURCE_INPUTS.json').read_text())['inputs_sha256']==pins['source_inputs_sha256']
    credentials=json.loads(Path('/etc/panel/first-login.json').read_text())
    csrf=api('/login',{key:credentials[key] for key in ('username','password')})['csrf']
    credentials.clear()
    catalog=api('/app-registry?refresh=1')
    assert not catalog['source']['stale'] and catalog['source']['resolved_commit']==pins['served_head']
    assert catalog['host']=={'platform':'debian-13','architecture':architecture}
    assert len(catalog['catalog']['apps'])==50
    item,=[row for row in catalog['catalog']['apps'] if row['id']=='website-analytics']
    assert item==pins['analytics'] and item['version']=='2.4.6'
    job=api('/app-registry/website-analytics/install',{'expected_version':item['version'],'expected_sha256':item['sha256']},202,secrets.token_hex(16))
    wait_job('runtime_jobs',job['job_id'],900)
    catalog=api('/app-registry?refresh=1')
    status,=[row for row in catalog['status'] if row['id']=='website-analytics']
    assert status['installed'] and status['installed_version']==item['version'] and not status['update_available']

    first,host_a,conf_a=new_site(1)
    second,host_b,conf_b=new_site(2)
    before={p:sha(p.read_bytes()) for p in (conf_a,conf_b)}
    # A single real epoch minute, at most 40 requests/second, below 100/s.
    remaining=60-time.time()%60
    if remaining<45:
        time.sleep(remaining+.25)
    start=time.time()
    same_ip='127.0.0.61'
    assert observe_http(first,host_a,same_ip,'/before') == (204,None)
    for index in range(1199):
        delay=start+(index+1)*.025-time.time()
        if delay>0: time.sleep(delay)
        assert observe_http(first,host_a,same_ip,'/quota-bot',bot=True)==(204,None),index
    assert observe_http(first,host_a,same_ip,'/blocked')==(429,'60')
    assert observe_http(first,host_a,same_ip,'/spoofed',forged=True)==(429,'60')
    assert observe_http(second,host_b,same_ip,'/other-website')==(204,None)
    assert observe_http(first,host_a,'127.0.0.62','/other-client')==(204,None)
    assert int(start)//60==int(time.time())//60
    a,b=stored_events(first,second)
    assert set(a)=={'/before','/other-client'} and set(b)=={'/other-website'}
    assert len(set(a.values())|set(b.values()))==3
    assert before=={p:sha(p.read_bytes()) for p in before}
    proof.update(ok=True,verified_real_addresses=True,both_original_nginx_configs_preserved=True,
                 same_address_other_site_accepted=True,same_site_forged_address_refused=True,
                 same_site_other_client_accepted=True,saturation_http_requests=1200,
                 accepted_stored_events=3,signed_analytics_version=item['version'])
except BaseException:
    proof['failure']=traceback.format_exc()
finally:
    if csrf:
        try:api('/logout',{})
        except Exception:proof['ok']=False
    save(out/'phase1.json',proof)
    print(json.dumps(proof),flush=True)
sys.exit(0 if proof['ok'] else 1)
