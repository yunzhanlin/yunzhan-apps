"""Validate signed consent-gated website replay against real managed Nginx sites."""
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
base=Path('/opt/panel-analytics-c190-qa-'+secrets.token_hex(16))
assert base.parent==Path('/opt') and re.fullmatch(r'panel-analytics-c190-qa-[a-f0-9]{32}',base.name)
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

def new_site(index):
    slug='c190-'+str(index)+'-'+secrets.token_hex(5)
    domain=slug+'.example.test'
    job=api('/sites',{'name':'C190 analytics fixture '+str(index),'slug':slug,'domain':domain},202,secrets.token_hex(16))
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

def status_post(cfg, host, body, *, source=None, privacy=None):
    from urllib.parse import urlencode
    endpoint='/__yunzhan/analytics/event?'+urlencode({'site':cfg['site_id'],'key':cfg['key']})
    headers={'Host':host,'Origin':'http://'+(source or host),'Content-Type':'application/json',
             'User-Agent':'Mozilla/5.0 Chrome/157.0'}
    if privacy:
        headers[privacy]='1'
    connection=http.client.HTTPConnection('127.0.0.1',19101,timeout=8)
    try:
        connection.request('POST',endpoint,json.dumps(body,separators=(',',':')),headers)
        response=connection.getresponse()
        assert len(response.read(4097))<=4096 and not response.getheader('Set-Cookie')
        return response.status
    finally:
        connection.close()

def policy(cfg, enabled, revision, sample=100):
    route='/analytics/sites/'+cfg['site_id']+'/replay-policy'
    before=api(route)
    assert before['site_id']==cfg['site_id'] and before['revision']==revision
    return api(route,{'enabled':enabled,'revision':revision,'sample_percent':sample,'site_id':cfg['site_id']})

def install_page(cfg, host, number):
    vhost=Path('/etc/panel/sites-enabled')/(cfg['site_id']+'.conf')
    server_root,=set(re.findall(r'^\s*root\s+([^;]+);', vhost.read_text(),re.M))
    root=Path(server_root.strip('"')).resolve(strict=True)
    assert root == Path('/srv/panel/sites') / cfg['site_id'] / 'public' and root.is_dir()
    filename=root/'c190-replay-fixture.html'
    tracker=cfg.get('tracker_url') or ('/__yunzhan/analytics/tracker.js?site='+cfg['site_id']+'&key='+cfg['key'])
    assert tracker.startswith('/__yunzhan/analytics/tracker.js?') and cfg['site_id'] in tracker and cfg['key'] in tracker
    from html import escape
    template='''<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>Owned C190 replay fixture</title><style>body{padding:18px;background:#fafbfc;font:17px system-ui}h1{background:rgb(18,171,239)}button{display:block;padding:14px;background:rgb(19,159,95)}main{min-height:1600px}article{min-height:85px}</style>
<main><h1>Cloud panel replay layout</h1><button id="move">Change page layout</button><form><input id="secret" value="c190-native-secret" style="background:rgb(231,13,14)"></form>
<article data-yunzhan-private style="background:rgb(232,13,14)"><p>Hidden visitor details</p></article>
<article style="background:rgb(19,83,158);margin-top:900px">Lower section</article></main>
<script>document.querySelector('#move').onclick=()=>{document.querySelector('h1').style.backgroundColor='rgb(179,201,39)'};</script>
<script defer src="%s"></script>''' % escape(tracker,quote=True)
    with filename.open('x') as f:
        f.write(template)
    filename.chmod(0o644)
    connection=http.client.HTTPConnection('127.0.0.1',19101,timeout=8)
    try:
        connection.request('GET','/'+filename.name,headers={'Host':host})
        response=connection.getresponse()
        assert response.status==200 and response.read().decode()==template
    finally:
        connection.close()
    return {'name':'C190 analytics fixture '+str(number),'host':host,'site':cfg['site_id'],'path':'/'+filename.name}

def scope_ids(site, anchor):
    with contextlib.closing(sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True)) as db:
        db.execute('PRAGMA query_only=ON')
        row,=db.execute('SELECT visitor,session FROM analytics_events WHERE id=? AND site_id=?',(anchor,site)).fetchall()
        assert all(re.fullmatch('[a-f0-9]{64}',item) for item in row)
        return row

def replay(cfg, visitor, session):
    from urllib.parse import urlencode
    query=urlencode({'visitor':visitor})
    return api('/analytics/sites/'+cfg['site_id']+'/sessions/'+session+'/replay?'+query)

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
    fixture_a=install_page(first,host_a,1)
    fixture_b=install_page(second,host_b,2)
    original_confs={p:sha(p.read_bytes()) for p in (conf_a,conf_b)}
    event={'id':secrets.token_hex(16),'page_id':secrets.token_hex(16),'visitor':secrets.token_hex(16),
           'session':secrets.token_hex(16),'kind':'pageview','path':'/c190-http-proof?secret=never-stored'}
    f={**event,'id':secrets.token_hex(16),'kind':'replay','path':'/wrong-path',
       'replay':{'width':820,'height':720,'scroll':250,'pointer':[170,210,1],
                 'tiles':[[0,0,1000,1000,0xfafafa,0],[14,30,654,41,0x12abef,1]]}}
    assert status_post(first,host_a,event)==204
    assert status_post(first,host_a,f)==403
    assert policy(first,True,0)['revision']==1 and policy(second,True,0)['revision']==1
    assert status_post(first,host_a,f,source=host_b)==403
    assert status_post(second,host_b,f)==409
    assert status_post(first,host_a,f,privacy='Sec-GPC')==204
    visitor,session=scope_ids(first['site_id'],event['id'])
    assert not replay(first,visitor,session)['frames']
    assert status_post(first,host_a,f)==204 and status_post(first,host_a,f)==204
    result=replay(first,visitor,session)
    assert len(result['frames'])==1 and result['site_id']==first['site_id']
    captured,=result['frames']
    assert captured['path']=='/c190-http-proof' and captured['viewport']==f['replay']
    assert not replay(second,visitor,session)['frames']
    assert policy(first,False,1)['revision']==2
    assert status_post(first,host_a,{**f,'id':secrets.token_hex(16)})==403
    assert len(replay(first,visitor,session)['frames'])==1
    assert policy(first,True,2)['revision']==3
    assert original_confs=={p:sha(p.read_bytes()) for p in original_confs}
    save(out/'browser-fixtures.json',{'primary':fixture_a,'secondary':fixture_b})
    proof.update(ok=True,signed_analytics_version=item['version'],normal_managed_nginx=True,
                 disabled_does_not_store=True,privacy_signal_blocks_storage=True,
                 same_site_page_anchor=True,wrong_origin_rejected=True,wrong_site_session_isolated=True,
                 idempotent_frame_replay=True,original_nginx_configs_preserved=True,
                 policy_withdrawal_blocks_next_frame=True,frames_read_from_management_api=1)
except BaseException:
    proof['failure']=traceback.format_exc()
finally:
    if csrf:
        try:api('/logout',{})
        except Exception:proof['ok']=False
    save(out/'phase1.json',proof)
    print(json.dumps(proof),flush=True)
sys.exit(0 if proof['ok'] else 1)
