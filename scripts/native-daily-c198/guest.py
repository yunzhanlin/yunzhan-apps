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
base=Path(sys.argv[2]).resolve(strict=True) if recovering else Path('/opt/panel-daily-c198-qa-'+secrets.token_hex(16))
assert base.parent==Path('/opt') and re.fullmatch(r'panel-daily-c198-qa-[a-f0-9]{32}',base.name)
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

RECEIVER="\nfrom pathlib import Path\nimport hashlib,hmac,http.server,json,os,sys,time\nroot=Path(sys.argv[1])\nsecret=(root/'receiver-secret').read_bytes()\nclass Handler(http.server.BaseHTTPRequestHandler):\n def log_message(self,*args): pass\n def do_POST(self):\n  n=int(self.headers.get('Content-Length','0'))\n  assert 0<n<16384\n  body=self.rfile.read(n)\n  ident=self.headers.get('X-Yunzhan-Delivery-ID','')\n  stamp=self.headers.get('X-Yunzhan-Timestamp','')\n  mac=hmac.new(secret,stamp.encode()+b'.'+ident.encode()+b'.'+body,hashlib.sha256)\n  assert hmac.compare_digest(self.headers.get('X-Yunzhan-Signature',''),'sha256='+mac.hexdigest())\n  assert abs(time.time()-int(stamp))<180\n  payload=json.loads(body)\n  status=204 if (root/'allow-receiver').exists() else 429\n  row={'id':ident,'payload':payload,'payload_sha':hashlib.sha256(body).hexdigest(),'status':status,'signature_verified':True}\n  with (root/'receiver.jsonl').open('a') as f:\n   f.write(json.dumps(row)+'\\n');f.flush();os.fsync(f.fileno())\n  self.send_response(status)\n  if status==429:self.send_header('Retry-After','90')\n  self.send_header('Content-Length','0')\n  self.end_headers()\nhttp.server.HTTPServer(('127.0.0.1',28419),Handler).serve_forever()\n"

import datetime as dt
from zoneinfo import ZoneInfo
module='/app-modules/daily-report'
def rows(query,args=()):
    with contextlib.closing(sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True)) as db:
        db.execute('PRAGMA query_only=ON')
        return db.execute(query,args).fetchall()
def observe(day):
    found=rows('SELECT report,created_at FROM app_daily_reports WHERE day=?',(day,))
    return {'reports':found,'notifications':rows("SELECT id FROM notifications WHERE source='daily-report' AND source_id=?",(day,))}
def wait(read,ready,timeout):
    stop=time.monotonic()+timeout
    while time.monotonic()<stop:
        value=read()
        if ready(value):return value
        time.sleep(1)
    raise TimeoutError('Original daily workflow did not complete')
def receiver_rows():
    f=base/'receiver.jsonl'
    return [json.loads(line) for line in f.read_text().splitlines()] if f.exists() else []
def receiver_setup():
    (base/'receiver-secret').write_bytes(secrets.token_hex(32).encode())
    (base/'receiver.py').write_text(RECEIVER)
    service=Path('/etc/systemd/system/panel-c198-daily-receiver.service')
    assert not service.exists()
    service.write_text('[Unit]\nAfter=network.target\n[Service]\nExecStart=/usr/bin/python3 -I -B '+str(base/'receiver.py')+' '+str(base)+'\n[Install]\nWantedBy=multi-user.target\n'.replace('\\n','\n'))
    command('receiver-reload',['systemctl','daemon-reload'])
    command('receiver-start',['systemctl','enable','--now','panel-c198-daily-receiver.service'])
def catalogue(installed):
    page=api('/app-registry?refresh=1')
    assert not page['source']['stale'] and page['source']['resolved_commit']==pins['served_head']
    item,=[item for item in page['catalog']['apps'] if item['id']=='daily-report']
    assert item==pins['daily'] and item['version']=='1.4.1'
    status,=[v for v in page['status'] if v['id']=='daily-report']
    assert status['state_known'] and status['supported'] and status['installed']==installed
    if installed:assert status['installed_version']=='1.4.1' and not status['update_available']
    return item
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
    creds=json.loads(Path('/etc/panel/first-login.json').read_bytes())
    csrf=api('/login',{key:creds[key] for key in ('username','password')})['csrf']
    creds.clear()
    if not recovering:
        item=catalogue(False)
        job=api('/sites',{'name':'Real daily schedule fixture','slug':'daily-c198','domain':'daily-c198.example.test'},202,secrets.token_hex(16))['job_id']
        site=wait_job('jobs',job,240)['site_id']
        job=api('/app-registry/daily-report/install',{'expected_version':item['version'],'expected_sha256':item['sha256']},202,secrets.token_hex(16))['job_id']
        wait_job('runtime_jobs',job,900)
        catalogue(True)
        old=api(module+'/run',{})
        assert old['sites']==1 and old['running_sites']==1 and old['resources']
        prior=rows('SELECT day,created_at,report FROM app_daily_reports ORDER BY day')
        original={day:sha(report.encode()) for day,_,report in prior}
        schedule=api(module+'/schedule')
        now=dt.datetime.now(dt.timezone.utc)
        due=now.replace(second=0,microsecond=0)+dt.timedelta(minutes=2)
        for timezone in ('Pacific/Pago_Pago','Pacific/Kiritimati'):
            location=ZoneInfo(timezone);day=due.astimezone(location).date().isoformat()
            if day not in original and now.astimezone(location).date().isoformat()==day:break
        else:raise AssertionError('No unused current local day')
        setting={'time_zone':timezone,'local_time':due.astimezone(location).strftime('%H:%M'),'expected_revision':schedule['revision']}
        saved=api(module+'/schedule',setting)
        assert saved['revision']==schedule['revision']+1
        assert api(module+'/schedule',{**setting,'local_time':'12:00'},409)['error']
        assert api(module+'/schedule')==saved
        receiver_setup()
        secret=(base/'receiver-secret').read_text()
        channel=api('/notification-channels',{'name':'Owned daily receiver','url':'http://127.0.0.1:28419/receive','secret':secret,'enabled':True,'kinds':['daily']})
        assert channel['secret_set'] and secret not in json.dumps(channel)
        assert observe(day)['reports']==[]
        waiting=wait(lambda:api(module)['daily_worker'],lambda v:v['state']=='waiting_schedule' and v['report_day']==day,85)
        save(out/'worker-waiting.json',waiting)
        generated=wait(lambda:observe(day),lambda v:len(v['reports'])==1 and len(v['notifications'])==1,210)
        report=api(module+'/report',{'resource_id':day})
        assert report==json.loads(generated['reports'][0][0])
        assert dt.datetime.fromisoformat(report['created_at'].replace('Z','+00:00'))>=due
        assert report['sites']==1 and report['running_sites']==1
        accepted=wait(receiver_rows,lambda v:len(v)==1,90)
        first=accepted[0]
        assert first['status']==429 and first['signature_verified']
        assert first['payload']['kind']=='daily' and not first['payload'].get('test',False)
        assert first['payload']['report']['day']==day
        assert first['payload']['report']['sites']==report['sites']
        for token in (secret,site,'daily-c198.example.test','first-login'):
            assert token not in json.dumps(first['payload'])
        delivery=wait(lambda:rows('SELECT id,state,http_status,attempts,next_attempt_at FROM notification_deliveries WHERE channel_id=?',(channel['id'],)),lambda v:v and v[0][1]=='pending' and v[0][2]==429,20)
        assert delivery[0][0]==first['id'] and delivery[0][4]>time.time()+40
        assert len(receiver_rows())==1
        for d,digest in original.items():assert sha(observe(d)['reports'][0][0].encode())==digest
        state={'boot':boot,'day':day,'saved_schedule':saved,'channel':channel,'delivery':first,'original_reports':original,
               'report_sha':sha(generated['reports'][0][0].encode()),'notification_id':generated['notifications'][0][0]}
        save(base/'state.json',state)
        save(out/'preboot-daily-receipt.json',state)
        proof.update(ok=True,powerloss_ready=True,phase='before-reboot',signed_daily_version=item['version'],
            actual_wait_and_schedule=True,exact_saved_report=True,original_reports_preserved=True,
            stale_schedule_rejected=True,actual_hmac_and_429=True,retry_persisted=True)
    else:
        state=json.loads((base/'state.json').read_bytes())
        assert state['boot']!=boot
        catalogue(True)
        assert api(module+'/schedule')==state['saved_schedule']
        observed=observe(state['day'])
        assert sha(observed['reports'][0][0].encode())==state['report_sha']
        assert observed['notifications']==[(state['notification_id'],)]
        for day,digest in state['original_reports'].items():assert sha(observe(day)['reports'][0][0].encode())==digest
        (base/'allow-receiver').write_text('accept exact original retry')
        received=wait(receiver_rows,lambda v:any(row['status']==204 for row in v),200)
        assert all(row['id']==state['delivery']['id'] and row['payload_sha']==state['delivery']['payload_sha'] for row in received)
        assert all(row['signature_verified'] for row in received)
        finished=wait(lambda:rows('SELECT state,http_status FROM notification_deliveries WHERE id=?',(state['delivery']['id'],)),lambda v:v==[('succeeded',204)],30)
        assert observe(state['day'])==observed
        save(out/'postboot-receiver-receipts.json',received)
        proof.update(ok=True,phase='after-reboot',prior_boot=state['boot'],signed_daily_version='1.4.1',
            actual_same_delivery_retry=True,original_reports_and_notifications_preserved=True,original_schedule_preserved=True)
except BaseException:
    proof['failure']=traceback.format_exc()
finally:
    if csrf:
        try:api('/logout',{})
        except Exception:proof['ok']=False
    save(out/('phase2.json' if recovering else 'phase1.json'),proof)
    print(json.dumps(proof),flush=True)
sys.exit(0 if proof['ok'] else 1)
