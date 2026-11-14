"""Generate a real interrupted Nginx log rotation on a disposable signed installation."""
import contextlib
import gzip
import hashlib
import http.cookiejar
import json
import os
from pathlib import Path
import platform
import re
import secrets
import signal
import sqlite3
import stat
import sys
import subprocess
import time
import traceback
import urllib.error
import urllib.request

os.umask(0o077)
assert os.geteuid() == 0 and os.environ.get('GITHUB_ACTIONS') == 'true'
assert os.environ.get('GITHUB_REPOSITORY') == 'yunzhanlin/yunzhan-apps'
root = Path(sys.argv[1]).resolve(strict=True)
program = json.loads((Path(__file__).parent/'cohort.json').read_bytes())
source = json.loads(Path('/opt/panel/current/SOURCE_INPUTS.json').read_bytes())['inputs_sha256']
assert source == program['source_inputs_sha256'] and not Path('/opt/panel/DEVELOPMENT_RELEASE').exists()
arch = {'aarch64':'arm64','x86_64':'amd64'}[platform.machine()]
work = root/'business-phase1'
work.mkdir(mode=0o700)
origin = 'http://127.0.0.1:19100'
site_origin = 'http://127.0.0.1:19101'
client = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
site = urllib.request.build_opener(urllib.request.ProxyHandler({}))
csrf = ''
proof = {'ok':False,'architecture':arch,'source_inputs_sha256':source,'Main_changed':False,'all50_commercial':False}

def save(name, value):
    with (work/name).open('x') as f:
        json.dump(value,f,indent=2)
        f.write('\n')

def api(path, body=None, expected=200, key=None):
    headers = {'Origin':origin,'Content-Type':'application/json','X-CSRF-Token':csrf}
    if key: headers['Idempotency-Key'] = key
    req = urllib.request.Request(origin+'/api'+path, None if body is None else json.dumps(body).encode(), headers)
    try:
        with client.open(req,timeout=50) as reply:
            assert reply.status==expected and reply.url==req.full_url
            data=reply.read((4<<20)+1)
    except urllib.error.HTTPError as error:
        raise RuntimeError('HTTP %s %s: %d' % ('GET' if body is None else 'POST',path,error.code)) from error
    assert len(data)<=4<<20
    return json.loads(data)

def eventually(action, accepted, seconds):
    deadline=time.monotonic()+seconds
    while True:
        value=action()
        if accepted(value): return value
        if time.monotonic()>=deadline: raise TimeoutError(repr(value)[:540])
        time.sleep(0.25)

def db_rows(query, params=()):
    with contextlib.closing(sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True)) as db:
        db.execute('PRAGMA query_only=ON')
        return db.execute(query,params).fetchall()

def terminal(table, job):
    assert table in ('jobs','schedule_runs') and re.fullmatch('[a-f0-9]{32}',job)
    row=eventually(lambda:db_rows('SELECT state,error FROM '+table+' WHERE id=?',(job,)),
                   lambda v:len(v)==1 and v[0][0] not in ('queued','running'),140)
    return row[0]

def record(path):
    st=path.lstat()
    assert stat.S_ISREG(st.st_mode) and st.st_nlink==1 and st.st_size<4<<20
    return {'dev':st.st_dev,'inode':st.st_ino,'mode':stat.S_IMODE(st.st_mode),
            'uid':st.st_uid,'size':st.st_size,'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}

def traffic(domain, marker):
    req=urllib.request.Request(site_origin+'/'+marker,headers={'Host':domain,'User-Agent':'Yunzhan native log QA'})
    try:
        with site.open(req,timeout=10) as reply: return reply.status
    except urllib.error.HTTPError as error: return error.code

def main_pid():
    return int(subprocess.check_output(['/usr/bin/systemctl','show','nginx.service','--property=MainPID','--value'],timeout=10))

def worker_for(path, pid):
    target=path.stat()
    children=Path(f'/proc/{pid}/task/{pid}/children').read_text().split()
    for child in children:
        proc=Path('/proc')/child
        try:
            if 'nginx: worker process' not in (proc/'cmdline').read_bytes().decode(errors='replace'): continue
            if (proc/'exe').stat().st_ino != (Path('/proc')/str(pid)/'exe').stat().st_ino: continue
            if any(d.stat().st_ino==target.st_ino and d.stat().st_dev==target.st_dev for d in (proc/'fd').iterdir() if d.exists()):
                return int(child)
        except FileNotFoundError:
            continue
    raise RuntimeError('could not identify an Nginx worker holding the test access log')

def new_schedule(label, sid):
    definition={'name':label,'kind':'log_cleanup','target_id':sid,'schedule_type':'daily','timezone':'UTC',
                'minute':29,'hour':23,'weekday':0,'retention_count':1,'enabled':False}
    row=api('/schedules',definition,201)
    assert not row['enabled'] and re.fullmatch('[a-f0-9]{32}',row['id'])
    return row['id']

def fire(sched):
    row=api('/schedules/'+sched+'/run',{},202)
    assert re.fullmatch('[a-f0-9]{32}',row['id'])
    return row['id']

try:
    assert db_rows('SELECT id FROM sites')==[]
    credentials_path=Path('/etc/panel/first-login.json')
    metadata=credentials_path.lstat()
    assert metadata.st_uid==0 and stat.S_IMODE(metadata.st_mode)==0o600 and metadata.st_nlink==1
    credentials=json.loads(credentials_path.read_bytes())
    csrf=api('/login',{k:credentials[k] for k in ('username','password')})['csrf']
    credentials.clear()
    registry=api('/app-registry?refresh=1')
    assert not registry['source']['stale'] and len(registry['catalog']['apps'])==50
    item,=[r for r in registry['catalog']['apps'] if r['id']=='nginx']
    assert item==program['application'] and registry['source']['resolved_commit']==program['served_head']
    nonce=secrets.token_hex(6)
    name='c169-logs-'+nonce
    domain=name+'.example.test'
    status=api('/sites',{'name':'Nginx 日志核对','slug':name,'domain':domain},202,secrets.token_hex(16))
    assert terminal('jobs',status['job_id'])[0]=='succeeded'
    created,=[r for r in api('/sites') if r['domain']==domain]
    assert created['status']=='running'
    sid=created['id']
    logdir=Path('/var/log/nginx')
    access=logdir/f'panel-{sid}.access.log'
    marker='c169-before-'+nonce
    assert traffic(domain,marker) in (200,404)
    eventually(lambda:access.read_bytes(),lambda v:marker.encode() in v,12)
    original=record(access)
    expired=access.with_name(access.name+'.20000101-000001.gz')
    with expired.open('xb') as f: f.write(gzip.compress(b'native owned archive\n',mtime=0))
    expired_original=record(expired)
    label='Nginx 中断日志验收'
    sched=new_schedule(label,sid)
    master=main_pid()
    worker=worker_for(access,master)
    pidfd=os.pidfd_open(worker)
    try:
        signal.pidfd_send_signal(pidfd,signal.SIGSTOP)
        eventually(lambda:Path(f'/proc/{worker}/status').read_text(),lambda value:'State:\tT' in value,5)
        interrupted=fire(sched)
        save('original-native-schedule.json',{'run':interrupted,'schedule':sched,'site':sid,'worker':worker,'master':master})
        state,error=terminal('schedule_runs',interrupted)
        assert state=='failed',state
    finally:
        try: signal.pidfd_send_signal(pidfd,signal.SIGCONT)
        finally: os.close(pidfd)
    inspection_url='/schedules/runs/'+interrupted+'/log-cleanup'
    evidence=api(inspection_url)
    assert evidence['state'] in ('unknown','running')
    assert evidence.get('result') is None and evidence['read_only'] and evidence['request_id']==interrupted and evidence['site_id']==sid
    assert not evidence.get('continuation') and re.fullmatch('[a-f0-9]{64}',evidence['plan_sha256'])
    assert any(row['name']==access.name and row['role']=='rotation' for row in evidence['files'])
    assert any(row['name']==expired.name and row['role']=='expiration' for row in evidence['files'])
    assert record(expired)==expired_original and main_pid()==master
    archived,=[p for p in logdir.glob(access.name+'.*') if p.lstat().st_ino==original['inode']]
    assert marker.encode() in archived.read_bytes()
    eventually(lambda:access.exists() and access.lstat().st_ino!=original['inode'],bool,12)
    assert traffic(domain,'c169-reopened-'+nonce) in (200,404)
    active=eventually(lambda:record(access),lambda v:v['size']>0,12)
    assert active['inode']!=original['inode']
    def worker_reopened():
        try: return worker_for(access,master)==worker
        except RuntimeError: return False
    eventually(worker_reopened,bool,12)
    evidence=api(inspection_url)
    assert evidence['state'] in ('unknown','running') and evidence.get('result') is None and not evidence.get('continuation')
    original_files={p.name:record(p) for p in (archived,expired,access)}
    save('browser-log-fixture.json',{'run':interrupted,'schedule_label':label,'site':sid,'inspection':evidence,
          'file_before':original_files,'master':master,'source':source})
    proof.update(ok=True,real_interrupted_log=True,source_ledger_state=evidence['state'],
                 exact_original_archive_retained=True,expired_archive_retained_before_continue=True,nginx_master_unchanged=True)
    if arch=='arm64':
        confirmation={'request_id':interrupted,'site_id':sid,'plan_sha256':evidence['plan_sha256'],'acknowledge_unknown':True}
        accepted=api(inspection_url+'/continue',confirmation)
        after=api(inspection_url)
        assert after['continuation']==accepted and re.fullmatch('[a-f0-9]{64}',accepted['evidence_sha256'])
        assert after['state']==evidence['state'] and after.get('result') is None
        assert {file.name:record(file) for file in (archived,expired,access)}==original_files
        assert main_pid()==master
        proof.update(real_continuation_via_api=True,read_only_file_identity_and_bytes_preserved=True,unknown_not_rewritten=True)
except BaseException:
    proof['failure']=traceback.format_exc()
finally:
    if csrf:
        try: api('/logout',{})
        except Exception: proof['ok']=False
    save('original-proof.json',proof)
if not proof['ok']: sys.exit(1)
