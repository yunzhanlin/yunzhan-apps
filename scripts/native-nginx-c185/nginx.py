"""Validate signed Nginx logs on a disposable Linux guest."""
import base64
import gzip
import hashlib
import http.cookiejar
import json
import os
from pathlib import Path
import platform
import pwd
import re
import secrets
import shutil
import socket
import sqlite3
import stat
import stat
import subprocess
import sys
import time
import traceback
import urllib.error
import urllib.request

os.umask(0o077)
root=Path(sys.argv[1]).resolve(strict=True)
assert os.geteuid()==0 and len(sys.argv)==2
plan=json.loads((root/'assets.json').read_bytes())
arch={'x86_64':'amd64','aarch64':'arm64'}[platform.machine()]
case=plan['OS_case']
assert arch==plan['architecture']
host_os=dict(line.partition('=')[::2] for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
assert host_os['ID'].strip('"')==case['os_id'] and host_os['VERSION_ID'].strip('"')==case['version_id']
assert case['platform']==case['os_id']+'-'+case['version_id']
assert Path('/etc/hostname').read_text().strip()==plan['OS_case']['hostname']
assert not Path('/opt/panel').exists() and not Path('/var/lib/panel').exists()
base=Path('/opt/panel-elastic-c174-qa-'+secrets.token_hex(16))
base.mkdir(mode=0o700)
private=base/'verified'
private.mkdir(mode=0o700)
out=base/'evidence'
out.mkdir(mode=0o700)
def sha(path):
    hashed=hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda:f.read(1<<20),b''):
            hashed.update(block)
    return hashed.hexdigest()
def keep(name,obj):
    with (out/(name+'.json')).open('x') as f:
        json.dump(obj,f,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
def command(name,args,limit=150):
    with (out/(name+'.stdout')).open('xb') as a,(out/(name+'.stderr')).open('xb') as b:
        p=subprocess.run(args,stdin=subprocess.DEVNULL,stdout=a,stderr=b,timeout=limit)
    assert p.returncode==0,name
def stage(path,artifact):
    owner=pwd.getpwnam('panel')
    path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    for d in path.parents:
        if d==Path('/var/lib/panel'):break
        assert not d.is_symlink()
        os.chown(d,owner.pw_uid,owner.pw_gid)
    temp=path.with_suffix('.new')
    temp.open('xb').write(artifact.read_bytes())
    os.chown(temp,owner.pw_uid,owner.pw_gid)
    os.replace(temp,path)
def wait(check,accept,seconds):
    deadline=time.monotonic()+seconds
    while time.monotonic()<deadline:
        got=check()
        if accept(got):return got
        time.sleep(2)
    state=got.get('state','unknown') if isinstance(got,dict) else 'unknown'
    raise TimeoutError('Original native operation did not reach the expected state: '+str(state))
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
panel_origin='http://127.0.0.1:19100'
csrf=''
def api(path,body=None,status=200,key=None,method=None):
    headers={'Origin':panel_origin,'Content-Type':'application/json','X-CSRF-Token':csrf}
    if key:headers['Idempotency-Key']=key
    return request(opener,panel_origin+'/api'+path,body,status,headers,method)
def request(client,url,body,status,headers,method):
    req=urllib.request.Request(url,None if body is None else json.dumps(body).encode(),headers,method=method)
    try:
        with client.open(req,timeout=80) as res:
            assert res.url==url
            code,raw=res.status,res.read(5<<20)
    except urllib.error.HTTPError as err:
        code,raw=err.code,err.read(5<<20)
    parsed=json.loads(raw)
    error=parsed.get('error','') if isinstance(parsed,dict) else ''
    if isinstance(error,dict):
        error=error.get('type','')
    assert status is None or code==status,(req.get_method(),url,code,status,str(error)[:260])
    return code,parsed
def rows(query, args=()):
    with sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro', uri=True) as db:
        db.execute('PRAGMA query_only=ON')
        return db.execute(query, args).fetchall()


def source():
    return json.loads(Path('/opt/panel/current/SOURCE_INPUTS.json').read_bytes())['inputs_sha256']


def record(path):
    info = path.lstat()
    assert stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size < 4 << 20
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    return {'inode': [info.st_dev, info.st_ino], 'uid': info.st_uid, 'mode': stat.S_IMODE(info.st_mode), 'sha256': digest, 'size': info.st_size}


def create_owned(path, data):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), 'wb') as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())


def settle(check, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = check()
        if result:
            return result
        time.sleep(0.2)
    raise TimeoutError('original operation did not reach the expected state')


def job_result(table, job, expected, seconds=420):
    assert table in ('jobs', 'schedule_runs', 'runtime_jobs') and re.fullmatch('[a-f0-9]{32}', job)

    def terminal():
        state, error = rows(f'SELECT state,error FROM {table} WHERE id=?', (job,))[0]
        return (state, error) if state not in ('queued', 'running') else None

    state, error = settle(terminal, seconds)
    assert state == expected, (state, error)
    return error


def writers():
    master = subprocess.check_output(['/usr/bin/systemctl', 'show', 'nginx.service', '--property=MainPID', '--value'], text=True).strip()
    assert master.isdigit() and int(master) > 1
    root = Path('/proc') / master
    executable = Path(os.readlink(root / 'exe'))
    selection = Path('/etc/panel/nginx/active.json')
    active = json.loads(selection.read_bytes())['id'] if selection.exists() else 'nginx-system'
    expected = {'nginx-system': '/usr/sbin/nginx', 'nginx-1.30.6': '/opt/panel/runtimes/nginx/1.30.6/sbin/nginx'}
    assert active in expected and executable == Path(expected[active]), (active, str(executable))
    worker_ids = (root / 'task' / master / 'children').read_text().split()
    assert 0 < len(worker_ids) <= 64
    result = {}
    for pid in (master, *worker_ids):
        root = Path('/proc') / pid
        identity = (root / 'stat').read_text().rsplit(')', 1)[1].split()[19]
        files = []
        for fd in (root / 'fd').iterdir():
            try:
                info = fd.stat()
            except FileNotFoundError:
                continue
            if stat.S_ISREG(info.st_mode):
                files.append([info.st_dev, info.st_ino])
        assert Path(os.readlink(root / 'exe')) == executable
        result[pid] = {'start': identity, 'files': sorted(files), 'path':str(executable), 'active_runtime':active}
    return result


report={'ok':False,'architecture':arch,'platform':case['platform'],'base':str(base),'Main_changed':False,'all50_commercial':False}
try:
    for name,digest in plan['files'].items():
        assert re.fullmatch(r'[a-zA-Z0-9._-]+',name)
        data=(root/name).read_bytes()
        assert 0<len(data)<64<<20 and hashlib.sha256(data).hexdigest()==digest
        (private/name).open('xb').write(data)
    archive=private/('panel-'+plan['version']+'-linux-'+arch+'.tar.gz')
    key=['--public-key',str(private/'release-signing-dev.pub')]
    signer=[sys.executable,'-I','-B',str(private/'signed-release.py')]
    command('archive-verify',signer+['verify',str(archive)]+key)
    command('archive-preflight',signer+['install',str(archive)]+key+['--preflight-only'],600)
    command('programme-install',signer+['install',str(archive)]+key,1800)
    assert json.loads(Path('/opt/panel/current/SOURCE_INPUTS.json').read_bytes())['inputs_sha256']==plan['source_inputs_sha256']
    creds=json.loads(Path('/etc/panel/first-login.json').read_bytes())
    csrf=api('/login',{k:creds[k] for k in ('username','password')})[1]['csrf'];creds.clear()

    assert sha(private/'catalogue.pub.pem')=='659ea4edcecaf23a586e2ff371616fde5f6ee7c219fb70fa978816e2b10acf75'
    command('catalogue-verify',['openssl','pkeyutl','-verify','-pubin','-inkey',str(private/'catalogue.pub.pem'),
            '-rawin','-in',str(private/'catalogue.json'),'-sigfile',str(private/'catalogue.sig.bin')])
    bundle=json.loads((private/'catalogue.bundle.json').read_bytes())
    assert base64.b64decode(bundle['signature'])==(private/'catalogue.sig.bin').read_bytes()
    item=plan['application']
    assert item['id']=='nginx' and item['version']=='1.30.6-compat1' and item['target']=='nginx-1.30.6'
    assert sha(private/'nginx.manifest.json')==item['sha256']
    cache=Path('/var/lib/panel/app-registry')
    stage(cache/'catalog'/'catalog-v1.bundle.json',private/'catalogue.bundle.json')
    stage(cache/'packages'/'nginx'/item['version']/'manifest.json',private/'nginx.manifest.json')
    assert bundle['catalog'].encode()==(private/'catalogue.json').read_bytes()
    directory=api('/app-registry')[1]
    assert next(r for r in directory['catalog']['apps'] if r['id']=='nginx')==item
    assert len(directory['catalog']['apps'])==50
    original_sites=rows('SELECT id,domain,status FROM sites ORDER BY id')
    install=api('/app-registry/nginx/install',{'expected_version':item['version'],'expected_sha256':item['sha256']},202,secrets.token_hex(16))[1]['job_id']
    assert job_result('runtime_jobs',install,'succeeded',1100)==''
    def signed_receipt_ready():
        observed=api('/app-registry')[1]
        status=next(v for v in observed['status'] if v['id']=='nginx')
        return status['state_known'] and status['installed'] and rows("SELECT version,sha256,target FROM app_registry_receipts WHERE app_id='nginx'")==[(item['version'],item['sha256'],item['target'])]
    wait(signed_receipt_ready,bool,90)
    switch=api('/runtimes/nginx/switch',{'release_id':item['target']},202,secrets.token_hex(16))[1]['job_id']
    assert job_result('runtime_jobs',switch,'succeeded')==''
    assert next(iter(writers().values()))['active_runtime']==item['target']
    for index in range(2):
        slug='qa-c185-'+secrets.token_hex(6)
        dom=slug+'.example.test'
        job=api('/sites',{'name':slug,'slug':slug,'domain':dom},202,secrets.token_hex(16))[1]['job_id']
        assert job_result('jobs',job,'succeeded')==''
        row,=[r for r in api('/sites')[1] if r['domain']==dom]
        assert row['status']=='running'
        if index==0:
            site=row['id']; domain=dom
        else:
            other=row['id']; other_domain=dom
    log_dir=Path('/var/log/nginx')
    access=log_dir/('panel-'+site+'.access.log')
    error=log_dir/('panel-'+site+'.error.log')
    public=Path('/srv/panel/sites')/site/'public'
    denied=public/'permission-denied.txt'
    create_owned(denied,b'isolated QA marker\n')
    own=record(denied)
    others=rows('SELECT id,domain,status FROM sites WHERE id!=? ORDER BY id',(site,))
    assert sorted([v for v in others if v[0]!=other])==sorted(original_sites)
    cfg=Path('/etc/panel/sites-enabled')/(site+'.conf')
    old_config=record(cfg)
    site_opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    def visit(domain,path):
        req=urllib.request.Request('http://127.0.0.1:19101'+path,headers={'Host':domain,'User-Agent':'Yunzhan QA'})
        try:
            with site_opener.open(req,timeout=6) as reply:
                return reply.status
        except urllib.error.HTTPError as reply:
            return reply.code
    def traffic(label):
        one='/absent-'+label+'-'+secrets.token_hex(5)
        two='/permission-denied.txt?ref='+label+'-'+secrets.token_hex(5)
        assert visit(domain,one)==404
        assert visit(domain,two) in (403,404)
        assert settle(lambda:one.encode() in access.read_bytes() and two.partition('?')[0].encode() in error.read_bytes(),15)
    def scheduled(label):
        req={'name':'Nginx signed '+label,'kind':'log_cleanup','target_id':site,
             'schedule_type':'daily','timezone':'UTC','minute':13,'hour':23,'weekday':0,
             'retention_count':1,'enabled':False}
        sch=api('/schedules',req,201)[1]
        assert not sch['enabled']
        return api('/schedules/'+sch['id']+'/run',{},202)[1]['id']
    traffic('before')
    assert visit(other_domain,'/missing-neighbor')==404
    other_access=log_dir/('panel-'+other+'.access.log')
    other_before=record(other_access)
    collision=access.with_name(access.name+'.20000101-000000.gz')
    collision.symlink_to(other_access)
    files=(access,error)
    before_refusal=[record(p) for p in files]
    refused=scheduled('refuse symlink')
    assert job_result('schedule_runs',refused,'failed')
    assert [record(p) for p in files]==before_refusal and record(other_access)==other_before
    collision.unlink()
    old=[record(path) for path in files]
    old_raw=[path.read_bytes() for path in files]
    listeners=writers()
    assert all(any(v['inode'] in o['files'] for o in listeners.values()) for v in old)
    expired=access.with_name(access.name+'.20000101-000003.gz')
    compressed=gzip.compress(old_raw[0],mtime=0)
    create_owned(expired,compressed)
    keeper=error.with_name(error.name+'.20991231-235959.gz')
    create_owned(keeper,gzip.compress(old_raw[1],mtime=0))
    keep_identity=record(keeper)
    result=scheduled('rotate')
    assert job_result('schedule_runs',result,'succeeded')==''
    result_route='/schedules/runs/'+result+'/log-cleanup'
    observed=api(result_route)[1]
    assert observed['state']=='completed' and observed['read_only'] and observed['site_id']==site
    assert observed['result']=={'rotated':2,'deleted':1,'deleted_bytes':len(compressed),'files':[expired.name]}
    assert not expired.exists() and record(keeper)==keep_identity
    archives=[]
    for p,v,raw in zip(files,old,old_raw):
        archived,=[c for c in p.parent.glob(p.name+'.*') if not c.name.endswith('.gz') and record(c)['inode']==v['inode']]
        assert archived.read_bytes().startswith(raw)
        archives.append(archived)
    archive_identity=[record(p) for p in archives]
    traffic('after')
    after=[record(p) for p in files]
    current=writers()
    assert {pid:v['start'] for pid,v in current.items()}=={pid:v['start'] for pid,v in listeners.items()}
    for original,replacement in zip(old,after):
        assert original['inode']!=replacement['inode']
        assert all(original['inode'] not in v['files'] for v in current.values())
        assert any(replacement['inode'] in v['files'] for v in current.values())
    assert record(other_access)==other_before and record(cfg)==old_config and record(denied)==own
    assert archive_identity==[record(p) for p in archives]
    assert api(result_route)[1]==observed and rows('SELECT id,domain,status FROM sites WHERE id!=? ORDER BY id',(site,))==others
    keep('nginx-log-observation',{'original':old,'replacement':after,'archive':archive_identity,'operation':observed,'refusal':refused})
    report.update(ok=True,source_inputs_sha256=plan['source_inputs_sha256'],signed_app_version=item['version'],
        signed_cache_validated=True,signed_nginx_runtime_active=True,
        original_writer_processes_reopened_both_logs=True,old_archives_and_other_site_preserved=True,
        verified_expired_archive_retired=True,unsafe_archive_refused_before_changes=True)
except BaseException:
    report['failure']=traceback.format_exc()
finally:
    keep('result',report)
    print(json.dumps(report),flush=True)
sys.exit(0 if report['ok'] else 1)
