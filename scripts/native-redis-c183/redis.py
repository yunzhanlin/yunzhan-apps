"""Validate signed Redis persistence on a disposable Debian guest."""
import base64
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
def redis_command(connection, stream, *items):
    payload = [f'*{len(items)}\r\n'.encode()]
    for item in items:
        raw = item.encode('utf8')
        payload += [f'${len(raw)}\r\n'.encode(), raw, b'\r\n']
    connection.sendall(b''.join(payload))
    line = stream.readline(1024)
    assert line.endswith(b'\r\n')
    value = line[1:-2]
    if line.startswith(b'$'):
        count = int(value)
        assert 0 <= count < 1024
        raw = stream.read(count + 2)
        assert len(raw) == count + 2 and raw.endswith(b'\r\n')
        return '$', raw[:-2]
    assert line[:1] in (b'+', b'-')
    return line[:1].decode(), value


def assert_unauthenticated(port):
    with socket.create_connection(('127.0.0.1', port), timeout=5) as c, c.makefile('rb') as f:
        kind, data = redis_command(c, f, 'GET', 'c81:proof')
        assert kind == '-' and data.startswith(b'NOAUTH')


def redis_read(instance, credentials, marker=None):
    with socket.create_connection(('127.0.0.1', instance['port']), timeout=5) as c, c.makefile('rb') as f:
        assert redis_command(c, f, 'AUTH', credentials['username'], credentials['password']) == ('+', b'OK')
        if marker:
            assert redis_command(c, f, 'SET', 'c81:proof', marker) == ('+', b'OK')
        kind, data = redis_command(c, f, 'GET', 'c81:proof')
        assert kind == '$'
        return data.decode()


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
    assert item['id']=='redis' and item['target']=='redis-8.2.11' and item['version']=='8.2.11-compat1'
    assert sha(private/'redis.manifest.json')==item['sha256']
    cache=Path('/var/lib/panel/app-registry')
    stage(cache/'catalog'/'catalog-v1.bundle.json',private/'catalogue.bundle.json')
    stage(cache/'packages'/'redis'/item['version']/'manifest.json',private/'redis.manifest.json')
    assert bundle['catalog'].encode()==(private/'catalogue.json').read_bytes()
    catalogue=api('/app-registry')[1]
    assert len(catalogue['catalog']['apps'])==50
    assert item==next(o for o in catalogue['catalog']['apps'] if o['id']=='redis')
    status=next(o for o in catalogue['status'] if o['id']=='redis')
    assert not status['installed'] and status['supported']
    queued=api('/app-registry/redis/install',{'expected_version':item['version'],'expected_sha256':item['sha256']},
               202,secrets.token_hex(16))[1]
    job=wait(lambda:api('/jobs/'+queued['job_id'])[1],lambda row:row.get('state') in ('succeeded','failed','needs_attention'),1200)
    keep('redis-signed-store-original-job',job)
    assert job['state']=='succeeded'
    with sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True) as db:
        binary,status=db.execute('SELECT binary_path,status FROM runtime_installations WHERE id=?',(item['target'],)).fetchone()
    assert (Path(binary).name,status)==('redis-server','installed')
    assert 'v=8.2.11 ' in subprocess.check_output([binary,'--version'],text=True,timeout=5)
    report['signed_cache_validated']=True
    port=16483
    marker=secrets.token_hex(12)
    instance=api('/redis/instances',{'name':'redis-qa-'+marker,'release_id':item['target'],'port':port,'max_memory_mb':128},201)[1]
    id=instance['id']
    assert re.fullmatch('[0-9a-f]{32}',id) and instance['auth_mode']=='acl-password-v2' and instance['status']=='running'
    credentials=api('/redis/instances/'+id+'/credentials',{})[1]
    assert credentials['host']=='127.0.0.1' and credentials['port']==port and credentials['username']=='app-'+id[:12]
    assert re.fullmatch('[0-9a-f]{64}',credentials['password'])
    assert_unauthenticated(port)
    with socket.create_connection(('127.0.0.1',port),timeout=5) as c,c.makefile('rb') as f:
        assert redis_command(c,f,'AUTH',credentials['username'],credentials['password'])==('+',b'OK')
        code,text=redis_command(c,f,'BGSAVE')
        assert code=='-' and text.startswith(b'NOPERM')
    old='snapshot-'+marker
    newer='live-'+marker
    assert redis_read(instance,credentials,old)==old
    route='/redis/instances/'+id+'/persistence'
    initial=api(route)[1]
    assert initial['instance_id']==id and initial['aof_enabled'] and initial['aof_write_status']=='ok'
    assert initial['changes_since_last_save']>=1 and not initial['snapshot_running']
    endpoint=panel_origin+'/api'+route
    blocked=request(opener,endpoint,{'confirm_id':id},403,{'Origin':panel_origin,'Content-Type':'application/json'},'POST')
    assert blocked[0]==403
    assert api(route,{'confirm_id':secrets.token_hex(16)},400)[0]==400
    assert api(route,{'confirm_id':id},202)[1]=={'instance_id':id}
    real=wait(lambda:api(route)[1],lambda o: not o['snapshot_running'] and o['snapshot_status']=='ok' and
              o['last_snapshot']>0 and o['changes_since_last_save']==0,90)
    assert real['instance_id']==id and real['snapshot_duration_seconds']>=0
    snapshot=Path('/srv/panel/redis')/id/'dump.rdb'
    state=snapshot.lstat()
    assert stat.S_ISREG(state.st_mode) and state.st_nlink==1 and state.st_size>60
    checksum=sha(snapshot)
    assert redis_read(instance,credentials,newer)==newer
    service=pwd.getpwnam('panel-redis')
    restore=Path('/run')/('redis-restore-'+marker)
    restore.mkdir(mode=0o700)
    os.chown(restore,service.pw_uid,service.pw_gid)
    rdb=restore/'dump.rdb'
    shutil.copyfile(snapshot,rdb)
    os.chown(rdb,service.pw_uid,service.pw_gid)
    os.chmod(rdb,0o600)
    restored_socket=restore/'restore.sock'
    argv=[binary,'--port','0','--unixsocket',str(restored_socket),'--unixsocketperm','600','--dir',str(restore),
          '--dbfilename','dump.rdb','--appendonly','no','--save','','--daemonize','no','--set-proc-title','no']
    with (out/'isolated-rdb-restore.log').open('xb') as log:
        process=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT,
                                 user=service.pw_uid,group=service.pw_gid,extra_groups=[])
        try:
            wait(restored_socket.is_socket,bool,30)
            with socket.socket(socket.AF_UNIX) as c:
                c.settimeout(5)
                c.connect(str(restored_socket))
                with c.makefile('rb') as f:
                    assert redis_command(c,f,'GET','c81:proof')==('$',old.encode())
        finally:
            process.terminate()
            process.wait(timeout=15)
    shutil.rmtree(restore)
    assert sha(snapshot)==checksum
    api('/redis/instances/'+id+'/restart',{})
    assert redis_read(instance,credentials)==newer
    assert api(route)[1]['aof_write_status']=='ok'
    with sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True) as db:
        actions=db.execute("SELECT result FROM audit_logs WHERE action='redis.snapshot.start' AND target=?",(id,)).fetchall()
    assert sorted(actions)==[('accepted',),('requested',)]
    keep('native-rdb-before',initial)
    keep('native-rdb-after',real)
    report.update(ok=True,source_inputs_sha256=plan['source_inputs_sha256'],actual_version='8.2.11',
        signed_app_version=item['version'],original_rdb_read_verified=True,
        original_instance_aof_after_restart=True,app_acl_blocks_bgsave=True,bad_confirmation_and_csrf_rejected=True,
        audit_verified=True)
except BaseException:
    report['failure']=traceback.format_exc()
finally:
    keep('result',report)
    print(json.dumps(report),flush=True)
sys.exit(0 if report['ok'] else 1)
