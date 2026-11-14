"""Validate signed MySQL backup, restore and migration on a disposable Debian guest."""
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
    assert item['id']=='mysql' and item['target']=='mysql-8.4.13' and item['version']=='8.4.13-compat1'
    assert sha(private/'mysql.manifest.json')==item['sha256']
    cache=Path('/var/lib/panel/app-registry')
    stage(cache/'catalog'/'catalog-v1.bundle.json',private/'catalogue.bundle.json')
    stage(cache/'packages'/'mysql'/item['version']/'manifest.json',private/'mysql.manifest.json')
    assert bundle['catalog'].encode()==(private/'catalogue.json').read_bytes()
    catalogue=api('/app-registry')[1]
    assert len(catalogue['catalog']['apps'])==50
    assert item==next(o for o in catalogue['catalog']['apps'] if o['id']=='mysql')
    state=next(o for o in catalogue['status'] if o['id']=='mysql')
    assert state['supported'] and not state['installed']

    def queue(table,label,route,data,expect='succeeded'):
        assert table in ('mysql_jobs','runtime_jobs')
        key=secrets.token_hex(16)
        queued=api(route,data,202,key)[1]
        job=queued['job_id']
        assert re.fullmatch('[a-f0-9]{32}',job)
        def observe():
            with sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True) as db:
                db.row_factory=sqlite3.Row
                row=db.execute('SELECT id,state,target_id,error,idempotency_key FROM '+table+' WHERE id=?',(job,)).fetchone()
            return dict(row) if row is not None else {}
        actual=wait(observe,lambda row:row.get('state') in ('succeeded','failed','needs_attention'),1150)
        assert actual.pop('idempotency_key')==key
        keep(label,actual)
        assert actual['state']==expect and (expect!='succeeded' or not actual['error']), (label,actual['state'],actual['error'])
        return actual
    queue('runtime_jobs','signed-store-install','/app-registry/mysql/install',
          {'expected_version':item['version'],'expected_sha256':item['sha256']})
    queue('runtime_jobs','migration-source-runtime','/runtimes/install',{'release_id':'mysql-8.0.46'})
    report['signed_cache_validated']=True

    def server(release,name,port):
        id=queue('mysql_jobs','instance-'+name,'/databases/instances',{'name':name,'release_id':release,'port':port})['target_id']
        state=api('/databases')[1]
        actual,=[o for o in state['actual']['servers'] if o['id']==id]
        assert actual['authenticated'] and actual['version']==release.removeprefix('mysql-') and actual['port']==port
        return id
    target=server('mysql-8.4.13','QA target',13479)
    origin=server('mysql-8.0.46','QA source',13480)
    def database(server,name):
        queue('mysql_jobs','database-'+name,'/databases/instances/'+server+'/databases',{'name':name})
        return database_row(server,name)
    def database_row(server,name):
        row,=[o for o in api('/databases')[1]['databases'] if o['server_id']==server and o['name']==name]
        assert row['status']=='ready'
        return row['id']
    def mysql(server,name,sql):
        ret=subprocess.run(['/opt/panel/current/bin/panel-executor','--database-cli',server,'--',
             '--batch','--skip-column-names',name],input=sql+'\\n',text=True,capture_output=True,timeout=35)
        assert ret.returncode==0, 'Unexpected no-read in the native SQL operation'
        return ret.stdout.strip()
    def backup_download(id,want=200):
        req=urllib.request.Request(panel_origin+'/api/databases/backups/'+id+'/download')
        try:
            with opener.open(req,timeout=50) as response:
                code,body=response.status,response.read(2<<20)
        except urllib.error.HTTPError as error:
            code,body=error.code,error.read(16384)
        assert code==want,(code,want)
        return body
    def data(server,name):
        return mysql(server,name,'SELECT id,marker FROM proof ORDER BY id')
    def seed(server,name,value):
        mysql(server,name,"CREATE TABLE proof(id INT PRIMARY KEY, marker VARCHAR(60) NOT NULL); INSERT INTO proof VALUES(1,'"+value+"'), (2,'two');")
    name='qa_recovery'
    db=database(target,name)
    marker='before-'+secrets.token_hex(6)
    seed(target,name,marker)
    peer_name='qa_neighbor'
    peer=database(target,peer_name)
    seed(target,peer_name,'untouched')
    original_peer=data(target,peer_name)
    before=data(target,name)
    route='/databases/items/'+db
    queued=queue('mysql_jobs','native-original-backup',route+'/backup',{})
    backup,=[row for row in api('/databases')[1]['backups'] if row['database_id']==db]
    download=backup_download(backup['id'])
    assert hashlib.sha256(download).hexdigest()==backup['sha256'] and len(download)==backup['bytes']
    assert marker.encode() in download
    mysql(target,name,"UPDATE proof SET marker='after' WHERE id=1; INSERT INTO proof VALUES(3,'extra');")
    changed=data(target,name)
    assert changed!=before
    assert api(route+'/restore',{'backup_id':backup['id'],'confirm_name':'different'},400)[0]==400
    assert api('/databases/items/'+peer+'/restore',{'backup_id':backup['id'],'confirm_name':peer_name},409)[0]==409
    assert data(target,peer_name)==original_peer
    path=Path('/var/backups/panel/mysql')/target/(backup['id']+'.sql')
    assert not path.is_symlink() and path.read_bytes()==download
    swapped=path.with_name(path.name+'.fixture-original')
    os.rename(path,swapped)
    path.symlink_to(swapped.name)
    try:
        backup_download(backup['id'],409)
        refused=queue('mysql_jobs','symlink-restore-refused',route+'/restore',
            {'backup_id':backup['id'],'confirm_name':name},'failed')
        assert refused['error']
        assert data(target,name)==changed
    finally:
        path.unlink()
        os.rename(swapped,path)
    assert path.read_bytes()==download and not path.is_symlink()
    queue('mysql_jobs','native-verified-restore',route+'/restore',{'backup_id':backup['id'],'confirm_name':name})
    assert data(target,name)==before and data(target,peer_name)==original_peer
    receipts=[row for row in api('/databases')[1]['backups'] if row['database_id']==db and row['id']!=backup['id']]
    rollback,=receipts
    copy=backup_download(rollback['id'])
    assert hashlib.sha256(copy).hexdigest()==rollback['sha256'] and b"after" in copy and b"extra" in copy

    migration_name='qa_move'
    moving=database(origin,migration_name)
    seed(origin,migration_name,'source-'+marker)
    mysql(origin,migration_name,'CREATE VIEW proof_view AS SELECT id,marker FROM proof WHERE id=1;')
    original=data(origin,migration_name)
    queue('mysql_jobs','native-80-to-84-migration','/databases/items/'+moving+'/migrate',
         {'target_id':target,'confirm_name':migration_name})
    assert database_row(target,migration_name)!=moving
    assert data(origin,migration_name)==original and data(target,migration_name)==original
    assert mysql(origin,migration_name,'SELECT * FROM proof_view')==mysql(target,migration_name,'SELECT * FROM proof_view')
    assert data(target,name)==before and data(target,peer_name)==original_peer
    report.update(ok=True,source_inputs_sha256=plan['source_inputs_sha256'],signed_app_version=item['version'],
         actual_version='8.4.13',restore_verified_with_exact_sql=True,source_hash_matches_download=True,
         retained_pre_restore_backup=True,symlink_rejected_before_any_database_replacement=True,
         source_and_neighbor_preserved=True,real_mysql_80_to_84_migration=True)
except BaseException:
    report['failure']=traceback.format_exc()
finally:
    keep('result',report)
    print(json.dumps(report),flush=True)
sys.exit(0 if report['ok'] else 1)
