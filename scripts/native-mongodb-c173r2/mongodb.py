"""Exercise the signed MongoDB package in an owned Ubuntu 26 test guest."""
from pathlib import Path
import hashlib
import http.cookiejar
import json
import os
import platform
import pwd
import re
import secrets
import shlex
import socket
import subprocess
import sys
import time
import traceback
import urllib.error
import urllib.request

os.umask(0o077)
root=Path(sys.argv[1]).resolve(strict=True)
assert os.geteuid()==0 and len(sys.argv)==2
pins=json.loads((root/'assets.json').read_bytes())
assert Path('/etc/hostname').read_text().strip()==pins['OS_case']['hostname']
arch={'x86_64':'amd64','aarch64':'arm64'}[platform.machine()]
assert arch==pins['architecture'] and 'VERSION_ID="26.04"' in Path('/etc/os-release').read_text()
assert not Path('/opt/panel').exists() and not Path('/var/lib/panel').exists()
base=Path('/opt/panel-mongo-c173-qa-'+secrets.token_hex(16))
base.mkdir(mode=0o700)
out=base/'evidence';out.mkdir(mode=0o700)
priv=base/'verified';priv.mkdir(mode=0o700)
for name,digest in pins['files'].items():
    assert re.fullmatch('[a-zA-Z0-9._-]+',name)
    raw=(root/name).read_bytes()
    assert len(raw)<=64<<20 and hashlib.sha256(raw).hexdigest()==digest
    (priv/name).open('xb').write(raw)
def run(label,args,timeout=120,data=None):
    p=subprocess.run(args,input=data,capture_output=True,timeout=timeout)
    (out/(label+'.out')).open('xb').write(p.stdout)
    (out/(label+'.err')).open('xb').write(p.stderr)
    assert p.returncode==0,label
    return p.stdout
def save(name,data):
    with (out/(name+'.json')).open('x') as f:
        json.dump(data,f,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
csrf=''
origin='http://127.0.0.1:19100'
client=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
def api(path,body=None,status=200,key=None):
    headers={'Content-Type':'application/json','Origin':origin,'X-CSRF-Token':csrf}
    if key:headers['Idempotency-Key']=key
    req=urllib.request.Request(origin+'/api'+path,None if body is None else json.dumps(body).encode(),headers)
    try:
        with client.open(req,timeout=80) as res:
            assert res.url==req.full_url
            code,raw=res.status,res.read(4<<20)
    except urllib.error.HTTPError as exc:
        code,raw=exc.code,exc.read(4<<20)
    assert code==status,(path,code,status)
    return json.loads(raw)
def observe(callback,verify,seconds):
    deadline=time.monotonic()+seconds
    while time.monotonic()<deadline:
        value=callback()
        if verify(value): return value
        time.sleep(2)
    raise TimeoutError('Original operation did not complete in its observation window')
def job(submission):
    jid=submission['job_id'];project=submission['project_id']
    assert re.fullmatch('[0-9a-f]{32}',jid) and re.fullmatch('[0-9a-f]{32}',project)
    row=observe(lambda:api('/docker/job-observations/'+jid),lambda a:a['state'] in ('succeeded','failed'),900)
    save('compose-'+jid,row)
    assert row['state']=='succeeded' and row['project_id']==project and not row.get('error')
    return project
def status(project):
    return next((row for row in api('/docker/projects')['projects'] if row['id']==project),{})
def docker(*args,input=None,timeout=70):
    return subprocess.run(['/usr/bin/docker',*args],input=input,capture_output=True,timeout=timeout)
def unique_container(project,image,port):
    found=docker('ps','-aq','--filter','label=com.docker.compose.project=panel_'+project[:12])
    assert found.returncode==0
    cid,=found.stdout.decode().splitlines()
    container,=json.loads(docker('inspect',cid).stdout)
    assert container['Config']['Image']==image and not container['HostConfig']['Privileged']
    assert container['HostConfig']['PortBindings']=={'27017/tcp':[{'HostIp':'127.0.0.1','HostPort':str(port)}]}
    runner,=json.loads(docker('image','inspect',container['Image']).stdout)
    assert runner['Architecture']==arch
    mount,=[m for m in container['Mounts'] if m['Destination']=='/data/db']
    assert mount['Type']=='volume' and mount['RW']
    st=Path(mount['Source']).lstat()
    return {'id':cid,'image':container['Image'],'volume':mount['Name'],'dev':st.st_dev,'inode':st.st_ino}
def evaluate(port,script):
    image=pins['image']
    command=docker('run','--rm','-i','--pull=never','--network=host','--entrypoint','mongosh',image,
                   '--host','127.0.0.1','--port',str(port),'--norc','--quiet','--file','/dev/stdin',input=script.encode(),timeout=100)
    assert command.returncode==0,'mongosh assertion failed'
    return command.stdout.decode()
def credentials(project):
    response=api('/docker/projects/'+project+'/credentials',{})
    assert response['project_id']==project and response['template_id']==pins['application']['target']
    fields=response['credentials']
    password=fields['MONGO_INITDB_ROOT_PASSWORD']
    assert fields['MONGO_INITDB_ROOT_USERNAME']=='paneladmin' and re.fullmatch('[0-9a-f]{64}',password)
    return password
def store_entry(page):
    assert page['host']=={'platform':'ubuntu-26.04','architecture':arch} and len(page['catalog']['apps'])==50
    item,=[row for row in page['catalog']['apps'] if row['id']=='mongodb']
    state,=[row for row in page['status'] if row['id']=='mongodb']
    return item,state
def cache_install(path,source):
    account=pwd.getpwnam('panel')
    path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    for ancestor in path.parents:
        if ancestor==Path('/var/lib/panel'):break
        if ancestor==Path('/var/lib/panel/app-registry') or Path('/var/lib/panel/app-registry') in ancestor.parents:
            assert not ancestor.is_symlink()
            os.chown(ancestor,account.pw_uid,account.pw_gid)
    temp=path.with_suffix('.qa-new')
    with temp.open('xb') as f:
        f.write(source.read_bytes());f.flush();os.fsync(f.fileno())
    os.chown(temp,account.pw_uid,account.pw_gid)
    os.replace(temp,path)
def tool(container, name, args, password, input=None):
    # Database Tools reads authentication from the root-private temporary YAML file.
    # In Docker exec its path, username and database names are the only argv data.
    wrapper='set -eu; umask 077; cfg=$(mktemp); trap \'rm -f "$cfg"\' EXIT; IFS= read -r password; printf \'password: "%s"\\n\' "$password" > "$cfg"; "$1" --config="$cfg" --host=127.0.0.1 --username=paneladmin --authenticationDatabase=admin "${@:2}"'
    cmd=['exec','-i',container,'bash','-c',wrapper,'mongodb-qa',name,*args]
    data=password.encode()+b'\n'+(input or b'')
    return docker(*cmd,input=data,timeout=160)
report={'ok':False,'architecture':arch,'platform':'ubuntu-26.04','Main_changed':False,'all50_commercial':False,'base':str(base)}
try:
    kernel=platform.release()
    signature=Path('/proc/version_signature').read_text().strip()
    assert kernel.startswith('7.0.0-') and signature.startswith('Ubuntu ') and tuple(map(int,signature.split()[-1].split('.')))>=(7,0,14)
    report.update(kernel=kernel,ubuntu_version_signature=signature)
    archive=priv/('panel-'+pins['version']+'-linux-'+arch+'.tar.gz')
    assert hashlib.sha256((priv/'release-signing-dev.pub').read_bytes()).hexdigest()=='4ccfcc861d56a41e3ba7f7ace7e2432c815f366c58448d783df92c6632f01339'
    signer=[sys.executable,'-I','-B',str(priv/'signed-release.py')]
    key=['--public-key',str(priv/'release-signing-dev.pub')]
    run('verify',signer+['verify',str(archive)]+key)
    run('preflight',signer+['install',str(archive)]+key+['--preflight-only'],600)
    run('install',signer+['install',str(archive)]+key,1800)
    assert json.loads(Path('/opt/panel/current/SOURCE_INPUTS.json').read_bytes())['inputs_sha256']==pins['source_inputs_sha256']
    creds=json.loads(Path('/etc/panel/first-login.json').read_bytes())
    csrf=api('/login',{k:creds[k] for k in ('username','password')})['csrf'];creds.clear()
    page=api('/app-registry?refresh=1')
    item,old=store_entry(page)
    assert page['source']['resolved_commit']==pins['served_head'] and not page['source']['stale']
    assert item['version']=='8.0-compat1' and not old['supported'] and not old['installed']
    report['old_version_guard_active']=True
    docker_item,=[item for item in page['catalog']['apps'] if item['id']=='docker-manager']
    start=api('/app-registry/docker-manager/install',{'expected_version':docker_item['version'],'expected_sha256':docker_item['sha256']},202,secrets.token_hex(16))
    row=observe(lambda:api('/jobs/'+start['job_id']),lambda r:r.get('state') in ('succeeded','failed','needs_attention'),1000)
    assert row['state']=='succeeded'
    save('signed-docker-manager',row)
    assert docker('info','--format','{{.OSType}}').stdout.strip()==b'linux'

    # Verify the isolated published QA bytes independently. The installed panel
    # re-verifies those same bytes with its normal signed-cache code and SHA
    # comparison. No product endpoint, GitHub trust root or release is changed.
    run('verify-candidate-catalogue',['openssl','pkeyutl','-verify','-pubin','-inkey',str(priv/'catalogue.pub.pem'),
                                     '-rawin','-in',str(priv/'catalogue.json'),'-sigfile',str(priv/'catalogue.sig.bin')])
    bundle=json.loads((priv/'catalogue.bundle.json').read_bytes())
    assert bundle['catalog'].encode()==(priv/'catalogue.json').read_bytes()
    assert __import__('base64').b64decode(bundle['signature'])==(priv/'catalogue.sig.bin').read_bytes()
    assert hashlib.sha256((priv/'mongo.manifest.json').read_bytes()).hexdigest()==pins['application']['sha256']
    cache=Path('/var/lib/panel/app-registry')
    cache_install(cache/'catalog'/'catalog-v1.bundle.json',priv/'catalogue.bundle.json')
    cache_install(cache/'packages'/'mongodb'/pins['application']['version']/'manifest.json',priv/'mongo.manifest.json')
    item,ready=store_entry(api('/app-registry'))
    assert item==pins['application'] and ready['supported'] and not ready['installed']
    nonce=secrets.token_hex(6)
    projects=[]
    for index,port in enumerate((26573,26574)):
        accepted=api('/app-registry/mongodb/install',{'expected_version':item['version'],'expected_sha256':item['sha256'],
                    'name':'mongo-c173-'+nonce+'-'+str(index),'host_port':port},202,secrets.token_hex(16))
        project=job(accepted)
        observe(lambda:status(project),lambda row:row.get('state')=='running' and row.get('healthy')==1,300)
        projects.append((project,port,credentials(project),unique_container(project,pins['image'],port)))
    src,dst=projects
    assert src[2]!=dst[2] and src[3]['volume']!=dst[3]['volume'] and (src[3]['dev'],src[3]['inode'])!=(dst[3]['dev'],dst[3]['inode'])
    dbname='c173_'+nonce
    other='restored_'+nonce
    def authenticated(password):
        return 'const admin=db.getSiblingDB("admin"); assert.eq(admin.auth("paneladmin",'+json.dumps(password)+').ok,1);\n'
    source=authenticated(src[2])+'const c=db.getSiblingDB('+json.dumps(dbname)+').events;\n'
    target=authenticated(dst[2])+'const c=db.getSiblingDB('+json.dumps(other)+').events;\n'
    assert 'denied' in evaluate(src[1],'''let code; try { db.getSiblingDB('test').runCommand({find:'events'}); } catch(e) { code=e.code; } assert.eq(code,13); print('denied');''')
    assert 'wrong denied' in evaluate(src[1],'''let rejected=false; try { db.getSiblingDB('admin').auth('paneladmin','bad-fixture-password'); } catch(e) { rejected=e.code===18 || e.codeName==='AuthenticationFailed'; } assert(rejected); print('wrong denied');''')
    assert 'written' in evaluate(src[1],source+'''assert.eq(db.version(),'8.0.38'); assert.eq(c.createIndex({k:1},{unique:true}),'k_1'); assert(c.insertMany([{k:'retain',v:1},{k:'delete',v:2}]).acknowledged); assert.eq(c.updateOne({k:'retain'},{$set:{v:3}}).modifiedCount,1); assert.eq(c.deleteOne({k:'delete'}).deletedCount,1); assert.eq(c.findOne({k:'retain'}).v,3); print('written');''')
    job(api('/docker/projects/'+src[0]+'/stop',{},202))
    observe(lambda:status(src[0]),lambda row:row.get('state')=='stopped',180)
    try:
        with socket.create_connection(('127.0.0.1',src[1]),timeout=2):
            raise AssertionError('Source port remained reachable after stop')
    except OSError:
        pass
    job(api('/docker/projects/'+src[0]+'/start',{},202))
    observe(lambda:status(src[0]),lambda row:row.get('healthy')==1,220)
    assert unique_container(src[0],pins['image'],src[1])==src[3]
    assert 'existing' in evaluate(src[1],source+'''assert.eq(c.findOne({k:'retain'}).v,3); assert.eq(c.getIndexes().filter(x=>x.name==='k_1').length,1); print('existing');''')

    dump=tool(src[3]['id'],'mongodump',['--gzip','--archive','--db='+dbname],src[2])
    assert dump.returncode==0 and 50<len(dump.stdout)<1<<20 and dump.stdout[:2]==b'\x1f\x8b','mongodump did not export the test database'
    opts=['--gzip','--archive','--nsInclude='+dbname+'.*','--nsFrom='+dbname+'.*','--nsTo='+other+'.*','--stopOnError']
    restored=tool(dst[3]['id'],'mongorestore',opts,dst[2],dump.stdout)
    assert restored.returncode==0,'mongorestore did not restore the scoped database'
    assert 'restored' in evaluate(dst[1],target+'''assert.eq(db.version(),'8.0.38'); assert.eq(c.countDocuments(),1); assert.eq(c.findOne({k:'retain'}).v,3); assert.eq(c.getIndexes().filter(x=>x.name==='k_1'&&x.unique).length,1); print('restored');''')
    assert unique_container(src[0],pins['image'],src[1])==src[3] and unique_container(dst[0],pins['image'],dst[1])==dst[3]
    item,receipt=store_entry(api('/app-registry'))
    assert item==pins['application'] and receipt['installed'] and receipt['healthy']
    assert len(receipt['instances'])==2 and all(v['version']==item['version'] and v['version_source']=='application-receipt' for v in receipt['instances'])
    report.update(ok=True,version=item['version'],source_inputs_sha256=pins['source_inputs_sha256'],
                  signed_cache_business_acceptance=True,independent_github_signed_catalogue=pins['qa_head'],
                  actual_database_version='8.0.38',authenticated_crud_and_unique_index=True,restart_persistence=True,
                  scoped_archive_restored_into_independent_volume=True,source_container_and_volume_preserved=True,
                  wrong_password_and_anonymous_rejected=True,backup_sha256=hashlib.sha256(dump.stdout).hexdigest())
except BaseException:
    report['failure']=traceback.format_exc()
finally:
    save('result',report)
    print(json.dumps(report),flush=True)
sys.exit(0 if report['ok'] else 1)
