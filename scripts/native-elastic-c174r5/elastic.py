"""Create and restore an actual signed Elasticsearch index snapshot in a QA guest."""
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
assert arch==plan['architecture'] and 'VERSION_ID="26.04"' in Path('/etc/os-release').read_text()
assert Path('/etc/hostname').read_text().strip()==plan['OS_case']['hostname']
assert not Path('/opt/panel').exists() and not Path('/var/lib/panel').exists()
base=Path('/opt/panel-elastic-c174-qa-'+secrets.token_hex(16))
base.mkdir(mode=0o700)
private=base/'verified'
private.mkdir(mode=0o700)
out=base/'evidence'
out.mkdir(mode=0o700)
def sha(path):
    return hashlib.file_digest(path.open('rb'),'sha256').hexdigest()
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
elastic=urllib.request.build_opener(urllib.request.ProxyHandler({}))
panel_origin='http://127.0.0.1:19100'
search_origin='http://127.0.0.1:26579'
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
    assert status is None or code==status,(req.get_method(),url,code,status)
    return code,json.loads(raw)
def search(path,status=200,password=None,body=None,method=None):
    extra={'Content-Type':'application/json'}
    if password:
        extra['Authorization']='Basic '+base64.b64encode(('elastic:'+password).encode()).decode()
    return request(elastic,search_origin+path,body,status,extra,method)[1]
def job(accepted):
    job_id,project=accepted['job_id'],accepted['project_id']
    def observed():
        code,item=api('/docker/job-observations/'+job_id,status=None)
        if code==409:return {'state':'unknown'}
        assert code==200 and item['job_id']==job_id and item['project_id']==project
        return item
    reply=wait(observed,lambda v:v['state'] in ('succeeded','failed'),900)
    keep('original-job-'+job_id,reply)
    assert reply['state']=='succeeded' and not reply.get('error')
    return project
def snapshot(path,body,status):
    return api('/docker/projects/'+project+'/elasticsearch-snapshots/'+path,body,status)[1]
def docker(*args):
    return subprocess.check_output(['/usr/bin/docker',*args],timeout=45)
def volume():
    cid,=docker('ps','-aq','--filter','label=com.docker.compose.project=panel_'+project[:12]).decode().splitlines()
    row,=json.loads(docker('inspect',cid))
    assert row['Config']['Image']==plan['image'] and not row['HostConfig']['Privileged']
    assert row['HostConfig']['PortBindings']=={'9200/tcp':[{'HostIp':'127.0.0.1','HostPort':'26579'}]}
    ident,=json.loads(docker('image','inspect',row['Image']))
    assert ident['Architecture']==arch
    result={}
    for m in row['Mounts']:
        assert m['Type']=='volume' and m['Driver']=='local'
        p=Path(m['Source']);st=p.lstat()
        result[m['Destination']]={'volume':m['Name'],'device':st.st_dev,'inode':st.st_ino}
    assert set(result)=={'/usr/share/elasticsearch/data','/usr/share/elasticsearch/logs'}
    assert result['/usr/share/elasticsearch/data']!=result['/usr/share/elasticsearch/logs']
    return {'id':cid,'volumes':result}
report={'ok':False,'architecture':arch,'platform':'ubuntu-26.04','base':str(base),'Main_changed':False,'all50_commercial':False}
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
    assert sha(private/'elastic.manifest.json')==item['sha256']
    cache=Path('/var/lib/panel/app-registry')
    stage(cache/'catalog'/'catalog-v1.bundle.json',private/'catalogue.bundle.json')
    stage(cache/'packages'/'elasticsearch'/item['version']/'manifest.json',private/'elastic.manifest.json')
    assert bundle['catalog'].encode()==(private/'catalogue.json').read_bytes()
    engine_item,=[v for v in json.loads(bundle['catalog'])['apps'] if v['id']=='docker-manager']
    assert sha(private/'docker.manifest.json')==engine_item['sha256']
    stage(cache/'packages'/'docker-manager'/engine_item['version']/'manifest.json',private/'docker.manifest.json')
    shown=api('/app-registry')[1]
    assert len(shown['catalog']['apps'])==50
    assert engine_item==next(r for r in shown['catalog']['apps'] if r['id']=='docker-manager')
    item=engine_item
    docker_job=api('/app-registry/docker-manager/install',{'expected_version':item['version'],'expected_sha256':item['sha256']},202,secrets.token_hex(16))[1]
    engine=wait(lambda:api('/jobs/'+docker_job['job_id'])[1],lambda r:r.get('state') in ('succeeded','failed','needs_attention'),1000)
    keep('docker-manager-original-job',engine)
    assert engine['state']=='succeeded', 'Signed Docker Manager installation did not succeed'

    item=plan['application']
    report['signed_cache_validated']=True
    report['docker_engine_installed_via_store']=True
    shown=api('/app-registry')[1]
    assert item==next(r for r in shown['catalog']['apps'] if r['id']=='elasticsearch')
    state=next(r for r in shown['status'] if r['id']=='elasticsearch')
    assert state['supported'] and not state['installed']
    nonce=secrets.token_hex(6)
    accepted=api('/app-registry/elasticsearch/install',{'expected_version':item['version'],'expected_sha256':item['sha256'],
                 'name':'elastic-c174-'+nonce,'host_port':26579},202,secrets.token_hex(16))[1]
    project=job(accepted)
    def listing():
        return next((r for r in api('/docker/projects')[1]['projects'] if r['id']==project),{})
    wait(listing,lambda r:r.get('healthy')==1 and r.get('state')=='running',540)
    identity=volume()
    fields=api('/docker/projects/'+project+'/credentials',{})[1]['credentials']
    password=fields['ELASTIC_PASSWORD'];fields.clear()
    assert re.fullmatch('[0-9a-f]{64}',password)
    assert search('/',401)['status']==401
    assert search('/',password=password)['version']['number']=='9.1.4'
    index='records-'+nonce
    target='restored-'+index+'-'+secrets.token_hex(16)
    snap='before-update-'+nonce
    document={'serial':nonce,'value':7}
    search('/'+index,password=password,method='PUT',body={'settings':{'number_of_shards':1,'number_of_replicas':0}})
    search('/'+index+'/_doc/1?refresh=wait_for',201,password,document,'PUT')
    create={'index':index,'snapshot':snap,'password':password}
    restore={**create,'restore_index':target}
    assert snapshot('create',{**create,'password':'incorrect'},409)['error']
    assert snapshot('create',{**create,'index':'*'},400)['error']
    accepted=snapshot('create',create,202);assert accepted['state']=='accepted'
    keep('snapshot-submission',accepted)
    actual=wait(lambda:snapshot('status',create,200),lambda r:r['state'] in ('complete','failed'),220)
    assert actual['state']=='complete' and actual['snapshot']==snap
    keep('snapshot-completion',actual)
    assert snapshot('create',create,409)['error']
    search('/'+index+'/_doc/1?refresh=wait_for',200,password,{**document,'value':9},'PUT')
    accepted=snapshot('restore',restore,202);assert accepted['state']=='accepted'
    keep('restore-submission',accepted)
    actual=wait(lambda:snapshot('status',restore,200),lambda r:r['state']=='complete',240)
    assert actual['restore_index']==target
    keep('restore-health',actual)
    assert snapshot('restore',restore,409)['error']
    assert search('/'+target+'/_doc/1',password=password)['_source']==document
    assert search('/'+index+'/_doc/1',password=password)['_source']=={**document,'value':9}
    job(api('/docker/projects/'+project+'/stop',{},202)[1])
    wait(listing,lambda v:v.get('state')=='stopped',120)
    job(api('/docker/projects/'+project+'/start',{},202)[1])
    wait(listing,lambda v:v.get('healthy')==1,300)
    assert volume()==identity
    assert search('/'+target+'/_doc/1',password=password)['_source']==document
    assert snapshot('status',create,200)['state']=='complete'
    receipt=next(v for v in api('/app-registry')[1]['status'] if v['id']=='elasticsearch')
    assert receipt['installed'] and receipt['installed_version']==item['version'] and receipt['version_source']=='application-receipt'
    report.update(ok=True,original_container_and_volumes=identity,actual_version='9.1.4',signed_app_version=item['version'],
                  source_inputs_sha256=plan['source_inputs_sha256'],auth_negative=True,snapshot_and_restore_real=True,
                  original_index_retained=True,original_snapshot_retained_after_restart=True,
                  duplicate_target_and_snapshot_refused=True)
except BaseException:
    report['failure']=traceback.format_exc()
finally:
    keep('result',report)
    print(json.dumps(report),flush=True)
sys.exit(0 if report['ok'] else 1)
