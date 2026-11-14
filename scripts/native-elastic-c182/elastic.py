"""Validate real snapshot inventory, pagination, scope, and restore in a signed Elasticsearch QA guest."""
import base64
from datetime import datetime, timedelta, timezone
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
    parsed=json.loads(raw)
    error=parsed.get('error','') if isinstance(parsed,dict) else ''
    if isinstance(error,dict):
        error=error.get('type','')
    assert status is None or code==status,(req.get_method(),url,code,status,str(error)[:260])
    return code,parsed
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
    def authenticated_version():
        headers={'Authorization':'Basic '+base64.b64encode(('elastic:'+password).encode()).decode()}
        code,resp=request(elastic,search_origin+'/',None,None,headers,None)
        if code==401:
            return None
        assert code==200,('Unexpected authenticated readiness status',code)
        return resp['version']['number']
    actual_version=wait(authenticated_version,lambda v:v is not None,120)
    assert actual_version=='9.1.4'
    report['valid_credentials_confirmed']=True
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
    def inventory(credentials, cursor='', status=200):
        code, page = api('/docker/projects/'+project+'/elasticsearch-snapshots/inventory',
                         {'password':credentials,'cursor':cursor},status)
        assert code==status
        return page
    missing=inventory(password)
    assert missing=={'project_id':project,'repository_ready':False,'snapshots':[]}
    assert inventory('incorrect',status=409)['error']
    assert inventory(password,'&after=other',400)['error']
    assert search('/_snapshot/yunzhan-local',404,password)['error']['type']=='repository_missing_exception'
    keep('inventory-original-missing-repository',missing)
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
    wait(authenticated_version,lambda v:v=='9.1.4',120)
    assert volume()==identity
    assert search('/'+target+'/_doc/1',password=password)['_source']==document
    assert snapshot('status',create,200)['state']=='complete'

    def policy(action, fields=None, expected=200):
        req={'index':index,'password':password}
        req.update(fields or {})
        return api('/docker/projects/'+project+'/elasticsearch-policies/'+action,req,expected)[1]
    initial=policy('read')
    assert initial=={'project_id':project,'index':index}
    assert policy('read',{'password':'wrong'},409)['error']
    assert policy('read',{'index':'*'},400)['error']
    name='yunzhan-'+hashlib.sha256((project+'/'+index).encode()).hexdigest()[:32]
    endpoint='/_slm/policy/'+name
    assert search(endpoint,404,password)['status']==404
    settings={'daily_time':(datetime.now(timezone.utc)+timedelta(seconds=95)).strftime('%H:%M'),
              'expire_days':30,'min_count':1,'max_count':2}
    invalid={**settings,'min_count':3}
    assert policy('save',{'settings':invalid},400)['error']
    created=policy('save',{'settings':settings})
    assert created['settings']==settings and created['next_execution_millis']>time.time()*1000
    native=search(endpoint,password=password)[name]
    assert native['policy']['config']['indices']==[index]
    assert native['policy']['config']['include_global_state'] is False
    assert native['policy']['retention']=={'expire_after':'30d','min_count':1,'max_count':2}
    assert created['revision']==str(native['version'])+':'+str(native['modified_date_millis'])
    assert policy('save',{'settings':settings,'revision':created['revision']})['revision']==created['revision']
    assert policy('save',{'settings':settings},409)['error']
    assert policy('remove',{'revision':'100:100'},409)['error']
    def completed(policy_snapshot):
        def check():
            try:
                row,=search('/_snapshot/yunzhan-local/'+policy_snapshot,password=password)['snapshots']
            except AssertionError as error:
                if error.args[0][2]==404:
                    return {}
                raise
            return row
        return wait(check,lambda row:row.get('state')=='SUCCESS',155)
    def scheduled():
        return policy('read').get('last_success')
    scheduled_name=wait(scheduled,lambda value:bool(value),170)
    first=completed(scheduled_name)
    assert first['indices']==[index] and first['metadata']['policy']==name
    assert first['metadata']['yunzhan_index']==index and first['metadata']['yunzhan_project']==project
    assert search('/'+index+'/_doc/1',password=password)['_source']['value']==9
    native_names=[scheduled_name]
    for _ in range(2):
        fresh=search(endpoint+'/_execute',password=password,method='PUT')['snapshot_name']
        assert fresh not in native_names
        native_names.append(fresh)
        assert completed(fresh)['indices']==[index]
    assert all(search('/_snapshot/yunzhan-local/'+v,password=password)['snapshots'] for v in native_names)
    search('/_slm/_execute_retention',password=password,method='POST')
    def names_after_retention():
        rows=search('/_snapshot/yunzhan-local/_all',password=password)['snapshots']
        return {row['snapshot'] for row in rows}
    keep('policy-retained-native',{'retained':sorted(wait(names_after_retention,lambda values:
        native_names[0] not in values and set(native_names[1:]+[snap]).issubset(values),160))})
    gone=search('/_snapshot/yunzhan-local/'+native_names[0],404,password)
    assert gone['error']['type']=='snapshot_missing_exception'
    current=policy('read')
    replacement={**settings,'daily_time':'00:01','max_count':3}
    if replacement==settings:
        raise AssertionError('policy edit must change settings')
    new=policy('save',{'revision':current['revision'],'settings':replacement})
    assert new['settings']==replacement and new['revision']!=current['revision']
    assert policy('remove',{'revision':current['revision']},409)['error']
    assert policy('remove',{'revision':new['revision']})==initial
    assert search(endpoint,404,password)['status']==404
    assert set(native_names[1:]+[snap]).issubset(names_after_retention())
    assert search('/'+target+'/_doc/1',password=password)['_source']==document
    assert search('/'+index+'/_doc/1',password=password)['_source']=={**document,'value':9}
    keep('policy-original',{'configured':created,'changed':new,'removed':initial,'native_completed':native_names})
    report.update(ok=True,actual_version='9.1.4',signed_app_version=item['version'],
        source_inputs_sha256=plan['source_inputs_sha256'],snapshot_and_restore_real=True,original_index_retained=True,
        native_policy_schedule=True,native_retention_verified=True,manual_snapshot_preserved=True,
        stale_revision_rejected=True,removed_policy_left_snapshots=True)
except BaseException:
    report['failure']=traceback.format_exc()
finally:
    keep('result',report)
    print(json.dumps(report),flush=True)
sys.exit(0 if report['ok'] else 1)
