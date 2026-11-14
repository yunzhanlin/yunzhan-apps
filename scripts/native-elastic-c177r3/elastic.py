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

    # A private synthetic index provides an observable write window. Only the
    # repository's documented rate setting changes, on this dedicated test VM.
    qa_source='interrupt-'+nonce
    qa_failed='during-interrupt-'+nonce
    qa_retry='after-interrupt-'+nonce
    retry_target='restored-'+qa_source+'-'+secrets.token_hex(16)
    search('/'+qa_source,password=password,method='PUT',
           body={'settings':{'number_of_shards':1,'number_of_replicas':0,'refresh_interval':'-1'},
                 'mappings':{'properties':{'payload':{'type':'keyword','index':False,'doc_values':False}}}})
    proof_seed=hashlib.sha256(('elasticsearch-interrupt-'+nonce).encode()).digest()
    corpus={}
    for number in range(72):
        part=hashlib.shake_256(proof_seed+number.to_bytes(4,'big')).digest(36<<10)
        data=base64.b64encode(part).decode()
        corpus[str(number)]=hashlib.sha256(data.encode()).hexdigest()
        search('/'+qa_source+'/_doc/'+str(number),201,password,{'ordinal':number,'payload':data},'PUT')
    search('/'+qa_source+'/_refresh',password=password,method='POST')
    assert search('/'+qa_source+'/_count',password=password)['count']==len(corpus)
    current=search('/_snapshot/yunzhan-local',password=password)['yunzhan-local']
    assert current['type']=='fs' and current['settings']['location']=='/usr/share/elasticsearch/logs/yunzhan-snapshots'
    slow=dict(current['settings'],max_snapshot_bytes_per_sec='16kb')
    assert search('/_snapshot/yunzhan-local?verify=true',password=password,method='PUT',body={'type':'fs','settings':slow})['acknowledged']
    interrupted={'index':qa_source,'snapshot':qa_failed,'password':password}
    fault_submission=snapshot('create',interrupted,202)
    assert fault_submission['state']=='accepted'
    keep('interruption-original-submission',fault_submission)
    def active_snapshot():
        rows=search('/_snapshot/yunzhan-local/'+qa_failed+'/_status',password=password)['snapshots']
        assert len(rows)==1
        return rows[0]
    active=wait(active_snapshot,lambda v:v['state']=='STARTED' and v['shards_stats']['started']>0,55)
    progress=active.get('stats',{})
    assert progress['total']['size_in_bytes']>1<<20
    assert progress['processed']['size_in_bytes']<progress['total']['size_in_bytes']
    keep('interruption-in-progress',{'id':qa_failed,'state':active['state'],'progress':progress})
    container,=docker('ps','-q','--no-trunc','--filter','label=com.docker.compose.project=panel_'+project[:12]).decode().splitlines()
    assert re.fullmatch('[a-f0-9]{64}',container) and container.startswith(identity['id'])
    original,=json.loads(docker('inspect',container))
    first_started=original['State']['StartedAt']
    assert original['State']['Running'] and original['Config']['Image']==plan['image']
    assert docker('kill','--signal=KILL',container).decode().strip()==container
    stopped,=json.loads(docker('inspect',container))
    assert not stopped['State']['Running'] and stopped['State']['ExitCode']==137
    keep('interrupted-process-exit',{'exit':137,'original_container':container,'started_at':first_started})
    assert docker('start',container).decode().strip()==container
    def available_after_interruption():
        try:return authenticated_version()
        except (OSError,urllib.error.URLError):return None
    wait(available_after_interruption,lambda version:version=='9.1.4',200)
    restarted,=json.loads(docker('inspect',container))
    assert restarted['State']['Running'] and restarted['State']['StartedAt']!=first_started
    assert volume()==identity
    # Observe the original identity before any second submission. Both a
    # terminal failure and a useful upstream completion require separate proof.
    def original_after_restart():
        panel=snapshot('status',interrupted,200)
        if panel['state']=='missing':
            missing=search('/_snapshot/yunzhan-local/'+qa_failed,404,password)
            assert missing['error']['type']=='snapshot_missing_exception'
        return panel
    fault=wait(original_after_restart,lambda n:n['state'] in ('failed','complete','missing'),145)
    if fault['state']=='missing':
        observations=[fault]
        for _ in range(5):
            time.sleep(2)
            observations.append(original_after_restart())
        assert all(row['state']=='missing' for row in observations)
        keep('original-missing-confirmed',{'observation_count':len(observations),'state':'missing','native_status':404})
    keep('original-interrupted-outcome',fault)
    assert search('/'+qa_source+'/_count',password=password)['count']==len(corpus)
    assert snapshot('status',create,200)['state']=='complete'
    assert search('/'+target+'/_doc/1',password=password)['_source']==document
    if fault['state']!='missing':
        assert snapshot('create',interrupted,409)['error']
    if fault['state'] in ('failed','missing'):
        failed_restore={**interrupted,'restore_index':'restored-'+qa_source+'-'+secrets.token_hex(16)}
        assert snapshot('restore',failed_restore,409)['error']
        assert search('/'+failed_restore['restore_index'],404,password)['status']==404
    assert search('/_snapshot/yunzhan-local?verify=true',password=password,method='PUT',body=current)['acknowledged']
    following={'index':qa_source,'snapshot':qa_retry,'password':password}
    assert snapshot('create',following,202)['state']=='accepted'
    wait(lambda:snapshot('status',following,200),lambda n:n['state']=='complete',120)
    recovery={**following,'restore_index':retry_target}
    assert snapshot('restore',recovery,202)['state']=='accepted'
    restored=wait(lambda:snapshot('status',recovery,200),lambda n:n['state']=='complete',160)
    keep('recovery-new-operation',restored)
    readiness=search('/'+retry_target+'/_search?allow_partial_search_results=false&size=1&_source=false&track_total_hits=false&terminate_after=1',password=password)
    assert not readiness['timed_out'] and readiness['_shards']['total']==readiness['_shards']['successful']==1
    assert readiness['_shards']['failed']==0,readiness['_shards']
    keep('first-post-completion-search',{'status':200,'shards':readiness['_shards'],'timed_out':readiness['timed_out']})
    assert search('/'+retry_target+'/_count',password=password)['count']==len(corpus)
    for number,witness in corpus.items():
        document_after_restore=search('/'+retry_target+'/_doc/'+number,password=password)['_source']
        assert document_after_restore['ordinal']==int(number)
        assert hashlib.sha256(document_after_restore['payload'].encode()).hexdigest()==witness
    assert search('/'+index+'/_doc/1',password=password)['_source']=={**document,'value':9}
    assert search('/'+qa_source+'/_count',password=password)['count']==len(corpus)
    assert volume()==identity
    report.update(snapshot_interruption_verified=True,first_post_completion_query_succeeded=True,interrupted_original_state=fault['state'],
                  original_container_and_independent_volumes_reused=True,original_snapshot_after_interruption=True,
                  recovered_document_sha256_count=len(corpus))
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
