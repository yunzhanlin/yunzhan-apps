"""Actual current signed Docker CRUD and persistent data on owned disposable native CI."""
import contextlib,hashlib,http.cookiejar,json,os,platform,re,secrets,subprocess,sys,time,urllib.error,urllib.request
from pathlib import Path
os.umask(0o077)
assert os.geteuid()==0 and os.environ.get('GITHUB_ACTIONS')=='true'and os.environ.get('GITHUB_REPOSITORY')=='yunzhanlin/yunzhan-apps'
evidence=Path(sys.argv[1]);out=evidence/'business-phase1';out.mkdir(mode=0o700)
plan=json.loads((Path(__file__).resolve().parent/'cohort.json').read_bytes());arch={'x86_64':'amd64','aarch64':'arm64'}[platform.machine()]
assert json.loads(Path('/opt/panel/current/SOURCE_INPUTS.json').read_bytes())['inputs_sha256']==plan['source_inputs_sha256']
origin='http://127.0.0.1:19100';csrf=''
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*args,**kwargs):raise AssertionError('Unexpected local redirect')
client=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect(),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
def save(name,value):
 with(out/(name+'.json')).open('x')as f:json.dump(value,f,indent=2);f.write('\n')
request_count=0
def api(path,data=None,expected=200,method=None):
 global request_count
 headers={'Origin':origin,'Content-Type':'application/json','X-CSRF-Token':csrf}
 if data is not None:headers['Idempotency-Key']=secrets.token_hex(16)
 body=None if data is None else json.dumps(data).encode()
 actual_method=method or ('POST'if data is not None else 'GET')
 label=None
 if actual_method!='GET':
  request_count+=1;label='api-'+str(request_count).zfill(4)
  save(label+'-intent',{'path':path,'method':actual_method,'body_sha256':hashlib.sha256(body or b'').hexdigest(),'idempotency_key':headers.get('Idempotency-Key'),'maximum_submissions':1})
 try:
  with client.open(urllib.request.Request(origin+'/api'+path,body,headers,method=actual_method),timeout=65)as response:
   status=response.status;raw=response.read((8<<20)+1)
 except urllib.error.HTTPError as error:
  status=error.code;raw=error.read((8<<20)+1)
 assert len(raw)<=8<<20
 if label:save(label+'-outcome',{'status':status,'response_bytes':len(raw),'response_sha256':hashlib.sha256(raw).hexdigest(),'response':json.loads(raw)if raw else{}})
 assert status==expected,(path,status,expected,raw[:8192].decode(errors='replace'))
 return json.loads(raw)if raw else{}
def wait(read,valid,limit=600):
 end=time.monotonic()+limit
 while time.monotonic()<end:
  value=read()
  if valid(value):return value
  time.sleep(1)
 raise TimeoutError('Actual native result did not settle')
def job(label,route,payload,kind='module'):
 save(label+'-request',{'path':route,'payload':payload,'maximum_posts':1});answer=api(route,payload,202);id=answer['job_id'];assert re.fullmatch('[a-f0-9]{32}',id)
 path=('/jobs/'if kind=='module'else'/docker/job-observations/')+id
 row=wait(lambda:api(path),lambda x:x['state']in('succeeded','failed','needs_attention'),2400);save(label+'-outcome',row);assert row['state']=='succeeded',(label,row);return answer,row

def docker(*args):return subprocess.check_output(['/usr/bin/docker',*args],text=True,timeout=40).strip()
def inspect(id):return json.loads(docker('inspect',id))[0]
def native_id(id):
 r=inspect(id);return{'id':r['Id'],'started_at':r['State']['StartedAt'],'pid':r['State']['Pid'],'image':r['Image'],'mounts':r['Mounts']}
def daemon():return subprocess.check_output(['/usr/bin/systemctl','show','docker.service','--property=MainPID,InvocationID,ExecMainStartTimestampMonotonic'],text=True).strip()
def project(id):return next((x for x in api('/docker/projects')['projects']if x['id']==id),None)
def http(port,path='/'):
 with urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect()).open('http://127.0.0.1:'+str(port)+path,timeout=5)as r:assert r.status==200;return r.read(1<<20)
proof={'ok':False,'architecture':arch,'source_inputs_sha256':plan['source_inputs_sha256'],'Main_changed':False,'all40_commercial':False,'scope':'Current signed Docker 1-compat2 native network and volume CRUD, data preservation, container and Compose lifecycle; not a blanket commercial qualification'}
try:
 login=json.loads(Path('/etc/panel/first-login.json').read_bytes());csrf=api('/login',{k:login[k]for k in('username','password')})['csrf'];login.clear()
 data=api('/app-registry?refresh=1');assert data['source']['resolved_commit']==plan['served_head']and not data['source']['stale']and len(data['catalog']['apps'])==40
 item,=[a for a in data['catalog']['apps']if a['id']=='docker-manager'];assert item==plan['items']['docker-manager']
 status,=[a for a in data['status']if a['id']=='docker-manager'];assert not status['installed']and status['state_known']and status['supported']
 _,installed=job('signed-docker-install','/app-registry/docker-manager/install',{'expected_version':item['version'],'expected_sha256':item['sha256']})
 active=api('/docker');assert active['available']and active['active']and active['version']=='29.8.2'
 templates=api('/docker/templates')['templates'];image,=[x['image']for x in templates if x['id']=='nginx-static'];assert re.fullmatch(r'[a-z0-9./:_-]+@sha256:[a-f0-9]{64}',image)
 job('cold-pinned-image-pull','/docker/jobs',{'action':'pull','image':image},'docker')
 # Independent original objects are seeded by the fixture, never claimed as panel-created resources.
 prior_network=docker('network','create','c291-original-network');docker('volume','create','c291-original-volume');token='c291-'+secrets.token_hex(16)
 prior=docker('run','-d','--name','c291-original-container','--network',prior_network,'-v','c291-original-volume:/data',image,'/bin/sh','-c','printf %s '+token+' > /data/token; exec sleep 3600')
 wait(lambda:docker('exec',prior,'cat','/data/token'),lambda x:x==token)
 original=native_id(prior);original_daemon=daemon();save('original-resource-identities',{'container':original,'daemon':original_daemon,'network':prior_network,'volume':json.loads(docker('volume','inspect','c291-original-volume')),'token_sha256':hashlib.sha256(token.encode()).hexdigest()})
 denied=api('/docker/networks/'+prior_network,{'confirm_name':'c291-original-network'},409,'DELETE');assert denied['error']
 denied=api('/docker/volumes/c291-original-volume',{'confirm_name':'c291-original-volume'},409,'DELETE');assert denied['error'];save('foreign-resource-delete-refusals',{'network':True,'volume':True})
 # Actual isolated bridge and local volume, verified independently in Docker Engine.
 network=api('/docker/networks',{'name':'c291-managed-network','internal':True},201);nid=network['Id'];assert re.fullmatch('[a-f0-9]{64}',nid)
 nr=json.loads(docker('network','inspect',nid))[0];assert nr['Internal']and nr['Driver']=='bridge'and nr['Labels']['com.yunzhan.panel.kind']=='network'
 volume=api('/docker/volumes',{'name':'c291-managed-volume'},201);assert volume['Name']=='c291-managed-volume'
 vr=json.loads(docker('volume','inspect','c291-managed-volume'))[0];assert vr['Driver']=='local'and vr['Labels']['com.yunzhan.panel.kind']=='volume'
 assert any(x['Id']==nid for x in api('/docker/networks')['networks']);assert any(x['Name']=='c291-managed-volume'for x in api('/docker/volumes')['volumes'])
 helper=docker('run','-d','--name','c291-managed-attacher','--network',nid,'-v','c291-managed-volume:/data',image,'/bin/sh','-c','printf %s '+token+' > /data/token; exec sleep 3600');wait(lambda:docker('exec',helper,'cat','/data/token'),lambda x:x==token)
 assert api('/docker/networks/'+nid,{'confirm_name':'wrong-name'},409,'DELETE')['error']
 assert api('/docker/volumes/c291-managed-volume',{'confirm_name':'wrong-name'},409,'DELETE')['error']
 assert api('/docker/networks/'+nid,{'confirm_name':'c291-managed-network'},409,'DELETE')['error']
 assert api('/docker/volumes/c291-managed-volume',{'confirm_name':'c291-managed-volume'},409,'DELETE')['error']
 assert docker('exec',helper,'cat','/data/token')==token;docker('stop',helper);docker('rm',helper)
 readback=docker('run','--rm','--network','none','-v','c291-managed-volume:/data:ro',image,'cat','/data/token');assert readback==token;save('actual-managed-data-readback',{'token_sha256':hashlib.sha256(readback.encode()).hexdigest(),'busy_and_wrong_confirmation_refused':True})
 api('/docker/volumes/c291-managed-volume',{'confirm_name':'c291-managed-volume'},200,'DELETE');api('/docker/networks/'+nid,{'confirm_name':'c291-managed-network'},200,'DELETE')
 assert not any(x['Name']=='c291-managed-volume'for x in api('/docker/volumes')['volumes']);assert not any(x['Id']==nid for x in api('/docker/networks')['networks'])
 # Rejected requests use ordinary Core/Root validation and must create no engine objects.
 original_objects={k:docker(*args)for k,args in{'containers':('ps','-aq'),'volumes':('volume','ls','-q'),'networks':('network','ls','-q')}.items()}
 saved_csrf=csrf;csrf=''
 assert api('/docker/networks',{'name':'c291-no-csrf','internal':True},403)['error'];csrf=saved_csrf
 refusals=[]
 cases=[('privileged','    privileged: true\n'),('host-network','    network_mode: host\n'),('host-bind','    volumes: ["/:/host:ro"]\n'),('public-binding','    ports: ["0.0.0.0:18227:80"]\n'),('build','    build: .\n')]
 for label,option in cases:
  compose='services:\n  web:\n    image: '+image+'\n'+option
  answer=api('/docker/projects',{'name':'c291-refuse-'+label,'template_id':'','host_port':0,'compose':compose},202)
  failed=wait(lambda:api('/docker/job-observations/'+answer['job_id']),lambda x:x['state']in('succeeded','failed','needs_attention'))
  save('actual-refused-'+label,{'submitted':answer,'outcome':failed});assert failed['state']=='failed'and failed.get('error'),(label,failed)
  assert not docker('ps','-aq','--filter','label=com.docker.compose.project=panel_'+answer['project_id'][:12]);refusals.append(label)
 assert original_objects=={k:docker(*args)for k,args in{'containers':('ps','-aq'),'volumes':('volume','ls','-q'),'networks':('network','ls','-q')}.items()}
 save('actual-privilege-and-path-refusals',{'cases':refusals,'missing_csrf_refused':True,'all_original_engine_object_sets_unchanged':True})
 # Container creation, logs, actual pause state and stable process, stop/start/restart and exact confirmation.
 _,created=job('api-container-create','/docker/jobs',{'action':'create','image':image,'name':'c291-managed-container','restart':'no','command':['/bin/sh','-c','echo c291-native-log; exec sleep 3600']},'docker');cid=created['container_id'];assert re.fullmatch('[a-f0-9]{64}',cid)
 wait(lambda:inspect(cid)['State']['Running'],bool);before=native_id(cid)
 sample=api('/docker/containers/'+cid+'/stats');assert sample['id']==cid and sample['observed_at'] and isinstance(sample['memory_bytes'],int)and sample['memory_bytes']>=0 and sample['memory_limit_bytes']>0 and sample['pids']>=1;save('actual-container-resource-sample',sample)
 api('/docker/containers/'+cid+'/pause',{});assert inspect(cid)['State']['Paused'];assert native_id(cid)==before
 api('/docker/containers/'+cid+'/unpause',{});assert not inspect(cid)['State']['Paused'];assert native_id(cid)==before
 for action in ['stop','start','restart']:
  api('/docker/containers/'+cid+'/'+action,{});wait(lambda:inspect(cid)['State']['Running'],lambda x:x is(action!='stop'))
 assert 'c291-native-log'in json.dumps(api('/docker/containers/'+cid+'/logs'))
 assert api('/docker/containers/'+cid,{'confirm_id':'000000000000'},409,'DELETE')['error']
 api('/docker/containers/'+cid+'/stop',{});api('/docker/containers/'+cid,{'confirm_id':cid[:12]},200,'DELETE')
 save('actual-container-lifecycle',{'container':cid,'create_logs_pause_unpause_stop_start_restart_delete':True,'paused_original_process_preserved':True})
 # Compose lifecycle preserves a real named volume, data and original external resource identities.
 answer,_=job('compose-create','/docker/projects',{'name':'c291-persistent-web','template_id':'nginx-static','host_port':18226,'compose':''},'docker');pid=answer['project_id'];pr=wait(lambda:project(pid),lambda x:x and x['state']=='running'and x['healthy']==1);engine=pr['engine_name']
 owned=docker('ps','-q','--filter','label=com.docker.compose.project='+engine);assert owned and '\n'not in owned
 mounts=inspect(owned)['Mounts'];vol,=[m['Name']for m in mounts if m['Type']=='volume'];docker('exec',owned,'/bin/sh','-c','printf %s '+token+' > /usr/share/nginx/html/c291.txt');assert http(18226,'/c291.txt')==token.encode()
 for action in ['stop','start','restart']:
  job('compose-'+action,'/docker/projects/'+pid+'/'+action,{},'docker')
  if action!='stop':wait(lambda:http(18226,'/c291.txt'),lambda b:b==token.encode())
 job('compose-final-stop','/docker/projects/'+pid+'/stop',{},'docker')
 # A stopped project still owns its original volume; generic delete must preserve it.
 assert api('/docker/volumes/'+vol,{'confirm_name':vol},409,'DELETE')['error']
 answer=api('/docker/projects/'+pid,{'confirm_name':'c291-persistent-web'},202,'DELETE');row=wait(lambda:api('/docker/job-observations/'+answer['job_id']),lambda x:x['state']in('succeeded','failed','needs_attention'));save('compose-delete-original-outcome',row);assert row['state']=='succeeded'
 assert docker('run','--rm','--network','none','-v',vol+':/data:ro',image,'cat','/data/c291.txt')==token
 save('actual-compose-volume-retained',{'project':pid,'engine':engine,'volume':vol,'retained_after_project_delete':True,'token_sha256':hashlib.sha256(token.encode()).hexdigest()})
 assert native_id(prior)==original and daemon()==original_daemon and docker('exec',prior,'cat','/data/token')==token
 final=api('/app-registry');last,=[a for a in final['status']if a['id']=='docker-manager'];assert last['installed']and last['installed_version']=='1-compat2'and not last['update_available']
 proof.update(ok=True,app_version=item['version'],installed_job=installed['id'],current_catalogue_head=plan['served_head'],managed_network_and_volume_real_crud=True,actual_persistent_data_readback=True,busy_resources_and_wrong_confirmations_refused=True,original_foreign_resources_and_lifetimes_preserved=True,actual_container_and_compose_lifecycle=True,actual_native_running_container_resource_sample=True,all_mutating_API_intents_and_original_responses_retained=True,stopped_project_data_protected=True,removed_project_named_volume_preserved=True,actual_privilege_path_public_binding_and_csrf_refusals=True)
except BaseException:
 import traceback
 proof['failure']=traceback.format_exc()
finally:
 if csrf:
  with contextlib.suppress(Exception):api('/logout',{})
 save('original-proof',proof)
sys.exit(0 if proof['ok']else 1)
