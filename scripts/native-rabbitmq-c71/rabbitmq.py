"""Actual signed RabbitMQ installation and AMQP durability on a disposable host."""
import urllib.parse
import base64,contextlib,hashlib,http.client,http.cookiejar,json,os,pathlib,platform,re,secrets,socket,sqlite3,stat,subprocess,sys,time,traceback,urllib.error,urllib.request
os.umask(0o077)
assert os.geteuid()==0 and len(sys.argv)==3
assert os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('GITHUB_REPOSITORY')=='yunzhanlin/yunzhan-apps'
assert pathlib.Path('/proc/1/comm').read_text().strip()=='systemd'
private=pathlib.Path(sys.argv[1]).resolve(strict=True)
fixture=pathlib.Path(__file__).resolve().parent
cohort=json.loads((fixture/'cohort.json').read_bytes())
runtime=pathlib.Path('/opt/panel/current').resolve(strict=True)
assert runtime==pathlib.Path('/opt/panel/releases')/cohort['version']
assert json.loads((runtime/'SOURCE_INPUTS.json').read_bytes())['inputs_sha256']==cohort['source_inputs_sha256']
wheel=pathlib.Path(sys.argv[2]).resolve(strict=True)
wheel_name='pika-1.3.2-py3-none-any.whl'
assert wheel.name==wheel_name
with os.fdopen(os.open(wheel,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC),'rb')as original:
 st=os.fstat(original.fileno());assert stat.S_ISREG(st.st_mode)and st.st_nlink==1 and 0<st.st_size<=512<<10
 raw=original.read((512<<10)+1)
assert len(raw)==st.st_size and hashlib.sha256(raw).hexdigest()=='0779a7c1fafd805672796085560d290213a465e4f6f76a6fb19e378d8041a14f'
protected=pathlib.Path('/var/lib/c71-pika-original-'+secrets.token_hex(16));protected.mkdir(mode=0o700)
local=protected/wheel_name
with local.open('xb')as f:f.write(raw);f.flush();os.fsync(f.fileno())
sys.path.insert(0,str(local))
import pika
assert pika.__version__=='1.3.2'and pika.__file__.startswith(str(local)+'/')
arch={'x86_64':'amd64','aarch64':'arm64'}[platform.machine()]
work=private/'business-phase1';work.mkdir(mode=0o700)
def save(name,value):
 assert re.fullmatch('[a-zA-Z0-9._-]+',name)
 with(work/name).open('x')as f:json.dump(value,f,indent=2,sort_keys=True);f.write('\n');f.flush();os.fsync(f.fileno())
def run(args,timeout=25):
 r=subprocess.run(args,stdin=subprocess.DEVNULL,capture_output=True,timeout=timeout)
 assert r.returncode==0,(args[0],r.returncode)
 assert len(r.stdout)<=8<<20
 return r.stdout
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*args,**kwargs):raise AssertionError('Unexpected HTTP redirect')
client=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect(),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
origin='http://127.0.0.1:19100';csrf='';pw='';events=[]
app='rabbitmq';candidate=cohort['application'];assert candidate['id']==app and candidate['version']=='4.1-compat1'
image=cohort['image'];assert image.startswith('rabbitmq:4.1.4-management-alpine@sha256:')
management,amqp=26571,26572;project='';username=''
proof={'ok':False,'architecture':arch,'source_inputs_sha256':cohort['source_inputs_sha256'],'panel_app_version':candidate['version'],'native_install_POSTs':0,'test_project_stop_POSTs':0,'test_project_start_POSTs':0,'docker_engine_fresh_install_qualified':False,'browser_UI_qualified':False,'all50_commercial':False,'Main_changed':False}
def api(label,path,body=None,expected=200,key=None,private_response=False,record=True):
 headers={'Origin':origin,'Content-Type':'application/json','X-CSRF-Token':csrf}
 if key:headers['Idempotency-Key']=key
 if body is not None and record:
  stored={'private_existing_first_login':True}if path=='/login'else body
  save(label+'-intent.json',{'path':path,'body':stored,'idempotency_key':key,'maximum_POSTs':1})
 req=urllib.request.Request(origin+'/api'+path,None if body is None else json.dumps(body,separators=(',',':')).encode(),headers=headers)
 try:
  with client.open(req,timeout=85)as r:status=r.status;raw=r.read((8<<20)+1);headers=dict(r.headers.items())
 except urllib.error.HTTPError as e:status=e.code;raw=e.read((8<<20)+1);headers=dict(e.headers.items())
 assert len(raw)<=8<<20
 value=json.loads(raw)
 if pw and not private_response:assert pw.encode()not in raw
 events.append({'path':path,'status':status,'at':time.time(),'method':'GET'if body is None else'POST'})
 if record:
  stored={'csrf_issued':bool(value.get('csrf'))}if path=='/login'else value
  if private_response and path!='/login':
   credentials=value.get('credentials',{})
   stored={k:v for k,v in value.items()if k!='credentials'}
   stored['credential_field_names']=sorted(credentials)
   stored['Cache-Control']=headers.get('Cache-Control')
  save(label+'-response.json',{'status':status,'value':stored})
 assert status==expected,(label,path,status)
 return value,headers
def poll(label,seconds,call,predicate):
 deadline=time.monotonic()+seconds;states=[]
 while True:
  value=call();states.append({'at':time.time(),'value':value})
  if predicate(value):
   save(label+'-observations.json',states);return value
  if time.monotonic()>=deadline:
   save(label+'-timed-out-observations.json',states);raise AssertionError(label+' original observation did not reach its terminal state')
  time.sleep(2)
def job(label,accepted):
 rid=accepted['job_id'];assert re.fullmatch('[0-9a-f]{32}',rid) and accepted['project_id']==project and accepted['kind']=='compose'
 value=poll(label,640,lambda:api(label,'/docker/jobs/'+rid,record=False)[0],lambda v:v['state']in('failed','succeeded'))
 assert value['id' if 'id'in value and 'job_id'not in value else'job_id']==rid and value['project_id']==project and value['kind']=='compose'and value['state']=='succeeded' and not value.get('error')
 return value
def application(label,expected_installed,expected_healthy):
 catalog,_=api(label,'/app-registry?refresh=1')
 assert catalog['source']['resolved_commit']==cohort['served_head']
 assert catalog['host']=={'platform':'ubuntu-24.04','architecture':arch} and len(catalog['catalog']['apps'])==50 and not catalog['source']['stale']
 item=next(v for v in catalog['catalog']['apps']if v['id']==app)
 for k in('id','version','sha256','provider','target'):assert item[k]==candidate[k]
 status=next(v for v in catalog['status']if v['id']==app)
 assert status['state_known'] and status['installed'] is expected_installed and status['healthy'] is expected_healthy
 if expected_installed:
  assert status['installed_version']==candidate['version'] and status['version_source']=='application-receipt' and not status['update_available']
  assert len(status['instances'])==1 and status['instances'][0]['id']==project
 return status
def project_view():
 value=api('observe-projects','/docker/projects',record=False)[0]
 found=[v for v in value['projects']if v['id']==project]
 assert len(found)==1 and found[0]['template_id']==app
 return found[0]
def observed_container(label,expected_running):
 engine='panel_'+project[:12];ids=run(['/usr/bin/docker','ps','-aq','--filter','label=com.docker.compose.project='+engine]).decode().splitlines()
 assert len(ids)==1 and re.fullmatch('[0-9a-f]{12,64}',ids[0])
 v,=json.loads(run(['/usr/bin/docker','inspect',ids[0]]))
 assert v['Config']['Image']==image and v['Config']['Labels']['com.docker.compose.service']=='rabbitmq'and v['State']['Running'] is expected_running
 assert v['HostConfig']['Privileged'] is False and v['HostConfig']['Memory']==512<<20
 assert v['HostConfig']['PortBindings']=={'15672/tcp':[{'HostIp':'127.0.0.1','HostPort':str(management)}],'5672/tcp':[{'HostIp':'127.0.0.1','HostPort':str(amqp)}]}
 if expected_running:assert v['State']['Health']['Status']=='healthy'
 else:assert v['State']['Pid']==0
 image_meta,=json.loads(run(['/usr/bin/docker','image','inspect',v['Image']]))
 assert image_meta['Architecture']==arch and image_meta['Os']=='linux' and any(d.endswith('@'+image.split('@')[1])for d in image_meta['RepoDigests'])
 volumes=[m for m in v['Mounts']if m['Destination']=='/var/lib/rabbitmq']
 assert len(volumes)==1 and volumes[0]['Type']=='volume'and volumes[0]['RW']
 volume=volumes[0];st=pathlib.Path(volume['Source']).lstat();assert stat.S_ISDIR(st.st_mode)
 state={'id':v['Id'],'image_id':v['Image'],'image':image,'architecture':arch,'process_id':v['State']['Pid'],'running':expected_running,'ports':v['HostConfig']['PortBindings'],'volume':{'name':volume['Name'],'source':volume['Source'],'device':st.st_dev,'inode':st.st_ino}}
 save(label+'.json',state);return state
def management_get(path,credential=None):
 conn=http.client.HTTPConnection('127.0.0.1',management,timeout=8)
 with contextlib.closing(conn):
  headers={'Accept':'application/json'}
  if credential:headers['Authorization']='Basic '+base64.b64encode(':'.join(credential).encode()).decode('ascii')
  conn.request('GET',path,headers=headers);r=conn.getresponse();body=r.read((1<<20)+1);assert len(body)<=1<<20
  return r.status,body
def amqp_connect(password):
 return pika.BlockingConnection(pika.ConnectionParameters(host='127.0.0.1',port=amqp,virtual_host='/',credentials=pika.PlainCredentials(username,password),connection_attempts=1,socket_timeout=5,stack_timeout=10,blocked_connection_timeout=10,heartbeat=10))
try:
 assert run(['/usr/bin/systemctl','is-active','docker.service']).strip()==b'active'
 versions=run(['/usr/bin/docker','version','--format','{{.Server.Version}}']).decode().strip()
 save('original-ephemeral-engine-observation.json',{'actual_server_version':versions,'compose_version':run(['/usr/bin/docker','compose','version','--short']).decode().strip(),'preexisting_engine_unchanged':True,'Docker_Manager_fresh_install_qualified':False})
 for port in (management,amqp):assert not run(['/usr/bin/ss','-H','-ltn','sport = :'+str(port)]).strip()
 access_file=pathlib.Path('/etc/panel/first-login.json');st=access_file.lstat()
 assert st.st_uid==0 and st.st_nlink==1 and stat.S_ISREG(st.st_mode)and stat.S_IMODE(st.st_mode)==0o600
 access=json.loads(access_file.read_bytes())
 try:csrf=api('original-login','/login',{k:access[k]for k in('username','password')},private_response=True)[0]['csrf']
 finally:access.clear()
 application('original-signed-before-install',False,False)
 key=secrets.token_hex(16);name='owned-c71-rabbit-'+key[:8]
 proof['native_install_POSTs']+=1
 accepted,_=api('one-signed-rabbitmq-install','/app-registry/rabbitmq/install',{'expected_version':candidate['version'],'expected_sha256':candidate['sha256'],'host_port':management,'name':name},202,key)
 project=accepted['project_id'];assert re.fullmatch('[a-f0-9]{32}',project)
 job('original-install',accepted)
 poll('actual-project-first-healthy',380,project_view,lambda v:v['state']=='running'and v['healthy']==v['running']==v['services']==1)
 first=observed_container('original-healthy-container',True)
 application('original-signed-installed-healthy',True,True)
 credentials,headers=api('one-read-generated-credentials','/docker/projects/'+project+'/credentials',{},private_response=True)
 assert credentials['project_id']==project and credentials['host_port']==management and credentials['template_id']==app and headers['Cache-Control']=='no-store'
 username=credentials['credentials']['RABBITMQ_DEFAULT_USER'];pw=credentials['credentials']['RABBITMQ_DEFAULT_PASS']
 assert username=='paneladmin'and len(pw)>=24
 for path in ('/api/whoami','/api/health/checks/alarms','/api/health/checks/ready-to-serve-clients','/api/overview'):
  status,body=management_get(path,(username,pw));assert status==200,path
  data=json.loads(body);assert pw.encode()not in body
  if path.endswith('/whoami'):assert data['name']==username
  if path.endswith('/overview'):assert data['rabbitmq_version']=='4.1.4'
  save('actual-management-'+path.rsplit('/',1)[1]+'.json',{'status':status,'reply_sha256':hashlib.sha256(body).hexdigest(),'actual_rabbitmq_version':data.get('rabbitmq_version')})
 assert management_get('/api/whoami')[0]==401 and management_get('/api/whoami',(username,secrets.token_urlsafe(30)))[0]==401
 try:
  wrong=amqp_connect(secrets.token_urlsafe(30))
 except (pika.exceptions.ProbableAuthenticationError,pika.exceptions.AuthenticationError):pass
 else:wrong.close();raise AssertionError('Original AMQP port accepted wrong authentication')
 queue='yunzhan.c164.'+key[:12];payload=secrets.token_bytes(1024);digest=hashlib.sha256(payload).hexdigest()
 route='/docker/projects/'+project+'/rabbitmq-queues'
 empty,headers=api('queues-original-empty',route+'?vhost=%2F')
 assert headers['Cache-Control']=='no-store' and empty['queues']==[] and empty['project_id']==project
 assert empty['virtual_host']=='/' and '/' in empty['virtual_hosts'] and empty['observed_at']
 other='运营/队列'
 run(['/usr/bin/docker','exec','--user','rabbitmq','--env','HOME=/var/lib/rabbitmq',first['id'],
      'rabbitmqctl','--quiet','add_vhost',other],60)
 run(['/usr/bin/docker','exec','--user','rabbitmq','--env','HOME=/var/lib/rabbitmq',first['id'],
      'rabbitmqctl','--quiet','set_permissions','--vhost='+other,username,'.*','.*','.*'],60)
 alternate_url=route+'?'+urllib.parse.urlencode({'vhost':other})
 alternate,headers=api('queues-other-vhost',alternate_url)
 assert alternate['project_id']==project and alternate['virtual_host']==other and alternate['queues']==[]
 assert set(alternate['virtual_hosts'])=={'/',other} and headers['Cache-Control']=='no-store'
 api('queues-foreign-project','/docker/projects/'+'0'*32+'/rabbitmq-queues',expected=409)
 api('queues-duplicate-vhost',route+'?vhost=%2F&vhost=other',expected=400)
 def queue_count(label,ready,unacked):
  observed,headers=api(label,route+'?vhost=%2F')
  assert headers['Cache-Control']=='no-store' and observed['project_id']==project and observed['virtual_host']=='/'
  row,=[row for row in observed['queues'] if row['name']==queue]
  assert row['type']=='classic' and row['durable'] is True
  assert (row['messages_ready'],row['messages_unacknowledged'],row['consumers'])==(ready,unacked,0)
  assert set(row)=={'name','type','state','durable','messages_ready','messages_unacknowledged','consumers'}
  return observed

 conn=amqp_connect(pw)
 try:
  ch=conn.channel();ch.queue_declare(queue=queue,durable=True,auto_delete=False,exclusive=False);ch.confirm_delivery()
  for i in range(2):ch.basic_publish('',queue,payload,pika.BasicProperties(delivery_mode=2,content_type='application/octet-stream',message_id=key+'-'+str(i)),mandatory=True)
  queue_count('queues-before-delivery',2,0)
  method,props,got=ch.basic_get(queue,auto_ack=False)
  assert got==payload and props.delivery_mode==2 and props.message_id==key+'-0'
  queue_count('queues-unacknowledged',1,1)
  ch.basic_ack(method.delivery_tag)
  assert ch.queue_declare(queue=queue,passive=True).method.message_count==1
 finally:conn.close()
 save('first-AMQP-acknowledged-and-durable-pending.json',{'actual_messages_confirmed':2,'first_acked':True,'original_payload_sha256':digest,'remaining':1,'wrong_management_and_AMQP_password_refused':True})
 proof['test_project_stop_POSTs']+=1
 accepted=api('one-owned-project-stop','/docker/projects/'+project+'/stop',{},202)[0];job('original-stop',accepted)
 stopped=observed_container('original-stopped-container-data-volume',False)
 assert stopped['id']==first['id'] and stopped['volume']==first['volume']
 application('original-signed-installed-stopped',True,False)
 api('queues-refuse-stopped-broker',route,expected=409)
 try:
  with socket.create_connection(('127.0.0.1',amqp),timeout=2):raise AssertionError('Stopped owned service still accepted a connection')
 except OSError:pass
 proof['test_project_start_POSTs']+=1
 accepted=api('one-owned-project-start','/docker/projects/'+project+'/start',{},202)[0];job('original-start',accepted)
 poll('actual-project-started-healthy',380,project_view,lambda v:v['state']=='running'and v['healthy']==v['running']==v['services']==1)
 started=observed_container('restarted-healthy-same-original-volume',True)
 assert started['volume']==first['volume']and started['image_id']==first['image_id']and started['process_id']!=first['process_id']
 queue_count('queues-original-backlog-after-start',1,0)
 conn=amqp_connect(pw)
 try:
  ch=conn.channel();assert ch.queue_declare(queue=queue,passive=True).method.message_count==1
  method,props,got=ch.basic_get(queue,auto_ack=False)
  assert props.delivery_mode==2 and props.message_id==key+'-1'and got==payload and hashlib.sha256(got).hexdigest()==digest
  ch.basic_ack(method.delivery_tag);assert ch.queue_declare(queue=queue,passive=True).method.message_count==0
 finally:conn.close()
 queue_count('queues-zero-after-ack',0,0)
 application('original-signed-installed-healthy-after-restart',True,True)
 with contextlib.closing(sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True))as db:
  db.execute('PRAGMA query_only=ON')
  receipts=db.execute('SELECT app_id,scope,version,sha256,target FROM app_registry_receipts WHERE app_id=?',(app,)).fetchall()
  assert receipts==[(app,project,candidate['version'],candidate['sha256'],app)]
  original=db.execute('SELECT app_id,scope,version,sha256,target FROM app_registry_install_requests WHERE idempotency_key=?',(key,)).fetchall();assert original==receipts
 save('original-AMQP-post-restart-and-signed-receipt.json',{'actual_retained_payload_sha256':digest,'actual_delivery_acknowledged':True,'actual_remaining':0,'same_original_volume':started['volume'],'receipts':receipts,'original_volume_removed':False})
 save('chrome-fixture.json',{'id':project,'name':name,'queue':queue,'alternate_vhost':other,'expected_ready':0})
 proof.update(ok=True,original_project_id=project,exact_signed_package_install=True,actual_management_credentials_and_readiness=True,wrong_management_and_AMQP_credentials_refused=True,actual_AMQP_publisher_confirms_ack_and_persistence=True,same_original_data_volume_and_pinned_image=True,store_healthy_stopped_then_healthy=True,preexisting_Docker_engine_preserved=True,actual_queue_workspace_observed=True)
except BaseException:
 failure=traceback.format_exc()
 if pw:failure=failure.replace(pw,'[generated test credential redacted]')
 proof['failure']=failure
finally:
 if csrf:
  try:api('original-logout','/logout',{})
  except BaseException:proof['logout_unconfirmed']=True;proof['ok']=False
 save('original-http-events.json',events);save('original-proof.json',proof)
 print(json.dumps({'ok':proof['ok'],'architecture':arch,'native_install_POSTs':proof['native_install_POSTs'],'Main_changed':False}),flush=True)
sys.exit(0 if proof['ok']else 1)
