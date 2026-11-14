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
app='rabbitmq';candidate=cohort['application'];assert candidate['id']==app and candidate['version']=='4.4.0-compat1'
image=cohort['image44'];assert image.startswith('rabbitmq:4.4.0-management-alpine@sha256:')
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
 if expected is not None:assert status==expected,(label,path,status)
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
 def observe():
  row,_=api(label,'/docker/jobs/'+rid,record=False,expected=None)
  # A queued worker may not have published the first result file yet.
  status=events[-1]['status']
  if status==404:
   return {'state':'waiting-for-original-result'}
  assert status==200 and row['job_id']==rid and row['project_id']==project
  return row
 value=poll(label,640,observe,lambda v:v['state']in('failed','succeeded'))
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
def healthy(label,project_id,template):
 def observe():
  rows=[row for row in api('observe-project','/docker/projects',record=False)[0]['projects'] if row['id']==project_id]
  if not rows:return {'state':'waiting'}
  row,=rows
  assert row['template_id']==template
  return row
 return poll('healthy-'+label,380,observe,lambda row:row['state']=='running' and row.get('healthy')==row.get('running')==1)

def registry(label):
 result,_=api(label,'/app-registry?refresh=1')
 assert result['source']['resolved_commit']==cohort['served_head'] and not result['source']['stale']
 assert len(result['catalog']['apps'])==50
 item,=[row for row in result['catalog']['apps'] if row['id']==app]
 assert item==candidate
 status,=[row for row in result['status'] if row['id']==app]
 assert status['state_known'] and status['supported']
 return status

try:
 assert run(['/usr/bin/systemctl','is-active','docker.service']).strip()==b'active'
 for port in (26561,26562,management,amqp):
  assert not run(['/usr/bin/ss','-H','-ltn','sport = :'+str(port)]).strip()
 access_file=pathlib.Path('/etc/panel/first-login.json')
 assert stat.S_IMODE(access_file.lstat().st_mode)==0o600
 access=json.loads(access_file.read_bytes())
 csrf=api('original-login','/login',{k:access[k] for k in ('username','password')},private_response=True)[0]['csrf']
 access.clear()
 status=registry('served-original-before-install')
 assert not status['installed'] and not status['update_available']
 old_name='legacy-rabbit-'+secrets.token_hex(5)
 old_create,_=api('one-old-template','/docker/projects',{'name':old_name,'template_id':'rabbitmq','host_port':26561},202,secrets.token_hex(16))
 project=old_create['project_id']
 job('old-template-terminal',old_create)
 healthy('original-legacy',project,'rabbitmq')
 original=api('old-volume-before','/docker/projects/'+project+'/rabbitmq-migration-preflight')[0]
 old_project=project
 status=registry('served-old-instance-upgrade-notice')
 assert status['installed'] and status['update_available'] and not status['update_supported']
 old_status,=status['instances']
 assert old_status['id']==old_project and old_status['version']=='4.1.4' and old_status['update_available']
 key=secrets.token_hex(16)
 payload={'expected_version':candidate['version'],'expected_sha256':candidate['sha256'],'host_port':management,'name':'signed-rabbit44-'+key[:8]}
 accepted,_=api('one-actual-44-store-install','/app-registry/rabbitmq/install',payload,202,key)
 project=accepted['project_id']
 job('signed-44-store-install-terminal',accepted)
 healthy('initial-44',project,'rabbitmq-440')
 new_before=observed_container('original-44-running-container',True)
 assert original['data_volume']!=new_before['volume']['name']
 credentials,headers=api('original-44-credentials','/docker/projects/'+project+'/credentials',{},private_response=True)
 assert headers['Cache-Control']=='no-store'
 assert credentials['template_id']=='rabbitmq-440' and credentials['project_id']==project
 username=credentials['credentials']['RABBITMQ_DEFAULT_USER']
 pw=credentials['credentials']['RABBITMQ_DEFAULT_PASS']
 result,body=management_get('/api/overview',(username,pw))
 assert result==200 and json.loads(body)['rabbitmq_version']=='4.4.0'
 message=secrets.token_bytes(1024)
 queue='yunzhan.signed.rabbit44.'+key[:12]
 conn=amqp_connect(pw)
 try:
  ch=conn.channel()
  ch.queue_declare(queue=queue,durable=True,arguments={'x-queue-type':'quorum'})
  ch.confirm_delivery()
  ch.basic_publish('',queue,message,pika.BasicProperties(delivery_mode=2),mandatory=True)
  assert ch.queue_declare(queue=queue,passive=True).method.message_count==1
 finally:
  conn.close()
 stopped,_=api('one-owned-44-stop','/docker/projects/'+project+'/stop',{},202)
 job('owned-44-stop-terminal',stopped)
 assert observed_container('stopped-44-same-volume',False)['volume']==new_before['volume']
 started,_=api('one-owned-44-start','/docker/projects/'+project+'/start',{},202)
 job('owned-44-start-terminal',started)
 healthy('restarted-44',project,'rabbitmq-440')
 live=observed_container('restarted-44-same-volume',True)
 assert live['volume']==new_before['volume'] and live['process_id']!=new_before['process_id']
 conn=amqp_connect(pw)
 try:
  ch=conn.channel()
  method,props,data=ch.basic_get(queue,auto_ack=False)
  assert method and props.delivery_mode==2 and data==message
  ch.basic_ack(method.delivery_tag)
 finally:
  conn.close()
 status=registry('served-44-current-and-legacy-still-needing-migration')
 by_id={row['id']:row for row in status['instances']}
 assert set(by_id)=={project,old_project} and by_id[old_project]['update_available']
 assert by_id[project]['version']==candidate['version'] and by_id[project]['version_source']=='application-receipt'
 assert not by_id[project]['update_available'] and status['update_available']
 still=api('original-41-volume-after','/docker/projects/'+old_project+'/rabbitmq-migration-preflight')[0]
 assert all(original[name]==still[name] for name in ('project_id','broker_version','node','data_volume','disabled_stable_features'))
 with contextlib.closing(sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True)) as db:
  db.execute('PRAGMA query_only=ON')
  receipts=db.execute('SELECT app_id,scope,version,sha256,target FROM app_registry_receipts WHERE app_id=?',(app,)).fetchall()
  assert receipts==[(app,project,candidate['version'],candidate['sha256'],'rabbitmq-440')]
  original_request=db.execute('SELECT app_id,scope,version,sha256,target FROM app_registry_install_requests WHERE idempotency_key=?',(key,)).fetchall()
  assert original_request==receipts
 save('actual-44-transaction-and-message.json',{'original_install_job':accepted['job_id'],'project':project,'old_project':old_project,
   'message_sha256':hashlib.sha256(data).hexdigest(),'retained_volume':live['volume'],'catalogue_head':cohort['served_head'],
   'receipt':receipts[0],'original_legacy_volume':original['data_volume']})
 proof.update(ok=True,native_install_POSTs=1,exact_44_signed_app_installed=True,legacy_update_notice=True,
  original_legacy_retained=True,original_44_message_retained=True)

except BaseException:
 failure=traceback.format_exc()
 if pw:failure=failure.replace(pw,'[generated test credential redacted]')
 if 'new_password' in globals():failure=failure.replace(new_password,'[generated test credential redacted]')
 proof['failure']=failure
finally:
 if csrf:
  try:api('original-logout','/logout',{})
  except BaseException:proof['logout_unconfirmed']=True;proof['ok']=False
 save('original-http-events.json',events);save('original-proof.json',proof)
 print(json.dumps({'ok':proof['ok'],'architecture':arch,'native_install_POSTs':proof['native_install_POSTs'],'Main_changed':False}),flush=True)
sys.exit(0 if proof['ok']else 1)
