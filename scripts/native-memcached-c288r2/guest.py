"""Actual normal signed Memcached installation/cache/control/cold acceptance in an owned guest."""
from pathlib import Path
import base64,contextlib,copy,grp,hashlib,http.cookiejar,json,os,platform,pwd,re,secrets,socket,sqlite3,stat,struct,subprocess,sys,time,traceback,urllib.request,urllib.error
os.umask(0o077);assert os.geteuid()==0 and len(sys.argv) in (2,3,4)
payload=Path(sys.argv[1]).resolve(strict=True);pins=json.loads((payload/'assets.json').read_bytes());arch={'aarch64':'arm64','x86_64':'amd64'}[platform.machine()];assert pins['architecture']==arch
case=pins['OS_case'];assert Path('/etc/hostname').read_text().strip()==case['hostname'] and case['hostname'].startswith('c285-memcached-')
target='b42832583eb74f0605d57a1360de5aa92faf3f300ab552175dd5997a918a98f3';assert pins['source_inputs_sha256']==target
base=Path(sys.argv[2]).resolve(strict=True) if len(sys.argv)>2 else Path('/opt/panel-memcached-c285-qa-'+secrets.token_hex(16));assert base.parent==Path('/opt') and re.fullmatch('panel-memcached-c285-qa-[a-f0-9]{32}',base.name)
evidence=base/'evidence'
if len(sys.argv)==2:evidence.mkdir(mode=0o700,parents=True)
phase='prepare' if len(sys.argv)==2 else sys.argv[3] if len(sys.argv)==4 else 'cold'
assert phase in ('prepare','after-browser','cold','after-retirement')
origin='http://127.0.0.1:19100';csrf='';counter=0;boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*a,**k):raise AssertionError('unexpected redirect')
client=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect(),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
def sha(p):
 digest=hashlib.sha256()
 with Path(p).open('rb') as f:
  for chunk in iter(lambda:f.read(1<<20),b''):digest.update(chunk)
 return digest.hexdigest()
def save(name,value):
 with(evidence/name).open('x') as f:json.dump(value,f,sort_keys=True,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
def cmd(args,timeout=30):
 p=subprocess.run(args,stdin=subprocess.DEVNULL,capture_output=True,text=True,timeout=timeout);assert p.returncode==0,(args[0],p.returncode,p.stderr[-1500:]);assert len(p.stdout)<4<<20;return p.stdout
def api(label,path,body=None,expected=200,key=None,cache_private=False):
 global counter
 name=phase+'-%04d-%s'%(counter,label);counter+=1
 if body is not None:save(name+'-intent.json',{'path':path,'body':{'private':True} if path=='/login' or cache_private else body,'key':key,'maximum_submissions':1})
 headers={'Origin':origin,'Content-Type':'application/json','X-CSRF-Token':csrf}
 if key:headers['Idempotency-Key']=key
 req=urllib.request.Request(origin+'/api'+path,None if body is None else json.dumps(body,separators=(',',':')).encode(),headers)
 try:
  with client.open(req,timeout=95) as r:status=r.status;raw=r.read((8<<20)+1)
 except urllib.error.HTTPError as r:status=r.code;raw=r.read((8<<20)+1)
 assert len(raw)<=8<<20;value=json.loads(raw)
 shown={'private_login_redacted':True} if path=='/login' else copy.deepcopy(value)
 if cache_private and isinstance(shown,dict) and isinstance(shown.get('cache'),dict):
  removed=shown['cache'].pop('value_base64',None)
  if removed is not None:shown['cache']['private_value_bytes']=len(base64.b64decode(removed))
 save(name+'-response.json',{'status':status,'value':shown});assert status==expected,(path,status,value.get('error'));return value
def login():
 global csrf
 access=json.loads(Path('/etc/panel/first-login.json').read_bytes())
 try:csrf=api(phase+'-login','/login',{k:access[k] for k in ('username','password')})['csrf']
 finally:access.clear()
def ready():
 for _ in range(90):
  try:
   with urllib.request.urlopen(origin+'/api/ready',timeout=3) as r:
    if r.status==200:return
  except Exception:pass
  time.sleep(1)
 raise TimeoutError('panel not ready')
def job(label,path,body):
 accepted=api(label,path,body,202,secrets.token_hex(16));identity=accepted['job_id'];assert re.fullmatch('[a-f0-9]{32}',identity)
 for n in range(1000):
  value=api(label+'-poll-'+str(n),'/jobs/'+identity)
  if value['state'] not in ('queued','running'):
   assert value['state']=='succeeded' and not value['error'],(label,value.get('error'));return value
  time.sleep(2)
 raise TimeoutError('original job unresolved; never replayed')
def snapshot():
 with contextlib.closing(sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True)) as db:
  db.execute('PRAGMA query_only=ON');db.execute('BEGIN');assert db.execute('PRAGMA quick_check').fetchone()==('ok',)
  session_activity=dict(db.execute('SELECT token_hash,last_activity_at FROM sessions'))
  schema=db.execute("SELECT type,name,tbl_name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name").fetchall();rows={}
  for kind,name,_,_ in schema:
   if kind!='table' or name in ('database_connection_samples','monitor_conditions','monitor_samples','monitor_services','notification_dispatch_status'):continue
   assert re.fullmatch('[A-Za-z0-9_]+',name)
   columns=[r[1] for r in db.execute('PRAGMA table_info('+name+')')]
   if name=='sessions':columns.remove('last_activity_at')
   if name=='runtime_installations':columns.remove('detected_at')
   if name=='load_balance_traffic_source':columns.remove('worker_checked_at')
   values=db.execute('SELECT '+','.join(columns)+' FROM '+name).fetchall()
   rows[name]=sorted(hashlib.sha256(json.dumps([{'blob_hex':v.hex()} if isinstance(v,bytes) else v for v in row],separators=(',',':')).encode()).hexdigest() for row in values)
 return {'schema':schema,'rows':rows,'session_activity':session_activity,'NSS':{n:sha('/etc/'+n) for n in ('passwd','group','shadow','gshadow')},'NSS_rows':{n:{line.split(':',1)[0]:hashlib.sha256(line.encode()).hexdigest() for line in Path('/etc/'+n).read_text().splitlines()} for n in ('passwd','group','shadow','gshadow')}}
def project_records(project):
 records={};root=Path('/etc/panel/compose')/project
 assert root.is_dir() and not root.is_symlink()
 for p in sorted(root.rglob('*')):
  info=p.lstat()
  if stat.S_ISDIR(info.st_mode):continue
  assert stat.S_ISREG(info.st_mode) and not p.is_symlink() and info.st_size<256<<10 and len(records)<128
  records[str(p)]={'uid':info.st_uid,'gid':info.st_gid,'mode':stat.S_IMODE(info.st_mode),'inode':info.st_ino,'bytes':info.st_size,'sha256':sha(p)}
 assert records;return records
def original_records():
 records={}
 for parent in sorted(Path('/var/lib/panel-executor').glob('memcached-*')):
  assert not parent.is_symlink()
  for p in ([parent] if parent.is_file() else sorted(parent.rglob('*'))):
   s=p.lstat()
   if stat.S_ISDIR(s.st_mode) or stat.S_ISSOCK(s.st_mode):continue
   assert stat.S_ISREG(s.st_mode) and s.st_size<16<<20 and len(records)<20000
   records[str(p)]={'uid':s.st_uid,'gid':s.st_gid,'mode':stat.S_IMODE(s.st_mode),'inode':s.st_ino,'bytes':s.st_size,'sha256':sha(p)}
 return records
def inspect(project):
 v=api('inspect','/app-registry/memcached/instances/'+project+'/workspace',{'action':'inspect'})
 assert v['format']==1 and v['project_id']==project and v['version']=='1.6.45-compat4' and v['state_known'] and v['network_mode']=='none' and v['cache_mb']==128 and v['memory_limit_mb']==192 and v['editor_limit_bytes']==49152
 return v
def cache(project,action,key=None,expected=200,**kw):
 body={'action':action,**kw}
 if key is not None:body['key_base64']=base64.b64encode(key).decode()
 v=api('cache-'+action,'/app-registry/memcached/instances/'+project+'/workspace',{'action':'cache','cache':body},expected,cache_private=True)
 return v.get('cache') if expected==200 else v
def control(project,action):
 old=inspect(project);body={'action':action,'expected_runtime_sha256':old['runtime_sha256'],'acknowledge_cache_loss':action in ('stop','restart')}
 key=secrets.token_hex(16);r=api('control-'+action,'/app-registry/memcached/instances/'+project+'/controls',body,200,key)
 assert r['state']=='completed' and r['operation']['request_id']==key and r['result']['state']=='completed'
 assert r['result']['final_state']==('stopped' if action=='stop' else 'running')
 return r
def kernel(project):
 w=inspect(project);assert w['healthy'] and w['state']=='running'
 ids=cmd(['/usr/bin/docker','ps','-aq','--no-trunc']).split();assert len(ids)==1 and re.fullmatch('[a-f0-9]{64}',ids[0])
 v=json.loads(cmd(['/usr/bin/docker','inspect',ids[0]]))[0];h=v['HostConfig'];assert v['Config']['Image']=='memcached:1.6.45-alpine@sha256:9e4de012dc607573052061c0bcb38abc775e1dd59b24e7ac38d1892842094aaf'
 assert h['NetworkMode']=='none' and h['Memory']==h['MemorySwap']==192<<20 and h['PidsLimit']==32 and h['ReadonlyRootfs'] and not h['Privileged'] and 'ALL' in h['CapDrop'] and h['NanoCpus']==1000000000
 uid,gid=map(int,v['Config']['User'].split(':'));assert 0<uid<1000 and 0<gid<1000
 account=pwd.getpwuid(uid);assert account.pw_name=='panel-memcached' and account.pw_gid==gid and account.pw_dir=='/nonexistent' and account.pw_shell=='/usr/sbin/nologin' and grp.getgrgid(gid).gr_name=='panel-memcached'
 pid=v['State']['Pid'];status={x.split(':',1)[0]:x.split(':',1)[1].strip() for x in Path('/proc/'+str(pid)+'/status').read_text().splitlines() if ':' in x}
 assert set(map(int,status['Uid'].split()))=={uid} and set(map(int,status['Gid'].split()))=={gid} and int(status['CapEff'],16)==0 and status['NoNewPrivs']=='1'
 with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as s:
  s.settimeout(3);s.connect(w['socket_path']);peer=struct.unpack('3i',s.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12));assert peer==(pid,uid,gid)
  s.sendall(b'version\r\n');assert s.recv(128)==b'VERSION 1.6.45\r\n'
 cgroups=Path('/proc/'+str(pid)+'/cgroup').read_text().splitlines();unified=[line.split(':',2)[2] for line in cgroups if line.startswith('0::')]
 assert len(unified)==1,'This owned cgroup-v2 cohort must expose its actual kernel limits'
 group=Path('/sys/fs/cgroup')/unified[0].lstrip('/')
 limits={name:(group/name).read_text().strip() for name in ('memory.max','memory.swap.max','pids.max','cpu.max')}
 assert limits['memory.max']==str(192<<20) and limits['memory.swap.max']=='0' and limits['pids.max']=='32'
 quota,period=map(int,limits['cpu.max'].split());assert quota==period
 assert not h.get('PortBindings') and not v['NetworkSettings']['Ports']
 assert len(v['Mounts'])==1 and v['Mounts'][0]['Type']=='bind' and v['Mounts'][0]['Source']==str(Path(w['socket_path']).parent) and v['Mounts'][0]['Destination']=='/run/memcached'
 return {'image_id':v['Image'],'container_id':ids[0],'pid':pid,'uid':uid,'gid':gid,'peer_pid_UID_GID_match':True,'actual_kernel_cgroup_limits':limits,'network_none_and_resource_limits_and_no_privileges':True}
proof={'ok':False,'phase':phase,'base':str(base),'architecture':arch,'source_inputs_sha256':target,'boot':boot,'Main_changed':False,'all40_commercial':False}
try:
 for name,pin in pins['files'].items():assert sha(payload/name)==pin,name
 if phase=='prepare':
  assert not any(os.path.lexists(p) for p in ('/opt/panel','/etc/panel','/var/lib/panel'))
  verified=base/'verified-input';verified.mkdir(mode=0o700)
  for name,digest in pins['files'].items():
   original=payload/name;info=original.lstat();assert stat.S_ISREG(info.st_mode) and not original.is_symlink() and sha(original)==digest
   with(verified/name).open('xb') as output:
    output.write(original.read_bytes());output.flush();os.fsync(output.fileno())
   current=(verified/name).lstat();assert current.st_uid==0 and current.st_nlink==1 and stat.S_IMODE(current.st_mode)==0o600 and sha(verified/name)==digest
  payload=verified
  archive=payload/('panel-'+pins['version']+'-linux-'+arch+'.tar.gz');assert sha(payload/'signed-release.py')=='fe128e82b4e11345b320cd782134768bfe1a4df14947c425d7494873a7a7b7b5'
  with(evidence/'normal-signed-install.stdout').open('xb') as out,(evidence/'normal-signed-install.stderr').open('xb') as err:p=subprocess.run([sys.executable,'-I','-B',str(payload/'signed-release.py'),'install',str(archive),'--public-key',str(payload/'release-signing-dev.pub')],stdout=out,stderr=err,timeout=1800)
  assert p.returncode==0;ready();assert json.loads(Path('/opt/panel/current/SOURCE_INPUTS.json').read_bytes())['inputs_sha256']==target;login()
  release={('debian','12'):'docker-ce-29.8.2-bookworm',('debian','13'):'docker-debian-26.1.5',('ubuntu','22.04'):'docker-ce-29.8.2-jammy',('ubuntu','24.04'):'docker-ce-29.8.2-noble',('ubuntu','26.04'):'docker-ce-29.8.2-resolute'}[(case['distribution'],case['version_id'])]
  job('Docker-install','/runtimes/install',{'release_id':release})
  catalog=api('current-catalogue','/app-registry?refresh=1');assert catalog['source']['resolved_commit']==pins['served_head'] and not catalog['source']['stale'] and len(catalog['catalog']['apps'])==40
  app=next(a for a in catalog['catalog']['apps'] if a['id']=='memcached');assert app['version']=='1.6.45-compat4'
  before=snapshot();save('before-app-original.json',before);name='c285-cache-'+secrets.token_hex(6)
  accepted=api('signed-Memcached-install','/app-registry/memcached/install',{'name':name,'settings':{'site_id':''},'expected_version':app['version'],'expected_sha256':app['sha256']},202,secrets.token_hex(16))
  identity=accepted['job_id'];project=accepted.get('project_id') or accepted.get('scope');assert re.fullmatch('[a-f0-9]{32}',identity) and re.fullmatch('[a-f0-9]{32}',project)
  for n in range(900):
   state=api('install-status-'+str(n),'/app-registry/memcached/installs/'+identity)
   if state['state'] not in ('queued','running'):
    assert state['state_known'] and state['state']=='succeeded',state;break
   time.sleep(2)
  else:raise TimeoutError('Original installation unresolved; no replay')
  api('post-install-ordinary-store-refresh','/app-registry')
  with sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True) as db:assert db.execute("SELECT version,sha256 FROM app_registry_receipts WHERE app_id='memcached' AND scope=?",(project,)).fetchall()==[(app['version'],app['sha256'])]
  actual=kernel(project);save('actual-native-install-kernel.json',actual)
  key=('c285:'+project+':binary').encode()+b'\x00\r\n';value=os.urandom(80);b64=lambda v:base64.b64encode(v).decode()
  added=cache(project,'add',key,value_base64=b64(value),ttl_seconds=300,flags=7);got=cache(project,'get',key);assert got['found'] and base64.b64decode(got['value_base64'])==value and got['cas']==added['cas'] and got['flags']==7
  cache(project,'add',key,expected=409,value_base64=b64(b'duplicate'),ttl_seconds=300)
  new=os.urandom(91);changed=cache(project,'cas',key,value_base64=b64(new),cas=got['cas'],ttl_seconds=300);assert changed['cas']!=got['cas']
  cache(project,'cas',key,expected=409,value_base64=b64(value),cas=got['cas'],ttl_seconds=300);cache(project,'delete',key,expected=409,cas=got['cas'])
  assert base64.b64decode(cache(project,'get',key)['value_base64'])==new;cache(project,'delete',key,cas=changed['cas']);assert not cache(project,'get',key)['found']
  large=os.urandom(48<<10);k=('c285:'+project+':48K').encode();put=cache(project,'add',k,value_base64=b64(large),ttl_seconds=300);assert base64.b64decode(cache(project,'get',k)['value_base64'])==large;cache(project,'delete',k,cas=put['cas'])
  cache(project,'add',k,expected=400,value_base64=b64(large+b'x'));cache(project,'add',k,expected=400,ttl_seconds=1);cache(project,'flush_all',expected=400)
  ttl_key=('c285:'+project+':ttl').encode();cache(project,'add',ttl_key,value_base64=b64(b'expires'),ttl_seconds=5);assert cache(project,'get',ttl_key)['found'];time.sleep(6);assert not cache(project,'get',ttl_key)['found']
  for group in ('basic','settings','items','slabs'):
   result=cache(project,'stats',stats=group);assert result['action']=='stats'
   stats=result.get('statistics',{});assert isinstance(stats,dict) and (group in ('items','slabs') or stats)
   if group=='basic':assert stats['version']=='1.6.45'
   if group=='settings':assert stats['maxbytes']=='134217728' and stats['maxconns']=='256' and stats['num_threads']=='2' and stats['item_size_max']=='4194304'
  controls=[control(project,a) for a in ('stop','start','restart')];assert kernel(project)['container_id']==actual['container_id'];save('original-completed-controls.json',controls)
  seed=('c285:'+project+':cold').encode();cache(project,'add',seed,value_base64=b64(os.urandom(32)),ttl_seconds=0)
  after=snapshot();save('after-app-original.json',after);assert len(before['session_activity'])==1 and before['session_activity'].keys()==after['session_activity'].keys()
  assert all(stamp<=after['session_activity'][key]<=int(time.time()) for key,stamp in before['session_activity'].items())
  assert after['schema']==before['schema'];allowed={'app_registry_install_requests','app_registry_pending','app_registry_receipts','memcached_unix_controls','audit_logs'}
  for table,rows in before['rows'].items():
   if table not in allowed:assert after['rows'][table]==rows,table
   else:assert set(rows)<=set(after['rows'][table]),table
  for n in ('passwd','group','shadow','gshadow'):
   assert set(after['NSS_rows'][n])-set(before['NSS_rows'][n])=={'panel-memcached'}
   assert all(after['NSS_rows'][n].get(name)==digest for name,digest in before['NSS_rows'][n].items())
  warm={'boot':boot,'project':project,'job':identity,'name':name,'manifest':app['sha256'],'kernel':kernel(project),'controls':controls,'compose_records':project_records(project),'NSS':after['NSS'],'seed_key_base64':b64(seed),'before':before}
  with(base/'warm-intent.json').open('x') as f:json.dump(warm,f);f.flush();os.fsync(f.fileno())
  proof.update(ok=True,normal_signed_programmes=1,normal_signed_Memcached_store_install=True,actual_binary_CAS_TTL_limits_and_four_statistics=True,actual_three_typed_controls=True,actual_network_none_nonroot_limits_and_peer=True,cache_prepared=True)
 elif phase=='after-browser':
  intent=json.loads((base/'warm-intent.json').read_bytes());assert intent['boot']==boot;login();actual=kernel(intent['project']);assert actual['container_id']==intent['kernel']['container_id'];assert cache(intent['project'],'get',base64.b64decode(intent['seed_key_base64']))['found']
  history=api('original-controls','/app-registry/memcached/controls');assert not history['truncated']
  for original in intent['controls']:assert original in history['records']
  cold={**intent,'protected_records':original_records(),'history':history,'snapshot':snapshot()};save('original-cold-intent-witness.json',cold)
  with(base/'cold-intent.json').open('x') as f:json.dump(cold,f);f.flush();os.fsync(f.fileno())
  for directory in (evidence,base):
   fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
  proof.update(ok=True,powerloss_ready=True,original_records_captured=True)
 elif phase=='after-retirement':
  intent=json.loads((base/'cold-intent.json').read_bytes());assert intent['boot']!=boot;login();workspace=inspect(intent['project'])
  assert workspace['state_known'] and workspace['state']=='retired' and not workspace['healthy'] and workspace.get('retirement_supported',False) is False and re.fullmatch('[a-f0-9]{32}',workspace['retirement_request_id'])
  assert cmd(['/usr/bin/docker','ps','-aq','--no-trunc']).strip()==''
  image=json.loads(cmd(['/usr/bin/docker','image','inspect','memcached:1.6.45-alpine@sha256:9e4de012dc607573052061c0bcb38abc775e1dd59b24e7ac38d1892842094aaf']))
  assert len(image)==1 and image[0]['Id']==intent['kernel']['image_id']
  actual=original_records();assert all(actual.get(name)==record for name,record in intent['protected_records'].items())
  compose=project_records(intent['project']);assert all(compose.get(name)==record for name,record in intent['compose_records'].items())
  assert snapshot()['NSS']==intent['NSS']
  history=api('retired-original-controls','/app-registry/memcached/controls');assert not history['truncated']
  for record in intent['controls']:assert record in history['records']
  old={row['operation']['request_id'] for row in intent['controls']};new=[row for row in history['records'] if row['operation']['request_id'] not in old]
  assert len(new)==2 and {row['operation']['input']['action'] for row in new}=={'stop','retire'}
  assert all(row['state']=='completed' and row['result']['state']=='completed' and row['operation']['project_id']==intent['project'] for row in new)
  requests={row['operation']['input']['action']:row['operation']['request_id'] for row in new};assert requests['retire']==workspace['retirement_request_id']
  with sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True)as db:assert db.execute("SELECT version,sha256 FROM app_registry_receipts WHERE app_id='memcached' AND scope=?",(intent['project'],)).fetchall()==[('1.6.45-compat4',intent['manifest'])]
  catalogue=api('retired-ordinary-store-discovery','/app-registry');status=next(row for row in catalogue['status'] if row['id']=='memcached');assert status['state_known'] and not status['installed'] and not status['healthy'] and not status['update_available']
  proof.update(ok=True,actual_retired_container_absent_and_original_image_retained=True,actual_original_Root_records_and_compose_configuration_and_NSS_preserved=True,historical_signed_install_receipt_retained_and_store_known_uninstalled=True,actual_final_UI_control_request_ids=requests)
 else:
  intent=json.loads((base/'cold-intent.json').read_bytes());assert intent['boot']!=boot;ready();login();end=time.monotonic()+120
  while True:
   try:actual=kernel(intent['project']);break
   except (AssertionError,OSError):
    if time.monotonic()>=end:raise
    time.sleep(.5)
  assert actual['container_id']==intent['kernel']['container_id'] and actual['uid']==intent['kernel']['uid'] and actual['gid']==intent['kernel']['gid']
  assert original_records()==intent['protected_records'];assert snapshot()['NSS']==intent['NSS']
  assert not cache(intent['project'],'get',base64.b64decode(intent['seed_key_base64']))['found']
  history=api('cold-original-controls','/app-registry/memcached/controls');assert history==intent['history']
  proof.update(ok=True,prior_boot=intent['boot'],actual_real_kernel_reboot=True,actual_same_container_UID_GID_limits_and_peer=True,cache_loss_matches_documented_volatile_semantics=True,original_control_history_and_Root_bytes_owners_inodes_preserved=True,original_NSS_preserved=True,project_id=intent['project'])
except BaseException:save('original-failure-'+secrets.token_hex(4)+'.json',{'traceback':traceback.format_exc()})
finally:
 try:
  diagnostic={'scope':'Read-only private diagnostic; never replays or completes any operation','records':{},'commands':{}}
  for root in sorted(Path('/var/lib/panel-executor').glob('memcached-*')):
   if root.is_symlink():continue
   for p in ([root] if root.is_file() else sorted(root.rglob('*'))):
    info=p.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size>1<<20 or p.is_symlink():continue
    assert len(diagnostic['records'])<1000
    raw=p.read_bytes();diagnostic['records'][str(p)]={'uid':info.st_uid,'gid':info.st_gid,'mode':stat.S_IMODE(info.st_mode),'inode':info.st_ino,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'original_base64':base64.b64encode(raw).decode()}
  commands={'units':['systemctl','list-units','--all','--no-pager','--plain','panel-memcached*'],'journal':['journalctl','-b','-u','panel-executor.service','-u','panel-memcached*','-u','docker.service','--no-pager','-o','json','-n','180'],'containers':['docker','ps','-a','--no-trunc','--format','json'],'Docker-version':['docker','version','--format','{{json .}}']}
  for label,args in commands.items():
   p=subprocess.run(args,stdin=subprocess.DEVNULL,capture_output=True,timeout=15);assert len(p.stdout)+len(p.stderr)<4<<20
   diagnostic['commands'][label]={'exit':p.returncode,'stdout_base64':base64.b64encode(p.stdout).decode(),'stderr_base64':base64.b64encode(p.stderr).decode()}
  save('original-'+phase+'-Root-install-diagnostic.json',diagnostic)
 except BaseException:save('original-'+phase+'-diagnostic-failure.json',{'traceback':traceback.format_exc()})
 if csrf:
  try:api('own-logout','/logout',{});csrf=''
  except BaseException:proof['ok']=False
 save('proof-'+phase+'.json',proof);print(json.dumps(proof),flush=True)
sys.exit(0 if proof['ok'] else 1)
