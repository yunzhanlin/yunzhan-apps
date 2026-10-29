"""Actual C28 kernel-policy reallocation with the original native L4 connection."""
import contextlib,hashlib,http.client,json,os,pathlib,re,runpy,secrets,socket,sqlite3,stat,struct,subprocess,threading,time
SOURCE='a90b74709a04c646ede65f499286046d7ef43bb80265b4afc3e121177f7d48bc'
def sha(p):return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
def save(n,v):
 with(base/n).open('xb')as f:f.write((json.dumps(v,sort_keys=True,indent=2)+'\n').encode());f.flush();os.fsync(f.fileno())

def info(p):
 s=p.lstat();v={'mode':s.st_mode,'uid':s.st_uid,'gid':s.st_gid,'links':s.st_nlink,'dev':str(s.st_dev),'inode':str(s.st_ino),'mtime_ns':str(s.st_mtime_ns),'ctime_ns':str(s.st_ctime_ns)}
 if stat.S_ISREG(s.st_mode):v.update(size=s.st_size,sha256=sha(p))
 elif stat.S_ISLNK(s.st_mode):v['link']=os.readlink(p)
 else:assert stat.S_ISDIR(s.st_mode)
 return v

def files():
 roots=[pathlib.Path('/etc')/n for n in('passwd','group','shadow','gshadow','nsswitch.conf')]+[pathlib.Path('/etc/panel/load-balance-stream'),pathlib.Path('/etc/panel/security-apps/modules/load-balance')]+list(pathlib.Path('/var/lib/panel-executor').glob('load-balance-stream-*'))
 return{str(p):info(p)for root in roots for p in[root,*sorted(root.rglob('*'))]if os.path.lexists(p)}

def processes():
 out={}
 for unit in('nginx.service','panel-load-balance-stream.service','panel.service','panel-executor.service'):
  raw=subprocess.check_output(['systemctl','show',unit,'--property=Id,MainPID,ControlPID,InvocationID,ActiveState,SubState,Result'],text=True,timeout=6);value=dict(x.split('=',1)for x in raw.splitlines());assert value['ActiveState']=='active'and value['SubState']=='running'and value['Result']=='success'
  cg=pathlib.Path('/sys/fs/cgroup/system.slice')/unit/'cgroup.procs';pids=sorted(map(int,cg.read_text().split()))
  out[unit]={'unit':value,'processes':[{'pid':pid,'start_ticks':pathlib.Path('/proc',str(pid),'stat').read_text().rsplit(')',1)[1].split()[19],'exe_sha256':sha('/proc/'+str(pid)+'/exe')}for pid in pids]}
 return out

def nft_static_and_counters(value):
 counters={}
 def walk(item,path):
  if isinstance(item,dict):
   out={}
   for k,v in item.items():
    if k=='counter'and isinstance(v,dict)and type(v.get('packets'))is int and type(v.get('bytes'))is int:
     assert v['packets']>=0 and v['bytes']>=0;counters[path+'/'+k]=(v['packets'],v['bytes']);out[k]={**v,'packets':0,'bytes':0}
    else:out[k]=walk(v,path+'/'+k)
   return out
  if isinstance(item,list):return[walk(v,path+'/'+str(i))for i,v in enumerate(item)]
  return item
 return walk(value,''),counters

def same_nft(a,b):
 aa,ac=nft_static_and_counters(a);bb,bc=nft_static_and_counters(b);assert aa==bb and ac.keys()==bc.keys()
 for key,old in ac.items():assert bc[key][0]>=old[0]and bc[key][1]>=old[1]
 return{'complete_static_rules_objects_and_handles_preserved':True,'all_counter_locations_checked':len(ac),'only_monotonic_counter_growth':True}

def kernel_read(label):
 with(base/(label+'.log')).open('xb')as f:r=subprocess.run([str(binary),'-test.v','-test.count=1','-test.run=^TestStreamFilterNativeExistingUnitKernelPolicyReadOnly$'],stdin=subprocess.DEVNULL,stdout=f,stderr=subprocess.STDOUT,timeout=25)
 log=(base/(label+'.log')).read_text();save(label+'-result.json',{'exit':r.returncode,'log_sha256':sha(base/(label+'.log'))})
 assert r.returncode==0 and 'SKIP'not in log and log.count('\n--- PASS:')==1
 m=re.search(r'actual native filter fingerprint ([0-9a-f]{64}); direct ingress=\[([0-9 ]+)\] egress=\[([0-9 ]+)\];',log);assert m
 return{'policy_sha256':m[1],'ingress':list(map(int,m[2].split())),'egress':list(map(int,m[3].split()))}

def run(cohort):
 global base,binary
 assert os.geteuid()==0
 assert json.loads(pathlib.Path('/opt/panel/current/SOURCE_INPUTS.json').read_bytes())['inputs_sha256']==SOURCE
 pins=json.loads((cohort/'assets.json').read_bytes());base=cohort/'evidence'/'C28-filter-reload';base.mkdir(mode=0o700)
 binary=cohort/'executor-tests';assert sha(binary)==pins['files']['executor-tests']
 lib=runpy.run_path(str(cohort/'candidate8-stream19-full-business.py'));policy=json.loads((cohort/'policy.json').read_bytes());original=json.loads((cohort/'evidence/programme-before-full.json').read_bytes())
 def capture():
  with contextlib.closing(sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True,timeout=3))as db:
   db.execute('PRAGMA query_only=ON');db.execute('BEGIN')
   assert db.execute("SELECT count(*)FROM runtime_jobs WHERE state IN('queued','running')").fetchone()==(0,)
   assert db.execute('SELECT count(*)FROM load_balance_stream_controls').fetchone()==(4,)
   assert db.execute("SELECT count(*)FROM load_balance_stream_controls WHERE state!='completed'").fetchone()==(0,)
   return lib['capture'](db,original,policy)
 def workspace(label):
  class U(http.client.HTTPConnection):
   def connect(self):
    self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.sock.settimeout(20);self.sock.connect('/run/panel-executor/control.sock')
  c=U('localhost')
  try:c.request('GET','/v1/load-balance-stream/workspace');r=c.getresponse();w=json.loads(r.read(1<<20));assert r.status==200
  finally:c.close()
  save(label+'.json',w);assert w['available']and w['state']=='running'and w['generation']==4 and w['configuration_verified'];return w
 def guard(label):
  r=subprocess.run(['/opt/panel/current/bin/panel-executor','--check-program-upgrade-queues'],capture_output=True,text=True,timeout=35)
  save(label+'.json',{'exit':r.returncode,'stdout':r.stdout,'stderr':r.stderr});assert r.returncode==0 and r.stdout==r.stderr==''
 def owned_fixture():
  root=cohort/'evidence/stream-live';echo=root/'echo.py';assert sha(echo)==pins['files']['owned-loopback-echo.py']
  record=json.loads((root/'backend-unit.json').read_bytes());unit=pathlib.Path(record['path']);assert sha(unit)==record['sha256']
  raw=subprocess.check_output(['systemctl','show',unit.name,'--property=Id,MainPID,ControlPID,InvocationID,ActiveState,SubState,Result,FragmentPath'],text=True,timeout=8);v=dict(x.split('=',1)for x in raw.splitlines())
  assert v['Id']==unit.name and v['ActiveState']=='active'and v['SubState']=='running'and v['Result']=='success'and v['FragmentPath']==str(unit)and v['ControlPID']=='0'
  pid=int(v['MainPID']);assert pid>1;p=pathlib.Path('/proc')/str(pid);assert p.joinpath('cmdline').read_bytes().split(bytes([0]))[:-1]==[b'/usr/bin/python3',b'-I',b'-B',str(echo).encode()]
  return {'unit':v,'start':p.joinpath('stat').read_text().rsplit(')',1)[1].split()[19],'exe_sha256':sha(p/'exe'),'source_sha256':sha(echo),'unit_sha256':sha(unit)}
 proof={'ok':False,'component_only':False,'actual_normal_C28_programme':True,'source_inputs_sha256':SOURCE,'normal_native_controls_already_completed':4,'new_native_controls_or_job_replays':0,'Main_changed':False,'all50_commercial':False}
 active=None;stop=threading.Event();errors=[];transfers=[];thread=None
 try:
  workspace('before-workspace');guard('before-guard')
  generation=json.loads(pathlib.Path('/var/lib/panel-executor/load-balance-stream-state/current.json').read_bytes());request=generation['request_id']
  receipt=json.loads((pathlib.Path('/var/lib/panel-executor/load-balance-stream-configurations')/request/'service.json').read_bytes())
  assert receipt['request_id']==request and receipt['native']['format']==2 and receipt['state']=='running'
  before=capture();protected=files();proc=processes();nft=json.loads(subprocess.check_output(['nft','-j','list','ruleset'],timeout=8));fixture=owned_fixture()
  for name,value in [('before-full111-105.json',before),('protected-before.json',protected),('processes-before.json',proc),('nft-before.json',nft),('owned-fixture-before.json',fixture),('original-service-receipt.json',receipt)]:save(name,value)
  with(base/'C28-all-filter-components.log').open('xb')as output:result=subprocess.run([str(binary),'-test.v','-test.count=1','-test.run=^TestStreamFilter'],stdin=subprocess.DEVNULL,stdout=output,stderr=subprocess.STDOUT,timeout=35)
  log=(base/'C28-all-filter-components.log').read_text();assert result.returncode==0 and 'SKIP'not in log and log.count('\n--- PASS:')==9
  active=socket.create_connection(('127.0.0.1',41080),timeout=5);active.settimeout(5);tag=b''
  while len(tag)<6:
   b=active.recv(6-len(tag));assert b;tag+=b
  assert tag in(b'31082|',b'31083|');nonce=secrets.token_bytes(24)
  def heartbeat():
   try:
    n=0
    while not stop.is_set():
     payload=nonce+struct.pack('>Q',n);active.sendall(payload);reply=b''
     while len(reply)<len(payload):
      b=active.recv(len(payload)-len(reply));assert b;reply+=b
     assert reply==payload;transfers.append({'sequence':n,'bytes':len(payload),'sha256':hashlib.sha256(payload).hexdigest()});n+=1;assert n<=10000;stop.wait(.025)
   except BaseException as e:
    if not stop.is_set():errors.append(type(e).__name__)
  thread=threading.Thread(target=heartbeat,daemon=True);thread.start()
  for _ in range(40):
   if len(transfers)>=3:break
   time.sleep(.025)
  assert len(transfers)>=3 and not errors
  first=kernel_read('kernel-before');save('kernel-before.json',first);assert first['policy_sha256']==receipt['native']['filter_sha256'];at_start=len(transfers)
  save('daemon-reload-once-intent.json',{'command':['systemctl','daemon-reload'],'maximum_attempts':1,'unknown_outcome_observe_only':True})
  result=subprocess.run(['systemctl','daemon-reload'],capture_output=True,text=True,stdin=subprocess.DEVNULL,timeout=25);save('daemon-reload-outcome.json',{'exit':result.returncode,'stdout':result.stdout,'stderr':result.stderr});assert result.returncode==0
  for _ in range(40):
   if len(transfers)>=at_start+3:break
   time.sleep(.025)
  last=kernel_read('kernel-after');save('kernel-after.json',last)
  assert first['policy_sha256']==last['policy_sha256']
  reallocated=first['ingress']!=last['ingress']or first['egress']!=last['egress']
  assert len(transfers)>=at_start+3 and not errors
  workspace('after-workspace');guard('after-guard')
  after=capture();newfiles=files();newproc=processes();newnft=json.loads(subprocess.check_output(['nft','-j','list','ruleset'],timeout=8));newfixture=owned_fixture()
  for name,value in [('after-full111-105.json',after),('protected-after.json',newfiles),('processes-after.json',newproc),('nft-after.json',newnft),('owned-fixture-after.json',newfixture)]:save(name,value)
  assert protected==newfiles and proc==newproc and fixture==newfixture
  nft_result=same_nft(nft,newnft);lib['full_delta'](before,after,original,policy);comparison=lib['C7']['compare_rows'](before,after)
  save('full105-SQL-qualified.json',comparison);save('NFT-qualified.json',nft_result);save('original-connection.json',{'backend_tag':tag.decode(),'same_socket_no_reconnection':True,'transfers_before_reload':at_start,'transfers':transfers,'errors':errors})
  proof.update(ok=True,actual_BPF_ids_reallocated=reallocated,actual_systemd_reload_completed=True,actual_policy_sha256_unchanged=first['policy_sha256'],native_receipt_format=2,normal_workspace_and_complete_guard_healthy_before_after=True,original_PID_UID_ELF_invocations_NSS_all_native_files_and_all105_full_business_preserved=True,unique_TCP_roundtrips=len(transfers),filter_components_passed=9,filter_components_skipped=0)
 finally:
  stop.set()
  if thread:thread.join(timeout=6)
  if active:active.close()
  save('proof.json',proof)
 return proof
