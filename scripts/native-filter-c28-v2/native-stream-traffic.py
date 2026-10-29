"""Actual fresh C15 native TCP/UDP/Core control lifecycle, no replay or reset."""
import contextlib,hashlib,http.cookiejar,json,os,pathlib,re,runpy,secrets,socket,sqlite3,stat,subprocess,sys,threading,time,traceback,urllib.error,urllib.request
os.umask(0o077);cohort=pathlib.Path(sys.argv[1]);assert len(sys.argv)==2 and os.geteuid()==0 and re.fullmatch('/opt/panel-native-qa-[a-f0-9]{32}',str(cohort))
base=cohort/'evidence'/'stream-live';base.mkdir(mode=0o700)
def sha(p):return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
assert json.loads(pathlib.Path('/opt/panel/current/SOURCE_INPUTS.json').read_bytes())['inputs_sha256']=='a90b74709a04c646ede65f499286046d7ef43bb80265b4afc3e121177f7d48bc'
pins=json.loads((cohort/'assets.json').read_bytes())
for n in('candidate8-programme-business.py','candidate8-stream19-full-business.py','policy.json','main-store-business24blhb.py','programme-full-business24blhy.py','monitor-active-observation24blhv.py','owned-loopback-echo.py'):
 p=cohort/n;s=p.lstat();assert stat.S_ISREG(s.st_mode)and s.st_uid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600 and sha(p)==pins['files'][n]
 library_path=base/('echo.py'if n=='owned-loopback-echo.py'else n)
 with os.fdopen(os.open(library_path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600),'wb')as out:out.write(p.read_bytes())
def save(n,v):
 with os.fdopen(os.open(base/n,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600),'w')as out:json.dump(v,out,sort_keys=True);out.write('\n');out.flush();os.fsync(out.fileno())
def command(n,args,timeout=15):
 r=subprocess.run(args,capture_output=True,text=True,timeout=timeout);save(n+'.json',{'exit':r.returncode,'stdout':r.stdout,'stderr':r.stderr});assert r.returncode==0,n;return r.stdout
library=runpy.run_path(str(base/'candidate8-stream19-full-business.py'));policy_contract=json.loads((base/'policy.json').read_bytes());original109_path=cohort/'evidence'/'programme-before-full.json';original109=json.loads(original109_path.read_bytes())
original_job=json.loads((cohort/'evidence'/'store-1.9.0-response.json').read_bytes())['response']['job_id']
with contextlib.closing(sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True,timeout=3))as db:
 db.execute('PRAGMA query_only=ON');assert db.execute('SELECT count(*)FROM load_balance_stream_controls').fetchone()==(0,)
 original_job_row=db.execute('SELECT *FROM runtime_jobs WHERE id=?',(original_job,)).fetchone();assert original_job_row is not None
 assert db.execute('SELECT state,error FROM runtime_jobs WHERE id=?',(original_job,)).fetchone()==('succeeded','')
def capture():
 with contextlib.closing(sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True,timeout=3))as db:
  db.execute('PRAGMA query_only=ON');db.execute('BEGIN');return library['capture'](db,original109,policy_contract)
proof={'ok':False,'Main_changed':False,'all50_commercial':False,'controls':[],'root':str(base)};csrf='';client=None;drain_thread=None;drain_stop=threading.Event();drain_errors=[];drain_count=[]
def api(path,body=None):
 raw=None if body is None else json.dumps(body,separators=(',',':')).encode();req=urllib.request.Request('http://127.0.0.1:19100/api'+path,data=raw,headers={'Content-Type':'application/json','Origin':'http://127.0.0.1:19100','X-CSRF-Token':csrf})
 try:
  with client.open(req,timeout=35)as response:return response.status,json.loads(response.read((4<<20)+1))
 except urllib.error.HTTPError as e:
  save('http-error-'+secrets.token_hex(8)+'.json',{'path':path,'status':e.code,'body':e.read(8192).decode('utf8','replace')});raise AssertionError('API '+path+' HTTP'+str(e.code))from None
def workspace(label,generation,state):
 status,v=api('/app-registry/load-balance/stream/workspace');save('workspace-'+label+'.json',v)
 assert status==200 and v['available']and v['configuration_verified']and v['generation']==generation and v['state']==state
 return v
def fingerprint(v):return hashlib.sha256(v['name'].encode()).hexdigest()[:20]+':'+str(v['revision'])+':'+hashlib.sha256(json.dumps(v,separators=(',',':')).encode()).hexdigest()[:24]
def control(action,name,entry=None,policy=None,pending=None):
 request=secrets.token_hex(16);m={'format':1,'action':action,'name':name,'expected_revision':entry['revision']if entry else 0,'expected_fingerprint':fingerprint(entry)if entry else'','policy':policy}
 save('control-'+request+'-once-intent.json',{'request_id':request,'mutation':m,'POST_maximum':1});proof['controls'].append({'request_id':request,'action':action,'name':name,'POST_attempts':1})
 status,row=api('/app-registry/load-balance/stream/controls/'+request,m);save('control-'+request+'-response.json',{'status':status,'row':row});assert status==202
 if pending:pending()
 for attempt in range(201):
  status,row=api('/app-registry/load-balance/stream/controls/'+request);save('control-'+request+'-observation-'+str(attempt)+'.json',{'status':status,'row':row});assert status==200
  if row['state']in('completed','unknown'):break
  assert row['state']in('reserved','issued')and attempt<200;time.sleep(2)
 assert row['state']=='completed'and row['result']['state']=='committed','Original control not committed; no replay or reset'
 return row
def connect_tag(port):
 s=socket.create_connection(('127.0.0.1',port),timeout=5);s.settimeout(5);tag=b''
 while len(tag)<6:
  b=s.recv(6-len(tag));assert b,'Connection closed before tag';tag+=b
 return s,tag
try:
 save('before-full105.json',capture());nss={n:sha('/etc/'+n)for n in('passwd','group','shadow','gshadow')};module=sha('/etc/panel/security-apps/modules/load-balance/installed.json')
 unit='yunzhan-qa-c15-echo-'+cohort.name.rsplit('-',1)[1][:16]
 path=pathlib.Path('/etc/systemd/system')/(unit+'.service');assert not os.path.lexists(path)
 service='[Unit]\nDescription=Owned C15 isolated loopback traffic witnesses\n[Service]\nType=exec\nExecStart=/usr/bin/python3 -I -B '+str(base/'echo.py')+'\nUser=root\nNoNewPrivileges=true\nCapabilityBoundingSet=\nProtectSystem=strict\nProtectHome=true\nPrivateTmp=true\nRestrictAddressFamilies=AF_INET AF_UNIX\nMemoryMax=256M\nTasksMax=256\nRestart=no\nRuntimeMaxSec=3h\n[Install]\nWantedBy=multi-user.target\n'
 with path.open('x')as out:out.write(service)
 os.chmod(path,0o644);save('backend-unit.json',{'path':str(path),'sha256':sha(path),'only_owned_loopback_ports':list(range(31081,31086))})
 command('backend-daemon-reload',['systemctl','daemon-reload']);command('backend-enable-start',['systemctl','enable','--now',unit+'.service'])
 for port in(31081,31082):
  for attempt in range(20):
   try:
    with socket.create_connection(('127.0.0.1',port),timeout=1)as s:assert s.recv(6)==(str(port)+'|').encode();break
   except ConnectionRefusedError:
    assert attempt<19;time.sleep(.1)
 credential=pathlib.Path('/etc/panel/first-login.json');s=credential.lstat();assert stat.S_ISREG(s.st_mode)and s.st_uid==0 and stat.S_IMODE(s.st_mode)==0o600
 access=json.loads(credential.read_bytes());client=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
 status,login=api('/login',{k:access[k]for k in('username','password')});access.clear();assert status==200;csrf=login['csrf']
 status,empty=api('/app-registry/load-balance/stream/workspace');save('workspace-initial.json',empty);assert status==200 and empty['available']and empty['state']=='empty'and empty['generation']==0 and empty['entries']==[]
 policy={'protocol':'tcp','port':41080,'nodes':[{'address':'127.0.0.1:'+str(n),'weight':1,'backup':False}for n in(31081,31082)],'method':'round-robin','connect_milliseconds':500,'session_seconds':5,'max_sessions':16,'udp_requests':0,'udp_responses':0}
 control('create','native-tcp.qa.example',policy=policy)
 first=workspace('tcp-created',1,'running');assert len(first['entries'])==1
 data=(bytes(range(256))*513)[:131076];nodes=[]
 for i in range(6):
  with socket.create_connection(('127.0.0.1',41080),timeout=8)as s:
   s.settimeout(8);tag=b''
   while len(tag)<6:
    chunk=s.recv(6-len(tag));assert chunk,'Forwarded connection closed before backend tag';tag+=chunk
   assert tag in(b'31081|',b'31082|');nodes.append(tag.decode());s.sendall(data);s.shutdown(socket.SHUT_WR);received=b''
   while True:
    b=s.recv(65536)
    if not b:break
    received+=b;assert len(received)<=len(data)
   assert received==data
 save('real-TCP-traffic.json',{'bytes_per_half_close_session':len(data),'sessions':6,'backend_tags':nodes,'sha256':hashlib.sha256(data).hexdigest(),'all_exact_payloads_echoed':True})
 assert set(nodes)=={'31081|','31082|'}
 policy={'protocol':'udp','port':41081,'nodes':[{'address':'127.0.0.1:'+str(n),'weight':1,'backup':False}for n in(31083,31084)],'method':'round-robin','connect_milliseconds':500,'session_seconds':5,'max_sessions':16,'udp_requests':1,'udp_responses':1}
 control('create','native-udp.qa.example',policy=policy);second=workspace('udp-created',2,'running');tags=[]
 for size in(16,49152,16,49152):
  data=(bytes(range(256))*193)[:size]
  with socket.socket(socket.AF_INET,socket.SOCK_DGRAM)as s:
   s.settimeout(6);s.sendto(data,('127.0.0.1',41081));reply,_=s.recvfrom(65536)
  assert reply[:6]in(b'31083|',b'31084|')and reply[6:]==data;tags.append(reply[:6].decode())
 assert set(tags)=={'31083|','31084|'};save('real-UDP-traffic.json',{'sizes':[16,49152,16,49152],'backend_tags':tags,'all_exact_payloads_echoed':True})
 # Root witnesses prove every tested destination is listening. The separate
 # no-capability UID probes then test actual kernel tuple enforcement.
 probe_code="""import os,json,socket,pathlib
status={l.split(':',1)[0]:l.split(':',1)[1].strip()for l in pathlib.Path('/proc/self/status').read_text().splitlines()if ':'in l}
assert os.geteuid()>0 and all(int(status[k],16)==0 for k in('CapInh','CapPrm','CapEff','CapBnd','CapAmb'))and status['NoNewPrivs']=='1'
tests=[('tcp','127.0.0.1',31081,True),('udp','127.0.0.1',31083,True),('tcp','127.0.0.1',31085,False),('udp','127.0.0.1',31085,False),('tcp','127.0.0.2',31081,False),('tcp','127.0.0.1',31083,False),('udp','127.0.0.1',31081,False)];results=[]
for proto,host,port,wanted in tests:
 ok=False
 try:
  with socket.socket(socket.AF_INET,socket.SOCK_STREAM if proto=='tcp'else socket.SOCK_DGRAM)as s:
   s.settimeout(.8);s.connect((host,port))
   if proto=='tcp':ok=s.recv(6)==(str(port)+'|').encode()
   else:s.send(b'probe');ok=s.recv(64)==(str(port)+'|').encode()+b'probe'
 except OSError:pass
 assert ok==wanted,(proto,host,port,ok,wanted);results.append({'protocol':proto,'address':host,'port':port,'allowed':ok})
print(json.dumps({'uid':os.geteuid(),'gid':os.getegid(),'zero_capabilities':True,'no_new_privileges':True,'results':results}))
"""
 for host,port in(('127.0.0.1',31085),('127.0.0.2',31081),('127.0.0.1',31083)):
  with socket.create_connection((host,port),timeout=2)as s:assert s.recv(6)==(str(port)+'|').encode()
 for port in(31085,31081):
  with socket.socket(socket.AF_INET,socket.SOCK_DGRAM)as s:s.settimeout(2);s.sendto(b'root-witness',('127.0.0.1',port));assert s.recv(64)==(str(port)+'|').encode()+b'root-witness'
 uid=int(command('dedicated-uid',['id','-u','panel-lbstream']));gid=int(command('dedicated-gid',['id','-g','panel-lbstream']))
 output=command('actual-UID-kernel-egress',['/usr/bin/setpriv','--reuid='+str(uid),'--regid='+str(gid),'--clear-groups','--bounding-set=-all','--inh-caps=-all','--ambient-caps=-all','--no-new-privs','/usr/bin/python3','-I','-B','-c',probe_code],20);egress=json.loads(output);assert egress['uid']==uid and egress['gid']==gid
 command('actual-nft-policy',['/usr/sbin/nft','-s','-a','-j','list','table','inet','panel_lbstream'])
 # Keep one actual old-backend connection alive while the new configuration
 # becomes externally observable, then close it normally so the drain ends.
 old_socket=None
 for attempt in range(6):
  candidate,tag=connect_tag(41080)
  if tag==b'31081|':old_socket=candidate;break
  candidate.close()
 assert old_socket is not None
 def drain_session():
  try:
   while not drain_stop.is_set():
    data=b'original-active-session';old_socket.sendall(data);reply=b''
    while len(reply)<len(data):
     b=old_socket.recv(len(data)-len(reply));assert b,'Old connection cut during drain';reply+=b
    assert reply==data;drain_count.append(1);time.sleep(.1)
   old_socket.shutdown(socket.SHUT_WR)
   assert old_socket.recv(1)==b''
  except BaseException:drain_errors.append(traceback.format_exc())
  finally:old_socket.close()
 drain_thread=threading.Thread(target=drain_session);drain_thread.start();tcp=next(v for v in second['entries']if v['name']=='native-tcp.qa.example');replacement={k:v for k,v in tcp.items()if k in policy};replacement['nodes']=[{'address':'127.0.0.1:'+str(n),'weight':1,'backup':False}for n in(31082,31083)]
 def observe_new_configuration():
  deadline=time.monotonic()+90;observed=[]
  while True:
   assert time.monotonic()<deadline and not drain_errors,'No new forwarding config before bounded drain deadline'
   s,tag=connect_tag(41080);s.close();observed.append(tag.decode())
   if tag==b'31083|':break
   time.sleep(.2)
  time.sleep(.5);drain_stop.set();drain_thread.join(8);assert not drain_thread.is_alive()and not drain_errors and len(drain_count)>=3
  save('actual-active-drain.json',{'old_backend':31081,'new_backend_observed':31083,'new_connection_tags':observed,'old_connection_echoes_during_change':len(drain_count),'old_connection_closed_normally':True})
 control('replace',tcp['name'],entry=tcp,policy=replacement,pending=observe_new_configuration);third=workspace('tcp-replaced',3,'running')
 udp=next(v for v in third['entries']if v['name']=='native-udp.qa.example');control('remove',udp['name'],entry=udp);fourth=workspace('udp-removed',4,'running')
 assert any(not v['removed']for v in fourth['entries'])
 with socket.socket(socket.AF_INET,socket.SOCK_DGRAM)as s:
  s.settimeout(1);s.sendto(b'after-native-removal',('127.0.0.1',41081))
  try:s.recv(64)
  except OSError:pass
  else:raise AssertionError('Removed UDP entry still forwards traffic')
 assert nss=={n:sha('/etc/'+n)for n in nss}and module==sha('/etc/panel/security-apps/modules/load-balance/installed.json')
 with contextlib.closing(sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True,timeout=3))as db:
  db.execute('PRAGMA query_only=ON');assert db.execute('SELECT *FROM runtime_jobs WHERE id=?',(original_job,)).fetchone()==original_job_row,'Original successful installation job changed'
 status,store=api('/app-registry');save('store-final.json',store);row=next(v for v in store['status']if v['id']=='load-balance');assert status==200 and row['installed']and row['healthy']and row['state_known']and row['installed_version']=='1.9.0'
 status,_=api('/logout',{});assert status==200;csrf='';proof.update(ok=True,TCP_131076_byte_half_close_sessions=6,both_TCP_round_robin_nodes_used=True,UDP_16_and49152_byte_datagrams_exact=True,actual_uid_address_protocol_port_egress_tests=True,active_TCP_connection_survived_replacement=True,normal_UDP_removal_and_TCP_retained=True,workspace_generation4_running_verified=True,NSS_and_module_unchanged=True,own_session_logged_out=True,cold_boot_and_browser_acceptance=False)
except BaseException:save('failure.json',{'traceback':traceback.format_exc()})
finally:
 drain_stop.set()
 if drain_thread:drain_thread.join(8)
 if csrf:
  try:api('/logout',{});csrf='';proof['own_session_logged_out']=True
  except BaseException:proof['own_session_logout_failed']=True
 try:save('after-full105.json',capture());proof['all105_fields_captured']=True;proof['owned_delta_comparison_pending']=True
 except BaseException:save('after-capture-failure.json',{'traceback':traceback.format_exc()})
 save('proof.json',proof)
print(json.dumps(proof));raise SystemExit(0 if proof['ok']else 1)
