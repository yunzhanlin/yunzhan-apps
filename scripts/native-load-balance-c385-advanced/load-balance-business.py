from pathlib import Path
import json,hashlib,http.cookiejar,urllib.request,urllib.error,secrets,os,time,re,sys,subprocess,socket,sqlite3,threading,contextlib
os.umask(0o077);base=Path(sys.argv[1]);evidence=base/'evidence'/'business-evidence';evidence.mkdir(mode=0o700);source='00b06c3f1793b60fc41e50256d99fc2211a2a4899d11390ac059434816e6e01a';assert json.loads(Path('/opt/panel/current/SOURCE_INPUTS.json').read_bytes())['inputs_sha256']==source
origin='http://127.0.0.1:19100';csrf='';counter=0
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*a,**k):raise AssertionError('Redirect refused')
client=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect(),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
def save(n,v):
 with(evidence/n).open('x')as f:json.dump(v,f,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
def api(label,path,body=None,expected=(200,),key=None):
 global counter
 name='%04d-'%counter+label;counter+=1;raw=None if body is None else json.dumps(body,separators=(',',':')).encode();headers={'Origin':origin,'Content-Type':'application/json','X-CSRF-Token':csrf}
 if key:headers['Idempotency-Key']=key
 if raw is not None:save(name+'-intent.json',{'path':path,'body':{'private':True}if path=='/login'else body,'maximum_submissions':1,'key':key})
 try:
  with client.open(urllib.request.Request(origin+'/api'+path,raw,headers),timeout=100)as r:status=r.status;v=json.load(r)
 except urllib.error.HTTPError as r:status=r.code;v=json.load(r)
 save(name+'-response.json',{'status':status,'value':{'private_login_redacted':True}if path=='/login'else v});assert status in expected,(path,status,v.get('error'));return v

def original_rows():
 with sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True)as db:
  db.execute('PRAGMA query_only=ON');return {t:db.execute('SELECT *FROM '+t+' ORDER BY 1').fetchall()for t in('runtime_jobs','app_registry_receipts','app_registry_install_requests','load_balance_stream_install_requests','sites')}
credentials=json.loads(Path('/etc/panel/first-login.json').read_bytes());csrf=api('login','/login',{k:credentials[k]for k in('username','password')})['csrf'];credentials.clear();baseline=original_rows();save('original-installed-jobs-receipts-sites.json',baseline)
module='/app-registry/load-balance/stream';controls=[]
def fingerprint(entry):return hashlib.sha256(entry['name'].encode()).hexdigest()[:20]+':'+str(entry['revision'])+':'+hashlib.sha256(json.dumps(entry,separators=(',',':')).encode()).hexdigest()[:24]
def control(action,name,policy=None,entry=None):
 identity=secrets.token_hex(16);route=module+'/controls/'+identity;mutation={'format':1,'action':action,'name':name,'expected_revision':entry['revision']if entry else 0,'expected_fingerprint':fingerprint(entry)if entry else'','policy':policy};api('original-'+action,route,mutation,(202,),identity);deadline=time.monotonic()+840
 while time.monotonic()<deadline:
  row=api('same-original-readonly-poll',route)
  if row['state']in('completed','unknown'):break
  assert row['state']in('reserved','issued');time.sleep(1)
 assert row['state']=='completed'and row['result']['state']=='committed',row;controls.append(identity);return api('workspace-after-'+action,module+'/workspace')
def policy(port,method='round-robin',weights=(1,1),backup=False,ports=(31181,31182)):
 return {'protocol':'tcp','port':port,'nodes':[{'address':'127.0.0.1:'+str(p),'weight':weights[i],'backup':backup and i==1}for i,p in enumerate(ports)],'method':method,'connect_milliseconds':500,'session_seconds':30,'max_sessions':16,'udp_requests':0,'udp_responses':0}
def exact(s,n):
 result=b''
 while len(result)<n:
  part=s.recv(n-len(result));assert part,'Unexpected short TCP receive';result+=part
 return result
@contextlib.contextmanager
def connection(port,ip='127.0.0.1'):
 s=socket.socket();s.settimeout(8);s.bind((ip,0));s.connect(('127.0.0.1',port));tag=exact(s,6).decode();assert re.fullmatch('3118[1-6]\\|',tag)
 try:yield s,tag
 finally:s.close()
def flow(port,ip='127.0.0.1'):
 with connection(port,ip)as(s,tag):
  data=b'C385-business-'+secrets.token_bytes(32);s.sendall(data);s.shutdown(socket.SHUT_WR);raw=b''
  while True:
   part=s.recv(65536)
   if not part:break
   raw+=part;assert len(raw)<=len(data)
  assert raw==data;return tag
backend_root=Path('/usr/local/lib')/('panel-owned-c385-'+secrets.token_hex(8));backend_root.mkdir(mode=0o755);backend_root.chmod(0o755);backend=backend_root/'backend.py'
backend.open('x').write("import socketserver,sys\nclass H(socketserver.BaseRequestHandler):\n def handle(self):\n  self.request.settimeout(90);self.request.sendall((str(self.server.server_address[1])+'|').encode())\n  while True:\n   data=self.request.recv(65536)\n   if not data:break\n   self.request.sendall(data)\n  self.request.shutdown(1)\nclass S(socketserver.ThreadingTCPServer):allow_reuse_address=True;daemon_threads=True\nwith S(('127.0.0.1',int(sys.argv[1])),H)as s:s.serve_forever()\n");backend.chmod(0o644)
units={};submitted=[]
def system(label,args):
 save(label+'-intent.json',{'args':args,'maximum_submissions':1});r=subprocess.run(args,capture_output=True,timeout=30);save(label+'-result.json',{'exit':r.returncode,'stdout':r.stdout.decode(errors='replace'),'stderr':r.stderr.decode(errors='replace')});assert r.returncode==0;return r
try:
 for p in(31181,31182,31183,31184,31185,31186):
  unit='panel-owned-c385-'+str(p)+'-'+secrets.token_hex(6)+'.service';units[p]=unit;file=Path('/etc/systemd/system')/unit
  file.open('x').write('[Unit]\nDescription=Owned bounded C385 TCP backend\n[Service]\nType=exec\nExecStart=/usr/bin/python3 -I -B '+str(backend)+' '+str(p)+'\nUser=nobody\nGroup=nogroup\nNoNewPrivileges=true\nCapabilityBoundingSet=\nPrivateTmp=true\nProtectSystem=strict\nProtectHome=true\nRestrictAddressFamilies=AF_INET AF_UNIX\nMemoryMax=32M\nTasksMax=20\nRestart=no\n');file.chmod(0o644)
 system('owned-backends-daemon-reload',['systemctl','daemon-reload'])
 for p,u in units.items():
  submitted.append(u);system('owned-backend-start-'+str(p),['systemctl','start',u])
  for i in range(40):
   try:
    with socket.create_connection(('127.0.0.1',p),timeout=1)as s:assert exact(s,6)==(str(p)+'|').encode()
    break
   except ConnectionRefusedError:assert i<39;time.sleep(.1)
 w=api('original-empty-workspace',module+'/workspace');assert w['available']and w['state']=='empty'and w['generation']==0
 w=control('create','weighted-c385.example.test',policy(41182,weights=(1,3)));weighted=next(e for e in w['entries']if e['name']=='weighted-c385.example.test')
 tags=[flow(41182)for _ in range(40)];save('actual-weighted-40-flows.json',{'tags':tags,'expected_ratio':'1:3'});assert tags.count('31181|')==10 and tags.count('31182|')==30
 w=control('create','least-c385.example.test',policy(41183,method='least-connections'))
 with connection(41183)as(held,tag):
  held.sendall(b'held-active');assert exact(held,11)==b'held-active';other='31182|'if tag=='31181|'else'31181|';tags=[]
  for _ in range(8):tags.append(flow(41183));time.sleep(.03)
  save('actual-least-connections-before-assert.json',{'held':tag,'completed':tags});assert tags==[other]*8;held.sendall(b'still-open');assert exact(held,10)==b'still-open';save('actual-least-connections-live-session.json',{'held_backend':tag,'new_completed_flows':tags,'held_session_still_usable':True})
 w=control('create','source-c385.example.test',policy(41184,method='source-ip'))
 clients={}
 for i in range(1,13):
  ip='127.0.0.'+str(i);tags=[flow(41184,ip)for _ in range(3)];save('source-IP-'+str(i)+'-before-assert.json',{'ip':ip,'tags':tags});assert len(set(tags))==1;clients[ip]=tags
 save('actual-source-IP-12-clients-36-flows.json',{'clients':clients});assert {v[0]for v in clients.values()}=={'31181|','31182|'}
 w=control('create','backup-c385.example.test',policy(41185,backup=True));tags=[flow(41185)for _ in range(8)];save('actual-backup-primary-before-assert.json',{'tags':tags});assert tags==['31181|']*8
 system('owned-primary-backend-stop',['systemctl','stop',units[31181]])
 tags=[flow(41185)for _ in range(8)];save('actual-backup-after-failure-before-assert.json',{'tags':tags});assert tags==['31182|']*8;save('actual-backup-failover.json',{'before_failure_primary_flows':8,'primary_owned_unit_stopped':True,'backup_flows':tags})
 system('owned-primary-backend-restart',['systemctl','start',units[31181]])
 for i in range(40):
  try:
   with socket.create_connection(('127.0.0.1',31181),timeout=1)as s:assert exact(s,6)==b'31181|'
   break
  except ConnectionRefusedError:assert i<39;time.sleep(.1)
 start=time.monotonic();samples=[];recovered=False
 try:
  for i in range(120):
   tag=flow(41185);samples.append({'seconds_after_backend_ready':round(time.monotonic()-start,6),'backend':tag})
   if tag=='31181|':recovered=True;break
   time.sleep(.1)
 finally:save('actual-original-primary-recovery-transition.json',{'recovered':recovered,'samples':samples,'maximum_observation_seconds':12})
 assert recovered,'Original passive primary did not recover within bounded observations'
 tags=[flow(41185)for _ in range(8)];save('actual-original-primary-recovered-stability.json',{'tags':tags});assert tags==['31181|']*8
 w=control('create','drain-c385.example.test',policy(41186,ports=(31183,31184)));entry=next(e for e in w['entries']if e['name']=='drain-c385.example.test')
 with connection(41186)as(held,oldtag):
  heartbeat=[];failures=[];done=threading.Event()
  def keepalive():
   try:
    while not done.is_set():
     data=b'C385-old-session-'+len(heartbeat).to_bytes(4,'big');held.sendall(data);assert exact(held,len(data))==data;heartbeat.append(hashlib.sha256(data).hexdigest());done.wait(.25)
   except BaseException as e:failures.append(type(e).__name__)
  thread=threading.Thread(target=keepalive,daemon=True);thread.start()
  try:w=control('replace',entry['name'],policy(41186,ports=(31185,31186)),entry)
  finally:
   done.set();thread.join(timeout=10);save('actual-heartbeat-during-original-replacement.json',{'heartbeat_roundtrips':len(heartbeat),'sha256':heartbeat,'failures':failures,'thread_joined':not thread.is_alive()})
  assert not thread.is_alive()and not failures and heartbeat
  tags=[flow(41186)for _ in range(8)];save('actual-new-generation-new-backends-only.json',{'tags':tags});assert set(tags)=={'31185|','31186|'}
  data=bytes(range(256))*129;held.sendall(data);held.shutdown(socket.SHUT_WR);received=b''
  while True:
   part=held.recv(65536)
   if not part:break
   received+=part;assert len(received)<=len(data)
  save('actual-original-held-session-after-new-commit.json',{'original_backend':oldtag,'sent_bytes':len(data),'received_bytes':len(received),'sent_sha256':hashlib.sha256(data).hexdigest(),'received_sha256':hashlib.sha256(received).hexdigest(),'half_close_completed':True});assert received==data
 for i in range(60):
  w=api('readonly-retiring-worker-poll',module+'/workspace')
  if w['retiring_workers']==0:break
  assert i<59;time.sleep(.1)
 assert original_rows()==baseline
 proof={'ok':True,'source_inputs_sha256':source,'scope':'Actual fresh signed AMD64 advanced TCP business only; no HTTP UDP browser or cold claim from this case','architecture':{'aarch64':'arm64','x86_64':'amd64'}[os.uname().machine],'actual_weighted_1_to_3_40_flows':True,'actual_least_connections_held_session_and_8_flows':True,'actual_source_IP_12_clients_36_flows':True,'actual_backup_primary_stop_and_bounded_recovery':True,'actual_original_connection_survives_new_generation_and_old_backend_egress_retirement':True,'actual_primary_first_recovered_seconds':samples[-1]['seconds_after_backend_ready'],'original_old_connection_post_commit_exact_bytes':len(data),'retiring_workers_after_original_exit':w['retiring_workers'],'original_installed_jobs_receipts_sites_exact':True,'original_control_ids':controls,'workspace':w,'all40_commercial':False};save('actual-original-business-proof.json',proof);api('logout','/logout',{});print(json.dumps(proof))
finally:
 for u in submitted:
  r=subprocess.run(['systemctl','stop',u],capture_output=True,timeout=30);save('owned-cleanup-'+u+'.json',{'exit':r.returncode});assert r.returncode==0
