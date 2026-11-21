from pathlib import Path
import json,hashlib,http.cookiejar,urllib.request,urllib.error,secrets,os,time,re,sys,subprocess,socket,sqlite3
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
credentials=json.loads(Path('/etc/panel/first-login.json').read_bytes());csrf=api('login','/login',{k:credentials[k]for k in('username','password')})['csrf'];credentials.clear();catalogue=api('normal-store-reconciliation','/app-registry?refresh=1');status=next(x for x in catalogue['status']if x['id']=='load-balance');assert status['installed']and status['state_known']and status['installed_version']=='1.9.0';baseline=original_rows();save('original-installed-jobs-receipts-sites.json',baseline)
w=api('initial-workspace','/app-registry/load-balance/stream/workspace');assert w['available']and w['state']=='empty';report=api('initial-HTTP','/app-modules/load-balance/run',{});assert not report['entries']and not report['pending']
backend=evidence/'owned-backends.py';backend.open('x').write(r'''from pathlib import Path
import json,http.server,socketserver,threading,socket,sys,time
root=Path(sys.argv[1])
class TCP(socketserver.BaseRequestHandler):
 def handle(self):
  self.request.settimeout(15);self.request.sendall((str(self.server.server_address[1])+'|').encode())
  while True:
   b=self.request.recv(65536)
   if not b:break
   self.request.sendall(b)
  self.request.shutdown(socket.SHUT_WR)
class UDP(socketserver.BaseRequestHandler):
 def handle(self):
  b,s=self.request;s.sendto((str(self.server.server_address[1])+'|').encode()+b,self.client_address)
class HTTP(http.server.BaseHTTPRequestHandler):
 protocol_version='HTTP/1.1'
 def do_GET(self):
  health=json.loads((root/'backend-health.json').read_bytes());port=self.server.server_port;ready=health[str(port)];b=(b'READY'if ready else b'NOTREADY')if self.path=='/ready'else json.dumps({'backend':port,'path':self.path,'xff':self.headers.get('X-Forwarded-For'),'forwarded':self.headers.get('Forwarded')}).encode();self.send_response((200 if ready else 503)if self.path=='/ready'else 200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(b)));self.end_headers();self.wfile.write(b)
 def log_message(self,*a):pass
servers=[]
for kind,handler,ports in((socketserver.ThreadingTCPServer,TCP,(31081,31082,31083)),(socketserver.ThreadingUDPServer,UDP,(31084,31085)),(http.server.ThreadingHTTPServer,HTTP,(31091,31092))):
 for port in ports:
  server=kind(('127.0.0.1',port),handler);server.daemon_threads=True;server.max_packet_size=65535;servers.append(server);threading.Thread(target=server.serve_forever,daemon=True).start()
while True:time.sleep(10)
''');health=evidence/'backend-health.json';save(health.name,{'31091':True,'31092':True});unit='panel-owned-c317-backends-'+secrets.token_hex(8)+'.service';unitfile=Path('/etc/systemd/system')/unit
unitfile.open('x').write('[Unit]\nDescription=Owned C317 loopback business witnesses\nAfter=network.target\n[Service]\nType=exec\nExecStart=/usr/bin/python3 -I -B '+str(backend)+' '+str(evidence)+'\nUser=root\nNoNewPrivileges=true\nCapabilityBoundingSet=\nProtectSystem=strict\nProtectHome=true\nPrivateTmp=true\nRestrictAddressFamilies=AF_INET AF_UNIX\nMemoryMax=128M\nTasksMax=128\nRestart=no\n[Install]\nWantedBy=multi-user.target\n');os.chmod(unitfile,0o644);subprocess.run(['systemctl','daemon-reload'],check=True);subprocess.run(['systemctl','enable','--now',unit],check=True)
for port in(31081,31082,31083,31091,31092):
 for i in range(30):
  try:
   with socket.create_connection(('127.0.0.1',port),timeout=2):break
  except ConnectionRefusedError:assert i<29;time.sleep(.2)
for path in(backend,health,unitfile):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
 try:os.fsync(fd)
 finally:os.close(fd)
for path in(evidence,base,base.parent,unitfile.parent,unitfile.parent/'multi-user.target.wants'):
 fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(fd)
 finally:os.close(fd)
save('preexisting-owned-backend-durability-before-first-business.json',{'ok':True,'application_outputs_globally_flushed':False})
root='/app-modules/load-balance';domain='http-c317.example.test';settings={'domain':domain,'port':41090,'expected_revision':0,'nodes':[{'address':'127.0.0.1:'+str(p),'weight':1,'backup':False}for p in(31091,31092)]}
api('HTTP-create',root+'/save',settings)
def http_samples(label,wanted):
 values=[]
 for i in range(12):
  path='/c317-business?sample='+str(i);req=urllib.request.Request('http://127.0.0.1:41090'+path,headers={'Host':domain})
  with urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect()).open(req,timeout=8)as r:assert r.status==200;v=json.load(r)
  assert v['path']==path;values.append(v)
 assert {v['backend']for v in values}==wanted;save(label+'.json',values)
http_samples('HTTP-round-robin',{31091,31092});settings['expected_revision']=1;settings['sticky']=True;api('HTTP-sticky',root+'/save',settings)
values=[]
for i in range(10):
 with urllib.request.urlopen(urllib.request.Request('http://127.0.0.1:41090/sticky',headers={'Host':domain}),timeout=8)as r:values.append(json.load(r)['backend'])
assert len(set(values))==1;save('HTTP-sticky-real-flows.json',values);api('HTTP-stale-revision-refused',root+'/save',settings,(400,409))
settings.update(expected_revision=2,sticky=False,health_check={'path':'/ready','interval':30,'timeout_ms':1000,'expected_status':200,'body_contains':'READY','failures':1,'successes':1,'auto_traffic':True},confirm='ENABLE HEALTH ROUTING '+domain);api('HTTP-enable-explicit-health-routing',root+'/save',settings);api('HTTP-health-baseline',root+'/check-http',{'domain':domain,'expected_revision':3})
def set_health(a,b):
 with health.open('w')as f:json.dump({'31091':a,'31092':b},f);f.flush();os.fsync(f.fileno())
set_health(False,True);api('HTTP-health-A-down',root+'/check-http',{'domain':domain,'expected_revision':3});http_samples('HTTP-failover-to-B',{31092});set_health(True,True);api('HTTP-health-A-recovered',root+'/check-http',{'domain':domain,'expected_revision':3});http_samples('HTTP-recovered-round-robin',{31091,31092})
module='/app-registry/load-balance/stream';controls=[]
def fingerprint(entry):return hashlib.sha256(entry['name'].encode()).hexdigest()[:20]+':'+str(entry['revision'])+':'+hashlib.sha256(json.dumps(entry,separators=(',',':')).encode()).hexdigest()[:24]
def control(action,name,policy=None,entry=None):
 identity=secrets.token_hex(16);route=module+'/controls/'+identity;mutation={'format':1,'action':action,'name':name,'expected_revision':entry['revision']if entry else 0,'expected_fingerprint':fingerprint(entry)if entry else'','policy':policy};row=api('original-'+action,route,mutation,(202,),identity);deadline=time.monotonic()+840
 while time.monotonic()<deadline:
  row=api('same-original-readonly-poll',route)
  if row['state']in('completed','unknown'):break
  assert row['state']in('reserved','issued');time.sleep(2)
 assert row['state']=='completed'and row['result']['state']=='committed',row;controls.append(identity);return api('workspace-after-'+action,module+'/workspace')
def policy(proto,port,backends):return {'protocol':proto,'port':port,'nodes':[{'address':'127.0.0.1:'+str(p),'weight':1,'backup':False}for p in backends],'method':'round-robin','connect_milliseconds':500,'session_seconds':6,'max_sessions':16,'udp_requests':1 if proto=='udp'else 0,'udp_responses':1 if proto=='udp'else 0}
w=control('create','tcp-c317.example.test',policy('tcp',41080,(31081,31082)));assert w['generation']==1 and w['state']=='running'
def traffic(proto,port,expected):
 tags=[]
 for i in range(64 if proto=='udp'else 8):
  data=(bytes(range(256))*513)[:131076]if proto=='tcp'else(bytes(range(256))*193)[:49152 if i%2 else 16]
  with socket.socket(socket.AF_INET,socket.SOCK_STREAM if proto=='tcp'else socket.SOCK_DGRAM)as s:
   s.settimeout(10);s.connect(('127.0.0.1',port));tag=b''
   if proto=='tcp':
    while len(tag)<6:
     part=s.recv(6-len(tag));assert part,'Backend closed tag';tag+=part
    s.sendall(data);s.shutdown(socket.SHUT_WR);raw=b''
    while True:
     b=s.recv(65536)
     if not b:break
     raw+=b;assert len(raw)<=len(data)
   else:s.sendall(data);reply=s.recv(65536);tag,raw=reply[:6],reply[6:]
  save('actual-'+proto+'-'+str(len(controls))+'-sample-'+str(i)+'.json',{'sent_bytes':len(data),'received_bytes':len(raw),'sent_sha256':hashlib.sha256(data).hexdigest(),'received_sha256':hashlib.sha256(raw).hexdigest(),'tag':tag.decode()});assert raw==data and tag.decode()in expected;tags.append(tag.decode())
 save('real-'+proto+'-traffic-'+str(len(controls))+'.json',{'tags':tags,'payload_exact':True,'TCP_half_close':proto=='tcp'});assert set(tags)==set(expected),(proto,tags)
traffic('tcp',41080,('31081|','31082|'));w=control('create','udp-c317.example.test',policy('udp',41081,(31084,31085)));assert w['generation']==2 and w['state']=='running';traffic('udp',41081,('31084|','31085|'))
tcp=next(x for x in w['entries']if x['protocol']=='tcp');w=control('replace',tcp['name'],policy('tcp',41080,(31082,31083)),tcp);assert w['generation']==3;traffic('tcp',41080,('31082|','31083|'));assert original_rows()==baseline
save('before-cold-original-native-workspace.json',w);save('before-cold-original-HTTP-workspace.json',api('HTTP-before-cold-readonly-status',root));save('before-cold-native-control-history.json',api('original-control-history',module+'/controls'));proof={'ok':True,'source_inputs_sha256':source,'architecture':{'aarch64':'arm64','x86_64':'amd64'}[os.uname().machine],'HTTP_round_robin_sticky_stale_CAS_health_failover_recovery':True,'TCP_half_close_131076_exact_bytes_and_replacement':True,'UDP_16_and_49152_exact_payloads':64,'original_installed_jobs_receipts_sites_unchanged':True,'original_control_ids':controls,'original_backend_service':unit,'workspace':w,'cold_and_browser_acceptance_pending':True,'all40_commercial':False};save('actual-original-business-proof.json',proof);api('logout','/logout',{});print(json.dumps(proof))
