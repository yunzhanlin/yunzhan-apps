"""Actual account permission and durable lifecycle contract on owned signed CI hosts."""
import contextlib,hashlib,http.cookiejar,json,os,platform,re,secrets,sqlite3,subprocess,sys,time,traceback,urllib.error,urllib.request
from pathlib import Path
os.umask(0o077)
assert os.geteuid()==0 and os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('GITHUB_REPOSITORY')=='yunzhanlin/yunzhan-apps'
evidence=Path(sys.argv[1]).resolve(strict=True);out=evidence/'business-phase1';out.mkdir(mode=0o700)
plan=json.loads((Path(__file__).parent/'cohort.json').read_bytes());arch={'x86_64':'amd64','aarch64':'arm64'}[platform.machine()]
assert json.loads(Path('/opt/panel/current/SOURCE_INPUTS.json').read_bytes())['inputs_sha256']==plan['source_inputs_sha256']
origin='http://127.0.0.1:19100';module='/app-modules/user-manager';registry='/app-registry/user-manager'
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*args,**kwargs):raise AssertionError('Unexpected redirect')
class Client:
 def __init__(self):
  self.client=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect(),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()));self.csrf=''
 def api(self,path,data=None,expected=200,key=None,csrf=None,method=None):
  headers={'Origin':origin,'Content-Type':'application/json','X-CSRF-Token':self.csrf if csrf is None else csrf}
  if data is not None:headers['Idempotency-Key']=key or secrets.token_hex(16)
  req=urllib.request.Request(origin+'/api'+path,None if data is None else json.dumps(data).encode(),headers,method=method)
  try:
   with self.client.open(req,timeout=65)as response:
    raw=response.read(6<<20);assert response.status==expected,(path,response.status,expected);return json.loads(raw)
  except urllib.error.HTTPError as error:
   raw=error.read(65536)
   if error.code==503 and expected==200:raise
   assert error.code==expected,(path,error.code,expected,raw[:1000]);return json.loads(raw)
 def login(self,name,password):self.csrf=self.api('/login',{'username':name,'password':password})['csrf'];return self

def save(name,value):
 with(out/name).open('x')as stream:json.dump(value,stream,indent=2);stream.write('\n')
def ready():
 cutoff=time.monotonic()+60
 while time.monotonic()<cutoff:
  try:
   with urllib.request.urlopen(origin+'/api/ready',timeout=3)as response:
    if response.status==200:return
  except (OSError,urllib.error.URLError):pass
  time.sleep(.5)
 raise TimeoutError('Actual HTTP readiness not reached')
def wait(read,valid,limit=600):
 cutoff=time.monotonic()+limit
 while time.monotonic()<cutoff:
  value=read()
  if valid(value):return value
  time.sleep(1)
 raise TimeoutError('Actual original job did not settle')
def job(label,path,payload):
 save(label+'-original-request.json',{'path':path,'payload':payload,'maximum_submissions':1})
 submitted=admin.api(path,payload,202);jid=submitted['job_id'];assert re.fullmatch('[a-f0-9]{32}',jid)
 value=wait(lambda:admin.api('/jobs/'+jid),lambda v:v['state']in('succeeded','failed','needs_attention'))
 save(label+'-original-outcome.json',value);assert value['state']=='succeeded',label;return value
def catalog():
 for delay in(10,30,60,0):
  try:
   value=admin.api('/app-registry?refresh=1');assert not value['source']['stale'];assert value['catalog']==plan['catalogue'];assert value['host']=={'platform':'ubuntu-24.04','architecture':arch}
   item,=[x for x in value['catalog']['apps']if x['id']=='user-manager'];status,=[x for x in value['status']if x['id']=='user-manager'];assert item==plan['item']and status['supported']and status['state_known'];return item,status
  except urllib.error.HTTPError as e:
   if e.code!=503 or not delay:raise
   time.sleep(delay)
def account(name):
 report=admin.api(module+'/run',{});assert report['menu_catalog'];row,=[x for x in report['users']if x['username']==name];assert not({'password','password_hash'}&set(row));return row
def stable(row):return {k:v for k,v in row.items()if k!='sessions'}
def sql_snapshot():
 with contextlib.closing(sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True))as db:
  return {table:[[{'blob_hex':v.hex()}if isinstance(v,bytes)else v for v in row]for row in db.execute('SELECT * FROM '+table+' ORDER BY 1')]for table in('users','app_user_roles','app_user_menus','app_user_request_receipts')}
def success_count():
 with contextlib.closing(sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True))as db:
  return db.execute("SELECT count(*) FROM app_module_events WHERE module_id='user-manager' AND outcome='succeeded' AND action IN ('create','update','revoke','delete')").fetchone()[0]
import base64,email,email.policy,socket,ssl,threading,tempfile
proof={'ok':False,'architecture':arch,'version':'1.4.1','source_inputs_sha256':plan['source_inputs_sha256'],'Main_changed':False,'all40_commercial':False};servers=[]
class Receiver:
 def __init__(self,label,mode,auth,policy):
  self.label=label;self.mode=mode;self.auth=auth;self.policy=policy;self.records=[];self.messages=[];self.errors=[];self.closed=False;self.username='c253-'+label;self.password=secrets.token_hex(24)
  self.listener=socket.socket();self.listener.bind(('127.0.0.1',0));self.listener.listen(8);self.listener.settimeout(.5);self.port=self.listener.getsockname()[1]
  self.context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);self.context.minimum_version=ssl.TLSVersion.TLSv1_2;self.context.load_cert_chain(str(certdir/'leaf.pem'),str(certdir/'leaf.key'))
  self.thread=threading.Thread(target=self.loop,daemon=True);self.thread.start();servers.append(self)
 def loop(self):
  while not self.closed:
   try:conn,peer=self.listener.accept()
   except socket.timeout:continue
   except OSError:break
   trace={'peer_is_loopback':peer[0]=='127.0.0.1','commands':[],'TLS':False,'authenticated':False,'DATA_seen':False};self.records.append(trace)
   try:
    conn.settimeout(12)
    if self.mode=='tls':conn=self.context.wrap_socket(conn,server_side=True);trace['TLS']=True
    stream=conn.makefile('rwb',buffering=0)
    def reply(line):stream.write(line.encode()+b'\r\n')
    def line():
     raw=stream.readline(16385);assert len(raw)<=16384;return raw
    reply('220 C253 owned local SMTP')
    while True:
     raw=line()
     if not raw:break
     fields=raw.rstrip(b'\r\n').split(b' ',2);verb=fields[0].decode('ascii').upper();trace['commands'].append(verb)
     if verb=='EHLO':
      reply('250-C253-local');reply('250-AUTH PLAIN LOGIN')
      if not trace['TLS']:reply('250-STARTTLS')
      reply('250 SIZE 16384')
     elif verb=='STARTTLS':
      assert not trace['TLS'];reply('220 Ready for verified TLS');stream.close();conn=self.context.wrap_socket(conn,server_side=True);stream=conn.makefile('rwb',buffering=0);trace['TLS']=True
     elif verb=='AUTH':
      assert trace['TLS']and self.auth!='none';mechanism=fields[1].decode('ascii').lower();assert mechanism==self.auth
      if mechanism=='plain':
       if len(fields)<3:reply('334 ');token=line().strip()
       else:token=fields[2]
       assert base64.b64decode(token,validate=True)==b'\0'+self.username.encode()+b'\0'+self.password.encode()
      else:
       reply('334 '+base64.b64encode(b'Username:').decode());assert base64.b64decode(line().strip(),validate=True)==self.username.encode();reply('334 '+base64.b64encode(b'Password:').decode());assert base64.b64decode(line().strip(),validate=True)==self.password.encode()
      trace['authenticated']=True;reply('235 Authenticated')
     elif verb=='MAIL':assert trace['TLS']and(self.auth=='none'or trace['authenticated']);reply('250 Sender accepted')
     elif verb=='RCPT':
      if self.policy=='permanent':reply('550 Owned permanent refusal')
      else:reply('250 Recipient accepted')
     elif verb=='DATA':
      assert trace['TLS']and(self.auth=='none'or trace['authenticated']);trace['DATA_seen']=True;reply('354 Send bounded message');parts=[]
      while True:
       part=line();assert part
       if part==b'.\r\n':break
       parts.append(part[1:]if part.startswith(b'..')else part);assert sum(map(len,parts))<=16384
      data=b''.join(parts);self.messages.append(data);trace['message_sha256']=hashlib.sha256(data).hexdigest()
      if self.policy=='retry'and len(self.messages)==1:trace['DATA_reply']=451;reply('451 Owned temporary refusal')
      else:trace['DATA_reply']=250;reply('250 Accepted by owned relay')
      if self.policy=='quit-drop':break
     elif verb=='QUIT':reply('221 Goodbye');break
     elif verb=='RSET':reply('250 Reset')
     else:raise AssertionError('Unexpected own SMTP command '+verb)
   except ssl.SSLError:trace['TLS_rejected']=True
   except BaseException as error:self.errors.append(type(error).__name__+':'+str(error))
   finally:
    with contextlib.suppress(Exception):stream.close()
    with contextlib.suppress(Exception):conn.close()
 def stop(self):self.closed=True;self.listener.close();self.thread.join(timeout=2)
def row(channel,event):
 rows=admin.api('/notification-channels/'+channel['id']+'/deliveries')['deliveries'];return next((r for r in rows if r['event_id']==event),None)
def cipher(channel):
 with contextlib.closing(sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True))as db:return db.execute('SELECT credential FROM notification_channels WHERE id=?',(channel['id'],)).fetchone()[0]
def report_snapshot():
 with contextlib.closing(sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True))as db:return[list(r)for r in db.execute('SELECT day,report,created_at FROM app_daily_reports ORDER BY day')]
try:
 ready();first=json.loads(Path('/etc/panel/first-login.json').read_bytes());admin=Client().login(first['username'],first['password']);first.clear();catalog=admin.api('/app-registry?refresh=1');assert not catalog['source']['stale']and catalog['catalog']==plan['catalogue'];item,=[a for a in catalog['catalog']['apps']if a['id']=='daily-report'];assert item==plan['item']
 job('normal-signed-daily-install','/app-registry/daily-report/install',{'expected_version':item['version'],'expected_sha256':item['sha256']});admin.api('/app-registry?refresh=1');assert admin.api('/app-modules/daily-report')['status']['version']=='1.4.1'
 schedule=admin.api('/app-modules/daily-report/schedule');configured=admin.api('/app-modules/daily-report/schedule',{'time_zone':'UTC','local_time':'23:59','expected_revision':schedule['revision']});assert configured['time_zone']=='UTC'
 site=job('own-private-site','/sites',{'name':'C253 private canary','slug':'c253-private','domain':'c253-private.example.test','php_version_id':''});admin.api('/app-modules/daily-report/run',{});original_reports=report_snapshot();assert original_reports;admin.api('/app-modules/daily-report/report-detail',{'resource_id':original_reports[-1][0]});assert report_snapshot()==original_reports
 certdir=Path(tempfile.mkdtemp(prefix='c253-owned-smtp-',dir='/var/lib'));ca=certdir/'ca.pem'
 commands=[['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(certdir/'ca.key'),'-out',str(ca),'-days','2','-subj','/CN=C253 owned QA CA','-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign'],['openssl','req','-new','-newkey','rsa:2048','-nodes','-keyout',str(certdir/'leaf.key'),'-out',str(certdir/'leaf.csr'),'-subj','/CN=127.0.0.1']]
 for args in commands:subprocess.run(args,check=True,capture_output=True,timeout=30)
 (certdir/'leaf.ext').write_text('basicConstraints=critical,CA:FALSE\nsubjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\n')
 subprocess.run(['openssl','x509','-req','-in',str(certdir/'leaf.csr'),'-CA',str(ca),'-CAkey',str(certdir/'ca.key'),'-CAcreateserial','-out',str(certdir/'leaf.pem'),'-days','2','-extfile',str(certdir/'leaf.ext')],check=True,capture_output=True,timeout=30)
 outcomes={};configurations={};cases=[('implicit-plain-retry','tls','plain','retry'),('starttls-login-quit-drop','starttls','login','quit-drop'),('implicit-no-auth','tls','none','success'),('bad-certificate-name','tls','plain','bad-name'),('permanent-550','tls','none','permanent')]
 for label,mode,auth,policy in cases:
  receiver=Receiver(label,mode,auth,policy);smtp={'host':'127.0.0.1','port':receiver.port,'tls_mode':mode,'server_name':'wrong.example.test'if policy=='bad-name'else'127.0.0.1','ca_pem':ca.read_text(),'auth_mode':auth,'username':receiver.username if auth!='none'else'','password':receiver.password if auth!='none'else'','from':'sender@example.test','to':['receiver@example.test']}
  payload={'name':'Owned C253 '+label,'type':'smtp','enabled':True,'kinds':['daily'],'smtp':smtp};channel=admin.api('/notification-channels',payload);assert channel['enabled']and channel['type']=='smtp';serialized=json.dumps(channel);assert receiver.password not in serialized and receiver.username not in serialized
  original_cipher=cipher(channel);assert receiver.password.encode()not in(original_cipher.encode()if isinstance(original_cipher,str)else original_cipher)
  if auth!='none':
   channel=admin.api('/notification-channels/'+channel['id'],{**payload,'revision':channel['revision'],'smtp':{**smtp,'username':'','password':''}},method='PUT');assert channel['smtp']['username_set']and channel['smtp']['password_set']
  # Actual loopback relay only. Recipient mailbox text does not cause an external network request.
  test=admin.api('/notification-channels/'+channel['id']+'/test',{'revision':channel['revision'],'daily':True},202);event=test['event_id']
  if policy=='retry':
   pending=wait(lambda:row(channel,event),lambda v:v is not None and v['state']=='pending'and v['attempts']==1,45);assert len(receiver.messages)==1;save(label+'-original-first-temporary-failure.json',pending)
   before_pid=subprocess.check_output(['/usr/bin/systemctl','show','panel.service','--property=MainPID','--value'],text=True).strip();stored_cipher=cipher(channel);subprocess.run(['/usr/bin/systemctl','restart','panel.service'],check=True,capture_output=True,timeout=60);ready();after_pid=subprocess.check_output(['/usr/bin/systemctl','show','panel.service','--property=MainPID','--value'],text=True).strip();assert before_pid!=after_pid
   first=json.loads(Path('/etc/panel/first-login.json').read_bytes());admin=Client().login(first['username'],first['password']);first.clear();assert cipher(channel)==stored_cipher and report_snapshot()==original_reports
  if policy=='bad-name':
   rejected=wait(lambda:row(channel,event),lambda v:v is not None and v['state']=='pending'and v['attempts']==1,30);save(label+'-original-TLS-refusal-before-pause.json',rejected);assert rejected['http_status']==0 and not receiver.messages and receiver.records and all(not r['authenticated']and not r['DATA_seen']for r in receiver.records)
   channel=admin.api('/notification-channels/'+channel['id'],{'name':channel['name'],'enabled':False,'kinds':['daily'],'revision':channel['revision']},method='PUT');assert not channel['enabled']
  want='cancelled'if policy=='bad-name'else'failed'if policy=='permanent'else'succeeded';final=wait(lambda:row(channel,event),lambda v:v is not None and v['state']==want,90);save(label+'-original-delivery.json',final)
  if policy=='retry':assert final['attempts']==2 and len(receiver.messages)==2 and receiver.messages[0]==receiver.messages[1]
  elif policy=='bad-name':assert final['attempts']==1 and not receiver.messages and receiver.records and all(not r['authenticated']and not r['DATA_seen']for r in receiver.records)
  elif policy=='permanent':assert final['attempts']==1 and final['http_status']==550 and not receiver.messages and not any(r['DATA_seen']for r in receiver.records)
  else:assert final['attempts']==1 and len(receiver.messages)==1
  for message in receiver.messages:
   parsed=email.message_from_bytes(message,policy=email.policy.default);content=parsed.get_content();assert parsed['X-Yunzhan-Delivery-ID']==final['id'];assert parsed['Message-ID']=='<yunzhan.'+final['id']+'@example.test>';assert '测试'in content and '不是新生成的自动日报'in content;assert 'c253-private.example.test'not in content and '/srv/panel/'not in content and receiver.password not in content
  assert not receiver.errors,receiver.errors
  outcomes[label]={'delivery':final,'connections':len(receiver.records),'messages_received':len(receiver.messages),'message_sha256':[hashlib.sha256(m).hexdigest()for m in receiver.messages],'protocol':mode,'auth':auth,'owned_loopback_only':True};configurations[label]=(channel,receiver)
  save(label+'-original-local-receiver.json',{'records':receiver.records,'messages_base64':[base64.b64encode(m).decode()for m in receiver.messages],'errors':receiver.errors})
 # Wait beyond the ordinary15s retry window: post-DATA250 QUIT loss and permanent550 never resend.
 time.sleep(17)
 for label in('starttls-login-quit-drop','permanent-550','bad-certificate-name'):
  channel,receiver=configurations[label];assert row(channel,outcomes[label]['delivery']['event_id'])==outcomes[label]['delivery'];assert len(receiver.messages)==outcomes[label]['messages_received'];assert len(receiver.records)==outcomes[label]['connections']
 assert report_snapshot()==original_reports;save('final-original-reports.json',original_reports)
 for label,(channel,receiver)in configurations.items():admin.api('/notification-channels/'+channel['id'],{'name':channel['name'],'enabled':False,'kinds':['daily'],'revision':channel['revision']},method='PUT')
 proof.update(ok=True,manifest_sha256=item['sha256'],normal_signed_install=True,actual_tls_plain_login_and_no_auth=True,actual_451_persisted_retry_after_new_daemon_PID_same_MessageID_and_bytes=True,DATA250_followed_by_QUIT_loss_not_retried=True,certificate_name_failure_before_AUTH_and_DATA=True,certificate_failure_pending_then_explicit_pause_cancels_retry=True,SMTP550_not_automatically_retried=True,SMTP_credentials_encrypted_and_blank_edit_preserves_auth=True,manual_daily_test_marked_and_sensitive_fields_absent=True,original_report_rows_not_overwritten=True,outcomes=outcomes,SQL_writes_by_fixture=0,external_mail_recipients_contacted=0,receiver_private_keys_uploaded=False)
except BaseException:
 proof['failure']=traceback.format_exc()
 for receiver in servers:
  save(receiver.label+'-failure-original-receiver.json',{'records':receiver.records,'message_sha256':[hashlib.sha256(m).hexdigest()for m in receiver.messages],'errors':receiver.errors})
 with contextlib.suppress(Exception):save('failure-original-channel-inventory.json',admin.api('/notification-channels'))
finally:
 for receiver in servers:receiver.stop()
 save('original-proof.json',proof)
sys.exit(0 if proof['ok']else 1)
