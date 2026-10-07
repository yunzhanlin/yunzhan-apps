#!/usr/bin/env python3
"""Isolated real encrypted FTP account limits, transactions and failure proof."""
import hashlib,json,os,pathlib,time,uuid
from panel_client import PanelClient
assert os.environ.get('PANEL_VM') in ('panel-compat-ubuntu24','panel-store-apps-debian13')
root=pathlib.Path(__file__).resolve().parents[1];out=root/os.environ.get('FTP_LIMITS_STATE','.local/ftp-limits-qa.json');assert not out.exists()
p=PanelClient();p.timeout=70
v={'username':'qa-ftp-limit-'+uuid.uuid4().hex[:8],'sites':[],'passed':False,'checks':[]};secret='QA-FTPS-'+uuid.uuid4().hex;created=False
original=p.api('/app-modules/pure-ftpd/run',{})
def save():out.write_text(json.dumps(v,indent=2)+'\n');out.chmod(0o600)
def module(action='run',**body):return p.api('/app-modules/pure-ftpd/'+action,body)
def account():return next(r for r in module()['users'] if r['username']==v['username'])
def passed(message):v['checks'].append(message);save();print('PASS',message,flush=True)
def rejected(call):
 try:call()
 except RuntimeError as e:assert 'HTTP 409' in str(e),e;return
 raise AssertionError('Unsafe operation accepted')
def limits(**kw):
 r=account();body={k:r[k] for k in ('quota_mb','quota_files','upload_kb','download_kb','max_sessions','client_allow','client_deny','expected_sha')};body.update(kw);return module('account-limits',username=v['username'],**body)
def private_snapshot():return p.vm('sudo','sha256sum','/etc/panel/security-apps/modules/pure-ftpd/users.passwd','/etc/panel/security-apps/modules/pure-ftpd/users.pdb').stdout
def ftp(mode='transfer',**extra):
 code="""import ctypes,ftplib,io,json,pathlib,ssl,subprocess,sys,tempfile,time
v=json.load(sys.stdin)
def connect():
 f=ftplib.FTP_TLS(context=ssl.create_default_context(cafile='/etc/panel/security-apps/modules/pure-ftpd/server.pem'));f.connect('localhost',v['port'],timeout=25);f.login(v['username'],v['password']);f.prot_p();return f
if v['mode']=='denied':
 try:f=connect()
 except ftplib.all_errors as e:assert str(e).startswith(('421','530'));print('PASS');sys.exit(0)
 raise AssertionError('Blocked IP or old password logged in')
if v['mode']=='quota-curl':
 with tempfile.TemporaryDirectory(prefix='qa-ftps-quota-') as directory:
  payload=pathlib.Path(directory)/'payload';payload.write_bytes(b'c'*2097152)
  config='url = "ftp://localhost:'+str(v['port'])+'/denied-curl.txt"\\nuser = "'+v['username']+':'+v['password']+'"\\nssl-reqd\\ncacert = "/etc/panel/security-apps/modules/pure-ftpd/server.pem"\\nupload-file = "'+str(payload)+'"\\nsilent\\nwrite-out = "%{response_code}"\\nmax-time = 25\\n'
  result=subprocess.run(['curl','--config','-'],input=config,text=True,capture_output=True)
  response=result.stdout.strip();allowed=v.get('expect_allowed',False)
  if allowed:assert result.returncode==0 and response=='226',(result.returncode,response)
  else:
   # libcurl can surface a reset of the rejected upload as CURLE_SEND_ERROR
   # before reading the final control reply. A reset alone is not acceptance:
   # verify absence of the over-limit object, preservation of the existing
   # file, then repeat this exact transfer successfully after removing quota.
   assert result.returncode in (25,55) and response in ('150','552'),(result.returncode,response)
  f=connect();received=io.BytesIO();f.retrbinary('RETR keep.txt',received.write);assert received.getvalue()==b'kept-existing-website-data'
  if allowed:
   received=io.BytesIO();f.retrbinary('RETR denied-curl.txt',received.write);assert received.getvalue()==payload.read_bytes();f.delete('denied-curl.txt')
  else:
   try:f.size('denied-curl.txt')
   except ftplib.error_perm as e:assert str(e).startswith('550'),e
   else:raise AssertionError('Over-limit curl upload left a published file')
  f.quit()
 print(json.dumps({'curl_return_code':result.returncode,'response_code':response,'allowed':allowed,'original_preserved':True,'content_verified' if allowed else 'rejected_object_absent':True}));sys.exit(0)
f=connect()
if v['mode']=='sessions':
 try:other=connect()
 except ftplib.all_errors as e:assert str(e).startswith(('421','530'));f.quit();print('PASS');sys.exit(0)
 other.quit();f.quit();raise AssertionError('Concurrent session limit ignored')
if v['mode'] in ('quota-size','quota-count'):
 payload=b'q'*(2097152 if v['mode']=='quota-size' else 1024)
 try:f.storbinary('STOR denied-'+v['mode']+'.txt',io.BytesIO(payload))
 except ftplib.all_errors as e:
  if not str(e).startswith(('552','550')):
   # An intentionally aborted data TLS socket can leave libcrypto's
   # thread-local error queue populated on CPython/OpenSSL combinations.
   # OpenSSL requires an empty queue before I/O on the independent control
   # SSL object. This does not bypass TLS checks or accept a reset as a pass:
   # the actual encrypted control response must still be 552/550.
   ctypes.CDLL('libcrypto.so.3').ERR_clear_error()
   try:f.voidresp()
   except ftplib.error_perm as control_error:e=control_error
  assert str(e).startswith(('552','550')),str(e);f.close();print('PASS');sys.exit(0)
 f.quit();raise AssertionError('FTP quota not enforced')
if v['mode']=='bandwidth':
 data=b's'*v.get('bytes',65536);start=time.monotonic();f.storbinary('STOR speed.txt',io.BytesIO(data));upload=time.monotonic()-start;received=io.BytesIO();start=time.monotonic();f.retrbinary('RETR speed.txt',received.write);download=time.monotonic()-start;assert received.getvalue()==data and upload>=v.get('min_seconds',3) and download>=v.get('min_seconds',3) and upload<v.get('max_seconds',20) and download<v.get('max_seconds',20),(upload,download);f.quit();print(json.dumps({'upload_seconds':upload,'download_seconds':download}));sys.exit(0)
received=io.BytesIO();f.retrbinary('RETR keep.txt',received.write);assert received.getvalue()==b'kept-existing-website-data' and f.pwd()=='/';f.quit();print('PASS')"""
 body={'mode':mode,'username':v['username'],'password':secret,'port':original['config']['port']};body.update(extra)
 result=p.vm('sudo','python3','-c',code,input=json.dumps(body),check=False)
 if result.returncode:raise AssertionError(result.stderr.replace(secret,'[redacted]').replace(body['password'],'[redacted]'))
 return result.stdout.strip()
try:
 save();assert original['service_active'] and not original['recovery_pending']
 slug='ftp-limits-'+uuid.uuid4().hex[:8];p.wait(p.api('/sites',{'name':slug,'slug':slug,'domain':slug+'.example.test','php_version_id':''})['job_id'],timeout=180)
 site=next(s['id'] for s in p.api('/sites') if s['slug']==slug);v['sites'].append(site);save()
 p.api('/sites/'+site+'/files/action',{'action':'create','path':'keep.txt','content':'kept-existing-website-data'})
 module('create',site_id=site,username=v['username'],password=secret);created=True
 assert ftp()=='PASS';before=private_snapshot();old=account()
 rejected(lambda:module('account-limits',username=v['username'],expected_sha='0'*64,upload_kb=8));assert private_snapshot()==before
 rejected(lambda:limits(client_allow=['example.test']));assert private_snapshot()==before
 rejected(lambda:module('recount-quota',username=v['username'],expected_sha=old['expected_sha']));assert private_snapshot()==before
 rejected(lambda:limits(quota_mb=1));assert private_snapshot()==before
 passed('Actual TLS chroot transfer; stale account, DNS input, live recount and uninitialized quota rejected without changing either account database')
 limits(client_allow=['192.0.2.0/24']);assert ftp('denied')=='PASS'
 limits(client_allow=['127.0.0.1'],client_deny=['127.0.0.0/8']);assert ftp('denied')=='PASS'
 limits(client_allow=['127.0.0.1'],client_deny=[],max_sessions=1);assert ftp('sessions')=='PASS'
 limits(client_allow=[],client_deny=[],max_sessions=0);assert ftp()=='PASS'
 passed('Real client allowlist, deny precedence and concurrent-account session rejection; clearing restrictions restores login')
 limits(upload_kb=8,download_kb=8);v['timings']=json.loads(ftp('bandwidth'))
 limits(upload_kb=1,download_kb=1);v['low_rate_timings']=json.loads(ftp('bandwidth',bytes=8192,min_seconds=6,max_seconds=16))
 limits(upload_kb=0,download_kb=0)
 assert account()['upload_kb']==0 and account()['download_kb']==0;passed('Real encrypted 64 KiB upload and download are throttled; explicit zero clears both limits')
 module('stop');stats=module('recount-quota',username=v['username'],expected_sha=account()['expected_sha']);assert stats['quota_usage_files']>=2 and stats['quota_usage_bytes']>=8192 and stats['soft_quota'];assert not module()['service_active']
 limits(quota_mb=1);module('start')
 for attempt in range(3):assert ftp('quota-size')=='PASS' and ftp()=='PASS'
 v['curl_quota_denied']=json.loads(ftp('quota-curl'));assert ftp()=='PASS'
 limits(quota_mb=0);v['curl_quota_removed']=json.loads(ftp('quota-curl',expect_allowed=True));save()
 module('stop');stats=module('recount-quota',username=v['username'],expected_sha=account()['expected_sha']);limits(quota_files=stats['quota_usage_files']);module('start');assert ftp('quota-count')=='PASS' and ftp()=='PASS'
 limits(quota_files=0);assert ftp()=='PASS';passed('Real existing-home recount, MiB/file-count upload rejection, original-file preservation and explicit quota removal')
 old_secret=secret;secret='QA-ROTATED-'+uuid.uuid4().hex;module('password',username=v['username'],password=secret);assert ftp('denied',password=old_secret)=='PASS' and ftp()=='PASS'
 assert old_secret not in json.dumps(module()) and secret not in json.dumps(p.api('/app-modules/pure-ftpd/history'))
 passed('Actual staged password rotation preserves restrictions; old credentials refused and histories contain no password')
 module('stop');before=private_snapshot()
 inject="""import base64,hashlib,json,pathlib,subprocess,sys,tempfile,uuid
v=json.load(sys.stdin);p=pathlib.Path('/etc/panel/security-apps/modules/pure-ftpd');old=(p/'users.passwd').read_bytes();db=(p/'users.pdb').read_bytes()
with tempfile.TemporaryDirectory(prefix='.qa-account-stage-',dir=p) as stage:
 text=pathlib.Path(stage)/'users.passwd';text.write_bytes(old);text.chmod(0o600);subprocess.run(['/usr/bin/pure-pw','usermod',v['username'],'-f',str(text),'-T','32'],check=True,capture_output=True);new=text.read_bytes()
job={'id':uuid.uuid4().hex,'state':'applying','username':v['username'],'action':'QA pre-commit boundary','time':'QA','old_text':base64.b64encode(old).decode(),'old_db':base64.b64encode(db).decode(),'next_text_sha':hashlib.sha256(new).hexdigest(),'next_db_sha':hashlib.sha256(db).hexdigest()};target=p/'pending-accounts.json';assert not target.exists();target.write_text(json.dumps(job));target.chmod(0o600);(p/'users.passwd').write_bytes(new);(p/'users.passwd').chmod(0o600);print(job['id'])"""
 v['recovery_id']=p.vm('sudo','python3','-c',inject,input=json.dumps({'username':v['username']})).stdout.strip();save()
 rejected(lambda:limits(upload_kb=16));p.vm('sudo','systemctl','restart','panel-pure-ftpd-recover.service');assert private_snapshot()==before and not module()['recovery_pending'];module('start');assert ftp()=='PASS'
 passed('Actual fixed boot recovery restores a split text/index transaction; new account writes refused while recovery is pending')
 v['passed']=True;save()
finally:
 if created:
  if module().get('recovery_pending'):module('recover-service')
  module('delete',username=v['username'])
 for id in v['sites']:
  own=next((s for s in p.api('/sites') if s['id']==id),None)
  if own:assert own['slug'].startswith('ftp-limits-');p.wait(p.api('/sites/'+id,{'confirm_domain':own['domain']},method='DELETE')['job_id'],timeout=180)
 if original['service_active']:module('start')
 else:module('stop')
 v['cleaned_up']=True;save();p.close()
