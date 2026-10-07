#!/usr/bin/env python3
"""Keep a private fixture between phases; verify a real isolated VM reboot."""
import base64,hashlib,json,os,pathlib,sys,time,uuid
from panel_client import PanelClient
assert os.environ.get('PANEL_VM') in ('panel-compat-ubuntu24','panel-store-apps-debian13')
p=PanelClient();out=pathlib.Path(__file__).resolve().parents[1]/os.environ['FTP_BOOT_STATE'];phase=sys.argv[1]
def module(action='run',**body):return p.api('/app-modules/pure-ftpd/'+action,body)
def save():out.write_text(json.dumps(v,indent=2)+'\n');out.chmod(0o600)
def account():return next(x for x in module()['users'] if x['username']==v['username'])
try:
 if phase=='prepare':
  assert not out.exists();r=module();assert r['account_limits_ready'] and r['service_active'] and not r['recovery_pending']
  v={'slug':'ftp-recovery-boot-'+uuid.uuid4().hex[:8],'username':'qa-ftp-boot-'+uuid.uuid4().hex[:8],'secret':uuid.uuid4().hex,'port':r['config']['port'],'passed':False,'boot_id':p.vm('cat','/proc/sys/kernel/random/boot_id').stdout.strip()};save()
  p.wait(p.api('/sites',{'name':v['slug'],'slug':v['slug'],'domain':v['slug']+'.example.test','php_version_id':''})['job_id'],timeout=180)
  v['site']=next(s['id'] for s in p.api('/sites') if s['slug']==v['slug']);save()
  p.api('/sites/'+v['site']+'/files/action',{'action':'create','path':'boot.txt','content':'r'*8192})
  module('create',site_id=v['site'],username=v['username'],password=v['secret']);module('stop');module('recount-quota',username=v['username'],expected_sha=account()['expected_sha'])
  module('account-limits',username=v['username'],expected_sha=account()['expected_sha'],quota_mb=1,quota_files=50,upload_kb=1,download_kb=1,max_sessions=1,client_allow=['127.0.0.0/8'],client_deny=['192.0.2.0/24']);module('start');v['account']=account();save()
  inject="""import base64,hashlib,json,pathlib,subprocess,sys,tempfile,uuid
v=json.load(sys.stdin);p=pathlib.Path('/etc/panel/security-apps/modules/pure-ftpd');old=(p/'users.passwd').read_bytes();db=(p/'users.pdb').read_bytes();runtime=(p/'runtime.json').read_bytes();next_runtime=runtime+b'\\n'
with tempfile.TemporaryDirectory(prefix='.boot-stage-',dir=p) as stage:
 text=pathlib.Path(stage)/'users.passwd';text.write_bytes(old);text.chmod(0o600);subprocess.run(['/opt/panel/app-modules/pure-ftpd/1.0.54-yz1/pure-pw','usermod',v['username'],'-f',str(text),'-T','16'],check=True,capture_output=True);new=text.read_bytes()
account={'id':uuid.uuid4().hex,'state':'applying','username':v['username'],'action':'QA cold boot','time':'QA','old_text':base64.b64encode(old).decode(),'old_db':base64.b64encode(db).decode(),'next_text_sha':hashlib.sha256(new).hexdigest(),'next_db_sha':hashlib.sha256(db).hexdigest()}
selection={'id':uuid.uuid4().hex,'state':'applying','old':base64.b64encode(runtime).decode(),'old_exists':True,'next_sha256':hashlib.sha256(next_runtime).hexdigest(),'was_active':True,'time':'QA'}
for name,obj in [('pending-accounts.json',account),('pending-runtime.json',selection)]:
 target=p/name;assert not target.exists();target.write_text(json.dumps(obj));target.chmod(0o600)
(p/'users.passwd').write_bytes(new);(p/'users.passwd').chmod(0o600);(p/'runtime.json').write_bytes(next_runtime);(p/'runtime.json').chmod(0o600)
print(json.dumps({'users.passwd':hashlib.sha256(old).hexdigest(),'users.pdb':hashlib.sha256(db).hexdigest(),'runtime.json':hashlib.sha256(runtime).hexdigest()}))"""
  v['sha']=json.loads(p.vm('sudo','python3','-c',inject,input=json.dumps({'username':v['username']})).stdout);v['prepared']=True;save();print('Private cold-boot FTPS quota/account/runtime fixture prepared; credentials are not printed')
 elif phase=='verify':
  v=json.loads(out.read_text());assert v['prepared'] and not v['passed'];assert v['boot_id']!=p.vm('cat','/proc/sys/kernel/random/boot_id').stdout.strip()
  r=module();assert r['service_active'] and r['account_limits_ready'] and not r['recovery_pending'];assert account()==v['account']
  for name,digest in v['sha'].items():assert p.vm('sudo','sha256sum','/etc/panel/security-apps/modules/pure-ftpd/'+name).stdout.split()[0]==digest
  transfer="""import ftplib,io,json,ssl,sys,time
v=json.load(sys.stdin);f=ftplib.FTP_TLS(context=ssl.create_default_context(cafile='/etc/panel/security-apps/modules/pure-ftpd/server.pem'));f.connect('localhost',v['port'],timeout=15);f.login(v['username'],v['secret']);f.prot_p();data=io.BytesIO();start=time.monotonic();f.retrbinary('RETR boot.txt',data.write);elapsed=time.monotonic()-start;assert data.getvalue()==b'r'*8192 and f.pwd()=='/' and 6<elapsed<16;f.quit();print('PASS')"""
  assert p.vm('sudo','python3','-c',transfer,input=json.dumps({k:v[k] for k in ('username','secret','port')})).stdout.strip()=='PASS'
  v['passed']=True;save();print('PASS real cold boot: exact split account/index/runtime recovery, limits and trusted encrypted chroot transfer')
 else:
  assert phase=='cleanup';v=json.loads(out.read_text());assert v['slug'].startswith('ftp-recovery-boot-');module('delete',username=v['username'])
  own=next(s for s in p.api('/sites') if s['id']==v['site']);assert own['slug']==v['slug'];p.wait(p.api('/sites/'+v['site'],{'confirm_domain':own['domain']},method='DELETE')['job_id'],timeout=180);v['cleaned_up']=True;save();print('Only own cold-boot FTP account removed and fixture site safely archived')
finally:p.close()
