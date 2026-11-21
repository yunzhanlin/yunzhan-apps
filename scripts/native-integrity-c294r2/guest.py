"""Current signed integrity apps: actual owned full native guest and hard cold."""
from pathlib import Path
import base64,contextlib,hashlib,http.cookiejar,json,os,platform,re,secrets,stat,subprocess,sys,time,traceback,urllib.request,urllib.error
os.umask(0o077);assert os.geteuid()==0 and len(sys.argv)in(2,3,4)
payload=Path(sys.argv[1]).resolve(strict=True);pins=json.loads((payload/'assets.json').read_bytes());arch={'aarch64':'arm64','x86_64':'amd64'}[platform.machine()];case=pins['OS_case']
assert pins['architecture']==arch and Path('/etc/hostname').read_text().strip()==case['hostname']and case['hostname'].startswith('c294-integrity-')
source='b42832583eb74f0605d57a1360de5aa92faf3f300ab552175dd5997a918a98f3';assert pins['source_inputs_sha256']==source
base=Path(sys.argv[2]).resolve(strict=True)if len(sys.argv)>2 else Path('/opt/panel-integrity-c294-qa-'+secrets.token_hex(16));assert base.parent==Path('/opt')and re.fullmatch('panel-integrity-c294-qa-[a-f0-9]{32}',base.name)
evidence=base/'evidence'
if len(sys.argv)==2:evidence.mkdir(mode=0o700,parents=True)
phase='prepare'if len(sys.argv)==2 else sys.argv[3]if len(sys.argv)==4 else'cold';assert phase in('prepare','after-browser','cold','after-release')
boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip();counter=0;csrf='';origin='http://127.0.0.1:19100'
def sha(p):
 h=hashlib.sha256()
 with Path(p).open('rb')as f:
  for b in iter(lambda:f.read(1<<20),b''):h.update(b)
 return h.hexdigest()
def save(n,v):
 with(evidence/n).open('x')as f:json.dump(v,f,indent=2,sort_keys=True);f.write('\n');f.flush();os.fsync(f.fileno())
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*a,**kw):raise AssertionError('Unexpected redirect')
client=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect(),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
def api(label,path,body=None,expected=200,key=None):
 global counter
 n=phase+'-%04d-'%counter+label;counter+=1
 raw=None if body is None else json.dumps(body,separators=(',',':')).encode()
 if raw is not None:save(n+'-intent.json',{'path':path,'body_sha256':hashlib.sha256(raw).hexdigest(),'body':{'private':True}if path=='/login'else body,'key':key,'maximum_submissions':1})
 headers={'Origin':origin,'Content-Type':'application/json','X-CSRF-Token':csrf}
 if key:headers['Idempotency-Key']=key
 try:
  with client.open(urllib.request.Request(origin+'/api'+path,raw,headers),timeout=80)as r:status=r.status;data=r.read((8<<20)+1)
 except urllib.error.HTTPError as r:status=r.code;data=r.read((8<<20)+1)
 assert len(data)<=8<<20;value=json.loads(data);save(n+'-response.json',{'status':status,'value':{'private_login_redacted':True}if path=='/login'else value});assert status==expected,(path,status,value.get('error'));return value
def ready():
 for _ in range(100):
  try:
   with urllib.request.urlopen(origin+'/api/ready',timeout=2)as r:
    if r.status==200:return
  except Exception:pass
  time.sleep(1)
 raise TimeoutError('Normal installed panel not ready')
def login():
 global csrf
 access=json.loads(Path('/etc/panel/first-login.json').read_bytes())
 try:csrf=api('login','/login',{k:access[k]for k in('username','password')})['csrf']
 finally:access.clear()
def state(app,site):
 v=api('status-'+app,'/app-modules/'+app+'/kernel?site_id='+site);assert v['app_version']=='1.5.0'and v['cap_linux_immutable']and v['site_id']==site;return v
def mutate(app,action,v):
 site=v['site_id'];body={'site_id':site,'expected_revision':v['revision'],'expected_app_version':'1.5.0','baseline_sha':'','source_operation':'','source_sha':'','confirm':''}
 if action=='enable':body.update(baseline_sha=v['baseline_sha'],confirm='PROTECT SITE '+site)
 else:body.update(source_operation=v['latest']['request']['id'],source_sha=v['latest']['request_sha256'],confirm='RELEASE SITE '+site)
 answer=api(app+'-'+action,'/app-modules/'+app+'/kernel/'+action,body,202,secrets.token_hex(16));identity=answer['request']['id'];assert re.fullmatch('[a-f0-9]{32}',identity)
 for _ in range(180):
  v=state(app,site)
  if v.get('latest')and v['latest']['request']['id']==identity and v['latest']['state']not in('queued','running'):
   assert v['latest']['state']=='succeeded'and v['state']==('enabled'if action=='enable'else'released');return v
  time.sleep(1)
 raise TimeoutError('Original kernel operation unresolved; no replay')
def records():
 root=Path('/etc/panel/security-apps/modules/website-tamper-proof/kernel-protection');rows={};assert root.is_dir()and not root.is_symlink()
 for p in sorted(root.rglob('*')):
  s=p.lstat();assert not stat.S_ISLNK(s.st_mode)
  if stat.S_ISDIR(s.st_mode):continue
  assert stat.S_ISREG(s.st_mode)and s.st_uid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600 and s.st_size<16<<20 and len(rows)<1000
  raw=p.read_bytes();rows[str(p)]={'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw),'uid':s.st_uid,'gid':s.st_gid,'mode':stat.S_IMODE(s.st_mode),'inode':s.st_ino,'content_base64':base64.b64encode(raw).decode()}
 assert rows;return rows
def site_files(site):
 root=Path('/srv/panel/sites')/site/'public';result={}
 for p in sorted(root.rglob('*')):
  s=p.lstat();assert stat.S_ISDIR(s.st_mode)or stat.S_ISREG(s.st_mode)
  result[str(p)]={'uid':s.st_uid,'gid':s.st_gid,'mode':stat.S_IMODE(s.st_mode),'inode':s.st_ino,'bytes':s.st_size,'sha256':sha(p)if p.is_file()else''}
 return result
def writer(site,blocked):
 root=Path('/srv/panel/sites')/site/'public';code=r'''import errno,json,os,pwd,sys
u=pwd.getpwnam('www-data');os.setgroups([]);os.setgid(u.pw_gid);os.setuid(u.pw_uid);assert os.geteuid()!=0
out={}
for label,path,value in [('static',sys.argv[1],b'A'),('excluded',sys.argv[2],b'B')]:
 try:
  f=os.open(path,os.O_WRONLY|os.O_NOFOLLOW)
  try:os.pwrite(f,value,0);os.fsync(f)
  finally:os.close(f)
  out[label]=0
 except OSError as e:out[label]=e.errno
print(json.dumps(out))
'''
 r=subprocess.run(['/usr/bin/python3','-I','-B','-c',code,str(root/'static-qa.txt'),str(root/'uploads-qa/dynamic-qa.txt')],capture_output=True,timeout=20)
 assert r.returncode==0;actual=json.loads(r.stdout);assert actual=={'static':1 if blocked else 0,'excluded':0};save(phase+'-actual-nonroot-writer.json',actual)
proof={'ok':False,'phase':phase,'architecture':arch,'base':str(base),'source_inputs_sha256':source,'boot':boot,'Main_changed':False,'all40_commercial':False}
try:
 for n,h in pins['files'].items():assert sha(payload/n)==h,n
 if phase=='prepare':
  assert not any(os.path.lexists(p)for p in('/opt/panel','/etc/panel','/var/lib/panel'))
  verified=base/'verified-input';verified.mkdir(mode=0o700)
  for n,h in pins['files'].items():
   p=payload/n;s=p.lstat();assert stat.S_ISREG(s.st_mode)and not p.is_symlink()
   with(verified/n).open('xb')as f:f.write(p.read_bytes());f.flush();os.fsync(f.fileno())
   s=(verified/n).lstat();assert s.st_uid==s.st_gid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600 and sha(verified/n)==h
  archive=verified/('panel-'+pins['version']+'-linux-'+arch+'.tar.gz');save('normal-signed-install-intent.json',{'archive_sha256':sha(archive),'maximum_submissions':1})
  with(evidence/'normal-signed-install.stdout').open('xb')as o,(evidence/'normal-signed-install.stderr').open('xb')as e:r=subprocess.run([sys.executable,'-I','-B',str(verified/'signed-release.py'),'install',str(archive),'--public-key',str(verified/'release-signing-dev.pub')],stdout=o,stderr=e,timeout=1800)
  save('normal-signed-install-outcome.json',{'exit':r.returncode});assert r.returncode==0
  assert json.loads(Path('/opt/panel/current/SOURCE_INPUTS.json').read_bytes())['inputs_sha256']==source
  with(evidence/'signed-full-business.stdout').open('xb')as o,(evidence/'signed-full-business.stderr').open('xb')as e:r=subprocess.run([sys.executable,'-I','-B',str(verified/'integrity-business.py'),str(evidence)],stdout=o,stderr=e,timeout=1800)
  save('signed-full-business-outcome.json',{'exit':r.returncode});assert r.returncode==0
  business=json.loads((evidence/'business-phase1/original-proof.json').read_bytes());assert business['ok']and business['architecture']==arch and business['source_inputs_sha256']==source
  site=business['site'];assert re.fullmatch('[a-f0-9]{32}',site);ready();login();v=mutate('website-tamper-proof','enable',state('website-tamper-proof',site));assert state('enterprise-tamper-proof',site)['state']=='other-application'
  save('prepared-state.json',{'site':site,'boot':boot,'base':str(base),'protection':v,'business':business});proof.update(ok=True,normal_signed_programmes=1,integrity_prepared=True,actual_both_signed_apps_old_FD_exclusions_cross_app_and_service_restart=True,site=site)
 else:
  ready();login();prepared=json.loads((evidence/'prepared-state.json').read_bytes());site=prepared['site'];v=state('website-tamper-proof',site);assert v['state']=='enabled'and v['latest']['request']['id']==prepared['protection']['latest']['request']['id']and state('enterprise-tamper-proof',site)['state']=='other-application'
  if phase=='after-browser':
   assert boot==prepared['boot'];save('pre-cold-private-originals.json',{'boot':boot,'records':records(),'site_files':site_files(site),'NSS':{n:sha('/etc/'+n)for n in('passwd','group','shadow','gshadow')},'app_records':{n:sha('/etc/panel/security-apps/modules/'+n+'/installed.json')for n in('website-tamper-proof','enterprise-tamper-proof')}});proof.update(ok=True,powerloss_ready=True,original_records_captured=True)
  elif phase=='cold':
   before=json.loads((evidence/'pre-cold-private-originals.json').read_bytes());assert boot!=before['boot']and records()==before['records']and site_files(site)==before['site_files'];assert {n:sha('/etc/'+n)for n in before['NSS']}==before['NSS'];assert {n:sha('/etc/panel/security-apps/modules/'+n+'/installed.json')for n in before['app_records']}==before['app_records'];writer(site,True);assert records()==before['records']and site_files(site)==before['site_files'];proof.update(ok=True,prior_boot=before['boot'],actual_real_kernel_reboot=True,actual_original_protection_after_cold=True,original_operations_and_Root_bytes_owners_inodes_preserved=True)
  else:
   before=json.loads((evidence/'pre-cold-private-originals.json').read_bytes());released=mutate('website-tamper-proof','release',v);writer(site,False);after=records();assert all(after[n]==p for n,p in before['records'].items())and site_files(site)==before['site_files'];proof.update(ok=True,actual_explicit_release_and_original_records_preserved=True,release_request_id=released['latest']['request']['id'])
except BaseException:proof['failure']=traceback.format_exc()
finally:
 if csrf:
  with contextlib.suppress(Exception):api('logout','/logout',{})
 save('original-'+phase+'-proof.json',proof);print(json.dumps(proof),flush=True)
sys.exit(0 if proof['ok']else 1)
