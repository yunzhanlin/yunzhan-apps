"""Current signed PHP82/83 native source installs and real managed-site switching."""
from pathlib import Path
import tarfile,socket,base64,contextlib,hashlib,http.cookiejar,json,os,platform,re,secrets,stat,subprocess,sys,time,traceback,urllib.request,urllib.error
os.umask(0o077);assert os.geteuid()==0 and len(sys.argv)in(2,3)
payload=Path(sys.argv[1]).resolve(strict=True);pins=json.loads((payload/'assets.json').read_bytes());arch={'aarch64':'arm64','x86_64':'amd64'}[platform.machine()];case=pins['OS_case']
assert pins['architecture']==arch and Path('/etc/hostname').read_text().strip()==case['hostname']and case['hostname'].startswith('c326-load-balance-')
source='b223c28247d9d20e50a356643a9744a9ab174068dd567a2c57f15c342934c15f';assert pins['source_inputs_sha256']==source
base=Path(sys.argv[2]).resolve(strict=True)if len(sys.argv)>2 else Path('/opt/panel-load-balance-c326-qa-'+secrets.token_hex(16));assert base.parent==Path('/opt')and re.fullmatch('panel-load-balance-c326-qa-[a-f0-9]{32}',base.name)
evidence=base/'evidence'
if len(sys.argv)==2:evidence.mkdir(mode=0o700,parents=True)
phase='prepare'if len(sys.argv)==2 else'cold';assert phase in('prepare','pre-powerloss','cold','post-cold-browser')
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
 if raw is not None:save(n+'-intent.json',{'path':path,'body_sha256':hashlib.sha256(raw).hexdigest(),'body':{'private':True}if path in('/login','/app-modules/files-sync/save-remote')else body,'key':key,'maximum_submissions':1})
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
def command(label,args,input=None,timeout=60):
 save(label+'-command-intent.json',{'args':args,'maximum_submissions':1})
 r=subprocess.run(args,input=input,capture_output=True,timeout=timeout);save(label+'-command-outcome.json',{'exit':r.returncode,'stdout_sha256':hashlib.sha256(r.stdout).hexdigest(),'stderr_sha256':hashlib.sha256(r.stderr).hexdigest()});assert r.returncode==0,(label,r.stderr[-500:]);return r.stdout

def job(label,path,body):
 accepted=api(label,path,body,202,secrets.token_hex(16));identity=accepted['job_id'];assert re.fullmatch('[a-f0-9]{32}',identity)
 for _ in range(5400):
  v=api(label+'-poll','/jobs/'+identity)
  if v['state']not in('queued','running'):
   assert v['state']=='succeeded',(label,v.get('error'));return v
  time.sleep(1)
 raise TimeoutError('Original job unresolved; no replay')

proof={'ok':False,'phase':phase,'architecture':arch,'base':str(base),'source_inputs_sha256':source,'boot':boot,'Main_changed':False,'all40_commercial':False}
try:
 if phase=='prepare':
  for n,h in pins['files'].items():assert sha(payload/n)==h,n
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
  ready();login();cohort=json.loads((verified/'cohort.json').read_bytes());catalogue=api('ordinary-signed-source-refresh','/app-registry?refresh=1');assert catalogue['source']['resolved_commit']==cohort['served_head']and not catalogue['source']['stale']and len(catalogue['catalog']['apps'])==40
  installed={}
  for identity in ('nginx','docker-manager','files-sync'):
   app=cohort['apps'][identity];assert next(x for x in catalogue['catalog']['apps']if x['id']==identity)==app
   native=job('normal-managed-'+identity+'-install','/app-registry/'+identity+'/install',{'expected_version':app['version'],'expected_sha256':app['sha256']});state=api('normal-'+identity+'-installed-discovery','/app-registry?refresh=1');current=next(x for x in state['status']if x['id']==identity);assert current['state_known']and current['installed']and current['installed_version']==app['version']and not current['update_available'];installed[identity]={'original_job':native,'actual_installed_status':current}
  api('logout-before-independent-business','/logout',{})
  actuals={}
  for slot in('81','80'):
   save('one-current-PHP-'+slot+'-business-intent.json',{'case_sha256':pins['files']['php-isolated-business.py'],'maximum_submissions':1,'original_operation_replays':0})
   with(evidence/('actual-PHP-'+slot+'-business.stdout')).open('xb')as o,(evidence/('actual-PHP-'+slot+'-business.stderr')).open('xb')as e:r=subprocess.run([sys.executable,'-I','-B',str(verified/'php-isolated-business.py'),str(evidence),slot],stdout=o,stderr=e,timeout=2400)
   actual=json.loads((evidence/('business-phase1-'+slot)/'original-proof.json').read_bytes());assert r.returncode==0 and actual['ok']and actual['architecture']==arch and actual['source_inputs_sha256']==source,('original-PHP-business-failed',slot)
   actuals[slot]=actual
  proof.update(ok=True,PHP_isolated_business_prepared=True,normal_signed_programmes=1,normal_managed_runtime_installs=installed,actual_current_PHP_isolated_business=actuals,hard_cold_or_browser_claim_from_this_case=False)
 
  volumes=Path('/var/lib/docker/volumes');snapshot={}
  for p in volumes.rglob('*'):
   st=p.lstat()
   if p.is_file()and not p.is_symlink()and '/_data/'in str(p):snapshot[str(p)]={'sha256':sha(p),'size':st.st_size,'uid':st.st_uid,'gid':st.st_gid,'mode':stat.S_IMODE(st.st_mode),'inode':st.st_ino,'links':st.st_nlink}
  assert snapshot;save('warm-original-volume-files.json',snapshot)
 else:
  
   ready();login();warm=json.loads((evidence/'prepare-result.json').read_bytes());assert warm['ok']and warm['boot']!=boot and warm['source_inputs_sha256']==source
   actuals=warm['actual_current_PHP_isolated_business'];assert set(actuals)=={'80','81'}
   cold_actual={}
   for slot,v in actuals.items():
    for _ in range(90):
     state=api('cold-project-'+slot,'/docker/projects');project=next(x for x in state['projects']if x['id']==v['project_id'])
     if project['state']=='running'and project['healthy']==project['running']==project['services']==2:break
     time.sleep(1)
    else:raise TimeoutError('Original PHP project not healthy after cold')
    records=json.loads(command('cold-inspect-'+slot,['/usr/bin/docker','inspect',*v['container_ids'].values()]))
    byservice={r['Config']['Labels']['com.docker.compose.service']:r for r in records};assert set(byservice)=={'web','php'}
    assert all(byservice[n]['Id']==i and byservice[n]['State']['Running']for n,i in v['container_ids'].items())
    for n,r in byservice.items():assert {m['Destination']:m for m in r['Mounts']}==v['volume_mounts'][n]and r['HostConfig']['ReadonlyRootfs']and not r['HostConfig']['Privileged']
    recipe=json.loads((payload/'cohort.json').read_bytes())['recipes'][slot];assert byservice['php']['Config']['Image']==recipe['image']and not byservice['php']['HostConfig']['PortBindings']
    port=26781 if slot=='80'else 26783
    def get(path,expected=200,domain=False):
     url='http://127.0.0.1:'+('19101'if domain else str(port))+path
     headers={'Host':v['bound_domain']}if domain else{}
     try:
      with client.open(urllib.request.Request(url,headers=headers),timeout=20)as r:status=r.status;body=r.read(1<<20)
     except urllib.error.HTTPError as r:status=r.code;body=r.read(4096)
     assert status==expected,(slot,path,status);return body
    assert json.loads(get('/'))==v['fastcgi_result']and get('/retained.txt')==b'retained'and get('/c560-proof.txt')==v['retained_static_text'].encode()
    assert get('/roundtrip.php')==('c560-synced-'+recipe['version']).encode()and get('/roundtrip.php',domain=True)==('c560-synced-'+recipe['version']).encode();get('/.private.php',403)
    cold_actual[slot]={'ok':True,'original_project_and_container_ids':True,'original_volume_mounts':True,'actual_fastcgi_version_and_mysql_drivers':True,'managed_domain_and_synced_files':True,'hidden_file_refused':True,'no_reinstall_or_project_start_API':True}
   snapshot=json.loads((evidence/'warm-original-volume-files.json').read_bytes())
   for n,want in snapshot.items():
    p=Path(n);st=p.lstat();actual={'sha256':sha(p),'size':st.st_size,'uid':st.st_uid,'gid':st.st_gid,'mode':stat.S_IMODE(st.st_mode),'inode':st.st_ino,'links':st.st_nlink};assert actual==want,n
   proof.update(ok=True,clean_whole_machine_cold=True,original_boot=warm['boot'],original_volume_files_preserved=len(snapshot),actual_current_PHP_isolated_cold=cold_actual,hard_powerloss_claimed=False,application_control_POSTs=0)
   api('cold-logout','/logout',{})
except BaseException as e:
 proof['failure']=str(e)[:1600];save(phase+'-failure.json',{'type':type(e).__name__,'traceback':traceback.format_exc()[-7000:]})
finally:save(phase+'-result.json',proof);print(json.dumps(proof),flush=True)
sys.exit(0 if proof['ok']else 1)
