"""Current signed integrity apps: actual owned full native guest and hard cold."""
from pathlib import Path
import socket,base64,contextlib,hashlib,http.cookiejar,json,os,platform,re,secrets,stat,subprocess,sys,time,traceback,urllib.request,urllib.error
os.umask(0o077);assert os.geteuid()==0 and len(sys.argv)==2
payload=Path(sys.argv[1]).resolve(strict=True);pins=json.loads((payload/'assets.json').read_bytes());arch={'aarch64':'arm64','x86_64':'amd64'}[platform.machine()];case=pins['OS_case']
assert pins['architecture']==arch and Path('/etc/hostname').read_text().strip()==case['hostname']and case['hostname'].startswith('c326-load-balance-')
source='5e51a17605fc0c32214e520533e246d9c22b8e7649ba12595768be867ad3f4ae';assert pins['source_inputs_sha256']==source
base=Path(sys.argv[2]).resolve(strict=True)if len(sys.argv)>2 else Path('/opt/panel-load-balance-c326-qa-'+secrets.token_hex(16));assert base.parent==Path('/opt')and re.fullmatch('panel-load-balance-c326-qa-[a-f0-9]{32}',base.name)
evidence=base/'evidence'
if len(sys.argv)==2:evidence.mkdir(mode=0o700,parents=True)
phase='prepare'if len(sys.argv)==2 else sys.argv[3]if len(sys.argv)==4 else'cold';assert phase in('prepare','pre-powerloss','cold','post-cold-browser')
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
 for identity in ('nginx','apache','php-82'):
  app=cohort['items'][identity];assert next(x for x in catalogue['catalog']['apps']if x['id']==identity)==app
  native=job('normal-managed-'+identity+'-install','/app-registry/'+identity+'/install',{'expected_version':app['version'],'expected_sha256':app['sha256']});state=api('normal-'+identity+'-installed-discovery','/app-registry?refresh=1');current=next(x for x in state['status']if x['id']==identity);assert current['state_known']and current['installed']and current['installed_version']==app['version']and not current['update_available'];installed[identity]={'original_job':native,'actual_installed_status':current}
 api('logout-before-independent-business','/logout',{})
 with(evidence/'actual-business.stdout').open('xb')as o,(evidence/'actual-business.stderr').open('xb')as e:actual=subprocess.run([sys.executable,'-I','-B',str(verified/'apache-business.py'),str(base)],stdout=o,stderr=e,timeout=1800)
 assert actual.returncode==0,'Actual original Nginx business failed; no mutation replay';business_proof=json.loads((evidence/'business-evidence'/'actual-original-business-proof.json').read_bytes());assert business_proof['ok']

 plan={'source_before':source,'source_after':source,'host':case['hostname'],'machine':hashlib.sha256(Path('/etc/machine-id').read_bytes()).hexdigest(),'architecture':arch,'platform':case['platform'],'catalogue':cohort['served_head'],'files':{n:pins['files'][n]for n in('cohort.json','acceptance.py','casebook.py')}}
 with(verified/'plan.json').open('x')as f:json.dump(plan,f);f.flush();os.fsync(f.fileno())
 save('one-current-native-WAF-business-intent.json',{'case_sha256':pins['files']['waf-business.py'],'maximum_submissions':1,'original_operation_replays':0})
 with(evidence/'actual-native-WAF-business.stdout').open('xb')as o,(evidence/'actual-native-WAF-business.stderr').open('xb')as e:waf_result=subprocess.run([sys.executable,'-I','-B',str(verified/'waf-business.py'),str(verified),str(evidence)],stdout=o,stderr=e,timeout=7200)
 assert waf_result.returncode==0,'Original current native Apache WAF business failed; no replay'
 waf_proof=json.loads((evidence/'native-current-Apache-WAF-business/evidence/original-proof.json').read_bytes());assert waf_proof['ok']and waf_proof['architecture']==arch and waf_proof['source_inputs_sha256']==source and waf_proof['actual_body_HTTP']==168 and waf_proof['body_blocked_never_reached_PHP']==32 and waf_proof['actual_held_UID33_FD_private_copy'];proof['actual_current_native_WAF_business']=waf_proof
 save('prepared.json',{'ok':True,'boot':boot,'source_inputs_sha256':source,'normal_signed_programme_installs':1,'normal_managed_runtime_installs':installed,'business':business_proof});proof.update(ok=True,apache_PHP_prepared=True,normal_signed_programmes=1,normal_managed_runtime_installs=installed,actual_Apache_PHP_business=business_proof,hard_cold_or_browser_claim_from_this_case=False)
except BaseException as e:
 proof['failure']=str(e)[:1600];save(phase+'-failure.json',{'type':type(e).__name__,'traceback':traceback.format_exc()[-7000:]})
finally:save(phase+'-result.json',proof);print(json.dumps(proof),flush=True)
sys.exit(0 if proof['ok']else 1)
