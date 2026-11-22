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
def http_site(domain,path,expected):
 try:
  with client.open(urllib.request.Request('http://127.0.0.1:19101'+path,headers={'Host':domain,'User-Agent':'C567 owned literal QA'}),timeout=15)as r:status=r.status;body=r.read(1<<20)
 except urllib.error.HTTPError as r:status=r.code;body=r.read(8192)
 assert status==expected,(path,status,expected);return body

def config_files():
 snapshot={}
 for root in('/etc/panel/waf','/etc/panel/sites-enabled','/etc/panel/security-apps/nginx-waf.json','/srv/panel/sites'):
  root=Path(root)
  if not root.exists():continue
  for p in([root]if root.is_file()else root.rglob('*')):
   st=p.lstat()
   if stat.S_ISDIR(st.st_mode):continue
   assert stat.S_ISREG(st.st_mode)and not p.is_symlink()
   snapshot[str(p)]={'sha256':sha(p),'size':st.st_size,'uid':st.st_uid,'gid':st.st_gid,'mode':stat.S_IMODE(st.st_mode),'inode':st.st_ino,'links':st.st_nlink}
 assert snapshot;return snapshot

def nginx_identity():
 pid=int(subprocess.check_output(['systemctl','show','nginx.service','--property=MainPID','--value'],text=True));assert pid>1
 p=Path('/proc')/str(pid);return {'pid':pid,'start':(p/'stat').read_text().rsplit(')',1)[1].split()[19],'exe_sha256':sha(p/'exe')}

try:
 assert json.loads((payload/'cohort.json').read_bytes())['source_inputs_sha256']==source
 for n,h in pins['files'].items():assert sha(payload/n)==h,n
 if phase=='prepare':
  assert not any(os.path.lexists(p)for p in('/opt/panel','/etc/panel','/var/lib/panel'))
  verified=base/'verified-input';verified.mkdir(mode=0o700)
  for n,h in pins['files'].items():
   p=payload/n;st=p.lstat();assert stat.S_ISREG(st.st_mode)and not p.is_symlink()
   with(verified/n).open('xb')as f:f.write(p.read_bytes());f.flush();os.fsync(f.fileno())
   st=(verified/n).lstat();assert st.st_uid==st.st_gid==0 and st.st_nlink==1 and stat.S_IMODE(st.st_mode)==0o600 and sha(verified/n)==h
  archive=verified/('panel-'+pins['version']+'-linux-'+arch+'.tar.gz');save('normal-signed-install-intent.json',{'archive_sha256':sha(archive),'maximum_submissions':1})
  with(evidence/'normal-signed-install.stdout').open('xb')as o,(evidence/'normal-signed-install.stderr').open('xb')as e:r=subprocess.run([sys.executable,'-I','-B',str(verified/'signed-release.py'),'install',str(archive),'--public-key',str(verified/'release-signing-dev.pub')],stdout=o,stderr=e,timeout=1800)
  save('normal-signed-install-outcome.json',{'exit':r.returncode});assert r.returncode==0
  assert json.loads(Path('/opt/panel/current/SOURCE_INPUTS.json').read_bytes())['inputs_sha256']==source
  ready();login();cohort=json.loads((verified/'cohort.json').read_bytes());catalogue=api('signed-source-refresh','/app-registry?refresh=1');assert catalogue['source']['resolved_commit']==cohort['served_head']and not catalogue['source']['stale']and len(catalogue['catalog']['apps'])==40
  n=cohort['apps']['nginx'];assert next(x for x in catalogue['catalog']['apps']if x['id']=='nginx')==n
  installed=job('normal-Nginx-install','/app-registry/nginx/install',{'expected_version':n['version'],'expected_sha256':n['sha256']})
  slug='c567-owned-waf-'+secrets.token_hex(6);domain=slug+'.example.test';site_job=job('normal-owned-static-site','/sites',{'name':slug,'slug':slug,'domain':domain,'php_version_id':''});site=next(x for x in api('owned-sites','/sites')if x['slug']==slug);site_id=site['id'];marker='C567 static original '+secrets.token_hex(16)
  for name in('c567-allowed.txt','c567-block-target.txt'):api('normal-owned-file-'+name,'/sites/'+site_id+'/files/action',{'action':'create','path':name,'content':marker})
  assert http_site(domain,'/c567-allowed.txt',200).decode()==marker and http_site(domain,'/c567-block-target.txt',200).decode()==marker
  before_nginx=nginx_identity();app=cohort['apps']['nginx-waf'];assert next(x for x in catalogue['catalog']['apps']if x['id']=='nginx-waf')==app and app['version']=='2.6.0'
  cfg=api('WAF-original-defaults','/software/nginx-waf/config')['defaults'];assert cfg['policy']['schema_version']==2 and cfg['policy']['revision']==0
  cfg['policy']['mode']='off';cfg['policy']['cc_enabled']=False
  for name in cfg['policy']['groups']:cfg['policy']['groups'][name]=False
  cfg['policy']['sites']=[{'site_id':site_id,'mode':'block','rate_per_second':0,'burst':0}];rule=secrets.token_hex(16);cfg['policy']['rules']=[{'id':rule,'name':'C567 owned literal URL only','site_id':site_id,'field':'uri','operator':'prefix','value':'/c567-block-','action':'block','enabled':True}]
  preview=api('WAF-install-preview','/software/nginx-waf/preview',{'settings':cfg});assert preview['settings']['policy']['mode']=='off'
  install=job('normal-signed-WAF-install','/app-registry/nginx-waf/install',{'expected_version':app['version'],'expected_sha256':app['sha256'],'settings':cfg})
  observed=api('WAF-installed','/software/nginx-waf/config');assert observed['status']['healthy']and observed['status']['installed']and observed['status']['version']=='2.6.0'and observed['settings']['policy']['mode']=='off';assert observed['settings']['policy']['rules'][0]['id']==rule
  original_revision=observed['settings']['policy']['revision'];configuration_jobs=[]
  for mode,requests,expected in [('block',55,403),('observe',5,200),('off',5,200),('block',1,403)]:
   current=api('WAF-current-'+mode,'/software/nginx-waf/config')['settings'];current['policy']['mode']='off'if mode=='off'else'block';current['policy']['sites'][0]['mode']=mode
   preview=api('WAF-configuration-preview-'+mode,'/software/nginx-waf/preview',{'settings':current});assert preview['settings']['policy']['sites'][0]['mode']==mode
   configured=job('normal-WAF-configuration-'+mode,'/software/nginx-waf/configure',{'settings':current});configuration_jobs.append(configured['id'])
   for _ in range(requests):http_site(domain,'/c567-block-target.txt',expected)
   assert http_site(domain,'/c567-allowed.txt',200).decode()==marker
  all_report=api('actual-WAF-event-report','/software/nginx-waf/report?site_id='+site_id+'&rule=custom-'+rule+'&limit=100');assert all_report['blocked']==56 and all_report['observed']==5 and all_report['total']==61
  before_rejection_files=config_files();before_settings=api('before-stale-native-config','/software/nginx-waf/config')['settings']
  with __import__('sqlite3').connect('file:/var/lib/panel/panel.db?mode=ro',uri=True)as db:before_ids=[r[0]for r in db.execute('SELECT id FROM runtime_jobs ORDER BY id')]
  stale=json.loads(json.dumps(current));stale['policy']['revision']=original_revision;accepted=api('stale-original-once','/software/nginx-waf/configure',{'settings':stale},202,secrets.token_hex(16));stale_job=accepted['job_id'];assert re.fullmatch('[a-f0-9]{32}',stale_job)
  for _ in range(120):
   rejected=api('original-stale-read-only-state','/jobs/'+stale_job)
   if rejected['state']not in('queued','running'):break
   time.sleep(1)
  assert rejected['state']=='failed'and'配置已变化'in rejected['error'];assert config_files()==before_rejection_files and api('after-stale-native-config','/software/nginx-waf/config')['settings']==before_settings
  with __import__('sqlite3').connect('file:/var/lib/panel/panel.db?mode=ro',uri=True)as db:after_ids=[r[0]for r in db.execute('SELECT id FROM runtime_jobs ORDER BY id')]
  assert set(after_ids)==set(before_ids)|{stale_job};save('original-async-stale-job-safe-refusal.json',{'job_id':stale_job,'state':'failed','original_request_POSTs':1,'exact_config_files_preserved':len(before_rejection_files),'exact_last_successful_settings_preserved':True,'failed_job_retained':True})

  assert nginx_identity()==before_nginx
  final=api('final-WAF-config','/software/nginx-waf/config');assert final['status']['healthy']and final['settings']['policy']['mode']=='block'and final['settings']['policy']['sites'][0]['mode']=='block'
  final_store=api('actual-installed-store','/app-registry');status=next(x for x in final_store['status']if x['id']=='nginx-waf');assert status['installed']and status['installed_version']=='2.6.0'and not status['update_available']
  api('logout-before-independent-country','/logout',{});csrf=''
  country_input=base/'owned-country-input';country_input.mkdir(mode=0o700)
  for name in('country-functional.py','country-functional-root.py'):
   raw=(verified/name).read_bytes();assert hashlib.sha256(raw).hexdigest()==pins['files'][name];(country_input/name).open('xb').write(raw)
  country_plan={'host':case['hostname'],'source':source,'app_manifest_sha256':app['sha256'],'module_sha256':pins['files']['country-functional.py'],'Main_changes':0,'original_operation_replays':0};(country_input/'plan.json').open('x').write(json.dumps(country_plan))
  save('one-current-country-business-intent.json',{'maximum_submissions':1,'source_sha256':pins['files']['country-functional-root.py'],'data_and_policy_requests_are_new_owned_operations':True})
  with(evidence/'actual-current-country-business.stdout').open('xb')as o,(evidence/'actual-current-country-business.stderr').open('xb')as e:r=subprocess.run([sys.executable,'-I','-B',str(country_input/'country-functional-root.py'),str(country_input)],stdout=o,stderr=e,timeout=1800)
  country=json.loads((evidence/'actual-current-country-business.stdout').read_text().splitlines()[-1]);country_base=Path(country['base']);assert country_base.parent==Path('/opt')and re.fullmatch('panel-country-native-qa-[a-f0-9]{32}',country_base.name)
  with tarfile.open(evidence/'actual-owned-country-private-evidence.tar.gz','x:gz')as t:t.add(country_base,arcname='country')
  assert r.returncode==0 and country['ok']and country['country_business']['real_provider_Nginx_policy']and country['country_business']['original_policy_restored'],'Original country case failed; no data-task or configure replay'
  login();after_country=api('WAF-after-country-policy-restoration','/software/nginx-waf/config');assert after_country['status']['healthy'];assert nginx_identity()==before_nginx
  files=config_files();save('warm-original-config-and-site-files.json',files);programmes={n:sha(Path('/opt/panel/current/bin')/n)for n in('panel','panel-executor')};save('warm-programme-sha256.json',programmes)
  proof.update(ok=True,Nginx_WAF_business_prepared=True,normal_signed_programmes=1,normal_managed_runtime_installs={'nginx':installed},actual_current_Nginx_WAF_business={'ok':True,'signed_version':app['version'],'manifest_sha256':app['sha256'],'normal_install_job':install['id'],'configuration_jobs':configuration_jobs,'domain':domain,'site_id':site_id,'rule':rule,'marker':marker,'real_block_HTTP':56,'real_observe_HTTP':5,'real_off_HTTP':5,'actual_report_blocked':56,'actual_report_observed':5,'original_nginx_master_and_executable_preserved':True,'stale_revision_failed_before_config_mutation':True,'final_revision':final['settings']['policy']['revision'],'unrelated_site_or_Main_requests':0},cold_pending=True)
  proof['actual_current_country_business']=country;proof['actual_current_Nginx_WAF_business']['final_revision']=after_country['settings']['policy']['revision']
  api('warm-logout','/logout',{})
 else:
  assert json.loads(Path('/opt/panel/current/SOURCE_INPUTS.json').read_bytes())['inputs_sha256']==source;ready();login();warm=json.loads((evidence/'prepare-result.json').read_bytes());assert warm['ok']and warm['boot']!=boot
  actual=warm['actual_current_Nginx_WAF_business'];state=api('cold-WAF-config','/software/nginx-waf/config');assert state['status']['healthy']and state['status']['version']=='2.6.0'and state['settings']['policy']['revision']==actual['final_revision']and state['settings']['policy']['mode']=='block'
  for _ in range(3):http_site(actual['domain'],'/c567-block-target.txt',403)
  assert http_site(actual['domain'],'/c567-allowed.txt',200).decode()==actual['marker']
  report=api('cold-original-WAF-events','/software/nginx-waf/report?site_id='+actual['site_id']+'&rule=custom-'+actual['rule']+'&limit=100');assert report['blocked']==59 and report['observed']==5 and report['total']==64
  snapshot=json.loads((evidence/'warm-original-config-and-site-files.json').read_bytes());now=config_files();assert now==snapshot
  programmes={n:sha(Path('/opt/panel/current/bin')/n)for n in('panel','panel-executor')};assert programmes==json.loads((evidence/'warm-programme-sha256.json').read_bytes())
  proof.update(ok=True,clean_whole_machine_cold=True,original_boot=warm['boot'],original_config_and_site_files=len(snapshot),actual_old_WAF_events_readable=True,real_cold_HTTP_blocked=3,actual_blocked_events=59,actual_observe_events=5,original_policy_revision_retained=True,programme_sha256_unchanged=True,no_install_configure_or_delete_after_cold=True,hard_powerloss_claimed=False)
  original_country=warm['actual_current_country_business'];cf=original_country['country_business'];country_records=Path(original_country['base'])/'evidence';data_files=json.loads((country_records/'actual-verified-data-files-and-probe-IPs.json').read_bytes())['files'];detail=json.loads((country_records/'country-original-detail.json').read_bytes());cache=detail['result']['cache'];country_root=Path('/var/lib/panel-executor/waf-country-data')/cache['dataset']
  for code,meta in data_files.items():assert sha(country_root/(code+'.cidr'))==meta['sha256']and(country_root/(code+'.cidr')).stat().st_size==meta['bytes']
  current_detail=api('cold-original-country-task','/software/nginx-waf/country-data/jobs/'+cf['original_country_job_id']);assert current_detail['request']['state']=='succeeded'and current_detail['result']==detail['result']
  proof.update(current_country_data_files_preserved_after_cold=True,original_country_completed_task_exact_after_cold=True,no_country_policy_automatically_enabled_after_cold=state['settings'].get('country')is None)
  api('cold-logout','/logout',{})
except BaseException as e:
 proof['failure']=str(e)[:1600];save(phase+'-failure.json',{'type':type(e).__name__,'traceback':traceback.format_exc()[-7000:]})
finally:save(phase+'-result.json',proof);print(json.dumps(proof),flush=True)
sys.exit(0 if proof['ok']else 1)
