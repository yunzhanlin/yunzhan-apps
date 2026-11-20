"""Once-only signed Apache/WAF runtime upgrade in a fresh owned Linux guest."""
from pathlib import Path
import ast,contextlib,copy,hashlib,http.cookiejar,json,os,platform,pwd,re,runpy,secrets,sqlite3,stat,subprocess,sys,time,traceback,types,urllib.error,urllib.request
os.umask(0o077)
assert os.geteuid()==0 and len(sys.argv)in(2,3)
payload=Path(sys.argv[1]).resolve(strict=True);pins=json.loads((payload/'assets.json').read_bytes());arch={'x86_64':'amd64','aarch64':'arm64'}[platform.machine()];assert pins['architecture']==arch
case=pins['OS_case'];assert Path('/etc/hostname').read_text().strip()==case['hostname']and case['hostname'].startswith('c266-apache-')
osinfo=dict(line.split('=',1)for line in Path('/etc/os-release').read_text().splitlines()if'='in line and not line.startswith('#'))
assert osinfo['ID'].strip('"')==case['distribution']and osinfo['VERSION_ID'].strip('"')==case['version_id']
base=Path(sys.argv[2]).resolve(strict=True)if len(sys.argv)==3 else Path('/opt/panel-apache-c266-qa-'+secrets.token_hex(16));assert base.parent==Path('/opt')and re.fullmatch('panel-apache-c266-qa-[a-f0-9]{32}',base.name)
evidence=base/'evidence'
if len(sys.argv)==2:evidence.mkdir(mode=0o700,parents=True)
assert base.stat().st_uid==evidence.stat().st_uid==0 and stat.S_IMODE(evidence.stat().st_mode)==0o700
oldsource='7fcf5fe021cefe421ecf1da4c8ac1c5c81e95b075416dbb79dbd11dc92d00830';target='5eaded11f824722c9e6f13de5110946dfab10b9259cd73f38f227af74fc99569';assert pins['source_inputs_sha256']==target
origin='http://127.0.0.1:19100';csrf='';events=[];secret=secrets.token_hex(32)
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*a,**k):raise AssertionError('unexpected redirect')
client=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect(),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
def sha(path):
 h=hashlib.sha256()
 with Path(path).open('rb')as f:
  for chunk in iter(lambda:f.read(65536),b''):h.update(chunk)
 return h.hexdigest()
def save(name,value):
 assert re.fullmatch('[A-Za-z0-9._-]+',name)
 with(evidence/name).open('x')as f:json.dump(value,f,sort_keys=True,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
def command(args,timeout=30):
 r=subprocess.run(args,capture_output=True,text=True,timeout=timeout);assert r.returncode==0,(args[0],r.returncode,r.stderr[-1400:]);assert len(r.stdout)<4<<20;return r.stdout
def unit(name):return dict(v.split('=',1)for v in command(['systemctl','show',name,'--property=LoadState,MainPID,InvocationID,ActiveState,SubState,UnitFileState']).splitlines())
def api(label,path,body=None,expected=200,key=None):
 headers={'Origin':origin,'Content-Type':'application/json','X-CSRF-Token':csrf}
 if key:headers['Idempotency-Key']=key
 if body is not None:save(label+'-intent.json',{'path':path,'body':{'private_login_redacted':True}if path=='/login'else body,'key':key,'maximum_submissions':1})
 req=urllib.request.Request(origin+'/api'+path,None if body is None else json.dumps(body,separators=(',',':')).encode(),headers)
 try:
  with client.open(req,timeout=90)as res:status=res.status;raw=res.read((8<<20)+1)
 except urllib.error.HTTPError as e:status=e.code;raw=e.read((8<<20)+1)
 assert len(raw)<=8<<20;answer=json.loads(raw);save(label+'-response.json',{'status':status,'value':{'csrf_issued':bool(answer.get('csrf'))}if path=='/login'else answer});events.append({'path':path,'status':status,'method':'GET'if body is None else'POST'})
 assert status==expected,(path,status,answer);return answer
def login(label):
 global csrf
 credentials=json.loads(Path('/etc/panel/first-login.json').read_bytes())
 try:csrf=api(label,'/login',{k:credentials[k]for k in('username','password')})['csrf']
 finally:credentials.clear()
def wait_job(label,job,table):
 assert re.fullmatch('[a-f0-9]{32}',job)and table in('jobs','runtime_jobs');end=time.monotonic()+5*3600;observations=[]
 while time.monotonic()<end:
  value=api(label+'-poll-'+str(len(observations)),'/jobs/'+job);observations.append({'state':value['state'],'at':time.time()})
  if value['state']not in('queued','running'):
   save(label+'-terminal.json',value);assert value['state']=='succeeded'and not value['error'],(label,value['state'],value['error']);return value
  time.sleep(3)
 raise TimeoutError('original job unresolved, no replay')
def job(label,path,body,table='runtime_jobs'):
 reply=api(label,path,body,202,secrets.token_hex(16));return wait_job(label,reply['job_id'],table)
def run_once(label,args,timeout=1800):
 save(label+'-intent.json',{'args':args,'maximum_submissions':1})
 with(evidence/(label+'.stdout')).open('xb')as out,(evidence/(label+'.stderr')).open('xb')as err:r=subprocess.run(args,stdin=subprocess.DEVNULL,stdout=out,stderr=err,timeout=timeout)
 save(label+'-exit.json',{'exit':r.returncode});assert r.returncode==0,(label,(evidence/(label+'.stderr')).read_text(errors='replace')[-1500:])
def ready():
 for _ in range(90):
  try:
   with urllib.request.urlopen(origin+'/api/ready',timeout=3)as r:
    if r.status==200:return
  except Exception:pass
  time.sleep(1)
 raise TimeoutError('panel not ready')
def current_source():return json.loads(Path('/opt/panel/current/SOURCE_INPUTS.json').read_bytes())['inputs_sha256']
def protected_snapshot():
 paths={}
 def walk(p):
  s=p.lstat();v={'uid':s.st_uid,'gid':s.st_gid,'mode':stat.S_IMODE(s.st_mode),'inode':s.st_ino,'dev':s.st_dev,'links':s.st_nlink}
  if stat.S_ISREG(s.st_mode):assert s.st_size<128<<20;v.update(bytes=s.st_size,sha256=sha(p))
  elif stat.S_ISLNK(s.st_mode):v['target']=os.readlink(p)
  else:assert stat.S_ISDIR(s.st_mode)
  paths[str(p)]=v;assert len(paths)<50000
  if stat.S_ISDIR(s.st_mode):
   for child in sorted(p.iterdir()):walk(child)
 for name in('/srv/panel/sites','/opt/panel/runtimes','/opt/panel/app-modules','/etc/panel/php-sites'):
  if Path(name).exists():walk(Path(name))
 with contextlib.closing(sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True))as db:
  db.execute('PRAGMA query_only=ON');rows={n:[[{'blob_hex':v.hex()}if isinstance(v,bytes)else v for v in row]for row in db.execute('SELECT *FROM '+n+' ORDER BY 1')]for n in('sites','users','app_user_roles','app_user_menus','runtime_installations')}
 return {'files':paths,'rows':rows,'NSS':{n:sha('/etc/'+n)for n in('passwd','group','shadow','gshadow')},'Apache':unit('panel-apache.service')}
def actual_apache(version):
 u=unit('panel-apache.service');assert u['ActiveState']=='active'and int(u['MainPID'])>1
 binary=os.readlink('/proc/'+u['MainPID']+'/exe');assert binary=='/opt/panel/runtimes/apache/'+version+'/bin/httpd';return u
# Both the warm and cold phases bind every input byte before executing helpers.
for name,digest in pins['files'].items():
 assert re.fullmatch('[A-Za-z0-9._-]+',name) and sha(payload/name)==digest,name
proof={'ok':False,'base':str(base),'architecture':arch,'source_inputs_sha256':target,'Main_changed':False,'all40_commercial':False,'powerloss_ready':False,'boot':Path('/proc/sys/kernel/random/boot_id').read_text().strip()}
try:
 if len(sys.argv)==3:
  intent=json.loads((base/'cold-intent.json').read_text());assert intent['source']==target and intent['architecture']==arch and intent['boot']!=Path('/proc/sys/kernel/random/boot_id').read_text().strip();ready();assert current_source()==target;login('cold-login')
  u=actual_apache('2.4.71');status=api('cold-runtime-status','/runtimes/apache');assert status['selected_id']==status['running_id']=='apache-2.4.71'and not status['activation_needed']
  cfg=api('cold-WAF-status','/software/apache-waf/config');assert cfg['status']['healthy']and cfg['settings']==intent['settings']
  for path,expected in intent['sealed_records'].items():assert sha(path)==expected,path
  witness=runpy.run_path(str(payload/'archive_acceptance.py'))['private_witness']();assert witness==intent['archive_private_witness']
  api('cold-logout','/logout',{});csrf='';proof.update(ok=True,prior_boot=intent['boot'],boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip(),actual_real_kernel_and_service_reboot=True,old_records_and_Root_private_archives_preserved=True,current_Apache_271_and_WAF_healthy=True)
 else:
  assert not any(os.path.lexists(n)for n in('/opt/panel','/var/lib/panel','/etc/panel'))
  verified=base/'verified-input';verified.mkdir(mode=0o700)
  for name,digest in pins['files'].items():
   assert re.fullmatch('[A-Za-z0-9._-]+',name)
   file=payload/name;s=file.lstat();assert stat.S_ISREG(s.st_mode)and s.st_nlink==1 and 0<s.st_size<=64<<20 and sha(file)==digest
   raw=file.read_bytes();(verified/name).open('xb').write(raw)
  payload=verified
  assert sha(payload/'signed-release.py')=='fe128e82b4e11345b320cd782134768bfe1a4df14947c425d7494873a7a7b7b5'and sha(payload/'release-signing-dev.pub')=='4ccfcc861d56a41e3ba7f7ace7e2432c815f366c58448d783df92c6632f01339'
  signer=[sys.executable,'-I','-B',str(payload/'signed-release.py')];key=['--public-key',str(payload/'release-signing-dev.pub')]
  old=payload/('panel-'+pins['previous_version']+'-linux-'+arch+'.tar.gz');new=payload/('panel-'+pins['version']+'-linux-'+arch+'.tar.gz')
  run_once('old-original-signature',signer+['verify',str(old)]+key,60);run_once('old-normal-signed-install',signer+['install',str(old)]+key,1800);ready();assert current_source()==oldsource;login('old-login')
  catalogue=api('old-catalogue','/app-registry?refresh=1');assert len(catalogue['catalog']['apps'])==40 and not catalogue['source']['stale']and catalogue['source']['resolved_commit']==pins['served_head']
  for app,version in [('apache','2.4.68-compat1'),('php-82','8.2.35-compat2')]:
   item=next(v for v in catalogue['catalog']['apps']if v['id']==app);assert item['version']==version
   job('old-'+app+'-signed-install','/app-registry/'+app+'/install',{'expected_version':item['version'],'expected_sha256':item['sha256']})
  site=job('old-bootstrap-site','/sites',{'name':'Owned Apache upgrade baseline','slug':'c266-base','domain':'c266-base.example.test','php_version_id':'php-8.2.35'},'jobs')['site_id'];settings=api('old-bootstrap-settings','/sites/'+site+'/settings');draft=copy.deepcopy(settings['settings']);draft['web_server']='apache';preview=api('old-bootstrap-preview','/sites/'+site+'/settings/preview',{'settings':draft,'expected_revision':settings['settings_revision']});job('old-bootstrap-bind','/sites/'+site+'/settings',{'settings':draft,'expected_revision':settings['settings_revision'],'expected_config_sha':preview['config_sha']},'jobs')
  job('old-built-in-WAF230','/software/apache-waf/install',{})
  catalogue=api('old-WAF-catalogue','/app-registry?refresh=1');waf=next(v for v in catalogue['catalog']['apps']if v['id']=='apache-waf');assert waf['version']=='2.5.1';job('old-signed-WAF251','/app-registry/apache-waf/update',{'expected_version':waf['version'],'expected_sha256':waf['sha256']})
  engine=job('old-native-WAF-engine','/software/apache-waf/body-engine/build',{})['id'];oldrecord=Path('/var/lib/panel-executor/apache-body-builds')/(engine+'.json');assert json.loads(oldrecord.read_bytes())['apache_version']=='2.4.68';oldrecord_sha=sha(oldrecord)
  h=types.SimpleNamespace(payload=payload,evidence=evidence,api=api,save=save,wait_job=wait_job,unit=unit,proof=proof)
  result=runpy.run_path(str(payload/'acceptance_old.py'))['run'](h,engine)
  result=runpy.run_path(str(payload/'archive_acceptance.py'))['run'](h,result);save('old-full-WAF-and-held-writer-archive.json',result)
  active=api('old-explicit-active-body-config','/software/apache-waf/config')['settings'];active=copy.deepcopy(active)
  active['body']={'engine_job_id':engine,'sites':[{'site_id':v['id'],'policy':{'mode':'block','paranoia_level':1,'inbound_threshold':5,'body_limit_kib':128,'non_file_limit_kib':64,'json_depth':64,'argument_limit':256}}for v in result['sites']]}
  api('old-explicit-active-body-preview','/software/apache-waf/preview',{'settings':active});job('old-explicit-active-body-enable','/software/apache-waf/configure',{'settings':active})
  loaded=api('old-both-native-modules-active','/software/apache-waf/config');assert loaded['status']['healthy']and len(loaded['settings']['body']['sites'])==2 and loaded['settings']['apache_cc']['engine_job_id']==engine
  proof['old_request_body_and_CC_active_before_programme_upgrade']=True
  private_before=runpy.run_path(str(payload/'archive_acceptance.py'))['private_witness']();before=protected_snapshot();save('before-programme-upgrade.json',before);oldcfg=Path('/etc/panel/apache/httpd.conf').read_bytes();installed_before=Path('/etc/panel/security-apps/modules/apache-waf/installed.json').read_bytes()
  api('old-session-logout','/logout',{});csrf='';run_once('old-original-complete-queue-guard',['/opt/panel/current/bin/panel-executor','--check-program-upgrade-queues'],120)
  run_once('target-original-signature',signer+['verify',str(new)]+key,60);run_once('target-normal-signed-programme-upgrade',signer+['install',str(new)]+key,1800);ready();assert current_source()==target
  after=protected_snapshot();assert before==after,'Programme upgrade changed original sites, runtime data, accounts or Apache lifetime';assert Path('/etc/panel/apache/httpd.conf').read_bytes()==oldcfg and Path('/etc/panel/security-apps/modules/apache-waf/installed.json').read_bytes()==installed_before
  login('target-login');status=api('before-target-install-runtime-status','/runtimes/apache');assert status['selected_id']==status['running_id']=='apache-2.4.68'and status['activation_needed']
  job('target-side-by-side-Apache-install','/runtimes/install',{'release_id':'apache-2.4.71'});assert actual_apache('2.4.68')==before['Apache']and Path('/etc/panel/apache/httpd.conf').read_bytes()==oldcfg
  newengine=job('target-native-WAF-engine','/software/apache-waf/body-engine/build',{})['id'];record=Path('/var/lib/panel-executor/apache-body-builds')/(newengine+'.json');new_engine=json.loads(record.read_bytes());assert new_engine['apache_version']=='2.4.71'and new_engine['format']==3 and new_engine['cc_module_abi_validated']and new_engine['module_abi_validated']
  prior=api('before-runtime-switch-WAF','/software/apache-waf/config')['settings'];before_switch=actual_apache('2.4.68');switch_key=secrets.token_hex(16);selection={'release_id':'apache-2.4.71','engine_job_id':newengine};reply=api('one-runtime-switch','/runtimes/apache/switch',selection,202,switch_key);terminal=wait_job('one-runtime-switch',reply['job_id'],'runtime_jobs');after_switch=actual_apache('2.4.71');assert after_switch['InvocationID']!=before_switch['InvocationID']
  current=api('after-runtime-switch-WAF','/software/apache-waf/config');expected=copy.deepcopy(prior);expected['policy']['revision']+=1
  if expected.get('body'):expected['body']['engine_job_id']=newengine
  if expected.get('apache_cc'):expected['apache_cc']['engine_job_id']=newengine
  assert current['settings']==expected and current['status']['healthy'];assert sha(oldrecord)==oldrecord_sha and runpy.run_path(str(payload/'archive_acceptance.py'))['private_witness']()==private_before
  attach=api('same-switch-key-attaches-only','/runtimes/apache/switch',selection,202,switch_key);assert attach['job_id']==reply['job_id'];api('read-original-switch','/jobs/'+reply['job_id']);assert actual_apache('2.4.71')==after_switch
  status=api('actual-target-runtime-status','/runtimes/apache');assert status['selected_id']==status['running_id']=='apache-2.4.71'and status['target_installed']and not status['activation_needed']
  # New-version HTTP checks reuse the original owned sites and counters; no source or policy is substituted.
  c=runpy.run_path(str(payload/'acceptance_target.py'))['Acceptance'];h.continue_after_shared_budget=True;h.original_CC_prefix_sha256=sha('/var/lib/panel-apache-body/cc-events.log');h.adopted_sites=[{**s,'initial_reached':s['reached']}for s in result['sites']]
  a=c(h,newengine);a.create_sites();a.rewrite_and_no_follow();a.body_cases();a.burst('new-runtime-owned-CC-isolation',a.sites[0],path='/cc56/ordinary',amount=3,allowed=3)
  final=api('final-current-WAF','/software/apache-waf/config');assert final['status']['healthy'];assert sha(oldrecord)==oldrecord_sha and runpy.run_path(str(payload/'archive_acceptance.py'))['private_witness']()==private_before
  sealed={str(oldrecord):oldrecord_sha,str(record):sha(record)}
  save('target-original-HTTP-results.json',a.requests);save('after-programme-and-runtime-upgrade.json',protected_snapshot())
  intent={'source':target,'architecture':arch,'boot':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'settings':final['settings'],'sealed_records':sealed,'archive_private_witness':private_before}
  with(base/'cold-intent.json').open('x')as f:json.dump(intent,f,sort_keys=True);f.write('\n');f.flush();os.fsync(f.fileno())
  api('final-owned-session-logout','/logout',{});csrf='';proof.update(ok=True,powerloss_ready=True,normal_signed_programmes=2,normal_old_and_new_Apache_installs=True,old_WAF_engine_and_private_archives_preserved=True,old_Apache_PID_unchanged_until_explicit_switch=True,normal_authenticated_runtime_switch=True,one_policy_generation_only=True,post_switch_actual_rewrite_PHP_body_and_CC_requests=len(a.requests),same_original_switch_key_did_not_restart=True)
except BaseException:
 save('original-failure-'+secrets.token_hex(4)+'.json',{'traceback':traceback.format_exc()})
 # Preserve the real failed service observation before the owned VM exits.
 # This diagnostic reads only this fresh QA guest; it cannot restart or replay.
 try:
  diagnostic={}
  for label,args in [('Apache-unit',['systemctl','cat','panel-apache.service']),('Apache-state',['systemctl','show','panel-apache.service','--property=MainPID,ActiveState,SubState,ExecStart']),('original-service-journal',['journalctl','--no-pager','-n','100','-u','panel-apache.service','-u','panel-executor.service','-o','short-precise'])]:
   r=subprocess.run(args,capture_output=True,text=True,timeout=15);diagnostic[label]={'exit':r.returncode,'stdout':r.stdout[-65536:],'stderr':r.stderr[-2048:]}
  diagnostic['Root-switch-receipts']={}
  directory=Path('/var/lib/panel-executor/apache-runtime-switches')
  if directory.exists():
   paths=list(directory.iterdir());assert len(paths)<=128
   for path in paths:
    assert re.fullmatch(r'[a-f0-9]{32}\.json',path.name)and path.is_file()and not path.is_symlink()and path.stat().st_size<=65536
    diagnostic['Root-switch-receipts'][path.name]=json.loads(path.read_bytes())
  save('original-runtime-switch-failure-diagnostic.json',diagnostic)
 except BaseException:save('original-diagnostic-failure.json',{'traceback':traceback.format_exc()})
finally:
 if csrf:
  try:api('failure-session-logout','/logout',{});csrf=''
  except BaseException:proof['ok']=False;proof['logout_unconfirmed']=True
 save('proof-'+('cold'if len(sys.argv)==3 else'warm')+'.json',proof);save('HTTP-events-'+('cold'if len(sys.argv)==3 else'warm')+'.json',events)
 print(json.dumps(proof),flush=True)
sys.exit(0 if proof['ok']else 1)
