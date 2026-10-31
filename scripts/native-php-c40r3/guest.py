"""One fresh signed C40r3 programme and four signed PHP apps on an owned guest.
Uses actual hardware-KVM AMD64. Existing Main ARM64 evidence is separate.
"""
import contextlib,hashlib,http.cookiejar,json,os,pathlib,platform,re,runpy,secrets,sqlite3,stat,subprocess,sys,time,traceback,urllib.error,urllib.request
os.umask(0o077);assert len(sys.argv)==2 and os.geteuid()==0
payload=pathlib.Path(sys.argv[1]).resolve(strict=True);pins=json.loads((payload/'assets.json').read_bytes());arch={'aarch64':'arm64','x86_64':'amd64'}[platform.machine()]
SOURCE='33c40c57a4c5e205e919e8117ae177b4048c893daf09b5379388af7dba605fc6';VERSION='0.1.0-dev.proapps24phpsessionguardcandidate40r3'
assert pins['architecture']==arch and pins['format']==1 and pins['source_inputs_sha256']==SOURCE and pins['version']==VERSION
case=pins['OS_case'];assert case['architecture']==arch=='amd64' and case['platform'] in ('debian-12','debian-13','ubuntu-22.04','ubuntu-24.04','ubuntu-26.04')
assert pathlib.Path('/etc/hostname').read_text().strip()==case['hostname']
assert 'VERSION_ID="'+case['version_id']+'"'in pathlib.Path('/usr/lib/os-release').read_text()and pathlib.Path('/proc/1/comm').read_text().strip()=='systemd'
base=pathlib.Path('/opt/panel-php-c40r3-native-qa-'+secrets.token_hex(16));base.mkdir(mode=0o700);evidence=base/'evidence';evidence.mkdir(mode=0o700)
def sha(p):return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
def save(n,v):
 assert re.fullmatch('[A-Za-z0-9._-]+',n)
 with os.fdopen(os.open(evidence/n,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600),'w')as f:json.dump(v,f,sort_keys=True,indent=2);f.write(chr(10));f.flush();os.fsync(f.fileno())
for n,h in pins['files'].items():
 assert re.fullmatch('[A-Za-z0-9._-]+',n);f=payload/n;s=f.lstat();assert stat.S_ISREG(s.st_mode)and s.st_nlink==1 and sha(f)==h
assert sha(payload/'signed-release.py')=='fe128e82b4e11345b320cd782134768bfe1a4df14947c425d7494873a7a7b7b5'
assert sha(payload/'release-signing-dev.pub')=='4ccfcc861d56a41e3ba7f7ace7e2432c815f366c58448d783df92c6632f01339'
# The normal installer requires an independently pinned Root-owned trust key.
# SCP input belongs to the disposable qa user; copy only exact pinned regular
# files through held descriptors into a new private Root directory first.
verified=base/'verified-input';verified.mkdir(mode=0o700)
for name,digest in pins['files'].items():
 fd=os.open(payload/name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
 with os.fdopen(fd,'rb')as src:
  s=os.fstat(src.fileno());assert stat.S_ISREG(s.st_mode)and s.st_nlink==1 and 0<s.st_size<=64<<20
  raw=src.read((64<<20)+1);assert len(raw)==s.st_size and hashlib.sha256(raw).hexdigest()==digest
  z=os.fstat(src.fileno());assert(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)==(z.st_dev,z.st_ino,z.st_size,z.st_mtime_ns,z.st_ctime_ns)
 with os.fdopen(os.open(verified/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600),'wb')as dst:dst.write(raw);dst.flush();os.fsync(dst.fileno())
 assert sha(verified/name)==digest and(verified/name).stat().st_uid==0
payload=verified
assert stat.S_IMODE((payload/'release-signing-dev.pub').stat().st_mode)==0o600
save('root-owned-original-trust-payload.json',{'files':pins['files'],'private_root_directory':True,'all_exact_hashes':True,'original_signer_or_key_changed':False,'installer_trust_checks_unchanged':True})
save('actual-native-identity-and-inputs.json',{'architecture':arch,'boot':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'machine_id_sha256':sha('/etc/machine-id'),'PID1':pathlib.Path('/proc/1/comm').read_text().strip(),'os_release':pathlib.Path('/usr/lib/os-release').read_text(),'files':pins['files'],'source_inputs_sha256':SOURCE})
def verify_full_installed_archive():
 import tarfile
 name='panel-'+VERSION+'-linux-'+arch+'.tar.gz';archive=payload/name
 assert sha(archive)==pins['files'][name]
 installed=pathlib.Path('/opt/panel/current').resolve(strict=True)
 assert str(installed)=='/opt/panel/releases/'+VERSION
 records=[];prefix='panel-'+VERSION+'-linux-'+arch+'/'
 with tarfile.open(archive,'r:gz')as stream:
  for member in stream.getmembers():
   if member.name.rstrip('/')==prefix.rstrip('/'):relative=''
   else:assert member.name.startswith(prefix);relative=member.name[len(prefix):].rstrip('/')
   assert not pathlib.PurePosixPath(relative).is_absolute()and '..'not in pathlib.PurePosixPath(relative).parts
   f=installed/relative;s=f.lstat();assert s.st_uid==0 and stat.S_IMODE(s.st_mode)==member.mode
   record={'path':relative,'mode':member.mode,'uid':s.st_uid,'gid':s.st_gid,'inode':s.st_ino}
   if member.isfile():
    assert stat.S_ISREG(s.st_mode)and s.st_nlink==1
    digest=hashlib.sha256(stream.extractfile(member).read()).hexdigest();assert sha(f)==digest
    record.update(type='file',sha256=digest,bytes=s.st_size)
   else:assert member.isdir()and stat.S_ISDIR(s.st_mode);record.update(type='directory')
   records.append(record)
 actual={''}|{str(f.relative_to(installed))for f in installed.rglob('*')}
 assert actual=={v['path']for v in records}and len(records)==203
 save('actual-entire-signed-installed-tree.json',{'ok':True,'read_only':True,'archive_sha256':sha(archive),'installed':str(installed),'entries':records,'count':203,'source_inputs_sha256':json.loads((installed/'SOURCE_INPUTS.json').read_bytes())['inputs_sha256']})
def command(label,args,timeout,env=None):
 save(label+'-once-intent.json',{'maximum_submissions':1,'args':args,'unknown_outcome_observe_only':True})
 with(evidence/(label+'.stdout.log')).open('xb')as out,(evidence/(label+'.stderr.log')).open('xb')as err:r=subprocess.run(args,stdin=subprocess.DEVNULL,stdout=out,stderr=err,timeout=timeout,env=env)
 save(label+'-outcome.json',{'exit':r.returncode,'stdout_sha256':sha(evidence/(label+'.stdout.log')),'stderr_sha256':sha(evidence/(label+'.stderr.log'))});assert r.returncode==0,'Original normal operation failed; no replay: '+label
def guard(label):
 for i in range(9):
  r=subprocess.run(['/opt/panel/current/bin/panel-executor','--check-program-upgrade-queues'],capture_output=True,timeout=30)
  u=dict(v.split('=',1)for v in subprocess.check_output(['systemctl','show','panel-mysql-overwrite-recovery.service','--property=LoadState,ActiveState,SubState,MainPID,ControlPID'],text=True,timeout=5).splitlines())
  save(label+'-guard-'+str(i)+'.json',{'exit':r.returncode,'stdout_hex':r.stdout.hex(),'stderr_hex':r.stderr.hex(),'fixed_recovery_unit':u})
  if r.returncode==0:assert r.stdout==r.stderr==b'';return
  assert i<8 and r.stdout==b''and b'panel-mysql-overwrite-recovery.service'in r.stderr and u['LoadState']=='loaded'and u['ActiveState']=='activating'and u['SubState']=='condition'and u['MainPID']=='0'
  time.sleep(1)
def lifetime(unit):
 pid=subprocess.check_output(['systemctl','show',unit,'--property=MainPID','--value'],text=True,timeout=5).strip();assert int(pid)>1
 return {'pid':pid,'start_ticks':pathlib.Path('/proc/'+pid+'/stat').read_text().rsplit(')',1)[1].split()[19],'exe_sha256':sha('/proc/'+pid+'/exe')}
def nss():return{n:{'entries':{line.split(':',1)[0]:hashlib.sha256(line.encode()).hexdigest()for line in pathlib.Path('/etc/'+n).read_text().splitlines()},'sha256':sha('/etc/'+n),'mode':pathlib.Path('/etc/'+n).stat().st_mode,'uid':pathlib.Path('/etc/'+n).stat().st_uid,'gid':pathlib.Path('/etc/'+n).stat().st_gid}for n in('passwd','group','shadow','gshadow','nsswitch.conf')}
import pwd,grp
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*args,**kwargs):raise AssertionError('Authentication redirect refused')
origin='http://127.0.0.1:19100';client=None;csrf='';http_events=[]
def api(path,body=None,key=None,allowed=(200,202)):
 headers={'Origin':origin,'Content-Type':'application/json','X-CSRF-Token':csrf}
 if key:headers['Idempotency-Key']=key
 req=urllib.request.Request(origin+'/api'+path,data=None if body is None else json.dumps(body,separators=(',',':')).encode(),headers=headers)
 try:
  with client.open(req,timeout=35)as r:status=r.status;raw=r.read((4<<20)+1)
 except urllib.error.HTTPError as e:status=e.code;raw=e.read((4<<20)+1)
 assert len(raw)<=4<<20;value=json.loads(raw);http_events.append({'path':path,'method':'GET'if body is None else'POST','status':status})
 if status not in allowed:save('HTTP-refusal-'+secrets.token_hex(8)+'.json',{'path':path,'status':status,'value':value});raise AssertionError('Original HTTP refusal '+str(status)+':'+path)
 return status,value

def job(label,identity):
 assert re.fullmatch('[a-f0-9]{32}',identity);observed=[];deadline=time.monotonic()+1800
 while True:
  with contextlib.closing(sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True,timeout=3))as db:
   db.row_factory=sqlite3.Row;db.execute('PRAGMA query_only=ON');rows=[(name,db.execute('SELECT * FROM '+name+' WHERE id=?',(identity,)).fetchone())for name in('jobs','runtime_jobs')];found=[(name,dict(row))for name,row in rows if row is not None]
  assert len(found)==1;table,row=found[0];observed.append({'state':row['state'],'error':row.get('error',''),'at':time.time()})
  if row['state']in('succeeded','failed','needs_attention','cancelled','canceled'):break
  assert time.monotonic()<deadline,'Original job unresolved; observe only';time.sleep(1)
 save(label+'-original-job-observations.json',observed);save(label+'-original-Core-terminal.json',{'table':table,'row':row});assert row['state']=='succeeded'and not row.get('error'),'Original job refused; no reset or replay'
 native=pathlib.Path('/var/lib/panel-executor/installs'if table=='runtime_jobs'else'/var/lib/panel-executor')/(identity+'.json');assert native.is_file();raw=native.read_bytes();assert len(raw)<2<<20;save(label+'-original-native-terminal.json',{'path':str(native),'sha256':sha(native),'value':json.loads(raw)});return row

def submit(label,path,body,wait=True):
 key=secrets.token_hex(16);save(label+'-once-intent.json',{'path':path,'body':body,'idempotency_key':key,'maximum_POSTs':1,'unknown_outcome_observe_only':True});status,value=api(path,body,key);save(label+'-original-accepted.json',{'status':status,'value':value})
 if wait:assert status==202 and re.fullmatch('[a-f0-9]{32}',value['job_id']);job(label,value['job_id'])
 return value

def kernel_rules():
 r=subprocess.run(['nft','-j','list','ruleset'],capture_output=True,text=True,timeout=5);assert r.returncode==0
 def normalize(v):
  if isinstance(v,list):return[normalize(x)for x in v]
  if isinstance(v,dict):return{k:({'packets':0,'bytes':0}if k=='counter'and isinstance(x,dict)and set(x)=={'packets','bytes'}else normalize(x))for k,x in v.items()}
  return v
 return normalize(json.loads(r.stdout))

web=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
def website(site,path,body=None,content_type=None):
 headers={'Host':site['domain'],'User-Agent':'yunzhan-owned-native-PHP-QA'}
 if content_type:headers['Content-Type']=content_type
 with web.open(urllib.request.Request('http://127.0.0.1:19101'+path,data=body,headers=headers),timeout=15)as response:assert response.status==200;raw=response.read(65537)
 assert len(raw)<=65536;return raw

def verify_site(label,site,version):
 account=pwd.getpwnam('ps'+site['id'][:24]);group=grp.getgrnam(account.pw_name);assert account.pw_uid!=0 and account.pw_gid==group.gr_gid!=0;user={'uid':account.pw_uid,'primary_gid':account.pw_gid,'export_gid':grp.getgrnam('www-data').gr_gid}
 def check(actual):
  assert actual['php']==version and actual['redis']=='6.3.0'and actual['uid']==user['uid']and actual['gid']==user['primary_gid']and actual['enabled']is False and actual['memory']=='256M'and actual['time']=='120'and actual['upload']=='16M'and actual['post']=='32M'and actual['timezone']=='UTC',actual
 actual=json.loads(website(site,'/session-upload.php'));check(actual);assert actual['files']==0
 token=secrets.token_hex(16);boundary='yunzhan'+token;sample=b'normal-upload\n'*128
 body=('--'+boundary+'\r\nContent-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nowned-probe\r\n--'+boundary+'\r\nContent-Disposition: form-data; name="sample"; filename="sample.txt"\r\nContent-Type: text/plain\r\n\r\n').encode()+sample+('\r\n--'+boundary+'--\r\n').encode();uploaded=json.loads(website(site,'/session-upload.php',body,'multipart/form-data; boundary='+boundary));check(uploaded);assert uploaded['files']==1 and uploaded['error']==0 and uploaded['sha256']==hashlib.sha256(sample).hexdigest()
 cli="echo json_encode(['php'=>PHP_VERSION,'redis'=>phpversion('redis'),'uid'=>posix_geteuid(),'gid'=>posix_getegid(),'enabled'=>filter_var(ini_get('session.upload_progress.enabled'),FILTER_VALIDATE_BOOL),'memory'=>ini_get('memory_limit'),'time'=>ini_get('max_execution_time'),'upload'=>ini_get('upload_max_filesize'),'post'=>ini_get('post_max_size'),'timezone'=>ini_get('date.timezone')]);";r=subprocess.run(['/opt/panel/current/bin/panel-executor','--site-cli='+site['id'],'--','-r',cli],capture_output=True,text=True,timeout=20);assert r.returncode==0 and not r.stderr;actual_cli=json.loads(r.stdout);check(actual_cli)
 with contextlib.closing(sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True))as db:
  db.row_factory=sqlite3.Row;db.execute('PRAGMA query_only=ON');row=dict(db.execute('SELECT * FROM sites WHERE id=?',(site['id'],)).fetchone())
 assert row['status']=='running'and row['php_version_id']=='php-'+version
 instance=row['runtime_instance_id'];config=pathlib.Path('/etc/panel/php-sites')/instance/'fpm.conf';manifest=config.parent/'pool.json';nginx=pathlib.Path('/etc/panel/sites-enabled')/(site['id']+'.conf');save(label+'-actual-site-and-upload.json',{'site':row,'account':user,'actual_GET':actual,'actual_multipart':uploaded,'actual_CLI':actual_cli,'FPM_configuration_sha256':sha(config),'FPM_manifest_sha256':sha(manifest),'nginx_sha256':sha(nginx)});return {'nginx':sha(nginx),'FPM':sha(config),'manifest':sha(manifest)}

proof={'ok':False,'architecture':arch,'base':str(base),'scope':'Normal signed programme, four signed PHP security applications, four Redis extensions, four configured sites, real HTTP multipart uploads, normal site CLI, private FPM positive control and normal cross-version rollback','source_inputs_sha256':SOURCE,'OS_case':case,'Main_changed':False,'all50_commercial':False,'application_install_POSTs':0,'extension_install_POSTs':0,'site_creation_POSTs':0,'site_switch_POSTs':0,'failed_or_unknown_requests_replayed':False}
try:
 assert all(not os.path.lexists(n)for n in('/opt/panel','/var/lib/panel','/var/lib/panel-executor','/etc/panel-release','/etc/nginx/nginx.conf'))
 archive=payload/('panel-'+VERSION+'-linux-'+arch+'.tar.gz');signer=['python3','-I','-B',str(payload/'signed-release.py')];command('signature-verify',signer+['verify',str(archive),'--public-key',str(payload/'release-signing-dev.pub')],30);command('normal-first-install',signer+['install',str(archive),'--public-key',str(payload/'release-signing-dev.pub')],1200)
 assert json.loads(pathlib.Path('/opt/panel/current/SOURCE_INPUTS.json').read_bytes())['inputs_sha256']==SOURCE and not os.path.lexists('/opt/panel/DEVELOPMENT_RELEASE');verify_full_installed_archive();guard('programme')
 before={'NSS':nss(),'lifetimes':{n:lifetime(n)for n in('panel.service','panel-executor.service','nginx.service','ssh.service','fail2ban.service')},'kernel_rules':kernel_rules()};save('protected-before-apps.json',before)
 accessfile=pathlib.Path('/etc/panel/first-login.json');s=accessfile.lstat();assert stat.S_ISREG(s.st_mode)and s.st_uid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600;access=json.loads(accessfile.read_bytes());client=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect(),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
 try:status,value=api('/login',{k:access[k]for k in('username','password')});assert status==200;csrf=value['csrf']
 finally:access.clear()
 _,catalogue=api('/app-registry?refresh=1');save('original-signed-catalogue.json',catalogue);assert len(catalogue['catalog']['apps'])==50 and catalogue['host']=={'platform':case['platform'],'architecture':arch}and not catalogue['source']['stale'];applications={a['id']:a for a in catalogue['catalog']['apps']};sites=[]
 versions=[('php-82','8.2.35'),('php-83','8.3.36'),('php-84','8.4.27'),('php-85','8.5.12')]
 for app,version in versions:
  item=applications[app];assert item['version']==version+'-compat2';proof['application_install_POSTs']+=1;submit(app+'-runtime-install','/app-registry/'+app+'/install',{'expected_version':item['version'],'expected_sha256':item['sha256'],'settings':{}})
  proof['extension_install_POSTs']+=1;submit(app+'-redis-install','/php/extensions/php-'+version+'/install',{'extension_id':'redis-6.3.0'})
  _,status=api('/app-registry?refresh=1');installed=next(v for v in status['status']if v['id']==app);assert installed['state_known']and installed['installed']and not installed['update_available']and installed['installed_version']==item['version'];save(app+'-actual-store-installed.json',installed)
  slug=app+'-'+secrets.token_hex(4);proof['site_creation_POSTs']+=1;submit(app+'-site-create','/sites',{'name':'PHP '+version+' native QA','slug':slug,'domain':slug+'.localhost','php_version_id':'php-'+version});_,all_sites=api('/sites');site=next(v for v in all_sites if v['slug']==slug);_,current=api('/sites/'+site['id']+'/settings');settings=current['settings'];settings['php']={'extensions':['redis-6.3.0'],'memory_mb':256,'max_execution_seconds':120,'upload_mb':16,'post_mb':32,'timezone':'UTC','display_errors':False,'max_children':2,'max_requests':500};request={'settings':settings,'expected_revision':current['settings_revision']};_,preview=api('/sites/'+site['id']+'/settings/preview',request);save(app+'-actual-settings-preview.json',preview);request['expected_config_sha']=sha(pathlib.Path('/etc/panel/sites-enabled')/(site['id']+'.conf'));submit(app+'-site-configure','/sites/'+site['id']+'/settings',request)
  code="<?php header('Content-Type: application/json'); echo json_encode(['php'=>PHP_VERSION,'redis'=>phpversion('redis'),'uid'=>posix_geteuid(),'gid'=>posix_getegid(),'enabled'=>filter_var(ini_get('session.upload_progress.enabled'),FILTER_VALIDATE_BOOL),'memory'=>ini_get('memory_limit'),'time'=>ini_get('max_execution_time'),'upload'=>ini_get('upload_max_filesize'),'post'=>ini_get('post_max_size'),'timezone'=>ini_get('date.timezone'),'files'=>count($_FILES),'error'=>$_FILES['sample']['error']??-1,'sha256'=>isset($_FILES['sample']['tmp_name'])?hash_file('sha256',$_FILES['sample']['tmp_name']):'']);";submit(app+'-site-script','/sites/'+site['id']+'/files/action',{'action':'create','path':'session-upload.php','content':code},False);verified=verify_site(app,site,version);sites.append((site,version,verified))
  print(json.dumps({'normal_installed_PHP':version,'actual_HTTP_upload_and_site_CLI':True,'platform':case['platform']}),flush=True)
 first,version,original=sites[0]
 for index,target in enumerate(('8.3.36','8.2.35'),1):
  proof['site_switch_POSTs']+=1;submit('site-switch-'+str(index),'/sites/'+first['id']+'/php',{'release_id':'php-'+target});result=verify_site('site-switch-'+str(index),first,target)
  if index==2:assert result==original,'Normal rollback did not restore original exact pool and ingress bytes'
 native=payload/'executor-session-linux-amd64.test';native.chmod(0o700);save('private-FPM-once-intent.json',{'source_inputs_sha256':SOURCE,'binary_sha256':sha(native),'site_id':first['id'],'maximum_invocations':1});command('actual-native-FPM',[str(native),'-test.v','-test.run=^TestPHP(?:StartupProtectionAppliesWithUnsetAndConfiguredSettings|ProbeRequiresStartupSessionProgressProtection|SessionStartupRealFPM|SessionNativeScriptRejectsLinksAndExistingFiles|SessionNativeProgressRejectsLinksAndOversize)$','-test.timeout=300s'],330,{'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C','TMPDIR':'/tmp','PANEL_PHP_SESSION_ACCEPT_SITE':first['id']})
 text=(evidence/'actual-native-FPM.stdout.log').read_text();assert '--- SKIP:'not in text and text.count('--- PASS: TestPHPSessionStartupRealFPM/')==9
 after={'NSS':nss(),'lifetimes':{n:lifetime(n)for n in before['lifetimes']},'kernel_rules':kernel_rules()};save('protected-after-apps.json',after);assert before['lifetimes']==after['lifetimes']and before['kernel_rules']==after['kernel_rules']
 for name,records in before['NSS'].items():
  for account,digest in records['entries'].items():assert after['NSS'][name]['entries'][account]==digest
  for key in('mode','uid','gid'):assert after['NSS'][name][key]==records[key]
 guard('final');status,_=api('/logout',{});assert status==200;csrf='';proof.update(ok=True,four_signed_normal_applications_installed=True,four_actual_Redis_extensions_installed=True,four_normal_configured_websites=True,actual_HTTP_GET_and_multipart_upload_and_site_CLI=True,nine_private_FPM_cases_and_enabled_positive_control=True,normal_cross_version_switch_and_exact_rollback=True,original_NSS_and_five_service_lifetimes_and_kernel_rules_preserved=True,complete_guard_exit=0,normal_own_logout=True)
except BaseException:save('failure.json',{'traceback':traceback.format_exc()})
finally:
 if csrf:
  try:status,_=api('/logout',{});assert status==200;proof['normal_own_logout']=True
  except BaseException:save('logout-failure.json',{'traceback':traceback.format_exc()});proof['ok']=False
 save('http-events.json',http_events);save('proof.json',proof);print(json.dumps({'ok':proof['ok'],'base':str(base),'proof_sha256':sha(evidence/'proof.json'),'source_inputs_sha256':SOURCE,'architecture':arch,'Main_changed':False,'all50_commercial':False}),flush=True)
sys.exit(0 if proof['ok']else 1)
