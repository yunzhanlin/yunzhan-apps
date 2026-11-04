"""Original signed programme and real Apache body/CC acceptance in owned KVM.

One submission per mutation. No compiler/module/catalogue substitution, repair
of original records, or replay after a failed or uncertain result.
"""
import ast,contextlib,copy,hashlib,http.cookiejar,json,os,pathlib,platform,pwd,re,runpy,secrets,sqlite3,stat,subprocess,sys,time,traceback,types,urllib.error,urllib.request
os.umask(0o077);assert os.geteuid()==0 and len(sys.argv)==2
payload=pathlib.Path(sys.argv[1]).resolve(strict=True);pins=json.loads((payload/'assets.json').read_bytes())
SOURCE='d41c971d111a9575ea76fb8de47bec9921a0b584c6492ef135878edea270439e'
VERSION='0.1.0-dev.proapps24apacheccarchivecandidate57r4'
assert platform.machine()=='x86_64' and pins['architecture']=='amd64' and pins['source_inputs_sha256']==SOURCE and pins['version']==VERSION
case=pins['OS_case'];assert case['architecture']=='amd64' and case['platform'] in ('debian-12','debian-13','ubuntu-22.04','ubuntu-24.04','ubuntu-26.04')
assert pathlib.Path('/etc/hostname').read_text().strip()==case['hostname'] and 'VERSION_ID="'+case['version_id']+'"' in pathlib.Path('/usr/lib/os-release').read_text()
base=pathlib.Path('/opt/panel-apache-cc-c57r4-native-qa-'+secrets.token_hex(16));base.mkdir(mode=0o700);evidence=base/'evidence';evidence.mkdir(mode=0o700)
def sha(f):return hashlib.sha256(pathlib.Path(f).read_bytes()).hexdigest()
def save(n,v):
 assert re.fullmatch('[A-Za-z0-9._-]+',n)
 with os.fdopen(os.open(evidence/n,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600),'w')as f:json.dump(v,f,sort_keys=True,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
verified=base/'verified-input';verified.mkdir(mode=0o700)
for name,digest in pins['files'].items():
 assert re.fullmatch('[A-Za-z0-9._-]+',name)
 with os.fdopen(os.open(payload/name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC),'rb')as f:
  s=os.fstat(f.fileno());assert stat.S_ISREG(s.st_mode) and s.st_nlink==1 and 0<s.st_size<=64<<20;raw=f.read((64<<20)+1);z=os.fstat(f.fileno())
  assert len(raw)==s.st_size and hashlib.sha256(raw).hexdigest()==digest and (s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)==(z.st_dev,z.st_ino,z.st_size,z.st_mtime_ns,z.st_ctime_ns)
 with os.fdopen(os.open(verified/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600),'wb')as f:f.write(raw);f.flush();os.fsync(f.fileno())
payload=verified
assert sha(payload/'signed-release.py')=='fe128e82b4e11345b320cd782134768bfe1a4df14947c425d7494873a7a7b7b5'
assert sha(payload/'release-signing-dev.pub')=='4ccfcc861d56a41e3ba7f7ace7e2432c815f366c58448d783df92c6632f01339'
assert sha(payload/'capture.py')=='6fcd61bf2544128a565b1672caa2bd721fc95cf79df5d1a9a48e7d4b67b54d22'
names={'command','unit','snapshot','api','NoRedirect'};nodes=[n for n in ast.parse((payload/'capture.py').read_bytes()).body if isinstance(n,(ast.FunctionDef,ast.ClassDef))and n.name in names];assert len(nodes)==len(names)
exec(compile(ast.Module(body=nodes,type_ignores=[]),'<original-once-HTTP-and-readonly-observers>','exec'),globals())
boot=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip();p={'boot':boot};own_site=None;secret=secrets.token_hex(32)
origin='http://127.0.0.1:19100';csrf='';events=[];client=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect(),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
proof={'ok':False,'architecture':'amd64','base':str(base),'OS_case':case,'source_inputs_sha256':SOURCE,'normal_programme_installer_submissions':0,'normal_programme_upgrade_submissions':0,'signed_runtime_install_POSTs':0,'legacy_builtin_runtime_install_POSTs':0,'signed_WAF_update_POSTs':0,'Main_changed':False,'all50_commercial':False,'original_operations_replayed':False,'actual_browser_UI_acceptance':False}
def run_once(label,args,timeout):
 save(label+'-once-intent.json',{'args':args,'maximum_submissions':1,'unknown_outcome_observe_only':True})
 with(evidence/(label+'.stdout.log')).open('xb')as out,(evidence/(label+'.stderr.log')).open('xb')as err:r=subprocess.run(args,stdin=subprocess.DEVNULL,stdout=out,stderr=err,timeout=timeout)
 save(label+'-original-outcome.json',{'exit':r.returncode,'stdout_sha256':sha(evidence/(label+'.stdout.log')),'stderr_sha256':sha(evidence/(label+'.stderr.log'))});assert r.returncode==0,'Original operation refused; no replay: '+label
def wait_job(label,jid,table):
 assert re.fullmatch('[a-f0-9]{32}',jid)and table in ('jobs','runtime_jobs');deadline=time.monotonic()+5400;observations=[]
 while True:
  with contextlib.closing(sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True))as db:
   db.row_factory=sqlite3.Row;db.execute('PRAGMA query_only=ON');row=dict(db.execute('SELECT *FROM '+table+' WHERE id=?',(jid,)).fetchone())
  if not observations or observations[-1]['state']!=row['state']:observations.append({'state':row['state'],'at':time.time()})
  if row['state']not in ('queued','running'):break
  assert time.monotonic()<deadline,'Original job unresolved; observe only';time.sleep(2)
 save(label+'-original-observations.json',observations);save(label+'-original-terminal.json',row);assert row['state']=='succeeded' and not row['error'],(label,row['state'],row['error']);return row
def guard(label):
 for i in range(9):
  r=subprocess.run(['/opt/panel/current/bin/panel-executor','--check-program-upgrade-queues'],capture_output=True,timeout=35);state=unit('panel-mysql-overwrite-recovery.service')
  save(label+'-original-queue-guard-'+str(i)+'.json',{'exit':r.returncode,'stdout_hex':r.stdout.hex(),'stderr_hex':r.stderr.hex(),'original_recovery_unit':state})
  if r.returncode==0:assert r.stdout==r.stderr==b'';return
  lines=r.stderr.decode('utf-8').splitlines();assert len(lines)==2 and r.stdout==b'' and lines[0].endswith('native program operation is active, failed or transitional; upgrade refused'),'Original nontransient refusal; no replay'
  refusal=json.loads(lines[1]);assert set(refusal)=={'format','kind','unit','load_state','active_state','sub_state','inventory_sha256'} and refusal['format']==1 and refusal['kind']=='native-program-unit-refusal-v1' and refusal['unit']=='panel-mysql-overwrite-recovery.service' and refusal['load_state']=='loaded' and refusal['active_state']=='activating' and refusal['sub_state'] in ('condition','start') and re.fullmatch('[a-f0-9]{64}',refusal['inventory_sha256'])
  assert i<8 and state['LoadState']=='loaded' and (state['ActiveState'],state['SubState'])in (('activating','condition'),('activating','start'),('active','exited'),('inactive','dead')) and state['MainPID'].isdigit(),'Original nontransient refusal; no replay'
  time.sleep(1)
def catalogue(label):
 v=api(label,'/app-registry?refresh=1');assert len(v['catalog']['apps'])==50 and not v['source']['stale'] and v['host']=={'platform':case['platform'],'architecture':'amd64'};return v
def pair(v,app):return next(x for x in v['catalog']['apps']if x['id']==app),next(x for x in v['status']if x['id']==app)
def login(label):
 global csrf
 f=pathlib.Path('/etc/panel/first-login.json');s=f.lstat();assert stat.S_ISREG(s.st_mode)and s.st_uid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600
 access=json.loads(f.read_bytes())
 try:csrf=api(label,'/login',{k:access[k]for k in ('username','password')})['csrf']
 finally:access.clear()
def verify_installed():
 import tarfile
 archive=payload/('panel-'+VERSION+'-linux-amd64.tar.gz');root=pathlib.Path('/opt/panel/current').resolve(strict=True);prefix='panel-'+VERSION+'-linux-amd64';records=[]
 assert str(root)=='/opt/panel/releases/'+VERSION
 with tarfile.open(archive,'r:gz')as tar:
  for member in tar:
   assert member.name==prefix or member.name.startswith(prefix+'/');name=member.name[len(prefix):].lstrip('/');f=root/name;s=f.lstat();assert s.st_uid==0 and stat.S_IMODE(s.st_mode)==member.mode
   if member.isfile():assert stat.S_ISREG(s.st_mode)and s.st_nlink==1 and sha(f)==hashlib.sha256(tar.extractfile(member).read()).hexdigest()
   else:assert member.isdir()and stat.S_ISDIR(s.st_mode)
   records.append(name)
 assert len(records)==len(set(records))==204 and set(records)=={''}|{str(f.relative_to(root))for f in root.rglob('*')}
 save('actual-entire-original-signed-installed-tree.json',{'ok':True,'entries':records,'count':204,'archive_sha256':sha(archive),'source_inputs_sha256':SOURCE})
try:
 assert all(not os.path.lexists(n)for n in ('/opt/panel','/var/lib/panel','/var/lib/panel-executor','/etc/panel-release','/etc/nginx/nginx.conf'))
 signer=['python3','-I','-B',str(payload/'signed-release.py')];key=['--public-key',str(payload/'release-signing-dev.pub')]
 initial=pins['baseline_version']if case.get('baseline_upgrade')else VERSION
 archive=payload/('panel-'+initial+'-linux-amd64.tar.gz')
 run_once('initial-original-programme-signature-verify',signer+['verify',str(archive)]+key,45)
 proof['normal_programme_installer_submissions']+=1;run_once('one-original-programme-fresh-install',signer+['install',str(archive)]+key,1800);login('initial-root-private-login')
 for app,version,release in [('apache','2.4.68-compat1','apache-2.4.68'),('php-82','8.2.35-compat2','php-8.2.35')]:
  if case.get('baseline_upgrade'):
   proof['legacy_builtin_runtime_install_POSTs']+=1;reply=api(app+'-one-normal-legacy-runtime-install','/runtimes/install',{'release_id':release},202,secrets.token_hex(16))
  else:
   item,status=pair(catalogue(app+'-original-signed-catalogue'),app);assert item['version']==version and status['state_known']and not status['installed']
   proof['signed_runtime_install_POSTs']+=1;reply=api(app+'-one-signed-runtime-install','/app-registry/'+app+'/install',{'expected_version':item['version'],'expected_sha256':item['sha256']},202,secrets.token_hex(16))
  wait_job(app+'-original-runtime-install',reply['job_id'],'runtime_jobs')
 # The normal WAF health contract requires an actual managed Apache vhost.
 # Create it before installing the legacy application; no health stand-in or
 # direct configuration edit is used. The two request-test sites are separate.
 nonce=secrets.token_hex(16);reply=api('one-owned-bootstrap-site-create','/sites',{'name':'Owned native CC bootstrap vhost','slug':'qa-cc56base-'+nonce[:12],'domain':'qa-cc56base-'+nonce[:12]+'.example.test','php_version_id':'php-8.2.35'},202,secrets.token_hex(16));row=wait_job('bootstrap-site-create',reply['job_id'],'jobs');bootstrap=row['site_id'];assert re.fullmatch('[a-f0-9]{32}',bootstrap)
 site=api('bootstrap-site-original-settings','/sites/'+bootstrap+'/settings');settings=copy.deepcopy(site['settings']);settings['web_server']='apache'
 preview=api('bootstrap-site-readonly-preview','/sites/'+bootstrap+'/settings/preview',{'settings':settings,'expected_revision':site['settings_revision']});assert preview['revision']==site['settings_revision']and hashlib.sha256(preview['current'].encode()).hexdigest()==preview['config_sha']
 reply=api('one-bootstrap-site-Apache-save','/sites/'+bootstrap+'/settings',{'settings':settings,'expected_revision':site['settings_revision'],'expected_config_sha':preview['config_sha']},202,secrets.token_hex(16));wait_job('bootstrap-site-Apache-save',reply['job_id'],'jobs');proof['bootstrap_site_id']=bootstrap
 assert not os.path.lexists('/etc/panel/security-apps/modules/apache-waf/installed.json')
 reply=api('one-normal-legacy230-WAF-install','/software/apache-waf/install',{},202,secrets.token_hex(16));wait_job('legacy230-WAF-install',reply['job_id'],'runtime_jobs')
 module=pathlib.Path('/etc/panel/security-apps/modules/apache-waf');old=(module/'installed.json').read_bytes();old_record=json.loads(old);assert old_record['version']=='2.3.0'
 history={n:(module/n).read_bytes()for n in ('history.json','last-report.json','history.sqlite')if(module/n).exists()};save('original-legacy230-installed.json',{'original_hex':old.hex(),'history_originals':{n:b.hex()for n,b in history.items()},'normal_builtin_legacy_not_signed_store_claim':True})
 legacy_body=None
 if case.get('baseline_upgrade'):
  reply=api('one-C55-original-Format1-build','/software/apache-waf/body-engine/build',{},202,secrets.token_hex(16));legacy_body=reply['job_id'];wait_job('C55-original-Format1-build',legacy_body,'runtime_jobs')
  file=pathlib.Path('/var/lib/panel-executor/apache-body-builds')/(legacy_body+'.json');legacy_bytes=file.read_bytes();assert json.loads(legacy_bytes)['format']==1
  save('original-C55-Format1-record.json',{'job_id':legacy_body,'original_hex':legacy_bytes.hex(),'sha256':sha(file)})
  api('pre-upgrade-logout','/logout',{});csrf='';guard('C55-complete-before-upgrade')
  before=snapshot();save('legacy-C55-before-programme-upgrade-original113.json',before);runtime_before={n:unit(n)for n in ('panel-apache.service','panel-php@'+bootstrap+'-php-8.2.35.service')};save('legacy-before-original-runtime-lifetimes.json',runtime_before)
  archive=payload/('panel-'+VERSION+'-linux-amd64.tar.gz');run_once('target-original-signature-verify',signer+['verify',str(archive)]+key,45)
  run_once('target-normal-signed-preflight',signer+['install',str(archive)]+key+['--preflight-only'],900)
  proof['normal_programme_upgrade_submissions']+=1;run_once('one-target-normal-signed-upgrade',signer+['install',str(archive)]+key,1800)
  immediate=snapshot();save('legacy-immediate-after-programme-upgrade-original113.json',immediate)
  def canonical_service_rows(table):
   assert table['columns']==['kind','resource_id','label','expected_state','actual_state','detail','checked_at']
   rows=[dict(zip(table['columns'],row))for row in table['rows']]
   assert len(rows)==len({(row['kind'],row['resource_id'])for row in rows})
   return {(row['kind'],row['resource_id']):{k:v for k,v in row.items()if k!='checked_at'}for row in rows}
  wanted_services=canonical_service_rows(before['tables']['monitor_services']);assert wanted_services and all(row['actual_state']=='active'and row['expected_state']=='active'and row['detail']=='loaded / running'for row in wanted_services.values())
  recovery_observations=[]
  for observation in range(16):
   with contextlib.closing(sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True))as db:
    db.execute('PRAGMA query_only=ON');table={'columns':[v[1]for v in db.execute('PRAGMA table_info(monitor_services)')],'rows':[list(row)for row in db.execute('SELECT *FROM monitor_services')]}
   recovery_observations.append({'at':time.time(),'table':table})
   if canonical_service_rows(table)==wanted_services:break
   assert observation<15,'Normal service observations did not recover after the confirmed programme upgrade'
   time.sleep(5)
  save('legacy-original-service-observation-recovery.json',{'read_only':True,'observations':recovery_observations,'original_immediate_snapshot_preserved':True,'no_mutation_or_job_replay':True,'original_unknown_states_not_relabelled':True})
  after=snapshot();assert canonical_service_rows(after['tables']['monitor_services'])==wanted_services;save('legacy-after-programme-upgrade-original113.json',after);reference=copy.deepcopy(before)
  for name,binary in [('panel.service','panel'),('panel-executor.service','panel-executor')]:
   assert before['lifetimes'][name]!=after['lifetimes'][name]and after['lifetimes'][name]['exe_sha256']==sha('/opt/panel/current/bin/'+binary);reference['lifetimes'][name]=copy.deepcopy(after['lifetimes'][name])
  assert reference['lifetimes']==after['lifetimes']
  protected=lambda v:{n:s for n,s in v['protected_files'].items()if not any(n==x or n.startswith(x+'/')for x in ('/opt/panel/current/bin','/opt/panel/current/web'))}
  # The normal programme replaces exactly this signed, changed mount unit.
  # The original C55r2 guard is byte-identical. Every other non-programme
  # protected entry retains its exact original bytes, owner, mode and inode.
  mount_name='var-cache-panel'+chr(92)+'x2dapache'+chr(92)+'x2dbody.mount'
  mount_path='/etc/systemd/system/'+mount_name
  def signed_mount(archive_path):
   import tarfile
   with tarfile.open(archive_path,'r:gz')as stream:
    prefix=archive_path.name[:-7]
    member=stream.getmember(prefix+'/systemd/'+mount_name)
    assert member.isfile()and member.mode==0o644 and (member.uid,member.gid)==(501,20) # original signed publisher metadata; installed ownership is checked below
    raw=stream.extractfile(member).read()
   return raw.replace(b'/opt/panel/bin/',b'/opt/panel/current/bin/').replace(b'/opt/panel/web',b'/opt/panel/current/web').replace(b'development ',b'')
  old_mount=signed_mount(payload/('panel-'+pins['baseline_version']+'-linux-amd64.tar.gz'))
  new_mount=signed_mount(archive)
  assert hashlib.sha256(old_mount).hexdigest()=='bc085b3907119c3bbc79c112aef9d4e033ccbf802d1a9a8c4e24a3dbdb24c570'
  assert hashlib.sha256(new_mount).hexdigest()=='0d9fa296c116f6fcc53319c390810324a6ac7ff208c013d4f1c2fa6c83ae52d2'
  for snapshot_value,raw in((before,old_mount),(after,new_mount)):
   metadata=snapshot_value['protected_files'][mount_path]
   assert metadata['uid']==metadata['gid']==0 and metadata['mode']&0o7777==0o644 and metadata['links']==1 and metadata['bytes']==len(raw)and metadata['sha256']==hashlib.sha256(raw).hexdigest()
  projected=copy.deepcopy(before);projected['protected_files'][mount_path]=copy.deepcopy(after['protected_files'][mount_path])
  assert protected(projected)==protected(after)
  save('legacy-exact-original-signed-mount-replacement.json',{'ok':True,'only_changed_programme_unit':mount_path,'original':before['protected_files'][mount_path],'target':after['protected_files'][mount_path],'both_original_signed_archives_bound':True,'all_other_non_programme_entries_preserved_exactly':True,'original_failed_QA1_not_relabelled':True})
  for key_name in ('schema','nss','packages','NFS_state'):assert before[key_name]==after[key_name],key_name
  assert runtime_before=={n:unit(n)for n in runtime_before};delta=runpy.run_path(str(payload/'preservation.py'))['qualify_background'](reference,after);save('legacy-entire113-programme-upgrade-qualified.json',{'ok':True,'typed_background_delta':delta,'original_files_accounts_packages_and_site_runtime_lifetimes_preserved':True})
  assert file.read_bytes()==legacy_bytes;run_once('old-original-Format1-readonly-verify',['/opt/panel/current/bin/panel-executor','--verify-apache-body',legacy_body],90);login('post-upgrade-root-private-login')
 verify_installed();assert json.loads(pathlib.Path('/opt/panel/current/SOURCE_INPUTS.json').read_bytes())['inputs_sha256']==SOURCE;guard('target-complete-before-app-update')
 item,status=pair(catalogue('signed251-update-offered'),'apache-waf');assert item['version']=='2.5.1'and item['sha256']=='6e747eb2f2e3088567bb7ab45008979aa230794b7b1be434b957186c5218c531'and status['installed_version']=='2.3.0'and status['update_available']
 proof['signed_WAF_update_POSTs']+=1;reply=api('one-normal-signed230-to251-update','/app-registry/apache-waf/update',{'expected_version':item['version'],'expected_sha256':item['sha256']},202,secrets.token_hex(16));wait_job('signed230-to251-update',reply['job_id'],'runtime_jobs')
 current=json.loads((module/'installed.json').read_bytes());assert current['version']=='2.5.1'and current['installed_at']==old_record['installed_at']and all((module/n).read_bytes()==b for n,b in history.items())
 _,status=pair(catalogue('signed251-update-completed'),'apache-waf');assert status['installed_version']=='2.5.1'and not status['update_available']
 reply=api('one-original-normal-Format3-build','/software/apache-waf/body-engine/build',{},202,secrets.token_hex(16));engine=reply['job_id'];wait_job('original-normal-Format3-build',engine,'runtime_jobs')
 record=pathlib.Path('/var/lib/panel-executor/apache-body-builds')/(engine+'.json');original=record.read_bytes();assert json.loads(original)['format']==3
 run_once('actual-sealed-Format3-readonly-verify',['/opt/panel/current/bin/panel-executor','--verify-apache-body',engine],90);guard('complete-with-genuine-original-Format3');assert record.read_bytes()==original
 h=types.SimpleNamespace(payload=payload,evidence=evidence,api=api,save=save,wait_job=wait_job,unit=unit,proof=proof)
 result=runpy.run_path(str(payload/'acceptance.py'))['run'](h,engine,legacy_body);save('actual-owned-native-before-archive-acceptance-result.json',result);result=runpy.run_path(str(payload/'archive_acceptance.py'))['run'](h,result);save('actual-owned-native-acceptance-result.json',result)
 api('final-owned-session-logout','/logout',{});csrf='';guard('complete-after-all-native-requests')
 save('before-hard-powerloss-original113.json',snapshot())
 receipts={f.name:{'sha256':sha(f),'original_hex':f.read_bytes().hex()}for f in pathlib.Path('/var/lib/panel-executor/apache-body-builds').iterdir()}
 intent={'base':str(base),'boot':boot,'source_inputs_sha256':SOURCE,'machine_id_sha256':sha('/etc/machine-id'),'root_uuid':command(['findmnt','-n','-o','UUID','/']).strip(),'cold_script_sha256':sha(payload/'cold.py'),'CC_log':result['CC_log'],'native_engine_receipts':receipts,'owned_result':result}
 with(base/'cold-intent.json').open('x')as f:json.dump(intent,f,sort_keys=True);f.write('\n');f.flush();os.fsync(f.fileno())
 proof.update(ok=True,actual_hard_powerloss_pending=True,normal_original_signed_programme_installed=True,all204_installed_entries_verified=True,legacy_metadata230_to_signed251_update_completed=True,legacy_installed_at_and_history_preserved=True,actual_Format3_complete_programme_guard_passed=True,legacy_Format1_preserved=legacy_body is not None,powerloss_ready=True)
except BaseException:save('original-failure.json',{'traceback':traceback.format_exc()})
finally:
 if csrf:
  try:api('failure-owned-session-logout','/logout',{});csrf=''
  except BaseException:proof['logout_unknown_observe_only']=True;proof['ok']=False
 save('HTTP-events.json',events);save('proof.json',proof)
 for directory in (evidence,base):
  fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
 print(json.dumps({'ok':proof['ok'],'base':str(base),'proof_sha256':sha(evidence/'proof.json'),'source_inputs_sha256':SOURCE,'architecture':'amd64','powerloss_ready':proof.get('powerloss_ready',False),'Main_changed':False,'all50_commercial':False}),flush=True)
sys.exit(0 if proof['ok']else 1)
