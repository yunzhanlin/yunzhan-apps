"""Fresh original-signed C53r3 -> C54, real retention, then prepare an actual hard power loss."""
import ast,contextlib,copy,gzip,hashlib,http.cookiejar,json,os,pathlib,platform,pwd,re,runpy,secrets,shutil,sqlite3,stat,subprocess,sys,tarfile,time,traceback,urllib.error,urllib.request
os.umask(0o077);assert os.geteuid()==0 and len(sys.argv)==2
payload=pathlib.Path(sys.argv[1]).resolve(strict=True);pins=json.loads((payload/'assets.json').read_bytes())
OLD='5205013d8b65fea12a4f3dd584c3a6cc49afa3bd7582c59e5f3c917cac36bb87';NEW='2b8e71c50b16ba6008955a4d9168b195a087e3063412445a0596f27b53b1bfb9'
OLD_VERSION='0.1.0-dev.proapps24analyticsidentitycandidate53r3';VERSION='0.1.0-dev.proapps24backupretentioncandidate54'
assert platform.machine()=='x86_64'and pins['architecture']=='amd64'and pins['version']==VERSION and pins['source_inputs_sha256']==NEW and pins['baseline_source_inputs_sha256']==OLD and pins['baseline_version']==OLD_VERSION
case=pins['OS_case'];assert case['platform']in('debian-12','debian-13','ubuntu-22.04','ubuntu-24.04','ubuntu-26.04')and pathlib.Path('/etc/hostname').read_text().strip()==case['hostname']and 'VERSION_ID="'+case['version_id']+'"'in pathlib.Path('/usr/lib/os-release').read_text()
base=pathlib.Path('/opt/panel-retention-c54-native-qa-'+secrets.token_hex(16));base.mkdir(mode=0o700);evidence=base/'evidence';evidence.mkdir(mode=0o700)
def sha(f):return hashlib.sha256(pathlib.Path(f).read_bytes()).hexdigest()
def save(n,v):
 assert re.fullmatch('[A-Za-z0-9._-]+',n)
 with os.fdopen(os.open(evidence/n,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600),'w')as f:json.dump(v,f,sort_keys=True,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
verified=base/'verified-input';verified.mkdir(mode=0o700)
for n,h in pins['files'].items():
 assert re.fullmatch('[A-Za-z0-9._-]+',n)
 with os.fdopen(os.open(payload/n,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC),'rb')as f:
  s=os.fstat(f.fileno());assert stat.S_ISREG(s.st_mode)and s.st_nlink==1 and 0<s.st_size<=64<<20;raw=f.read((64<<20)+1);z=os.fstat(f.fileno());assert len(raw)==s.st_size and hashlib.sha256(raw).hexdigest()==h and(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)==(z.st_dev,z.st_ino,z.st_size,z.st_mtime_ns,z.st_ctime_ns)
 with os.fdopen(os.open(verified/n,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600),'wb')as f:f.write(raw);f.flush();os.fsync(f.fileno())
payload=verified;assert sha(payload/'signed-release.py')=='fe128e82b4e11345b320cd782134768bfe1a4df14947c425d7494873a7a7b7b5'and sha(payload/'release-signing-dev.pub')=='4ccfcc861d56a41e3ba7f7ace7e2432c815f366c58448d783df92c6632f01339'
names={'command','unit','snapshot','NoRedirect'};nodes=[v for v in ast.parse((payload/'capture.py').read_bytes()).body if isinstance(v,(ast.FunctionDef,ast.ClassDef))and v.name in names];assert len(nodes)==4;exec(compile(ast.Module(body=nodes,type_ignores=[]),'<original-full113-observer>','exec'),globals())
names={'guard','wait_initial_cpu_observation','run_once','installed_archive','preserving_programme_compare'};nodes=[v for v in ast.parse((payload/'baseline-guest.py').read_bytes()).body if isinstance(v,ast.FunctionDef)and v.name in names];assert len(nodes)==5;exec(compile(ast.Module(body=nodes,type_ignores=[]),'<original-C53r3-install-and-preservation-helpers>','exec'),globals())
qualify=runpy.run_path(str(payload/'preservation.py'))['qualify_background'];boot=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip();p={'boot':boot};own_site=None
proof={'ok':False,'base':str(base),'architecture':'amd64','OS_case':case,'source_inputs_sha256':NEW,'normal_C53r3_first_install_submissions':0,'normal_C54_upgrade_submissions':0,'Main_changed':False,'all50_commercial':False,'actual_browser_UI_acceptance':False,'original_mutations_replayed':False,'powerloss_ready':False}
try:
 assert all(not os.path.lexists(n)for n in('/opt/panel','/var/lib/panel','/var/lib/panel-executor','/etc/nginx/nginx.conf','/etc/panel-release'))
 signer=['python3','-I','-B',str(payload/'signed-release.py')];key=['--public-key',str(payload/'release-signing-dev.pub')];old=payload/('panel-'+OLD_VERSION+'-linux-amd64.tar.gz');new=payload/('panel-'+VERSION+'-linux-amd64.tar.gz')
 run_once('original-C53r3-signature-verify',signer+['verify',str(old)]+key,45);proof['normal_C53r3_first_install_submissions']+=1;run_once('one-original-C53r3-first-install',signer+['install',str(old)]+key,1800);assert not pathlib.Path('/opt/panel/DEVELOPMENT_RELEASE').exists();installed_archive('actual-C53r3',OLD_VERSION,OLD);wait_initial_cpu_observation();guard('original-baseline')
 before=snapshot();save('before-C54-upgrade-original113.json',before);run_once('original-C54-signature-verify',signer+['verify',str(new)]+key,45)
 run_once('one-C54-upgrade-preflight',signer+['install',str(new)]+key+['--preflight-only'],900);pre=snapshot();save('after-C54-preflight-original113.json',pre);save('preflight-preservation-qualified.json',preserving_programme_compare(before,pre))
 proof['normal_C54_upgrade_submissions']+=1;run_once('one-original-signed-C54-upgrade',signer+['install',str(new)]+key,1200);target=installed_archive('actual-C54',VERSION,NEW);after=snapshot();save('after-C54-upgrade-original113.json',after);save('upgrade-preservation-qualified.json',preserving_programme_compare(before,after,target));guard('C54-upgraded')
 nonce=secrets.token_hex(16);business_root=pathlib.Path('/opt/panel-retention-c54-business-'+nonce);business_root.mkdir(mode=0o700);files={}
 for n,source in [('guest.py',payload/'business.py'),('capture.py',payload/'capture.py')]:
  with(business_root/n).open('xb')as f:f.write(source.read_bytes());f.flush();os.fsync(f.fileno())
  files[n]=sha(business_root/n)
 intent={'root':str(business_root),'nonce':nonce,'files':files,'peer':{'boot':boot,'machine_id_sha256':sha('/etc/machine-id')},'boot':boot,'site_id':None,'resource_id':None,'source_inputs_sha256':NEW}
 with(business_root/'intent.json').open('x')as f:json.dump(intent,f,sort_keys=True);f.flush();os.fsync(f.fileno())
 run_once('one-real-scheduler-and-Root-business',['python3','-I','-B',str(business_root/'guest.py'),str(business_root)],420)
 business=json.loads((business_root/'evidence/proof.json').read_bytes());assert business['ok']and business['real_backups_created']==7 and business['actual_completed_deletions']==1 and business['durable_unknown_not_replayed_after_real_Core_SIGKILL'];save('original-business-proof.json',business)
 shutil.copytree(business_root/'evidence',evidence/'business',copy_function=shutil.copyfile)
 definitions={'api','policy','entry','backup_inventory'};nodes=[v for v in ast.parse((payload/'business.py').read_bytes()).body if isinstance(v,ast.FunctionDef)and v.name in definitions];assert len(nodes)==4;exec(compile(ast.Module(body=nodes,type_ignores=[]),'<reviewed-once-only-business-API-and-observer>','exec'),globals())
 origin='http://127.0.0.1:19100';csrf='';events=[];client=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect(),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()));access=json.loads(pathlib.Path('/etc/panel/first-login.json').read_bytes())
 try:csrf=api('cold-preparation-login','/login',{k:access[k]for k in('username','password')})['csrf']
 finally:access.clear()
 current=api('cold-owned-schedules','/schedules')['schedules'];assert {v['id']for v in current}==set(business['schedule_ids'])and all(not v['enabled']for v in current)
 for i,schedule in enumerate(current):updated=policy('cold-enable-only-owned-'+str(i),schedule,2,True);assert updated['enabled']and updated['revision']==4
 api('cold-preparation-logout','/logout',{});time.sleep(7)
 with contextlib.closing(sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True))as db:
  db.row_factory=sqlite3.Row;db.execute('PRAGMA query_only=ON');cleanup=[dict(v)for v in db.execute('SELECT *FROM site_schedule_cleanup_jobs ORDER BY artifact_id')];assert len(cleanup)==3 and all(v['attempts']==1 for v in cleanup)
 save('cold-enabled-original-records.json',cleanup);cold_before=snapshot();save('before-hard-powerloss-original113.json',cold_before);backup_inventory('before-hard-powerloss-backups')
 # Persist only this QA's evidence. Do not sync/checkpoint, chmod or otherwise
 # prepare the product DB, backup files or executor receipts for the power cut.
 for outcome_file in evidence.glob('*-original-outcome.json'):
  operation=json.loads(outcome_file.read_bytes());stem=outcome_file.name[:-len('-original-outcome.json')]
  for channel in('stdout','stderr'):assert sha(evidence/(stem+'.'+channel+'.log'))==operation[channel+'_sha256']
 durable={}
 for f in sorted(evidence.rglob('*')):
  metadata=f.lstat();assert not stat.S_ISLNK(metadata.st_mode)
  if stat.S_ISDIR(metadata.st_mode):continue
  assert stat.S_ISREG(metadata.st_mode)and metadata.st_uid==0 and metadata.st_nlink==1 and stat.S_IMODE(metadata.st_mode)==0o600 and metadata.st_size<32<<20
  fd=os.open(f,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
  try:os.fsync(fd)
  finally:os.close(fd)
  durable[str(f.relative_to(evidence))]={'sha256':sha(f),'bytes':metadata.st_size,'mode':stat.S_IMODE(metadata.st_mode),'uid':metadata.st_uid,'gid':metadata.st_gid,'inode':metadata.st_ino}
 save('pre-powerloss-durable-QA-evidence.json',durable)
 for folder in sorted([evidence,*[f for f in evidence.rglob('*')if f.is_dir()]],key=lambda f:len(f.parts),reverse=True):
  fd=os.open(folder,os.O_RDONLY|os.O_DIRECTORY)
  try:os.fsync(fd)
  finally:os.close(fd)
 cold={'base':str(base),'boot':boot,'machine_id_sha256':sha('/etc/machine-id'),'root_uuid':subprocess.check_output(['findmnt','-n','-o','UUID','/'],text=True).strip(),'source_inputs_sha256':NEW,'cold_script_sha256':sha(payload/'cold.py'),'target_programmes':target,'business_root':str(business_root),'schedule_ids':business['schedule_ids']}
 with(base/'cold-intent.json').open('x')as f:json.dump(cold,f,sort_keys=True);f.flush();os.fsync(f.fileno())
 fd=os.open(base,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
 proof.update(ok=True,powerloss_ready=True,business_root=str(business_root),normal_original_signed_install_and_upgrade=True,all203_actual_installed_entries_verified=True,all113_original_upgrade_tables_qualified=True,real_normal_API_backups=7,real_permission_failure_no_starvation=True,real_Core_SIGKILL_unknown_not_replayed=True,two_owned_schedules_enabled_for_real_powerloss=True,independent_business_original113_reconciliation_pending=True)
except BaseException:save('original-failure.json',{'traceback':traceback.format_exc()})
save('proof.json',proof);print(json.dumps(proof),flush=True);sys.exit(0 if proof['ok']else 1)
