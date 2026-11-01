"""One normal historical bootstrap to signed C44r2 upgrade and PM2 store journey.
Uses actual hardware-KVM AMD64. Existing isolated ARM64 evidence is separate.
"""
import ast,contextlib,copy,hashlib,http.cookiejar,json,os,pathlib,platform,pwd,re,runpy,secrets,socket,sqlite3,stat,subprocess,sys,time,traceback,urllib.error,urllib.request
os.umask(0o077);assert len(sys.argv)==2 and os.geteuid()==0
payload=pathlib.Path(sys.argv[1]).resolve(strict=True);pins=json.loads((payload/'assets.json').read_bytes());arch={'aarch64':'arm64','x86_64':'amd64'}[platform.machine()]
SOURCE='038aeb46562e6e080e8bba061c1dd3285405056b9e8fafe6bcaba6213abe57cd';VERSION='0.1.0-dev.proapps24alertreadonlycandidate44r2'
BOOTSTRAP_VERSION='0.1.0-dev.proapps24phpswitchpreservecandidate41r3'
BOOTSTRAP_SOURCE='757e1941dc2e3e138cef458eb52114545d168ee41286872012e100770c50a1fb'
assert pins['architecture']==arch and pins['format']==1 and pins['source_inputs_sha256']==SOURCE and pins['version']==VERSION
case=pins['OS_case'];assert case['architecture']==arch=='amd64' and case['platform'] in ('debian-12','debian-13','ubuntu-22.04','ubuntu-24.04','ubuntu-26.04')
assert pathlib.Path('/etc/hostname').read_text().strip()==case['hostname']
assert 'VERSION_ID="'+case['version_id']+'"'in pathlib.Path('/usr/lib/os-release').read_text()and pathlib.Path('/proc/1/comm').read_text().strip()=='systemd'
base=pathlib.Path('/opt/panel-pm2-c44r2-native-qa-'+secrets.token_hex(16));base.mkdir(mode=0o700);evidence=base/'evidence';evidence.mkdir(mode=0o700)
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

proof={'ok':False,'architecture':arch,'base':str(base),'scope':'Original-key normal C41 install and legacy default PM2 compat5, signed normal C44r2 programme upgrade, real nonroot account/project journey and signed PM2 compat6 store update; no full commercial claim','source_inputs_sha256':SOURCE,'OS_case':case,'Main_changed':False,'all50_commercial':False,'original_operation_replay':False}
functional_base=None;prepare_base=None;bootstrap_base=None;shop_base=None
try:
 assert all(not os.path.lexists(n)for n in('/opt/panel','/var/lib/panel','/var/lib/panel-executor','/etc/panel-release','/etc/nginx/nginx.conf'))
 archive=payload/('panel-'+VERSION+'-linux-'+arch+'.tar.gz');legacy_archive=payload/('panel-'+BOOTSTRAP_VERSION+'-linux-'+arch+'.tar.gz');signer=['python3','-I','-B',str(payload/'signed-release.py')];key=['--public-key',str(payload/'release-signing-dev.pub')]
 command('legacy-programme-signature-verify',signer+['verify',str(legacy_archive)]+key,30);command('normal-first-C41-install',signer+['install',str(legacy_archive)]+key,1200);assert json.loads(pathlib.Path('/opt/panel/current/SOURCE_INPUTS.json').read_bytes())['inputs_sha256']==BOOTSTRAP_SOURCE and not os.path.lexists('/opt/panel/DEVELOPMENT_RELEASE');guard('legacy-programme')
 def stage_worker(target,plan,worker):
  for name,raw in [('worker.py',(payload/worker).read_bytes()),('capture.py',(payload/'capture.py').read_bytes()),('intent.json',json.dumps(plan,sort_keys=True).encode())]:
   with os.fdopen(os.open(target/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600),'wb')as f:f.write(raw);f.flush();os.fsync(f.fileno())
  for directory in(target,target.parent):
   fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
 bootstrap_base=pathlib.Path('/opt/panel-pm2-c44r2-bootstrap-'+secrets.token_hex(16));bootstrap_base.mkdir(mode=0o700);boot=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip();bootstrap={'base':str(bootstrap_base),'boot':boot,'architecture':arch,'platform':case['platform'],'synthetic_environment':secrets.token_urlsafe(36),'install_key':secrets.token_hex(16),'files':{'capture.py':sha(payload/'capture.py'),'worker.py':sha(payload/'bootstrap.py')}};stage_worker(bootstrap_base,bootstrap,'bootstrap.py');command('original-legacy-PM2-bootstrap',['/usr/bin/python3','-I','-B',str(bootstrap_base/'worker.py'),str(bootstrap_base)],1500);legacy=json.loads((bootstrap_base/'evidence/proof.json').read_bytes());assert legacy['ok']and legacy['normal_legacy_PM2_install_POSTs']==1 and not legacy['normal_signed_catalogue_install_claim']
 def programme_snapshot(label):
  selected={'sha','command','unit','snapshot'};nodes=[n for n in ast.parse((payload/'capture.py').read_bytes()).body if isinstance(n,ast.FunctionDef)and n.name in selected];assert len(nodes)==len(selected);ns={**globals(),'p':{'boot':boot},'own_site':None};exec(compile(ast.Module(body=nodes,type_ignores=[]),'<original-full113-programme-preservation-observer>','exec'),ns);v=ns['snapshot']();v['source_inputs']=json.loads(pathlib.Path('/opt/panel/current/SOURCE_INPUTS.json').read_bytes())['inputs_sha256'];save(label+'.json',v);return v
 before=programme_snapshot('programme-before');command('new-programme-signature-verify',signer+['verify',str(archive)]+key,30);upgrade=signer+['install',str(archive)]+key;command('new-programme-preflight',upgrade+['--preflight-only'],900);pre=programme_snapshot('programme-after-preflight');command('one-normal-programme-upgrade',upgrade,1200);after=programme_snapshot('programme-after-upgrade');assert before['source_inputs']==pre['source_inputs']==BOOTSTRAP_SOURCE and after['source_inputs']==SOURCE
 assert before['schema']==pre['schema']==after['schema']and before['nss']==pre['nss']==after['nss']and before['packages']==pre['packages']==after['packages']and before['NFS_state']==pre['NFS_state']==after['NFS_state'];assert before['protected_files']==pre['protected_files']
 protected=lambda v:{n:x for n,x in v['protected_files'].items()if not any(n==k or n.startswith(k+'/')for k in('/opt/panel/current/bin','/opt/panel/current/web'))};assert protected(before)==protected(after)
 for name in before['lifetimes']:
  assert before['lifetimes'][name]==pre['lifetimes'][name]
  if name in('panel.service','panel-executor.service'):assert before['lifetimes'][name]['MainPID']!=after['lifetimes'][name]['MainPID']and before['lifetimes'][name]['InvocationID']!=after['lifetimes'][name]['InvocationID']
  else:assert before['lifetimes'][name]==after['lifetimes'][name]
 assert json.loads(pathlib.Path('/etc/panel/security-apps/modules/pm2-manager/installed.json').read_bytes())['version']=='7.0.4-compat5';verify_full_installed_archive();guard('upgraded-programme');save('normal-programme-upgrade-preserved.json',{'all113_schema_and_NSS_preserved':True,'nonprogramme_protected_entries':len(protected(before)),'old_legacy_PM2_identity_preserved':True,'only_expected_two_programme_lifetimes_changed':True,'full_SQL_row_independent_reconciliation_pending':True})
 nonce=secrets.token_hex(16);prepare_base=pathlib.Path('/opt/panel-pm2-c43-prepare-'+nonce);prepare_base.mkdir(mode=0o700)
 prepare={'base':str(prepare_base),'boot':boot,'architecture':arch,'platform':case['platform'],'source_inputs_sha256':SOURCE,'legacy_install_job_id':legacy['legacy_install_job_id'],'resource_id':'qa-c43-'+nonce[:16],'marker':'owned-C44r2-fresh-'+nonce,'entry':'pm2-c43-baseline.js','port':24431,'synthetic_environment':secrets.token_urlsafe(36),'install_key':secrets.token_hex(16),'site_key':secrets.token_hex(16),'files':{'capture.py':sha(payload/'capture.py'),'worker.py':sha(payload/'prepare.py')}}
 stage_worker(prepare_base,prepare,'prepare.py');save('original-prepare-bound-plan.json',{'source_inputs_sha256':SOURCE,'architecture':arch,'platform':case['platform'],'worker_sha256':sha(payload/'prepare.py'),'capture_sha256':sha(payload/'capture.py'),'maximum_normal_install_POSTs':0,'legacy_install_was_separate_once':True,'maximum_site_create_POSTs':1,'maximum_PM2_create_POSTs':1,'synthetic_environment_sha256':hashlib.sha256(prepare['synthetic_environment'].encode()).hexdigest(),'no_plaintext_environment_in_uploaded_plan':True})
 command('original-prepare',['/usr/bin/python3','-I','-B',str(prepare_base/'worker.py'),str(prepare_base)],1800);prepared=json.loads((prepare_base/'evidence/proof.json').read_bytes());assert prepared['ok']and prepared['normal_PM2_install_POSTs']==0 and prepared['normal_site_create_POSTs']==prepared['normal_PM2_create_POSTs']==1
 fixture=json.loads((prepare_base/'evidence/prepared-owned-fixture.json').read_bytes());assert fixture['native_unit_stopped_boot_disabled']and fixture['app_revision']==2 and fixture['start_count']==2 and fixture['actual_nonroot_UID']>0 and fixture['actual_primary_GID']>0
 functional_base=pathlib.Path('/opt/panel-pm2-c43-service-'+secrets.token_hex(16));functional_base.mkdir(mode=0o700)
 plan={**prepare,'base':str(functional_base),'site_id':fixture['site_id'],'bad_entry':'pm2-c43-deliberately-failing.js','replacement_environment':secrets.token_urlsafe(36),'failed_candidate_environment':secrets.token_urlsafe(36),'files':{'worker.py':sha(payload/'functional.py'),'guest.py':sha(payload/'functional.py'),'capture.py':sha(payload/'capture.py')}}
 stage_worker(functional_base,plan,'functional.py');save('original-functional-bound-plan.json',{'source_inputs_sha256':SOURCE,'site_id':fixture['site_id'],'resource_id':fixture['resource_id'],'architecture':arch,'platform':case['platform'],'worker_sha256':sha(payload/'functional.py'),'capture_sha256':sha(payload/'capture.py'),'maximum_each_named_POST':1,'unknown_outcome_observe_only':True,'environment_value_hashes':{k:hashlib.sha256(plan[k].encode()).hexdigest()for k in ('synthetic_environment','replacement_environment','failed_candidate_environment')}})
 command('original-functional',['/usr/bin/python3','-I','-B',str(functional_base/'worker.py'),str(functional_base)],300);result=json.loads((functional_base/'evidence/proof.json').read_bytes());assert result['ok']and result['stopped_configuration_saves_never_started_project']and result['active_failed_update_restored_exact_manifest_and_old_secret']and result['owned_fixture_retained_stopped_boot_disabled']
 shop_base=pathlib.Path('/opt/panel-pm2-c44r2-shop-'+secrets.token_hex(16));shop_base.mkdir(mode=0o700);shop_plan={**plan,'base':str(shop_base),'store_key':secrets.token_hex(16),'files':{'worker.py':sha(payload/'shop.py'),'capture.py':sha(payload/'capture.py')}};stage_worker(shop_base,shop_plan,'shop.py');command('original-signed-compat6-store-update',['/usr/bin/python3','-I','-B',str(shop_base/'worker.py'),str(shop_base)],1200);shop=json.loads((shop_base/'evidence/proof.json').read_bytes());assert shop['ok']and shop['normal_store_update_POSTs']==1 and shop['old_encrypted_configuration_bytes_preserved']and shop['actual_stopped_unit_and_start_counter_unchanged']and shop['store_no_longer_offers_same_update']
 proof.update(ok=True,normal_programme_signature_and_all203_installed_entries_verified=True,normal_C41_to_C44r2_programme_upgrade=True,original_legacy_PM2_install_version='7.0.4-compat5',legacy_install_not_signed_catalogue_claim=True,normal_signed_PM2_store_update_version='7.0.4-compat6',actual_nonroot_UID=fixture['actual_nonroot_UID'],actual_primary_GID=fixture['actual_primary_GID'],bootstrap_proof_sha256=sha(bootstrap_base/'evidence/proof.json'),prepare_proof_sha256=sha(prepare_base/'evidence/proof.json'),functional_proof_sha256=sha(functional_base/'evidence/proof.json'),shop_proof_sha256=sha(shop_base/'evidence/proof.json'),actual_HTTP_primary_GID_stopped_save_boot_controls_and_rollback=True,handler_source_inputs_sha256=SOURCE,actual_reboot_pending=True,actual_browser_UI_acceptance=False,full_SQL_row_independent_reconciliation_pending=True)


except BaseException:save('original-failure.json',{'traceback':traceback.format_exc()})
finally:
 for selected,label in ((bootstrap_base,'bootstrap-'),(prepare_base,'prepare-'),(functional_base,'functional-'),(shop_base,'shop-')):
  if selected is not None and(selected/'evidence').is_dir():
   members=sorted((selected/'evidence').iterdir());assert len(members)<=250;total=0
   for f in members:
    s=f.lstat();assert re.fullmatch('[A-Za-z0-9._-]+',f.name)and stat.S_ISREG(s.st_mode)and s.st_uid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600 and s.st_size<32<<20;raw=f.read_bytes();total+=len(raw);assert total<128<<20
    with os.fdopen(os.open(evidence/(label+f.name),os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600),'wb')as dst:dst.write(raw);dst.flush();os.fsync(dst.fileno())
 save('proof.json',proof);print(json.dumps({'ok':proof['ok'],'base':str(base),'proof_sha256':sha(evidence/'proof.json'),'source_inputs_sha256':SOURCE,'architecture':arch,'Main_changed':False,'all50_commercial':False}),flush=True)
sys.exit(0 if proof['ok']else 1)
