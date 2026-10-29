"""One clean native C27 install and original disk1.4.1 functional requests.

All actions are once-only; failures retain the original evidence. SQL, logs
and native receipts stay private and are encrypted by the KVM host.
"""
import contextlib,datetime,hashlib,json,os,pathlib,platform,re,runpy,secrets,shutil,sqlite3,stat,subprocess,sys,time,traceback
os.umask(0o077);assert os.geteuid()==0 and platform.machine()=='x86_64'and len(sys.argv)==2
payload=pathlib.Path(sys.argv[1]).resolve(strict=True);base=pathlib.Path('/opt/panel-native-qa-'+secrets.token_hex(16));base.mkdir(mode=0o700);evidence=base/'evidence';evidence.mkdir(mode=0o700)
def sha(path):
 h=hashlib.sha256()
 with pathlib.Path(path).open('rb')as source:
  for block in iter(lambda:source.read(1<<20),b''):h.update(block)
 return h.hexdigest()
def save(name,value):
 assert re.fullmatch('[A-Za-z0-9._-]+',name)
 with os.fdopen(os.open(evidence/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600),'w')as out:json.dump(value,out,sort_keys=True);out.write('\n');out.flush();os.fsync(out.fileno())
pins=json.loads((payload/'assets-v3.json').read_bytes());assert pins['format']==1 and pins['architecture']=='amd64'and pins['harness_revision']==3 and pins['source_inputs_sha256']=='3905be8250f8927d651ab90ec2b2bedafb737f2a4e4bb607b79fd1a18057a6c9'
assert pins['programme_key_sha256']=='4ccfcc861d56a41e3ba7f7ace7e2432c815f366c58448d783df92c6632f01339'and pins['verifier_sha256']=='fe128e82b4e11345b320cd782134768bfe1a4df14947c425d7494873a7a7b7b5'
for name,digest in pins['files'].items():
 assert re.fullmatch('[A-Za-z0-9._-]+',name);source=payload/name;s=source.lstat();assert stat.S_ISREG(s.st_mode)and s.st_nlink==1 and sha(source)==digest
 shutil.copyfile(source,base/name,follow_symlinks=False);os.chmod(base/name,0o600)
assert sha(base/'programme.pub')==pins['programme_key_sha256']and sha(base/'signed-release.py')==pins['verifier_sha256']
model=runpy.run_path(str(base/'candidate8-programme-business.py'));original=model['original']
def capture():
 with contextlib.closing(sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True,timeout=3))as db:
  db.execute('PRAGMA query_only=ON');db.execute('BEGIN');assert db.execute('PRAGMA quick_check').fetchone()==('ok',)
  names={r[0]for r in db.execute("SELECT name FROM sqlite_schema WHERE type='table'AND name NOT LIKE'sqlite_%'")};assert len(names)==111 and original['VOLATILE']<=names
  columns={name:[r[1]for r in db.execute('PRAGMA table_info("'+name+'")')]for name in sorted(names-original['VOLATILE'])};assert len(columns)==105
  records={};count=0
  for name,fields in columns.items():
   assert all(re.fullmatch('[A-Za-z_][A-Za-z_0-9]*',value)for value in(name,*fields));values=db.execute('SELECT * FROM "'+name+'"').fetchmany(10001);assert len(values)<=10000;count+=len(values);assert count<=50000
   records[name]=sorted([[original['encode'](v)for v in row]for row in values],key=original['raw'])
  result={'at':time.time(),'actual_tables':111,'business_tables':105,'columns':columns,'full_rows':records,'data':{n:original['digest'](v)for n,v in records.items()},'row_count':count,'schema':[list(v)for v in db.execute("SELECT type,name,tbl_name,sql FROM sqlite_schema WHERE name NOT LIKE'sqlite_%'ORDER BY type,name")],'migration_columns':[v[1]for v in db.execute('PRAGMA table_info(schema_migrations)')],'migrations':sorted([[original['encode'](v)for v in row]for row in db.execute('SELECT *FROM schema_migrations')],key=original['raw'])}
  assert len(original['raw'](result))<=16<<20;return result
def command(label,args,timeout):
 started=time.monotonic()
 with(evidence/(label+'.log')).open('xb')as output:value=subprocess.run(args,stdin=subprocess.DEVNULL,stdout=output,stderr=subprocess.STDOUT,timeout=timeout)
 result={'exit':value.returncode,'seconds':time.monotonic()-started,'log_sha256':sha(evidence/(label+'.log'))};save(label+'-result.json',result);assert value.returncode==0,label+' failed; original evidence retained';return result
def guard():
 p=subprocess.run(['/opt/panel/current/bin/panel-executor','--check-program-upgrade-queues'],capture_output=True,timeout=30);assert p.returncode==0 and p.stdout==p.stderr==b''
def nss():return {name:sha('/etc/'+name)for name in('passwd','group','shadow','gshadow','nsswitch.conf')}
def nginx():
 raw=subprocess.check_output(['systemctl','show','nginx.service','--property=LoadState,ActiveState,SubState,MainPID,InvocationID,ExecMainStartTimestampMonotonic'],text=True,timeout=5);value=dict(line.split('=',1)for line in raw.splitlines());assert value['LoadState']=='loaded'and value['ActiveState']=='active'and int(value['MainPID'])>0;return value
def healthy_capture(label):
 trace=[]
 for attempt in range(65):
  with contextlib.closing(sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True,timeout=3))as db:
   db.execute('PRAGMA query_only=ON');rows=db.execute('SELECT id,worker_state,worker_checked_at FROM load_balance_traffic_source').fetchall();assert len(rows)<=1
   trace.append({'at':time.time(),'rows':rows})
   if not rows:
    assert not os.path.lexists('/etc/panel/security-apps/modules/load-balance')
    assert not os.path.lexists('/etc/panel/load-balance-stream')
    assert not any(p.name.startswith('load-balance-stream')for p in pathlib.Path('/var/lib/panel-executor').iterdir())
    counts={}
    for table,predicate in [('load_balance_stream_controls','1=1'),('load_balance_stream_install_requests','1=1'),('app_registry_receipts',"app_id='load-balance'"),('app_registry_pending',"app_id='load-balance'"),('app_registry_install_requests',"app_id='load-balance'"),('app_registry_update_requests',"app_id='load-balance'"),('runtime_jobs',"target_id='load-balance'")]:
     count=db.execute('SELECT count(*) FROM '+table+' WHERE '+predicate).fetchone()[0];assert type(count)is int and count==0;counts[table]=count
    save(label+'-source-gate.json',{'known_uninstalled_module_and_original_native_authority_absent':True,'counts':counts,'observations':trace,'source_synthesized_or_repaired':False})
    return capture()
  if rows:
   identity,state,clock=rows[0];assert identity==1
   if state=='clear'and time.time()-16<=datetime.datetime.fromisoformat(clock.replace('Z','+00:00')).timestamp()<=time.time()+1:
    save(label+'-source-gate.json',{'original_healthy_source_clock':True,'observations':trace,'source_synthesized_or_repaired':False})
    return capture()
  if attempt==64:save(label+'-source-gate-refused.json',{'observations':trace,'source_synthesized_or_repaired':False});raise AssertionError('No healthy original source clock; not synthesized or repaired')
  time.sleep(1)


def initialized_baseline_capture(label):
 # The normal background worker initializes exactly these five zero cursors
 # after its first five-second tick. Wait for that real committed observation
 # before freezing the baseline; do not create rows or relax the comparison.
 expected=[(name,0)for name in sorted(('file-monitor','website-tamper-proof','enterprise-tamper-proof','files-sync','php-code-security'))]
 trace=[];consecutive=0
 for attempt in range(65):
  with contextlib.closing(sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True,timeout=3))as db:
   db.execute('PRAGMA query_only=ON');db.execute('BEGIN')
   cursors=db.execute('SELECT module_id,cursor FROM app_notification_cursors ORDER BY module_id').fetchall()
   dispatch=db.execute('SELECT id,last_error,last_check_at FROM notification_dispatch_status').fetchall()
   assert len(dispatch)==1 and dispatch[0][0]==1
   assert all(type(name)is str and type(cursor)is int and(name,cursor)in expected for name,cursor in cursors)and len(cursors)==len(set(cursors))
   assert dispatch[0][1]=='','Background initialization reported a failure; not suppressed'
   checked=dispatch[0][2];now=time.time()
   fresh=bool(checked)and now-16<=datetime.datetime.fromisoformat(checked.replace('Z','+00:00')).timestamp()<=now+1
   trace.append({'at':now,'cursors':cursors,'dispatch':dispatch})
   consecutive=consecutive+1 if cursors==expected and fresh else 0
  if consecutive>=2:
   value=healthy_capture(label)
   assert value['full_rows']['app_notification_cursors']==[[['text',name],['integer','0']]for name,_ in expected]
   save(label+'-initialized-cursors-gate.json',{'real_background_initialization_committed':True,'two_consecutive_read_only_observations':True,'observations':trace,'database_rows_synthesized_or_ignored':False,'upgrade_full_row_comparison_unchanged':True})
   return value
  if attempt==64:
   save(label+'-initialized-cursors-gate-refused.json',{'observations':trace,'database_rows_synthesized_or_ignored':False})
   raise AssertionError('Normal baseline initialization did not settle; not synthesized or repaired')
  time.sleep(1)



def collect_native():
 # Collect original receipts even if a later independent phase fails.
 # Never replay an operation or replace any original worker record.
 native=evidence/'native';native.mkdir(mode=0o700);files={}
 for case in sorted(evidence.iterdir()):
  if not case.is_dir()or not re.fullmatch(r'0[1-4]-(?:store-install|native-scan|native-fast-cancel|native-active-cancel)',case.name):continue
  record=case/'proof.json'
  if not record.exists():continue
  job=json.loads(record.read_bytes()).get('original_job_id')
  if not job:continue
  assert re.fullmatch('[a-f0-9]{32}',job)
  root=pathlib.Path('/var/lib/panel-executor/disk-host-jobs')/job
  target=native/job;target.mkdir(mode=0o700)
  for path in sorted(root.iterdir()):
   s=path.lstat();assert stat.S_ISREG(s.st_mode)and s.st_uid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600 and s.st_size<=16<<20
   raw=path.read_bytes();after=path.lstat()
   assert len(raw)==s.st_size and all(getattr(s,key)==getattr(after,key)for key in('st_mode','st_uid','st_gid','st_dev','st_ino','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
   with(target/path.name).open('xb')as out:out.write(raw)
   os.chmod(target/path.name,0o600)
   relative=job+'/'+path.name
   files[relative]={'sha256':hashlib.sha256(raw).hexdigest(),'bytes':s.st_size,'mode':stat.S_IMODE(s.st_mode),'uid':s.st_uid,'gid':s.st_gid,'inode':str(s.st_ino),'original_mtime_ns':str(s.st_mtime_ns),'original_ctime_ns':str(s.st_ctime_ns)}
 save('native-original-file-ledger.json',files)
 if proof['ok']:assert 15<=len(files)<=1024
 return len(files)

proof={'harness_revision':3,'previous_failed_native_runs':[40787292285,40789776886,40792222289],'ok':False,'base':str(base),'actual_KVM_guest':True,'architecture':'amd64','Main_changed':False,'all50_commercial':False,'source_inputs_sha256':pins['source_inputs_sha256'],'phases':[]}
try:
 assert all(not os.path.lexists(path)for path in('/opt/panel','/var/lib/panel','/var/lib/panel-executor','/etc/panel-release'))
 baseline='0.1.0-dev.proapps24streamcandidate24';old_archive=base/('panel-'+baseline+'-linux-amd64.tar.gz')
 for action in('verify','install'):
  save('baseline-'+action+'-once-intent.json',{'archive_sha256':sha(old_archive),'attempt':1,'original_key_only':True});command('baseline-'+action,['python3','-I','-B',str(base/'signed-release.py'),action,str(old_archive),'--public-key',str(base/'programme.pub')],1200 if action=='install'else 30)
 assert json.loads(pathlib.Path('/opt/panel/current/SOURCE_INPUTS.json').read_bytes())['inputs_sha256']=='93b1973ed627e8b471d5b7d17c843c6a30f7a92bd68b1f01725f78bd80f57f96';guard();before_upgrade=initialized_baseline_capture('baseline');save('before-C27-upgrade-full-Core.json',before_upgrade);baseline_nss=nss();baseline_nginx=nginx();save('before-C27-upgrade-NSS-and-Nginx.json',{'NSS':baseline_nss,'nginx':baseline_nginx})
 version='0.1.0-dev.proapps24diskcancelcandidate27';archive=base/('panel-'+version+'-linux-amd64.tar.gz')
 for action in('verify','install'):
  save('normal-'+action+'-once-intent.json',{'archive_sha256':sha(archive),'attempt':1,'original_key_only':True});command('normal-'+action,['python3','-I','-B',str(base/'signed-release.py'),action,str(archive),'--public-key',str(base/'programme.pub')],1200 if action=='install'else 30)
 assert json.loads(pathlib.Path('/opt/panel/current/SOURCE_INPUTS.json').read_bytes())['inputs_sha256']==pins['source_inputs_sha256'];guard();before=healthy_capture('upgraded');save('programme-installed-full-Core.json',before);initial_nss=nss();assert initial_nss==baseline_nss and nginx()==baseline_nginx;save('programme-installed-NSS-hashes.json',initial_nss)
 for key in('actual_tables','business_tables','schema','columns','migration_columns','migrations'):assert before[key]==before_upgrade[key]
 upgrade_preservation=model['compare_rows'](before_upgrade,before);save('C27-upgrade-full-business-comparison.json',upgrade_preservation);proof['normal_original_key_C24_to_C27_upgrade_full111_schema_and105_business_columns']=True
 guards={}
 for unit in('panel.service','panel-executor.service','panel-terminal.service','panel-terminal-root.service','panel-mysql-overwrite-recovery.service'):
  raw=subprocess.check_output(['systemctl','show',unit,'--property=Id,LoadState,NeedDaemonReload,ExecCondition'],text=True,timeout=5);v=dict(line.split('=',1)for line in raw.splitlines());assert v['Id']==unit and v['LoadState']=='loaded'and v['NeedDaemonReload']=='no'and v['ExecCondition'].startswith('{ path=/usr/lib/panel-program-upgrade/start-guard-v4 ; argv[]=/usr/lib/panel-program-upgrade/start-guard-v4 '+unit+' ; ignore_errors=no ;');guards[unit]=v
 save('actual-five-loaded-start-guards.json',guards)
 peer={'boot':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'machine_id_sha256':sha('/etc/machine-id')};save('native-identity.json',peer)
 cases={}
 for number,phase in enumerate(('store-install','native-scan','native-fast-cancel','native-active-cancel'),1):
  root=evidence/('%02d-'%number+phase);root.mkdir(mode=0o700);worker=base/('native-active-cancel-v3.py'if phase=='native-active-cancel'else phase+'.py');shutil.copyfile(worker,root/'guest.py');os.chmod(root/'guest.py',0o600)
  intent={'peer':peer,'files':{'guest.py':sha(worker)},'once_only':True,'Main_changed':False,'all50_commercial':False}
  if phase=='native-active-cancel':intent['fixture_record']=str(cases['native-fast-cancel']/'fixture-before.json')
  (root/'intent.json').write_text(json.dumps(intent,sort_keys=True)+'\n');os.chmod(root/'intent.json',0o600)
  snapshot=capture();save(phase+'-full-Core-before.json',snapshot);command('case-'+phase,['python3','-I','-B',str(root/'guest.py'),str(root)],420)
  result=json.loads((root/'proof.json').read_bytes());assert result['ok']is True;proof['phases'].append({'phase':phase,'proof_sha256':sha(root/'proof.json'),'result':result});cases[phase]=root
  after=capture();save(phase+'-full-Core-after.json',after)
  for key in('actual_tables','business_tables','schema','columns','migration_columns','migrations'):assert after[key]==snapshot[key],phase+' changed '+key
  assert nss()==initial_nss;guard()
 proof.update(ok=True,normal_original_key_C27_installed=True,actual_five_loaded_guards=True,original_signed141_installed=True,exact_sparse_hardlink_and_large_integer_scan=True,original_prestart_cancel_closed_without_recovery_POST=True,original_active_process_cancellation_verified=True,complete_guard_exit=0,all_full111_schema_and105_business_columns_captured=True,independent_full_SQL_row_qualification_pending=True,public_ingress_and_all50_commercial=False)
except BaseException:save('failure.json',{'traceback':traceback.format_exc()})
finally:
 try:proof['original_native_files_collected']=collect_native()
 except BaseException:proof['ok']=False;save('native-collection-failure.json',{'traceback':traceback.format_exc()})
 save('proof.json',proof);print(json.dumps(proof,sort_keys=True),flush=True)
raise SystemExit(0 if proof['ok']else 1)





