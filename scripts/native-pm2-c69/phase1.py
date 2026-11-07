"""One normal C68r3-to-C69r4 upgrade and real non-root PM2 boundary journey."""
import ast,contextlib,fcntl,hashlib,http.cookiejar,json,os,pathlib,platform,pwd,re,secrets,shutil,socket,sqlite3,stat,subprocess,sys,time,traceback,urllib.error,urllib.request
os.umask(0o077)
assert os.geteuid()==0 and len(sys.argv)==3
inputs=pathlib.Path(sys.argv[1]).resolve(strict=True);private=pathlib.Path(sys.argv[2]).resolve(strict=True);source=pathlib.Path(__file__).resolve().parent
cohort=json.loads((source/'cohort.json').read_bytes());assert os.environ.get('GITHUB_ACTIONS')=='true'and os.environ.get('GITHUB_REPOSITORY')=='yunzhanlin/yunzhan-apps'
arch={'x86_64':'amd64','aarch64':'arm64'}[platform.machine()]
assert pathlib.Path('/proc/1/comm').read_text().strip()=='systemd'
evidence=private/'business-phase1';evidence.mkdir(mode=0o700)
raw=(source/'capture.py').read_bytes();assert hashlib.sha256(raw).hexdigest()==cohort['files']['capture.py']
exec(compile(raw,'<bound-original-native-observers>','exec'),globals())
nonce=secrets.token_hex(4);boot=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()
ids=['qa-c69-'+nonce+'-'+str(i)for i in range(1,7)]
p={'boot':boot,'owned_project_ids':ids,'resource_id':ids[0],'platform':'ubuntu-24.04','architecture':arch,'marker':'owned-C69-'+nonce,'entry':'c69-1.js','port':24431,'synthetic_environment':secrets.token_urlsafe(36)}
secret=p['synthetic_environment'];own_site=None;csrf='';events=[]
origin='http://127.0.0.1:19100';client=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect(),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
module=pathlib.Path('/etc/panel/security-apps/modules/pm2-manager')
faults=pathlib.Path('/var/lib/c69-original-owned-faults-'+secrets.token_hex(16));faults.mkdir(mode=0o700)
proof={'ok':False,'architecture':arch,'phase':'actual-upgrade-and-service-boundaries','source_inputs_sha256':cohort['source_inputs_sha256'],'new_VM_or_reboot_or_uninstall_submissions':0,'Main_changed':False,'all50_commercial':False}
ro=False
def select(i):
 p.update(resource_id=ids[i],entry='c69-'+str(i+1)+'.js',port=24431+i)
def counter(i):return pathlib.Path('/srv/panel/sites')/own_site/'private'/('pm2-'+ids[i])/'qa-c43-start-count'
def app(i):return module/'apps'/(ids[i]+'.json')
def stopped(i):
 u=unit('panel-pm2@'+ids[i]+'.service')
 assert u['LoadState']=='loaded'and u['ActiveState']=='inactive'and u['SubState']=='dead'and u['MainPID']=='0'and u['UnitFileState']=='disabled'
 assert counter(i).read_text()=='2'
 try:
  c=socket.create_connection(('127.0.0.1',24431+i),timeout=2);c.close();raise AssertionError('Stopped owned port remains reachable')
 except ConnectionRefusedError:pass
 return u
def projects(label):
 before={str(f):(f.stat().st_ino,sha(f))for f in [module/'installed.json',*[app(i)for i in range(6)]]}
 page=api(label,'/app-modules/pm2-manager/projects?limit=32&offset=0')
 assert page['projects_readonly']is True and page['project_page_complete']is True and page['configuration_not_inspected']is True and page['configuration_or_deployment_replayed']is False and page['history_or_report_written']is False
 assert page['total']==6 and page['limit']==32 and page['offset']==0 and page['unreadable_projects']==[]
 assert {v['app']['id']for v in page['apps']}==set(ids)and all(v['state_known']for v in page['apps'])
 assert all((pathlib.Path(f).stat().st_ino,sha(f))==v for f,v in before.items())
 return page
def stop(i,label,persistence=True):
 select(i);original=app(i).read_bytes()
 out=api(label,'/app-modules/pm2-manager/stop',{'resource_id':ids[i],'expected_revision':1})
 assert out['id']==ids[i]and out['action']=='stop'and out['ok']is True and out['state']=='inactive'and out['boot_enabled']is False
 assert out['service_outcome_verified']is True and out['configuration_preserved']is True and out['configuration_or_deployment_replayed']is False and out['original_project_sha256']==hashlib.sha256(original).hexdigest()
 assert type(out['history_persisted'])is bool and type(out['last_report_persisted'])is bool
 if persistence:assert out['history_persisted']and out['last_report_persisted']
 else:assert (not out['history_persisted']or not out['last_report_persisted'])and out['persistence_warning']
 assert app(i).read_bytes()==original;stopped(i);return out
def record_private(label,f):
 st=f.lstat();v={'path':str(f),'dev':st.st_dev,'inode':st.st_ino,'uid':st.st_uid,'gid':st.st_gid,'mode':stat.S_IMODE(st.st_mode),'nlink':st.st_nlink}
 if stat.S_ISLNK(st.st_mode):v['target']=os.readlink(f)
 else:v.update(sha256=sha(f),original_hex=f.read_bytes().hex())
 save(label+'.json',v);return v
try:
 assert json.loads(pathlib.Path('/opt/panel/current/SOURCE_INPUTS.json').read_bytes())['inputs_sha256']=='7ae19475cac7a31941533befe97d6288eabcc6f5b8a0ea9b83e3feadc3e8fdda'
 access_file=pathlib.Path('/etc/panel/first-login.json');st=access_file.lstat();assert stat.S_ISREG(st.st_mode)and st.st_uid==0 and st.st_nlink==1 and stat.S_IMODE(st.st_mode)==0o600
 access=json.loads(access_file.read_bytes())
 try:csrf=api('old-programme-original-login','/login',{k:access[k]for k in('username','password')})['csrf']
 finally:access.clear()
 accepted=api('one-old-normal-PM2-install','/software/pm2-manager/install',{'settings':{}},202,secrets.token_hex(16));wait_job('one-old-normal-PM2-install',accepted['job_id'],'runtime_jobs')
 installed=(module/'installed.json').read_bytes();assert json.loads(installed)['version']=='7.0.4-compat9'
 accepted=api('one-original-site-create','/sites',{'name':'Owned C69 original PM2','slug':'qa-c69-'+nonce,'domain':'qa-c69-'+nonce+'.localhost','php_version_id':''},202,secrets.token_hex(16));own_site=wait_job('one-original-site-create',accepted['job_id'],'jobs')['site_id'];p['site_id']=own_site
 original_apps={}
 for i in range(6):
  select(i);code=fixture_source(p);result=api('old-entry-create-'+str(i),'/sites/'+own_site+'/files/action',{'action':'create','path':p['entry'],'content':code});assert result['sha256']==hashlib.sha256(code.encode()).hexdigest()
  created=api('old-project-create-'+str(i),'/app-modules/pm2-manager/create',{'resource_id':p['resource_id'],'site_id':own_site,'entry':p['entry'],'port':p['port'],'instances':1,'memory_mb':128,'environment_patch':{'QA_PM2_CANARY':secret}});assert created['ok']and created['app']['revision']==1
  running=probe('old-original-running-'+str(i));assert running['actual_HTTP']['start_count']==1
  result=api('old-original-stop-'+str(i),'/app-modules/pm2-manager/stop',{'resource_id':p['resource_id']});assert result['ok']and result['boot_enabled']is False
  assert unit('panel-pm2@'+ids[i]+'.service')['ActiveState']=='inactive'and counter(i).read_text()=='1';original_apps[ids[i]]=app(i).read_bytes().hex()
 guard();before=snapshot();save('programme-before.json',before)
 # Copy only independent pinned public inputs into a new Root private tree.
 root=pathlib.Path('/var/lib/c69-original-programme-inputs-'+secrets.token_hex(16));root.mkdir(mode=0o700);pins=cohort['new_release_assets'];archive_name=cohort['cohorts'][arch]['archive']
 chosen=[archive_name+s for s in('','.manifest','.sig')]+['release-signing-dev.pub']
 assert {f.name for f in inputs.iterdir()}==set(chosen)
 for n in chosen:
  pin=pins[n];f=inputs/n;st=f.lstat();assert stat.S_ISREG(st.st_mode)and st.st_nlink==1 and not st.st_mode&0o022 and st.st_size==pin['bytes']and sha(f)==pin['sha256']
  fd=os.open(f,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
  with os.fdopen(fd,'rb')as a,os.fdopen(os.open(root/n,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600),'wb')as b:
   raw=a.read((128<<20)+1);assert len(raw)==pin['bytes']and hashlib.sha256(raw).hexdigest()==pin['sha256'];b.write(raw);b.flush();os.fsync(b.fileno())
  assert sha(f)==sha(root/n)==pin['sha256']
 signer=root/'signed-release.py';raw=(source/'original-signed-release.py').read_bytes();assert hashlib.sha256(raw).hexdigest()=='fe128e82b4e11345b320cd782134768bfe1a4df14947c425d7494873a7a7b7b5';signer.open('xb').write(raw);signer.chmod(0o600)
 def normal(label,args,timeout):
  save(label+'-intent.json',{'args':args,'maximum_submissions':1})
  with(evidence/(label+'.stdout')).open('xb')as a,(evidence/(label+'.stderr')).open('xb')as b:r=subprocess.run(args,stdout=a,stderr=b,timeout=timeout)
  save(label+'-outcome.json',{'exit':r.returncode});assert r.returncode==0,label+' original refusal retained without replay'
 argv=['/usr/bin/python3','-I','-B',str(signer)];key=['--public-key',str(root/'release-signing-dev.pub')];archive=root/archive_name
 normal('original-C69-signature-verify',argv+['verify',str(archive)]+key,60)
 normal('one-C69-normal-upgrade-preflight',argv+['install',str(archive)]+key+['--preflight-only'],900)
 pre=snapshot();save('programme-after-preflight.json',pre)
 normal('one-C69-normal-upgrade',argv+['install',str(archive)]+key,1200)
 after=snapshot();save('programme-after-upgrade.json',after)
 assert before['schema']==pre['schema']==after['schema']and before['nss']==pre['nss']==after['nss']and before['packages']==pre['packages']==after['packages']and before['NFS_state']==pre['NFS_state']==after['NFS_state']
 assert before['protected_files']==pre['protected_files']
 protected=lambda v:{k:x for k,x in v['protected_files'].items()if not any(k==n or k.startswith(n+'/')for n in('/opt/panel/current/bin','/opt/panel/current/web'))}
 assert protected(before)==protected(after)
 for n,v in before['lifetimes'].items():
  assert v==pre['lifetimes'][n]
  if n in('panel.service','panel-executor.service'):assert v['MainPID']!=after['lifetimes'][n]['MainPID']and v['InvocationID']!=after['lifetimes'][n]['InvocationID']
  else:assert v==after['lifetimes'][n]
 assert (module/'installed.json').read_bytes()==installed
 assert json.loads(pathlib.Path('/opt/panel/current/SOURCE_INPUTS.json').read_bytes())['inputs_sha256']==cohort['source_inputs_sha256']
 # The installer intentionally uses a Root-owned current pointer. Verify its exact
 # new signed destination; never pass a symlink as an ordinary release directory.
 pointer=pathlib.Path('/opt/panel/current');pointer_info=pointer.lstat()
 assert stat.S_ISLNK(pointer_info.st_mode)and pointer_info.st_uid==0
 destination=pathlib.Path('/opt/panel/releases')/cohort['version']
 assert os.readlink(pointer)==str(destination)and pointer.resolve(strict=True)==destination
 for directory in(destination,*destination.parents):
  info=directory.lstat();assert stat.S_ISDIR(info.st_mode)and info.st_uid==0 and not info.st_mode&0o022
 command(['/bin/bash',str(destination/'verify-release.sh'),str(destination)],120)
 save('original-exact-signed-current-destination-verified.json',{'destination':str(destination),'Root_owned_pointer':True,'ordinary_destination_verified':True,'symbolic_link_policy_relaxed':False})
 for i in range(6):
  assert app(i).read_bytes().hex()==original_apps[ids[i]]
  select(i);started=api('C69-explicit-start-'+str(i),'/app-modules/pm2-manager/start',{'resource_id':ids[i]});assert started['ok']and started['boot_enabled'];running=probe('C69-original-environment-and-HTTP-'+str(i));assert running['actual_HTTP']['start_count']==2
 # The independent inventory remains an authenticated Core route.
 unauthenticated=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
 request=urllib.request.Request(origin+'/api/app-modules/pm2-manager/projects?limit=32&offset=0',headers={'Origin':origin})
 try:
  with unauthenticated.open(request,timeout=10)as response:status=response.status;body=response.read(4097)
 except urllib.error.HTTPError as exc:status=exc.code;body=exc.read(4097)
 assert status==401 and len(body)<=4096
 save('actual-unauthenticated-project-read-refused.json',{'status':status,'response_sha256':hashlib.sha256(body).hexdigest(),'no_application_operation_dispatched':True})
 projects('before-damaged-configuration-current-projects')
 config=module/'configuration-transactions';config.mkdir(mode=0o700,exist_ok=True);bad=config/(secrets.token_hex(16)+'.intent.json');bad.open('xb').write(b'{"original-owned-incomplete":');bad.chmod(0o600);bad_before=record_private('original-owned-malformed-configuration',bad)
 projects('damaged-configuration-current-projects');previous=unit('panel-pm2@'+ids[0]+'.service');api('damaged-configuration-still-refuses-start','/app-modules/pm2-manager/start',{'resource_id':ids[0]},409);assert unit('panel-pm2@'+ids[0]+'.service')==previous
 stop(0,'damaged-configuration-independent-stop');assert sha(bad)==bad_before['sha256']and bad.stat().st_ino==bad_before['inode'];os.rename(bad,faults/bad.name)
 history_file=module/'history.json';original_history=faults/'original-history-retained.json';os.rename(history_file,original_history);history_file.open('xb').write(b'{"original-owned-broken-history":');history_file.chmod(0o600);bad_before=record_private('original-owned-malformed-history',history_file)
 page=api('history-fault-original-module-page','/app-modules/pm2-manager');assert page['status']['installed'];projects('history-fault-current-projects');stop(1,'history-fault-independent-stop',False)
 assert history_file.stat().st_ino==bad_before['inode']and sha(history_file)==bad_before['sha256'];os.rename(history_file,faults/'broken-history-retained.json');os.rename(original_history,history_file)
 report=module/'last-report.json';original_report=faults/'original-report-retained.json';os.rename(report,original_report);target=faults/'owned-link-target-canary';target.open('xb').write(b'owned-root-private-unaltered-report-canary');target.chmod(0o600);target_hash=sha(target);report.symlink_to(target);bad_before=record_private('original-owned-report-symlink',report)
 page=api('linked-report-original-module-page','/app-modules/pm2-manager');assert page['status']['installed']and page['report_state_unknown'];projects('linked-report-current-projects');stop(2,'linked-report-independent-stop',False)
 assert report.is_symlink()and report.lstat().st_ino==bad_before['inode']and sha(target)==target_hash;os.rename(report,faults/'linked-report-retained');os.rename(original_report,report)
 # Only the newly owned module inside the existing executor mount namespace is read-only.
 lock5=module/'locks'/(ids[4]+'.lock');old5=record_private('original-owned-legacy-lock',lock5);os.rename(lock5,faults/'legacy-lock-retained')
 executor_pid=unit('panel-executor.service')['MainPID']
 namespace=['/usr/bin/nsenter','--target',executor_pid,'--mount','--']
 command(namespace+['/usr/bin/mount','--bind',str(module),str(module)]);ro=True;command(namespace+['/usr/bin/mount','-o','remount,bind,ro,nodev,nosuid,noexec',str(module)])
 check_ro="""import errno,os
p=OWNED_PROBE
try:
 f=os.open(p,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
except OSError as e:
 assert e.errno==errno.EROFS
else:
 os.close(f);raise AssertionError('Executor did not observe the actual owned read-only mount')
print('actual-executor-EROFS')
""".replace('OWNED_PROBE',repr(str(module/('.owned-c69-ro-probe-'+nonce))))
 observed=command(['/usr/bin/nsenter','--target',executor_pid,'--mount','--','/usr/bin/python3','-I','-B','-c',check_ro]);assert observed.strip()=='actual-executor-EROFS';save('actual-executor-namespace-EROFS.json',{'ok':True,'executor_pid':executor_pid,'service_restarted':False,'module_only':str(module)})
 projects('read-only-current-projects');stop(3,'read-only-original-lock-independent-stop',False)
 active5=unit('panel-pm2@'+ids[4]+'.service');api('read-only-missing-original-lock-refused','/app-modules/pm2-manager/stop',{'resource_id':ids[4],'expected_revision':1},409)
 assert not os.path.lexists(lock5)and unit('panel-pm2@'+ids[4]+'.service')==active5
 command(namespace+['/usr/bin/umount',str(module)]);ro=False;os.rename(faults/'legacy-lock-retained',lock5);assert lock5.stat().st_ino==old5['inode'];stop(4,'restored-original-lock-new-explicit-stop')
 lock6=module/'locks'/(ids[5]+'.lock');old6=record_private('original-owned-last-lock',lock6);os.rename(lock6,faults/'last-lock-retained');lock6.symlink_to(target);old_active=unit('panel-pm2@'+ids[5]+'.service');projects('linked-lock-current-projects')
 api('linked-lock-refused','/app-modules/pm2-manager/stop',{'resource_id':ids[5],'expected_revision':1},409);assert unit('panel-pm2@'+ids[5]+'.service')==old_active and sha(target)==target_hash
 os.rename(lock6,faults/'linked-lock-retained');os.rename(faults/'last-lock-retained',lock6);assert lock6.stat().st_ino==old6['inode']
 with lock6.open('rb')as held:
  fcntl.flock(held,fcntl.LOCK_EX|fcntl.LOCK_NB);projects('held-lock-current-projects');api('held-lock-refused','/app-modules/pm2-manager/stop',{'resource_id':ids[5],'expected_revision':1},409);assert unit('panel-pm2@'+ids[5]+'.service')==old_active
 stop(5,'released-original-lock-new-explicit-stop')
 final=projects('final-all-original-projects-stopped');assert all(v['state']=='inactive'and v['boot_enabled']is False for v in final['apps'])
 for i in range(6):assert app(i).read_bytes().hex()==original_apps[ids[i]];stopped(i)
 assert (module/'installed.json').read_bytes()==installed;guard()
 for f in [pathlib.Path('/var/lib/panel/panel.db'),pathlib.Path('/var/lib/panel/panel.db-wal')]:
  if f.exists():assert secret.encode()not in f.read_bytes()
 save('original-owned-store-next-phase-intent.json',{**p,'original_apps':original_apps,'original_installed_hex':installed.hex(),'original_stopped_units':{ids[i]:stopped(i)for i in range(6)},'original_faults_retained':str(faults)})
 proof.update(ok=True,actual_normal_204_entry_C68r3_to_C69r4_upgrade=True,original_PM2_install_version_retained='7.0.4-compat9',actual_nonroot_project_count=6,actual_nonroot_HTTP_before_and_after_upgrade=True,all_original_encrypted_manifests_preserved=True,malformed_configuration_independent_stop_and_start_refusal=True,malformed_history_service_outcome_separate_from_failed_persistence=True,linked_report_and_linked_lock_targets_untouched=True,actual_running_executor_EROFS_and_existing_lock_stop=True,readonly_missing_lock_refused_without_service_change=True,held_original_lock_refused_without_waiting_or_service_change=True,all_owned_projects_stopped_boot_disabled_and_counters2=True,normal_signed_9to10_store_update_pending=True,full113_raw_SQL_independent_qualification_pending=True)
except BaseException:
 proof['failure']=traceback.format_exc().replace(secret,'[synthetic-environment-redacted]')
finally:
 if ro:
  try:command(namespace+['/usr/bin/umount',str(module)]);ro=False
  except BaseException:proof['owned_mount_cleanup_failure']=traceback.format_exc()
 if csrf:
  try:api('phase1-original-logout','/logout',{});csrf=''
  except BaseException:proof['logout_failure']='Inspect original response without replay'
 try:save('phase1-final-original-snapshot.json',snapshot())
 except BaseException:proof['capture_failure']=traceback.format_exc();proof['ok']=False
 save('HTTP-events.json',events);save('original-proof.json',proof)
 print(json.dumps({'ok':proof['ok'],'phase':'actual-upgrade-and-service-boundaries','architecture':arch,'all50_commercial':False}),flush=True)
sys.exit(0 if proof['ok']else 1)

