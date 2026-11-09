"""Preserve an actual running PM2 project across the normal C69r4 to C70 programme upgrade."""
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
ids=['qa-c70-'+nonce+'-'+str(i)for i in range(1,7)]
p={'boot':boot,'owned_project_ids':ids,'resource_id':ids[0],'platform':'ubuntu-24.04','architecture':arch,'marker':'owned-C70-'+nonce,'entry':'c70-1.js','port':24431,'synthetic_environment':secrets.token_urlsafe(36)}
secret=p['synthetic_environment'];own_site=None;csrf='';events=[]
origin='http://127.0.0.1:19100';client=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect(),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
module=pathlib.Path('/etc/panel/security-apps/modules/pm2-manager')
faults=pathlib.Path('/var/lib/c70-original-owned-faults-'+secrets.token_hex(16));faults.mkdir(mode=0o700)
proof={'ok':False,'architecture':arch,'phase':'actual-upgrade-and-service-boundaries','source_inputs_sha256':cohort['source_inputs_sha256'],'new_VM_or_reboot_or_uninstall_submissions':0,'Main_changed':False,'all50_commercial':False}
ro=False
def select(i):
 p.update(resource_id=ids[i],entry='c70-'+str(i+1)+'.js',port=24431+i)
def counter(i):return pathlib.Path('/srv/panel/sites')/own_site/'private'/('pm2-'+ids[i])/'qa-c43-start-count'
def app(i):return module/'apps'/(ids[i]+'.json')
try:
 assert json.loads(pathlib.Path('/opt/panel/current/SOURCE_INPUTS.json').read_bytes())['inputs_sha256']=='9983bbf3986af49b75aba6e06f94a6f43f2e66eb18b2b013895453017cff681e'
 access_file=pathlib.Path('/etc/panel/first-login.json');st=access_file.lstat();assert stat.S_ISREG(st.st_mode)and st.st_uid==0 and st.st_nlink==1 and stat.S_IMODE(st.st_mode)==0o600
 access=json.loads(access_file.read_bytes())
 try:csrf=api('old-programme-original-login','/login',{k:access[k]for k in('username','password')})['csrf']
 finally:access.clear()
 accepted=api('one-old-normal-PM2-install','/software/pm2-manager/install',{'settings':{}},202,secrets.token_hex(16));wait_job('one-old-normal-PM2-install',accepted['job_id'],'runtime_jobs')
 installed=(module/'installed.json').read_bytes();assert json.loads(installed)['version']=='7.0.4-compat10'
 accepted=api('one-original-site-create','/sites',{'name':'Owned C70 original PM2','slug':'qa-c70-'+nonce,'domain':'qa-c70-'+nonce+'.localhost','php_version_id':''},202,secrets.token_hex(16));own_site=wait_job('one-original-site-create',accepted['job_id'],'jobs')['site_id'];p['site_id']=own_site
 original_apps={}
 for i in range(6):
  select(i);code=fixture_source(p);result=api('old-entry-create-'+str(i),'/sites/'+own_site+'/files/action',{'action':'create','path':p['entry'],'content':code});assert result['sha256']==hashlib.sha256(code.encode()).hexdigest()
  created=api('old-project-create-'+str(i),'/app-modules/pm2-manager/create',{'resource_id':p['resource_id'],'site_id':own_site,'entry':p['entry'],'port':p['port'],'instances':1,'memory_mb':128,'environment_patch':{'QA_PM2_CANARY':secret}});assert created['ok']and created['app']['revision']==1
  running=probe('old-original-running-'+str(i));assert running['actual_HTTP']['start_count']==1
  if i:
   result=api('old-original-stop-'+str(i),'/app-modules/pm2-manager/stop',{'resource_id':p['resource_id'],'expected_revision':1});assert result['ok']and result['boot_enabled']is False
   assert unit('panel-pm2@'+ids[i]+'.service')['ActiveState']=='inactive'
  assert counter(i).read_text()=='1';original_apps[ids[i]]=app(i).read_bytes().hex()
 # Hosted runner parent modes differ from clean distro modes. Prepare only
 # the exact Root-owned distro ancestors on this disposable CI machine.
 fixture_changes={};system_programs={}
 for name in ('/usr/bin/node','/usr/bin/npm'):
  f=pathlib.Path(name);link=f.lstat();assert link.st_uid==0
  resolved=f.resolve(strict=True);assert resolved.is_relative_to('/usr')
  value=resolved.lstat();assert stat.S_ISREG(value.st_mode)and value.st_uid==0 and not value.st_mode&0o022
  system_programs[name]={'path':str(resolved),'sha256':sha(resolved),'inode':value.st_ino,'mode':value.st_mode}
  for parent in reversed(resolved.parents):
   st=parent.lstat();assert stat.S_ISDIR(st.st_mode)and st.st_uid==0
   if not st.st_mode&0o022:continue
   assert parent.is_relative_to('/usr')
   old_mode=stat.S_IMODE(st.st_mode);parent.chmod(old_mode&~0o022);after=parent.lstat()
   assert (st.st_dev,st.st_ino,st.st_uid,st.st_gid)==(after.st_dev,after.st_ino,after.st_uid,after.st_gid)and not after.st_mode&0o022
   fixture_changes[str(parent)]={'original_mode':old_mode,'prepared_mode':stat.S_IMODE(after.st_mode),'original_device':st.st_dev,'original_inode':st.st_ino}
 save('owned-runner-distro-program-parent-fixture.json',{'changes':fixture_changes,'system_programs':system_programs,'only_owned_disposable_GitHub_runner':True,'product_owner_or_link_check_unchanged':True,'Main_changed':False})
 original_units={rid:unit('panel-pm2@'+rid+'.service')for rid in ids};assert original_units[ids[0]]['ActiveState']=='active'and original_units[ids[0]]['UnitFileState']=='enabled'
 assert all(original_units[rid]['ActiveState']=='inactive'and original_units[rid]['UnitFileState']=='disabled'for rid in ids[1:])
 guard();before=snapshot();save('programme-before.json',before)
 vendor='/opt/panel/app-modules/pm2';old_vendor={n:v for n,v in before['protected_files'].items()if n==vendor or n.startswith(vendor+'/')}
 assert len(old_vendor)>1000 and vendor in old_vendor
 owned_writers=[n for n,v in old_vendor.items()if n.startswith(vendor+'/node_modules/')and v['uid']>0 and 'sha256'in v and v['mode']&0o200 and v['links']==1 and n.endswith(('.md','.js'))]
 assert owned_writers,'Must actually observe an original writable non-Root package file, not fabricate a replacement'
 old_writer=sorted(owned_writers,key=lambda n:(not n.endswith('.md'),n))[0]
 save('original-legacy-PM2-vendor-inventory.json',{'root':vendor,'entries':old_vendor,'actual_foreign_owned_ordinary_candidates':len(owned_writers),'old_writer':old_writer,'old_writer_identity':old_vendor[old_writer]})
 # Copy only independent pinned public inputs into a new Root private tree.
 root=pathlib.Path('/var/lib/c70-original-programme-inputs-'+secrets.token_hex(16));root.mkdir(mode=0o700);pins=cohort['new_release_assets'];archive_name=cohort['cohorts'][arch]['archive']
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
 normal('original-C70-signature-verify',argv+['verify',str(archive)]+key,60)
 normal('one-C70-normal-upgrade-preflight',argv+['install',str(archive)]+key+['--preflight-only'],900)
 pre=snapshot();save('programme-after-preflight.json',pre)
 normal('one-C70-normal-upgrade',argv+['install',str(archive)]+key,1200)
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
 for i,rid in enumerate(ids):
  assert app(i).read_bytes().hex()==original_apps[rid]and unit('panel-pm2@'+rid+'.service')==original_units[rid]and counter(i).read_text()=='1'
 select(0);live=probe('C70-existing-original-project-stays-running');assert live['actual_HTTP']['start_count']==1
 check=subprocess.run(['/opt/panel/current/bin/panel-executor','--pm2-config-start-check',ids[0]],capture_output=True,timeout=25)
 assert check.returncode!=0 and '独立 Root' in (check.stdout+check.stderr).decode('utf-8','replace')
 assert unit('panel-pm2@'+ids[0]+'.service')==original_units[ids[0]]
 save('unsealed-original-start-refused-without-stopping-live-service.json',{'exit':check.returncode,'stdout_sha256':hashlib.sha256(check.stdout).hexdigest(),'stderr_sha256':hashlib.sha256(check.stderr).hexdigest(),'old_active_generation_preserved':True})
 page=api('original-signed-programme-independent-projects','/app-modules/pm2-manager/projects?limit=32&offset=0');assert page['projects_readonly']is True and page['project_page_complete']is True and page['total']==6 and page['history_or_report_written']is False
 assert (module/'installed.json').read_bytes()==installed;guard()
 save('original-owned-store-next-phase-intent.json',{**p,'original_apps':original_apps,'original_installed_hex':installed.hex(),'original_units':original_units,'original_old_vendor_writer':old_writer,'original_node_programs':system_programs})
 proof.update(ok=True,actual_normal_204_entry_C69r4_to_C70_upgrade=True,original_PM2_install_version_retained='7.0.4-compat10',actual_nonroot_project_count=6,actual_one_running_and_five_stopped_projects_preserved=True,unsealed_new_start_refused_without_stopping_original=True,all_original_encrypted_manifests_preserved=True,original_vendor_inodes_and_all_bytes_preserved_before_app_update=True,normal_signed_10to11_store_update_pending=True,full113_raw_SQL_independent_qualification_pending=True)
except BaseException:
 proof['failure']=traceback.format_exc().replace(secret,'[synthetic-environment-redacted]')
finally:
 if csrf:
  try:api('phase1-original-logout','/logout',{});csrf=''
  except BaseException:proof['logout_failure']='Inspect original response without replay'
 try:save('phase1-final-original-snapshot.json',snapshot())
 except BaseException:proof['capture_failure']=traceback.format_exc();proof['ok']=False
 save('HTTP-events.json',events);save('original-proof.json',proof)
 print(json.dumps({'ok':proof['ok'],'phase':'C70 normal programme and legacy PM2 vendor baseline','architecture':arch,'all50_commercial':False}),flush=True)
sys.exit(0 if proof['ok']else 1)
