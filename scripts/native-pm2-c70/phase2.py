"""One actual signed PM2 compat10->11 store update with an original open writer."""
import base64,contextlib,hashlib,http.cookiejar,json,os,pathlib,pwd,re,select,sqlite3,stat,subprocess,sys,time,traceback,urllib.error,urllib.request
os.umask(0o077)
assert os.geteuid()==0 and len(sys.argv)==2 and os.environ.get('GITHUB_ACTIONS')=='true'and os.environ.get('GITHUB_REPOSITORY')=='yunzhanlin/yunzhan-apps'
private=pathlib.Path(sys.argv[1]).resolve(strict=True);source=pathlib.Path(__file__).resolve().parent;cohort=json.loads((source/'cohort.json').read_bytes())
phase1=json.loads((private/'business-phase1/original-proof.json').read_bytes());assert phase1['ok']and phase1['actual_nonroot_project_count']==6 and phase1['source_inputs_sha256']==cohort['source_inputs_sha256']
p=json.loads((private/'business-phase1/original-owned-store-next-phase-intent.json').read_bytes());assert pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()==p['boot']
evidence=private/'business-phase2';evidence.mkdir(mode=0o700)
raw=(source/'capture.py').read_bytes();assert hashlib.sha256(raw).hexdigest()==cohort['files']['capture.py'];exec(compile(raw,'<original-source-bound-observers>','exec'),globals())
assert json.loads(pathlib.Path('/opt/panel/current/SOURCE_INPUTS.json').read_bytes())['inputs_sha256']==cohort['source_inputs_sha256']
secret=p['synthetic_environment'];own_site=p['site_id'];csrf='';events=[];ids=p['owned_project_ids'];module=pathlib.Path('/etc/panel/security-apps/modules/pm2-manager')
origin='http://127.0.0.1:19100';client=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect(),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
proof={'ok':False,'phase':'actual-signed-store10to11-update','architecture':p['architecture'],'source_inputs_sha256':cohort['source_inputs_sha256'],'actual_store_update_POSTs':0,'actual_explicit_project_restart_POSTs':0,'actual_browser_UI_acceptance':False,'Main_changed':False,'all50_commercial':False}
vendor=pathlib.Path('/opt/panel/app-modules/pm2');writer=None
inventory=json.loads((private/'business-phase1/original-legacy-PM2-vendor-inventory.json').read_bytes())
old_writer=pathlib.Path(p['original_old_vendor_writer']);assert str(old_writer)==inventory['old_writer'];relative=old_writer.relative_to(vendor);assert relative.parts[0]=='node_modules'
expected_old=inventory['old_writer_identity']
def projects(count=1,old_generation=True):
 output={}
 for i,rid in enumerate(ids):
  f=module/'apps'/(rid+'.json');assert f.read_bytes().hex()==p['original_apps'][rid]
  counter=pathlib.Path('/srv/panel/sites')/own_site/'private'/('pm2-'+rid)/'qa-c43-start-count'
  assert counter.read_text()==str(count if i==0 else 1)
  u=unit('panel-pm2@'+rid+'.service');assert u['LoadState']=='loaded'
  if i:assert u==p['original_units'][rid]and u['ActiveState']=='inactive'and u['UnitFileState']=='disabled'
  else:
   assert u['ActiveState']=='active'and u['UnitFileState']=='enabled'and int(u['MainPID'])>1
   if old_generation:assert u==p['original_units'][rid]
   else:assert u['InvocationID']!=p['original_units'][rid]['InvocationID']
  output[rid]={'unit':u,'original_encrypted_manifest_sha256':sha(f),'counter':counter.read_text()}
 return output
def record(f):
 st=f.lstat();d={'mode':st.st_mode,'uid':st.st_uid,'gid':st.st_gid,'ino':st.st_ino,'dev':st.st_dev,'links':st.st_nlink}
 if stat.S_ISREG(st.st_mode):assert st.st_size<=256<<20;d.update(bytes=st.st_size,sha256=sha(f))
 elif stat.S_ISLNK(st.st_mode):d['target']=os.readlink(f)
 else:assert stat.S_ISDIR(st.st_mode)
 return d
writer_code=r'''
import hashlib,json,os,stat,sys
file,uid,gid,expected=sys.argv[1:];uid=int(uid);gid=int(gid)
os.setgroups([]);os.setgid(gid);os.setuid(uid)
assert os.getuid()==os.geteuid()==uid>0 and os.getgid()==os.getegid()==gid
cap=dict(v.split(':',1)for v in open('/proc/self/status').read().splitlines()if':'in v);assert int(cap['CapEff'],16)==0
fd=os.open(file,os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK);old=os.fstat(fd)
assert stat.S_ISREG(old.st_mode)and old.st_uid==uid and old.st_nlink==1 and old.st_size<=2<<20
body=os.pread(fd,old.st_size+1,0);assert len(body)==old.st_size and hashlib.sha256(body).hexdigest()==expected
print(json.dumps({'uid':uid,'gid':gid,'dev':old.st_dev,'ino':old.st_ino,'original_sha256':expected,'capabilities_zero':True}),flush=True)
assert sys.stdin.readline()=='WRITE-ONLY-RETAINED-FD\n'
new=os.lstat(file);assert new.st_uid==new.st_gid==0 and (new.st_dev,new.st_ino)!=(old.st_dev,old.st_ino)
try:f=os.open(file,os.O_WRONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
except PermissionError:pass
else:os.close(f);raise AssertionError('Original unprivileged account can open the replacement for writes')
marker=b'C70 owned native test: old writable descriptor affects only retained original\n'
os.ftruncate(fd,0);assert os.pwrite(fd,marker,0)==len(marker);os.fsync(fd)
assert os.pread(fd,len(marker)+1,0)==marker
print(json.dumps({'actual_original_fd_truncate_pwrite':True,'old_ino':old.st_ino,'old_dev':old.st_dev,'new_ino':new.st_ino,'new_dev':new.st_dev,'old_written_sha256':hashlib.sha256(marker).hexdigest(),'new_write_open_refused':True}),flush=True)
'''
try:
 guard();before=snapshot();save('before-signed-store-update.json',before)
 originals=projects();save('original-one-running-five-stopped.json',originals)
 original_vendor={n:v for n,v in before['protected_files'].items()if n==str(vendor)or n.startswith(str(vendor)+'/')}
 assert original_vendor==inventory['entries'];assert record(old_writer)==expected_old and expected_old['uid']>0
 old=(module/'installed.json').read_bytes();assert old.hex()==p['original_installed_hex']and json.loads(old)['version']=='7.0.4-compat10'
 access_file=pathlib.Path('/etc/panel/first-login.json');st=access_file.lstat();assert stat.S_ISREG(st.st_mode)and st.st_uid==0 and st.st_nlink==1 and stat.S_IMODE(st.st_mode)==0o600;access=json.loads(access_file.read_bytes())
 try:csrf=api('phase2-original-login','/login',{k:access[k]for k in('username','password')})['csrf']
 finally:access.clear()
 catalog=api('signed-official-store-update-offered','/app-registry?refresh=1');assert len(catalog['catalog']['apps'])==50 and not catalog['source']['stale']and catalog['host']=={'platform':'ubuntu-24.04','architecture':p['architecture']}
 item=next(v for v in catalog['catalog']['apps']if v['id']=='pm2-manager');status=next(v for v in catalog['status']if v['id']=='pm2-manager')
 assert item['version']=='7.0.4-compat11'and item['sha256']==cohort['new_manifest_sha256']and status['state_known']and status['healthy']is False and status['installed_version']=='7.0.4-compat10'and status['update_available']and status['update_supported']
 with contextlib.closing(sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True))as db:db.execute('PRAGMA query_only=ON');assert db.execute("SELECT COUNT(*)FROM app_registry_receipts WHERE app_id='pm2-manager'").fetchone()==(0,)
 save('owned-original-vendor-writer-input.json',{'path':str(old_writer),'identity':expected_old,'original_base64':base64.b64encode(old_writer.read_bytes()).decode()})
 writer=subprocess.Popen(['/usr/bin/python3','-I','-B','-c',writer_code,str(old_writer),str(expected_old['uid']),str(expected_old['gid']),expected_old['sha256']],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
 ready,_,_=select.select([writer.stdout],[],[],20);assert ready
 writer_before=json.loads(writer.stdout.readline());assert writer_before['ino']==expected_old['ino']and writer_before['dev']==expected_old['dev']and writer_before['uid']==expected_old['uid']and writer_before['capabilities_zero']
 save('original-unprivileged-writer-held-before-update.json',writer_before)
 proof['actual_store_update_POSTs']+=1
 accepted=api('one-original-signed-store10to11-update','/app-registry/pm2-manager/update',{'expected_version':item['version'],'expected_sha256':item['sha256']},202,secrets.token_hex(16))
 wait_job('one-original-signed-store10to11-update',accepted['job_id'],'runtime_jobs')
 updated=api('original-signed-store-updated','/app-registry?refresh=1');status=next(v for v in updated['status']if v['id']=='pm2-manager')
 assert status['state_known']and status['installed']and status['healthy']and status['installed_version']=='7.0.4-compat11'and not status['update_available']
 installed=json.loads((module/'installed.json').read_bytes());prior=json.loads(old);assert installed['version']=='7.0.4-compat11'
 assert {k:v for k,v in installed.items()if k not in('version','updated_at')}=={k:v for k,v in prior.items()if k not in('version','updated_at')}
 assert projects()==originals;running=probe('original-active-project-not-restarted-by-store-update');assert running['actual_HTTP']['start_count']==1
 pub_pointer=vendor/'.root-owned-pm2-vendor.json';pin=json.loads(pub_pointer.read_bytes());assert re.fullmatch(r'\.pm2-vendor-[a-f0-9]{32}',pin['workspace'])
 work=vendor.parent/pin['workspace'];wst=work.lstat();assert stat.S_ISDIR(wst.st_mode)and wst.st_uid==wst.st_gid==0 and stat.S_IMODE(wst.st_mode)==0o700
 complete=json.loads((work/'original-publication-completed.json').read_bytes());assert complete=={'published':True,'original_directory_retained':True,'private_evidence_directory':str(work)}
 anchor=work/'vendor-anchor.json';assert sha(anchor)==pin['anchor_sha256'];index=json.loads(anchor.read_bytes());assert index['upstream']=='7.0.4' and len(index['entries'])>=3000
 for label,file in [('original-public-Root-vendor-pointer',pub_pointer),('original-private-Root-vendor-anchor',anchor),('original-private-Root-vendor-completion',work/'original-publication-completed.json'),('original-updated-installed-record',module/'installed.json'),('original-dependency-result',module/'dependency-result.json')]:
  original=record(file);assert original['uid']==0 and stat.S_ISREG(original['mode'])and original['links']==1
  if label in ('original-updated-installed-record','original-dependency-result'):
   expected=before['protected_files'].get(str(file),{})
   if 'gid'in expected:assert original['gid']==expected['gid']
  else:assert original['gid']==0
  raw=file.read_bytes();assert hashlib.sha256(raw).hexdigest()==original['sha256']
  with(evidence/(label+'.bytes')).open('xb')as out:out.write(raw);out.flush();os.fsync(out.fileno())
 retained=work/'candidate';assert record(retained)==original_vendor[str(vendor)]
 for n,v in original_vendor.items():
  if n!=str(vendor):assert record(retained/pathlib.Path(n).relative_to(vendor))==v,n
 new_before=record(old_writer);assert new_before['uid']==new_before['gid']==0 and new_before['ino']!=expected_old['ino']
 stdout,stderr=writer.communicate('WRITE-ONLY-RETAINED-FD\n',timeout=20);save('original-unprivileged-writer-after-exchange.json',{'exit':writer.returncode,'stdout':stdout,'stderr':stderr})
 assert writer.returncode==0 and not stderr
 after_writer=json.loads(stdout);assert after_writer['actual_original_fd_truncate_pwrite']and after_writer['old_ino']==expected_old['ino']and after_writer['new_ino']==new_before['ino']and after_writer['new_write_open_refused']
 assert record(old_writer)==new_before and sha(retained/relative)==after_writer['old_written_sha256'] and sha(retained/relative)!=expected_old['sha256']
 for n,v in original_vendor.items():
  if n!=str(old_writer):assert record(retained/pathlib.Path(n).relative_to(vendor))==v,n
 for n,original in p['original_node_programs'].items():
  f=pathlib.Path(n).resolve(strict=True);st=f.lstat();assert {'path':str(f),'sha256':sha(f),'inode':st.st_ino,'mode':st.st_mode}==original
 with contextlib.closing(sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True))as db:
  db.execute('PRAGMA query_only=ON');rows=db.execute("SELECT app_id,scope,version,sha256,target FROM app_registry_receipts WHERE app_id='pm2-manager'").fetchall()
  assert rows==[('pm2-manager','pm2-manager','7.0.4-compat11',cohort['new_manifest_sha256'],'pm2-manager')]
 save('original-vendor-and-signed-receipt-outcome.json',{'public_new':new_before,'old_retained':record(retained/relative),'Root_anchor_sha256':pin['anchor_sha256'],'original_vendor_entries_preserved_except_owned_test_writer':len(original_vendor)-1,'original_receipts':rows,'original_active_generation_still_running':True})
 before_restart=snapshot();save('after-store-before-explicit-restart.json',before_restart);assert before['schema']==before_restart['schema']and before['nss']==before_restart['nss']and before['packages']==before_restart['packages']and before['lifetimes']==before_restart['lifetimes']
 proof['actual_explicit_project_restart_POSTs']+=1
 restarted=api('one-explicit-restart-on-new-sealed-runtime','/app-modules/pm2-manager/restart',{'resource_id':ids[0],'expected_revision':1});assert restarted['ok']and restarted['boot_enabled']
 new_live=probe('explicit-new-generation-real-nonroot-HTTP');assert new_live['actual_HTTP']['start_count']==2;save('final-six-projects.json',projects(count=2,old_generation=False))
 proof.update(ok=True,normal_signed_store10to11_update_completed=True,original_job_id=accepted['job_id'],package_sha256=item['sha256'],original_live_generation_preserved_until_explicit_restart=True,other_five_projects_still_stopped_boot_disabled=True,all_six_original_encrypted_manifests_preserved=True,actual_old_unprivileged_writer_changes_only_retained_copy=True,original_installed_at_settings_and_other_identity_fields_preserved=True,durable_original_signed_receipt_exact=True,same_update_no_longer_offered=True,full113_original_SQL_independent_qualification_pending=True)
except BaseException:
 proof['failure']=traceback.format_exc().replace(secret,'[synthetic-environment-redacted]')
finally:
 if writer and writer.poll() is None:
  try:writer.communicate('',timeout=5)
  except subprocess.TimeoutExpired:writer.terminate();writer.communicate(timeout=5)
 if csrf:
  try:api('phase2-original-logout','/logout',{});csrf=''
  except BaseException:proof['logout_failure']='Inspect original response without replay'
 try:save('after-signed-store-update.json',snapshot())
 except BaseException:proof['capture_failure']=traceback.format_exc();proof['ok']=False
 save('HTTP-events.json',events);save('original-proof.json',proof)
 print(json.dumps({'ok':proof['ok'],'phase':'actual-signed-store10to11-update','architecture':p['architecture'],'actual_update_POSTs':proof['actual_store_update_POSTs'],'all50_commercial':False}),flush=True)
sys.exit(0 if proof['ok']else 1)
