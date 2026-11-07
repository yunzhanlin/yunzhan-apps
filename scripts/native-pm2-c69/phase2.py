"""Complete one normal original-signed compat9-to-compat10 store update."""
import contextlib,hashlib,http.cookiejar,json,os,pathlib,pwd,re,socket,sqlite3,stat,subprocess,sys,time,traceback,urllib.error,urllib.request
os.umask(0o077)
assert os.geteuid()==0 and len(sys.argv)==2
private=pathlib.Path(sys.argv[1]).resolve(strict=True);source=pathlib.Path(__file__).resolve().parent;cohort=json.loads((source/'cohort.json').read_bytes())
phase1=json.loads((private/'business-phase1/original-proof.json').read_bytes());assert phase1['ok']and phase1['actual_nonroot_project_count']==6 and phase1['source_inputs_sha256']==cohort['source_inputs_sha256']
p=json.loads((private/'business-phase1/original-owned-store-next-phase-intent.json').read_bytes());assert pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()==p['boot']
evidence=private/'business-phase2';evidence.mkdir(mode=0o700)
raw=(source/'capture.py').read_bytes();assert hashlib.sha256(raw).hexdigest()==cohort['files']['capture.py'];exec(compile(raw,'<original-source-bound-observers>','exec'),globals())
assert json.loads(pathlib.Path('/opt/panel/current/SOURCE_INPUTS.json').read_bytes())['inputs_sha256']==cohort['source_inputs_sha256']
secret=p['synthetic_environment'];own_site=p['site_id'];csrf='';events=[];ids=p['owned_project_ids'];module=pathlib.Path('/etc/panel/security-apps/modules/pm2-manager')
origin='http://127.0.0.1:19100';client=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect(),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
proof={'ok':False,'phase':'actual-signed-store9to10-update','architecture':p['architecture'],'source_inputs_sha256':cohort['source_inputs_sha256'],'actual_store_update_POSTs':0,'actual_browser_UI_acceptance':False,'Main_changed':False,'all50_commercial':False}
def stopped_all():
 result={}
 for i,rid in enumerate(ids):
  app=module/'apps'/(rid+'.json');assert app.read_bytes().hex()==p['original_apps'][rid]
  counter=pathlib.Path('/srv/panel/sites')/own_site/'private'/('pm2-'+rid)/'qa-c43-start-count';assert counter.read_text()=='2'
  u=unit('panel-pm2@'+rid+'.service');assert u['LoadState']=='loaded'and u['ActiveState']=='inactive'and u['SubState']=='dead'and u['MainPID']=='0'and u['UnitFileState']=='disabled'
  result[rid]={'unit':u,'counter_sha256':sha(counter),'original_encrypted_manifest_sha256':sha(app)}
 return result
try:
 guard();before=snapshot();save('before-signed-store-update.json',before);original=stopped_all();save('original-six-stopped-units.json',original);old=(module/'installed.json').read_bytes();assert old.hex()==p['original_installed_hex']and json.loads(old)['version']=='7.0.4-compat9'
 access_file=pathlib.Path('/etc/panel/first-login.json');st=access_file.lstat();assert stat.S_ISREG(st.st_mode)and st.st_uid==0 and st.st_nlink==1 and stat.S_IMODE(st.st_mode)==0o600;access=json.loads(access_file.read_bytes())
 try:csrf=api('phase2-original-login','/login',{k:access[k]for k in('username','password')})['csrf']
 finally:access.clear()
 catalog=api('signed-official-store-update-offered','/app-registry?refresh=1');assert len(catalog['catalog']['apps'])==50 and not catalog['source']['stale']and catalog['host']=={'platform':'ubuntu-24.04','architecture':p['architecture']}
 item=next(v for v in catalog['catalog']['apps']if v['id']=='pm2-manager');status=next(v for v in catalog['status']if v['id']=='pm2-manager')
 assert item['version']=='7.0.4-compat10'and item['sha256']==cohort['new_manifest_sha256']and status['state_known']and status['healthy']and status['installed_version']=='7.0.4-compat9'and status['update_available']and status['update_supported']
 with contextlib.closing(sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True))as db:db.execute('PRAGMA query_only=ON');assert db.execute("SELECT COUNT(*)FROM app_registry_receipts WHERE app_id='pm2-manager'").fetchone()==(0,)
 proof['actual_store_update_POSTs']+=1
 accepted=api('one-original-signed-store9to10-update','/app-registry/pm2-manager/update',{'expected_version':item['version'],'expected_sha256':item['sha256']},202,secrets.token_hex(16))
 wait_job('one-original-signed-store9to10-update',accepted['job_id'],'runtime_jobs')
 updated=api('original-signed-store-updated','/app-registry?refresh=1');status=next(v for v in updated['status']if v['id']=='pm2-manager')
 assert status['state_known']and status['installed']and status['healthy']and status['installed_version']=='7.0.4-compat10'and not status['update_available']
 installed=json.loads((module/'installed.json').read_bytes());prior=json.loads(old);assert installed['version']=='7.0.4-compat10'
 assert {k:v for k,v in installed.items()if k not in('version','updated_at')}=={k:v for k,v in prior.items()if k not in('version','updated_at')}
 final=stopped_all();save('final-original-six-stopped-units.json',final)
 for rid in ids:
  assert final[rid]['counter_sha256']==original[rid]['counter_sha256']and final[rid]['original_encrypted_manifest_sha256']==original[rid]['original_encrypted_manifest_sha256']
 with contextlib.closing(sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True))as db:
  db.execute('PRAGMA query_only=ON');rows=db.execute("SELECT app_id,scope,version,sha256,target FROM app_registry_receipts WHERE app_id='pm2-manager'").fetchall()
  assert rows==[('pm2-manager','pm2-manager','7.0.4-compat10',cohort['new_manifest_sha256'],'pm2-manager')]
 projects=api('signed-update-independent-project-read','/app-modules/pm2-manager/projects?limit=32&offset=0');assert projects['project_page_complete']is True and len(projects['apps'])==6 and all(v['state_known']and v['state']=='inactive'and v['boot_enabled']is False for v in projects['apps'])
 proof.update(ok=True,normal_signed_store9to10_update_completed=True,original_job_id=accepted['job_id'],package_sha256=item['sha256'],all_six_original_encrypted_manifests_and_counters_preserved=True,all_six_original_projects_remain_stopped_and_boot_disabled=True,original_installed_at_settings_and_other_identity_fields_preserved=True,durable_original_signed_receipt_exact=True,same_update_no_longer_offered=True,full113_original_SQL_independent_qualification_pending=True)
except BaseException:
 proof['failure']=traceback.format_exc().replace(secret,'[synthetic-environment-redacted]')
finally:
 if csrf:
  try:api('phase2-original-logout','/logout',{});csrf=''
  except BaseException:proof['logout_failure']='Inspect original response without replay'
 try:save('after-signed-store-update.json',snapshot())
 except BaseException:proof['capture_failure']=traceback.format_exc();proof['ok']=False
 save('HTTP-events.json',events);save('original-proof.json',proof)
 print(json.dumps({'ok':proof['ok'],'phase':'actual-signed-store9to10-update','architecture':p['architecture'],'actual_update_POSTs':proof['actual_store_update_POSTs'],'all50_commercial':False}),flush=True)
sys.exit(0 if proof['ok']else 1)

