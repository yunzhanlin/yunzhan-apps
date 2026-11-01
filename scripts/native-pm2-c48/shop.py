"""One original-signed PM2 compat7 to compat8 update through normal store API."""
import ast,contextlib,hashlib,http.cookiejar,json,os,pathlib,pwd,re,socket,sqlite3,stat,subprocess,sys,time,traceback,urllib.error,urllib.request
os.umask(0o077);assert os.geteuid()==0 and len(sys.argv)==2;base=pathlib.Path(sys.argv[1]);assert re.fullmatch('/opt/panel-pm2-c48-shop-[a-f0-9]{32}',str(base));p=json.loads((base/'intent.json').read_bytes());evidence=base/'evidence';evidence.mkdir(mode=0o700);assert pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()==p['boot'];SOURCE='08e692c22b06cf6267b665ddd1a320250e520c1caf745afaf90d7d10d7b7743a';assert json.loads(pathlib.Path('/opt/panel/current/SOURCE_INPUTS.json').read_bytes())['inputs_sha256']==SOURCE
capture=(base/'capture.py').read_bytes();assert hashlib.sha256(capture).hexdigest()==p['files']['capture.py'];names={'sha','save','command','unit','snapshot','guard','api','wait_job','NoRedirect','history'};nodes=[v for v in ast.parse(capture).body if isinstance(v,(ast.FunctionDef,ast.ClassDef))and v.name in names];assert len(nodes)==len(names);exec(compile(ast.Module(body=nodes,type_ignores=[]),'<original-source-bound-native-observers>','exec'),globals());origin='http://127.0.0.1:19100';client=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect(),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()));csrf='';events=[];secret=p['replacement_environment'];own_site=p['site_id'];module=pathlib.Path('/etc/panel/security-apps/modules/pm2-manager');app=module/'apps'/(p['resource_id']+'.json');counter=pathlib.Path('/srv/panel/sites')/own_site/'private'/('pm2-'+p['resource_id'])/'qa-c43-start-count';name='panel-pm2@'+p['resource_id']+'.service'
def stopped():
 u=unit(name);assert u['LoadState']=='loaded'and u['ActiveState']=='inactive'and u['SubState']=='dead'and u['MainPID']=='0'and u['UnitFileState']=='disabled';assert counter.read_text()=='6';return u
proof={'ok':False,'source_inputs_sha256':SOURCE,'normal_store_update_POSTs':0,'actual_browser_UI_acceptance':False,'Main_changed':False,'all50_commercial':False,'original_operations_replayed':False}
try:
 guard();before=snapshot();save('before.json',before);history('history-before');original=app.read_bytes();original_counter=counter.read_bytes();state=stopped();save('original-stopped-unit.json',state);installed=json.loads((module/'installed.json').read_bytes());assert installed['version']=='7.0.4-compat8';access_file=pathlib.Path('/etc/panel/first-login.json');s=access_file.lstat();assert stat.S_ISREG(s.st_mode)and s.st_uid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600;access=json.loads(access_file.read_bytes())
 try:csrf=api('login','/login',{k:access[k]for k in('username','password')})['csrf']
 finally:access.clear()
 catalog=api('signed-catalogue-update-offered','/app-registry?refresh=1');assert len(catalog['catalog']['apps'])==50 and not catalog['source']['stale']and catalog['host']=={'platform':p['platform'],'architecture':'amd64'};item=next(v for v in catalog['catalog']['apps']if v['id']=='pm2-manager');status=next(v for v in catalog['status']if v['id']=='pm2-manager');assert item['version']=='7.0.4-compat9'and item['sha256']=='f53bd60c94d4ef5b20af0ed2a44fc1393c7e61811779944855b726872804ba71'and status['state_known']and status['healthy']and status['installed_version']=='7.0.4-compat8'and status['update_available']
 with contextlib.closing(sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True))as db:db.execute('PRAGMA query_only=ON');assert db.execute("SELECT COUNT(*) FROM app_registry_receipts WHERE app_id='pm2-manager'").fetchone()==(0,)
 proof['normal_store_update_POSTs']+=1;accepted=api('one-normal-signed-store-update','/app-registry/pm2-manager/update',{'expected_version':item['version'],'expected_sha256':item['sha256']},202,p['store_key']);wait_job('one-normal-signed-store-update',accepted['job_id'],'runtime_jobs');catalog=api('signed-store-updated','/app-registry?refresh=1');status=next(v for v in catalog['status']if v['id']=='pm2-manager');assert status['state_known']and status['installed']and status['healthy']and status['installed_version']=='7.0.4-compat9'and not status['update_available']
 assert json.loads((module/'installed.json').read_bytes())['version']=='7.0.4-compat9'and app.read_bytes()==original and counter.read_bytes()==original_counter and stopped()==state
 with contextlib.closing(sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True))as db:
  db.execute('PRAGMA query_only=ON');rows=db.execute('SELECT app_id,scope,version,sha256,target FROM app_registry_receipts WHERE app_id=?',('pm2-manager',)).fetchall();assert rows==[('pm2-manager','pm2-manager',item['version'],item['sha256'],'pm2-manager')]
 proof.update(ok=True,normal_signed_shop_update_completed=True,original_update_job_id=accepted['job_id'],from_version='7.0.4-compat8',to_version='7.0.4-compat9',package_sha256=item['sha256'],actual_stopped_unit_and_start_counter_unchanged=True,old_encrypted_configuration_bytes_preserved=True,new_durable_signed_receipt_from_no_old_receipt=True,store_no_longer_offers_same_update=True)
except BaseException:
 message=traceback.format_exc()
 for k in('synthetic_environment','replacement_environment','failed_candidate_environment'):message=message.replace(p[k],'[synthetic-environment-redacted]')
 proof['failure']=message
finally:
 if csrf:
  try:api('logout','/logout',{});csrf=''
  except BaseException:proof['logout_failure']='Inspect original response; no replay'
 try:save('after.json',snapshot());history('history-after');save('final-stopped-unit.json',stopped())
 except BaseException:proof['capture_failure']=traceback.format_exc();proof['ok']=False
 save('HTTP-events.json',events);save('proof.json',proof);print(json.dumps({'ok':proof['ok'],'base':str(base),'proof_sha256':sha(evidence/'proof.json')}),flush=True)
sys.exit(0 if proof['ok']else 1)
