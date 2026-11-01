"""Fresh normal API intents against the upgraded C47 owned PM2 fixture."""
import ast,contextlib,copy,hashlib,http.cookiejar,json,os,pathlib,pwd,re,socket,sqlite3,stat,subprocess,sys,time,traceback,urllib.error,urllib.request
os.umask(0o077);base=pathlib.Path(sys.argv[1]);assert re.fullmatch('/opt/panel-pm2-c43-service-[a-f0-9]{32}',str(base));assert os.geteuid()==0
p=json.loads((base/'intent.json').read_bytes());assert pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()==p['boot'];assert json.loads(pathlib.Path('/opt/panel/current/SOURCE_INPUTS.json').read_bytes())['inputs_sha256']=='c761613ae003b8cde9df5d777d6b1c4013dbaeb832082a5dc3a0ee4d1e1c319c'
evidence=base/'evidence';evidence.mkdir(mode=0o700)
names={'sha','save','command','unit','snapshot','guard','api','probe','NoRedirect','history','owned_journal'};nodes=[v for v in ast.parse((base/'capture.py').read_bytes()).body if isinstance(v,(ast.FunctionDef,ast.ClassDef))and v.name in names];assert len(nodes)==len(names)
exec(compile(ast.Module(body=nodes,type_ignores=[]),'<bound-original-native-PM2-observers-and-normal-client>','exec'),globals())
origin='http://127.0.0.1:19100';client=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect(),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()));csrf='';events=[];secret=p['synthetic_environment'];own_site=p['site_id'];name='panel-pm2@'+p['resource_id']+'.service';app_path=pathlib.Path('/etc/panel/security-apps/modules/pm2-manager/apps')/(p['resource_id']+'.json');counter=pathlib.Path('/srv/panel/sites')/own_site/'private'/('pm2-'+p['resource_id'])/p.get('counter_file','qa-c43-start-count');assert counter.name in('qa-c42-start-count','qa-c43-start-count');initial_revision=p.get('initial_revision',2);initial_count=p.get('initial_start_count',2);initial_memory=p.get('initial_memory_mb',160)
def stopped(label,count):
 v=unit(name);assert v['LoadState']=='loaded'and v['ActiveState']=='inactive'and v['SubState']=='dead'and v['MainPID']=='0'and v['UnitFileState']=='disabled';assert counter.read_text()==str(count)
 try:
  connection=socket.create_connection(('127.0.0.1',p['port']),timeout=2);connection.close();raise AssertionError('Stopped application port remains reachable')
 except ConnectionRefusedError:pass
 result={'unit':v,'start_count':count,'counter_sha256':sha(counter),'app_sha256':sha(app_path),'port_connection_refused':True};save(label+'.json',result);return result
proof={'ok':False,'purpose':'Actual C47 PM2 stopped-save/start/stop/restart/active-failure rollback; no reboot or catalogue update claim','source_inputs_sha256':'c761613ae003b8cde9df5d777d6b1c4013dbaeb832082a5dc3a0ee4d1e1c319c','actual_application_install_version':'7.0.4-compat7','native_reboot_pending':True,'normal_signed_store_update_pending':True,'Main_changed':False,'all50_commercial':False,'original_mutations_replayed':False}
try:
 guard();loaded=dict(v.split('=',1)for v in command(['systemctl','show',name,'--property=KillMode,TimeoutStopUSec,NeedDaemonReload,FragmentPath,DropInPaths']).splitlines());assert loaded=={'KillMode':'mixed','TimeoutStopUSec':'10s','NeedDaemonReload':'no','FragmentPath':'/etc/systemd/system/panel-pm2@.service','DropInPaths':''};assert sha('/etc/systemd/system/panel-pm2@.service')=='699c21953f4f50958605d7514e95e44bff53fb78dcfb8fa94fd08f3fa84528f2';save('actual-loaded-PM2-graceful-stop-unit.json',loaded);save('before.json',snapshot());history('history-before');initial=json.loads(app_path.read_bytes());assert initial['id']==p['resource_id']and initial['site_id']==own_site and initial['revision']==initial_revision and initial['memory_mb']==initial_memory;stopped('initial-stopped',initial_count)
 access_path=pathlib.Path('/etc/panel/first-login.json');s=access_path.lstat();assert stat.S_ISREG(s.st_mode)and s.st_uid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600;access=json.loads(access_path.read_bytes())
 try:login=api('login','/login',{k:access[k]for k in ('username','password')});csrf=login['csrf']
 finally:access.clear()
 report=api('read-stopped-report','/app-modules/pm2-manager/run',{});row=next(v for v in report['apps']if v['app']['id']==p['resource_id']);assert row['state']=='inactive'and row['state_known']and row['boot_enabled']is False
 saved=api('save-stopped','/app-modules/pm2-manager/update',{'resource_id':p['resource_id'],'expected_revision':initial_revision,'memory_mb':192});assert saved['ok']and saved['preserved_stopped']and saved['runtime_validated']is False and saved['boot_enabled']is False and saved['app']['revision']==initial_revision+1;stopped('after-stopped-save',initial_count+0);assert json.loads(app_path.read_bytes())['environment_cipher']==initial['environment_cipher']
 before_stale=app_path.read_bytes();api('stale-save-refused','/app-modules/pm2-manager/update',{'resource_id':p['resource_id'],'expected_revision':initial_revision,'memory_mb':224},409);assert app_path.read_bytes()==before_stale;stopped('after-stale-refusal',initial_count+0)
 started=api('explicit-start','/app-modules/pm2-manager/start',{'resource_id':p['resource_id']});assert started['ok']and started['boot_enabled'];running=probe('after-explicit-start');assert running['actual_HTTP']['start_count']==initial_count+1
 stopped_response=api('explicit-stop','/app-modules/pm2-manager/stop',{'resource_id':p['resource_id']});assert stopped_response['ok']and stopped_response['boot_enabled']is False;stopped('after-explicit-stop',initial_count+1)
 secret=p['replacement_environment'];saved=api('save-stopped-secret','/app-modules/pm2-manager/update',{'resource_id':p['resource_id'],'expected_revision':initial_revision+1,'memory_mb':208,'environment_patch':{'QA_PM2_CANARY':secret}});assert saved['preserved_stopped']and saved['runtime_validated']is False and saved['app']['revision']==initial_revision+2;stopped('after-stopped-secret-save',initial_count+1);assert json.loads(app_path.read_bytes())['environment_cipher']!=initial['environment_cipher']
 api('explicit-start-new-secret','/app-modules/pm2-manager/start',{'resource_id':p['resource_id']});running=probe('after-new-secret-start');assert running['actual_HTTP']['start_count']==initial_count+2
 restart=api('explicit-restart','/app-modules/pm2-manager/restart',{'resource_id':p['resource_id']});assert restart['ok']and restart['boot_enabled'];running=probe('after-explicit-restart');assert running['actual_HTTP']['start_count']==initial_count+3
 bad="throw new Error('owned C43 explicit failed-entry rollback fixture');\n";created=api('create-failed-entry','/sites/'+own_site+'/files/action',{'action':'create','path':p['bad_entry'],'content':bad});assert created['sha256']==hashlib.sha256(bad.encode()).hexdigest()
 original=app_path.read_bytes();save('active-original-manifest.json',json.loads(original));owned_journal('journal-before-active-rollback');started=time.monotonic();api('active-bad-entry-update','/app-modules/pm2-manager/update',{'resource_id':p['resource_id'],'expected_revision':initial_revision+2,'entry':p['bad_entry'],'memory_mb':224,'environment_patch':{'QA_PM2_CANARY':p['failed_candidate_environment']}},409);elapsed=time.monotonic()-started;assert 45<=elapsed<75 and app_path.read_bytes()==original
 running=probe('after-active-failure-rollback');assert running['actual_HTTP']['start_count']==initial_count+4 and running['app']['revision']==initial_revision+2 and running['app']['entry']==p['entry']and running['app']['memory_mb']==208;save('actual-active-rollback.json',{'old_manifest_bytes_exact':True,'old_encrypted_environment_preserved':True,'old_actual_primary_GID_and_nonroot_HTTP_verified':True,'seconds':elapsed,'candidate_secret_not_committed':True})
 result=api('final-explicit-stop','/app-modules/pm2-manager/stop',{'resource_id':p['resource_id']});assert result['ok']and result['boot_enabled']is False;stopped('final-stopped',initial_count+4);guard()
 for file in (pathlib.Path('/var/lib/panel/panel.db'),pathlib.Path('/var/lib/panel/panel.db-wal')):
  if file.exists():
   raw=file.read_bytes();assert all(v.encode()not in raw for v in (p['synthetic_environment'],p['replacement_environment'],p['failed_candidate_environment']))
 proof.update(ok=True,stopped_configuration_saves_never_started_project=True,stop_disables_boot_and_explicit_start_enables_boot=True,restart_preserved_boot=True,actual_HTTP_start_counts=[initial_count+n for n in(0,0,1,1,2,3,4)],actual_nonroot_primary_GID_environment_and_hardening_verified=True,stale_revision_refused_without_configuration_change=True,active_failed_update_restored_exact_manifest_and_old_secret=True,owned_fixture_retained_stopped_boot_disabled=True)
except BaseException:
 failure=traceback.format_exc()
 for key in ('synthetic_environment','replacement_environment','failed_candidate_environment'):failure=failure.replace(p[key],'[synthetic-environment-redacted]')
 proof['failure']=failure
finally:
 if csrf:
  try:api('logout','/logout',{});csrf=''
  except BaseException:proof['logout_failure']='Normal logout did not complete; inspect original response without replay'
 try:save('after.json',snapshot())
 except BaseException:proof['after_capture_failure']=traceback.format_exc();proof['ok']=False
 try:history('history-after')
 except BaseException:proof['history_capture_failure']=traceback.format_exc();proof['ok']=False
 try:owned_journal('journal-after-active-rollback')
 except BaseException:proof['journal_capture_failure']=traceback.format_exc();proof['ok']=False
 save('HTTP-events.json',events);save('proof.json',proof);print(json.dumps({'ok':proof['ok'],'base':str(base),'proof_sha256':sha(evidence/'proof.json'),'Main_changed':False,'all50_commercial':False}),flush=True)
sys.exit(0 if proof['ok']else 1)
