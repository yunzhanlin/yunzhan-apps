"""Install the existing C47 normal default PM2 identity before a signed upgrade.
This is the legacy normal API, not a signed catalogue-install acceptance claim.
"""
import ast,contextlib,hashlib,http.cookiejar,json,os,pathlib,re,sqlite3,stat,subprocess,sys,time,traceback,urllib.error,urllib.request
os.umask(0o077);assert os.geteuid()==0 and len(sys.argv)==2;base=pathlib.Path(sys.argv[1]);assert re.fullmatch('/opt/panel-pm2-c48-bootstrap-[a-f0-9]{32}',str(base));p=json.loads((base/'intent.json').read_bytes());assert pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()==p['boot'];assert json.loads(pathlib.Path('/opt/panel/current/SOURCE_INPUTS.json').read_bytes())['inputs_sha256']=='c761613ae003b8cde9df5d777d6b1c4013dbaeb832082a5dc3a0ee4d1e1c319c'
evidence=base/'evidence';evidence.mkdir(mode=0o700);capture=(base/'capture.py').read_bytes();assert hashlib.sha256(capture).hexdigest()==p['files']['capture.py'];names={'sha','save','command','unit','snapshot','guard','api','wait_job','NoRedirect'};nodes=[v for v in ast.parse(capture).body if isinstance(v,(ast.FunctionDef,ast.ClassDef))and v.name in names];assert len(nodes)==len(names);exec(compile(ast.Module(body=nodes,type_ignores=[]),'<unchanged-native-observers>','exec'),globals());origin='http://127.0.0.1:19100';client=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect(),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()));csrf='';events=[];secret=p['synthetic_environment'];own_site=None
proof={'ok':False,'normal_legacy_PM2_install_POSTs':0,'normal_signed_catalogue_install_claim':False,'Main_changed':False,'all50_commercial':False,'original_operation_replayed':False}
try:
 guard();save('before.json',snapshot());assert not os.path.lexists('/etc/panel/security-apps/modules/pm2-manager/installed.json');access_file=pathlib.Path('/etc/panel/first-login.json');s=access_file.lstat();assert stat.S_ISREG(s.st_mode)and s.st_uid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600;access=json.loads(access_file.read_bytes())
 try:csrf=api('login','/login',{k:access[k]for k in('username','password')})['csrf']
 finally:access.clear()
 proof['normal_legacy_PM2_install_POSTs']+=1;accepted=api('legacy-PM2-normal-install','/software/pm2-manager/install',{'settings':{}},202,p['install_key']);wait_job('legacy-PM2-normal-install',accepted['job_id'],'runtime_jobs');installed=json.loads(pathlib.Path('/etc/panel/security-apps/modules/pm2-manager/installed.json').read_bytes());assert installed['version']=='7.0.4-compat8'
 with contextlib.closing(sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True))as db:
  db.execute('PRAGMA query_only=ON');assert db.execute("SELECT COUNT(*) FROM app_registry_receipts WHERE app_id='pm2-manager'").fetchone()==(0,)
 proof.update(ok=True,legacy_install_job_id=accepted['job_id'],original_legacy_PM2_version='7.0.4-compat8',no_fabricated_signed_receipt=True,no_PM2_project_before_programme_upgrade=True)
except BaseException:proof['failure']=traceback.format_exc().replace(secret,'[synthetic-environment-redacted]')
finally:
 if csrf:
  try:api('logout','/logout',{});csrf=''
  except BaseException:proof['logout_failure']='Inspect original response; no replay'
 try:save('after.json',snapshot())
 except BaseException:proof['capture_failure']=traceback.format_exc();proof['ok']=False
 save('HTTP-events.json',events);save('proof.json',proof);print(json.dumps({'ok':proof['ok'],'base':str(base),'proof_sha256':sha(evidence/'proof.json')}),flush=True)
sys.exit(0 if proof['ok']else 1)
