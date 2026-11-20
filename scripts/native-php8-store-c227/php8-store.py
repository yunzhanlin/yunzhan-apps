"""Exercise actual signed Core and independent Root policy; never install retired PHP."""
import contextlib,hashlib,http.client,http.cookiejar,json,os,platform,re,secrets,socket,sqlite3,subprocess,sys,urllib.request,urllib.error
from pathlib import Path
os.umask(0o077)
assert os.geteuid()==0 and os.environ.get('GITHUB_ACTIONS')=='true'and os.environ.get('GITHUB_REPOSITORY')=='yunzhanlin/yunzhan-apps'
evidence=Path(sys.argv[1]);out=evidence/'business-phase1';out.mkdir(mode=0o700);plan=json.loads((Path(__file__).resolve().parent/'cohort.json').read_bytes());arch={'x86_64':'amd64','aarch64':'arm64'}[platform.machine()]
assert json.loads(Path('/opt/panel/current/SOURCE_INPUTS.json').read_bytes())['inputs_sha256']==plan['source_inputs_sha256']
origin='http://127.0.0.1:19100';csrf=''
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*a,**kw):raise AssertionError('Unexpected redirect')
client=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect(),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
def save(name,v):
 with(out/(name+'.json')).open('x')as f:json.dump(v,f,indent=2);f.write('\n')
def api(path,data=None,expected=200):
 headers={'Origin':origin,'Content-Type':'application/json','X-CSRF-Token':csrf}
 if data is not None:headers['Idempotency-Key']=secrets.token_hex(16)
 try:
  with client.open(urllib.request.Request(origin+'/api'+path,None if data is None else json.dumps(data).encode(),headers),timeout=60)as r:assert r.status==expected;return json.loads(r.read(8<<20))
 except urllib.error.HTTPError as e:
  raw=e.read(4096);assert e.code==expected,(path,e.code,expected,raw);return json.loads(raw)
class RootConnection(http.client.HTTPConnection):
 def connect(self):
  self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.sock.settimeout(10);self.sock.connect('/run/panel-executor/control.sock')
def root(data):
 connection=RootConnection('executor',timeout=10)
 try:
  connection.request('POST','/v1/docker/projects/jobs',json.dumps(data),{'Content-Type':'application/json'});r=connection.getresponse();value=json.loads(r.read(8192));return r.status,value
 finally:connection.close()
def paths():
 result={}
 for root in ['/var/lib/panel-executor/docker-jobs','/etc/panel/compose']:
  p=Path(root)
  if not p.exists():result[root]={'exists':False};continue
  for f in [p,*sorted(p.rglob('*'))]:
   st=f.lstat();assert not f.is_symlink();result[str(f)]={'mode':st.st_mode,'uid':st.st_uid,'gid':st.st_gid,'inode':st.st_ino,'bytes':st.st_size,'sha256':hashlib.sha256(f.read_bytes()).hexdigest()if f.is_file()else None}
 return result
def tables():
 result={}
 with sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True)as db:
  for name in ['jobs','sites','runtime_installations','app_registry_receipts','app_registry_install_requests','app_registry_update_requests','app_registry_pending']:
   assert re.fullmatch('[a-z_]+',name);rows=db.execute('SELECT * FROM "'+name+'"').fetchall();encoded=sorted(json.dumps(row,ensure_ascii=True,default=str)for row in rows);result[name]={'rows':len(rows),'sha256':hashlib.sha256(json.dumps(encoded).encode()).hexdigest()}
 return result
def lifetimes():return subprocess.check_output(['/usr/bin/systemctl','show','panel.service','panel-executor.service','--property=Id,MainPID,InvocationID,ExecMainStartTimestampMonotonic'],text=True)
proof={'ok':False,'architecture':arch,'source_inputs_sha256':plan['source_inputs_sha256'],'Main_changed':False,'all40_commercial':False,'retired_PHP_installations':0}
try:
 login=json.loads(Path('/etc/panel/first-login.json').read_bytes());csrf=api('/login',{k:login[k]for k in('username','password')})['csrf'];login.clear()
 data=api('/app-registry?refresh=1');assert data['source']['resolved_commit']==plan['served_head']and not data['source']['stale']and len(data['catalog']['apps'])==40
 ids={a['id']for a in data['catalog']['apps']};assert ids.isdisjoint(plan['retired_templates'])
 for id in ['php-80','php-81','php-82','php-83','php-84','php-85']:
  assert id in ids;status,=[a for a in data['status']if a['id']==id];assert status['supported']and status['state_known']
 templates=api('/docker/templates')['templates'];names={a['id']for a in templates};assert {'php-legacy-80-bullseye-compat2','php-legacy-81-bookworm-compat2'}<=names
 retired={t for id,t in plan['retired_templates'].items()}|{'php-legacy-'+id.split('-')[1]for id in plan['retired_templates']};assert names.isdisjoint(retired)
 before={'paths':paths(),'tables':tables(),'lifetimes':lifetimes()};save('original-before-admission',before)
 outcomes=[]
 for template in sorted(retired):
  response=api('/docker/projects',{'name':'retired-policy','template_id':template,'host_port':23000,'compose':''},400);assert response['request_not_accepted']is True and'已从商店移除'in response['error']
  job,project=secrets.token_hex(16),secrets.token_hex(16);status,result=root({'job_id':job,'project_id':project,'action':'create','name':'retired-policy','template_id':template,'compose':'services:\n  web:\n    image: nginx:1.30.6-alpine\n'});assert status==400 and'已从商店移除'in result['error']
  outcomes.append({'template':template,'Core_status':400,'Root_status':status,'Core_error':response['error'],'Root_error':result['error'],'Root_job_not_queued':job,'Root_project_not_created':project})
 for template in ['php-legacy-80-bullseye-compat2','php-legacy-81-bookworm-compat2']:
  # Incomplete requests must reach the ORIGINAL generic constraint, not the retired policy; no deployment is submitted.
  status,result=root({'job_id':secrets.token_hex(16),'project_id':secrets.token_hex(16),'action':'create','name':'php8-policy','template_id':template,'compose':'x'});assert status==400 and result['error']=='Compose 内容长度无效'
 after={'paths':paths(),'tables':tables(),'lifetimes':lifetimes()};save('original-after-admission',after);assert after==before
 save('actual-Core-and-Root-refusals',outcomes);assert len(outcomes)==20
 proof.update(ok=True,version=plan['version'],actual_installed_programme_entries=207,Core_retired_requests_refused=len(outcomes),Root_retired_requests_refused=len(outcomes),all_six_PHP8_apps_remain_supported=True,both_PHP8_isolated_current_templates_present=True,PHP8_Root_validation_reaches_unchanged_generic_constraints=True,original_job_project_app_site_and_runtime_records_unchanged=True,original_daemon_lifetimes_unchanged=True,original_queue_and_project_paths_unchanged=True,no_PHP_or_Docker_app_installation_performed=True)
except BaseException:
 import traceback
 proof['failure']=traceback.format_exc()
finally:
 if csrf:
  with contextlib.suppress(Exception):api('/logout',{})
 save('original-proof',proof)
sys.exit(0 if proof['ok']else 1)
