"""Actual account permission and durable lifecycle contract on owned signed CI hosts."""
import contextlib,hashlib,http.cookiejar,json,os,platform,re,secrets,sqlite3,subprocess,sys,time,traceback,urllib.error,urllib.request
from pathlib import Path
os.umask(0o077)
assert os.geteuid()==0 and os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('GITHUB_REPOSITORY')=='yunzhanlin/yunzhan-apps'
evidence=Path(sys.argv[1]).resolve(strict=True);out=evidence/'business-phase1';out.mkdir(mode=0o700)
plan=json.loads((Path(__file__).parent/'cohort.json').read_bytes());arch={'x86_64':'amd64','aarch64':'arm64'}[platform.machine()]
assert json.loads(Path('/opt/panel/current/SOURCE_INPUTS.json').read_bytes())['inputs_sha256']==plan['source_inputs_sha256']
origin='http://127.0.0.1:19100';module='/app-modules/user-manager';registry='/app-registry/user-manager'
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*args,**kwargs):raise AssertionError('Unexpected redirect')
class Client:
 def __init__(self):
  self.client=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect(),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()));self.csrf=''
 def api(self,path,data=None,expected=200,key=None,csrf=None):
  headers={'Origin':origin,'Content-Type':'application/json','X-CSRF-Token':self.csrf if csrf is None else csrf}
  if data is not None:headers['Idempotency-Key']=key or secrets.token_hex(16)
  req=urllib.request.Request(origin+'/api'+path,None if data is None else json.dumps(data).encode(),headers)
  try:
   with self.client.open(req,timeout=65)as response:
    raw=response.read(6<<20);assert response.status==expected,(path,response.status,expected);return json.loads(raw)
  except urllib.error.HTTPError as error:
   raw=error.read(65536)
   if error.code==503 and expected==200:raise
   assert error.code==expected,(path,error.code,expected,raw[:1000]);return json.loads(raw)
 def login(self,name,password):self.csrf=self.api('/login',{'username':name,'password':password})['csrf'];return self

def save(name,value):
 with(out/name).open('x')as stream:json.dump(value,stream,indent=2);stream.write('\n')
def ready():
 cutoff=time.monotonic()+60
 while time.monotonic()<cutoff:
  try:
   with urllib.request.urlopen(origin+'/api/ready',timeout=3)as response:
    if response.status==200:return
  except (OSError,urllib.error.URLError):pass
  time.sleep(.5)
 raise TimeoutError('Actual HTTP readiness not reached')
def wait(read,valid,limit=600):
 cutoff=time.monotonic()+limit
 while time.monotonic()<cutoff:
  value=read()
  if valid(value):return value
  time.sleep(1)
 raise TimeoutError('Actual original job did not settle')
def job(label,path,payload):
 save(label+'-original-request.json',{'path':path,'payload':payload,'maximum_submissions':1})
 submitted=admin.api(path,payload,202);jid=submitted['job_id'];assert re.fullmatch('[a-f0-9]{32}',jid)
 value=wait(lambda:admin.api('/jobs/'+jid),lambda v:v['state']in('succeeded','failed','needs_attention'))
 save(label+'-original-outcome.json',value);assert value['state']=='succeeded',label;return value
def catalog():
 for delay in(10,30,60,0):
  try:
   value=admin.api('/app-registry?refresh=1');assert not value['source']['stale'];assert value['catalog']==plan['catalogue'];assert value['host']=={'platform':'ubuntu-24.04','architecture':arch}
   item,=[x for x in value['catalog']['apps']if x['id']=='user-manager'];status,=[x for x in value['status']if x['id']=='user-manager'];assert item==plan['item']and status['supported']and status['state_known'];return item,status
  except urllib.error.HTTPError as e:
   if e.code!=503 or not delay:raise
   time.sleep(delay)
def account(name):
 report=admin.api(module+'/run',{});assert report['menu_catalog'];row,=[x for x in report['users']if x['username']==name];assert not({'password','password_hash'}&set(row));return row
def stable(row):return {k:v for k,v in row.items()if k!='sessions'}
def sql_snapshot():
 with contextlib.closing(sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True))as db:
  return {table:[[{'blob_hex':v.hex()}if isinstance(v,bytes)else v for v in row]for row in db.execute('SELECT * FROM '+table+' ORDER BY 1')]for table in('users','app_user_roles','app_user_menus','app_user_request_receipts')}
def success_count():
 with contextlib.closing(sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True))as db:
  return db.execute("SELECT count(*) FROM app_module_events WHERE module_id='user-manager' AND outcome='succeeded'").fetchone()[0]
proof={'ok':False,'architecture':arch,'version':'1.3.2','source_inputs_sha256':plan['source_inputs_sha256'],'Main_changed':False,'all40_commercial':False}
try:
 ready();login=json.loads(Path('/etc/panel/first-login.json').read_bytes());admin=Client().login(login['username'],login['password']);seed=login['username']
 item,status=catalog();assert not status['installed'];payload={'expected_version':item['version'],'expected_sha256':item['sha256']};installation=job('normal-signed-install',registry+'/install',payload);assert admin.api(module)['status']['version']=='1.3.2';seedrow=account(seed);assert seedrow['full_admin']
 sites={};canaries={}
 for label in('allowed','other'):
  slug='c240-'+label;created=job('site-'+label,'/sites',{'name':slug,'slug':slug,'domain':slug+'.example.test'});sid=created['site_id'];sites[label]=sid
  path=Path('/srv/panel/sites')/sid/'public'/'c240-preserved.txt';raw=secrets.token_bytes(64);path.write_bytes(raw);canaries[str(path)]=hashlib.sha256(raw).hexdigest()
 username='c240-viewer';password=secrets.token_hex(24);grants=['overview','sites','files'];key=secrets.token_hex(16);create={'username':username,'password':password,'role':'viewer','site_ids':[sites['allowed']],'menu_ids':grants}
 before_count=success_count();response=admin.api(module+'/create',create,key=key);assert response=={'ok':True,'username':username,'action':'create'};original=account(username);assert original['revision']==1 and original['site_ids']==[sites['allowed']]
 assert admin.api(module+'/create',create,key=key)==response and account(username)==original and success_count()==before_count+1
 assert admin.api(module+'/create',{**create,'site_ids':[]},409,key=key)['error'];assert stable(account(username))==stable(original)
 viewer=Client().login(username,password);assert [x['id']for x in viewer.api('/sites')]==[sites['allowed']];viewer.api('/sites/'+sites['allowed']+'/files');viewer.api('/sites/'+sites['other']+'/files',expected=403)
 viewer.api('/sites/'+sites['allowed']+'/files/action',{'action':'create','path':'denied.txt','content':'denied'},403);viewer.api('/filesystem',expected=403)
 viewer.api('/app-registry/nginx-waf/install',{'expected_version':'2.5.2','expected_sha256':'0'*64},403);assert not(Path('/srv/panel/sites')/sites['allowed']/'public'/'denied.txt').exists()
 proof.update(real_multiuser_login_and_site_scope=True,viewer_file_reads_and_write_denial=True,direct_registry_install_denied_without_menu=True,original_request_exact_replay_single_business_event=True)
 # A limited administrator can neither manage the complete admin nor grant beyond its own menus.
 restricted_name='c240-limited-admin';restricted_password=secrets.token_hex(24);restricted_grants=['overview','panel-access']
 admin.api(module+'/create',{'username':restricted_name,'password':restricted_password,'role':'admin','site_ids':[],'menu_ids':restricted_grants})
 limited=Client().login(restricted_name,restricted_password);assert not account(restricted_name)['full_admin'];limited.api(module+'/run',{})
 seed_before=stable(account(seed));limited.api(module+'/update',{'username':seed,'role':'admin','site_ids':[],'menu_ids':restricted_grants,'expected_revision':seedrow['revision']},409)
 limited.api(module+'/create',{'username':'c240-denied-elevation','password':secrets.token_hex(24),'role':'admin','site_ids':[],'menu_ids':seedrow['menu_ids']},409)
 assert stable(account(seed))==seed_before and not any(x['username']=='c240-denied-elevation'for x in admin.api(module+'/run',{})['users'])
 limited.api('/sites',expected=403);limited.api('/security/firewall',expected=403);limited.api('/app-registry/nginx-waf/install',{},403)
 proof.update(restricted_admin_per_request_menu_ceiling=True,cannot_manage_or_grant_above_own_menus=True)
 # Menu changes revoke existing sessions and stale revisions cannot mutate anything.
 change={'username':username,'role':'viewer','site_ids':[sites['allowed']],'menu_ids':[],'expected_revision':original['revision']}
 admin.api(module+'/update',change);empty=account(username);assert empty['menu_ids']==[]and empty['revision']==2 and empty['sessions']==0
 viewer.api('/me',expected=401);admin.api(module+'/update',{**change,'site_ids':[sites['other']]},409);assert account(username)==empty
 empty_client=Client().login(username,password);assert empty_client.api('/me')['menu_ids']==[];assert empty_client.api('/account')['username']==username
 empty_client.api('/sites',expected=403);empty_client.api('/sites/'+sites['allowed']+'/files',expected=403);empty_client.api('/overview',expected=403)
 admin.api(module+'/update',{'username':username,'role':'viewer','site_ids':[sites['allowed']],'expected_revision':empty['revision']});narrow=account(username);assert narrow['menu_ids']==[]and narrow['revision']==3
 empty_client.api('/me',expected=401)
 proof.update(empty_menus_only_self_account_security=True,legacy_omitted_menu_preserves_narrow_grants=True,stale_revision_refused_without_change=True,menu_changes_revoke_previous_sessions=True)
 # The limited admin must not satisfy the last complete administrator protection.
 for action,body in [('delete',{'username':seed}),('update',{'username':seed,'role':'viewer','site_ids':[],'menu_ids':[],'expected_revision':seedrow['revision']}),('update',{'username':seed,'role':'admin','site_ids':[],'menu_ids':restricted_grants,'expected_revision':seedrow['revision']})]:
  assert admin.api(module+'/'+action,body,409)['error'];assert stable(account(seed))==seed_before
 proof['last_full_admin_delete_downgrade_and_menu_restriction_refused']=True
 # No request may replay through a bad CSRF or a different actor/payload.
 assert admin.api(module+'/create',create,403,key=key,csrf='wrong')['error']
 assert limited.api(module+'/create',create,409,key=key)['error']
 assert stable(account(username))==stable(narrow)
 proof['replay_rechecks_CSRF_actor_and_payload']=True
 # Actual password rotation and explicit session revocation, without changing website files.
 pass2=secrets.token_hex(24);admin.api(module+'/update',{'username':username,'password':pass2,'role':'viewer','site_ids':[sites['allowed']],'menu_ids':[],'expected_revision':narrow['revision']});rotated=account(username)
 active=Client().login(username,pass2);admin.api(module+'/revoke',{'username':username});active.api('/me',expected=401)
 proof['password_update_and_explicit_session_revocation']=True
 preserved=sql_snapshot();save('before-real-daemon-restart-accounts.json',preserved)
 subprocess.run(['/usr/bin/systemctl','restart','panel.service'],check=True,capture_output=True,timeout=60);ready();admin=Client().login(login['username'],login['password'])
 assert sql_snapshot()==preserved;assert stable(account(username))==stable(rotated);proof['actual_daemon_restart_preserves_accounts_revisions_and_receipts']=True
 # Normal application removal preserves core users, grants, original receipts and website data.
 job('normal-module-uninstall','/software/user-manager/uninstall',{});assert sql_snapshot()==preserved
 for name,h in canaries.items():assert hashlib.sha256(Path(name).read_bytes()).hexdigest()==h
 Client().login(username,pass2).api('/account');proof['normal_uninstall_preserves_accounts_scopes_receipts_and_files']=True
 item,status=catalog();assert not status['installed'];job('normal-signed-reinstall',registry+'/install',payload);assert sql_snapshot()==preserved
 count=success_count();assert admin.api(module+'/create',create,key=key)==response;assert sql_snapshot()==preserved and success_count()==count
 proof['completed_original_request_survives_uninstall_reinstall_without_reexecution']=True
 # A real account can be deleted with its session revoked; unrelated accounts/files persist.
 deletion='c240-disposable';delete_password=secrets.token_hex(24);admin.api(module+'/create',{'username':deletion,'password':delete_password,'role':'viewer','site_ids':[],'menu_ids':[]});deleted=Client().login(deletion,delete_password)
 admin.api(module+'/delete',{'username':deletion});deleted.api('/me',expected=401);assert not any(x['username']==deletion for x in admin.api(module+'/run',{})['users'])
 assert stable(account(username))==stable(rotated)and stable(account(seed))==seed_before
 for name,h in canaries.items():assert hashlib.sha256(Path(name).read_bytes()).hexdigest()==h
 save('final-real-account-report.json',admin.api(module+'/run',{}));proof.update(ok=True,actual_create_password_update_revoke_and_delete=True,signed_install_job=installation['id'],manifest_sha256=item['sha256'],user_site_files_retained=True,SQL_writes_by_fixture=0)
except BaseException:proof['failure']=traceback.format_exc()
finally:save('original-proof.json',proof)
sys.exit(0 if proof['ok']else 1)
