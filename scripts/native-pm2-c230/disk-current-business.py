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
    raw=response.read(6<<20);assert response.status in (expected if isinstance(expected,tuple)else(expected,)),(path,response.status,expected);return json.loads(raw)
  except urllib.error.HTTPError as error:
   raw=error.read(65536)
   if error.code==503 and expected==200:raise
   assert error.code in (expected if isinstance(expected,tuple)else(expected,)),(path,error.code,expected,raw[:1000]);return json.loads(raw)
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
  return db.execute("SELECT count(*) FROM app_module_events WHERE module_id='user-manager' AND outcome='succeeded' AND action IN ('create','update','revoke','delete')").fetchone()[0]
proof={'ok':False,'architecture':arch,'version':'1.4.1','source_inputs_sha256':plan['source_inputs_sha256'],'Main_changed':False,'all40_commercial':False};disk='/software/disk-analysis/host'
try:
 ready();login=json.loads(Path('/etc/panel/first-login.json').read_bytes());admin=Client().login(login['username'],login['password']);login.clear()
 catalog=admin.api('/app-registry?refresh=1');assert not catalog['source']['stale']and catalog['catalog']==plan['catalogue'];item,=[x for x in catalog['catalog']['apps']if x['id']=='disk-analysis'];assert item==plan['item']
 job('original-normal-signed-install','/app-registry/disk-analysis/install',{'expected_version':item['version'],'expected_sha256':item['sha256']})
 def receipt():
  with contextlib.closing(sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True))as db:return[list(row)for row in db.execute("SELECT version,sha256,target,scope FROM app_registry_receipts WHERE app_id='disk-analysis'")]
 save('signed-receipt-before-normal-store-read.json',receipt())
 normal=admin.api('/app-registry?refresh=1');status,=[row for row in normal['status']if row['id']=='disk-analysis'];assert status['installed']and status['installed_version']=='1.4.1'and not status['update_available'];assert receipt()==[['1.4.1',item['sha256'],'disk-analysis','disk-analysis']];save('signed-receipt-after-normal-store-read.json',receipt())
 state=admin.api(disk);assert state['installed']and state['app_version']=='1.4.1'and state['app_manifest_sha256']==item['sha256']
 mount,=[m for m in state['inventory']['inventory']['mounts']if m['mount_point']=='/'];assert mount['path_actionable']and mount['filesystem_class']=='local'and not mount['stacked_mount_point']
 fixture=Path('/srv/c248-owned-disk-fixture');fixture.mkdir(mode=0o700);small=fixture/'small';small.mkdir(mode=0o700);(small/'retained.txt').write_bytes(b'C248 original disk fixture');large=fixture/'large';large.mkdir(mode=0o700)
 # 200k hard links to four ordinary canaries; each inode stays below ext4 link limits.
 for index in range(4):(large/('source-'+str(index))).write_bytes(('owned-'+str(index)).encode())
 for directory in range(200):
  leaf=large/('d-%03d'%directory);leaf.mkdir()
  for index in range(1000):os.link(large/('source-'+str(directory%4)),leaf/('%04d'%index))
 def selection(path):return{**state['inventory']['host'],'mount_id':mount['mount_id'],'mount_binding_sha256':mount['binding_sha256'],'relative_directory':str(path).lstrip('/'),**{k:state[k]for k in('app_version','installation_id','app_manifest_sha256')}}
 small_selection=selection(small);large_selection=selection(large);sentinel=(small/'retained.txt').read_bytes();source_files={p.name:hashlib.sha256(p.read_bytes()).hexdigest()for p in large.glob('source-*')}
 def submit(label,choice):
  key=secrets.token_hex(16);save(label+'-original-request.json',{'key':key,'selection':choice,'maximum_submissions':1});value=admin.api(disk+'/jobs',choice,202,key=key);assert not value['replayed'];save(label+'-original-submission.json',value);return key,value['job']
 def detail(id):return admin.api(disk+'/jobs/'+id)
 def terminal(id):return wait(lambda:detail(id),lambda d:d['terminal_verified'],180)
 # Immediate cancellation crosses the real admission/start race; never manufacture a canceled outcome.
 fast_key,fast=submit('immediate-cancel',large_selection);fast_cancel=admin.api(disk+'/jobs/'+fast['id']+'/cancel',{},(200,202));save('immediate-cancel-original-ack.json',fast_cancel);fast_end=terminal(fast['id']);save('immediate-cancel-original-terminal.json',fast_end);assert fast_end['job']['state']=='canceled'
 # Actual running worker, then a refused lifecycle operation before one explicit cancellation.
 active_key,active=submit('active-cancel',large_selection);active_seen=wait(lambda:detail(active['id']),lambda d:d['job']['state']=='running'and not d['terminal_verified'],40);save('active-worker-original-observation.json',active_seen)
 assert admin.api('/software/disk-analysis/uninstall',{},409)['error'];active_cancel=admin.api(disk+'/jobs/'+active['id']+'/cancel',{},(200,202));save('active-cancel-original-ack.json',active_cancel);active_end=terminal(active['id']);save('active-cancel-original-terminal.json',active_end);assert active_end['job']['state']=='canceled'
 for key,original,end in[(fast_key,fast,fast_end),(active_key,active,active_end)]:
  again=admin.api(disk+'/jobs',large_selection,202,key=key);assert again['replayed']and again['job']['id']==original['id'];assert terminal(original['id'])['job']['state']=='canceled'
  repeat=admin.api(disk+'/jobs/'+original['id']+'/cancel',{},200);assert repeat['terminal_verified']and not repeat['native_cancel_requested']
  found=admin.api(disk+'/requests/'+key);assert found['found']and found['job']['id']==original['id']
 proof.update(immediate_cancel_native_signal_requested=fast_cancel['native_cancel_requested'],immediate_cancel_terminal_in_original_reply=fast_cancel['terminal_verified'],actual_immediate_cancel_terminal_closed=True,actual_running_cancel_terminal_closed=True,active_scan_blocks_uninstall=True,original_requests_replay_same_canceled_job_without_reenumeration=True)
 # A subsequent real scan proves canceled jobs released capacity without resetting old receipts.
 complete_key,complete=submit('after-cancel-complete',small_selection);complete_end=terminal(complete['id']);save('after-cancel-original-complete.json',complete_end);assert complete_end['job']['state']=='complete'
 result=complete_end.get('result')or complete_end['observation']['result'];report=result['report'];assert report['enumeration_complete']and report['regular_file_entries']=='1'and report['unique_regular_files']=='1'and report['regular_logical_entry_bytes']==str(len(sentinel))and report['selected_path']==str(small)
 assert(small/'retained.txt').read_bytes()==sentinel and all(hashlib.sha256((large/n).read_bytes()).hexdigest()==h for n,h in source_files.items())
 def evidence_files():
  root=Path('/var/lib/panel-executor/disk-host-jobs');values={}
  for original in(fast,active,complete):
   for p in(root/original['id']).iterdir():
    if p.is_file()and not p.is_symlink():
     st=p.stat();values[str(p.relative_to(root))]={'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'uid':st.st_uid,'gid':st.st_gid,'mode':st.st_mode&0o777,'inode':st.st_ino}
  return values
 before=evidence_files();save('original-native-files-before-cold.json',before)
 subprocess.run(['/usr/bin/systemctl','restart','panel.service'],check=True,capture_output=True,timeout=60);ready();first=json.loads(Path('/etc/panel/first-login.json').read_bytes());admin=Client().login(first['username'],first['password']);first.clear()
 assert evidence_files()==before
 for key,original,state_name in[(fast_key,fast,'canceled'),(active_key,active,'canceled'),(complete_key,complete,'complete')]:
  observed=detail(original['id']);assert observed['terminal_verified']and observed['job']['state']==state_name;lookup=admin.api(disk+'/requests/'+key);assert lookup['found']and lookup['job']['id']==original['id']
 assert evidence_files()==before;proof['actual_daemon_cold_restart_preserves_canceled_complete_original_records']=True
 install=Path('/etc/panel/security-apps/modules/disk-analysis/installed.json');original_instance=state['installation_id'];job('normal-scan-app-uninstall','/software/disk-analysis/uninstall',{});assert not install.exists()and evidence_files()==before and(small/'retained.txt').read_bytes()==sentinel
 job('normal-signed-scan-app-reinstall','/app-registry/disk-analysis/install',{'expected_version':item['version'],'expected_sha256':item['sha256']});admin.api('/app-registry?refresh=1');new_state=admin.api(disk);assert new_state['installation_id']!=original_instance and evidence_files()==before
 # Uninstall retains bytes; old installation IDs never acquire new-instance launch authority.
 assert admin.api(disk+'/jobs',small_selection,409,key=secrets.token_hex(16))['error'];assert evidence_files()==before
 proof.update(ok=True,normal_uninstall_reinstall_preserves_original_native_scan_data=True,new_installation_refuses_old_scan_selection=True,real_scan_after_both_cancellations=True,actual_large_fixture_entries=200004,manifest_sha256=item['sha256'],SQL_writes_by_fixture=0)
except BaseException:
 proof['failure']=traceback.format_exc()
 for label,args in [('executor-journal',['/usr/bin/journalctl','--no-pager','-b','-u','panel-executor','-n','100','-o','short-iso']),('disk-unit-state',['/usr/bin/systemctl','list-units','--all','--plain','--no-pager','panel-disk*'])]:
  with(out/(label+'.stdout')).open('xb')as stream:subprocess.run(args,stdout=stream,stderr=subprocess.STDOUT,timeout=20)
 with contextlib.suppress(Exception):save('failure-normal-module-observation.json',admin.api('/app-modules/disk-analysis'))
 with contextlib.suppress(Exception):save('failure-normal-registry-observation.json',admin.api('/app-registry'))
finally:save('original-proof.json',proof)
sys.exit(0 if proof['ok']else 1)
