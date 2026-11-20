"""Real PM2 public npm deployment and preservation on owned disposable native CI."""
import base64,contextlib,hashlib,http.cookiejar,json,os,platform,pwd,re,secrets,shlex,stat,subprocess,sys,tempfile,time,urllib.error,urllib.request
from pathlib import Path
os.umask(0o077)
assert os.geteuid()==0 and os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('GITHUB_REPOSITORY')=='yunzhanlin/yunzhan-apps'
evidence=Path(sys.argv[1]);phase='phase1';assert len(sys.argv)==2;out=evidence/('business-'+phase);out.mkdir(mode=0o700)
plan=json.loads((Path(__file__).resolve().parent/'cohort.json').read_bytes());arch={'x86_64':'amd64','aarch64':'arm64'}[platform.machine()]
upgrade=json.loads((Path(__file__).resolve().parent/'upgrade.json').read_bytes())
assert json.loads(Path('/opt/panel/current/SOURCE_INPUTS.json').read_bytes())['inputs_sha256']==plan['source_inputs_sha256']
origin='http://127.0.0.1:19100';csrf=''
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*args,**kwargs):raise AssertionError('Unexpected local redirect')
client=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect(),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
local=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
def save(name,value):
 with(out/(name+'.json')).open('x')as f:json.dump(value,f,indent=2);f.write('\n')
def api(path,data=None,expected=200,method=None):
 headers={'Origin':origin,'Content-Type':'application/json','X-CSRF-Token':csrf}
 if data is not None:headers['Idempotency-Key']=secrets.token_hex(16)
 try:
  with client.open(urllib.request.Request(origin+'/api'+path,None if data is None else json.dumps(data).encode(),headers,method=method),timeout=85)as r:
   assert r.status==expected,(path,r.status,expected);raw=r.read(8<<20);return json.loads(raw)if raw else{}
 except urllib.error.HTTPError as e:
  raw=e.read(8192)
  if e.code!=expected:raise AssertionError((path,e.code,expected,raw.decode(errors='replace')))from e
  return json.loads(raw)
def wait(read,valid,limit=90):
 end=time.monotonic()+limit;last=None
 while time.monotonic()<end:
  last=read()
  if valid(last):return last
  time.sleep(1)
 raise TimeoutError(('Actual native result did not settle',last))
def job(label,route,payload):
 answer=api(route,payload,202);id=answer['job_id'];assert re.fullmatch('[a-f0-9]{32}',id)
 row=wait(lambda:api('/jobs/'+id),lambda x:x['state']in('succeeded','failed','needs_attention'),2400);save(label+'-job',row);assert row['state']=='succeeded',(label,row);return row
base='/api/app-modules/pm2-manager/'
def action(name,id,extra=None,expected=200):return api(base.removeprefix('/api')+name,dict(resource_id=id,**(extra or{})),expected)
def request_http(port,path="/"):
 try:
  with local.open('http://127.0.0.1:'+str(port)+path,timeout=3)as r:
   assert r.status==200;return json.loads(r.read(16384))
 except (OSError,urllib.error.URLError):return None
def ready(port,secret):return wait(lambda:request_http(port),lambda v:v is not None and v['secret_sha256']==hashlib.sha256(secret.encode()).hexdigest(),60)
def unit(id):return 'panel-pm2@'+id+'.service'
def system(*args):return subprocess.check_output(['/usr/bin/systemctl',*args],text=True,timeout=25).strip()
def identity(id):return system('show',unit(id),'--property=MainPID,InvocationID,ExecMainStartTimestampMonotonic,ActiveState,UnitFileState')
def manifest(id):return Path('/etc/panel/security-apps/modules/pm2-manager/apps')/(id+'.json')
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def inode(p):
 s=p.lstat();assert stat.S_ISDIR(s.st_mode);return [s.st_dev,s.st_ino,s.st_uid,s.st_gid]
def put(site,name,text):
 p=Path('/srv/panel/sites')/site/'public'/name
 payload={'path':name,'content':text,'action':'save'if p.exists()else'create'}
 if p.exists():payload['expected_sha256']=digest(p)
 answer=api('/sites/'+site+'/files/action',payload);assert answer['path']==name and p.read_text()==text;return p
entry="""const http=require('http'),crypto=require('crypto');
let dep=false,depPath=null,depVersion=null,odd=false;try{depPath=require.resolve('./node_modules/is-number');dep=require(depPath)(42);depVersion=require('./node_modules/is-number/package.json').version}catch{}try{require.resolve('./node_modules/is-odd');odd=true}catch{}
if(odd){console.error('C230 owned candidate dependency startup failure');process.exit(43)}
http.createServer((req,res)=>{res.setHeader('Content-Type','application/json');res.end(JSON.stringify({uid:process.getuid(),gid:process.getgid(),pid:process.pid,instance:process.env.NODE_APP_INSTANCE,dependency:dep,dependency_path:depPath,dependency_version:depVersion,secret_sha256:crypto.createHash('sha256').update(process.env.C230_SECRET||'').digest('hex'),extra_present:process.env.C230_EXTRA!==undefined}));}).listen(Number(process.env.PORT),'127.0.0.1',()=>console.log('C230 owned HTTP ready'));
"""
def site(label):
 slug='qa-c234-'+label+'-'+secrets.token_hex(3);row=job(label+'-site','/sites',{'name':'Owned PM2 C234 '+label,'slug':slug,'domain':slug+'.localhost','php_version_id':''});assert row['kind']=='create_site'and row['site_name']=='Owned PM2 C234 '+label;id=row['site_id'];assert re.fullmatch('[0-9a-f]{32}',id);put(id,'app.js',entry);return id

def locked(label,dependencies,hook=False):
 # Only the non-root hosted runner prepares a lock; the panel itself performs the actual install as the website UID.
 runner=pwd.getpwnam('runner');tmp=Path(tempfile.mkdtemp(prefix='c230-lock-',dir='/tmp'));os.chown(tmp,runner.pw_uid,runner.pw_gid)
 pkg={'name':'c230-owned-fixture','version':'1.0.0','private':True,'dependencies':dependencies}
 hookjs="require('fs').writeFileSync('.c230-hook.json',JSON.stringify({uid:process.getuid(),gid:process.getgid(),app_secret_present:process.env.C230_SECRET!==undefined}));"+('setTimeout(()=>{},30000);'if hook else'')
 pkg['scripts']={'postinstall':'node -e '+shlex.quote(hookjs)}
 p=tmp/'package.json';p.write_text(json.dumps(pkg));os.chown(p,runner.pw_uid,runner.pw_gid)
 args=['/usr/bin/npm','install','--package-lock-only','--ignore-scripts','--no-audit','--no-fund','--userconfig=/dev/null','--registry=https://registry.npmjs.org/','--fetch-timeout=20000','--fetch-retries=1']
 with(out/(label+'-lock.stdout')).open('xb')as stdout,(out/(label+'-lock.stderr')).open('xb')as stderr:
  r=subprocess.run(args,cwd=tmp,env={'PATH':'/usr/bin:/bin','HOME':str(tmp),'LANG':'C.UTF-8'},user=runner.pw_uid,group=runner.pw_gid,extra_groups=[],stdout=stdout,stderr=stderr,timeout=180)
 save(label+'-lock-outcome',{'exit':r.returncode,'uid':runner.pw_uid});assert r.returncode==0
 lock=json.loads((tmp/'package-lock.json').read_bytes())
 assert lock['lockfileVersion']in(2,3)
 for name,item in lock['packages'].items():
  if name:assert item['resolved'].startswith('https://registry.npmjs.org/') and item['resolved'].endswith('.tgz') and len(base64.b64decode(item['integrity'].removeprefix('sha512-'),validate=True))==64
 save(label+'-original-public-lock',lock);return pkg,lock

def files(site,pkg,lock):put(site,'package.json',json.dumps(pkg));put(site,'package-lock.json',json.dumps(lock))
def deploy(id,label,revision,allow=False,terminal=None):
 answer=action('dependencies',id,{'expected_revision':revision,'allow_install_scripts':allow});job=answer['deployment'];save(label+'-queued',job)
 assert re.fullmatch('[a-f0-9]{32}',job['id'])
 if terminal is None:return job
 row=wait(lambda:action('deployment',id),lambda x:x['deployment']['state']in('succeeded','failed','needs_attention'),660);save(label+'-original-terminal',row);assert row['deployment']['id']==job['id'] and row['deployment']['state']==terminal;return row['deployment']
def stage(site,id):return Path('/srv/panel/sites')/site/'private'/('pm2-deploy-'+id)
def snapshot_tree(root):
 return {str(p.relative_to(root)):digest(p)for p in root.rglob('*')if p.is_file()and not p.is_symlink()and '.cache'not in p.parts}
root=Path('/etc/panel/security-apps/modules/pm2-manager')
proof={'ok':False,'architecture':arch,'Main_changed':False,'all40_commercial':False,'source_inputs_sha256':plan['source_inputs_sha256'],'version':'1.3.2'}
ids=[];unmanaged=None
try:
 first=json.loads(Path('/etc/panel/first-login.json').read_bytes());csrf=api('/login',{k:first[k]for k in('username','password')})['csrf'];first.clear()
 registry=api('/app-registry?refresh=1');assert not registry['source']['stale']and registry['catalog']==plan['catalogue']
 task_item,=[x for x in registry['catalog']['apps']if x['id']=='task-manager'];pm2_item,=[x for x in registry['catalog']['apps']if x['id']=='pm2-manager'];assert task_item==plan['item']
 for item in(task_item,pm2_item):job('signed-install-'+item['id'],'/app-registry/'+item['id']+'/install',{'expected_version':item['version'],'expected_sha256':item['sha256']})
 assert api('/app-modules/task-manager')['status']['version']=='1.3.2'
 sid=site('task-owned');id='c244-task-'+secrets.token_hex(3);secret=secrets.token_hex(24);ids.append(id)
 action('create',id,{'site_id':sid,'entry':'app.js','port':18330,'instances':1,'memory_mb':128,'environment_patch':{'C230_SECRET':secret}});http=ready(18330,secret);pid=http['pid'];assert http['uid']>0 and http['gid']>0
 canary=Path('/srv/panel/sites')/sid/'public/app.js';source_hash=digest(canary);config_hash=digest(manifest(id));original_service=identity(id)
 def sample():
  report=api('/app-modules/task-manager/run',{});assert 0<len(report['processes'])<=500;return report
 def selected(number):
  row,=[x for x in sample()['processes']if x['pid']==number];return row
 row=selected(pid);assert row['can_terminate']and row['managed']and row['memory']>0 and row['start_time']>0;assert isinstance(row['cpu_available'],bool)and isinstance(row['io_available'],bool)
 actual_start=int((Path('/proc')/str(pid)/'stat').read_text().rsplit(')',1)[1].split()[19]);assert row['start_time']==actual_start
 save('real-owned-process-original',{'row':row,'http':http,'service':original_service,'actual_proc_start':actual_start})
 # Every refused request targets only a process created by this disposable fixture or its own root interpreter.
 before=ready(18330,secret);assert api('/app-modules/task-manager/terminate',{'pid':pid,'start_time':row['start_time']+1},409)['error'];assert ready(18330,secret)==before
 old_csrf=csrf;csrf='invalid-owned-csrf';assert api('/app-modules/task-manager/terminate',{'pid':pid,'start_time':row['start_time']},403)['error'];csrf=old_csrf;assert ready(18330,secret)==before
 assert api('/app-modules/task-manager/terminate',{'pid':1,'start_time':1},409)['error'];rootpid=os.getpid();root_start=int((Path('/proc')/str(rootpid)/'stat').read_text().rsplit(')',1)[1].split()[19]);assert api('/app-modules/task-manager/terminate',{'pid':rootpid,'start_time':root_start},409)['error'];assert Path('/proc/'+str(rootpid)).exists()
 unmanaged=subprocess.Popen(['/usr/bin/sleep','180'],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,user=http['uid'],group=http['gid'],extra_groups=[])
 unmanaged_start=int((Path('/proc')/str(unmanaged.pid)/'stat').read_text().rsplit(')',1)[1].split()[19]);assert api('/app-modules/task-manager/terminate',{'pid':unmanaged.pid,'start_time':unmanaged_start},409)['error'];assert unmanaged.poll()is None
 proof['PID1_root_unmanaged_stale_identity_and_bad_CSRF_refused']=True
 # Exactly one valid signal request. The signed handler reports acceptance, never verified exit.
 save('one-owned-signal-intent',{'pid':pid,'start_time':row['start_time'],'maximum_valid_submissions':1,'owned_PM2_child_only':True})
 signalled=api('/app-modules/task-manager/terminate',{'pid':pid,'start_time':row['start_time']});assert signalled=={'signal':'SIGTERM','pid':pid,'signal_accepted':True,'exit_verified':False};save('one-owned-signal-original-outcome',signalled)
 current=wait(lambda:request_http(18330),lambda v:v is not None and v['pid']!=pid,35);assert not Path('/proc/'+str(pid)).exists()and current['uid']==http['uid']and current['secret_sha256']==http['secret_sha256'];assert identity(id)==original_service and digest(manifest(id))==config_hash
 assert api('/app-modules/task-manager/terminate',{'pid':pid,'start_time':row['start_time']},409)['error'];assert ready(18330,secret)==current
 samples=[]
 for _ in range(5):
  value=ready(18330,secret);assert value==current;samples.append(value);time.sleep(2)
 save('independent-original-exit-and-supervisor-recovery',{'old_pid':pid,'new_http':current,'samples':samples,'old_PID_absent':True,'separate_from_signal_acceptance_reply':True})
 proof.update(one_real_owned_pidfd_SIGTERM_accepted=True,independent_actual_old_exit_and_PM2_recovery=True,old_identity_refused_after_exit_without_new_signal=True,actual_nonroot_process_memory_CPU_IO_availability=True)
 inventories={}
 for view in('services','startup','sysv-startup','network','accounts','cron','ssh'):
  value=api('/app-modules/task-manager/inventory/'+view);assert value['view']==view and isinstance(value['available'],bool)and isinstance(value['partial'],bool)and len(value['rows'])<=256;save('actual-inventory-'+view,value);inventories[view]={'available':value['available'],'partial':value['partial'],'rows':len(value['rows'])}
 assert any(x['name']=='panel.service'and x['active_state']=='active'for x in api('/app-modules/task-manager/inventory/services')['rows'])
 assert any(x['name']=='root'and x['uid']=='0'for x in api('/app-modules/task-manager/inventory/accounts')['rows'])
 proof['actual_readonly_system_inventories']=inventories
 install=root.parent/'task-manager/installed.json';original_install=install.read_bytes();task_root=install.parent
 def retained():return{str(p.relative_to(task_root)):digest(p)for p in task_root.rglob('*')if p.is_file()and p.name!='installed.json'}
 files_before=retained();source_before=digest(canary);m_before=digest(manifest(id));life_before=identity(id)
 job('task-normal-uninstall','/software/task-manager/uninstall',{});assert not install.exists()and retained()==files_before and digest(canary)==source_before and digest(manifest(id))==m_before and identity(id)==life_before and ready(18330,secret)==current
 assert api('/app-modules/task-manager/inventory/services',expected=409)['error']
 job('task-normal-signed-reinstall','/app-registry/task-manager/install',{'expected_version':task_item['version'],'expected_sha256':task_item['sha256']});assert retained()==files_before and digest(canary)==source_before and identity(id)==life_before and ready(18330,secret)==current
 proof['normal_task_uninstall_reinstall_preserves_reports_sites_and_processes']=True
 subprocess.run(['/usr/bin/systemctl','restart','panel.service'],check=True,capture_output=True,timeout=50)
 end=time.monotonic()+60
 while True:
  try:
   with local.open(origin+'/api/ready',timeout=3)as response:
    if response.status==200:break
  except (OSError,urllib.error.URLError):pass
  assert time.monotonic()<end;time.sleep(.5)
 assert retained()==files_before and identity(id)==life_before;assert ready(18330,secret)==current
 first=json.loads(Path('/etc/panel/first-login.json').read_bytes());csrf=api('/login',{k:first[k]for k in('username','password')})['csrf'];first.clear();assert selected(current['pid'])['can_terminate'];proof['actual_daemon_cold_restart_preserves_process_identity_and_reports']=True
 # A live project prevents PM2 removal; after explicitly removing only this owned project, files and records remain.
 request=api('/software/pm2-manager/uninstall',{},202);failed=wait(lambda:api('/jobs/'+request['job_id']),lambda x:x['state']in('succeeded','failed','needs_attention'),120);save('live_PM2_reference_uninstall_refused',failed);assert failed['state']=='failed'and identity(id)==life_before and digest(manifest(id))==m_before
 action('stop',id);action('delete',id);assert not manifest(id).exists()and digest(canary)==source_hash
 before_pm2={str(p.relative_to(root)):digest(p)for p in root.rglob('*')if p.is_file()and p.name!='installed.json'}
 job('empty-PM2-normal-uninstall','/software/pm2-manager/uninstall',{});assert not(root/'installed.json').exists();assert{str(p.relative_to(root)):digest(p)for p in root.rglob('*')if p.is_file()and p.name!='installed.json'}==before_pm2 and digest(canary)==source_hash
 proof.update(ok=True,manifest_sha256=task_item['sha256'],normal_PM2_reference_guard_and_data_preserving_uninstall=True,SQL_writes_by_fixture=0)
except BaseException:
 import traceback
 proof['failure']=traceback.format_exc()
finally:
 if unmanaged is not None and unmanaged.poll()is None:unmanaged.terminate();unmanaged.wait(timeout=10)
 save('original-proof',proof)
sys.exit(0 if proof['ok']else 1)
