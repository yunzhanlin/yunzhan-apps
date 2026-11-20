"""Real PM2 public npm deployment and preservation on owned disposable native CI."""
import base64,contextlib,hashlib,http.cookiejar,json,os,platform,pwd,re,secrets,shlex,stat,subprocess,sys,tempfile,time,urllib.error,urllib.request
from pathlib import Path
os.umask(0o077)
assert os.geteuid()==0 and os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('GITHUB_REPOSITORY')=='yunzhanlin/yunzhan-apps'
evidence=Path(sys.argv[1]);assert len(sys.argv)==2;phase='phase3';out=evidence/'business-phase3';out.mkdir(mode=0o700)
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
def login_once():
 global csrf
 first=json.loads(Path('/etc/panel/first-login.json').read_bytes());csrf=api('/login',{k:first[k]for k in('username','password')})['csrf'];first.clear()
def observations(state):
 v={}
 for name in ('target','control'):
  id=state[name+'_id'];sid=state[name];port=state[name+'_port'];secret=state[name+'_secret'];m=manifest(id);st=m.lstat()
  v[name]={'service':identity(id),'manifest_sha256':digest(m),'manifest_identity':[st.st_dev,st.st_ino,st.st_uid,st.st_gid,stat.S_IMODE(st.st_mode)],'http':ready(port,secret),'app_sha256':digest(Path('/srv/panel/sites')/sid/'public/app.js')}
 return v
def tree(path):
 result={}
 for p in sorted(path.rglob('*')):
  st=p.lstat();assert not stat.S_ISLNK(st.st_mode)and st.st_uid==0
  result[str(p.relative_to(path))]={'type':'dir'if stat.S_ISDIR(st.st_mode)else'file','uid':st.st_uid,'gid':st.st_gid,'mode':stat.S_IMODE(st.st_mode),'inode':st.st_ino,'dev':st.st_dev,'sha256':digest(p)if p.is_file()else None}
 return result
def old_configuration(operation):return api('/app-modules/pm2-manager/configuration?pm2_operation_id='+operation+'&limit=128&offset=0')
import signal,concurrent.futures
proof={'ok':False,'phase':'phase3','architecture':arch,'source_inputs_sha256':plan['source_inputs_sha256'],'Main_changed':False,'all40_commercial':False,'scope':'Actual signed installed daemon interrupted at a real archive rename boundary; no production hooks, copied records or forged outcomes','host_powerloss_not_claimed':True}
tracer=None
try:
 assert str(evidence).startswith('/home/runner/work/_temp/')and evidence.resolve()==evidence
 assert Path('/etc/panel-release').is_file()and not Path('/opt/panel/DEVELOPMENT_RELEASE').exists()
 assert pwd.getpwnam('runner').pw_uid>0 and evidence.stat().st_uid==pwd.getpwnam('runner').pw_uid
 assert json.loads((evidence/'business-phase2/original-proof.json').read_bytes())['ok']
 state=json.loads((evidence/'business-phase1/retained-original-project-state.json').read_bytes())
 assert state['target_id'].startswith('c234-target-')and state['control_id'].startswith('c234-control-')
 assert Path('/proc/sys/kernel/random/boot_id').read_text().strip()==state['original_boot']
 installed=json.loads((root/'installed.json').read_bytes());instance=installed['installation_id'];assert installed['version']=='7.0.4-compat12'and re.fullmatch('[a-f0-9]{32}',instance)
 login_once();url='/app-modules/pm2-manager/configuration-archives?pm2_installation_id='+instance+'&limit=32&offset=0'
 independent_control=observations(state)['control'];assert independent_control==state['original']['control']
 if not Path('/usr/bin/strace').exists():
  apt=json.loads((evidence/'isolated-ubuntu-apt-config.json').read_bytes())['path']
  with(out/'distribution-strace-install.stdout').open('xb')as stdout,(out/'distribution-strace-install.stderr').open('xb')as stderr:r=subprocess.run(['/usr/bin/apt-get','install','-y','--no-upgrade','--no-install-recommends','strace'],env={**os.environ,'APT_CONFIG':apt},stdout=stdout,stderr=stderr,timeout=300)
  save('distribution-strace-install-outcome',{'exit':r.returncode,'Main_changed':False});assert r.returncode==0
 st=Path('/usr/bin/strace').lstat();assert stat.S_ISREG(st.st_mode)and st.st_uid==0 and st.st_nlink==1 and not st.st_mode&0o022
 save('actual-distribution-instrumentation',{'strace_sha256':digest(Path('/usr/bin/strace')),'version':subprocess.check_output(['/usr/bin/strace','--version'],text=True,timeout=10),'dpkg':subprocess.check_output(['/usr/bin/dpkg-query','-W','strace'],text=True,timeout=10),'purpose':'Only syscall entry delays on the owned fresh QA executor, then actual process termination. No return values, payloads, service unit guards or product bytes are changed.'})
 expected_executor=digest(Path('/opt/panel/current/bin/panel-executor'));cases=[]
 def runtime_process(pid):
  p=Path('/proc')/str(pid);raw=(p/'stat').read_text();return{'pid':pid,'start':raw[raw.rfind(')')+2:].split()[19],'exe':str((p/'exe').resolve()),'exe_sha256':digest(p/'exe'),'boot':Path('/proc/sys/kernel/random/boot_id').read_text().strip()}
 def current_executor():return int(system('show','panel-executor.service','--property=MainPID','--value'))
 def original_archive_http(body):
  headers={'Origin':origin,'Content-Type':'application/json','X-CSRF-Token':csrf,'Idempotency-Key':secrets.token_hex(16)}
  try:
   with client.open(urllib.request.Request(origin+'/api/app-modules/pm2-manager/archive-configurations',json.dumps(body).encode(),headers),timeout=90)as r:return{'status':r.status,'raw':r.read(65536).decode()}
  except urllib.error.HTTPError as e:return{'status':e.code,'raw':e.read(65536).decode()}
  except (OSError,urllib.error.URLError)as e:return{'status':None,'connection_error':str(e)}
 for index,(label,after_move,recovery_action)in enumerate([('intent-before-move-forward',False,'recover-configuration-archive'),('old-moved-forward',True,'recover-configuration-archive'),('old-moved-restore',True,'restore-configuration-archive')]):
  if index:
   revision=json.loads(manifest(state['target_id']).read_bytes())['revision'];op=secrets.token_hex(16)
   result=action('update',state['target_id'],{'expected_revision':revision,'memory_mb':160 if index==1 else 192,'pm2_operation_id':op});assert result['ok'];ready(state['target_port'],state['target_secret']);save(label+'-real-new-configuration',result)
  page=api(url);assert page['archive_eligible']and page['active_record_count']>=1 and page['active_pending_count']==0
  original_active=tree(root/'configuration-transactions');services_before=observations(state);assert services_before['control']==independent_control
  nonce=secrets.token_hex(16);body={'pm2_installation_id':instance,'pm2_operation_id':nonce,'expected_sha':page['inventory_sha256'],'confirm':'ARCHIVE PM2 CONFIGURATIONS '+page['inventory_sha256']}
  request=root/'configuration-archives/requests'/nonce;generation=root/'configuration-archives/generations'/nonce
  assert not request.exists()and not generation.exists()
  pid=current_executor();process=runtime_process(pid);assert pid>1 and process['exe_sha256']==expected_executor and process['exe']==str(Path('/opt/panel/current/bin/panel-executor').resolve())and process['boot']==state['original_boot']
  trace=out/(label+'-original-syscalls.txt');attach=out/(label+'-original-attach.stderr')
  trace_error=attach.open('xb');tracer=subprocess.Popen(['/usr/bin/strace','-f','-e','trace=renameat2','-e','inject=renameat2:delay_enter=2s','-p',str(pid),'-o',str(trace)],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=trace_error)
  def attached():
   if tracer.poll()is not None:raise AssertionError('Original owned tracer attach failed; private stderr retained')
   tids=list((Path('/proc')/str(pid)/'task').iterdir());return bool(tids)and all('TracerPid:\t'+str(tracer.pid)+'\n'in(t/'status').read_text()for t in tids)
  wait(attached,bool,10);assert runtime_process(pid)==process
  save(label+'-original-one-request-intent',{'body':body,'executor':process,'tracer_pid':tracer.pid,'maximum_submissions':1,'after_original_move':after_move,'recovery_direction':recovery_action})
  with concurrent.futures.ThreadPoolExecutor(max_workers=1)as pool:
   future=pool.submit(original_archive_http,body);limit=time.monotonic()+40
   while True:
    observed=request.is_dir()and(request/'intent.json').is_file()and not(request/'outcome.json').exists()
    if observed and (not after_move or generation.is_dir()and not(root/'configuration-transactions').exists()):break
    if future.done():raise AssertionError(('Original archive completed before chosen boundary; no replay',future.result()))
    assert time.monotonic()<limit,'Original requested boundary was not observed; never resubmit'
    time.sleep(.02)
   # The delay only widens the real kernel boundary. Termination itself is an
   # actual SIGKILL of this verified owned executor; no original record changes.
   assert runtime_process(pid)==process;os.kill(pid,signal.SIGKILL)
   result=future.result(timeout=95);save(label+'-original-interrupted-response',result);assert result['status']is None or not 200<=result['status']<300 or (json.loads(result['raw']).get('archive',{}).get('state')=='needs_attention'and json.loads(result['raw']).get('duplicate_observation')is True and json.loads(result['raw']).get('automatic_replay')is False)
  tracer.wait(timeout=15);trace_error.close();tracer=None
  assert(request/'intent.json').is_file()and not(request/'outcome.json').exists()
  if after_move:assert not(root/'configuration-transactions').exists()and tree(generation)==original_active
  else:assert not generation.exists()and tree(root/'configuration-transactions')==original_active
  save(label+'-original-kernel-boundary',{'original_process':process,'raw_intent_sha256':digest(request/'intent.json'),'after_move':after_move,'original_active_records':original_active,'new_outcome_absent':True,'actual_services':observations(state)})
  assert observations(state)==services_before
  def executor_restarted():
   try:
    new=current_executor();return new>1 and new!=pid and runtime_process(new)['exe_sha256']==expected_executor
   except FileNotFoundError:return False
  wait(executor_restarted,bool,60)
  reads=[]
  def pending_report():
   try:
    value=api(url);reads.append({'ok':True,'value':value});return value
   except (OSError,urllib.error.URLError,AssertionError)as e:reads.append({'error':str(e)});return None
  pending=wait(pending_report,lambda v:v is not None,60);save(label+'-original-post-restart-readonly',{'observations':reads,'new_executor':runtime_process(current_executor())})
  chosen,=[r for r in pending['configuration_archives']if r['pm2_operation_id']==nonce];assert chosen['state']=='needs_attention'and not chosen['restore_requested']and not(request/'outcome.json').exists()
  # Both separate reads must leave the pending original in place without replay.
  private_before=tree(root/'configuration-archives');again=api(url);assert tree(root/'configuration-archives')==private_before and observations(state)==services_before
  confirm=('RECOVER PM2 CONFIG ARCHIVE 'if recovery_action=='recover-configuration-archive'else'RESTORE PM2 CONFIG ARCHIVE ')+nonce
  recovered=api('/app-modules/pm2-manager/'+recovery_action,{'pm2_installation_id':instance,'pm2_operation_id':nonce,'expected_sha':chosen['expected_sha'],'confirm':confirm});save(label+'-original-explicit-recovery',recovered)
  final=recovered['archive'];assert final['pm2_operation_id']==nonce and final['state']==('archived'if recovery_action=='recover-configuration-archive'else'restored_for_review')
  if recovery_action=='recover-configuration-archive':assert tree(generation)==original_active and not list((root/'configuration-transactions').iterdir())
  else:
   assert tree(root/'configuration-transactions')==original_active and not generation.exists()
   restore=json.loads((request/'restore.json').read_bytes());assert restore['mode']=='restore_for_review'and restore['started_after_move']is True
  assert observations(state)==services_before and observations(state)['control']==independent_control
  cases.append({'label':label,'state':final['state'],'operation_id':nonce,'source_inputs_sha256':plan['source_inputs_sha256'],'old_executor_pid':pid,'new_executor_pid':current_executor(),'old_original_files_UID_GID_inodes_and_bytes_preserved':True,'independent_project_lifetimes_and_encrypted_manifests_preserved':True,'pending_GET_did_not_replay':True,'actual_process_exit_and_new_executor':True,'raw_interrupted_response_retained':True})
 save('all-original-live-interruption-cases',cases);assert len(cases)==3
 assert Path('/proc/sys/kernel/random/boot_id').read_text().strip()==state['original_boot']and json.loads(Path('/opt/panel/current/SOURCE_INPUTS.json').read_bytes())['inputs_sha256']==plan['source_inputs_sha256']
 proof.update(ok=True,app_version='7.0.4-compat12',cases=cases,actual_signed_normal_install=True,actual_live_intent_before_move_forward_recovery=True,actual_live_old_moved_forward_recovery=True,actual_live_old_moved_reverse_restores_original_directory=True,Root_recorded_GIDs_and_all_raw_originals_preserved=True,independent_running_projects_and_encrypted_manifests_preserved=True,product_source_or_runtime_fault_hooks_added=False,syscall_return_values_or_original_record_bytes_modified=False)
except BaseException:
 import traceback
 proof['failure']=traceback.format_exc()
finally:
 if tracer is not None:
  with contextlib.suppress(Exception):tracer.terminate();tracer.wait(timeout=10)
 with(out/'original-proof.json').open('x')as f:json.dump(proof,f,indent=2);f.write('\n')
 print(json.dumps({k:v for k,v in proof.items()if k not in('failure','cases')}),flush=True)
sys.exit(0 if proof['ok']else 1)
