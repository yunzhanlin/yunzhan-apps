"""Real PM2 public npm deployment and preservation on owned disposable native CI."""
import base64,contextlib,hashlib,http.cookiejar,json,os,platform,pwd,re,secrets,shlex,stat,subprocess,sys,tempfile,time,urllib.error,urllib.request
from pathlib import Path
os.umask(0o077)
assert os.geteuid()==0 and os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('GITHUB_REPOSITORY')=='yunzhanlin/yunzhan-apps'
evidence=Path(sys.argv[1]);out=evidence/'business-phase1';out.mkdir(mode=0o700)
plan=json.loads((Path(__file__).resolve().parent/'cohort.json').read_bytes());arch={'x86_64':'amd64','aarch64':'arm64'}[platform.machine()]
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
 slug='qa-c230-'+label+'-'+secrets.token_hex(3);row=job(label+'-site','/sites',{'name':'Owned PM2 C230 '+label,'slug':slug,'domain':slug+'.localhost','php_version_id':''});assert row['kind']=='create_site'and row['site_name']=='Owned PM2 C230 '+label;id=row['site_id'];assert re.fullmatch('[0-9a-f]{32}',id);put(id,'app.js',entry);return id

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
proof={'ok':False,'architecture':arch,'source_inputs_sha256':plan['source_inputs_sha256'],'Main_changed':False,'all40_commercial':False,'scope':'Actual current PM2 native public npm business and preservation; no blanket platform qualification'}
ids=[]
try:
 login=json.loads(Path('/etc/panel/first-login.json').read_bytes());csrf=api('/login',{k:login[k]for k in('username','password')})['csrf'];login.clear()
 registry=api('/app-registry?refresh=1');assert registry['source']['resolved_commit']==plan['served_head'] and not registry['source']['stale'] and len(registry['catalog']['apps'])==40
 item,=[a for a in registry['catalog']['apps']if a['id']=='pm2-manager'];assert item==plan['item']
 status,=[a for a in registry['status']if a['id']=='pm2-manager'];assert not status['installed']and status['supported']and status['state_known']
 installed=job('signed-pm2-install','/app-registry/pm2-manager/install',{'expected_version':item['version'],'expected_sha256':item['sha256']})
 target=site('target');control=site('control');target_id='c230-target-'+secrets.token_hex(3);control_id='c230-control-'+secrets.token_hex(3);secret=secrets.token_hex(24);control_secret=secrets.token_hex(24)
 for id,sid,port,value in[(target_id,target,18330,secret),(control_id,control,18331,control_secret)]:
  created=action('create',id,{'site_id':sid,'entry':'app.js','port':port,'instances':1,'memory_mb':128,'environment_patch':{'C230_SECRET':value}});assert created['ok']and created['app']['revision']==1;ids.append(id)
 first=ready(18330,secret);original=ready(18331,control_secret);save('actual-original-HTTP-before-checks',{'target':first,'control':original});assert first['uid']>0 and first['gid']>0 and original['uid']>0 and not first['dependency']
 control_identity=identity(control_id);control_manifest=digest(manifest(control_id));control_source=digest(Path('/srv/panel/sites')/control/'public/app.js')
 raw=manifest(target_id).read_text();assert secret not in raw and 'environment_cipher'in raw
 save('actual-nonroot-originals',{'target':first,'control':original,'control_service':control_identity,'control_manifest_sha256':control_manifest,'control_source_sha256':control_source,'secret_plaintext_absent_from_private_manifest':True})
 pkg,lock=locked('valid-number',{'is-number':'7.0.0'});files(target,pkg,lock)
 deployed=deploy(target_id,'valid-number',1,terminal='succeeded');actual=ready(18330,secret);assert actual['dependency']and actual['dependency_version']=='7.0.0'and actual['dependency_path']==str(Path('/srv/panel/sites')/target/'public/node_modules/is-number/index.js')
 modules=Path('/srv/panel/sites')/target/'public/node_modules';original_modules=inode(modules);module_hashes=snapshot_tree(modules);assert not(stage(target,deployed['id'])/'.c230-hook.json').exists()
 save('actual-public-package-deployed',{'http':actual,'node_modules_identity':original_modules,'files':module_hashes,'default_lifecycle_hook_absent':True})
 # A cryptographically malformed actual download must fail and leave the live directory and service unchanged.
 corrupt=json.loads(json.dumps(lock));corrupt['packages']['node_modules/is-number']['integrity']='sha512-'+base64.b64encode(bytes(64)).decode();files(target,pkg,corrupt)
 before_bad=identity(target_id);bad=deploy(target_id,'bad-integrity',1,terminal='failed');assert inode(modules)==original_modules and snapshot_tree(modules)==module_hashes and identity(target_id)==before_bad and ready(18330,secret)['dependency'];badlog=Path('/etc/panel/security-apps/modules/pm2-manager/deployments')/(bad['id']+'.npm.log');assert 'EINTEGRITY'in badlog.read_text()
 save('bad-integrity-preservation',{'job':bad,'service_unchanged':True,'original_modules_unchanged':True})
 # Install succeeds but candidate exits on a newly present package: restore exactly the old inode and data.
 odd_pkg,odd_lock=locked('startup-rollback',{'is-number':'7.0.0','is-odd':'3.0.1'});files(target,odd_pkg,odd_lock)
 failed=deploy(target_id,'startup-rollback',1,terminal='failed');assert inode(modules)==original_modules and snapshot_tree(modules)==module_hashes and ready(18330,secret)['dependency']
 save('actual-startup-failure-old-inode-restored',{'job':failed,'node_modules_identity':inode(modules),'original_file_hashes_retained':True,'old_http_restored':True})
 hook_pkg,hook_lock=locked('controlled-hook',{'is-number':'7.0.0'},True);files(target,hook_pkg,hook_lock)
 before_cancel=identity(target_id);queued=deploy(target_id,'controlled-hook',1,allow=True);hookfile=stage(target,queued['id'])/'.c230-hook.json'
 wait(lambda:hookfile.exists(),bool,90);hook=json.loads(hookfile.read_bytes());assert hook['uid']==actual['uid'] and hook['gid']==actual['gid'] and not hook['app_secret_present']
 running=action('deployment',target_id);assert running['deployment']['state']=='running' and identity(target_id)==before_cancel and inode(modules)==original_modules
 deployunit='panel-pm2-deploy@'+queued['id']+'.service';cg=system('show',deployunit,'--property=ControlGroup','--value');cgroup=Path('/sys/fs/cgroup')/cg.lstrip('/');limits={n:(cgroup/n).read_text().strip()for n in('memory.max','pids.max')};assert limits=={'memory.max':str(768<<20),'pids.max':'128'}
 assert action('dependencies',target_id,{'expected_revision':1},409)['error'];assert action('update',target_id,{'expected_revision':1,'instances':2,'pm2_operation_id':secrets.token_hex(16)},409)['error']
 assert action('deployment',target_id)['deployment']['id']==queued['id']
 cancelled=action('cancel-deployment',target_id);save('controlled-hook-real-cancel',{'hook':hook,'actual_kernel_limits':limits,'before':running,'cancel_result':cancelled});last=action('deployment',target_id)['deployment'];assert last['id']==queued['id']and last['state']=='failed'
 assert system('show',deployunit,'--property=ActiveState','--value')not in('active','activating','deactivating')and inode(modules)==original_modules and snapshot_tree(modules)==module_hashes and ready(18330,secret)['dependency']
 recovered=action('recover-deployment',target_id);save('cancelled-terminal-explicit-recovery',recovered);assert action('deployment',target_id)['deployment']['id']==queued['id']
 # Actual durable configuration update, cluster round-robin and encrypted write-only delta/deletion.
 newsecret=secrets.token_hex(24);updated=action('update',target_id,{'expected_revision':1,'instances':2,'memory_mb':128,'environment_patch':{'C230_SECRET':newsecret,'C230_EXTRA':'owned-value'},'pm2_operation_id':secrets.token_hex(16)});save('cluster-update-original',updated);assert json.loads(manifest(target_id).read_bytes())['revision']==2
 samples=[ready(18330,newsecret)for _ in range(16)];assert len({x['pid']for x in samples})==2 and {x['instance']for x in samples}=={'0','1'}and all(x['uid']==actual['uid']and x['extra_present']for x in samples)
 assert newsecret not in manifest(target_id).read_text()and 'owned-value'not in manifest(target_id).read_text()
 public=api('/app-modules/pm2-manager/projects?limit=32&offset=0');assert newsecret not in json.dumps(public)and 'owned-value'not in json.dumps(public)
 save('actual-multiworker-round-robin',{'samples':samples,'read_only_projects':public,'plaintext_absent':True})
 action('update',target_id,{'expected_revision':2,'environment_patch':{'C230_EXTRA':None},'pm2_operation_id':secrets.token_hex(16)});assert not ready(18330,newsecret)['extra_present'];assert json.loads(manifest(target_id).read_bytes())['revision']==3
 old_config=digest(manifest(target_id));put(target,'bad.js',"console.error('C230 bad entry');process.exit(44);\n")
 assert action('update',target_id,{'expected_revision':3,'entry':'bad.js','environment_patch':{'C230_SECRET':'owned-failed-secret'},'pm2_operation_id':secrets.token_hex(16)},409)['error'];assert digest(manifest(target_id))==old_config and ready(18330,newsecret)['dependency']
 save('actual-bad-entry-encrypted-config-rollback',{'manifest_sha256':old_config,'revision':3,'previous_secret_digest_restored':True})
 # Real entry and port revision, then a bounded memory-threshold restart on this owned worker.
 assert action('update',target_id,{'expected_revision':3,'port':18331,'pm2_operation_id':secrets.token_hex(16)},409)['error'];assert digest(manifest(target_id))==old_config
 memory_entry=entry.replace("let dep=false,odd=false;","let held;let dep=false,odd=false;").replace("http.createServer((req,res)=>{", "http.createServer((req,res)=>{if(req.url==='/memory'){held=Buffer.alloc(80*1024*1024,0x61);}").replace("uid:process.getuid(),", "source:'second-entry',rss:process.memoryUsage().rss,uid:process.getuid(),")
 put(target,'second.js',memory_entry)
 moved=action('update',target_id,{'expected_revision':3,'entry':'second.js','port':18332,'instances':1,'memory_mb':64,'pm2_operation_id':secrets.token_hex(16)});save('actual-entry-and-port-revision-update',moved)
 row=ready(18332,newsecret);assert row['source']=='second-entry'and json.loads(manifest(target_id).read_bytes())['revision']==4 and request_http(18330)is None
 group=system('show',unit(target_id),'--property=ControlGroup','--value');appcg=Path('/sys/fs/cgroup')/group.lstrip('/');assert(appcg/'memory.max').read_text().strip()==str(1<<30)
 def memory_events():return {k:int(v)for k,v in(line.split()for line in(appcg/'memory.events').read_text().splitlines())}
 before_events=memory_events();start_memory=time.monotonic();allocated=request_http(18332,'/memory');assert allocated and allocated['pid']==row['pid']and 64<<20<allocated['rss']<256<<20
 restarted=wait(lambda:request_http(18332),lambda v:v is not None and v['pid']!=row['pid']and v['source']=='second-entry'and v['secret_sha256']==hashlib.sha256(newsecret.encode()).hexdigest(),100)
 assert memory_events()['oom_kill']==before_events['oom_kill']and restarted['uid']==row['uid']and restarted['gid']==row['gid']and restarted['dependency']
 process_status=Path('/proc')/str(restarted['pid'])/'status';native_status={k:v.strip()for k,v in(line.split(':',1)for line in process_status.read_text().splitlines())};assert int(native_status['CapEff'],16)==0 and native_status['NoNewPrivs']=='1'
 observed=[]
 for _ in range(5):
  sample=ready(18332,newsecret);assert sample['pid']==restarted['pid']and sample['source']=='second-entry';observed.append(sample);time.sleep(3)
 save('actual-memory-threshold-restart',{'before':row,'actual_bounded_allocation':allocated,'after':restarted,'elapsed_seconds':time.monotonic()-start_memory,'configured_memory_threshold_MB':64,'bounded_buffer_bytes':80<<20,'kernel_total_hard_limit':1<<30,'kernel_oom_kill_unchanged':True,'native_process_status':{k:native_status[k]for k in('Uid','Gid','CapEff','NoNewPrivs')},'stable_after_restart_samples':observed})
 logs=action('logs',target_id);assert 'C230 owned HTTP ready'in logs['logs'];save('actual-owned-journal',logs)
 action('stop',target_id);assert system('show',unit(target_id),'--property=ActiveState','--value')=='inactive';action('start',target_id);ready(18332,newsecret);before_restart=identity(target_id);action('restart',target_id);ready(18332,newsecret);assert identity(target_id)!=before_restart
 latest_before=action('deployment',target_id)['deployment'];archive=action('archive-deployments',target_id);save('real-old-deployment-archive',archive);assert archive['archived']>=3 and archive['records_retained']and archive['dependency_directories_retained'];assert action('deployment',target_id)['deployment']==latest_before
 for id in(deployed['id'],bad['id'],failed['id'],queued['id']):assert stage(target,id).is_dir()
 assert identity(control_id)==control_identity and digest(manifest(control_id))==control_manifest and digest(Path('/srv/panel/sites')/control/'public/app.js')==control_source and ready(18331,control_secret)==original
 for id in ids:action('stop',id);action('delete',id);assert not manifest(id).exists()
 assert (Path('/srv/panel/sites')/target/'public/app.js').read_text()==entry and (Path('/srv/panel/sites')/control/'public/app.js').read_text()==entry
 final=api('/app-registry');last,=[a for a in final['status']if a['id']=='pm2-manager'];assert last['installed']and last['installed_version']==item['version']and not last['update_available']
 proof.update(ok=True,app_version=item['version'],installed_job=installed['id'],current_catalogue_head=plan['served_head'],actual_public_npm_sha512_install=True,default_hook_disabled=True,explicit_hook_exact_nonroot_UID_without_app_secret=True,actual_bad_integrity_preserves_old_service_and_inode=True,actual_startup_failure_restores_old_inode=True,actual_concurrent_refusal_and_cancel_recovery=True,actual_two_worker_round_robin=True,actual_encrypted_delta_deletion_and_bad_entry_rollback=True,actual_stop_start_restart_logs_and_archive=True,independent_project_lifetime_and_data_preserved=True,self_owned_project_records_removed_without_site_data_deletion=True,platform_matrix_complete=False,actual_entry_port_and_memory_threshold_restart=True,host_reboot_not_claimed=True)
except BaseException:
 import traceback
 proof['failure']=traceback.format_exc()
finally:
 # Read-only original diagnostics; do not mask a failed business operation with a cleanup retry.
 if ids:
  for id in ids:
   with contextlib.suppress(Exception):
    save(id+'-final-unit',{'show':system('show',unit(id),'--property=ActiveState,SubState,MainPID,Result,ExecMainStatus,InvocationID')})
    with(out/(id+'-original-journal.txt')).open('xb')as f:subprocess.run(['/usr/bin/journalctl','--no-pager','-b','-u',unit(id),'-n','160','-o','cat'],stdout=f,stderr=subprocess.STDOUT,timeout=15)
 with contextlib.suppress(Exception):
  records=Path('/etc/panel/security-apps/modules/pm2-manager/deployments')
  retained=out/'original-deployment-records';retained.mkdir(mode=0o700)
  for p in records.rglob('*'):
   if p.is_file()and not p.is_symlink()and p.suffix in('.json','.log'):
    assert p.stat().st_size<=3<<20
    dest=retained/p.relative_to(records);dest.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    with dest.open('xb')as f:f.write(p.read_bytes())
 if csrf:
  with contextlib.suppress(Exception):api('/logout',{})
 save('original-proof',proof)
sys.exit(0 if proof['ok']else 1)
