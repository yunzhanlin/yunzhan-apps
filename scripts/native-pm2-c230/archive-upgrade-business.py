"""Real PM2 public npm deployment and preservation on owned disposable native CI."""
import base64,contextlib,hashlib,http.cookiejar,json,os,platform,pwd,re,secrets,shlex,stat,subprocess,sys,tempfile,time,urllib.error,urllib.request
from pathlib import Path
os.umask(0o077)
assert os.geteuid()==0 and os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('GITHUB_REPOSITORY')=='yunzhanlin/yunzhan-apps'
evidence=Path(sys.argv[1]);phase=sys.argv[2];assert phase in ('phase1','phase2');out=evidence/('business-'+phase);out.mkdir(mode=0o700)
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
 slug='qa-c233-'+label+'-'+secrets.token_hex(3);row=job(label+'-site','/sites',{'name':'Owned PM2 C233 '+label,'slug':slug,'domain':slug+'.localhost','php_version_id':''});assert row['kind']=='create_site'and row['site_name']=='Owned PM2 C233 '+label;id=row['site_id'];assert re.fullmatch('[0-9a-f]{32}',id);put(id,'app.js',entry);return id

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
proof={'ok':False,'phase':phase,'architecture':arch,'Main_changed':False,'all40_commercial':False,'host_reboot_not_claimed':True}
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
try:
 login_once()
 if phase=='phase1':
  registry=api('/app-registry?refresh=1');assert registry['source']['resolved_commit']==plan['served_head']and len(registry['catalog']['apps'])==40 and not registry['source']['stale']
  item,=[a for a in registry['catalog']['apps']if a['id']=='pm2-manager'];assert item==plan['item']
  status,=[a for a in registry['status']if a['id']=='pm2-manager'];assert status['supported']and not status['installed']
  installed=job('original-signed11-install','/app-registry/pm2-manager/install',{'expected_version':item['version'],'expected_sha256':item['sha256']})
  state={'target':site('target'),'control':site('control'),'target_id':'c233-target-'+secrets.token_hex(3),'control_id':'c233-control-'+secrets.token_hex(3),'target_secret':secrets.token_hex(24),'control_secret':secrets.token_hex(24),'target_port':18330,'control_port':18331,'config_operation':secrets.token_hex(16),'cancel_operation':secrets.token_hex(16)}
  for name in ('target','control'):
   created=action('create',state[name+'_id'],{'site_id':state[name],'entry':'app.js','port':state[name+'_port'],'instances':1,'memory_mb':128,'environment_patch':{'C230_SECRET':state[name+'_secret']}});assert created['ok']and created['app']['revision']==1;ready(state[name+'_port'],state[name+'_secret'])
  pkg,lock=locked('original-public-number',{'is-number':'7.0.0'});files(state['target'],pkg,lock);deploy(state['target_id'],'original-public-number',1,terminal='succeeded');assert ready(18330,state['target_secret'])['dependency']
  updated=action('update',state['target_id'],{'expected_revision':1,'memory_mb':160,'pm2_operation_id':state['config_operation']});assert updated['ok']and json.loads(manifest(state['target_id']).read_bytes())['revision']==2;ready(18330,state['target_secret']);save('original-real-configuration-update',updated)
  canceled=action('cancel-configuration-request',state['target_id'],{'pm2_operation_id':state['cancel_operation'],'confirm':'CANCEL PM2 '+state['cancel_operation']});save('original-real-unpublished-request-cancellation',canceled)
  original=observations(state);assert original['target']['http']['uid']>0 and original['control']['http']['uid']>0
  journal=tree(root/'configuration-transactions');assert journal and any(k.startswith(state['config_operation']+'/')for k in journal)and any(k.startswith(state['cancel_operation']+'/')for k in journal)
  state.update(original=original,journal=journal,installed_job=installed['id'],original_boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip(),old_installed_record_sha256=digest(root/'installed.json'))
  save('retained-original-project-state',state)
  proof.update(ok=True,app_version='7.0.4-compat11',source_inputs_sha256=plan['source_inputs_sha256'],old_programme_normal_signed_install=True,old_app_normal_signed_install=True,two_real_nonroot_projects_running=True,real_public_npm_dependency=True,actual_config_commit_and_cancellation=True,original_active_records=2,projects_deliberately_retained_for_real_upgrade=True)
 else:
  assert len(sys.argv)==4
  state=json.loads((evidence/'business-phase1/retained-original-project-state.json').read_bytes());assert observations(state)==state['original']and tree(root/'configuration-transactions')==state['journal']
  inputs=Path(sys.argv[3]);assert inputs.resolve()==inputs and inputs.stat().st_uid==pwd.getpwnam('runner').pw_uid
  target=Path('/var/lib/c233-signed-upgrade-inputs-'+secrets.token_hex(16));target.mkdir(mode=0o700)
  archive_name='panel-'+upgrade['version']+'-linux-'+arch+'.tar.gz'
  for name in [archive_name+s for s in('','.manifest','.sig')]+['release-signing-dev.pub']:
   pin=upgrade['assets'][name];p=inputs/name;st=p.lstat();assert stat.S_ISREG(st.st_mode)and st.st_nlink==1 and st.st_uid==inputs.stat().st_uid and not st.st_mode&0o022 and st.st_size==pin['bytes']
   fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
   with os.fdopen(fd,'rb')as f:raw=f.read(pin['bytes']+1);assert os.fstat(f.fileno())==st
   assert len(raw)==pin['bytes']and hashlib.sha256(raw).hexdigest()==pin['sha256']
   with(target/name).open('xb')as f:f.write(raw);f.flush();os.fsync(f.fileno())
  verifier=Path(__file__).resolve().parent/'original-signed-release.py';assert digest(verifier)==upgrade['original_verifier_sha256'];(target/'verifier.py').write_bytes(verifier.read_bytes())
  signer=['/usr/bin/python3','-I','-B',str(target/'verifier.py')];args=signer+['install',str(target/archive_name),'--public-key',str(target/'release-signing-dev.pub')]
  def one(label,args,timeout=900):
   save(label+'-intent',{'args':args,'maximum_submissions':1})
   with(out/(label+'.stdout')).open('xb')as stdout,(out/(label+'.stderr')).open('xb')as stderr:r=subprocess.run(args,stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr,timeout=timeout,env={**os.environ,'APT_CONFIG':json.loads((evidence/'isolated-ubuntu-apt-config.json').read_bytes())['path']})
   save(label+'-outcome',{'exit':r.returncode,'stdout_sha256':digest(out/(label+'.stdout')),'stderr_sha256':digest(out/(label+'.stderr'))});assert r.returncode==0,('Original one submission failed',label)
  one('normal-signed-programme-upgrade-preflight',args+['--preflight-only'])
  one('normal-signed-programme-upgrade',args,1500)
  assert json.loads(Path('/opt/panel/current/SOURCE_INPUTS.json').read_bytes())['inputs_sha256']==upgrade['source_inputs_sha256']
  assert Path('/opt/panel/current').resolve()==Path('/opt/panel/releases')/upgrade['version']
  assert not Path('/opt/panel/DEVELOPMENT_RELEASE').exists()
  assert observations(state)==state['original']and tree(root/'configuration-transactions')==state['journal']and digest(root/'installed.json')==state['old_installed_record_sha256']
  save('real-programme-upgrade-original-projects-and-journal-preserved',{'ok':True,'observations':observations(state),'journal':tree(root/'configuration-transactions'),'source_inputs_sha256':upgrade['source_inputs_sha256']})
  # Candidate channel is promoted only by the coordinator after both encrypted
  # original old11 readiness proofs and the full publisher CI are qualified.
  observed=[];end=time.monotonic()+900
  while True:
   catalog=api('/app-registry?refresh=1');pm2,=[a for a in catalog['catalog']['apps']if a['id']=='pm2-manager'];observed.append({'commit':catalog['source']['resolved_commit'],'version':pm2['version'],'stale':catalog['source']['stale']})
   if pm2==upgrade['item']and not catalog['source']['stale']:break
   assert pm2==plan['item']and not catalog['source']['stale']and time.monotonic()<end,('Awaiting qualified channel promotion',observed)
   time.sleep(8)
  status,=[a for a in catalog['status']if a['id']=='pm2-manager'];assert status['installed']and status['installed_version']=='7.0.4-compat11'and status['update_available']and status['supported']
  save('real-signed-app-update-hint',{'observations':observed,'catalogue_item':pm2,'status':status})
  update=job('normal-signed-app12-update','/app-registry/pm2-manager/update',{'expected_version':pm2['version'],'expected_sha256':pm2['sha256']})
  assert observations(state)==state['original']and tree(root/'configuration-transactions')==state['journal']
  installed=json.loads((root/'installed.json').read_bytes());instance=installed['installation_id'];assert re.fullmatch('[a-f0-9]{32}',instance)and installed['version']=='7.0.4-compat12'
  detail=api('/app-modules/pm2-manager');assert detail['status']['installation_id']==instance;save('actual-installed12-instance',{'record':installed,'public_detail':detail,'job':update})
  url='/app-modules/pm2-manager/configuration-archives?pm2_installation_id='+instance+'&limit=32&offset=0'
  before=tree(root);page=api(url);save('real-active-journal-preview',page);assert page['archive_eligible']and page['active_record_count']==2 and page['total']==0 and page['active_pending_count']==0;assert tree(root)==before
  body={'pm2_installation_id':instance,'pm2_operation_id':secrets.token_hex(16),'expected_sha':page['inventory_sha256'],'confirm':'ARCHIVE PM2 CONFIGURATIONS '+page['inventory_sha256']}
  assert api('/app-modules/pm2-manager/archive-configurations',{**body,'pm2_installation_id':secrets.token_hex(16)},409)['error'];assert tree(root)==before
  archived=api('/app-modules/pm2-manager/archive-configurations',body);save('real-journal-archive',archived);assert archived['archive']['state']=='archived'and archived['archive']['record_count']==2
  generation=root/'configuration-archives/generations'/body['pm2_operation_id'];assert tree(generation)==state['journal']and not list((root/'configuration-transactions').iterdir())and observations(state)==state['original']
  stable=tree(root/'configuration-archives');duplicate=api('/app-modules/pm2-manager/archive-configurations',body);assert duplicate['duplicate_observation']and tree(root/'configuration-archives')==stable and observations(state)==state['original']
  # Original nonce remains selected from the archived original and cannot run again.
  original=old_configuration(state['config_operation']);save('real-selected-old-operation',original);assert original['archived_original']and original['configuration_transactions'][0]['pm2_operation_id']==state['config_operation']
  assert action('update',state['target_id'],{'expected_revision':2,'memory_mb':160,'pm2_operation_id':state['cancel_operation']},409)['error'];assert observations(state)==state['original']
  aid=body['pm2_operation_id'];records=api('/app-modules/pm2-manager/configuration-archives/'+aid+'/records?pm2_installation_id='+instance+'&limit=1&offset=0');assert records['total']==2 and len(records['configuration_transactions'])==1 and not records['page_complete'];save('real-archive-original-page1',records)
  second=api('/app-modules/pm2-manager/configuration-archives/'+aid+'/records?pm2_installation_id='+instance+'&limit=1&offset=1');assert second['page_complete']and second['configuration_transactions'][0]['pm2_operation_id']!=records['configuration_transactions'][0]['pm2_operation_id'];save('real-archive-original-page2',second)
  # An already terminal request never rewinds live journals or services.
  row=api(url)['configuration_archives'][0];restore={'pm2_installation_id':instance,'pm2_operation_id':aid,'expected_sha':row['expected_sha'],'confirm':'RESTORE PM2 CONFIG ARCHIVE '+aid};terminal=api('/app-modules/pm2-manager/restore-configuration-archive',restore);assert terminal['already_terminal']and tree(generation)==state['journal']and observations(state)==state['original'];save('real-terminal-restore-is-observation',terminal)
  # The former capacity is released by the actual archive. A new stopped
  # project revision can commit, while the independent control stays exact.
  control_before=observations(state)['control'];newop=secrets.token_hex(16);newsave=action('update',state['target_id'],{'expected_revision':2,'memory_mb':192,'pm2_operation_id':newop});assert newsave['ok']and json.loads(manifest(state['target_id']).read_bytes())['revision']==3;ready(18330,state['target_secret']);assert observations(state)['control']==control_before
  assert tree(generation)==state['journal'];save('real-new-config-after-complete-archive',newsave)
  # Actual service cold restart of panel/executor, with PM2 workers left alive.
  aftersave=observations(state);all_before=tree(root);one('actual-panel-executor-service-cold-restart',['/usr/bin/systemctl','restart','panel-executor.service','panel.service'],120)
  wait(lambda:subprocess.run(['/usr/bin/systemctl','is-active','--quiet','panel.service','panel-executor.service']).returncode,lambda x:x==0,45)
  assert observations(state)==aftersave and tree(root)==all_before
  login_once();cold=api(url);assert cold['total']==1 and cold['active_record_count']==1;old=old_configuration(state['config_operation']);assert old['archived_original']and old['configuration_transactions'][0]['state']=='committed';save('real-cold-daemon-restart-old-journal-readable',{'archive_page':cold,'old_selected':old,'original_projects_preserved':True})
  final=api('/app-registry');status,=[a for a in final['status']if a['id']=='pm2-manager'];assert status['installed_version']=='7.0.4-compat12'and not status['update_available'];assert Path('/proc/sys/kernel/random/boot_id').read_text().strip()==state['original_boot']
  proof.update(ok=True,source_inputs_sha256=upgrade['source_inputs_sha256'],app_version='7.0.4-compat12',normal_signed_programme_upgrade=True,original_running_PM2_lifetimes_manifests_and_journal_preserved_through_both_upgrades=True,actual_store_update_hint_and_job=True,instance_bound_archive_and_wrong_instance_refusal=True,complete_original_journal_moved_with_original_inodes=True,bounded_original_pagination=True,archived_operation_nonce_remains_consumed=True,duplicate_archive_and_terminal_restore_do_not_replay=True,new_real_configuration_after_archive=True,actual_daemon_cold_restart_old_history_readable=True,Root_recorded_GIDs_preserved=True,independent_control_lifetime_and_data_preserved=True,actual_full_power_loss_not_claimed=True,commercial_matrix_not_claimed=True)
except BaseException:
 import traceback
 proof['failure']=traceback.format_exc()
finally:
 with(out/'original-proof.json').open('x')as f:json.dump(proof,f,indent=2);f.write('\n')
 print(json.dumps({k:v for k,v in proof.items()if k!='failure'}),flush=True)
sys.exit(0 if proof['ok']else 1)
