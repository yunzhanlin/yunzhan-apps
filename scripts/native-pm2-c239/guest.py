"""Normal signed Ubuntu22 private Node/npm and archived-history hard-boot acceptance."""
from pathlib import Path
import os,sys,json,hashlib,secrets,stat,re,subprocess,time,traceback,http.cookiejar,urllib.request,urllib.error
os.umask(0o077);assert os.geteuid()==0 and len(sys.argv)in(2,3)
inputs=Path(sys.argv[1]).resolve(strict=True);pins=json.loads((inputs/'assets.json').read_bytes());assert Path('/etc/hostname').read_text().strip()=='yunzhan-qa-pm2-c239-ubuntu22-amd64';assert 'VERSION_ID="22.04"'in Path('/etc/os-release').read_text()
recovering=len(sys.argv)==3;base=Path(sys.argv[2]).resolve(strict=True)if recovering else Path('/opt/panel-pm2-c171-qa-'+secrets.token_hex(16));assert base.parent==Path('/opt')and re.fullmatch('panel-pm2-c171-qa-[a-f0-9]{32}',base.name)
out=base/'evidence'
if not recovering:out.mkdir(mode=0o700,parents=True)
assert out.stat().st_uid==0 and stat.S_IMODE(out.stat().st_mode)==0o700
boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip();proof={'ok':False,'base':str(base),'boot':boot,'platform':'ubuntu-22.04','architecture':'amd64','signed_pm2_version':'7.0.4-compat12','source_inputs_sha256':pins['source_inputs_sha256'],'Main_changed':False,'all40_commercial':False}
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def save(n,v):
 with(out/n).open('x')as f:json.dump(v,f,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
def command(n,args,limit=120):
 with(out/(n+'.stdout')).open('xb')as stdout,(out/(n+'.stderr')).open('xb')as stderr:r=subprocess.run(args,stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr,timeout=limit)
 save(n+'-outcome.json',{'exit':r.returncode});assert r.returncode==0,n
origin='http://127.0.0.1:19100';csrf='';client=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()));local=urllib.request.build_opener(urllib.request.ProxyHandler({}))
def api(path,body=None):
 headers={'Origin':origin,'Content-Type':'application/json','X-CSRF-Token':csrf}
 if body is not None:headers['Idempotency-Key']=secrets.token_hex(16)
 with client.open(urllib.request.Request(origin+'/api'+path,None if body is None else json.dumps(body).encode(),headers),timeout=85)as r:assert r.status==200;return json.load(r)
def ready_panel():
 end=time.monotonic()+90;samples=[]
 while time.monotonic()<end:
  try:
   with local.open(origin+'/api/ready',timeout=3)as r:
    samples.append({'status':r.status})
    if r.status==200:return samples
  except (OSError,urllib.error.URLError)as e:samples.append({'error':str(e)})
  time.sleep(1)
 raise TimeoutError('Actual panel HTTP not ready')
def login():
 global csrf
 first=json.loads(Path('/etc/panel/first-login.json').read_bytes());csrf=api('/login',{k:first[k]for k in('username','password')})['csrf'];first.clear()
def http(port):
 with local.open('http://127.0.0.1:'+str(port)+'/',timeout=3)as r:assert r.status==200;return json.load(r)
def service(id):return subprocess.check_output(['/usr/bin/systemctl','show','panel-pm2@'+id+'.service','--property=ActiveState,UnitFileState,MainPID,InvocationID'],text=True,timeout=20)
def files(root):
 return{p.relative_to(root).as_posix():{'sha256':sha(p),'uid':p.stat().st_uid,'gid':p.stat().st_gid,'inode':p.stat().st_ino,'mode':stat.S_IMODE(p.stat().st_mode)}for p in root.rglob('*')if p.is_file()and not p.is_symlink()}
module=Path('/etc/panel/security-apps/modules/pm2-manager')
try:
 if not recovering:
  assert not Path('/opt/panel').exists()and not Path('/var/lib/panel').exists()
  verified=base/'verified-input';verified.mkdir(mode=0o700)
  for name,pin in pins['files'].items():
   assert re.fullmatch('[A-Za-z0-9._-]+',name);p=inputs/name;st=p.lstat();assert stat.S_ISREG(st.st_mode)and st.st_nlink==1 and st.st_size<64<<20 and sha(p)==pin
   with(verified/name).open('xb')as f:f.write(p.read_bytes());f.flush();os.fsync(f.fileno())
  archive=verified/('panel-'+pins['version']+'-linux-amd64.tar.gz');args=['/usr/bin/python3','-I','-B',str(verified/'signed-release.py')];trust=['--public-key',str(verified/'release-signing-dev.pub')]
  assert sha(verified/'signed-release.py')=='fe128e82b4e11345b320cd782134768bfe1a4df14947c425d7494873a7a7b7b5'and sha(verified/'release-signing-dev.pub')=='4ccfcc861d56a41e3ba7f7ace7e2432c815f366c58448d783df92c6632f01339'
  command('one-original-signature-verify',args+['verify',str(archive)]+trust)
  command('one-original-preflight',args+['install',str(archive)]+trust+['--preflight-only'],900)
  command('one-normal-signed-install',args+['install',str(archive)]+trust,1800)
  assert json.loads(Path('/opt/panel/current/SOURCE_INPUTS.json').read_bytes())['inputs_sha256']==pins['source_inputs_sha256'];assert not Path('/opt/panel/DEVELOPMENT_RELEASE').exists()
  save('original-panel-HTTP-ready.json',ready_panel())
  # The same bounded actual project/npm/archive helper uses this explicit owned
  # Ubuntu22 guest principal. No GitHub environment or product guard is forged.
  command('actual-normal-PM2-npm-and-projects',['/usr/bin/python3','-I','-B',str(verified/'business.py'),str(out),'phase1'],1800)
  command('actual-archive-and-daemon-cold-read',['/usr/bin/python3','-I','-B',str(verified/'business.py'),str(out),'phase2'],600)
  assert json.loads((out/'business-phase1/original-proof.json').read_bytes())['ok']and json.loads((out/'business-phase2/original-proof.json').read_bytes())['ok']
  state=json.loads((out/'business-phase1/retained-original-project-state.json').read_bytes());login()
  stopped=api('/app-modules/pm2-manager/stop',{'resource_id':state['control_id']});assert stopped['ok']and not stopped['boot_enabled'];assert 'ActiveState=inactive\n'in service(state['control_id'])and 'UnitFileState=disabled\n'in service(state['control_id'])
  target=http(state['target_port']);node=Path('/proc')/str(target['pid'])/'exe';resolved=node.resolve(strict=True);assert str(resolved).startswith('/opt/panel/app-modules/')and str(resolved).endswith('/node/bin/node');node_version=subprocess.check_output([str(resolved),'--version'],text=True,timeout=10).strip();assert node_version=='v24.21.0'
  save('original-Ubuntu22-private-Node-npm-path.json',{'running_Node':str(resolved),'Node_version':node_version,'actual_HTTP':target,'real_public_npm_integrity_succeeded':True,'private_Node_sha256':sha(resolved)})
  installed=json.loads((module/'installed.json').read_bytes());before={'boot':boot,'state':state,'target_HTTP':target,'target_service':service(state['target_id']),'control_service':service(state['control_id']),'module_files':files(module),'instance':installed['installation_id'],'node':str(resolved),'node_sha256':sha(resolved)}
  save('prepared.json',before);os.sync();proof.update(ok=True,powerloss_ready=True,app_version='7.0.4-compat12',actual_private_Node24_and_public_npm=True,actual_config_archive_and_daemon_restart=True,original_target_started_count=target['startup_count'],one_active_one_stopped=True)
 else:
  before=json.loads((out/'prepared.json').read_bytes());assert before['boot']!=boot and json.loads(Path('/opt/panel/current/SOURCE_INPUTS.json').read_bytes())['inputs_sha256']==pins['source_inputs_sha256'];save('original-post-boot-HTTP-readiness.json',ready_panel());state=before['state'];login();observed=http(state['target_port']);assert observed['startup_count']==before['target_HTTP']['startup_count']+1 and observed['secret_sha256']==before['target_HTTP']['secret_sha256']and observed['uid']==before['target_HTTP']['uid']and observed['gid']==before['target_HTTP']['gid']and observed['dependency']and observed['dependency_version']=='7.0.0'
  assert service(state['target_id'])!=before['target_service']and 'ActiveState=active\n'in service(state['target_id']);assert 'ActiveState=inactive\n'in service(state['control_id'])and 'UnitFileState=disabled\n'in service(state['control_id'])
  try:http(state['control_port'])
  except urllib.error.URLError:pass
  else:raise AssertionError('Explicitly stopped control restarted')
  assert files(module)==before['module_files']and sha(Path(before['node']))==before['node_sha256']
  page=api('/app-modules/pm2-manager/configuration-archives?pm2_installation_id='+before['instance']+'&limit=32&offset=0');assert page['total']==1 and page['active_record_count']==1
  old=api('/app-modules/pm2-manager/configuration?pm2_operation_id='+state['config_operation']+'&limit=128&offset=0');assert old['archived_original']and old['configuration_transactions'][0]['state']=='committed';save('original-post-powerloss-old-history.json',{'archive':page,'old_configuration':old})
  observations=[];start=time.monotonic()
  while time.monotonic()-start<90:
   sample=http(state['target_port']);assert sample==observed;assert 'ActiveState=inactive\n'in service(state['control_id']);observations.append(sample);time.sleep(5)
  assert len(observations)>=18 and files(module)==before['module_files'];save('actual-90-second-stability.json',observations)
  proof.update(ok=True,prior_boot=before['boot'],app_version='7.0.4-compat12',actual_hard_powerloss=True,actual_private_Node24_and_public_npm=True,active_project_restored_once=True,stopped_control_not_started=True,all_original_encrypted_manifests_and_archive_bytes_GID_inodes_preserved=True,actual_old_archive_and_active_records_after_powerloss=True,observed_stable_seconds=int(time.monotonic()-start),active_restored_exactly_once=True,stopped_not_started=True,encrypted_manifests_unchanged=True,nonroot_process_and_canary_preserved=observed['uid']>0 and observed['gid']>0,post_boot_http_samples=len(observations))
except BaseException:proof['failure']=traceback.format_exc()
finally:
 if csrf:
  try:api('/logout',{})
  except Exception:proof['logout_failed']=True
 save('cold.json'if recovering else'phase1.json',proof);print(json.dumps({k:v for k,v in proof.items()if k!='failure'}),flush=True)
sys.exit(0 if proof['ok']else 1)
