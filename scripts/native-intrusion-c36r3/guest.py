"""One fresh signed C36r3 programme + signed111 app/Core/Root journey on owned Ubuntu24.
Runs unchanged on ARM64 and actual hardware-KVM AMD64. No Main/reference changes.
"""
import contextlib,hashlib,http.cookiejar,json,os,pathlib,platform,re,runpy,secrets,sqlite3,stat,subprocess,sys,time,traceback,urllib.error,urllib.request
os.umask(0o077);assert len(sys.argv)==2 and os.geteuid()==0
payload=pathlib.Path(sys.argv[1]).resolve(strict=True);pins=json.loads((payload/'assets.json').read_bytes());arch={'aarch64':'arm64','x86_64':'amd64'}[platform.machine()]
SOURCE='1d9910740e082833fb4e5156fc6baf2e2b977bc67efc865ec6ee4a3ebc425f25';VERSION='0.1.0-dev.proapps24nfsreportcandidate36r3'
assert pins['architecture']==arch and pins['format']==1 and pins['source_inputs_sha256']==SOURCE and pins['version']==VERSION
assert pathlib.Path('/etc/hostname').read_text().strip()=={'arm64':'lima-panel-intrusion-c36r3-fresh-ubuntu24','amd64':'yunzhan-native-kvm-c36r3'}[arch]
assert 'VERSION_ID="24.04"'in pathlib.Path('/usr/lib/os-release').read_text()and pathlib.Path('/proc/1/comm').read_text().strip()=='systemd'
base=pathlib.Path('/opt/panel-intrusion-native-qa-'+secrets.token_hex(16));base.mkdir(mode=0o700);evidence=base/'evidence';evidence.mkdir(mode=0o700)
def sha(p):return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
def save(n,v):
 assert re.fullmatch('[A-Za-z0-9._-]+',n)
 with os.fdopen(os.open(evidence/n,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600),'w')as f:json.dump(v,f,sort_keys=True,indent=2);f.write(chr(10));f.flush();os.fsync(f.fileno())
for n,h in pins['files'].items():
 assert re.fullmatch('[A-Za-z0-9._-]+',n);f=payload/n;s=f.lstat();assert stat.S_ISREG(s.st_mode)and s.st_nlink==1 and sha(f)==h
assert sha(payload/'signed-release.py')=='fe128e82b4e11345b320cd782134768bfe1a4df14947c425d7494873a7a7b7b5'
assert sha(payload/'programme.pub')=='4ccfcc861d56a41e3ba7f7ace7e2432c815f366c58448d783df92c6632f01339'
# The normal installer requires an independently pinned Root-owned trust key.
# SCP input belongs to the disposable qa user; copy only exact pinned regular
# files through held descriptors into a new private Root directory first.
verified=base/'verified-input';verified.mkdir(mode=0o700)
for name,digest in pins['files'].items():
 fd=os.open(payload/name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
 with os.fdopen(fd,'rb')as src:
  s=os.fstat(src.fileno());assert stat.S_ISREG(s.st_mode)and s.st_nlink==1 and 0<s.st_size<=64<<20
  raw=src.read((64<<20)+1);assert len(raw)==s.st_size and hashlib.sha256(raw).hexdigest()==digest
  z=os.fstat(src.fileno());assert(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)==(z.st_dev,z.st_ino,z.st_size,z.st_mtime_ns,z.st_ctime_ns)
 with os.fdopen(os.open(verified/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600),'wb')as dst:dst.write(raw);dst.flush();os.fsync(dst.fileno())
 assert sha(verified/name)==digest and(verified/name).stat().st_uid==0
payload=verified
assert stat.S_IMODE((payload/'programme.pub').stat().st_mode)==0o600
save('root-owned-original-trust-payload.json',{'files':pins['files'],'private_root_directory':True,'all_exact_hashes':True,'original_signer_or_key_changed':False,'installer_trust_checks_unchanged':True})
save('actual-native-identity-and-inputs.json',{'architecture':arch,'boot':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'machine_id_sha256':sha('/etc/machine-id'),'PID1':pathlib.Path('/proc/1/comm').read_text().strip(),'files':pins['files'],'source_inputs_sha256':SOURCE})
def command(label,args,timeout):
 save(label+'-once-intent.json',{'maximum_submissions':1,'args':args,'unknown_outcome_observe_only':True})
 with(evidence/(label+'.stdout.log')).open('xb')as out,(evidence/(label+'.stderr.log')).open('xb')as err:r=subprocess.run(args,stdin=subprocess.DEVNULL,stdout=out,stderr=err,timeout=timeout)
 save(label+'-outcome.json',{'exit':r.returncode,'stdout_sha256':sha(evidence/(label+'.stdout.log')),'stderr_sha256':sha(evidence/(label+'.stderr.log'))});assert r.returncode==0,'Original normal operation failed; no replay: '+label
def guard(label):
 for i in range(9):
  r=subprocess.run(['/opt/panel/current/bin/panel-executor','--check-program-upgrade-queues'],capture_output=True,timeout=30)
  u=dict(v.split('=',1)for v in subprocess.check_output(['systemctl','show','panel-mysql-overwrite-recovery.service','--property=LoadState,ActiveState,SubState,MainPID,ControlPID'],text=True,timeout=5).splitlines())
  save(label+'-guard-'+str(i)+'.json',{'exit':r.returncode,'stdout_hex':r.stdout.hex(),'stderr_hex':r.stderr.hex(),'fixed_recovery_unit':u})
  if r.returncode==0:assert r.stdout==r.stderr==b'';return
  assert i<8 and r.stdout==b''and b'panel-mysql-overwrite-recovery.service'in r.stderr and u['LoadState']=='loaded'and u['ActiveState']=='activating'and u['SubState']=='condition'and u['MainPID']=='0'
  time.sleep(1)
def lifetime(unit):
 pid=subprocess.check_output(['systemctl','show',unit,'--property=MainPID','--value'],text=True,timeout=5).strip();assert int(pid)>1
 return {'pid':pid,'start_ticks':pathlib.Path('/proc/'+pid+'/stat').read_text().rsplit(')',1)[1].split()[19],'exe_sha256':sha('/proc/'+pid+'/exe')}
def nss():return{n:{'sha256':sha('/etc/'+n),'mode':pathlib.Path('/etc/'+n).stat().st_mode,'uid':pathlib.Path('/etc/'+n).stat().st_uid,'gid':pathlib.Path('/etc/'+n).stat().st_gid}for n in('passwd','group','shadow','gshadow','nsswitch.conf')}
def job(label,identity):
 assert re.fullmatch('[a-f0-9]{32}',identity);observed=[];end=time.monotonic()+240
 while True:
  with contextlib.closing(sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True,timeout=3))as db:
   db.execute('PRAGMA query_only=ON');row=db.execute('SELECT state,error FROM runtime_jobs WHERE id=?',(identity,)).fetchone()
  assert row is not None;observed.append({'state':row[0],'error':row[1],'at':time.time()})
  if row[0]in('succeeded','failed','needs_attention','cancelled'):break
  assert time.monotonic()<end,'Original job unresolved; observe only';time.sleep(1)
 save(label+'-original-job-observations.json',observed);assert row==('succeeded',''),'Original job refused; no reset or replay'
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*args,**kwargs):raise AssertionError('Authentication redirect refused')
origin='http://127.0.0.1:19100';client=None;csrf='';http_events=[]
def api(path,body=None,key=None):
 headers={'Origin':origin,'Content-Type':'application/json','X-CSRF-Token':csrf}
 if key:headers['Idempotency-Key']=key
 req=urllib.request.Request(origin+'/api'+path,data=None if body is None else json.dumps(body,separators=(',',':')).encode(),headers=headers)
 try:
  with client.open(req,timeout=35)as r:status=r.status;raw=r.read((4<<20)+1)
 except urllib.error.HTTPError as e:status=e.code;raw=e.read((4<<20)+1)
 assert len(raw)<=4<<20;v=json.loads(raw);http_events.append({'path':path,'method':'GET'if body is None else'POST','status':status})
 if status not in(200,202):save('HTTP-refusal-'+secrets.token_hex(8)+'.json',{'path':path,'status':status,'value':v});raise AssertionError('Original HTTP refusal '+str(status)+':'+path)
 return status,v
proof={'ok':False,'architecture':arch,'base':str(base),'scope':'normal signed programme/app111, actual dualstack SSH, preserving configuration, audited unban and store status; no update or Main acceptance claimed','source_inputs_sha256':SOURCE,'Main_changed':False,'all50_commercial':False,'app_install_POSTs':0,'configure_POSTs':0,'failed_or_unknown_requests_replayed':False}
try:
 assert all(not os.path.lexists(n)for n in('/opt/panel','/var/lib/panel','/var/lib/panel-executor','/etc/panel-release','/etc/nginx/nginx.conf'))
 archive=payload/('panel-'+VERSION+'-linux-'+arch+'.tar.gz');args=['python3','-I','-B',str(payload/'signed-release.py')]
 command('signature-verify',args+['verify',str(archive),'--public-key',str(payload/'programme.pub')],30)
 command('normal-first-install',args+['install',str(archive),'--public-key',str(payload/'programme.pub')],1200)
 assert json.loads(pathlib.Path('/opt/panel/current/SOURCE_INPUTS.json').read_bytes())['inputs_sha256']==SOURCE and not os.path.lexists('/opt/panel/DEVELOPMENT_RELEASE')
 units={}
 for unit in('panel.service','panel-executor.service','panel-terminal.service','panel-terminal-root.service','panel-mysql-overwrite-recovery.service'):
  raw=subprocess.check_output(['systemctl','show',unit,'--property=Id,LoadState,NeedDaemonReload,ExecCondition,DropInPaths'],text=True,timeout=5);v=dict(x.split('=',1)for x in raw.splitlines());assert v['Id']==unit and v['LoadState']=='loaded'and v['NeedDaemonReload']=='no'and v['ExecCondition'].startswith('{ path=/usr/lib/panel-program-upgrade/start-guard-v4 ; argv[]=/usr/lib/panel-program-upgrade/start-guard-v4 '+unit+' ; ignore_errors=no ;');units[unit]=v
 save('actual-five-loaded-guards.json',units);guard('programme')
 fresh_actions=subprocess.check_output(['fail2ban-client','get','sshd','actions'],text=True,timeout=5);fresh_port=subprocess.check_output(['fail2ban-client','get','sshd','action','nftables-multiport','port'],text=True,timeout=5).strip();assert fresh_actions.strip().splitlines()==['The jail sshd has the following actions:','nftables-multiport']and fresh_port=='22';save('actual-automatic-first-policy-before-app.json',{'actions':fresh_actions,'port':fresh_port,'manual_OS_reload_restart_or_first_app_request':0,'normal_signed_installer_loaded_policy':True})
 version=subprocess.check_output(['fail2ban-client','--version'],text=True,timeout=5);assert version.strip()=='Fail2Ban v1.0.2'
 actions=subprocess.check_output(['fail2ban-client','get','sshd','actions'],text=True,timeout=5);assert 'nftables-multiport'in actions and 'iptables'not in actions
 save('actual-upstream-and-fresh-action.json',{'package':subprocess.check_output(['dpkg-query','-W','-f='+chr(36)+'{Version}','fail2ban'],text=True,timeout=5),'upstream':version,'actions':actions,'fresh_default':pathlib.Path('/etc/fail2ban/jail.d/panel-sshd.local').read_text()})
 assert not os.path.lexists('/etc/panel/security-apps/intrusion-prevention.json')
 before={'nss':nss(),'lifetimes':{n:lifetime(n)for n in('panel.service','panel-executor.service','nginx.service','ssh.service','fail2ban.service')}};save('protected-before-app.json',before)
 accessfile=pathlib.Path('/etc/panel/first-login.json');s=accessfile.lstat();assert stat.S_ISREG(s.st_mode)and s.st_uid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600
 access=json.loads(accessfile.read_bytes());client=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect(),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
 try:status,login=api('/login',{k:access[k]for k in('username','password')});assert status==200;csrf=login['csrf']
 finally:access.clear()
 status,page=api('/app-registry?refresh=1');save('actual-original-signed-catalogue.json',page);assert len(page['catalog']['apps'])==50 and page['host']=={'platform':'ubuntu-24.04','architecture':arch}and not page['source']['stale']
 item=next(v for v in page['catalog']['apps']if v['id']=='anti-intrusion');assert item['version']=='1.1.1'and item['sha256']=='6d612505ac72ec97fdafdbc0eb8dae999df296e5203bb47058f799dd2aa6f01e'
 state=next(v for v in page['status']if v['id']=='anti-intrusion');assert state['state_known']and not state['installed']and state['supported']and not state['update_available']
 status,inspection=api('/software/intrusion-prevention/inspection');save('uninstalled-inspection.json',inspection);assert not inspection['installed']
 request={'expected_version':'1.1.1','expected_sha256':item['sha256'],'settings':{'max_retry':5,'find_time_minutes':10,'ban_time_minutes':60}};key=secrets.token_hex(16)
 save('signed-app-install-once-intent.json',{'key':key,'request':request,'maximum_POSTs':1});proof['app_install_POSTs']=1
 status,accepted=api('/app-registry/anti-intrusion/install',request,key);save('signed-app-install-accepted.json',accepted);assert status==202 and accepted['provider']=='panel-module'and accepted['target']=='intrusion-prevention';proof['install_job']=accepted['job_id'];job('install',accepted['job_id'])
 status,inspection=api('/software/intrusion-prevention/inspection');save('installed111-inspection.json',inspection)
 assert inspection['installed']and inspection['version']=='1.1.1'and inspection['config_matches']and inspection['service_active']and inspection['ssh_ports_match']and inspection['ssh_effective_ports']==inspection['ssh_listening_ports']==[22]and inspection['active_bans_known']and inspection['active_bans']==0
 assert not inspection['healthy']and inspection['kernel_scope_deferred']and not inspection['kernel_scope_verified']
 journey=runpy.run_path(str(payload/'ssh-journey.py'))['run'](base,arch,api,save,job);assert journey['ok'];proof['actual_SSH_journey']=journey;proof['configure_POSTs']=journey['configure_POSTs']
 status,workspace=api('/software/intrusion-prevention/workspace');save('actual111-workspace.json',workspace)
 status,page=api('/app-registry?refresh=1');save('installed111-store-status.json',page);state=next(v for v in page['status']if v['id']=='anti-intrusion');assert state['state_known']and state['installed']and state['supported']and not state['update_available']and state['installed_version']=='1.1.1'
 after={'nss':nss(),'lifetimes':{n:lifetime(n)for n in before['lifetimes']}};save('protected-after-app.json',after);assert after==before
 guard('final');status,_=api('/logout',{});assert status==200;csrf=''
 proof.update(ok=True,normal_original_key_signed_programme_install=True,normal_original_key_signed_registry_app111_install=True,actual_runtime_configuration_readback=True,original_NSS_and_five_service_lifetimes_preserved=True,complete_guard_exit=0,normal_own_session_logged_out=True,actual_SSH_authentication_journey_passed=True,store_supports111_and_marks_installed_without_false_update=True)
except BaseException:save('failure.json',{'traceback':traceback.format_exc()})
finally:
 if csrf:
  try:status,_=api('/logout',{});assert status==200;proof['normal_own_session_logged_out']=True
  except BaseException:save('logout-failure.json',{'traceback':traceback.format_exc()});proof['ok']=False
 save('http-events.json',http_events);save('proof.json',proof)
 print(json.dumps({'ok':proof['ok'],'base':str(base),'proof_sha256':sha(evidence/'proof.json'),'source_inputs_sha256':SOURCE,'architecture':arch,'Main_changed':False,'all50_commercial':False}),flush=True)
sys.exit(0 if proof['ok']else 1)

