"""One normal signed old110 stable baseline -> C35r2 programme upgrade on the owned Ubuntu22 QA.
Preserve all current business rows/configuration/NSS and the installed110 Jail and original remaining IPv6 ban.
No app installation, SSH control, service migration or unknown-request replay.
"""
import ast,contextlib,hashlib,json,os,pathlib,platform,re,runpy,sqlite3,stat,subprocess,sys,time,traceback,urllib.request
os.umask(0o077);assert os.geteuid()==0 and len(sys.argv)==2
base=pathlib.Path(sys.argv[1]);assert re.fullmatch('/var/tmp/yunzhan-intrusion-c35r2-old110-upgrade-[a-f0-9]{32}',str(base))
def sha(p):return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
def save(n,v):
 assert re.fullmatch('[A-Za-z0-9._-]+',n)
 with os.fdopen(os.open(base/n,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600),'w')as f:json.dump(v,f,sort_keys=True,indent=2);f.write(chr(10));f.flush();os.fsync(f.fileno())
p=json.loads((base/'intent.json').read_bytes());assert platform.machine()=={'arm64':'aarch64','amd64':'x86_64'}[p['peer']['arch']]
assert pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()==p['peer']['boot']and sha('/etc/machine-id')==p['peer']['machine_id_sha256']
assert pathlib.Path('/etc/hostname').read_text().strip()=={'arm64':'lima-panel-intrusion-c35-update2-ubuntu24','amd64':'yunzhan-native-kvm-c35-update'}[p['peer']['arch']]
for n,h in p['files'].items():
 f=base/n;s=f.lstat();assert stat.S_ISREG(s.st_mode)and s.st_uid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600 and sha(f)==h
assert sha(base/'signed-release.py')=='fe128e82b4e11345b320cd782134768bfe1a4df14947c425d7494873a7a7b7b5'
assert sha(base/'programme.pub')=='4ccfcc861d56a41e3ba7f7ace7e2432c815f366c58448d783df92c6632f01339'
OLD='e2800be6bf3da01db4548e7fc90bc88861a3ba5d7ca32284a72cdd72d66d2a46';NEW='3c8dbb9dacc68ad23a5904c99303f421703e48db39e3f4d0215d5013603b48a8'
lib=runpy.run_path(str(base/'business.py'));obs=runpy.run_path(str(base/'observations.py'))
scope={'pathlib':pathlib,'subprocess':subprocess,'json':json,'re':re,'sha':sha}
capture=ast.parse((base/'capture-model.py').read_text())
for name in('nginx','nft','nft_clean'):
 fn=next(n for n in capture.body if isinstance(n,ast.FunctionDef)and n.name==name);exec(compile(ast.Module(body=[fn],type_ignores=[]),'<original-qa-readonly-capture>','exec'),scope)
def tree():
 entries={};total=0
 def walk(f):
  nonlocal total
  s=f.lstat();v={'dev':s.st_dev,'ino':s.st_ino,'mode':s.st_mode,'uid':s.st_uid,'gid':s.st_gid,'links':s.st_nlink,'mtime_ns':s.st_mtime_ns,'ctime_ns':s.st_ctime_ns}
  if stat.S_ISREG(s.st_mode):total+=s.st_size;assert s.st_size<=128<<20 and total<=1<<30;v.update(bytes=s.st_size,sha256=sha(f))
  elif stat.S_ISLNK(s.st_mode):v['target']=os.readlink(f)
  else:assert stat.S_ISDIR(s.st_mode)
  entries[str(f)]=v;assert len(entries)<=100000
  if stat.S_ISDIR(s.st_mode):
   for c in sorted(f.iterdir()):walk(c)
 for n in('/etc/panel','/etc/nginx','/etc/fail2ban','/etc/ssh','/etc/passwd','/etc/group','/etc/shadow','/etc/gshadow','/etc/nsswitch.conf','/srv/panel/sites'):
  f=pathlib.Path(n)
  if os.path.lexists(f):walk(f)
  else:entries[n]={'absent':True}
 return entries
def lifetime(unit):
 raw=subprocess.check_output(['systemctl','show',unit,'--property=MainPID,ActiveState,SubState,InvocationID'],text=True,timeout=5);v=dict(x.split('=',1)for x in raw.splitlines());pid=v['MainPID'];assert int(pid)>1 and v['ActiveState']=='active'
 x=pathlib.Path('/proc/'+pid+'/stat').read_text();v['start_ticks']=x[x.rfind(')')+2:].split()[19];v['exe_sha256']=sha('/proc/'+pid+'/exe');return v
def guard(label):
 values=[]
 for i in range(9):
  c=subprocess.run(['/opt/panel/current/bin/panel-executor','--check-program-upgrade-queues'],capture_output=True,timeout=30)
  state=subprocess.check_output(['systemctl','show','panel-mysql-overwrite-recovery.service','--property=LoadState,ActiveState,SubState,MainPID,ControlPID'],text=True,timeout=5);v=dict(x.split('=',1)for x in state.splitlines())
  values.append({'exit':c.returncode,'stdout_hex':c.stdout.hex(),'stderr_hex':c.stderr.hex(),'fixed_recovery_unit':v})
  save(label+'-guard-'+str(i)+'.json',values[-1])
  if c.returncode==0:assert c.stdout==c.stderr==b'';return values
  assert i<8 and c.stdout==b''and b'panel-mysql-overwrite-recovery.service'in c.stderr and v['LoadState']=='loaded'and v['ActiveState']=='activating'and v['SubState']=='condition'and v['MainPID']=='0','Original full guard refused; no action or reset permitted'
  time.sleep(1)
def snapshot(label):
 v={'core':lib['capture_core'](),'files':tree(),'nginx':scope['nginx'](),'nft':scope['nft'](),'security_lifetimes':{n:lifetime(n)for n in('ssh.service','fail2ban.service')},'source_inputs':json.loads(pathlib.Path('/opt/panel/current/SOURCE_INPUTS.json').read_bytes())['inputs_sha256'],'ban_times':subprocess.check_output(['fail2ban-client','get','sshd','banip','--with-time'],text=True,timeout=5),'actions':subprocess.check_output(['fail2ban-client','get','sshd','actions'],text=True,timeout=5)}
 save(label+'.json',v);return v
def compare(a,z):
 assert a['files']==z['files']and a['nginx']==z['nginx']and a['security_lifetimes']==z['security_lifetimes']and a['actions']==z['actions']and a['ban_times']==z['ban_times']
 x=[];y=[];assert scope['nft_clean'](a['nft'],x)==scope['nft_clean'](z['nft'],y)and len(x)==len(y)and all(b[0]>=c[0]and b[1]>=c[1]for c,b in zip(x,y))
 before=a['core'];after=z['core'];assert before['schema']==after['schema']and before['columns']==after['columns']and before['rows'].keys()==after['rows'].keys()
 observations=obs['observation_deltas'](before,after,p['peer']['boot'],lib['stamp']);assert observations['ok'];moving=[]
 for name,rows in before['rows'].items():
  current=after['rows'][name]
  if rows==current:continue
  if name in('database_connection_samples','monitor_samples','monitor_conditions','monitor_services','notification_dispatch_status','sqlite_sequence'):assert observations['ok']
  elif name=='load_balance_traffic_source':
   assert len(rows)==len(current)==1 and rows[0][:3]==current[0][:3]and rows[0][1]==['text','clear']and lib['stamp'](rows[0][3][1])<=lib['stamp'](current[0][3][1])<=after['at']+1
  elif name=='runtime_installations':
   cols=[v[1]for v in before['columns'][name]];at=cols.index('detected_at');idx=cols.index('id');old={json.dumps(v[idx]):v for v in rows};new={json.dumps(v[idx]):v for v in current};assert old.keys()==new.keys()
   for k,r in old.items():assert r[:at]+r[at+1:]==new[k][:at]+new[k][at+1:]and lib['stamp'](r[at][1])<=lib['stamp'](new[k][at][1])<=after['at']+1
  else:raise AssertionError('Original business/task changed: '+name)
  moving.append(name)
 return {'ok':True,'all_original_tables_and_columns':len(before['rows']),'qualified_background_changes':moving,'observations':observations,'all_protected_file_bytes_identities_modes':len(a['files']),'installed110_Jail_remaining_ban_and_Nginx_lifetimes_unchanged':True}
def command(label,args,timeout):
 save(label+'-once-intent.json',{'args':args,'maximum_submissions':1,'unknown_outcome_observe_only':True})
 with(base/(label+'.stdout.log')).open('xb')as out,(base/(label+'.stderr.log')).open('xb')as err:r=subprocess.run(args,stdin=subprocess.DEVNULL,stdout=out,stderr=err,timeout=timeout)
 save(label+'-outcome.json',{'exit':r.returncode,'stdout_sha256':sha(base/(label+'.stdout.log')),'stderr_sha256':sha(base/(label+'.stderr.log'))});assert r.returncode==0,'Original signed operation refused; never replay'
proof={'ok':False,'normal_original_key_signed_programme_upgrade':False,'app_operations':0,'Main_changed':False,'all50_commercial':False}
try:
 assert not os.path.lexists('/opt/panel/DEVELOPMENT_RELEASE')and json.loads(pathlib.Path('/opt/panel/current/SOURCE_INPUTS.json').read_bytes())['inputs_sha256']==OLD
 original=pathlib.Path(p['installed110_case']['proof_path']);assert re.fullmatch('/opt/panel-intrusion-native-qa-[a-f0-9]{32}/evidence/proof.json',str(original))and sha(original)==p['installed110_case']['proof_sha256']and json.loads(original.read_bytes())['ok'];assert json.loads(pathlib.Path('/etc/panel/security-apps/intrusion-prevention.json').read_bytes())['version']=='1.1.0'
 guard('initial');before=snapshot('before');assert before['actions'].strip().splitlines()in(['The jail sshd has the following actions:','nftables'],['The jail sshd has the following actions:','nftables-multiport'])and '2001:db8:35::2 \t'in before['ban_times']
 archive=base/('panel-'+p['version']+'-linux-'+p['peer']['arch']+'.tar.gz');command('verify',['python3','-I','-B',str(base/'signed-release.py'),'verify',str(archive),'--public-key',str(base/'programme.pub')],30)
 args=['python3','-I','-B',str(base/'signed-release.py'),'install',str(archive),'--public-key',str(base/'programme.pub')]
 command('preflight',args+['--preflight-only'],900);pre=snapshot('after-preflight');assert pre['source_inputs']==OLD;save('preflight-preservation.json',compare(before,pre))
 command('upgrade',args,1100);after=snapshot('after-upgrade');assert after['source_inputs']==NEW;save('upgrade-preservation.json',compare(before,after))
 guard('final')
 units={}
 for n in('panel.service','panel-executor.service','panel-terminal.service','panel-terminal-root.service','panel-mysql-overwrite-recovery.service'):
  raw=subprocess.check_output(['systemctl','show',n,'--property=Id,LoadState,NeedDaemonReload,ExecCondition,DropInPaths'],text=True,timeout=5);v=dict(x.split('=',1)for x in raw.splitlines());assert v['Id']==n and v['LoadState']=='loaded'and v['NeedDaemonReload']=='no'and v['ExecCondition'].startswith('{ path=/usr/lib/panel-program-upgrade/start-guard-v4 ; argv[]=/usr/lib/panel-program-upgrade/start-guard-v4 '+n+' ; ignore_errors=no ;');units[n]=v
 save('actual-loaded-five-guards.json',units)
 with urllib.request.build_opener(urllib.request.ProxyHandler({})).open('http://127.0.0.1:19100/api/ready',timeout=5)as r:assert r.status==200
 proof.update(ok=True,normal_original_key_signed_programme_upgrade=True,old_source_inputs_sha256=OLD,source_inputs_sha256=NEW,complete_guard_exit=0,ready=200,original_security_configuration_and_service_lifetimes_retained=True,installed110_original_Jail_and_remaining_ban_preserved=True,signed110_already_installed_not_reinstalled=True,frontend111_browser_acceptance_pending=True)
except BaseException:save('failure.json',{'traceback':traceback.format_exc()})
finally:save('proof.json',proof);print(json.dumps(proof))
sys.exit(0 if proof['ok']else 1)

