import os,pathlib,sys,json,hashlib,stat,subprocess,platform,traceback,urllib.request
os.umask(0o077);base=pathlib.Path(sys.argv[1]);assert len(sys.argv)==2 and os.geteuid()==0
intent=json.loads((base/'intent.json').read_bytes());assert platform.machine()=={'arm64':'aarch64','amd64':'x86_64'}[intent['peer']['arch']]and pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()==intent['peer']['boot']
assert hashlib.sha256(pathlib.Path('/etc/machine-id').read_bytes()).hexdigest()==intent['peer']['machine_id_sha256']
def sha(p):return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
def save(n,v):
 with os.fdopen(os.open(base/n,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600),'w')as f:json.dump(v,f,sort_keys=True);f.write(chr(10));f.flush();os.fsync(f.fileno())
def observe_guard(label):
    for i in range(9):
        r = subprocess.run(['/opt/panel/current/bin/panel-executor', '--check-program-upgrade-queues'], capture_output=True, timeout=30)
        u = dict((v.split('=', 1) for v in subprocess.check_output(['systemctl', 'show', 'panel-mysql-overwrite-recovery.service', '--property=LoadState,ActiveState,SubState,MainPID,ControlPID'], text=True, timeout=5).splitlines()))
        save(label + '-guard-' + str(i) + '.json', {'exit': r.returncode, 'stdout_hex': r.stdout.hex(), 'stderr_hex': r.stderr.hex(), 'fixed_recovery_unit': u})
        if r.returncode == 0:
            assert r.stdout == r.stderr == b''
            return
        assert i < 8 and r.stdout == b'' and (b'panel-mysql-overwrite-recovery.service' in r.stderr) and (u['LoadState'] == 'loaded') and (u['ActiveState'] == 'activating') and (u['SubState'] == 'condition') and (u['MainPID'] == '0')
        time.sleep(1)
proof={'ok':False,'scope':'fresh owned ARM programme installation only; Anti-intrusion app not installed','Main_changed':False,'all50_commercial':False}
try:
 for name,digest in intent['files'].items():
  p=base/name;s=p.lstat();assert stat.S_ISREG(s.st_mode)and s.st_uid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600 and sha(p)==digest
 assert all(not os.path.lexists(n)for n in('/opt/panel','/var/lib/panel','/var/lib/panel-executor','/etc/panel-release','/etc/nginx/nginx.conf'))
 archive=base/('panel-0.1.0-dev.proapps24intrusionbaseline35r1-linux-'+intent['peer']['arch']+'.tar.gz')
 for action in('verify','install'):
  save(action+'-once-intent.json',{'archive_sha256':sha(archive),'normal_original_key_signed_verifier':True,'attempt':1})
  with(base/(action+'.log')).open('xb')as f:r=subprocess.run(['/usr/bin/python3','-I','-B',str(base/'signed-release.py'),action,str(archive),'--public-key',str(base/'programme.pub')],stdout=f,stderr=subprocess.STDOUT,timeout=1100 if action=='install' else 30)
  save(action+'-result.json',{'exit':r.returncode,'log_sha256':sha(base/(action+'.log'))});assert r.returncode==0
 inputs=json.loads(pathlib.Path('/opt/panel/current/SOURCE_INPUTS.json').read_bytes());assert inputs['inputs_sha256']=='e2800be6bf3da01db4548e7fc90bc88861a3ba5d7ca32284a72cdd72d66d2a46'
 observe_guard('complete')
 units={}
 for unit in('panel.service','panel-executor.service','panel-terminal.service','panel-terminal-root.service','panel-mysql-overwrite-recovery.service'):
  raw=subprocess.check_output(['/usr/bin/systemctl','show',unit,'--property=Id,LoadState,NeedDaemonReload,ExecCondition,DropInPaths'],text=True,timeout=5);v=dict(x.split('=',1)for x in raw.splitlines());assert v['Id']==unit and v['LoadState']=='loaded'and v['NeedDaemonReload']=='no'and v['ExecCondition'].startswith('{ path=/usr/lib/panel-program-upgrade/start-guard-v4 ; argv[]=/usr/lib/panel-program-upgrade/start-guard-v4 '+unit+' ; ignore_errors=no ;');units[unit]=v
 save('actual-loaded-guards.json',units)
 with urllib.request.build_opener(urllib.request.ProxyHandler({})).open('http://127.0.0.1:19100/api/ready',timeout=5)as r:assert r.status==200
 # Explicit QA fixture preparation before the first app operation: this
 # historical installer writes numeric22 after the distro daemon auto-starts.
 # Load that already-written normal configuration without a daemon restart.
 assert not pathlib.Path('/etc/panel/security-apps/intrusion-prevention.json').exists()
 import sqlite3,time
 with sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True)as d:d.execute('PRAGMA query_only=ON');assert d.execute('SELECT count(*)FROM runtime_jobs').fetchone()==(0,)
 def life(unit):
  pid=subprocess.check_output(['systemctl','show',unit,'--property=MainPID','--value'],text=True,timeout=5).strip();assert int(pid)>1
  return[pid,pathlib.Path('/proc/'+pid+'/stat').read_text().rsplit(')',1)[1].split()[19],sha('/proc/'+pid+'/exe')]
 units_before={n:life(n)for n in('ssh.service','nginx.service','panel.service','panel-executor.service','fail2ban.service')};config=pathlib.Path('/etc/fail2ban/jail.d/panel-sshd.local');raw=config.read_bytes();assert raw==b'[sshd]\nbackend = systemd\nport = 22\n'
 empty=subprocess.check_output(['fail2ban-client','get','sshd','banip'],text=True,timeout=5);assert empty.strip()in('', '[]')
 actions=subprocess.check_output(['fail2ban-client','get','sshd','actions'],text=True,timeout=5);assert actions.strip().splitlines()==['The jail sshd has the following actions:','nftables']
 before_port=subprocess.check_output(['fail2ban-client','get','sshd','action','nftables','port'],text=True,timeout=5);assert before_port in('ssh\n','22\n')
 nss={n:sha('/etc/'+n)for n in('passwd','group','shadow','gshadow','nsswitch.conf')};save('old110-OS-fixture-before-first-app.json',{'source':'normal historical installer has already written numeric22 config; apply ordinary OS reload before first app install','port_before':before_port,'services':units_before,'bans':empty,'config_sha256':sha(config),'not_product_automatic_initialization_acceptance':True})
 save('old110-OS-fixture-reload-once-intent.json',{'command':['fail2ban-client','reload','sshd'],'maximum_submissions':1,'app_jobs_before':0,'bans_before':0,'no_source_or_key_override':True})
 r=subprocess.run(['fail2ban-client','reload','sshd'],capture_output=True,timeout=15);save('old110-OS-fixture-reload-outcome.json',{'exit':r.returncode,'stdout_hex':r.stdout.hex(),'stderr_hex':r.stderr.hex()});assert r.returncode==0
 port_observations=[]
 for i in range(20):
  r=subprocess.run(['fail2ban-client','get','sshd','action','nftables','port'],capture_output=True,text=True,timeout=5);port_observations.append({'exit':r.returncode,'stdout':r.stdout,'stderr':r.stderr})
  if r.returncode==0 and r.stdout=='22\n':break
  assert i<19;time.sleep(.2)
 save('old110-OS-fixture-port-observations.json',port_observations);assert r.returncode==0 and r.stdout=='22\n'
 assert config.read_bytes()==raw and units_before=={n:life(n)for n in units_before}and nss=={n:sha('/etc/'+n)for n in nss}and subprocess.check_output(['fail2ban-client','get','sshd','banip'],text=True,timeout=5).strip()in('', '[]')
 proof['historical_OS_numeric22_configuration_explicitly_loaded_before_first_app_not_automatic_fresh_acceptance']=True
 proof.update(ok=True,fresh_normal_signed_old110_stable_programme_install=True,original_public_key_sha256=intent['files']['programme.pub'],actual_five_loaded_startup_guards_and_current_cache_verified=True,complete_guard_exit=0,ready=200,programme_inputs_sha256=inputs['inputs_sha256'],intrusion_app_install_or_control_or_commercial_acceptance=False)
except BaseException:save('failure.json',{'traceback':traceback.format_exc()})
finally:save('proof.json',proof)
print(json.dumps(proof));raise SystemExit(0 if proof['ok'] else 1)
