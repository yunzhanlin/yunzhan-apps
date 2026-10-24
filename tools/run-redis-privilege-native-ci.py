#!/usr/bin/env python3
"""Disposable CI-only product-helper handover. Never installs a panel or Redis."""
import hashlib,json,os,pathlib,pwd,re,shutil,stat,subprocess,sys,tempfile
assert os.geteuid()==0 and sys.platform.startswith('linux')and os.uname().machine=='x86_64'
assert os.environ.get('GITHUB_ACTIONS')=='true'and os.environ.get('GITHUB_REPOSITORY')=='yunzhanlin/yunzhan-apps'and os.environ.get('GITHUB_JOB')=='redis-privilege-native-amd64'
assert len(sys.argv)==2 and pathlib.Path('/proc/1/comm').read_text().strip()=='systemd'
repo=pathlib.Path(__file__).resolve().parents[1];source=repo/'panel-integration-redis-privilege'
index=json.loads((source/'source-sha256.json').read_bytes())
assert index['release']['frozen_inputs_sha256']=='7eda920eaa2431390acfceb1dd797fd53b5d5eb0464602a10742ad1ebe527903'and index['test_overrides']=={}and len(index['files'])==1813
def sources():
    for name,digest in index['files'].items():
        path=source/name;s=path.lstat()
        assert not path.is_symlink()and stat.S_ISREG(s.st_mode)and s.st_nlink==1 and hashlib.sha256(path.read_bytes()).hexdigest()==digest,name
sources();os.umask(0o077)
state=pathlib.Path('/var/lib/panel-executor')
if os.path.lexists(state):
    s=state.lstat();assert stat.S_ISDIR(s.st_mode)and s.st_uid==0 and not s.st_mode&0o022 and list(state.iterdir())==[], 'Not a clean disposable CI host; no repair or existing-data cleanup'
else:state.mkdir(mode=0o700)
for kind in('passwd','group'):
    result=subprocess.run(['/usr/bin/getent',kind,'panel-redis'],capture_output=True,timeout=5)
    assert result.returncode==2 and result.stdout==result.stderr==b'', 'Never adopts an existing host account'
subprocess.run(['/usr/sbin/useradd','--system','--user-group','--no-create-home','--home-dir','/nonexistent','--shell','/usr/sbin/nologin','--comment','panel-redis','panel-redis'],check=True,timeout=10)
account=pwd.getpwnam('panel-redis');assert account.pw_uid>0 and account.pw_gid>0
root=pathlib.Path(tempfile.mkdtemp(prefix='redis-privilege-ci-',dir=state));nonce=root.name.removeprefix('redis-privilege-ci-')
def save(file,raw,mode):
    with os.fdopen(os.open(file,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode),'wb')as out:
        os.fchmod(out.fileno(),mode);out.write(raw);out.flush();os.fsync(out.fileno())
save(state/'runtime-lifecycle.lock',b'',0o600)
binary=pathlib.Path(sys.argv[1]).resolve(strict=True);raw=binary.read_bytes()
assert len(raw)>1<<20 and raw[:6]==b'\x7fELF\x02\x01'and raw[18:20]==b'\x3e\x00'
save(root/'executor.test',raw,0o500);binary_sha=hashlib.sha256(raw).hexdigest()
models=['TestRedisPrivilegeModelsStrictOrderAndEveryFailureStops','TestRedisPrivilegeModelsRejectInvalidAccountAndMissingVerifierBeforeEffects','TestRedisPrivilegeUnitRetainsIdentityChangeOnlyUntilVerifiedExec']
result=subprocess.run([str(root/'executor.test'),'-test.run=^('+'|'.join(models)+')$','-test.count=1','-test.v=true','-test.timeout=60s'],cwd=source/'internal/executor',capture_output=True,timeout=75)
text=result.stdout.decode('utf8','strict');assert result.returncode==0 and sorted(re.findall(r'^--- PASS: (TestRedisPrivilege[A-Za-z0-9_]+) ',text,re.M))==sorted(models)and'--- SKIP'not in text and'--- FAIL'not in text and text.endswith('PASS\n'),text
save(root/'models.log',result.stdout+result.stderr,0o600)
probe=(repo/'tools/redis-privilege-ci-probe.py').read_bytes()
assert hashlib.sha256(probe).hexdigest()=='f802291a311263384a57c6bab1440335ae92e85ca6d57fbe90644f5b748dd85d'
save(root/'probe.py',probe,0o644)
token=os.urandom(8).hex();runtime='panel-qa-redis-privilege24bkxx-amd64-'+token;alias='/run/'+runtime+'/probe.py'
unit='panel-qa-redis-privilege-ci-'+token
args=['systemd-run','--quiet','--wait','--collect','--pipe','--unit='+unit,'--property=Type=oneshot','--property=WorkingDirectory='+str(source/'internal/executor'),'--property=User=root','--property=Group=panel-redis','--property=CapabilityBoundingSet=CAP_CHOWN CAP_SETGID CAP_SETUID','--property=AmbientCapabilities=CAP_SETUID','--property=NoNewPrivileges=yes','--property=PrivateNetwork=yes','--property=PrivateTmp=yes','--property=ProtectSystem=strict','--property=ProtectHome=yes','--property=RuntimeDirectory='+runtime,'--property=RuntimeDirectoryMode=0755','--property=BindReadOnlyPaths='+str(root/'probe.py')+':'+alias,'--property=RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6','--property=MemoryMax=128M','--property=MemorySwapMax=0','--property=TasksMax=32','--property=TimeoutStartSec=30','--property=TimeoutStopSec=5','--property=KillMode=control-group',str(root/'executor.test'),'-test.run=^TestRedisPrivilegeNativeExecHandover$','-test.count=1','-test.v=true','-test.timeout=20s','-redis-privilege-native-probe='+alias]
assert subprocess.check_output(['systemctl','show',unit+'.service','-p','LoadState','--value'],text=True).strip()=='not-found'
result=subprocess.run(args,capture_output=True,timeout=45)
lines=result.stdout.decode('utf8','strict').splitlines()
assert result.returncode==0 and len(lines)==2 and lines[0]=='=== RUN   TestRedisPrivilegeNativeExecHandover',repr((result.returncode,result.stdout,result.stderr))
value=json.loads(lines[1]);assert value['UID']==account.pw_uid and value['GID']==account.pw_gid and value['all_active_and_inheritable_capabilities_zero']and value['NoNewPrivileges']and value['seccomp_present']and value['actual_production_locked_thread_helper_execd_this_observer']
assert hashlib.sha256((root/'executor.test').read_bytes()).hexdigest()==binary_sha and(root/'probe.py').read_bytes()==probe
sources()
proof={'ok':True,'product_helper_frozen_source_inputs':index['release']['frozen_inputs_sha256'],'models':3,'model_skips':0,'native_exec_handover':value,'installed_Redis_or_store_API_acceptance':False,'all50_commercial':False}
save(root/'proof.json',(json.dumps(proof,sort_keys=True)+'\n').encode(),0o600)
print(json.dumps(proof,sort_keys=True))

