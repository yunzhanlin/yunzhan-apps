"""One fresh signed C41r3 programme and two signed PHP apps and custom Nginx/CAS preservation on an owned guest.
Uses actual hardware-KVM AMD64. Existing Main ARM64 evidence is separate.
"""
import contextlib,hashlib,http.cookiejar,json,os,pathlib,platform,re,runpy,secrets,sqlite3,stat,subprocess,sys,time,traceback,urllib.error,urllib.request
os.umask(0o077);assert len(sys.argv)==2 and os.geteuid()==0
payload=pathlib.Path(sys.argv[1]).resolve(strict=True);pins=json.loads((payload/'assets.json').read_bytes());arch={'aarch64':'arm64','x86_64':'amd64'}[platform.machine()]
SOURCE='757e1941dc2e3e138cef458eb52114545d168ee41286872012e100770c50a1fb';VERSION='0.1.0-dev.proapps24phpswitchpreservecandidate41r3'
assert pins['architecture']==arch and pins['format']==1 and pins['source_inputs_sha256']==SOURCE and pins['version']==VERSION
case=pins['OS_case'];assert case['architecture']==arch=='amd64' and case['platform'] == 'ubuntu-24.04'
assert pathlib.Path('/etc/hostname').read_text().strip()==case['hostname']
assert 'VERSION_ID="'+case['version_id']+'"'in pathlib.Path('/usr/lib/os-release').read_text()and pathlib.Path('/proc/1/comm').read_text().strip()=='systemd'
base=pathlib.Path('/opt/panel-php-c41r3-native-qa-'+secrets.token_hex(16));base.mkdir(mode=0o700);evidence=base/'evidence';evidence.mkdir(mode=0o700)
def sha(p):return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
def save(n,v):
 assert re.fullmatch('[A-Za-z0-9._-]+',n)
 with os.fdopen(os.open(evidence/n,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600),'w')as f:json.dump(v,f,sort_keys=True,indent=2);f.write(chr(10));f.flush();os.fsync(f.fileno())
for n,h in pins['files'].items():
 assert re.fullmatch('[A-Za-z0-9._-]+',n);f=payload/n;s=f.lstat();assert stat.S_ISREG(s.st_mode)and s.st_nlink==1 and sha(f)==h
assert sha(payload/'signed-release.py')=='fe128e82b4e11345b320cd782134768bfe1a4df14947c425d7494873a7a7b7b5'
assert sha(payload/'release-signing-dev.pub')=='4ccfcc861d56a41e3ba7f7ace7e2432c815f366c58448d783df92c6632f01339'
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
assert stat.S_IMODE((payload/'release-signing-dev.pub').stat().st_mode)==0o600
save('root-owned-original-trust-payload.json',{'files':pins['files'],'private_root_directory':True,'all_exact_hashes':True,'original_signer_or_key_changed':False,'installer_trust_checks_unchanged':True})
save('actual-native-identity-and-inputs.json',{'architecture':arch,'boot':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'machine_id_sha256':sha('/etc/machine-id'),'PID1':pathlib.Path('/proc/1/comm').read_text().strip(),'os_release':pathlib.Path('/usr/lib/os-release').read_text(),'files':pins['files'],'source_inputs_sha256':SOURCE})

def verify_full_installed_archive():
 import tarfile
 name='panel-'+VERSION+'-linux-'+arch+'.tar.gz';archive=payload/name
 assert sha(archive)==pins['files'][name]
 installed=pathlib.Path('/opt/panel/current').resolve(strict=True)
 assert str(installed)=='/opt/panel/releases/'+VERSION
 records=[];prefix='panel-'+VERSION+'-linux-'+arch+'/'
 with tarfile.open(archive,'r:gz')as stream:
  for member in stream.getmembers():
   if member.name.rstrip('/')==prefix.rstrip('/'):relative=''
   else:assert member.name.startswith(prefix);relative=member.name[len(prefix):].rstrip('/')
   assert not pathlib.PurePosixPath(relative).is_absolute()and '..'not in pathlib.PurePosixPath(relative).parts
   f=installed/relative;s=f.lstat();assert s.st_uid==0 and stat.S_IMODE(s.st_mode)==member.mode
   record={'path':relative,'mode':member.mode,'uid':s.st_uid,'gid':s.st_gid,'inode':s.st_ino}
   if member.isfile():
    assert stat.S_ISREG(s.st_mode)and s.st_nlink==1
    digest=hashlib.sha256(stream.extractfile(member).read()).hexdigest();assert sha(f)==digest
    record.update(type='file',sha256=digest,bytes=s.st_size)
   else:assert member.isdir()and stat.S_ISDIR(s.st_mode);record.update(type='directory')
   records.append(record)
 actual={''}|{str(f.relative_to(installed))for f in installed.rglob('*')}
 assert actual=={v['path']for v in records}and len(records)==203
 save('actual-entire-signed-installed-tree.json',{'ok':True,'read_only':True,'archive_sha256':sha(archive),'installed':str(installed),'entries':records,'count':203,'source_inputs_sha256':json.loads((installed/'SOURCE_INPUTS.json').read_bytes())['inputs_sha256']})

def command(label,args,timeout,env=None):
 save(label+'-once-intent.json',{'maximum_submissions':1,'args':args,'unknown_outcome_observe_only':True})
 with(evidence/(label+'.stdout.log')).open('xb')as out,(evidence/(label+'.stderr.log')).open('xb')as err:r=subprocess.run(args,stdin=subprocess.DEVNULL,stdout=out,stderr=err,timeout=timeout,env=env)
 save(label+'-outcome.json',{'exit':r.returncode,'stdout_sha256':sha(evidence/(label+'.stdout.log')),'stderr_sha256':sha(evidence/(label+'.stderr.log'))});assert r.returncode==0,'Original normal operation failed; no replay: '+label

def guard(label):
 for i in range(9):
  r=subprocess.run(['/opt/panel/current/bin/panel-executor','--check-program-upgrade-queues'],capture_output=True,timeout=30)
  u=dict(v.split('=',1)for v in subprocess.check_output(['systemctl','show','panel-mysql-overwrite-recovery.service','--property=LoadState,ActiveState,SubState,MainPID,ControlPID'],text=True,timeout=5).splitlines())
  save(label+'-guard-'+str(i)+'.json',{'exit':r.returncode,'stdout_hex':r.stdout.hex(),'stderr_hex':r.stderr.hex(),'fixed_recovery_unit':u})
  if r.returncode==0:assert r.stdout==r.stderr==b'';return
  assert i<8 and r.stdout==b''and b'panel-mysql-overwrite-recovery.service'in r.stderr and u['LoadState']=='loaded'and u['ActiveState']=='activating'and u['SubState']=='condition'and u['MainPID']=='0'
  time.sleep(1)

proof={'ok':False,'architecture':arch,'base':str(base),'scope':'Original-key fresh normal C41r3 programme, two signed PHP apps, Redis, actual nonroot website/CLI/upload and custom Nginx configuration CAS switch/return','source_inputs_sha256':SOURCE,'OS_case':case,'Main_changed':False,'all50_commercial':False,'original_operation_replay':False}
functional_base=None
try:
 assert all(not os.path.lexists(n)for n in('/opt/panel','/var/lib/panel','/var/lib/panel-executor','/etc/panel-release','/etc/nginx/nginx.conf'))
 archive=payload/('panel-'+VERSION+'-linux-'+arch+'.tar.gz');signer=['python3','-I','-B',str(payload/'signed-release.py')];command('signature-verify',signer+['verify',str(archive),'--public-key',str(payload/'release-signing-dev.pub')],30);command('normal-first-install',signer+['install',str(archive),'--public-key',str(payload/'release-signing-dev.pub')],1200)
 assert json.loads(pathlib.Path('/opt/panel/current/SOURCE_INPUTS.json').read_bytes())['inputs_sha256']==SOURCE and not os.path.lexists('/opt/panel/DEVELOPMENT_RELEASE');verify_full_installed_archive();guard('programme')
 functional_base=pathlib.Path('/opt/panel-php-c41r3-functional-'+secrets.token_hex(16));functional_base.mkdir(mode=0o700)
 plan={'base':str(functional_base),'boot':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'architecture':'amd64','platform':'ubuntu-24.04','prepare_apps':True,'files':{'worker.py':sha(payload/'functional.py')},'programme_binaries':{n:sha('/opt/panel/current/bin/'+n)for n in('panel','panel-executor','panel-start-guard')},'Main_changed':False}
 for name,raw in [('worker.py',(payload/'functional.py').read_bytes()),('intent.json',json.dumps(plan,sort_keys=True).encode())]:
  with os.fdopen(os.open(functional_base/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600),'wb')as f:f.write(raw);f.flush();os.fsync(f.fileno())
 save('original-functional-bound-plan.json',{'plan':plan,'maximum_submissions':1,'unknown_outcome_observe_only':True})
 command('original-functional',['/usr/bin/python3','-I','-B',str(functional_base/'worker.py'),str(functional_base)],2400)
 result=json.loads((functional_base/'evidence/proof.json').read_bytes());assert result['ok']is True and result['architecture']=='amd64'and result['normal_application_install_POSTs']==2 and result['normal_extension_install_POSTs']==2 and result['normal_PHP_switch_POSTs']==3
 proof.update(ok=True,normal_programme_signature_and_all203_installed_entries_verified=True,functional_proof_sha256=sha(functional_base/'evidence/proof.json'),actual_nonroot_account_HTTP_multipart_CLI_Redis_custom_config_and_stale_CAS=True)
except BaseException:save('original-failure.json',{'traceback':traceback.format_exc()})
finally:
 if functional_base is not None and(functional_base/'evidence').is_dir():
  members=sorted((functional_base/'evidence').iterdir());assert len(members)<=250;total=0
  for f in members:
   s=f.lstat();assert re.fullmatch('[A-Za-z0-9._-]+',f.name)and stat.S_ISREG(s.st_mode)and s.st_uid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600 and s.st_size<32<<20;raw=f.read_bytes();total+=len(raw);assert total<128<<20
   with os.fdopen(os.open(evidence/('functional-'+f.name),os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600),'wb')as dst:dst.write(raw);dst.flush();os.fsync(dst.fileno())
 save('proof.json',proof);print(json.dumps({'ok':proof['ok'],'base':str(base),'proof_sha256':sha(evidence/'proof.json'),'source_inputs_sha256':SOURCE,'architecture':arch,'Main_changed':False,'all50_commercial':False}),flush=True)
sys.exit(0 if proof['ok']else 1)
