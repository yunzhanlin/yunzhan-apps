"""Once-only normal signed install and owned static fixtures on disposable CI.

The runner's inactive, unmodified distribution Nginx conffile is retained by
rename before provisioning. This is explicit CI host preparation, never a
production upgrade or an installer bypass; no existing panel is accepted.
"""
import contextlib,hashlib,http.cookiejar,json,os,pathlib,platform,pwd,re,secrets,shutil,sqlite3,stat,subprocess,sys,tarfile,time,urllib.error,urllib.request,zipfile
os.umask(0o077)
assert os.geteuid()==0 and len(sys.argv)==3
assets=pathlib.Path(sys.argv[1]).resolve(strict=True);private=pathlib.Path(sys.argv[2]).resolve(strict=True)
source=pathlib.Path(__file__).resolve().parent;dispatch=json.loads((source/'dispatch.json').read_bytes())
assert os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('GITHUB_REPOSITORY')=='yunzhanlin/yunzhan-apps'
assert pathlib.Path('/proc/1/comm').read_text().strip()=='systemd'
arch={'x86_64':'amd64','aarch64':'arm64'}[platform.machine()]
assert subprocess.check_output(['dpkg','--print-architecture'],text=True).strip()==arch
assert 'ID=ubuntu\n'in pathlib.Path('/etc/os-release').read_text() and 'VERSION_ID="24.04"'in pathlib.Path('/etc/os-release').read_text()
owner=private.stat();runner=pwd.getpwuid(owner.st_uid);assert runner.pw_name=='runner' and owner.st_uid!=0 and stat.S_IMODE(owner.st_mode)==0o700
def sha(p):return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
def save(name,value,public_to_runner=False):
 assert re.fullmatch('[A-Za-z0-9._-]+',name)
 with(private/name).open('x')as f:json.dump(value,f,indent=2,sort_keys=True);f.write('\n');f.flush();os.fsync(f.fileno())
 if public_to_runner:os.chown(private/name,owner.st_uid,owner.st_gid)
def native_fixed_path_observation(label):
 paths={'/'}
 for name in ('/var/cache/panel-runtime-build','/var/cache/panel-analytics-html-build','/var/lib/panel-network-ids','/opt/panel/network-rule-feeds','/var/cache/panel-apache-body-build','/var/cache/panel-apache-body','/var/lib/panel-apache-body','/var/lib/panel-executor/apache-body-builds','/var/lib/panel-executor/apache-body-requests','/var/lib/panel-executor/apache-body-cancellations','/opt/panel/app-modules/apache-waf/engines'):
  f=pathlib.Path(name);paths.add(str(f));paths.update(str(p)for p in f.parents)
 result={}
 for name in sorted(paths):
  f=pathlib.Path(name)
  try:
   s=f.lstat();v={'uid':s.st_uid,'gid':s.st_gid,'mode':stat.S_IMODE(s.st_mode),'inode':s.st_ino,'dev':s.st_dev,'links':s.st_nlink,'type':stat.S_IFMT(s.st_mode)}
   v['POSIX_ACL_xattrs']={a:os.getxattr(f,a,follow_symlinks=False).hex()for a in os.listxattr(f,follow_symlinks=False)if a in('system.posix_acl_access','system.posix_acl_default')}
   if stat.S_ISDIR(s.st_mode)and pathlib.Path('/usr/bin/getfacl').exists():
    r=subprocess.run(['/usr/bin/getfacl','-p','-n',name],stdin=subprocess.DEVNULL,capture_output=True,timeout=5);assert len(r.stdout)<65536 and len(r.stderr)<65536;v['getfacl']={'exit':r.returncode,'stdout':r.stdout.decode(),'stderr':r.stderr.decode()}
   result[name]=v
  except FileNotFoundError:result[name]={'exists':False}
 save(label+'-original-native-fixed-paths.json',result)

def original_fixed_service_observation(label):
 units=('panel.service','panel-executor.service','panel-compose-recovery.service','panel-firewall.service','panel-nginx-recovery.service','panel-firewall-recovery.service','panel-terminal.service','panel-terminal-root.service','panel-mysql-overwrite-recovery.service','nginx.service','ssh.service','fail2ban.service')
 result={}
 for name in units:
  r=subprocess.run(['/usr/bin/systemctl','show',name,'--property=Id,LoadState,ActiveState,SubState,MainPID,ExecMainStatus,Result,NeedDaemonReload,InvocationID,ExecCondition,ExecStart,ExecStartPre,FragmentPath,DropInPaths,User,Group,CapabilityBoundingSet,NoNewPrivileges'],stdin=subprocess.DEVNULL,capture_output=True,timeout=10)
  assert len(r.stdout)<1<<20 and len(r.stderr)<1<<16;result[name]={'exit':r.returncode,'stdout':r.stdout.decode(),'stderr':r.stderr.decode()}
  prefix=label+'-'+name+'-original-journal'
  with(private/(prefix+'.stdout')).open('xb')as out,(private/(prefix+'.stderr')).open('xb')as err:
   jr=subprocess.run(['/usr/bin/journalctl','--no-pager','-b','-u',name,'-n','200','-o','json'],stdin=subprocess.DEVNULL,stdout=out,stderr=err,timeout=15)
  assert(private/(prefix+'.stdout')).stat().st_size<4<<20 and(private/(prefix+'.stderr')).stat().st_size<1<<16
  save(prefix+'-outcome.json',{'exit':jr.returncode,'stdout_sha256':sha(private/(prefix+'.stdout')),'stderr_sha256':sha(private/(prefix+'.stderr'))})
 save(label+'-original-fixed-service-observation.json',result)

def run_once(name,args,timeout=60):
 if name=='one-normal-original-signed-first-install':native_fixed_path_observation('before-original-normal-install');original_fixed_service_observation('before-original-normal-install')
 save(name+'-intent.json',{'args':args,'maximum_submissions':1})
 with(private/(name+'.stdout')).open('xb')as out,(private/(name+'.stderr')).open('xb')as err:r=subprocess.run(args,stdin=subprocess.DEVNULL,stdout=out,stderr=err,timeout=timeout)
 save(name+'-outcome.json',{'exit':r.returncode,'stdout_sha256':sha(private/(name+'.stdout')),'stderr_sha256':sha(private/(name+'.stderr'))})
 if name=='one-normal-original-signed-first-install':native_fixed_path_observation('after-original-normal-install');original_fixed_service_observation('after-original-normal-install')
 assert r.returncode==0,'Original '+name+' failed; retain private output, never replay'
assert not(private/'normal-preparation-started.json').exists()
save('normal-preparation-started.json',{'architecture':arch,'boot':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'original_outcomes_will_not_be_replayed':True})
assert all(not os.path.lexists(n)for n in('/opt/panel','/var/lib/panel','/var/lib/panel-executor','/etc/panel-release','/etc/panel','/etc/fail2ban','/usr/bin/fail2ban-client','/var/lib/fail2ban'))
# CI downloads are owned by the unprivileged runner. Preserve those original
# inputs and copy their independently pinned bytes into a new Root private tree.
# The original verifier and installer keep their Root ownership checks intact.
assert os.getegid()==0
input_archive=dispatch['cohorts'][arch]['archive']
expected_inputs={name:dispatch['release_assets'][name] for name in [input_archive+suffix for suffix in ('','.manifest','.sig')]+['release-signing-dev.pub']}
expected_inputs['signed-release.py']={'sha256':'fe128e82b4e11345b320cd782134768bfe1a4df14947c425d7494873a7a7b7b5','bytes':(source/'original-signed-release.py').stat().st_size}
browser_input=json.loads((source/'browser-pins.json').read_bytes())[arch]
expected_inputs['chromium.zip']={'sha256':browser_input['sha256'],'bytes':browser_input['bytes']}
assert {x.name for x in assets.iterdir()}==set(expected_inputs)
root_inputs=pathlib.Path('/var/lib/c66-ci-verified-inputs-'+secrets.token_hex(16));root_inputs.mkdir(mode=0o700)
copied={}
def input_identity(s):return(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
for name,pin in sorted(expected_inputs.items()):
 assert re.fullmatch('[A-Za-z0-9._-]+',name)and 0<pin['bytes']<512<<20
 original=assets/name;s=original.lstat();assert stat.S_ISREG(s.st_mode)and s.st_nlink==1 and s.st_uid==owner.st_uid and not s.st_mode&0o022 and s.st_size==pin['bytes']
 fd=os.open(original,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC);h=hashlib.sha256();size=0
 with os.fdopen(fd,'rb')as src,os.fdopen(os.open(root_inputs/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600),'wb')as dst:
  assert input_identity(os.fstat(src.fileno()))==input_identity(s)
  while True:
   b=src.read(1<<20)
   if not b:break
   size+=len(b);assert size<=pin['bytes'];h.update(b);dst.write(b)
  assert input_identity(os.fstat(src.fileno()))==input_identity(s)and size==pin['bytes']and h.hexdigest()==pin['sha256'];dst.flush();os.fsync(dst.fileno())
 st=(root_inputs/name).lstat();assert stat.S_ISREG(st.st_mode)and st.st_uid==st.st_gid==0 and st.st_nlink==1 and stat.S_IMODE(st.st_mode)==0o600 and sha(root_inputs/name)==pin['sha256']
 copied[name]={'source_uid':s.st_uid,'source_inode':s.st_ino,'uid':st.st_uid,'gid':st.st_gid,'mode':stat.S_IMODE(st.st_mode),'inode':st.st_ino,'bytes':size,'sha256':h.hexdigest()}
save('original-Root-owned-verified-inputs-preparation.json',{'original_downloads_preserved':True,'original_installer_owner_check_unchanged':True,'root':str(root_inputs),'inputs':copied})
assets=root_inputs

assert sha(assets/'signed-release.py')=='fe128e82b4e11345b320cd782134768bfe1a4df14947c425d7494873a7a7b7b5'
assert sha(assets/'release-signing-dev.pub')=='4ccfcc861d56a41e3ba7f7ace7e2432c815f366c58448d783df92c6632f01339'
for port in(80,443,19100,19101,19102,19443):assert subprocess.check_output(['ss','-H','-ltn','sport = :'+str(port)])==b''
# This disposable Actions host is a developer image. Keep original metadata
# and require ordinary Root ancestors. Only a Root-owned writable /opt may be
# explicitly tightened for this CI installation; no existing content, owner,
# link, or installer guard is changed. This is never used on retained hosts.
layout={}
for name in('/','/var','/var/cache','/var/lib','/opt'):
 f=pathlib.Path(name);s=f.lstat();layout[name]={'uid':s.st_uid,'gid':s.st_gid,'mode':stat.S_IMODE(s.st_mode),'inode':s.st_ino,'dev':s.st_dev,'links':s.st_nlink,'ordinary_directory':stat.S_ISDIR(s.st_mode)}
save('original-ephemeral-host-ancestor-layout.json',layout)
for name,v in layout.items():
 assert v['ordinary_directory']and v['uid']==0,(name,v)
 if name!='/opt':assert not v['mode']&0o022,(name,v)
opt=pathlib.Path('/opt');old_opt=layout['/opt'];children={f.name:input_identity(f.lstat())for f in opt.iterdir()}
if old_opt['mode']&0o022:
 assert old_opt['mode']in(0o775,0o777)
 fd=os.open(opt,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  st=os.fstat(fd);assert st.st_ino==old_opt['inode']and st.st_dev==old_opt['dev']and st.st_uid==0 and stat.S_IMODE(st.st_mode)==old_opt['mode'];os.fchmod(fd,0o755);os.fsync(fd)
 finally:os.close(fd)
st=opt.lstat();assert st.st_ino==old_opt['inode']and st.st_dev==old_opt['dev']and st.st_uid==old_opt['uid']and st.st_gid==old_opt['gid']and not st.st_mode&0o022
assert children=={f.name:input_identity(f.lstat())for f in opt.iterdir()}
save('explicit-ephemeral-host-opt-protection.json',{'before':old_opt,'after':{'uid':st.st_uid,'gid':st.st_gid,'mode':stat.S_IMODE(st.st_mode),'inode':st.st_ino,'dev':st.st_dev},'direct_children_original_metadata_preserved':True,'child_count':len(children),'existing_content_owners_links_and_installer_guards_unchanged':True,'fresh_disposable_CI_host_only':True,'Main_changed':False})


# Use the original real-host preflight while this disposable image still has
# its original writable default ACL, after its existing access mode was
# protected by the explicit CI setup above. Never add or weaken a host ACL.
negative_archive=assets/dispatch['cohorts'][arch]['archive']
for suffix in('','.manifest','.sig'):
 item=pathlib.Path(str(negative_archive)+suffix);pin=dispatch['release_assets'][item.name];assert sha(item)==pin['sha256']and item.stat().st_size==pin['bytes']
negative_signer=['/usr/bin/python3','-I','-B',str(assets/'signed-release.py')]
negative_key=['--public-key',str(assets/'release-signing-dev.pub')]
negative_args=negative_signer+['install',str(negative_archive)]+negative_key+['--preflight-only']
def negative_host_state(label):
 opt=pathlib.Path('/opt');st=opt.lstat()
 assert stat.S_ISDIR(st.st_mode)and st.st_uid==st.st_gid==0 and stat.S_IMODE(st.st_mode)==0o755
 raw=os.getxattr(opt,'system.posix_acl_default',follow_symlinks=False)
 assert raw.hex()=='0200000001000700ffffffff02000700e903000004000700ffffffff10000700ffffffff20000700ffffffff'
 native_fixed_path_observation(label)
 paths=json.loads((private/(label+'-original-native-fixed-paths.json')).read_bytes())
 return {'parent':[st.st_dev,st.st_ino,st.st_mode,st.st_uid,st.st_gid,st.st_nlink,st.st_size,str(st.st_mtime_ns),str(st.st_ctime_ns)],'default_ACL_hex':raw.hex(),'opt_children':{f.name:input_identity(f.lstat())for f in opt.iterdir()},'fixed_paths':paths,'NSS':{n:sha(pathlib.Path('/etc')/n)for n in('passwd','group','shadow','gshadow')},'dpkg_status_sha256':sha('/var/lib/dpkg/status')}
negative_before=negative_host_state('C68r3-before-original-negative-ACL-preflight')
assert negative_before['fixed_paths']['/opt/panel']=={'exists':False}and negative_before['fixed_paths']['/var/lib/panel-executor']=={'exists':False}
save('C68r3-original-signed-inherited-ACL-negative-preflight-intent.json',{'args':negative_args,'maximum_submissions':1,'root_fixture_only':False,'actual_real_host_original_preflight':True,'actual_real_host_install_acceptance_separate':True,'original_host_default_ACL_not_added_or_weakened':True,'before':negative_before})
with(private/'C68r3-original-signed-inherited-ACL-negative-preflight.stdout').open('xb')as nout,(private/'C68r3-original-signed-inherited-ACL-negative-preflight.stderr').open('xb')as nerr:
 negative_result=subprocess.run(negative_args,stdin=subprocess.DEVNULL,stdout=nout,stderr=nerr,timeout=120)
save('C68r3-original-signed-inherited-ACL-negative-preflight-outcome.json',{'exit':negative_result.returncode,'stdout_sha256':sha(private/'C68r3-original-signed-inherited-ACL-negative-preflight.stdout'),'stderr_sha256':sha(private/'C68r3-original-signed-inherited-ACL-negative-preflight.stderr')})
negative_after=negative_host_state('C68r3-after-original-negative-ACL-preflight')
negative_error=(private/'C68r3-original-signed-inherited-ACL-negative-preflight.stderr').read_text()
assert negative_result.returncode==1 and 'native build cache parent default ACL would inherit writable permissions; not repaired'in negative_error
assert negative_before==negative_after
save('C68r3-original-signed-inherited-ACL-negative-preflight-qualified.json',{'ok':True,'uid':os.geteuid(),'gid':os.getegid(),'architecture':arch,'source_inputs_sha256':dispatch['source_inputs_sha256'],'archive_sha256':sha(negative_archive),'original_exit':negative_result.returncode,'original_ACL_parent_and_empty_target_namespaces_NSS_and_dpkg_preserved':True,'actual_real_host_original_preflight':True,'before':negative_before,'after':negative_after,'normal_real_host_first_install_still_pending':True})

# Original QA6 proves the Actions image carries a writable inherited ACL on
# /opt, even after its access mode is tightened. Retain that exact developer
# image ACL then remove only this default on the otherwise empty target's
# fixed Root parent. Existing descendants and their ACLs are untouched.
import struct
acl_opt=pathlib.Path('/opt');acl_before=acl_opt.lstat();assert stat.S_ISDIR(acl_before.st_mode)and acl_before.st_uid==0 and stat.S_IMODE(acl_before.st_mode)==0o755 and not os.path.lexists('/opt/panel')
acl_children={f.name:input_identity(f.lstat())for f in acl_opt.iterdir()}
fd=os.open(acl_opt,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
try:
 assert input_identity(os.fstat(fd))==input_identity(acl_before)
 original_acl={n:os.getxattr(fd,n).hex()for n in os.listxattr(fd)if n in('system.posix_acl_access','system.posix_acl_default')}
 save('original-fresh-CI-opt-default-ACL-retained.json',{'path':'/opt','uid':acl_before.st_uid,'gid':acl_before.st_gid,'inode':acl_before.st_ino,'dev':acl_before.st_dev,'mode':stat.S_IMODE(acl_before.st_mode),'original_POSIX_ACLs_hex':original_acl,'existing_child_count':len(acl_children),'fresh_disposable_CI_host_only':True})
 if 'system.posix_acl_default'in original_acl:
  raw=bytes.fromhex(original_acl['system.posix_acl_default']);assert len(raw)==44 and struct.unpack_from('<I',raw)[0]==2
  entries=[struct.unpack_from('<HHI',raw,n)for n in range(4,len(raw),8)]
  assert entries==[(1,7,0xffffffff),(2,7,owner.st_uid),(4,7,0xffffffff),(16,7,0xffffffff),(32,7,0xffffffff)],'Unexpected default ACL, retain without alteration'
  os.removexattr(fd,'system.posix_acl_default');os.fsync(fd)
 after_acl={n:os.getxattr(fd,n).hex()for n in os.listxattr(fd)if n in('system.posix_acl_access','system.posix_acl_default')}
 assert after_acl=={n:v for n,v in original_acl.items()if n!='system.posix_acl_default'}
 st=os.fstat(fd);assert (st.st_dev,st.st_ino,st.st_mode,st.st_uid,st.st_gid,st.st_nlink)==(acl_before.st_dev,acl_before.st_ino,acl_before.st_mode,acl_before.st_uid,acl_before.st_gid,acl_before.st_nlink)
finally:os.close(fd)
assert acl_children=={f.name:input_identity(f.lstat())for f in acl_opt.iterdir()}
save('explicit-fresh-CI-opt-default-ACL-protection.json',{'ok':True,'only_removed_default_ACL':True,'original_default_ACL_retained':True,'Root_access_mode_and_owner_inode_preserved':True,'all_original_direct_children_metadata_preserved':True,'existing_descendant_ACLs_not_modified':True,'after_POSIX_ACLs_hex':after_acl,'Main_changed':False})

original=pathlib.Path('/etc/nginx/nginx.conf');s=original.lstat()
assert stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o644
nginx=subprocess.check_output(['systemctl','show','nginx.service','--property=ActiveState,SubState,MainPID'],text=True)
assert 'ActiveState=inactive\n'in nginx and 'MainPID=0\n'in nginx
conffiles=subprocess.check_output(['dpkg-query','-W','-f=${Conffiles}','nginx-common'],text=True)
expected=[row.split()[1]for row in conffiles.splitlines()if row.split()and row.split()[0]=='/etc/nginx/nginx.conf']
assert len(expected)==1 and hashlib.md5(original.read_bytes()).hexdigest()==expected[0]
retained=pathlib.Path('/var/lib/c66-ci-original-platform-'+secrets.token_hex(16));retained.mkdir(mode=0o700)
before={'sha256':sha(original),'uid':s.st_uid,'gid':s.st_gid,'inode':s.st_ino,'mode':stat.S_IMODE(s.st_mode),'dev':s.st_dev,'nginx_unit':nginx,'distribution_conffile_MD5':expected[0]}
os.rename(original,retained/'stock-nginx.conf')
assert sha(retained/'stock-nginx.conf')==before['sha256'] and(retained/'stock-nginx.conf').stat().st_ino==before['inode']
save('original-distribution-Nginx-config-retained.json',{'retained':str(retained/'stock-nginx.conf'),'before':before,'inactive_CI_image_configuration_only':True,'original_bytes_and_inode_preserved':True})
# The ephemeral developer image may have no server host keys or active SSH
# runtime, whereas normal Linux servers already provide both. Preserve every
# existing key's metadata and config bytes; only generate missing host keys
# using the distribution command, then start its standard service once.
# Private host-key bytes are never read into or exported by this QA observer.
def ssh_key_metadata():
 result={}
 for f in sorted(pathlib.Path('/etc/ssh').glob('ssh_host_*_key*')):
  s=f.lstat();assert stat.S_ISREG(s.st_mode)and s.st_uid==0 and s.st_nlink==1 and not s.st_mode&0o022
  v={'uid':s.st_uid,'gid':s.st_gid,'mode':stat.S_IMODE(s.st_mode),'inode':s.st_ino,'dev':s.st_dev,'bytes':s.st_size,'mtime_ns':s.st_mtime_ns,'ctime_ns':s.st_ctime_ns}
  if f.name.endswith('.pub'):v['public_sha256']=sha(f)
  result[str(f)]=v
 return result
ssh_original_keys=ssh_key_metadata()
ssh_original_config={str(f):{'sha256':sha(f),'inode':f.lstat().st_ino,'mode':stat.S_IMODE(f.lstat().st_mode),'uid':f.lstat().st_uid,'gid':f.lstat().st_gid}for f in [pathlib.Path('/etc/ssh/sshd_config'),*sorted(pathlib.Path('/etc/ssh/sshd_config.d').glob('*.conf'))]}
probe=subprocess.run(['/usr/sbin/sshd','-T'],stdin=subprocess.DEVNULL,capture_output=True,timeout=10)
assert len(probe.stdout)<1<<20 and len(probe.stderr)<1<<16
save('original-platform-SSH-readonly-probe.json',{'exit':probe.returncode,'stderr_utf8':probe.stderr.decode(errors='replace'),'effective_configuration_sha256':hashlib.sha256(probe.stdout).hexdigest(),'existing_key_metadata_only':ssh_original_keys,'existing_configuration_metadata':ssh_original_config})
run_once('explicit-fresh-CI-generate-only-missing-host-keys',['/usr/bin/ssh-keygen','-A'])
ssh_after_keys=ssh_key_metadata();assert all(ssh_after_keys[n]==v for n,v in ssh_original_keys.items())
run_once('explicit-fresh-CI-start-distribution-SSH-once',['/usr/bin/systemctl','start','ssh.service'],30)
run_once('explicit-fresh-CI-SSH-effective-configuration',['/usr/sbin/sshd','-T'])
ssh_lifetime=subprocess.check_output(['/usr/bin/systemctl','show','ssh.service','--property=ActiveState,SubState,MainPID,InvocationID'],text=True)
assert 'ActiveState=active\n'in ssh_lifetime and 'SubState=running\n'in ssh_lifetime
assert ssh_original_config=={str(f):{'sha256':sha(f),'inode':f.lstat().st_ino,'mode':stat.S_IMODE(f.lstat().st_mode),'uid':f.lstat().st_uid,'gid':f.lstat().st_gid}for f in [pathlib.Path('/etc/ssh/sshd_config'),*sorted(pathlib.Path('/etc/ssh/sshd_config.d').glob('*.conf'))]}
save('explicit-fresh-CI-SSH-readiness.json',{'ok':True,'distribution_SSH_lifetime':ssh_lifetime,'original_configuration_and_existing_host_key_metadata_preserved':True,'new_key_filenames':sorted(set(ssh_after_keys)-set(ssh_original_keys)),'private_host_key_bytes_exported':False,'fresh_disposable_CI_host_only':True,'Main_changed':False})

archive=assets/dispatch['cohorts'][arch]['archive']
for suffix in('','.manifest','.sig'):
 f=pathlib.Path(str(archive)+suffix);pin=dispatch['release_assets'][f.name];assert sha(f)==pin['sha256'] and f.stat().st_size==pin['bytes']
signer=['/usr/bin/python3','-I','-B',str(assets/'signed-release.py')];key=['--public-key',str(assets/'release-signing-dev.pub')]
run_once('original-programme-signature-verify',signer+['verify',str(archive)]+key)

run_once('one-normal-first-install-preflight',signer+['install',str(archive)]+key+['--preflight-only'],900)
run_once('one-normal-original-signed-first-install',signer+['install',str(archive)]+key,1800)
assert not pathlib.Path('/opt/panel/DEVELOPMENT_RELEASE').exists()
version=dispatch['version'];installed=pathlib.Path('/opt/panel/current').resolve(strict=True)
assert installed==pathlib.Path('/opt/panel/releases')/version
archive_root=archive.name[:-7]
with tarfile.open(archive)as tar:
 original_inputs=json.loads(tar.extractfile(archive_root+'/SOURCE_INPUTS.json').read())
 assert original_inputs['inputs_sha256']==dispatch['source_inputs_sha256']
 checked={}
 for member in tar:
  n=pathlib.PurePosixPath(member.name)
  name=str(n.relative_to(archive_root));target=installed/name
  st=target.lstat();assert st.st_uid==0 and stat.S_IMODE(st.st_mode)==member.mode
  if member.isfile():
   raw=tar.extractfile(member).read();assert stat.S_ISREG(st.st_mode)and st.st_nlink==1 and target.read_bytes()==raw
   checked[name]={'type':'file','sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw),'mode':stat.S_IMODE(st.st_mode)}
  else:assert member.isdir()and stat.S_ISDIR(st.st_mode);checked[name]={'type':'directory','mode':stat.S_IMODE(st.st_mode)}
 assert 'bin/panel'in checked and 'bin/panel-executor'in checked and 'web/index.html'in checked and len(checked)==204
 assert {'.'}|{str(f.relative_to(installed))for f in installed.rglob('*')}==set(checked)
save('original-installed-programme-bytes.json',checked)
# Anonymous ordinary TLS observations only; never change the product transport,
# credentials, DNS, certificates, catalogue or application installation policy.
observer='/usr/local/libexec/c68r3-original-store-transport'
st=pathlib.Path(observer).lstat();assert stat.S_ISREG(st.st_mode) and st.st_uid==st.st_gid==0 and stat.S_IMODE(st.st_mode)==0o755 and st.st_nlink==1
save('original-installed-panel-transport-observer.json',{'sha256':sha(observer),'product_transport_or_trust_changed':False})
original_unit=subprocess.run(['/usr/bin/systemctl','show','panel.service','--property=User,Group,MainPID,ActiveState,SubState,NoNewPrivileges,PrivateTmp,ProtectHome,ProtectSystem,RestrictAddressFamilies,EnvironmentFiles'],stdin=subprocess.DEVNULL,capture_output=True,text=True,timeout=10)
save('original-installed-panel-transport-unit.json',{'exit':original_unit.returncode,'stdout':original_unit.stdout,'stderr':original_unit.stderr})
assert original_unit.returncode==0 and 'User=panel\n' in original_unit.stdout and 'ActiveState=active\n' in original_unit.stdout
panel_user=pwd.getpwnam('panel')
for observer_label,observer_args in [
 ('original-after-install-root-HTTPS-observer',['/usr/bin/env','-i','PATH=/usr/sbin:/usr/bin:/sbin:/bin',observer]),
 ('original-after-install-panel-user-HTTPS-observer',['/usr/bin/setpriv','--reuid='+str(panel_user.pw_uid),'--regid='+str(panel_user.pw_gid),'--clear-groups','--no-new-privs','/usr/bin/env','-i','PATH=/usr/sbin:/usr/bin:/sbin:/bin',observer])]:
 save(observer_label+'-intent.json',{'args':observer_args,'maximum_submissions':1,'only_anonymous_GETs_and_ordinary_certificate_verification':True})
 with(private/(observer_label+'.stdout')).open('xb')as obsout,(private/(observer_label+'.stderr')).open('xb')as obserr:
  observed=subprocess.run(observer_args,stdin=subprocess.DEVNULL,stdout=obsout,stderr=obserr,timeout=45)
 save(observer_label+'-outcome.json',{'exit':observed.returncode,'stdout_sha256':sha(private/(observer_label+'.stdout')),'stderr_sha256':sha(private/(observer_label+'.stderr'))})
 assert observed.returncode==0
 original_observer=json.loads((private/(observer_label+'.stdout')).read_bytes())
 assert original_observer['uid']==(0 if observer_label=='original-after-install-root-HTTPS-observer'else panel_user.pw_uid) and original_observer['no_credentials_or_env_values_logged']
 assert len(original_observer['results'])==3
 # Preserve ordinary network failures; the real product store response below
 # remains the acceptance condition rather than this independent observation.

origin='http://127.0.0.1:19100';csrf='';client=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
def api(label,path,body=None,expected_status=200):
 headers={'Origin':origin,'Content-Type':'application/json','X-CSRF-Token':csrf}
 if body is not None:headers['Idempotency-Key']=secrets.token_hex(16);save(label+'-intent.json',{'path':path,'maximum_POSTs':1,'body':'existing owned credentials omitted'if path=='/login'else body})
 request=urllib.request.Request(origin+'/api'+path,data=None if body is None else json.dumps(body).encode(),headers=headers)
 try:
  with client.open(request,timeout=80)as response:status=response.status;raw=response.read((8<<20)+1)
 except urllib.error.HTTPError as error:status=error.code;raw=error.read((8<<20)+1)
 assert len(raw)<=8<<20;value=json.loads(raw)
 save(label+'-response.json',{'status':status,'value':{'csrf_issued':bool(value.get('csrf'))}if path=='/login'else value})
 assert status==expected_status,(label,status)
 return value
def wait_job(label,identity,table):
 assert table in('jobs','runtime_jobs') and re.fullmatch('[0-9a-f]{32}',identity)
 observations=[];end=time.monotonic()+300
 while True:
  with contextlib.closing(sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True))as db:
   db.row_factory=sqlite3.Row;db.execute('PRAGMA query_only=ON');row=dict(db.execute('SELECT *FROM '+table+' WHERE id=?',(identity,)).fetchone())
  observations.append({'state':row['state'],'at':time.time()})
  if row['state']not in('queued','running'):break
  assert time.monotonic()<end,'Original job unresolved; observe only'
  time.sleep(.5)
 save(label+'-observations.json',observations);save(label+'-terminal.json',row)
 assert row['state']=='succeeded' and row['error']==''
 return row
credentials=pathlib.Path('/etc/panel/first-login.json');st=credentials.lstat();assert stat.S_ISREG(st.st_mode)and st.st_uid==0 and st.st_nlink==1 and stat.S_IMODE(st.st_mode)==0o600
access=json.loads(credentials.read_bytes());csrf=api('one-setup-login','/login',{k:access[k]for k in('username','password')})['csrf']
# Only catalogue GET acquisition may be repeated. Every original failed
# response is retained; no install, authentication or site mutation is replayed.
catalog=None
for attempt in range(1,7):
 label='original-signed-catalogue-attempt-'+str(attempt)
 try:catalog=api(label,'/app-registry?refresh=1')
 except AssertionError:
  outcome=json.loads((private/(label+'-response.json')).read_bytes())
  assert outcome['status']==503 and isinstance(outcome['value'].get('error'),str)and outcome['value']['error'].startswith('加载已签名应用目录失败:'),'Original non-acquisition refusal is never retried'
  if attempt==6:raise
  time.sleep(min(4,attempt))
  continue
 assert len(catalog['catalog']['apps'])==50 and not catalog['source']['stale']
 save('original-signed-catalogue-response.json',json.loads((private/(label+'-response.json')).read_bytes()))
 save('original-signed-catalogue-readonly-acquisition.json',{'ok':True,'GET_attempts':attempt,'failed_original_responses_retained':attempt-1,'auth_or_install_POSTs_replayed':0,'TLS_and_signature_verification_unchanged':True})
 break
assert catalog is not None
app=next(a for a in catalog['catalog']['apps']if a['id']=='website-analytics');assert app['version']=='2.4.2' and app['sha256']==dispatch['analytics242_sha256']
job=api('one-signed-analytics242-install','/app-registry/website-analytics/install',{'expected_version':app['version'],'expected_sha256':app['sha256']},202)
wait_job('one-signed-analytics242-install',job['job_id'],'runtime_jobs')
module=pathlib.Path('/etc/panel/security-apps/modules/website-analytics/installed.json');assert json.loads(module.read_bytes())['version']=='2.4.2'
# Complete the normal successful installation's receipt reconciliation and
# distribution discovery through ordinary authenticated read APIs before the
# preservation baseline. No install, job, account or website POST is replayed.
installed_job=job['job_id']
def registry_inventory_rows():
 with contextlib.closing(sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True))as db:
  db.row_factory=sqlite3.Row;db.execute('PRAGMA query_only=ON');db.execute('BEGIN')
  result={name:[dict(r)for r in db.execute('SELECT *FROM '+name)]for name in('app_registry_pending','app_registry_receipts','runtime_versions','runtime_installations','runtime_instances')}
  result['original_job']=dict(db.execute('SELECT *FROM runtime_jobs WHERE id=?',(installed_job,)).fetchone());db.rollback();return result
original_inventory=registry_inventory_rows();save('original-installed-before-receipt-and-probe.json',original_inventory)
assert original_inventory['original_job']['state']=='succeeded'and len(original_inventory['app_registry_pending'])==1 and not original_inventory['app_registry_receipts']
pending=original_inventory['app_registry_pending'][0]
assert pending['job_id']==installed_job and pending['app_id']==pending['scope']==pending['target']=='website-analytics'and pending['provider']=='panel-module'and pending['version']=='2.4.2'and pending['sha256']==app['sha256']
api('one-normal-existing-install-receipt-reconciliation','/app-registry')
api('one-normal-distribution-runtime-discovery','/runtimes')
settled=registry_inventory_rows();save('original-installed-after-receipt-and-probe.json',settled)
assert settled['original_job']==original_inventory['original_job']and not settled['app_registry_pending']and len(settled['app_registry_receipts'])==1
receipt=settled['app_registry_receipts'][0]
assert {k:receipt[k]for k in('app_id','scope','version','sha256','target')}=={k:pending[k]for k in('app_id','scope','version','sha256','target')}
assert not original_inventory['runtime_versions']and not original_inventory['runtime_installations']and not original_inventory['runtime_instances']
assert len(settled['runtime_versions'])==len(settled['runtime_installations'])==len(settled['runtime_instances'])==1
distribution_version=subprocess.check_output(['/usr/bin/dpkg-query','-W','-f=${Version}','nginx'],text=True).strip();version_id=hashlib.sha256(('nginx:'+distribution_version).encode()).hexdigest()[:32]
assert settled['runtime_versions'][0]=={'id':version_id,'family':'nginx','version':distribution_version,'channel':'distribution','source_url':'https://packages.ubuntu.com/noble/nginx','verification':'verified_base'}
installation=settled['runtime_installations'][0]
assert {k:installation[k]for k in('id','version_id','binary_path','architecture','status')}=={'id':'nginx-system','version_id':version_id,'binary_path':'/usr/sbin/nginx','architecture':arch,'status':'installed'}
assert settled['runtime_instances'][0]=={'id':'nginx-ingress','installation_id':'nginx-system','family':'nginx','name':'development-ingress','service_name':'nginx','port':19101,'socket_path':None,'data_dir':None,'config_path':'/etc/nginx/nginx.conf'}
save('original-install-receipt-and-distribution-probe-qualified.json',{'ok':True,'original_completed_install_job':installed_job,'original_signed_analytics242_sha256':app['sha256'],'original_job_unchanged':True,'only_same_succeeded_job_pending_converted_to_exact_receipt':True,'only_existing_distribution_Nginx_discovered':True,'actual_distribution_version':distribution_version,'actual_version_id':version_id,'additional_installs_or_job_submissions_or_account_changes':0,'Core_source_receipts':'internal/core/app_registry_receipts.go','Core_source_inventory':'internal/core/store.go RecordNginxInventory; internal/core/http.go runtimes'})

nonce=secrets.token_hex(16);slug='c66-native-'+arch+'-'+nonce[:12];domain=slug+'.localhost'
job=api('one-owned-static-site','/sites',{'name':'C66 '+arch+' real BFCache and heatmap','slug':slug,'domain':domain,'php_version_id':''},202)
site=wait_job('one-owned-static-site',job['job_id'],'jobs')['site_id'];assert re.fullmatch('[0-9a-f]{32}',site)
config=api('new-owned-analytics-config','/analytics/sites/'+site+'/config');assert config['revision']==0 and not config['enabled']
job=api('one-owned-collector-enable','/analytics/sites/'+site+'/config',{'enabled':True,'clicks':True,'retention_days':30,'revision':0,'auto_inject_html':False},202)
wait_job('one-owned-collector-enable',job['job_id'],'jobs');config=api('original-enabled-config','/analytics/sites/'+site+'/config')
assert config['enabled']and config['clicks']and config['revision']==1 and config['client_address_mode']=='managed_proxy'
observer='''"use strict";(()=>{const s={document_instance:crypto.randomUUID(),shows:0,restored_shows:0,last_pageshow_persisted:null,last_pagehide_persisted:null,trusted_clicks:0,history:[]};const draw=()=>{document.getElementById("c66-state").textContent=JSON.stringify(s)};window.addEventListener("pageshow",e=>{s.shows++;s.last_pageshow_persisted=e.persisted;if(e.persisted)s.restored_shows++;s.history.push({event:"pageshow",persisted:e.persisted});draw()});window.addEventListener("pagehide",e=>{s.last_pagehide_persisted=e.persisted;s.history.push({event:"pagehide",persisted:e.persisted});draw()});document.addEventListener("click",e=>{if(e.isTrusted){s.trusted_clicks++;draw()}});document.getElementById("native-back").onclick=()=>history.back();document.getElementById("native-forward").onclick=()=>history.forward();draw()})();'''
files={'observer.js':observer,'finish.html':'<!doctype html><html><head><meta charset="utf-8"><title>Owned native collection complete</title></head><body>Collection complete</body></html>'}
for page,other in(('a','b'),('b','a')):
 files[page+'.html']='<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>C66 '+arch+' '+page+'</title><style>*{box-sizing:border-box}html,body{margin:0;width:100%;height:100%;overflow:hidden}.surface{position:fixed;inset:0;width:100%;height:100%;border:0;background:#e2f2ed}nav{position:fixed;bottom:100px;left:10%;right:10%;display:flex;justify-content:space-between}nav>*{padding:12px;font:16px system-ui}#c66-state{position:fixed;bottom:0;left:0;right:0;font:11px monospace;pointer-events:none;white-space:pre-wrap}input{position:fixed;left:10%;bottom:160px}</style><script defer src="/observer.js"></script><script defer src="/__yunzhan/analytics/tracker.js?site='+site+'&amp;key='+config['key']+'"></script></head><body><button class="surface" id="c66-private-target-'+nonce+'" aria-label="点击坐标画布"></button><input aria-label="隐私测试输入" autocomplete="off"><nav><a href="/'+other+'.html">打开页面 '+other.upper()+'</a><button id="native-back">返回上一页</button><button id="native-forward">前进下一页</button></nav><pre id="c66-state"></pre></body></html>'
for index,(name,text)in enumerate(files.items()):
 value=api('one-fixture-'+str(index),'/sites/'+site+'/files/action',{'action':'create','path':name,'content':text})
 assert value['sha256']==hashlib.sha256(text.encode()).hexdigest()and value['bytes']==len(text.encode())
run_once('original-Nginx-config-check',['/usr/sbin/nginx','-t'])
# Extract only the fixed, independently pinned official browser into a new
# Root-owned tree; the application and original installed archive are untouched.
browser=json.loads((source/'browser-pins.json').read_bytes())[arch]
assert sha(assets/'chromium.zip')==browser['sha256'] and(assets/'chromium.zip').stat().st_size==browser['bytes']
browser_root=pathlib.Path('/opt/yunzhan-c66-ci-browser-'+nonce);browser_root.mkdir(mode=0o755);total=0;seen=set()
with zipfile.ZipFile(assets/'chromium.zip')as archive_zip:
 for member in archive_zip.infolist():
  n=pathlib.PurePosixPath(member.filename);assert not n.is_absolute()and all(x not in('.','..')for x in n.parts)and str(n)not in seen and 1<=len(n.parts)<=8;seen.add(str(n));target=browser_root/str(n)
  if member.is_dir():target.mkdir(mode=0o755,parents=True,exist_ok=True);continue
  mode=member.external_attr>>16;assert stat.S_IFMT(mode)in(0,stat.S_IFREG)and 0<=member.file_size<800<<20
  total+=member.file_size;assert total<1600<<20;target.parent.mkdir(mode=0o755,parents=True,exist_ok=True)
  with archive_zip.open(member)as src,target.open('xb')as dst:shutil.copyfileobj(src,dst,1<<20)
  os.chmod(target,0o755 if mode&0o111 else 0o644)
for root,dirs,names in os.walk(browser_root):os.chmod(root,0o755)
chrome=browser_root/browser['chrome_path'];sandbox=browser_root/browser['sandbox_path']
assert sha(chrome)==browser['chrome_sha256']and sha(sandbox)==browser['sandbox_sha256']
os.chmod(sandbox,0o4755);assert sandbox.stat().st_uid==0 and stat.S_IMODE(sandbox.stat().st_mode)==0o4755
# Ubuntu's AppArmor policy needs an exact-path exception for downloaded
# developer Chrome. Apply the documented per-binary profile only to this new
# Root-owned, digest-pinned browser; no wildcard, global sysctl or service reload.
assert re.fullmatch('/opt/yunzhan-c66-ci-browser-[0-9a-f]{32}/chrome-linux(?:64|-arm64)/chrome',str(chrome))
for f in(chrome,*chrome.parents):
 z=f.lstat();assert z.st_uid==0 and not z.st_mode&0o022 and not stat.S_ISLNK(z.st_mode)
policy_root=pathlib.Path('/etc/apparmor.d');ps=policy_root.lstat();assert stat.S_ISDIR(ps.st_mode)and ps.st_uid==0 and not ps.st_mode&0o022
profiles_file=pathlib.Path('/sys/kernel/security/apparmor/profiles')
before_profiles=profiles_file.read_text();assert 0<len(before_profiles)<4<<20
settings={n:pathlib.Path('/proc/sys/kernel',n).read_text()if pathlib.Path('/proc/sys/kernel',n).exists()else None for n in('apparmor_restrict_unprivileged_userns','apparmor_restrict_unprivileged_unconfined','unprivileged_userns_clone')}
assert settings['apparmor_restrict_unprivileged_userns']=='1\n'
profile_name='yunzhan-c66r2-'+nonce;profile_path=policy_root/profile_name;assert not os.path.lexists(profile_path)and not any(v.startswith(profile_name+' ')for v in before_profiles.splitlines())
profile_text='abi <abi/4.0>,\ninclude <tunables/global>\nprofile '+profile_name+' "'+str(chrome)+'" flags=(unconfined) {\n  userns,\n}\n'
with os.fdopen(os.open(profile_path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600),'w')as stream:
 stream.write(profile_text);stream.flush();os.fsync(stream.fileno())
assert profile_path.lstat().st_uid==profile_path.lstat().st_gid==0 and stat.S_IMODE(profile_path.lstat().st_mode)==0o600
save('original-fresh-CI-browser-AppArmor-profile-before.json',{'original_profiles':before_profiles,'original_global_settings':settings,'new_profile':profile_text,'exact_verified_chrome_sha256':sha(chrome),'only_new_profile_path':str(profile_path),'main_or_retained_guests_changed':False,'reference':'https://chromium.googlesource.com/chromium/src/+/main/docs/security/apparmor-userns-restrictions.md'})
run_once('one-exact-verified-browser-AppArmor-profile-add',['/usr/sbin/apparmor_parser','--add','--skip-cache',str(profile_path)],30)
after_profiles=profiles_file.read_text();added=set(after_profiles.splitlines())-set(before_profiles.splitlines())
assert set(before_profiles.splitlines())<=set(after_profiles.splitlines())and added=={profile_name+' (unconfined)'}
assert settings=={n:pathlib.Path('/proc/sys/kernel',n).read_text()if pathlib.Path('/proc/sys/kernel',n).exists()else None for n in settings}
assert profile_path.read_text()==profile_text and sha(chrome)==browser['chrome_sha256']
save('original-fresh-CI-browser-AppArmor-profile-after.json',{'ok':True,'original_profiles_unchanged':True,'only_added_profile':sorted(added),'all_global_settings_unchanged':settings,'exact_path_only':str(chrome),'browser_sha256':sha(chrome),'new_profile_sha256':sha(profile_path),'global_disable_or_no_sandbox_or_service_reload':False})

# One normal current133 app install on this fresh owned host. The genuine
# original snapshot below is taken after setup; no old baseline is rewritten.
mobile_pins=json.loads((source/'mobile-store-pins.json').read_bytes())
run_once('capture-original-before-mobile133-install',['/usr/bin/python3','-I','-B',str(source/'snapshot.py'),str(private/'original-before-mobile133-install.json')])
mobile_catalog=api('original-mobile133-GitHub-catalogue','/app-registry?refresh=1')
mobile=next(v for v in mobile_catalog['catalog']['apps']if v['id']=='mobile');mobile_status=next(v for v in mobile_catalog['status']if v['id']=='mobile')
assert len(mobile_catalog['catalog']['apps'])==50 and not mobile_catalog['source']['stale']and mobile['version']=='1.3.3'and mobile['sha256']==mobile_pins['mobile_manifest_sha256']and mobile_status['state_known']and not mobile_status['installed']
mobile_root=pathlib.Path('/etc/panel/security-apps/modules/mobile-pwa');assert not os.path.lexists(mobile_root)
mobile_response=api('one-original-signed-mobile133-install','/app-registry/mobile/install',{'expected_version':'1.3.3','expected_sha256':mobile_pins['mobile_manifest_sha256']},202)
mobile_job=wait_job('one-original-signed-mobile133-install',mobile_response['job_id'],'runtime_jobs');assert mobile_job['target_id']=='mobile-pwa'and mobile_job['kind']=='software_install'and json.loads(mobile_job['payload'])=={'settings':None,'version':'1.3.3'}
mobile_record=mobile_root/'installed.json';st=mobile_record.lstat();assert stat.S_ISREG(st.st_mode)and st.st_uid==0 and stat.S_IMODE(st.st_mode)==0o600 and st.st_nlink==1 and not mobile_record.is_symlink();record=json.loads(mobile_record.read_bytes());assert record['version']=='1.3.3'
settled_mobile=api('original-mobile133-normal-receipt-reconciliation','/app-registry');status=next(v for v in settled_mobile['status']if v['id']=='mobile');assert status['state_known']and status['installed_version']=='1.3.3'and not status['update_available']and not settled_mobile['source']['stale']
mobile_report=api('one-original-mobile133-native-delivery-report','/app-modules/mobile-pwa/run',{})
assert mobile_report['version']=='1.3.3'and mobile_report['native_source_inputs_sha256']==mobile_pins['native_source_inputs_sha256']and mobile_report['android_signer_sha256']==mobile_pins['android_signer_sha256']
assert len(mobile_report['mobile_downloads'])==3
for artifact in mobile_report['mobile_downloads']:
 pin=mobile_pins['client_assets'][artifact['filename']];assert artifact['sha256']==pin['sha256']and artifact['url']=='https://github.com/yunzhanlin/yunzhan-apps/releases/download/mobile-v1.3.3/'+artifact['filename']
save('original-mobile133-normal-install-and-report-proof.json',{'ok':True,'architecture':arch,'source_inputs_sha256':dispatch['source_inputs_sha256'],'catalogue_head':mobile_pins['catalogue_head'],'original_install_POSTs':1,'original_report_POSTs':1,'original_job_id':mobile_job['id'],'normal_original_install_version':'1.3.3','original_record_sha256':sha(mobile_record),'original_record_identity':{'dev':st.st_dev,'ino':st.st_ino,'uid':st.st_uid,'gid':st.st_gid,'mode':stat.S_IMODE(st.st_mode),'links':st.st_nlink},'original_manifest_sha256':mobile_pins['mobile_manifest_sha256'],'all_three_original_native_artifact_links_and_digests_verified':True,'source_overlays':0,'Main_changed':False,'all50_commercial':False})

api('original-setup-logout','/logout',{})
save('browser-credentials.json',{k:access[k]for k in('username','password')},True);access.clear();csrf=''
save('browser-setup.json',{'architecture':arch,'site':site,'name':'C66 '+arch+' real BFCache and heatmap','domain':domain,'visitor_origin':'http://'+domain+':19101','panel_origin':origin,'chrome':str(chrome),'sandbox':str(sandbox),'nonce':nonce,'source_inputs_sha256':dispatch['source_inputs_sha256'],'version':version,'browser_version':browser['version'],'stock_Nginx_retained':str(retained/'stock-nginx.conf'),'stock_Nginx_witness':before},True)
warmup=[];deadline=time.monotonic()+120
while True:
 with contextlib.closing(sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True))as db:
  db.execute('PRAGMA query_only=ON');samples=db.execute('SELECT sampled_at,state,error,boot_id,cpu_percent FROM monitor_samples ORDER BY id DESC LIMIT 2').fetchall();metrics={x[0]for x in db.execute('SELECT metric FROM monitor_conditions')}
 warmup.append({'at':time.time(),'samples':samples,'metrics':sorted(metrics)})
 if len(samples)==2 and all(v[1]=='ok'and v[2]==''and v[3]==pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()for v in samples)and samples[0][4]is not None and {'collector','cpu','disk','memory','service:nginx:nginx'}<=metrics:break
 assert time.monotonic()<deadline,'Original native monitoring sample unresolved; retain outcome'
 time.sleep(1)
save('original-native-monitor-warmup.json',warmup)
run_once('capture-original-before-browser',['/usr/bin/python3','-I','-B',str(source/'snapshot.py'),str(private/'original-before-browser.json')])
save('original-preparation-proof.json',{'ok':True,'architecture':arch,'normal_programme_installs':1,'normal_signed_analytics242_installs':1,'normal_owned_site_creates':1,'normal_owned_collector_enables':1,'source_inputs_sha256':dispatch['source_inputs_sha256'],'installed_programme_entries':len(checked),'actual_BFCache_and_narrow_UI_pending':True,'Main_changed':False,'all50_commercial':False})
print(json.dumps({'ok':True,'architecture':arch,'normal_signed_programme_installed':True,'signed_analytics242_installed':True,'owned_site_created':True,'browser_acceptance_pending':True}))
