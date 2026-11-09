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
negative_before=negative_host_state('C69r4-before-original-negative-ACL-preflight')
assert negative_before['fixed_paths']['/opt/panel']=={'exists':False}and negative_before['fixed_paths']['/var/lib/panel-executor']=={'exists':False}
save('C69r4-original-signed-inherited-ACL-negative-preflight-intent.json',{'args':negative_args,'maximum_submissions':1,'root_fixture_only':False,'actual_real_host_original_preflight':True,'actual_real_host_install_acceptance_separate':True,'original_host_default_ACL_not_added_or_weakened':True,'before':negative_before})
with(private/'C69r4-original-signed-inherited-ACL-negative-preflight.stdout').open('xb')as nout,(private/'C69r4-original-signed-inherited-ACL-negative-preflight.stderr').open('xb')as nerr:
 negative_result=subprocess.run(negative_args,stdin=subprocess.DEVNULL,stdout=nout,stderr=nerr,timeout=120)
save('C69r4-original-signed-inherited-ACL-negative-preflight-outcome.json',{'exit':negative_result.returncode,'stdout_sha256':sha(private/'C69r4-original-signed-inherited-ACL-negative-preflight.stdout'),'stderr_sha256':sha(private/'C69r4-original-signed-inherited-ACL-negative-preflight.stderr')})
negative_after=negative_host_state('C69r4-after-original-negative-ACL-preflight')
negative_error=(private/'C69r4-original-signed-inherited-ACL-negative-preflight.stderr').read_text()
assert negative_result.returncode==1 and 'native build cache parent default ACL would inherit writable permissions; not repaired'in negative_error
assert negative_before==negative_after
save('C69r4-original-signed-inherited-ACL-negative-preflight-qualified.json',{'ok':True,'uid':os.geteuid(),'gid':os.getegid(),'architecture':arch,'source_inputs_sha256':dispatch['source_inputs_sha256'],'archive_sha256':sha(negative_archive),'original_exit':negative_result.returncode,'original_ACL_parent_and_empty_target_namespaces_NSS_and_dpkg_preserved':True,'actual_real_host_original_preflight':True,'before':negative_before,'after':negative_after,'normal_real_host_first_install_still_pending':True})

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
