"""Explicit disposable developer-image preparation, preserving original metadata.

Actions' /usr/share is Root-owned 0777 on both current native images. Protect
that existing directory without changing child owners, data, links or product
guards. Never invoke on Main or retained hosts.
"""
import hashlib,json,os,platform,stat,sys
from pathlib import Path
os.umask(0o077)
assert os.geteuid()==os.getegid()==0 and os.environ.get('GITHUB_ACTIONS')=='true'and os.environ.get('GITHUB_REPOSITORY')=='yunzhanlin/yunzhan-apps'
assert Path('/proc/1/comm').read_text().strip()=='systemd'and 'VERSION_ID="24.04"'in Path('/etc/os-release').read_text()
assert platform.machine()in('x86_64','aarch64')
private=Path(sys.argv[1]);assert private.is_dir()and not(private/'explicit-pm2-ephemeral-host-share-protection.json').exists()
plan=json.loads((Path(__file__).resolve().parent/'cohort.json').read_bytes());assert json.loads(Path('/opt/panel/current/SOURCE_INPUTS.json').read_bytes())['inputs_sha256']==plan['source_inputs_sha256']
assert not Path('/opt/panel/app-modules/pm2').exists()and not Path('/etc/panel/security-apps/modules/pm2-manager/installed.json').exists()
def identity(s):return(s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
p=Path('/usr/share');before=p.lstat();assert stat.S_ISDIR(before.st_mode)and before.st_uid==0 and stat.S_IMODE(before.st_mode)in(0o755,0o775,0o777)
for name in('/','/usr'):
 s=Path(name).lstat();assert stat.S_ISDIR(s.st_mode)and s.st_uid==0 and not s.st_mode&0o022
children={f.name:identity(f.lstat())for f in p.iterdir()}
original={'path':str(p),'identity':identity(before),'mode':stat.S_IMODE(before.st_mode),'child_count':len(children),'children':children,'xattrs':{a:os.getxattr(p,a,follow_symlinks=False).hex()for a in os.listxattr(p,follow_symlinks=False)}}
with(private/'original-pm2-ephemeral-host-share.json').open('x')as f:json.dump(original,f,indent=2)
fd=os.open(p,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
try:
 assert identity(os.fstat(fd))==identity(before)
 if before.st_mode&0o022:os.fchmod(fd,0o755);os.fsync(fd)
 after=os.fstat(fd)
finally:os.close(fd)
assert after.st_dev==before.st_dev and after.st_ino==before.st_ino and after.st_uid==before.st_uid and after.st_gid==before.st_gid and stat.S_IMODE(after.st_mode)==0o755
assert children=={f.name:identity(f.lstat())for f in p.iterdir()}
proof={'ok':True,'fresh_disposable_CI_host_only':True,'Main_changed':False,'path':str(p),'before_identity':identity(before),'after_identity':identity(after),'only_existing_Root_directory_access_mode_tightened':True,'child_count':len(children),'all_direct_child_original_metadata_preserved':True,'original_child_owners_links_and_content_not_changed':True,'product_source_and_Root_checks_unchanged':True,'negative_original_install_receipts_retained_locally':True}
with(private/'explicit-pm2-ephemeral-host-share-protection.json').open('x')as f:json.dump(proof,f,indent=2)
