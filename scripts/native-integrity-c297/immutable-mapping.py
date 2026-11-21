"""Native immutable mapping test, synthetic newly owned files only."""
import hashlib,json,os,pathlib,platform,resource,selectors,signal,stat,subprocess,sys,tempfile
os.umask(0o077);assert os.geteuid()==0 and os.environ.get('GITHUB_ACTIONS')=='true'and os.environ.get('GITHUB_REPOSITORY')=='yunzhanlin/yunzhan-apps'and os.environ.get('RUNNER_ENVIRONMENT')=='github-hosted'
out=pathlib.Path(sys.argv[1]).resolve(strict=True);owner=out.stat();assert owner.st_uid!=0 and stat.S_IMODE(owner.st_mode)==0o700
resource.setrlimit(resource.RLIMIT_CORE,(0,0));cases=[]
child_code=r"""import errno,json,mmap,os,resource,sys
resource.setrlimit(resource.RLIMIT_CORE,(0,0));fd=int(sys.argv[1]);variant=sys.argv[2];os.setgroups([]);os.setgid(33);os.setuid(33);assert os.geteuid()==33
status=dict(s.split(':',1)for s in open('/proc/self/status')if ':'in s);assert int(status['CapEff'],16)==int(status['CapPrm'],16)==int(status['CapInh'],16)==int(status['CapAmb'],16)==0
mapped=None
if variant=='mapping-created-before-immutable':
 mapped=mmap.mmap(fd,0,flags=mmap.MAP_SHARED,prot=mmap.PROT_READ|mmap.PROT_WRITE);mapped[0]=65;mapped.flush()
print(json.dumps({'ready':True,'uid':os.geteuid(),'effective_permitted_inheritable_ambient_caps_zero':True}),flush=True)
assert sys.stdin.readline().strip()=='immutable-is-verified'
try:os.pwrite(fd,b'B',0);direct_errno=0
except OSError as e:direct_errno=e.errno
print(json.dumps({'direct_write_errno':direct_errno,'mapping_write_attempt_is_next':True}),flush=True)
try:
 if mapped is None:mapped=mmap.mmap(fd,0,flags=mmap.MAP_SHARED,prot=mmap.PROT_READ|mmap.PROT_WRITE)
 mapped[0]=66;mapped.flush();print(json.dumps({'mapped_write_completed':True}),flush=True)
except OSError as e:print(json.dumps({'mapped_write_errno':e.errno}),flush=True)
finally:
 if mapped is not None:mapped.close()
"""
def save(name,value):
 p=out/name
 with p.open('x')as f:json.dump(value,f,indent=2);f.write('\n')
 os.chown(p,owner.st_uid,owner.st_gid)
def call(*args):return subprocess.check_output(args,stdin=subprocess.DEVNULL,text=True,timeout=15).strip()
for variant in('mapping-created-before-immutable','mapping-created-after-immutable-via-original-descriptor'):
 root=pathlib.Path(tempfile.mkdtemp(prefix='yunzhan-c297-owned-mapping-',dir='/var/tmp'));assert root.parent==pathlib.Path('/var/tmp')and root.stat().st_uid==0 and stat.S_IMODE(root.stat().st_mode)==0o700
 file=root/'synthetic-A-only.bin';original=b'A'*4096
 with file.open('xb')as f:f.write(original);f.flush();os.fsync(f.fileno())
 os.chown(file,33,33);os.chmod(file,0o644);before=file.lstat();assert stat.S_ISREG(before.st_mode)and before.st_nlink==1
 fd=os.open(file,os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC);child=None;immutable=False
 try:
  child=subprocess.Popen(['/usr/bin/python3','-I','-B','-c',child_code,str(fd),variant],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,pass_fds=(fd,),text=True)
  sel=selectors.DefaultSelector();sel.register(child.stdout,selectors.EVENT_READ);assert sel.select(15),'Owned child did not become ready';ready=json.loads(child.stdout.readline());sel.close();assert ready['ready']and ready['uid']==33
  call('/usr/bin/chattr','+i',str(file));immutable=True;assert 'i'in call('/usr/bin/lsattr','-d',str(file)).split()[0]
  child.stdin.write('immutable-is-verified\n');child.stdin.flush();stdout,stderr=child.communicate(timeout=15);assert len(stdout)<1<<16 and len(stderr)<1<<16
  values=[json.loads(s)for s in stdout.splitlines()if s.startswith('{')];assert values and values[0]['direct_write_errno']==1
  raw=file.read_bytes();s=file.lstat();assert(s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,s.st_nlink,s.st_size)==(before.st_dev,before.st_ino,before.st_uid,before.st_gid,before.st_mode,before.st_nlink,before.st_size)
  unchanged=raw==original;assert child.returncode in(0,-signal.SIGBUS),(child.returncode,stderr)
  fs=json.loads(call('/usr/bin/findmnt','--json','--target',str(file),'--output','FSTYPE,TARGET'))['filesystems'][0]
  cases.append({'variant':variant,'actor':ready,'file_bytes':len(original),'original_sha256':hashlib.sha256(original).hexdigest(),'actual_sha256_after_mapping_attempt':hashlib.sha256(raw).hexdigest(),'original_inode_owner_mode_and_length_preserved':True,'file_contents_unchanged':unchanged,'child_exit':child.returncode,'actual_child_events':values,'actual_filesystem':fs,'immutable_flag_still_set':'i'in call('/usr/bin/lsattr','-d',str(file)).split()[0],'private_or_site_data_used':False})
 finally:
  if child is not None and child.poll()is None:child.kill();child.wait(timeout=10)
  os.close(fd)
  current=file.lstat();assert current.st_ino==before.st_ino and current.st_dev==before.st_dev and current.st_nlink==1
  if immutable:call('/usr/bin/chattr','-i',str(file))
  file.unlink();root.rmdir()
proof={'ok':all(c['file_contents_unchanged']and c['immutable_flag_still_set']for c in cases),'architecture':{'x86_64':'amd64','aarch64':'arm64'}[platform.machine()],'kernel':platform.release(),'cases':cases,'scope':'Native filesystem property on two newly owned synthetic files; not signed installed app or full commercial qualification.','primary_ext4_implementation':'https://github.com/torvalds/linux/blob/master/fs/ext4/ioctl.c','reviewed_ext4_file_blob':'e8e579498c9902f94cee6c05ec6cdf41ca9c229e','Main_changed':False,'all40_commercial':False}
save('original-proof.json',proof);print(json.dumps({'ok':proof['ok'],'architecture':proof['architecture'],'file_contents_unchanged':[c['file_contents_unchanged']for c in cases]}));sys.exit(0 if proof['ok']else 1)
