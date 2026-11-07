"""Read only the pinned browser and its CDP-reported native process identities."""
import hashlib,json,os,pathlib,re,select,stat,sys,time
assert os.geteuid()==0 and sys.platform=='linux'and len(sys.argv)==1
raw=sys.stdin.buffer.read((1<<20)+1);assert len(raw)<=1<<20;p=json.loads(raw)
assert set(p)=={'chrome','sha256','uid','browser_pid','renderer_pids'}
assert re.fullmatch('/opt/yunzhan-c66-ci-browser-[0-9a-f]{32}/chrome-linux(?:64|-arm64)/chrome',p['chrome'])
assert re.fullmatch('[0-9a-f]{64}',p['sha256'])and isinstance(p['uid'],int)and p['uid']>0
assert isinstance(p['browser_pid'],int)and 1<p['browser_pid']<1<<24
assert 1<=len(p['renderer_pids'])<=64 and len(set(p['renderer_pids']))==len(p['renderer_pids'])
assert all(isinstance(v,int)and 1<v<1<<24 for v in p['renderer_pids'])
chrome=pathlib.Path(p['chrome'])
for parent in chrome.parents:
 s=parent.lstat();assert stat.S_ISDIR(s.st_mode)and s.st_uid==0 and not s.st_mode&0o022
def identity(s):return[s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,str(s.st_mtime_ns),str(s.st_ctime_ns)]
s=chrome.lstat();assert stat.S_ISREG(s.st_mode)and s.st_uid==s.st_gid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o755 and 0<s.st_size<1<<30
source_id=identity(s);digest=hashlib.sha256();size=0;deadline=time.monotonic()+20
with os.fdopen(os.open(chrome,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC),'rb')as stream:
 assert identity(os.fstat(stream.fileno()))==source_id
 for block in iter(lambda:stream.read(1<<20),b''):
  size+=len(block);assert size<=s.st_size and time.monotonic()<deadline;digest.update(block)
 assert size==s.st_size and identity(os.fstat(stream.fileno()))==source_id
assert digest.hexdigest()==p['sha256']and identity(chrome.lstat())==source_id
def process(pid,renderer):
 pidfd=os.pidfd_open(pid,0);directory=os.open('/proc/'+str(pid),os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
 def read(name):
  with os.fdopen(os.open(name,os.O_RDONLY|os.O_CLOEXEC,dir_fd=directory),'rb')as f:return f.read((1<<20)+1)
 try:
  poll=select.poll();poll.register(pidfd,select.POLLIN);assert not poll.poll(0)
  first=read('stat');assert len(first)<1<<20;start=first.decode().rsplit(')',1)[1].split()[19]
  status=read('status').decode();assert len(status)<1<<20
  fields={name:re.search(r'^'+name+r':\s*(.+)$',status,re.M).group(1)for name in('Uid','Gid','CapEff','Seccomp','NoNewPrivs','PPid')}
  assert set(map(int,fields['Uid'].split()))=={p['uid']}and int(fields['CapEff'],16)==0
  if renderer:assert fields['Seccomp']=='2'and fields['NoNewPrivs']=='1'
  # This follows only the kernel's fixed process executable link. All application
  # and archive paths retain their existing no-follow restrictions unchanged.
  executable=os.open('exe',os.O_RDONLY|os.O_CLOEXEC,dir_fd=directory)
  try:actual=identity(os.fstat(executable));assert actual==source_id
  finally:os.close(executable)
  command=read('cmdline');assert len(command)<1<<20
  last=read('stat');assert last.decode().rsplit(')',1)[1].split()[19]==start and not poll.poll(0)
  return{'pid':pid,'fields':fields,'executable_identity':actual,'actual_pinned_chrome_sha256':digest.hexdigest(),'start_ticks':start,'original_cmdline_hex':command.hex(),'pidfd_alive_before_and_after':True,'read_only_Root_observation':True}
 finally:os.close(directory);os.close(pidfd)
browser=process(p['browser_pid'],False);renderers=[];vanished=[]
for pid in p['renderer_pids']:
 try:renderers.append(process(pid,True))
 except ProcessLookupError:vanished.append(pid)
 except FileNotFoundError:vanished.append(pid)
assert renderers and identity(chrome.lstat())==source_id
print(json.dumps({'ok':True,'boot':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'observer_uid':0,'browser':browser,'renderers':renderers,'vanished_reported_pids_retained':vanished,'chrome_sha256':digest.hexdigest(),'source_identity':source_id,'only_read_operations':True},sort_keys=True))
