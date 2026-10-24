#!/usr/bin/env python3
"""Own mount namespace for a genuine Apache prerequisite and exact235 models.

Hosted CI may expose a world-writable /opt. Never chmod/adopt that parent or
mask the production refusal. An empty private /opt is used only by this job;
the host tool cache is rebound read-only, not copied into a panel runtime.
"""
import hashlib,json,os,pathlib,re,secrets,shutil,stat,subprocess,sys

def opt_identity(path):
 s=path.lstat();assert stat.S_ISDIR(s.st_mode)
 return {k:str(getattr(s,k))for k in('st_dev','st_ino','st_mode','st_uid','st_gid')}

def check_private_case(base):
 for path in(base,*base.parents):
  s=path.lstat();assert stat.S_ISDIR(s.st_mode)and s.st_uid==0 and not s.st_mode&0o022
 assert stat.S_IMODE(base.lstat().st_mode)==0o700

def tool_content_tree(root):
 # Treat the pre-existing CI cache ONLY as data. Its original modes/owners are
 # recorded, never repaired or used to authorize privileged execution.
 root=root.resolve(strict=True);pending=[root];entries={};identities={};total=0
 while pending:
  path=pending.pop();s=path.lstat();rel=path.relative_to(root).as_posix()
  assert rel not in entries and len(entries)<50000
  identities[rel]={k:str(getattr(s,k))for k in('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')}
  if stat.S_ISLNK(s.st_mode):
   link=os.readlink(path);target=(path.parent/link).resolve(strict=True)
   assert not pathlib.Path(link).is_absolute()and target.is_relative_to(root),'Tool-cache link leaves its exact source prefix'
   entries[rel]={'kind':'link','target':link}
  elif stat.S_ISDIR(s.st_mode):
   entries[rel]={'kind':'directory'};pending.extend(sorted(path.iterdir()))
  else:
   assert stat.S_ISREG(s.st_mode)and s.st_size<=256<<20
   total+=s.st_size;assert total<1<<30
   entries[rel]={'kind':'file','bytes':s.st_size,'executable':bool(s.st_mode&0o111),'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}
 return {'entries':entries,'identities':identities,'bytes':total,'content_sha256':hashlib.sha256(json.dumps(entries,sort_keys=True,separators=(',',':')).encode()).hexdigest()}

def seal_ci_tool_tree(source,destination):
 check_private_case(destination.parent)
 assert not os.path.lexists(destination)
 before=tool_content_tree(source)
 shutil.copytree(source,destination,symlinks=True)
 copied=tool_content_tree(destination)
 assert copied['entries']==before['entries'],'Copied tool bytes/types/executable structure differ'
 assert tool_content_tree(source)==before,'Original tool cache changed while copying; never adopt a moving input'
 # These are NEW owned copies only. No pre-existing cache parent/file changes.
 for current,dirs,files in os.walk(destination,followlinks=False):
  for name in ['.',*dirs,*files]:
   path=pathlib.Path(current)/name;s=path.lstat()
   os.chown(path,0,0,follow_symlinks=False)
   if not stat.S_ISLNK(s.st_mode):os.chmod(path,0o755 if stat.S_ISDIR(s.st_mode)or s.st_mode&0o111 else 0o644)
 after=tool_content_tree(destination)
 assert after['entries']==before['entries']and after['content_sha256']==before['content_sha256']
 for identity in after['identities'].values():
  mode=int(identity['st_mode']);assert identity['st_uid']==identity['st_gid']=='0'
  if not stat.S_ISLNK(mode):assert not mode&0o022
 assert tool_content_tree(source)==before,'Original cache changed during sealing'
 return {'source_root':str(source),'sealed_root':str(destination),'entries':len(after['entries']),'bytes':after['bytes'],'content_sha256':after['content_sha256'],'source_metadata_unchanged':True,'only_new_copies_chmodded_or_chowned':True}

def enter_private_opt(base,host_mount_namespace,tools):
 assert os.geteuid()==0 and os.readlink('/proc/self/ns/mnt')!=host_mount_namespace
 # unshare --propagation private must have isolated every existing mount.
 for line in pathlib.Path('/proc/self/mountinfo').read_text().splitlines():
  fields=line.split();optional=fields[6:fields.index('-')]
  assert not any(v.startswith(('shared:','master:','propagate_from:'))for v in optional)
 check_private_case(base)
 original=opt_identity(pathlib.Path('/opt'))
 retained=base/'original-opt';retained.mkdir(mode=0o700)
 private=base/'private-opt';private.mkdir(mode=0o755)
 def mount(*args):subprocess.run(['/usr/bin/mount',*args],check=True,timeout=10)
 mount('--bind','/opt',str(retained));mount('-o','remount,bind,ro',str(retained))
 mount('--bind',str(private),'/opt')
 current=opt_identity(pathlib.Path('/opt'))
 assert current==opt_identity(private)and current['st_uid']=='0'and stat.S_IMODE(int(current['st_mode']))==0o755
 assert not os.path.lexists('/opt/panel'),'Never inherit/adopt any host panel installation'
 cache=retained/'hostedtoolcache'
 if os.path.lexists(cache):
  s=cache.lstat();assert stat.S_ISDIR(s.st_mode)
  target=pathlib.Path('/opt/hostedtoolcache');target.mkdir(mode=0o755)
  mount('--bind',str(cache),str(target));mount('-o','remount,bind,ro',str(target))
  rows=[v.split()for v in pathlib.Path('/proc/self/mountinfo').read_text().splitlines()if v.split()[4]==str(target)]
  assert len(rows)==1 and 'ro'in rows[0][5].split(',')
 for item in tools:
  tool=pathlib.Path(item['path']);s=tool.lstat()
  assert stat.S_ISREG(s.st_mode)and s.st_mode&0o111 and hashlib.sha256(tool.read_bytes()).hexdigest()==item['sha256']
 return {'original_opt_identity':original,'private_opt_identity':current,'hosted_tool_cache_read_only':os.path.lexists(cache),'mount_namespace':os.readlink('/proc/self/ns/mnt'),'host_panel_inherited':False,'existing_host_parent_permission_changes':0}

def main():
 assert sys.platform=='linux'and os.geteuid()==0
 os.umask(0o022)
 repo=pathlib.Path(__file__).resolve().parents[1]
 if len(sys.argv)==3:
  original_tools=[]
  for role,name in zip(('go','node'),sys.argv[1:]):
   path=pathlib.Path(name).resolve(strict=True);s=path.lstat()
   diagnostic={'path':str(path),'uid':s.st_uid,'gid':s.st_gid,'mode':oct(stat.S_IMODE(s.st_mode)),'source_data_only_NOT_execution_admission':True}
   print(json.dumps({'phase':'original-tool-input-observation','tool':diagnostic}),flush=True)
   assert path.is_absolute()and stat.S_ISREG(s.st_mode)and s.st_mode&0o111,diagnostic
   assert path.name==role and path.parent.name=='bin','Exact setup-go/setup-node source prefix required'
   original_tools.append({'path':str(path),'sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'role':role,'metadata':diagnostic})
  anchor=pathlib.Path('/var/lib/panel-executor')
  if not os.path.lexists(anchor):anchor.mkdir(mode=0o755)
  for parent in(anchor,*anchor.parents):
   s=parent.lstat();assert stat.S_ISDIR(s.st_mode)and s.st_uid==0 and not s.st_mode&0o022
  base=anchor/('redis-cli-isolated-ci.'+secrets.token_hex(16));base.mkdir(mode=0o700)
  tools=[];seals=[]
  for item in original_tools:
   original=pathlib.Path(item['path']);destination=base/('sealed-'+item['role'])
   seals.append(seal_ci_tool_tree(original.parent.parent,destination))
   binary=destination/'bin'/item['role'];s=binary.lstat()
   assert stat.S_ISREG(s.st_mode)and s.st_uid==0 and not s.st_mode&0o022 and s.st_mode&0o111
   assert hashlib.sha256(binary.read_bytes()).hexdigest()==item['sha256']
   tools.append({'path':str(binary),'sha256':item['sha256']})
  intent={'base':str(base),'repo':str(repo),'tools':tools,'original_tools_data_only':original_tools,'sealed_toolchain_trees':seals,'host_mount_namespace':os.readlink('/proc/self/ns/mnt'),'host_opt_identity':opt_identity(pathlib.Path('/opt')),'helper_sha256':hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest()}
  with(base/'intent.json').open('x')as out:json.dump(intent,out,sort_keys=True)
  result=subprocess.run(['/usr/bin/unshare','--mount','--propagation','private','/usr/bin/python3','-I','-B',str(pathlib.Path(__file__).resolve()),'--inside',str(base)],stdin=subprocess.DEVNULL,timeout=1800)
  unchanged=opt_identity(pathlib.Path('/opt'))==intent['host_opt_identity']
  proof={'ok':result.returncode==0 and unchanged,'exit':result.returncode,'host_opt_identity_unchanged':unchanged,'scope':'isolated CI prerequisite and235 integration models,not installed panel/application acceptance','base':str(base),'all50_commercial':False}
  with(base/'outer-proof.json').open('x')as out:json.dump(proof,out,sort_keys=True)
  print(json.dumps(proof),flush=True);return 0 if proof['ok']else 1
 assert len(sys.argv)==3 and sys.argv[1]=='--inside','Only two explicit tool paths or one original private case'

if __name__=='__main__':
 # Distinguish the internal case before interpreting arguments as tool paths.
 if len(sys.argv)==3 and sys.argv[1]=='--inside':
  assert sys.platform=='linux'and os.geteuid()==0
  os.umask(0o022);base=pathlib.Path(sys.argv[2])
  assert re.fullmatch(r'/var/lib/panel-executor/redis-cli-isolated-ci\.[a-f0-9]{32}',str(base))
  check_private_case(base);intent=json.loads((base/'intent.json').read_bytes())
  assert str(base)==intent['base']and hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest()==intent['helper_sha256']
  view=enter_private_opt(base,intent['host_mount_namespace'],intent['tools'])
  with(base/'namespace-proof.json').open('x')as out:json.dump(view,out,sort_keys=True)
  print(json.dumps({'phase':'private-empty-opt-entered','view':view}),flush=True)
  repo=pathlib.Path(intent['repo']);go,node=[v['path']for v in intent['tools']]
  environment={**os.environ,'GOROOT':str(pathlib.Path(go).parent.parent),'PATH':str(pathlib.Path(go).parent)+':'+str(pathlib.Path(node).parent)+':'+os.environ.get('PATH','/usr/bin:/bin')}
  print(json.dumps({'phase':'sealed-toolchain-execution','seals':intent['sealed_toolchain_trees'],'go_version':subprocess.check_output([go,'version'],text=True,env=environment).strip(),'node_version':subprocess.check_output([node,'--version'],text=True,env=environment).strip()}),flush=True)
  for command in([
   '/usr/bin/python3','-I','-B',str(repo/'tools/prepare-module-version-apache-ci.py')],
   [node,str(repo/'tools/run-redis-cli-native-ci.mjs'),go],
   [node,str(repo/'tools/run-redis-cli-native-ci.mjs'),go,'--race']):
   subprocess.run(command,check=True,stdin=subprocess.DEVNULL,timeout=1500,env=environment)
  for item in intent['tools']:assert hashlib.sha256(pathlib.Path(item['path']).read_bytes()).hexdigest()==item['sha256']
 else:sys.exit(main())
