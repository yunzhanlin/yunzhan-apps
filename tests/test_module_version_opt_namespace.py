"""Actual Root mount-namespace and data-only promotion models.
No fabricated Apache executable, panel installation, service action or deletion.
"""
import ast,ctypes,errno,hashlib,json,os,pathlib,secrets,shutil,stat,subprocess,sys
from unittest.mock import patch

assert sys.platform=='linux'and os.geteuid()==0
os.umask(0o022)
repo=pathlib.Path(__file__).resolve().parents[1]
names={'tools/run-module-version-isolated-ci.py':('opt_identity','check_private_case','enter_private_opt'),'tools/prepare-module-version-apache-ci.py':('prepare_runtime_parents','verify_runtime_parents','sealed_ci_tree','promote_private_ci_tree')}
source={}
for name,selected in names.items():
 raw=(repo/name).read_bytes();source[name]=hashlib.sha256(raw).hexdigest();tree=ast.parse(raw)
 nodes=[n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name in selected]
 assert len(nodes)==len(selected)
 exec(compile(ast.Module(body=nodes,type_ignores=[]),name,'exec'),globals())

def file_snapshot(root):
 result={}
 for current,dirs,files in os.walk(root,followlinks=False):
  for name in ['.',*files]:
   p=pathlib.Path(current)/name;s=p.lstat();entry={k:str(getattr(s,k))for k in('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')}
   if stat.S_ISREG(s.st_mode):entry['sha256']=hashlib.sha256(p.read_bytes()).hexdigest()
   result[p.relative_to(root).as_posix()]=entry
 return result

if len(sys.argv)==3 and sys.argv[1]=='--inside-model':
 base=pathlib.Path(sys.argv[2]);check_private_case(base)
 intent=json.loads((base/'intent.json').read_bytes());assert os.readlink('/proc/self/ns/mnt')!=intent['host_mount_namespace']
 subprocess.run(['/usr/bin/mount','--bind',str(base/'runner-opt'),'/opt'],check=True,timeout=10)
 checks=[]
 def check(value,label):
  assert value,label
  checks.append(label)
 check(stat.S_IMODE(pathlib.Path('/opt').lstat().st_mode)==0o777,'actual private model of hosted0777 opt')
 try:prepare_runtime_parents(pathlib.Path('/opt/panel/runtimes/apache/2.4.68'))
 except AssertionError:checks.append('unchanged original installer parent policy refuses0777')
 else:raise AssertionError('unsafe existing parent was adopted')
 original=file_snapshot(base/'runner-opt')
 view=enter_private_opt(base,intent['host_mount_namespace'],[])
 check(stat.S_IMODE(pathlib.Path('/opt').lstat().st_mode)==0o755,'private opt root0755')
 check(not os.path.lexists('/opt/panel'),'no existing panel inherited')
 check((pathlib.Path('/opt/hostedtoolcache/cache-marker')).read_bytes()==b'original tool-cache DATA ONLY','original cache data visible without copy')
 try:
  with pathlib.Path('/opt/hostedtoolcache/cache-marker').open('wb')as out:out.write(b'not permitted')
 except OSError as e:check(e.errno==errno.EROFS,'even UID0 cannot write readonly tool-cache mount')
 else:raise AssertionError('tool cache was writable')
 prefix=pathlib.Path('/opt/panel/ci-data-only/published')
 parents=prepare_runtime_parents(prefix);verify_runtime_parents(parents)
 check(all(not int(r['identity']['st_mode'])&0o022 for r in parents),'every actual private destination parent remains nonwritable by group or others')
 candidate=base/'sealed-DATA-only';candidate.mkdir(mode=0o755)
 with(candidate/'data-marker').open('xb')as out:out.write(b'sealed data fixture,not an Apache executable')
 (candidate/'empty-directory').mkdir(mode=0o755)
 digest=promote_private_ci_tree(candidate,prefix)
 check(sealed_ci_tree(candidate)==sealed_ci_tree(prefix)==digest,'cross-mount copy binds every file byte type and mode')
 check(not os.path.lexists(prefix/'bin/httpd'),'no fabricated Apache executable exists')
 before=file_snapshot(prefix)
 try:promote_private_ci_tree(candidate,prefix)
 except AssertionError:checks.append('already existing destination refused without copy or overwrite')
 else:raise AssertionError('existing destination adopted')
 check(file_snapshot(prefix)==before,'existing destination remains byte and metadata exact')
 race=pathlib.Path('/opt/panel/ci-data-only/race-target');real_copy=shutil.copytree
 def concurrent(src,dst,*args,**kwargs):
  value=real_copy(src,dst,*args,**kwargs)
  if pathlib.Path(src)==candidate:
   race.mkdir(mode=0o755)
   with(race/'original-data').open('xb')as out:out.write(b'concurrent owned data fixture')
  return value
 with patch.object(shutil,'copytree',side_effect=concurrent):
  try:promote_private_ci_tree(candidate,race)
  except OSError as e:check(e.errno==errno.EEXIST,'kernel NOREPLACE rejects concurrent destination')
  else:raise AssertionError('concurrent destination overwritten')
 check((race/'original-data').read_bytes()==b'concurrent owned data fixture','concurrent destination original bytes retained')
 check(file_snapshot(base/'runner-opt')==original,'original unsafe opt and existing data remain completely unchanged')
 result={'ok':True,'checks':checks,'check_count':len(checks),'view':view,'source':source,'scope':'real Root mount namespace and data-only file promotion,not Apache build or installed acceptance','all50_commercial':False}
 with(base/'inner-proof.json').open('x')as out:json.dump(result,out,sort_keys=True)
 print(json.dumps(result));sys.exit(0)

assert len(sys.argv)==1
anchor=pathlib.Path('/var/lib/panel-executor')
if not os.path.lexists(anchor):anchor.mkdir(mode=0o755)
for parent in(anchor,*anchor.parents):
 s=parent.lstat();assert stat.S_ISDIR(s.st_mode)and s.st_uid==0 and not s.st_mode&0o022
base=anchor/('qa-opt-namespace24bkov.'+secrets.token_hex(16));base.mkdir(mode=0o700)
fake=base/'runner-opt';fake.mkdir(mode=0o755);fake.chmod(0o777)
(fake/'panel').mkdir(mode=0o755);(fake/'hostedtoolcache').mkdir(mode=0o755)
with(fake/'panel/installed-DATA-marker').open('xb')as out:out.write(b'original host-owned data,not software')
with(fake/'hostedtoolcache/cache-marker').open('xb')as out:out.write(b'original tool-cache DATA ONLY')
intent={'host_mount_namespace':os.readlink('/proc/self/ns/mnt'),'host_opt_identity':opt_identity(pathlib.Path('/opt')),'original_fake_opt':file_snapshot(fake),'source':source}
with(base/'intent.json').open('x')as out:json.dump(intent,out,sort_keys=True)
result=subprocess.run(['/usr/bin/unshare','--mount','--propagation','private','/usr/bin/python3','-I','-B',str(pathlib.Path(__file__).resolve()),'--inside-model',str(base)],capture_output=True,timeout=45)
with(base/'process.json').open('x')as out:json.dump({'exit':result.returncode,'stdout':result.stdout.decode(),'stderr':result.stderr.decode()},out,sort_keys=True)
unchanged=opt_identity(pathlib.Path('/opt'))==intent['host_opt_identity']and file_snapshot(fake)==intent['original_fake_opt']
proof={'ok':result.returncode==0 and unchanged,'base':str(base),'exit':result.returncode,'host_original_opt_and_all_existing_data_unchanged':unchanged,'source':source,'inner':json.loads(result.stdout)if result.returncode==0 else None,'failure_stderr':result.stderr.decode()if result.returncode else '', 'model_only_no_Apache_or_panel_installation':True,'all_artifacts_retained':True,'all50_commercial':False}
with(base/'proof.json').open('x')as out:json.dump(proof,out,sort_keys=True)
print(json.dumps(proof));sys.exit(0 if proof['ok']else 1)
