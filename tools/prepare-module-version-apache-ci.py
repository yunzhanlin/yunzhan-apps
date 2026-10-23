#!/usr/bin/env python3
"""Build a genuine pinned Apache prerequisite on an empty disposable CI runner.
No fake executable, service start, panel installation or source overlays.
"""
import hashlib,json,os,pathlib,pwd,re,secrets,stat,struct,subprocess,sys,tarfile,urllib.request,urllib.error
assert sys.platform=='linux' and os.geteuid()==0
repo=pathlib.Path(__file__).resolve().parents[1]
source=repo/'panel-integration-module-version'
index_raw=(source/'source-sha256.json').read_bytes()
assert hashlib.sha256(index_raw).hexdigest()=='37b5a6885fc685204ca8b15f2bc2d873013749a25987973d39bd8386dcbff491'
index=json.loads(index_raw);assert index['release']['frozen_inputs_sha256']=='41c4295d400488bc6d69faa6a36a3a9556fc50b0b7e14d2011b083b964113cb4'and not index['test_overrides']
def read_source(name):
 raw=(source/name).read_bytes();assert hashlib.sha256(raw).hexdigest()==index['files'][name];return raw.decode()
catalog=read_source('internal/runtimecatalog/catalog.go')
pin=re.findall(r'\{"apache-2\.4\.68", "apache", "2\.4\.68", "2\.4", "stable", "(https://[^"]+)", "([a-f0-9]{64})",',catalog)
assert len(pin)==1
url,digest=pin[0]
assert url=='https://downloads.apache.org/httpd/httpd-2.4.68.tar.gz'and digest=='ed9a9d4500fb48bb28eaffb3ba71d06ccf86d498fa13ab9f781da010cc488498'
install=read_source('internal/executor/install_linux.go')
blocks=re.findall(r'if r\.Family == "apache" \{\s*flags = \[\]string\{([^}]+)\}\s*\}',install)
assert len(blocks)==1
block=blocks[0]
flags=re.findall(r'"([^"]*)"',block)
assert flags[0]=='--prefix=' and '--enable-remoteip=shared'in flags and '--with-mpm=event'in flags
prefix=pathlib.Path('/opt/panel/runtimes/apache/2.4.68')
assert not os.path.lexists(prefix),'Refuse any existing runtime; never overwrite,adopt or uninstall it'
try:account=pwd.getpwnam('panel-ci-apache')
except KeyError:
 subprocess.run(['/usr/sbin/useradd','--system','--user-group','--no-create-home','--home-dir','/nonexistent','--shell','/usr/sbin/nologin','panel-ci-apache'],check=True,timeout=15)
 account=pwd.getpwnam('panel-ci-apache')
assert account.pw_uid!=0 and account.pw_gid!=0 and account.pw_dir=='/nonexistent'and account.pw_shell=='/usr/sbin/nologin'
anchor=pathlib.Path('/var/lib/panel-executor')
if not anchor.exists():anchor.mkdir(mode=0o755)
for parent in(anchor,*anchor.parents):
 s=parent.lstat();assert stat.S_ISDIR(s.st_mode)and s.st_uid==0 and not s.st_mode&0o022
base=anchor/('module-version-apache-ci.'+secrets.token_hex(16));base.mkdir(mode=0o711)
work=base/'work';work.mkdir(mode=0o700);os.chown(work,account.pw_uid,account.pw_gid)
archive=base/'source.tar.gz'
class OfficialOnly(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,req,fp,code,msg,headers,newurl):
  from urllib.parse import urlparse
  parsed=urlparse(newurl)
  if parsed.scheme!='https'or parsed.hostname not in('downloads.apache.org','dlcdn.apache.org','archive.apache.org'):raise ValueError('untrusted source redirect')
  return super().redirect_request(req,fp,code,msg,headers,newurl)
opener=urllib.request.build_opener(OfficialOnly())
used=None
for candidate in(url,'https://archive.apache.org/dist/httpd/httpd-2.4.68.tar.gz'):
 try:
  with opener.open(candidate,timeout=30)as response:
   assert response.status==200
   raw=response.read((64<<20)+1);assert 0<len(raw)<=64<<20
  assert hashlib.sha256(raw).hexdigest()==digest,'Exact production source pin mismatch; no untrusted fallback'
  with archive.open('xb')as out:out.write(raw)
  used=candidate;break
 except urllib.error.HTTPError as exc:
  if exc.code not in(404,410)or candidate!=url:raise
assert used is not None
with tarfile.open(archive,'r:gz')as tar:
 members=tar.getmembers();assert 0<len(members)<=50000 and sum(m.size for m in members)<=512<<20
 for member in members:
  path=pathlib.PurePosixPath(member.name)
  assert not path.is_absolute()and '..'not in path.parts and path.parts[0]=='httpd-2.4.68'
  assert member.isdir()or member.isfile(),'No archive links or special files adopted'
 tar.extractall(work,members=members,filter='data')
for current,dirs,files in os.walk(work,followlinks=False):
 for name in['.',*dirs,*files]:
  path=pathlib.Path(current)/name;s=path.lstat();assert not stat.S_ISLNK(s.st_mode);os.chown(path,account.pw_uid,account.pw_gid)
stage=work/'stage';stage.mkdir(mode=0o700);os.chown(stage,account.pw_uid,account.pw_gid)
plan={'format':1,'source':str(work/'httpd-2.4.68'),'stage':str(stage),'flags':['--prefix='+str(prefix),*flags[1:]],'source_sha256':digest,'User':'panel-ci-apache','MemoryMax':'768M','MemorySwapMax':'0','service_start':False}
(base/'plan.json').write_text(json.dumps(plan)+'\n');os.chmod(base/'plan.json',0o644)
worker=base/'build.py'
worker.write_text("""import json,pathlib,subprocess,sys
p=json.loads(pathlib.Path(sys.argv[1]).read_bytes())
root=pathlib.Path(p['source']);commands=[['./configure',*p['flags']],['/usr/bin/make','-j1'],['/usr/bin/make','install','DESTDIR='+p['stage']]]
for i,args in enumerate(commands):
 with(root.parent/('phase-'+str(i)+'.log')).open('xb')as log:
  subprocess.run(args,cwd=root,check=True,stdout=log,stderr=subprocess.STDOUT,timeout=600)
""");os.chmod(worker,0o644)
unit='panel-ci-module-apache-'+base.name.rsplit('.',1)[1][:12]
subprocess.run(['systemd-run','--quiet','--wait','--collect','--pipe','--unit='+unit,'--property=Type=oneshot','--property=User=panel-ci-apache','--property=Group=panel-ci-apache','--property=NoNewPrivileges=yes','--property=CapabilityBoundingSet=','--property=AmbientCapabilities=','--property=ProtectSystem=strict','--property=ProtectHome=yes','--property=PrivateTmp=yes','--property=MemoryHigh=640M','--property=MemoryMax=768M','--property=MemorySwapMax=0','--property=ReadWritePaths='+str(work),'/usr/bin/python3','-I','-B',str(worker),str(base/'plan.json')],check=True,timeout=1820)
candidate=stage/str(prefix).lstrip('/')
binary=candidate/'bin/httpd';info=binary.lstat();assert stat.S_ISREG(info.st_mode)and info.st_nlink==1 and info.st_mode&0o111
with binary.open('rb')as inp:elf=inp.read(20)
assert elf[:6]==b'\x7fELF\x02\x01'and struct.unpack('<H',elf[18:20])[0]==62
version=subprocess.run([str(binary),'-v'],capture_output=True,text=True,check=True,timeout=10)
assert version.stderr==''and version.stdout.splitlines()[0]=='Server version: Apache/2.4.68 (Unix)'
for current,dirs,files in os.walk(candidate,followlinks=False):
 for name in['.',*dirs,*files]:
  path=pathlib.Path(current)/name;s=path.lstat();assert not stat.S_ISLNK(s.st_mode)
  os.chown(path,0,0);os.chmod(path,0o755 if stat.S_ISDIR(s.st_mode)or s.st_mode&0o111 else 0o644)
prefix.parent.mkdir(parents=True,exist_ok=True)
for parent in(prefix.parent,*prefix.parent.parents):
 s=parent.lstat();assert stat.S_ISDIR(s.st_mode)and s.st_uid==0 and not s.st_mode&0o022
assert not os.path.lexists(prefix)
# The isolated CI job is the sole owner; destination is absent and no existing
# runtime is removed or overwritten. Keep all source/build logs for diagnostics.
os.rename(candidate,prefix)
actual=subprocess.run([str(prefix/'bin/httpd'),'-v'],capture_output=True,text=True,check=True,timeout=10)
assert actual.stdout==version.stdout and actual.stderr==''
out={'ok':True,'scope':'genuine pinned Apache CI prerequisite,not a normal panel/runtime installation receipt','source_url':used,'source_sha256':digest,'prefix':str(prefix),'CLI_version':actual.stdout,'CLI_sha256':hashlib.sha256((prefix/'bin/httpd').read_bytes()).hexdigest(),'original_production_configure_flags':True,'unprivileged_compiler':account.pw_name,'memory_max_configured_bytes':768<<20,'swap_max_configured_bytes':0,'service_started':False,'panel_installed':False,'all50_commercial':False,'retained_build_root':str(base)}
(base/'proof.json').write_text(json.dumps(out,sort_keys=True)+'\n')
print(json.dumps(out))
