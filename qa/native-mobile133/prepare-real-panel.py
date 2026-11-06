"""One normal signed install and a real owned file-management site on fresh CI.

No existing panel is accepted. Inputs and inactive image Nginx configuration
are retained; host preparation is separate from the unchanged installer.
"""
import contextlib,hashlib,http.cookiejar,json,os,pathlib,pwd,re,secrets,shutil,sqlite3,stat,subprocess,sys,tarfile,time,urllib.error,urllib.parse,urllib.request
os.umask(0o077)
assert os.geteuid()==0 and os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('GITHUB_REPOSITORY')=='yunzhanlin/yunzhan-apps'
assert pathlib.Path('/proc/1/comm').read_text().strip()=='systemd' and subprocess.check_output(['dpkg','--print-architecture'],text=True).strip()=='amd64'
assert 'ID=ubuntu\n' in pathlib.Path('/etc/os-release').read_text() and 'VERSION_ID="24.04"'in pathlib.Path('/etc/os-release').read_text()
base=pathlib.Path(__file__).resolve().parent;pins=json.loads((base/'pins.json').read_bytes());assets=pathlib.Path(sys.argv[1]).resolve(strict=True);private=pathlib.Path(sys.argv[2]).resolve(strict=True)
owner=private.stat();assert pwd.getpwuid(owner.st_uid).pw_name=='runner' and owner.st_uid!=0 and stat.S_IMODE(owner.st_mode)==0o700
def sha(p):return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
def save(name,value,to_runner=False):
 with(private/name).open('x')as f:json.dump(value,f,indent=2,sort_keys=True);f.write('\n');f.flush();os.fsync(f.fileno())
 if to_runner:os.chown(private/name,owner.st_uid,owner.st_gid)
def once(name,args,timeout=90):
 save(name+'-intent.json',{'args':args,'maximum_submissions':1})
 with(private/(name+'.stdout')).open('xb')as out,(private/(name+'.stderr')).open('xb')as err:r=subprocess.run(args,stdin=subprocess.DEVNULL,stdout=out,stderr=err,timeout=timeout)
 save(name+'-outcome.json',{'exit':r.returncode,'stdout_sha256':sha(private/(name+'.stdout')),'stderr_sha256':sha(private/(name+'.stderr'))})
 assert r.returncode==0,(name,r.returncode)
assert all(not os.path.lexists(n)for n in('/opt/panel','/etc/panel','/var/lib/panel','/var/lib/panel-executor','/etc/fail2ban','/usr/bin/fail2ban-client'))
save('original-fresh-host.json',{'boot':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'NSS_SHA256':{n:sha('/etc/'+n)for n in('passwd','group','shadow','gshadow')},'Main_changed':False})
protected=pathlib.Path('/var/lib/c68-native-inputs-'+secrets.token_hex(16));protected.mkdir(mode=0o700)
for name,pin in pins['programme_assets'].items():
 f=assets/name;s=f.lstat();assert stat.S_ISREG(s.st_mode)and s.st_uid==owner.st_uid and s.st_nlink==1 and not s.st_mode&0o022 and s.st_size==pin['bytes']and sha(f)==pin['sha256']
 with(protected/name).open('xb')as out:out.write(f.read_bytes());out.flush();os.fsync(out.fileno())
 assert sha(protected/name)==pin['sha256']
verifier=base/'original-signed-release.py';assert sha(verifier)==pins['original_verifier_sha256'];shutil.copyfile(verifier,protected/'signed-release.py');os.chmod(protected/'signed-release.py',0o600)
assert sha(protected/'release-signing-dev.pub')=='4ccfcc861d56a41e3ba7f7ace7e2432c815f366c58448d783df92c6632f01339'
# Root's target parent on the fresh developer image can carry a runner default
# ACL. Retain that ACL, protect only this empty install namespace's parent, and
# leave every existing descendant and the installer itself untouched.
opt=pathlib.Path('/opt');s=opt.lstat();assert stat.S_ISDIR(s.st_mode)and s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)in(0o755,0o775,0o777)
identity=lambda f:(f.lstat().st_dev,f.lstat().st_ino,f.lstat().st_mode,f.lstat().st_uid,f.lstat().st_gid,f.lstat().st_mtime_ns,f.lstat().st_ctime_ns)
children={f.name:identity(f)for f in opt.iterdir()};acls={n:os.getxattr(opt,n,follow_symlinks=False).hex()for n in os.listxattr(opt,follow_symlinks=False)if n.startswith('system.posix_acl_')}
save('original-fresh-opt-parent.json',{'uid':s.st_uid,'gid':s.st_gid,'mode':stat.S_IMODE(s.st_mode),'inode':s.st_ino,'ACL_hex':acls,'children':children})
if 'system.posix_acl_default'in acls:
 import struct
 raw=bytes.fromhex(acls['system.posix_acl_default']);assert len(raw)==44 and struct.unpack_from('<I',raw)[0]==2
 assert[struct.unpack_from('<HHI',raw,n)for n in range(4,len(raw),8)]==[(1,7,0xffffffff),(2,7,owner.st_uid),(4,7,0xffffffff),(16,7,0xffffffff),(32,7,0xffffffff)]
 os.removexattr(opt,'system.posix_acl_default',follow_symlinks=False)
if stat.S_IMODE(s.st_mode)!=0o755:os.chmod(opt,0o755,follow_symlinks=False)
assert children=={f.name:identity(f)for f in opt.iterdir()} and opt.lstat().st_ino==s.st_ino
save('explicit-fresh-opt-preparation.json',{'only_parent_access_mode_and_original_default_ACL_protected':True,'original_descendants_preserved':True,'not_a_production_upgrade':True})
original=pathlib.Path('/etc/nginx/nginx.conf')
if original.exists():
 st=original.lstat();assert stat.S_ISREG(st.st_mode)and st.st_uid==st.st_gid==0 and st.st_nlink==1 and stat.S_IMODE(st.st_mode)==0o644
 state=subprocess.check_output(['systemctl','show','nginx.service','--property=ActiveState,MainPID'],text=True);assert 'ActiveState=inactive\n'in state and 'MainPID=0\n'in state
 entries=subprocess.check_output(['dpkg-query','-W','-f=${Conffiles}','nginx-common'],text=True);md5=next(row.split()[1]for row in entries.splitlines()if row.split()and row.split()[0]==str(original));assert hashlib.md5(original.read_bytes()).hexdigest()==md5
 witness={'sha256':sha(original),'inode':st.st_ino,'dev':st.st_dev,'uid':st.st_uid,'gid':st.st_gid,'mode':stat.S_IMODE(st.st_mode)};os.rename(original,protected/'original-distribution-nginx.conf');save('original-distribution-Nginx-retained.json',witness)
once('fresh-generate-missing-SSH-host-keys',['ssh-keygen','-A']);once('fresh-start-distribution-SSH',['systemctl','start','ssh.service'])
archive=protected/pins['programme_archive'];args=['python3','-I','-B',str(protected/'signed-release.py')]
key=['--public-key',str(protected/'release-signing-dev.pub')]
once('original-signature-verify',args+['verify',str(archive)]+key)
once('original-normal-preflight',args+['install',str(archive)]+key+['--preflight-only'],120)
once('original-normal-install',args+['install',str(archive)]+key,1800)
installed=pathlib.Path('/opt/panel/current').resolve(strict=True);assert installed==pathlib.Path('/opt/panel/releases')/pins['programme_version']
checked={}
with tarfile.open(archive)as t:
 for member in t:
  name=str(pathlib.PurePosixPath(member.name).relative_to(pins['programme_archive'][:-7]));target=installed/name;st=target.lstat();assert st.st_uid==0 and stat.S_IMODE(st.st_mode)==member.mode
  if member.isfile():assert stat.S_ISREG(st.st_mode)and st.st_nlink==1 and target.read_bytes()==t.extractfile(member).read();checked[name]=sha(target)
  else:assert member.isdir()and stat.S_ISDIR(st.st_mode);checked[name]='directory'
assert len(checked)==204
save('original-installed-204-entries.json',checked)
origin='http://127.0.0.1:19100';csrf='';client=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
def api(label,path,body=None,binary=None,expected=200):
 headers={'Origin':origin,'X-CSRF-Token':csrf,'Content-Type':'application/json'};data=None
 if body is not None:data=json.dumps(body).encode()
 if binary is not None:data=binary;headers['Content-Type']='application/octet-stream';headers['X-File-SHA256']=hashlib.sha256(binary).hexdigest()
 if data is not None:headers['Idempotency-Key']=secrets.token_hex(16);save(label+'-intent.json',{'path':path,'maximum_POSTs':1,'credential_values_excluded':True})
 request=urllib.request.Request(origin+'/api'+path,data=data,headers=headers)
 try:
  with client.open(request,timeout=90)as response:status=response.status;raw=response.read((8<<20)+1)
 except urllib.error.HTTPError as e:status=e.code;raw=e.read((8<<20)+1)
 assert len(raw)<=8<<20;value=json.loads(raw);save(label+'-response.json',{'status':status,'value':{'csrf_issued':bool(value.get('csrf'))}if path=='/login'else value});assert status==expected,(label,status)
 return value
access=json.loads(pathlib.Path('/etc/panel/first-login.json').read_bytes());csrf=api('setup-login','/login',{k:access[k]for k in('username','password')})['csrf']
api('normal-runtime-discovery','/runtimes')
job=api('owned-file-management-site','/sites',{'name':'C68 real native file management','slug':'c68-owned-download','domain':'c68-owned-download.localhost','php_version_id':''},expected=202)
deadline=time.monotonic()+300;observations=[]
while True:
 with contextlib.closing(sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True))as db:
  db.row_factory=sqlite3.Row;db.execute('PRAGMA query_only=ON');row=dict(db.execute('SELECT *FROM jobs WHERE id=?',(job['job_id'],)).fetchone())
 observations.append({'state':row['state'],'at':time.time()})
 if row['state']not in('running','queued'):break
 assert time.monotonic()<deadline;time.sleep(.5)
save('owned-site-original-job-observations.json',observations);save('owned-site-original-job.json',row);assert row['state']=='succeeded'and row['error']==''
site=row['site_id'];assert re.fullmatch('[0-9a-f]{32}',site)
payload=bytes((i*31)&255 for i in range(131137));name='C68-备份.bin';digest=hashlib.sha256(payload).hexdigest()
value=api('owned-original-binary-upload','/sites/'+site+'/files/upload?'+urllib.parse.urlencode({'path':name}),binary=payload,expected=201)
assert value['bytes']==len(payload)and value['sha256']==digest
api('setup-logout','/logout',{})
save('device-credentials.json',{k:access[k]for k in('username','password')},True)
save('real-panel-setup.json',{'ok':True,'panel_origin':origin,'site':site,'filename':name,'bytes':len(payload),'sha256':digest,'programme_source_inputs_sha256':pins['programme_source_inputs_sha256'],'native_source_inputs_sha256':pins['native_source_inputs_sha256'],'real_file_manager_backend':True,'normal_signed_programme_installs':1,'owned_site_creates':1,'owned_binary_uploads':1,'native_UI_acceptance_pending':True,'Main_changed':False},True)
print(json.dumps({'ok':True,'original_signed_install':True,'real_file_management_backend':True,'device_UI_pending':True}))
