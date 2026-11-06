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
def run_once(name,args,timeout=60):
 save(name+'-intent.json',{'args':args,'maximum_submissions':1})
 with(private/(name+'.stdout')).open('xb')as out,(private/(name+'.stderr')).open('xb')as err:r=subprocess.run(args,stdin=subprocess.DEVNULL,stdout=out,stderr=err,timeout=timeout)
 save(name+'-outcome.json',{'exit':r.returncode,'stdout_sha256':sha(private/(name+'.stdout')),'stderr_sha256':sha(private/(name+'.stderr'))})
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
catalog=api('original-signed-catalogue','/app-registry?refresh=1');assert len(catalog['catalog']['apps'])==50 and not catalog['source']['stale']
app=next(a for a in catalog['catalog']['apps']if a['id']=='website-analytics');assert app['version']=='2.4.2' and app['sha256']==dispatch['analytics242_sha256']
job=api('one-signed-analytics242-install','/app-registry/website-analytics/install',{'expected_version':app['version'],'expected_sha256':app['sha256']},202)
wait_job('one-signed-analytics242-install',job['job_id'],'runtime_jobs')
module=pathlib.Path('/etc/panel/security-apps/modules/website-analytics/installed.json');assert json.loads(module.read_bytes())['version']=='2.4.2'
nonce=secrets.token_hex(16);slug='c66-native-'+arch+'-'+nonce[:12];domain=slug+'.localhost'
job=api('one-owned-static-site','/sites',{'name':'C66 '+arch+' real BFCache and heatmap','slug':slug,'domain':domain,'php_version_id':''},202)
site=wait_job('one-owned-static-site',job['job_id'],'jobs')['site_id'];assert re.fullmatch('[0-9a-f]{32}',site)
config=api('new-owned-analytics-config','/analytics/sites/'+site+'/config');assert config['revision']==0 and not config['enabled']
job=api('one-owned-collector-enable','/analytics/sites/'+site+'/config',{'enabled':True,'clicks':True,'retention_days':30,'revision':0,'auto_inject_html':False},202)
wait_job('one-owned-collector-enable',job['job_id'],'jobs');config=api('original-enabled-config','/analytics/sites/'+site+'/config')
assert config['enabled']and config['clicks']and config['revision']==1 and config['client_address_mode']=='managed_proxy'
observer='''"use strict";(()=>{const s={document_instance:crypto.randomUUID(),shows:0,restored_shows:0,last_pageshow_persisted:null,last_pagehide_persisted:null,trusted_clicks:0,history:[]};const draw=()=>{document.getElementById("c66-state").textContent=JSON.stringify(s)};window.addEventListener("pageshow",e=>{s.shows++;s.last_pageshow_persisted=e.persisted;if(e.persisted)s.restored_shows++;s.history.push({event:"pageshow",persisted:e.persisted});draw()});window.addEventListener("pagehide",e=>{s.last_pagehide_persisted=e.persisted;s.history.push({event:"pagehide",persisted:e.persisted});draw()});document.addEventListener("click",e=>{if(e.isTrusted){s.trusted_clicks++;draw()}});document.getElementById("native-back").onclick=()=>history.back();document.getElementById("native-forward").onclick=()=>history.forward();draw()})();'''
files={'observer.js':observer}
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
