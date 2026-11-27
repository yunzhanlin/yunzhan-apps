from pathlib import Path
import hashlib,http.cookiejar,json,os,re,sqlite3,stat,subprocess,sys,time,traceback,urllib.request
os.umask(0o077);inp=Path(sys.argv[1]);phase=sys.argv[2];assert phase in('snapshot','cold');plan=json.loads((inp/'plan.json').read_bytes());assert os.geteuid()==0 and Path('/etc/hostname').read_text().strip()==plan['host'];source=json.loads(Path('/opt/panel/current/SOURCE_INPUTS.json').read_bytes())['inputs_sha256'];assert source==plan['source'];base=Path(plan['case_base']);assert base.parent==Path('/var/lib/panel-executor')and re.fullmatch('c614-owned-platform-cold-[a-f0-9]{32}',base.name)
if phase=='snapshot':base.mkdir(mode=0o700)
else:assert base.is_dir()and not base.is_symlink()
origin='http://127.0.0.1:19100';csrf='';client=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
def sha(p):
 h=hashlib.sha256()
 with Path(p).open('rb')as f:
  for b in iter(lambda:f.read(1<<20),b''):h.update(b)
 return h.hexdigest()
def save(n,v):
 with(base/(phase+'-'+n)).open('x')as f:json.dump(v,f,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
def api(path,body=None):
 raw=None if body is None else json.dumps(body).encode();h={'Origin':origin,'Content-Type':'application/json','X-CSRF-Token':csrf}
 with client.open(urllib.request.Request(origin+'/api'+path,raw,h),timeout=90)as r:assert r.status==200;return json.load(r)
def encode(v):
 if isinstance(v,bytes):return {'blob_hex':v.hex()}
 if isinstance(v,(list,tuple)):return [encode(x)for x in v]
 return v

def metadata():
 files={}
 for d in map(Path,('/opt/panel/current','/etc/panel','/srv/panel/sites','/var/lib/panel-executor/platform-maintenance-jobs')):
  if not d.exists():continue
  for p in d.rglob('*'):
   st=p.lstat()
   if stat.S_ISDIR(st.st_mode):continue
   if stat.S_ISLNK(st.st_mode):files[str(p)]={'link':os.readlink(p)};continue
   assert stat.S_ISREG(st.st_mode)and st.st_nlink==1
   files[str(p)]={'sha256':sha(p),'bytes':st.st_size,'uid':st.st_uid,'gid':st.st_gid,'mode':stat.S_IMODE(st.st_mode),'inode':str(st.st_ino),'dev':str(st.st_dev),'links':st.st_nlink}
 with sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True)as db:
  db.execute('PRAGMA query_only=ON');assert db.execute('PRAGMA quick_check').fetchone()==('ok',);tables={r[0]for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")};selected=['sites','runtime_jobs','app_registry_receipts','app_registry_install_requests','app_platform_hosts','app_platform_tokens','platform_maintenance_grants','platform_maintenance_operations'];rows={t:encode(db.execute('SELECT *FROM '+t+' ORDER BY 1').fetchall())for t in selected};assert set(selected)<=tables;rows['runtime_installations']=encode(db.execute('SELECT id,version_id,binary_path,architecture,status FROM runtime_installations ORDER BY id').fetchall())
 pid=int(subprocess.check_output(['systemctl','show','nginx.service','-p','MainPID','--value'],text=True));assert pid>1;p=Path('/proc')/str(pid);binary=(p/'exe').resolve(strict=True);config=subprocess.check_output([str(binary),'-T'],stderr=subprocess.DEVNULL,timeout=20)
 return {'files':files,'rows':rows,'Nginx_executable_sha256':sha(binary),'Nginx_actual_configuration_sha256':hashlib.sha256(config).hexdigest()}
proof={'ok':False,'phase':phase,'base':str(base),'source_inputs_sha256':source,'Main_changes':0,'all40_commercial':False}
try:
 for _ in range(120):
  try:
   with urllib.request.urlopen(origin+'/api/ready',timeout=2)as r:
    if r.status==200:break
  except Exception:pass
  time.sleep(1)
 else:raise TimeoutError('Core not ready')
 access=json.loads(Path('/etc/panel/first-login.json').read_bytes());csrf=api('/login',{k:access[k]for k in('username','password')})['csrf'];access.clear();catalogue=api('/app-registry');assert len(catalogue['catalog']['apps'])==40 and catalogue['source']['source']in('github','verified-cache');cache=json.loads(Path('/var/lib/panel/app-registry/catalog/catalog-v1.bundle.json').read_bytes());assert hashlib.sha256(cache['catalog'].encode()).hexdigest()=='c4860ba82898bd9f4f15644ea1b6839f4af99b6234dbd0f211f78c3090fc69be';module=api('/app-modules/platform-ops');assert module['status']['healthy']and module['status']['version']=='1.3.1'and module['status']['installation_id']==plan['installation_id'];ops=api('/app-modules/platform-ops/maintenance/operations');assert ops['read_only']and {r['request_id']for r in ops['entries']}==set(plan['operation_ids'])and all(r['state']=='completed'and r['retry_allowed']is False for r in ops['entries']);grants=api('/app-modules/platform-ops/maintenance/grants');assert grants['read_only']and len(grants['entries'])==3 and all(r['revoked']and r['installation_id']==plan['installation_id']and not r['legacy_unbound']for r in grants['entries']);save('original-API-inventories.json',{'operations':ops,'grants':grants})
 original=plan['original_owned_site'];req=urllib.request.Request('http://127.0.0.1:19101/c610-original.txt',headers={'Host':original['domain']})
 with client.open(req,timeout=15)as r:assert r.status==200 and hashlib.sha256(r.read(1<<20)).hexdigest()==plan['original_owned_file']['sha256']
 current=metadata();boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip();save('all-original-state.json',{'boot':boot,'metadata':current})
 if phase=='cold':
  before=json.loads((base/'snapshot-all-original-state.json').read_bytes());assert boot!=before['boot']and current==before['metadata'];proof['different_boot_and_all_original_state_exact']=True;proof['original_boot']=before['boot']
 proof.update(ok=True,boot=boot,actual_retained_original_operation_API_readable=True,actual_revoked_grants_API_retained=True,actual_original_static_HTTP200=True,original_preserved_files=len(current['files']),original_full_platform_data_and_Root_receipts_preserved=True,no_install_configure_remote_command_or_replay_in_this_phase=True)
except BaseException:proof['failure']=traceback.format_exc()[-6000:]
finally:
 if csrf:
  try:api('/logout',{})
  except Exception:proof['ok']=False
 save('proof.json',proof);print(json.dumps(proof),flush=True)
sys.exit(0 if proof['ok']else 1)
