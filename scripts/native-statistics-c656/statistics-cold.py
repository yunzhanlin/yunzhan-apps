from pathlib import Path
import hashlib,http.cookiejar,json,os,re,sqlite3,stat,subprocess,sys,time,traceback,urllib.request
os.umask(0o077);inp=Path(sys.argv[1]);phase=sys.argv[2];assert phase in('snapshot','cold');plan=json.loads((inp/'plan.json').read_bytes());assert os.geteuid()==0;source=json.loads(Path('/opt/panel/current/SOURCE_INPUTS.json').read_bytes())['inputs_sha256'];assert source==plan['source'];base=Path(plan['case_base'])/'evidence';assert base.is_dir()and not base.is_symlink()
origin='http://127.0.0.1:19100';csrf='';client=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
def sha(p):
 h=hashlib.sha256()
 with Path(p).open('rb')as f:
  for b in iter(lambda:f.read(1<<20),b''):h.update(b)
 return h.hexdigest()
def save(n,v):
 with(base/('v2-'+phase+'-'+n)).open('x')as f:json.dump(v,f,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
def api(path,body=None):
 raw=None if body is None else json.dumps(body).encode();h={'Origin':origin,'Content-Type':'application/json','X-CSRF-Token':csrf}
 with client.open(urllib.request.Request(origin+'/api'+path,raw,h),timeout=90)as r:assert r.status==200;return json.load(r)
def encode(v):
 if isinstance(v,bytes):return {'blob_hex':v.hex()}
 if isinstance(v,(list,tuple)):return [encode(x)for x in v]
 return v

def metadata():
 files={}
 for d in map(Path,('/opt/panel/current','/etc/panel','/srv/panel/sites','/var/lib/panel-executor/platform-maintenance-jobs','/var/lib/panel-executor/statistics-geodata','/var/lib/panel-executor/statistics-geodata-jobs','/var/lib/panel-executor/statistics-geodata-job-archive')):
  if not d.exists():continue
  for p in d.rglob('*'):
   if str(p).startswith('/etc/panel/security-apps/modules/website-statistics-v2/')and(p.name.startswith('access.sqlite')or p.name=='history-worker.json'):continue
   st=p.lstat()
   if stat.S_ISDIR(st.st_mode):continue
   if stat.S_ISLNK(st.st_mode):files[str(p)]={'link':os.readlink(p)};continue
   assert stat.S_ISREG(st.st_mode)and st.st_nlink==1
   files[str(p)]={'sha256':sha(p),'bytes':st.st_size,'uid':st.st_uid,'gid':st.st_gid,'mode':stat.S_IMODE(st.st_mode),'inode':str(st.st_ino),'dev':str(st.st_dev),'links':st.st_nlink}
 with sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True)as db:
  db.execute('PRAGMA query_only=ON');assert db.execute('PRAGMA quick_check').fetchone()==('ok',);tables={r[0]for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")};selected=sorted(t for t in tables if t.startswith(('analytics_','statistics_geodata_')) or t in ('sites','runtime_jobs','app_registry_receipts','app_registry_install_requests','app_platform_hosts','app_platform_tokens','platform_maintenance_grants','platform_maintenance_operations'));rows={t:encode(db.execute('SELECT *FROM '+t+' ORDER BY 1').fetchall())for t in selected};assert set(selected)<=tables;rows['runtime_installations']=encode(db.execute('SELECT id,version_id,binary_path,architecture,status FROM runtime_installations ORDER BY id').fetchall())
 pid=int(subprocess.check_output(['systemctl','show','nginx.service','-p','MainPID','--value'],text=True));assert pid>1;p=Path('/proc')/str(pid);binary=(p/'exe').resolve(strict=True);config=subprocess.check_output([str(binary),'-T'],stderr=subprocess.DEVNULL,timeout=20)
 history=Path('/etc/panel/security-apps/modules/website-statistics-v2/access.sqlite');st=history.lstat();assert stat.S_ISREG(st.st_mode)and st.st_uid==0 and st.st_nlink==1 and stat.S_IMODE(st.st_mode)==0o600
 with sqlite3.connect('file:'+str(history)+'?mode=ro',uri=True)as db:
  db.execute('PRAGMA query_only=ON');assert db.execute('PRAGMA quick_check').fetchone()==('ok',);schema=db.execute('SELECT name,type,tbl_name,sql FROM sqlite_master ORDER BY name').fetchall();history_rows={t:encode(db.execute('SELECT *FROM '+t+' ORDER BY 1,2').fetchall())for t in('access_rows','access_retention','access_receipts','access_archives')};history_rows['access_streams']=encode(db.execute('SELECT site,identity,name,offset,anchor,size,blocked,invalid FROM access_streams ORDER BY site,identity').fetchall())
 worker=json.loads(history.with_name('history-worker.json').read_bytes());assert worker['healthy']and not worker['error'];identity={'uid':st.st_uid,'gid':st.st_gid,'mode':stat.S_IMODE(st.st_mode),'inode':str(st.st_ino),'links':st.st_nlink}
 return {'statistics_history_schema':encode(schema),'statistics_history_rows':history_rows,'statistics_database_identity':identity,'files':files,'rows':rows,'Nginx_executable_sha256':sha(binary),'Nginx_actual_configuration_sha256':hashlib.sha256(config).hexdigest()}
proof={'ok':False,'phase':phase,'source_inputs_sha256':source,'Main_changes':0,'all40_commercial':False}
try:
 for _ in range(120):
  try:
   with urllib.request.urlopen(origin+'/api/ready',timeout=2)as response:
    if response.status==200:break
  except Exception:pass
  time.sleep(1)
 else:raise TimeoutError('Core readiness')
 access=json.loads(Path('/etc/panel/first-login.json').read_bytes());csrf=api('/login',{k:access[k]for k in('username','password')})['csrf'];access.clear();catalog=api('/app-registry');assert len(catalog['catalog']['apps'])==40;status=next(x for x in catalog['status']if x['id']=='website-statistics-v2');assert status['installed']and status['installed_version']=='2.6.0'and not status['update_available'];assert api('/app-modules/website-statistics-v2')['status']['healthy']
 fixtures=json.loads((base/'cold-fixtures.json').read_bytes())
 for _ in range(90):
  state=api('/software/website-statistics-v2/geodata')['state']
  if state['metadata']['available']and not state['loading']:break
  time.sleep(1)
 assert state['selected']==fixtures['selected']and state['metadata']['sha256']==fixtures['database_sha256']and state['metadata']['manifest_sha256']==fixtures['manifest_sha256']and state.get('error','')==''
 inventory=api('/software/website-statistics-v2/geodata-job-records');assert fixtures['job_record']in inventory['inventory']['entries']and fixtures['data_job']in inventory['committed']
 report=json.loads((base/'actual-geodata-live-report.json').read_bytes());assert report['site_id']==fixtures['primary_site']and report['requests']==1 and report['geography']['metadata']['sha256']==fixtures['database_sha256']and report['geography']['counts']['non_public']==1
 save('original-live-report-and-job-inventory.json',{'report':report,'inventory':inventory,'state':state})
 current=metadata();boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip();save('all-original-state.json',{'boot':boot,'metadata':current})
 assert current['statistics_history_rows']['access_rows']and current['statistics_history_rows']['access_receipts']
 if phase=='cold':
  before=json.loads((base/'v2-snapshot-all-original-state.json').read_bytes());assert boot!=before['boot']and current==before['metadata'];proof['different_boot_and_all_original_state_exact']=True;proof['original_boot']=before['boot']
 proof.update(ok=True,boot=boot,retained_history_archive_progress_signed_city_data_job_evidence_and_configs_exact=True,original_preserved_files=len(current['files']),ordinary_signed_store_version_correct=True,original_report_files_byte_exact_and_archived_original_job_readable_after_cold=True,no_event_command_install_or_configuration_replay=True)
except BaseException:proof['failure']=traceback.format_exc()[-5000:]
finally:
 if csrf:
  try:api('/logout',{})
  except Exception:proof['ok']=False
 save('proof.json',proof);print(json.dumps(proof),flush=True)
sys.exit(0 if proof['ok']else 1)
