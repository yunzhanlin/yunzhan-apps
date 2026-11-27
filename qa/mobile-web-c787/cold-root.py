from pathlib import Path
import contextlib,hashlib,http.cookiejar,json,os,secrets,sqlite3,subprocess,sys,time,urllib.request,urllib.error
os.umask(0o077);base=Path(__file__).resolve().parent;private=Path(sys.argv[1]).resolve(strict=True);assert os.geteuid()==0 and os.environ.get('GITHUB_ACTIONS')=='true';pins=json.loads((base/'base/pins.json').read_bytes());owner=private.stat();origin='http://127.0.0.1:19100';csrf='';client=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()));events=[]
def save(n,v,runner=False):
 with(private/n).open('x')as f:json.dump(v,f,indent=2);f.write('\n')
 if runner:os.chown(private/n,owner.st_uid,owner.st_gid)
def api(label,path,body=None,expected=200):
 data=None if body is None else json.dumps(body).encode();h={'Origin':origin,'X-CSRF-Token':csrf,'Content-Type':'application/json'}
 if body is not None:h['Idempotency-Key']=secrets.token_hex(16);save(label+'-intent.json',{'path':path,'maximum_POSTs':1,'credential_values_excluded':True})
 with client.open(urllib.request.Request(origin+'/api'+path,data,h),timeout=90)as r:status=r.status;value=json.load(r)
 events.append({'label':label,'path':path,'status':status,'method':'GET'if body is None else'POST'});assert status==expected;save(label+'-response.json',{'status':status,'csrf_issued':bool(value.get('csrf'))}if path=='/login'else{'status':status,'value':value});return value
def login(label):
 access=json.loads(Path('/etc/panel/first-login.json').read_bytes());value=api(label,'/login',{k:access[k]for k in['username','password']});access.clear();return value['csrf']
proof={'ok':False,'native_App_runs':0,'Main_changes':0,'all40_commercial':False}
try:
 csrf=login('original-fresh-login');before=api('original-before-registry','/app-registry?refresh=1');app=next(x for x in before['catalog']['apps']if x['id']=='mobile');state=next(x for x in before['status']if x['id']=='mobile');assert len(before['catalog']['apps'])==40 and not before['source']['stale']and not state['installed'];assert app['version']=='1.4.0'and app['sha256']=='6b6f78237d29089c0be23ed3194fa401123876b79e56e374b8c7b80d2b00bb0f';queued=api('original-normal140-install','/app-registry/mobile/install',{'expected_version':app['version'],'expected_sha256':app['sha256']},202);deadline=time.monotonic()+300
 while True:
  with contextlib.closing(sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True))as db:db.row_factory=sqlite3.Row;row=dict(db.execute('SELECT *FROM runtime_jobs WHERE id=?',(queued['job_id'],)).fetchone())
  if row['state']not in['queued','running']:break
  assert time.monotonic()<deadline;time.sleep(.5)
 save('original-normal140-install-job.json',row);assert row['state']=='succeeded'and row['error']=='';api('original-before-notifications','/notifications');api('original-before-logout','/logout',{});csrf=''
 beforePIDs={n:int(subprocess.check_output(['systemctl','show',n,'-p','MainPID','--value'],text=True))for n in ['panel.service','panel-executor.service']};assert all(beforePIDs.values());save('original-restart-intent.json',{'services':list(beforePIDs),'maximum_submissions':1});r=subprocess.run(['systemctl','restart',*beforePIDs],capture_output=True,timeout=90);save('original-restart-outcome.json',{'returncode':r.returncode});assert r.returncode==0;attempts=[];ready=False
 for attempt in range(120):
  try:
   with client.open(origin+'/',timeout=2)as response:status=response.status;ready=status==200 and b'<html'in response.read(65536).lower();attempts.append({'status':status,'ready':ready})
  except (urllib.error.URLError,TimeoutError)as e:attempts.append({'transport':type(e).__name__,'no_login_POST_submitted':True})
  if ready:break
  time.sleep(.25)
 save('original-HTTP-readiness-before-login.json',attempts);assert ready,'Owned service did not become ready; no login replay';afterPIDs={n:int(subprocess.check_output(['systemctl','show',n,'-p','MainPID','--value'],text=True))for n in beforePIDs};assert all(afterPIDs[n]>0 and afterPIDs[n]!=beforePIDs[n]for n in beforePIDs);csrf=login('original-first-post-ready-login');after=api('original-cold-registry','/app-registry');module=api('original-cold-module','/app-modules/mobile-pwa');alerts=api('original-cold-notifications','/notifications');state=next(x for x in after['status']if x['id']=='mobile');assert state['installed']and state['installed_version']=='1.4.0'and state['version_known']and not state['update_available'];assert module['status']['installed']and module['status']['version']=='1.4.0';assert json.loads(Path('/opt/panel/current/SOURCE_INPUTS.json').read_bytes())['inputs_sha256']==pins['programme_source_inputs_sha256'];setup=json.loads((private/'real-panel-setup.json').read_bytes());originalFile=Path('/srv/panel/sites')/setup['site']/'public'/setup['filename'];assert originalFile.stat().st_size==setup['bytes']and hashlib.sha256(originalFile.read_bytes()).hexdigest()==setup['sha256'];root=Path('/opt/panel/current').resolve(strict=True);originals=json.loads((private/'original-installed-213-entries.json').read_bytes());assert len(originals)==213
 for name,digest in originals.items():
  p=root/name
  if digest=='directory':assert p.is_dir()and not p.is_symlink()
  else:assert p.is_file()and not p.is_symlink()and hashlib.sha256(p.read_bytes()).hexdigest()==digest
 api('original-cold-logout','/logout',{});csrf='';access=json.loads(Path('/etc/panel/first-login.json').read_bytes());save('root-credentials.json',{k:access[k]for k in['username','password']},True);access.clear();proof.update(ok=True,architecture='amd64',source_inputs_sha256=pins['programme_source_inputs_sha256'],normal_original_key_web140_install=True,fresh_service_processes=True,HTTP_readiness_before_single_post_ready_login=True,actual_cold_registry_module_alert_reads_200=True,original_site_attachment_and_all213_programme_entries_preserved=True,before_PIDs=beforePIDs,after_PIDs=afterPIDs,normal_install_job=queued['job_id']);save('original-cold-server-proof.json',proof,True)
finally:save('original-HTTP-events.json',events)
print(json.dumps(proof));assert proof['ok']
