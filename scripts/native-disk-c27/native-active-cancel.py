"""One original signed disk-analysis store install in this owned fresh QA guest."""
import base64,contextlib,hashlib,http.cookiejar,json,os,pathlib,platform,secrets,sqlite3,stat,subprocess,sys,time,traceback,urllib.error,urllib.request
os.umask(0o077);base=pathlib.Path(sys.argv[1]);assert len(sys.argv)==2 and os.geteuid()==0
intent=json.loads((base/'intent.json').read_bytes());assert platform.machine()=='x86_64' and pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()==intent['peer']['boot']
assert hashlib.sha256(pathlib.Path('/etc/machine-id').read_bytes()).hexdigest()==intent['peer']['machine_id_sha256']
def save(n,v):
 with os.fdopen(os.open(base/n,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600),'w')as o:json.dump(v,o,sort_keys=True);o.write(chr(10));o.flush();os.fsync(o.fileno())
def sha(p):return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
def capture():
 out={};db=sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True,timeout=3)
 try:
  db.execute('PRAGMA query_only=ON');db.execute('BEGIN')
  for name,sql in db.execute("SELECT name,sql FROM sqlite_schema WHERE type='table' ORDER BY name").fetchall():
   q='"'+name.replace('"','""')+'"';cur=db.execute('SELECT * FROM '+q)
   enc=lambda v:{'blob_base64':base64.b64encode(v).decode()}if isinstance(v,bytes)else v
   out[name]={'sql':sql,'columns':[x[0]for x in cur.description],'rows':sorted([[enc(v)for v in row]for row in cur.fetchall()],key=lambda v:json.dumps(v,sort_keys=True))}
 finally:db.close()
 return out
proof={'ok':False,'scope':'actual distinct original active-phase native scan and one explicit cancellation in isolated QA','Main_changed':False,'all50_commercial':False,'real_host_scan_acceptance':False};csrf='';opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*args,**kwargs):raise AssertionError('API redirect refused')
opener.add_handler(NoRedirect())
def api(path,body=None,key=None):
 h={'Origin':'http://127.0.0.1:19100','X-CSRF-Token':csrf,'Content-Type':'application/json'}
 if key:h['Idempotency-Key']=key
 req=urllib.request.Request('http://127.0.0.1:19100/api'+path,data=None if body is None else json.dumps(body,separators=(',',':')).encode(),headers=h)
 try:
  with opener.open(req,timeout=40)as r:
   b=r.read((4<<20)+1);assert len(b)<=4<<20
   return r.status,json.loads(b)
 except urllib.error.HTTPError as e:
  save('http-error-'+secrets.token_hex(6)+'.json',{'path':path,'status':e.code,'body':e.read(8192).decode('utf8','replace')});raise AssertionError('API status '+str(e.code)+' at '+path)from None
try:
 assert sha(base/'guest.py')==intent['files']['guest.py']
 assert json.loads(pathlib.Path('/opt/panel/current/SOURCE_INPUTS.json').read_bytes())['inputs_sha256']=='3905be8250f8927d651ab90ec2b2bedafb737f2a4e4bb607b79fd1a18057a6c9'
 before=capture();save('before-all-Core-fields.json',before)
 prior=pathlib.Path(intent['fixture_record']);fixture_record=json.loads(prior.read_bytes());assert fixture_record['regular_entries']==250005
 fixture=pathlib.Path(fixture_record['fixture']);assert str(fixture).startswith('/srv/yunzhan-qa-disk-cancel-')and len(fixture.name)==len('yunzhan-qa-disk-cancel-')+32and fixture.is_dir()and not fixture.is_symlink()
 unique=[pathlib.Path(v['path'])for v in fixture_record['unique']];assert len(unique)==5
 witnesses=[{'path':str(p),'ino':p.stat().st_ino,'nlink':p.stat().st_nlink,'bytes':p.stat().st_size,'sha256':sha(p)}for p in unique];assert witnesses==fixture_record['unique']
 save('fixture-before.json',fixture_record)
 access=json.loads(pathlib.Path('/etc/panel/first-login.json').read_bytes())
 try:status,login=api('/login',{k:access[k]for k in('username','password')})
 finally:access.clear()
 assert status==200 and login['csrf'];csrf=login['csrf']
 status,host=api('/software/disk-analysis/host');assert status==200 and host['installed']is True and host['app_version']=='1.4.1'
 mount=next(m for m in host['inventory']['inventory']['mounts']if m['mount_point']=='/'and m['filesystem']=='ext4')
 selection={**host['inventory']['host'],'mount_id':mount['mount_id'],'mount_binding_sha256':mount['binding_sha256'],'relative_directory':str(fixture).lstrip('/'),'app_version':host['app_version'],'installation_id':host['installation_id'],'app_manifest_sha256':host['app_manifest_sha256']}
 key=secrets.token_hex(16);save('original-host-job-once-intent.json',{'POST_maximum':1,'idempotency_key':key,'selection':selection})
 status,reply=api('/software/disk-analysis/host/jobs',selection,key);save('original-host-job-response.json',{'status':status,'value':reply});assert status==202 and reply['replayed']is False
 job=reply['job']['id'];assert len(job)==32;proof['original_job_id']=job
 for n in range(121):
  status,warm=api('/software/disk-analysis/host/jobs/'+job);save('original-start-observation-%03d.json'%n,{'status':status,'value':warm});assert status==200
  observed=warm.get('observation',{})
  if observed.get('started')is not None and observed['original_process']=='alive'and observed['original_scope']=='busy'and not warm['terminal_verified']:break
  assert not warm['terminal_verified']and n<120,'Original new scan did not reach a verifiable active phase; no cancel retry'
  time.sleep(.05)
 assert observed['started']['job_id']==job and observed['started']['request_sha256']
 save('verified-original-active-worker-before-cancel.json',observed)
 save('original-cancel-once-intent.json',{'original_job_id':job,'POST_maximum':1})
 status,cancel=api('/software/disk-analysis/host/jobs/'+job+'/cancel',{});save('original-cancel-response.json',{'status':status,'value':cancel});assert status==202 and cancel['job']['id']==job and cancel['native_cancel_requested']is True and cancel['cancel_uncertain']is False
 for n in range(181):
  status,detail=api('/software/disk-analysis/host/jobs/'+job);save('original-observation-%03d.json'%n,{'status':status,'value':detail});assert status==200 and detail['job']['id']==job
  if detail['terminal_verified']:break
  assert n<180;time.sleep(1)
 assert detail['terminal_verified']is True and detail['job']['state']=='canceled','Original cancel did not produce a verified cancellation; not retried'
 status,final=api('/software/disk-analysis/host/jobs/'+job);save('actual-terminal-original-result.json',final);assert status==200 and final['terminal_verified']is True
 result=final.get('result')or final.get('observation',{}).get('result');assert result and result['state']=='canceled'
 after_witnesses=[{'path':str(p),'ino':p.stat().st_ino,'nlink':p.stat().st_nlink,'bytes':p.stat().st_size,'sha256':sha(p)}for p in unique];assert witnesses==after_witnesses
 save('fixture-after.json',{'fixture':str(fixture),'unique':after_witnesses})
 status,found=api('/software/disk-analysis/host/requests/'+key);save('read-only-original-key-lookup.json',found);assert status==200 and found['found']is True and found['job']['id']==job
 guard=subprocess.run(['/opt/panel/current/bin/panel-executor','--check-program-upgrade-queues'],capture_output=True,timeout=20);save('complete-guard-after-native-job.json',{'exit':guard.returncode,'stderr_sha256':hashlib.sha256(guard.stderr).hexdigest()});assert guard.returncode==0
 proof.update(ok=True,actual_native_original_scan_canceled_and_terminal_verified=True,original_worker_no_longer_holds_active_slot=True,cancel_POSTs=1,fixture_original_inodes_links_bytes_unchanged=True,read_only_original_request_lookup_verified=True,complete_guard_exit=0,all50_commercial=False)
except BaseException:save('failure.json',{'traceback':traceback.format_exc()})
finally:
 if csrf:
  try:status,_=api('/logout',{});assert status==200;proof['own_session_logged_out']=True
  except BaseException:proof['ok']=False;save('logout-failure.json',{'traceback':traceback.format_exc()})
 after=capture();save('after-all-Core-fields.json',after);save('Core-changed-table-names.json',{'changed':sorted(k for k in set(before)|set(after)if before.get(k)!=after.get(k))}if 'before'in locals()else{})
 save('proof.json',proof)
print(json.dumps(proof));sys.exit(0 if proof['ok']else 1)

