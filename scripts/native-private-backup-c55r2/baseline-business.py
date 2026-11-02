"""Actual C54 normal API -> scheduler -> Root executor; owned disposable data only."""
import ast,contextlib,copy,gzip,hashlib,http.cookiejar,json,os,pathlib,pwd,re,secrets,signal,sqlite3,stat,subprocess,sys,time,traceback,urllib.error,urllib.request,zipfile
os.umask(0o077)
assert os.geteuid()==0 and len(sys.argv)==2
base=pathlib.Path(sys.argv[1]);assert re.fullmatch('/opt/panel-retention-c54-business-[a-f0-9]{32}',str(base))
p=json.loads((base/'intent.json').read_bytes());evidence=base/'evidence';evidence.mkdir(mode=0o700);own_site=p['site_id']
for f in (base,*base.parents):
 s=f.lstat();assert stat.S_ISDIR(s.st_mode)and s.st_uid==0 and not s.st_mode&0o022
def sha(f):return hashlib.sha256(pathlib.Path(f).read_bytes()).hexdigest()
for n,h in p['files'].items():
 f=base/n;s=f.lstat();assert stat.S_ISREG(s.st_mode)and s.st_uid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600 and sha(f)==h
assert pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()==p['peer']['boot']and sha('/etc/machine-id')==p['peer']['machine_id_sha256']
NEW='2b8e71c50b16ba6008955a4d9168b195a087e3063412445a0596f27b53b1bfb9'
assert json.loads(pathlib.Path('/opt/panel/current/SOURCE_INPUTS.json').read_bytes())['inputs_sha256']==NEW
def save(n,v):
 assert re.fullmatch('[A-Za-z0-9._-]+',n)
 with os.fdopen(os.open(evidence/n,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600),'w')as f:json.dump(v,f,sort_keys=True,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
nodes=[v for v in ast.parse((base/'capture.py').read_bytes()).body if isinstance(v,ast.FunctionDef)and v.name in {'sha','command','unit','snapshot'}];assert len(nodes)==4
exec(compile(ast.Module(body=nodes,type_ignores=[]),'<original-read-only-113-capture>','exec'),globals())
def rows(query,values=()):
 with contextlib.closing(sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True,timeout=3))as d:
  d.row_factory=sqlite3.Row;d.execute('PRAGMA query_only=ON');return [dict(v)for v in d.execute(query,values)]
def state(label):
 v=snapshot();v['actual_boot']=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip();assert v['actual_boot']==p['peer']['boot'];v['RPC111']=command(['ss','-H','-lntu','sport','=',':111']);assert not v['RPC111'];raw=json.dumps(v,sort_keys=True,indent=2).encode()
 with(evidence/(label+'.json.gz')).open('xb')as f:f.write(gzip.compress(raw,mtime=0));f.flush();os.fsync(f.fileno())
 save(label+'-storage.json',{'raw_sha256':hashlib.sha256(raw).hexdigest(),'compressed_sha256':sha(evidence/(label+'.json.gz')),'raw_bytes':len(raw)});return v
def entry(f):
 f=pathlib.Path(f)
 if not os.path.lexists(f):return {'exists':False}
 s=f.lstat();assert not stat.S_ISLNK(s.st_mode)and(stat.S_ISDIR(s.st_mode)or stat.S_ISREG(s.st_mode));v={'mode':stat.S_IMODE(s.st_mode),'uid':s.st_uid,'gid':s.st_gid,'ino':s.st_ino,'dev':s.st_dev,'links':s.st_nlink}
 if stat.S_ISREG(s.st_mode):assert s.st_nlink==1 and s.st_size<8<<20;v.update(bytes=s.st_size,sha256=sha(f))
 else:v['children']=sorted(c.name for c in f.iterdir())
 return v
def backup_inventory(label):
 v={}
 def walk(f):
  v[str(f)]=entry(f);assert len(v)<256
  if f.exists()and f.is_dir():
   for child in sorted(f.iterdir()):walk(child)
 for n in('sites','mysql','mariadb'):walk(pathlib.Path('/var/backups/panel')/n)
 save(label+'.json',v);return v
origin='http://127.0.0.1:19100';csrf='';logged=False;events=[];client=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
def api(label,path,body=None,expected=200,method=None):
 method=method or('GET'if body is None else'POST');headers={'Origin':origin,'Content-Type':'application/json','X-CSRF-Token':csrf};safe=body
 if path=='/login':safe={'existing_root_private_credentials':'redacted'}
 if method!='GET':
  key=secrets.token_hex(16);headers['Idempotency-Key']=key;save(label+'-once-intent.json',{'method':method,'path':path,'body':safe,'idempotency_key':key,'maximum_submissions':1,'unknown_outcome':'observe_only'})
 request=urllib.request.Request(origin+'/api'+path,method=method,headers=headers,data=None if body is None else json.dumps(body,separators=(',',':')).encode())
 try:
  with client.open(request,timeout=30)as r:status=r.status;raw=r.read((8<<20)+1)
 except urllib.error.HTTPError as e:status=e.code;raw=e.read((8<<20)+1)
 assert len(raw)<=8<<20;v=json.loads(raw);save(label+'-original-response.json',{'status':status,'value':v if path!='/login'else{'csrf_issued':bool(v.get('csrf'))}});events.append({'path':path,'method':method,'status':status,'at':time.time()});assert status==expected,(path,status,v);return v
def until(label,fn,accept,seconds=80):
 deadline=time.monotonic()+seconds;observations=[]
 while True:
  v=fn();observations.append({'at':time.time(),'value':v})
  if accept(v):save(label+'-original-observations.json',observations);return v
  if time.monotonic()>deadline:save(label+'-original-timeout.json',observations);raise AssertionError('Original operation unresolved; observe only: '+label)
  time.sleep(.25)
def job(identity):
 assert re.fullmatch('[a-f0-9]{32}',identity);v=until('site-create',lambda:rows('SELECT *FROM jobs WHERE id=?',(identity,)),lambda v:len(v)==1 and v[0]['state']not in('queued','running'))[0];assert v['kind']=='create_site'and v['state']=='succeeded'and not v['error'];return v
def schedule(label,site):
 t=time.gmtime(time.time()+8*3600);return api(label,'/schedules',{'name':'C54 '+label+' '+p['nonce'][:12],'kind':'site_backup','target_id':site,'schedule_type':'daily','timezone':'UTC','hour':t.tm_hour,'minute':t.tm_min,'weekday':0,'retention_count':100,'enabled':True},201)
def policy(label,schedule,count,enabled=True):
 body=copy.deepcopy(schedule);body.update(retention_count=count,enabled=enabled);return api(label,'/schedules/'+schedule['id'],body,method='PUT')
def archive(label,schedule,site):
 f=pathlib.Path('/srv/panel/sites')/site/'public/index.html';s=f.lstat();assert stat.S_ISREG(s.st_mode)and s.st_uid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o644
 marker='C54 actual backup '+p['nonce']+' '+label+'\n'
 with f.open('w')as target:target.write(marker);target.flush();os.fsync(target.fileno())
 reply=api(label+'-run','/schedules/'+schedule['id']+'/run',{},202);run=reply['id'];assert re.fullmatch('[a-f0-9]{32}',run)
 terminal=until(label+'-run',lambda:rows('SELECT *FROM schedule_runs WHERE id=?',(run,)),lambda v:len(v)==1 and v[0]['state']not in('queued','running'))[0]
 assert terminal['state']=='succeeded'and not terminal['error']and terminal['schedule_id']==schedule['id'];aid=terminal['artifact_id'];assert re.fullmatch('[a-f0-9]{32}',aid)
 folder=pathlib.Path('/var/backups/panel/sites')/site;z=folder/(aid+'.zip');meta=folder/(aid+'.json');record=rows('SELECT *FROM site_backups WHERE id=?',(aid,))[0];info=entry(z)
 assert info['mode']==0o600 and info['uid']==0 and info['sha256']==record['sha256']and info['bytes']==record['bytes'];assert entry(meta)['mode']==0o600 and entry(folder)['mode']==0o700
 with zipfile.ZipFile(z)as bundle:assert bundle.read('public/index.html').decode()==marker and bundle.testzip()is None
 result={'run':terminal,'backup':record,'zip':info,'manifest':entry(meta),'marker_sha256':hashlib.sha256(marker.encode()).hexdigest()};save(label+'-actual-archive.json',result);return result
def cleanup(sid):return rows('SELECT *FROM site_schedule_cleanup_jobs WHERE schedule_id=?ORDER BY created_at,artifact_id',(sid,))
def same_file(f,expected):assert entry(f)==expected,(str(f),'original file changed')
def lifetime(name):
 v=unit(name);assert int(v['MainPID'])>1;process=pathlib.Path('/proc')/v['MainPID'];v.update(exe_sha256=sha(process/'exe'),start_ticks=process.joinpath('stat').read_text().rsplit(')',1)[1].split()[19]);return v
def signal_original(name,old,sig):
 assert lifetime(name)==old;save(name.replace('.','-')+'-'+signal.Signals(sig).name+'-once-intent.json',{'unit':name,'original_process':old,'signal':signal.Signals(sig).name,'maximum_submissions':1});os.kill(int(old['MainPID']),sig)
proof={'ok':False,'Main_changed':False,'all50_commercial':False,'source_inputs_sha256':NEW,'normal_installed_API_and_real_Root_executor':True,'original_mutation_replay':False};stopped=None;schedules=[];archives=[]
try:
 save('execution-started.json',{'maximum_executions':1});before=state('before-entire113');original_backups=backup_inventory('before-original-backup-directories')
 for n in('sites','mysql','mariadb'):
  v=original_backups['/var/backups/panel/'+n];assert v['uid']==v['gid']==0 and v['mode']in(0o700,0o755)and not v['children']
 for n in('schedules','schedule_runs','site_backups','site_schedule_cleanup_jobs','schedule_cleanup_jobs','mariadb_schedule_cleanup_jobs'):assert not before['tables'][n]['rows'],n
 access_path=pathlib.Path('/etc/panel/first-login.json');assert entry(access_path)['mode']==0o600;access=json.loads(access_path.read_bytes())
 try:csrf=api('one-login','/login',{k:access[k]for k in('username','password')})['csrf'];logged=True
 finally:access.clear()
 nonce=p['nonce'][:12];reply=api('one-owned-site-create','/sites',{'name':'C54 actual retention acceptance','slug':'qa-retention-c54-'+nonce,'domain':'qa-retention-c54-'+nonce+'.localhost','php_version_id':''},202);created=job(reply['job_id']);site=created['site_id'];assert re.fullmatch('[a-f0-9]{32}',site);proof.update(site_id=site,create_job=created['id']);save('owned-site.json',created)
 a=schedule('failed-head',site);schedules.append(a)
 for i in range(4):archives.append(archive('fairness-'+str(i),a,site));time.sleep(1.05)
 first=archives[0];second=archives[1];folder=pathlib.Path('/var/backups/panel/sites')/site;z=folder/(first['backup']['id']+'.zip');same_file(z,first['zip']);save('owned-permission-failure-once-intent.json',{'path':str(z),'before':first['zip'],'target_mode':0o640,'only_owned_test_file':True});z.chmod(0o640)
 a=policy('one-retention-two',a,2);schedules[0]=a
 terminal=until('real-failed-head-and-next-expired',lambda:cleanup(a['id']),lambda v:len(v)==2 and sum(x['state']=='completed'for x in v)==1 and any(x['attempts']==1 and x['last_error']and x['state']=='pending'for x in v))
 failed=next(x for x in terminal if x['artifact_id']==first['backup']['id']);done=next(x for x in terminal if x['artifact_id']==second['backup']['id']);assert failed['state']=='pending'and failed['attempts']==1 and '权限' in failed['last_error']and done['state']=='completed'and done['attempts']==1 and not done['last_error'];assert not os.path.lexists(folder/(second['backup']['id']+'.zip'))and not os.path.lexists(folder/(second['backup']['id']+'.json'))
 receipt=json.loads((folder/('.deleted-'+second['backup']['id']+'.json')).read_bytes());assert receipt['state']=='deleted'and receipt['backup']['id']==second['backup']['id']and receipt['backup']['sha256']==second['backup']['sha256']
 changed=dict(first['zip'],mode=0o640);same_file(z,changed);save('owned-permission-restore-once-intent.json',{'path':str(z),'expected':changed,'target_mode':0o600});z.chmod(0o600);same_file(z,first['zip']);time.sleep(6.5);assert cleanup(a['id'])==terminal
 for x in archives[2:]:same_file(folder/(x['backup']['id']+'.zip'),x['zip']);same_file(folder/(x['backup']['id']+'.json'),x['manifest'])
 save('actual-failed-head-does-not-starve-and-no-retry.json',{'original_records':terminal,'deleted_receipt':receipt,'restored_original_file':entry(z),'observation_seconds_after_permission_restore':6.5});proof['real_failed_head_does_not_starve']=True;proof['failure_not_replayed_after_permission_restore']=True
 a=policy('pause-fairness-schedule',a,2,False);schedules[0]=a
 b=schedule('unknown-after-dispatch',site);schedules.append(b);unknown_archives=[]
 for i in range(3):unknown_archives.append(archive('unknown-'+str(i),b,site));time.sleep(1.05)
 executor=lifetime('panel-executor.service');core=lifetime('panel.service');signal_original('panel-executor.service',executor,signal.SIGSTOP);stopped=executor
 try:
  b=policy('one-unknown-retention-two',b,2);schedules[1]=b
  unknown=until('actual-durable-dispatch-before-Core-kill',lambda:cleanup(b['id']),lambda v:len(v)==1 and v[0]['attempts']==1 and v[0]['state']=='pending',seconds=15)[0]
  assert unknown['artifact_id']==unknown_archives[0]['backup']['id']and unknown['last_error']=='清理请求已登记，执行结果尚未确认；原备份与记录需核对，不自动重复执行';audit=rows("SELECT *FROM audit_logs WHERE action='schedule.retention.dispatch'AND target=?",('site:'+unknown['artifact_id'],));assert len(audit)==1;save('actual-durable-unknown-row-and-audit-before-kill.json',{'row':unknown,'audit':audit,'core':core,'executor':executor});signal_original('panel.service',core,signal.SIGKILL)
 finally:
  assert lifetime('panel-executor.service')==executor;os.kill(int(executor['MainPID']),signal.SIGCONT);stopped=None;save('original-executor-resumed.json',{'same_process':executor,'signal':'SIGCONT','maximum_submissions':1})
 current=until('Core-restarted-after-SIGKILL',lambda:unit('panel.service'),lambda v:v['ActiveState']=='active'and int(v['MainPID'])>1 and v['MainPID']!=core['MainPID'],seconds=50);time.sleep(7);assert lifetime('panel-executor.service')==executor;assert cleanup(b['id'])==[unknown]and rows("SELECT *FROM audit_logs WHERE action='schedule.retention.dispatch'AND target=?",('site:'+unknown['artifact_id'],))==audit
 save('actual-unknown-remains-without-second-dispatch-after-Core-crash.json',{'original_row':unknown,'current_row':cleanup(b['id'])[0],'single_original_audit':audit,'new_Core':lifetime('panel.service'),'executor_original_process':executor,'first_possible_Root_result':{name:entry(folder/name)for name in(unknown['artifact_id']+'.zip',unknown['artifact_id']+'.json','.deleted-'+unknown['artifact_id']+'.json')},'no_result_forged_or_replayed':True});proof['durable_unknown_not_replayed_after_real_Core_SIGKILL']=True
 b=policy('pause-unknown-schedule',b,2,False);schedules[1]=b
 page=api('actual-readonly-retention-records','/schedules/retention?limit=10&offset=0');assert page['read_only']and page['total']==3 and page['counts']=={'needs_attention':2,'completed':1,'ready':0,'held':0}and len(page['items'])==3 and all(v['attempts']==1 for v in page['items']);save('actual-retention-summary.json',page)
 for x in unknown_archives[1:]:same_file(folder/(x['backup']['id']+'.zip'),x['zip']);same_file(folder/(x['backup']['id']+'.json'),x['manifest'])
 proof.update(ok=True,real_backups_created=7,actual_completed_deletions=1,original_failed_cleanup_records_preserved=1,original_unknown_cleanup_records_preserved=1,only_owned_new_site_modified=True,schedule_ids=[v['id']for v in schedules],business_runs=[v['run']['id']for v in archives+unknown_archives],backup_artifact_ids=[v['backup']['id']for v in archives+unknown_archives],Core_process_before=core,Core_process_after=lifetime('panel.service'),original_executor_process_preserved=True,normal_whole_VM_powerloss_pending=True)
except BaseException:save('original-failure.json',{'traceback':traceback.format_exc()})
finally:
 if stopped is not None:
  try:
   assert lifetime('panel-executor.service')==stopped;os.kill(int(stopped['MainPID']),signal.SIGCONT);save('emergency-original-executor-resumed.json',{'original':stopped})
  except BaseException:save('resume-observation-failure.json',{'traceback':traceback.format_exc()})
 if logged:
  try:api('one-logout','/logout',{});logged=False
  except BaseException:save('logout-original-failure.json',{'traceback':traceback.format_exc()})
 try:state('after-entire113');backup_inventory('after-original-and-owned-backups')
 except BaseException:save('final-observation-error.json',{'traceback':traceback.format_exc()});proof['ok']=False
 save('events.json',events);save('proof.json',proof);print(json.dumps({'ok':proof['ok'],'base':str(base),'proof_sha256':sha(evidence/'proof.json'),'Main_changed':False}),flush=True)
sys.exit(0 if proof['ok']else 1)
