"""Fresh original-signed programme, Apache/PHP installation and body requests.
All mutations are submitted once; an unknown result is retained, never replayed.
"""
import ast,contextlib,copy,fcntl,hashlib,http.cookiejar,json,os,pathlib,platform,pwd,re,runpy,secrets,socket,sqlite3,stat,subprocess,sys,time,traceback,urllib.error,urllib.request
os.umask(0o077);assert len(sys.argv)==2 and os.geteuid()==0
payload=pathlib.Path(sys.argv[1]).resolve(strict=True);pins=json.loads((payload/'assets.json').read_bytes())
SOURCE='44fa6a9522dbf207647c5664d05fbfbdc9f348e4bd2b66560373e1140805ba72'
VERSION='0.1.0-dev.proapps24apachewriterbusycandidate52'
assert platform.machine()=='x86_64'and pins['architecture']=='amd64'and pins['source_inputs_sha256']==SOURCE and pins['version']==VERSION
case=pins['OS_case'];assert case['architecture']=='amd64'and case['platform']in('debian-12','debian-13','ubuntu-22.04','ubuntu-24.04','ubuntu-26.04')
assert pathlib.Path('/etc/hostname').read_text().strip()==case['hostname']
assert 'VERSION_ID="'+case['version_id']+'"'in pathlib.Path('/usr/lib/os-release').read_text()and pathlib.Path('/proc/1/comm').read_text().strip()=='systemd'
base=pathlib.Path('/opt/panel-apache-c52-native-qa-'+secrets.token_hex(16));base.mkdir(mode=0o700);evidence=base/'evidence';evidence.mkdir(mode=0o700)
def sha(f):return hashlib.sha256(pathlib.Path(f).read_bytes()).hexdigest()
def save(n,v):
 assert re.fullmatch('[A-Za-z0-9._-]+',n)
 with os.fdopen(os.open(evidence/n,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600),'w')as f:json.dump(v,f,sort_keys=True,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
verified=base/'verified-input';verified.mkdir(mode=0o700)
for name,digest in pins['files'].items():
 assert re.fullmatch('[A-Za-z0-9._-]+',name)
 with os.fdopen(os.open(payload/name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC),'rb')as f:
  s=os.fstat(f.fileno());assert stat.S_ISREG(s.st_mode)and s.st_nlink==1 and 0<s.st_size<=64<<20
  raw=f.read((64<<20)+1);z=os.fstat(f.fileno())
  assert len(raw)==s.st_size and hashlib.sha256(raw).hexdigest()==digest and(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)==(z.st_dev,z.st_ino,z.st_size,z.st_mtime_ns,z.st_ctime_ns)
 with os.fdopen(os.open(verified/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600),'wb')as f:f.write(raw);f.flush();os.fsync(f.fileno())
payload=verified
assert sha(payload/'signed-release.py')=='fe128e82b4e11345b320cd782134768bfe1a4df14947c425d7494873a7a7b7b5'
assert sha(payload/'release-signing-dev.pub')=='4ccfcc861d56a41e3ba7f7ace7e2432c815f366c58448d783df92c6632f01339'
names={'command','unit','snapshot','api','NoRedirect'}
nodes=[n for n in ast.parse((payload/'capture.py').read_bytes()).body if isinstance(n,(ast.FunctionDef,ast.ClassDef))and n.name in names]
assert len(nodes)==len(names);exec(compile(ast.Module(body=nodes,type_ignores=[]),'<original-bound-readonly-and-once-HTTP-client>','exec'),globals())
boot=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip();p={'boot':boot};own_site=None;secret=secrets.token_hex(32)
origin='http://127.0.0.1:19100';csrf='';events=[];requests=[];reached=[];native_processes={}
client=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect(),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
proof={'ok':False,'architecture':'amd64','base':str(base),'source_inputs_sha256':SOURCE,'OS_case':case,'normal_programme_installer_submissions':0,'legacy_WAF_install_POSTs':0,'signed_runtime_install_POSTs':0,'signed_WAF_update_POSTs':0,'site_create_POSTs':0,'site_settings_POSTs':0,'body_engine_build_POSTs':0,'body_configure_POSTs':0,'synthetic_HTTP_requests':0,'Main_changed':False,'all50_commercial':False,'original_operations_replayed':False,'actual_browser_UI_acceptance':False}
def wait_job(label,jid,table):
 assert re.fullmatch('[a-f0-9]{32}',jid)and table in('jobs','runtime_jobs');deadline=time.monotonic()+5400;observations=[]
 while True:
  with contextlib.closing(sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True))as db:
   db.row_factory=sqlite3.Row;db.execute('PRAGMA query_only=ON');row=dict(db.execute('SELECT *FROM '+table+' WHERE id=?',(jid,)).fetchone())
  if not observations or observations[-1]['state']!=row['state']:observations.append({'state':row['state'],'at':time.time()})
  if row['state']not in('queued','running'):break
  assert time.monotonic()<deadline,'Original job unresolved; observe only';time.sleep(2)
 save(label+'-original-observations.json',observations);save(label+'-original-terminal.json',row)
 assert row['state']=='succeeded'and not row['error'],(label,row['state'],row['error']);return row
def guard(label):
 for i in range(9):
  v=subprocess.run(['/opt/panel/current/bin/panel-executor','--check-program-upgrade-queues'],capture_output=True,timeout=35)
  u=unit('panel-mysql-overwrite-recovery.service')
  save(label+'-guard-'+str(i)+'.json',{'exit':v.returncode,'stdout_hex':v.stdout.hex(),'stderr_hex':v.stderr.hex(),'recovery_unit':u})
  if v.returncode==0:assert v.stdout==v.stderr==b'';return
  assert i<8 and v.stdout==b''and b'panel-mysql-overwrite-recovery.service'in v.stderr and u['ActiveState']=='activating'and u['SubState']=='condition'and u['MainPID']=='0'
  time.sleep(1)
def run_once(label,args,timeout):
 save(label+'-once-intent.json',{'args':args,'maximum_submissions':1,'unknown_observe_only':True})
 with(evidence/(label+'.stdout.log')).open('xb')as out,(evidence/(label+'.stderr.log')).open('xb')as err:v=subprocess.run(args,stdin=subprocess.DEVNULL,stdout=out,stderr=err,timeout=timeout)
 save(label+'-original-outcome.json',{'exit':v.returncode,'stdout_sha256':sha(evidence/(label+'.stdout.log')),'stderr_sha256':sha(evidence/(label+'.stderr.log'))})
 assert v.returncode==0,'Original operation failed; no replay: '+label
def catalogue(label):
 v=api(label,'/app-registry?refresh=1');assert len(v['catalog']['apps'])==50 and not v['source']['stale']and v['host']=={'platform':case['platform'],'architecture':'amd64'};return v
def pair(v,app):return next(x for x in v['catalog']['apps']if x['id']==app),next(x for x in v['status']if x['id']==app)
def install_runtime(app,version):
 v=catalogue(app+'-original-signed-catalogue');item,status=pair(v,app);assert item['version']==version and status['state_known']and not status['installed']
 proof['signed_runtime_install_POSTs']+=1
 reply=api(app+'-one-original-signed-runtime-install','/app-registry/'+app+'/install',{'expected_version':item['version'],'expected_sha256':item['sha256']},202,secrets.token_hex(16))
 row=wait_job(app+'-original-install',reply['job_id'],'runtime_jobs');assert row['kind']=='install_runtime'
 v=catalogue(app+'-actual-installed-catalogue');_,status=pair(v,app);assert status['state_known']and status['installed']and status['installed_version']==version and not status['update_available']
 save(app+'-signed-runtime-receipt.json',{'job_id':reply['job_id'],'item':item,'status':status})
 return reply['job_id']
def counter_rows():
 s=counter.lstat();assert stat.S_ISREG(s.st_mode)and stat.S_IMODE(s.st_mode)==0o600 and s.st_nlink==1 and s.st_uid==account.pw_uid and s.st_gid==account.pw_gid and s.st_size<=262144
 rows=counter.read_text().splitlines();assert all(re.fullmatch('[a-f0-9]{32}',x)for x in rows)and len(rows)==len(set(rows));return rows
automatic_read_contentions=[]
def automatic_status_observation(label):
 # Only this fixed read-only GET may wait after the exact shared-lock conflict.
 # The original HTTP response and event have already been saved by api().
 try:return api(label,'/software/apache-waf/body-log/automatic')
 except AssertionError:
  original=evidence/(label+'-original-response.json')
  if not original.is_file():raise
  response=json.loads(original.read_bytes())
  if response!={'status':409,'value':{'error':'WAF 正在变更或恢复，请稍后重试'}}:raise
  automatic_read_contentions.append({'label':label,'at':time.time(),'method':'GET','path':'/software/apache-waf/body-log/automatic','status':409})
  return None
def request_once(mode,port,c):
 rid=secrets.token_hex(16);label=mode+'-'+str(port)+'-'+c['name'];before=counter_rows();assert before==reached
 raw=bytes.fromhex(c['body_hex']);assert len(raw)==c['body_bytes']and hashlib.sha256(raw).hexdigest()==c['body_sha256']
 headers={'Host':domain,'User-Agent':'Mozilla/5.0 Yunzhan owned native acceptance','X-Yunzhan-QA-Request':rid}
 if c['content_type']:headers['Content-Type']=c['content_type']
 if c['encoding']:headers['Content-Encoding']=c['encoding']
 wanted=c['block_status']if mode=='block'else 200
 save(label+'-one-HTTP-intent.json',{'request_id':rid,'method':c['method'],'port':port,'body_bytes':len(raw),'body_sha256':c['body_sha256'],'expected_status':wanted,'maximum_submissions':1})
 req=urllib.request.Request('http://127.0.0.1:'+str(port)+'/'+probe_name,data=None if c['method']=='GET'else raw,headers=headers,method=c['method'])
 opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect());proof['synthetic_HTTP_requests']+=1
 try:
  with opener.open(req,timeout=15)as response:status=response.status;body=response.read(8193);rh=response.headers.get('X-Yunzhan-QA-Reached','')
 except urllib.error.HTTPError as e:status=e.code;body=e.read(8193);rh=e.headers.get('X-Yunzhan-QA-Reached','')
 assert len(body)<=8192
 # Actual original successful PHP response bytes are retained encrypted.
 result={'mode':mode,'route_port':port,'case':c['name'],'request_id':rid,'status':status,'body_bytes':len(body),'body_sha256':hashlib.sha256(body).hexdigest(),'original_body_hex':body.hex(),'PHP_reached_header':rh};save(label+'-original-HTTP-result.json',result);requests.append(result)
 assert status==wanted,(label,status,wanted)
 if wanted==200:
  v=json.loads(body);assert v['marker']==php_marker and v['php']=='8.2.35'and v['pid']>1 and rh==rid
  process=pathlib.Path('/proc')/str(v['pid']);ps=dict(x.split(':',1)for x in(process/'status').read_text().splitlines()if':'in x)
  assert int(ps['Uid'].split()[1])==account.pw_uid and int(ps['Gid'].split()[1])==account.pw_gid and ps['NoNewPrivs'].strip()=='1'and all(int(ps[k],16)==0 for k in('CapPrm','CapEff','CapAmb'))
  native_processes[str(v['pid'])]={'UID':int(ps['Uid'].split()[1]),'GID':int(ps['Gid'].split()[1]),'NoNewPrivs':ps['NoNewPrivs'].strip(),'capabilities':{k:ps[k].strip()for k in('CapInh','CapPrm','CapEff','CapAmb')},'cgroup':(process/'cgroup').read_text(),'exe_sha256':sha(process/'exe'),'start_ticks':process.joinpath('stat').read_text().rsplit(')',1)[1].split()[19]}
  if c['expected_upload_sha256']is not None:assert v['files']['upload']=={'error':0,'bytes':len(b'ordinary owned upload content\n'),'sha256':c['expected_upload_sha256']}and v['raw_bytes']==0 and v['raw_sha256']==hashlib.sha256(b'').hexdigest()
  else:assert v['raw_bytes']==len(raw)and v['raw_sha256']==c['body_sha256']and v['files']==[]
  if c['expected_term_sha256']is not None:assert v['term_sha256']==c['expected_term_sha256']
  reached.append(rid);assert counter_rows()==reached
 else:assert not rh and counter_rows()==before
def verify_actual_automatic_rotation():
 """Use real PHP requests and the installed daemon's minute timer, never runOnce."""
 global reached
 baseline=api('auto-default-before-optin','/software/apache-waf/body-log/automatic')
 assert not baseline['configured']and baseline['policy_revision']==0 and not baseline['policy']['enabled']
 original=api('auto-original-paused-config','/software/apache-waf/config')
 assert original['settings']['body']=={'engine_job_id':engine_id,'sites':[]}
 settings=copy.deepcopy(original['settings'])
 settings['body']={'engine_job_id':engine_id,'sites':[{'site_id':own_site,'policy':{'mode':'observe','paranoia_level':1,'inbound_threshold':5,'body_limit_kib':128,'non_file_limit_kib':64,'json_depth':64,'argument_limit':256}}]}
 reply=api('auto-one-observe-enable','/software/apache-waf/configure',{'settings':settings},202,secrets.token_hex(16));wait_job('auto-observe-enable',reply['job_id'],'runtime_jobs')
 c=next(v for v in cases if v['name']=='form_sqli');body=bytes.fromhex(c['body_hex']);results=[];opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
 assert counter_rows()==reached and len(reached)==136
 save('auto4000-original-request-intent.json',{'method':'POST','port':19080,'maximum_HTTP_submissions':4000,'automatic_retries':0,'body_bytes':len(body),'body_sha256':c['body_sha256']})
 for i in range(4000):
  rid=secrets.token_hex(16);proof['synthetic_HTTP_requests']+=1
  req=urllib.request.Request('http://127.0.0.1:19080/'+probe_name,data=body,headers={'Host':domain,'Content-Type':c['content_type'],'User-Agent':'Mozilla/5.0 Yunzhan owned native timer acceptance','X-Yunzhan-QA-Request':rid})
  with opener.open(req,timeout=15)as response:status=response.status;raw=response.read(8193);rh=response.headers.get('X-Yunzhan-QA-Reached')
  assert status==200 and len(raw)<=8192 and rh==rid
  v=json.loads(raw);assert v['marker']==php_marker and v['php']=='8.2.35'and v['raw_bytes']==len(body)and v['raw_sha256']==c['body_sha256']
  pid=str(v['pid'])
  if pid not in native_processes:
   proc=pathlib.Path('/proc')/pid;ps=dict(x.split(':',1)for x in(proc/'status').read_text().splitlines()if':'in x)
   assert int(ps['Uid'].split()[1])==account.pw_uid and int(ps['Gid'].split()[1])==account.pw_gid and ps['NoNewPrivs'].strip()=='1'and all(int(ps[k],16)==0 for k in('CapInh','CapPrm','CapEff','CapAmb'))
   native_processes[pid]={'UID':int(ps['Uid'].split()[1]),'GID':int(ps['Gid'].split()[1]),'NoNewPrivs':ps['NoNewPrivs'].strip(),'capabilities':{k:ps[k].strip()for k in('CapInh','CapPrm','CapEff','CapAmb')},'cgroup':(proc/'cgroup').read_text(),'exe_sha256':sha(proc/'exe'),'start_ticks':proc.joinpath('stat').read_text().rsplit(')',1)[1].split()[19]}
  reached.append(rid);results.append({'request_id':rid,'status':status,'pid':int(pid),'response_sha256':hashlib.sha256(raw).hexdigest(),'original_body_hex':raw.hex()})
  if(i+1)%500==0:save('auto-HTTP-progress-'+str(i+1)+'.json',{'actual_completed':i+1,'at':time.time(),'current_log_bytes':pathlib.Path('/var/lib/panel-apache-body/events.log').stat().st_size})
 assert counter_rows()==reached and len(reached)==4136 and len(set(reached))==4136
 save('auto4000-original-HTTP-results.json',results);save('auto-actual-nonroot-FPM-processes.json',native_processes)
 current=api('auto-before-pause-current-config','/software/apache-waf/config');restore=copy.deepcopy(original['settings']);restore['policy']['revision']=current['settings']['policy']['revision']
 reply=api('auto-one-pause-restore','/software/apache-waf/configure',{'settings':restore},202,secrets.token_hex(16));wait_job('auto-pause-restore',reply['job_id'],'runtime_jobs')
 after=api('auto-actual-restored-paused-config','/software/apache-waf/config');expected=copy.deepcopy(restore);expected['policy']['revision']+=1;assert after['settings']==expected and after['status']['healthy']
 log=pathlib.Path('/var/lib/panel-apache-body/events.log');before=log.lstat();raw=log.read_bytes();digest=hashlib.sha256(raw).hexdigest();assert 1<<20<=len(raw)<16<<20 and len(raw)==before.st_size
 numeric=[json.loads(line)for line in raw.splitlines()]
 assert all(set(e)=={'time_us','engine','site_id','rule_id','phase','severity','mode','blocked'}and e['engine']=='2.9.15-yz5'and e['site_id']==own_site and e['mode']=='observe'and not e['blocked']for e in numeric)
 assert body_marker.encode()not in raw and php_marker.encode()not in raw and domain.encode()not in raw
 save('auto-original-numeric-log.json',{'bytes':len(raw),'sha256':digest,'original_hex':raw.hex(),'rule_matches':len(numeric),'actual_HTTP_requests':4000,'source_stat':{'dev':before.st_dev,'ino':before.st_ino,'uid':before.st_uid,'gid':before.st_gid,'mode':before.st_mode,'bytes':before.st_size,'sha256':digest}})
 inventory=api('auto-original-empty-inventory','/software/apache-waf/body-log/archives');assert inventory['archives']==inventory['recovery']==inventory['index_stages']==[]and inventory['maintenance_healthy']and inventory['inventory_complete']
 lifetimes={name:unit(name)for name in('panel.service','panel-executor.service','nginx.service','panel-apache.service','panel-php@'+own_site+'-php-8.2.35.service')};save('auto-before-timer-lifetimes.json',lifetimes);save('auto-before-timer-entire113.json',snapshot())
 writer=os.fdopen(os.open(log,os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC),'r+b',buffering=0)
 try:
  fcntl.flock(writer.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
  held=pathlib.Path('/proc/self/fdinfo')/str(writer.fileno());info=held.read_text()
  assert 'FLOCK'in info and 'WRITE'in info and log.read_bytes()==raw
  save('auto-real-BSD-writer-held.json',{'pid':os.getpid(),'fd':writer.fileno(),'fdinfo':info,'source_inode':before.st_ino,'original_bytes':len(raw),'original_sha256':digest})
  enabled=api('auto-one-explicit-policy-enable','/software/apache-waf/body-log/automatic/configure',{'expected_revision':0,'enabled':True,'rotate_mib':1,'max_age_minutes':60})
  assert enabled['configured']and enabled['policy_revision']==1 and enabled['policy']=={'enabled':True,'rotate_mib':1,'max_age_minutes':60}
  busy_observations=[];busy_deadline=time.monotonic()+150;busy_reads=0
  while True:
   current=automatic_status_observation('auto-known-writer-busy-readonly-'+str(busy_reads));busy_reads+=1
   if current is None:
    assert time.monotonic()<busy_deadline,'Read-only configuration lock remains busy; original operation unresolved'
    time.sleep(3);continue
   busy_observations.append(current);busy_record=current['record']
   assert busy_record['state']in('idle','blocked')and not busy_record.get('error_code'),busy_record
   assert busy_record['history']==enabled['record']['history']and all(busy_record.get(k)==enabled['record'].get(k)for k in('window_started_at','last_rotation_at'))
   assert log.read_bytes()==raw and log.lstat().st_ino==before.st_ino and list(pathlib.Path('/var/lib/panel-apache-body/archives').iterdir())==[]
   if busy_record['state']=='blocked':break
   assert time.monotonic()<busy_deadline,'Actual BSD writer exclusion result unresolved; no replay'
   time.sleep(3)
  save('auto-actual-known-busy-original-result.json',{'ok':True,'observations':busy_observations,'record':busy_record,'source_inode_unchanged':True,'source_bytes_unchanged':True,'no_snapshots_created':True,'no_unknown_fence':True,'original_window_and_history_preserved':True,'fdinfo':held.read_text()})
 finally:
  fcntl.flock(writer.fileno(),fcntl.LOCK_UN);writer.close()
 released_at=time.time();save('auto-real-BSD-writer-released.json',{'at':released_at,'next_minute_check_is_new_operation_not_replay':True})
 save('auto-real-minute-timer-wait-started.json',{'at':time.time(),'maximum_wait_seconds':150,'direct_rotate_or_runOnce_calls':0})
 observations=[];deadline=time.monotonic()+150;timer_reads=0
 while True:
  v=automatic_status_observation('auto-timer-readonly-'+str(timer_reads));timer_reads+=1
  if v is None:
   assert time.monotonic()<deadline,'Read-only configuration lock remains busy; original operation unresolved'
   time.sleep(3);continue
  observations.append(v);record=v['record']
  assert record['state']in('idle','blocked','rotating','completed')and not record.get('error_code'),record
  if record.get('last_rotation_at'):break
  assert time.monotonic()<deadline,'Actual installed daemon timer unresolved; no replay'
  time.sleep(5)
 assert record['id']!=busy_record['id']and record['checked_at']>busy_record['checked_at']
 row=record['archive'];assert row['state']=='completed'and row['bytes']==len(raw)and row['sha256']==digest and record['archive_count']==1 and len(record['history'])==1 and record['history'][0]['archive']==row
 copied=pathlib.Path('/var/lib/panel-apache-body/archives')/(row['id']+'.log');assert copied.read_bytes()==raw
 end=log.lstat();assert end.st_size==0 and(before.st_dev,before.st_ino,before.st_uid,before.st_gid,before.st_mode)==(end.st_dev,end.st_ino,end.st_uid,end.st_gid,end.st_mode)
 disabled=api('auto-one-explicit-policy-disable','/software/apache-waf/body-log/automatic/configure',{'expected_revision':1,'enabled':False,'rotate_mib':1,'max_age_minutes':60})
 assert disabled['policy_revision']==2 and not disabled['policy']['enabled']and disabled['record']['history']==record['history']and disabled['record']['window_started_at']==record['window_started_at']and disabled['record']['id']==record['id']
 assert lifetimes=={name:unit(name)for name in lifetimes}
 save('auto-actual-minute-timer-original-result.json',{'ok':True,'observations':observations,'archive':row,'actual_original_log_bytes':len(raw),'actual_rule_matches':len(numeric),'actual_HTTP_requests':4000,'same_inode':True,'no_service_reload_by_timer':True,'all_original_primary_service_lifetimes_unchanged':True,'policy_disabled_history_window_id_preserved':True,'direct_timer_invocations':0,'known_BSD_writer_contention_deferred':True,'busy_record_id':busy_record['id'],'completed_record_id':record['id'],'lock_released_at':released_at,'live_after':{'dev':end.st_dev,'ino':end.st_ino,'uid':end.st_uid,'gid':end.st_gid,'mode':end.st_mode,'bytes':end.st_size,'sha256':hashlib.sha256(log.read_bytes()).hexdigest()}})
 save('auto-after-timer-entire113.json',snapshot());guard('auto-real-timer-completed')
 proof.update(actual_installed_minute_automatic_timer_verified=True,additional_actual_nonroot_PHP_HTTP_requests=4000,total_actual_HTTP_requests=proof['synthetic_HTTP_requests'],total_actual_PHP_reached=len(reached),automatic_numeric_rule_matches=len(numeric),automatic_archive=row,automatic_real_requests_same_inode_and_original_bytes_verified=True,automatic_original_window_history_preserved_on_disable=True,automatic_timer_primary_services_lifetimes_preserved=True,real_BSD_writer_known_noop_deferred=True,all4000_original_PHP_response_bodies_retained=True,automatic_cold_powerloss_and_full_failure_paths_pending=True)



arch='amd64'
def verify_full_installed_archive():
    import tarfile
    name = 'panel-' + VERSION + '-linux-' + arch + '.tar.gz'
    archive = payload / name
    assert sha(archive) == pins['files'][name]
    installed = pathlib.Path('/opt/panel/current').resolve(strict=True)
    assert str(installed) == '/opt/panel/releases/' + VERSION
    records = []
    prefix = 'panel-' + VERSION + '-linux-' + arch + '/'
    with tarfile.open(archive, 'r:gz') as stream:
        for member in stream.getmembers():
            if member.name.rstrip('/') == prefix.rstrip('/'):
                relative = ''
            else:
                assert member.name.startswith(prefix)
                relative = member.name[len(prefix):].rstrip('/')
            assert not pathlib.PurePosixPath(relative).is_absolute() and '..' not in pathlib.PurePosixPath(relative).parts
            f = installed / relative
            s = f.lstat()
            assert s.st_uid == 0 and stat.S_IMODE(s.st_mode) == member.mode
            record = {'path': relative, 'mode': member.mode, 'uid': s.st_uid, 'gid': s.st_gid, 'inode': s.st_ino}
            if member.isfile():
                assert stat.S_ISREG(s.st_mode) and s.st_nlink == 1
                digest = hashlib.sha256(stream.extractfile(member).read()).hexdigest()
                assert sha(f) == digest
                record.update(type='file', sha256=digest, bytes=s.st_size)
            else:
                assert member.isdir() and stat.S_ISDIR(s.st_mode)
                record.update(type='directory')
            records.append(record)
    actual = {''} | {str(f.relative_to(installed)) for f in installed.rglob('*')}
    assert actual == {v['path'] for v in records} and len(records) == 203
    save('actual-entire-signed-installed-tree.json', {'ok': True, 'read_only': True, 'archive_sha256': sha(archive), 'installed': str(installed), 'entries': records, 'count': 203, 'source_inputs_sha256': json.loads((installed / 'SOURCE_INPUTS.json').read_bytes())['inputs_sha256']})

try:
 assert all(not os.path.lexists(n)for n in('/opt/panel','/var/lib/panel','/var/lib/panel-executor','/etc/panel-release','/etc/nginx/nginx.conf'))
 archive=payload/('panel-'+VERSION+'-linux-amd64.tar.gz');signer=['python3','-I','-B',str(payload/'signed-release.py')];key=['--public-key',str(payload/'release-signing-dev.pub')]
 run_once('original-programme-signature-verify',signer+['verify',str(archive)]+key,30)
 proof['normal_programme_installer_submissions']+=1;run_once('one-original-programme-first-install',signer+['install',str(archive)]+key,1800)
 assert json.loads(pathlib.Path('/opt/panel/current/SOURCE_INPUTS.json').read_bytes())['inputs_sha256']==SOURCE and not os.path.lexists('/opt/panel/DEVELOPMENT_RELEASE')
 verify_full_installed_archive()
 guard('programme-ready');save('programme-installed-before-apps.json',snapshot())
 access_file=pathlib.Path('/etc/panel/first-login.json');s=access_file.lstat();assert stat.S_ISREG(s.st_mode)and s.st_uid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600
 access=json.loads(access_file.read_bytes())
 try:csrf=api('login','/login',{k:access[k]for k in('username','password')})['csrf']
 finally:access.clear()
 install_runtime('apache','2.4.68-compat1');install_runtime('php-82','8.2.35-compat2')
 nonce=secrets.token_hex(16);domain='qa-ap24-'+nonce[:12]+'.example.test';probe_name='qa-apache24-body-'+nonce[:12]+'.php';php_marker='apache24-php-'+nonce;body_marker='apache24-body-'+nonce
 proof['site_create_POSTs']+=1;reply=api('one-owned-PHP-site-create','/sites',{'name':'Apache native real PHP acceptance','slug':'qa-ap24-'+nonce[:12],'domain':domain,'php_version_id':'php-8.2.35'},202,secrets.token_hex(16));created=wait_job('owned-site-create',reply['job_id'],'jobs');own_site=created['site_id'];assert re.fullmatch('[a-f0-9]{32}',own_site)
 site=api('actual-created-PHP-site','/sites/'+own_site+'/settings');assert site['status']=='running'and site['settings']['web_server']=='nginx'and site['php_version_id']=='php-8.2.35'
 settings=copy.deepcopy(site['settings']);settings['web_server']='apache';preview=api('owned-Apache-site-readonly-preview','/sites/'+own_site+'/settings/preview',{'settings':settings,'expected_revision':site['settings_revision']})
 assert preview['revision']==site['settings_revision']and hashlib.sha256(preview['current'].encode()).hexdigest()==preview['config_sha']and 'proxy_pass http://127.0.0.1:19080;'in preview['candidate']
 proof['site_settings_POSTs']+=1;reply=api('one-owned-Apache-site-save','/sites/'+own_site+'/settings',{'settings':settings,'expected_revision':site['settings_revision'],'expected_config_sha':preview['config_sha']},202,secrets.token_hex(16));wait_job('owned-Apache-site-save',reply['job_id'],'jobs')
 account=pwd.getpwnam('ps'+own_site[:24]);assert account.pw_uid>0 and account.pw_gid>0
 root=pathlib.Path('/srv/panel/sites')/own_site
 public=(root/'public').lstat();private=(root/'private').lstat()
 assert stat.S_IMODE(public.st_mode)==0o750 and public.st_uid==account.pw_uid and public.st_gid==pwd.getpwnam('www-data').pw_gid
 assert stat.S_IMODE(private.st_mode)==0o700 and private.st_uid==account.pw_uid and private.st_gid==account.pw_gid
 save('actual-site-native-account.json',{'site_id':own_site,'UID':account.pw_uid,'primary_GID':account.pw_gid,'public_GID':public.st_gid,'domain':domain,'probe':probe_name})
 # Observe the actual managed front listener; do not change an existing port.
 conf=pathlib.Path('/etc/panel/sites-enabled')/(own_site+'.conf');text=conf.read_text()
 assert re.search(r'^\s*listen 127\.0\.0\.1:19101;',text,re.M);front_port=19101
 save('actual-managed-front-listener.json',{'path':str(conf),'sha256':sha(conf),'port':front_port})
 assert not os.path.lexists('/etc/panel/security-apps/modules/apache-waf/installed.json')
 proof['legacy_WAF_install_POSTs']+=1;reply=api('one-original-legacy-default-WAF-install','/software/apache-waf/install',{},202,secrets.token_hex(16));legacyjob=wait_job('legacy-WAF-install',reply['job_id'],'runtime_jobs')
 cfg=api('legacy-metadata-installed-config','/software/apache-waf/config');assert cfg['status']['healthy']and cfg['status']['version']=='2.3.0'and cfg['settings'].get('body')is None
 module=pathlib.Path('/etc/panel/security-apps/modules/apache-waf')
 original_installed=(module/'installed.json').read_bytes();history_before={n:(module/n).read_bytes()for n in('history.json','last-report.json','history.sqlite')if(module/n).exists()}
 save('legacy-WAF-baseline-original.json',{'job':legacyjob,'installed_hex':original_installed.hex(),'history_originals':{k:v.hex()for k,v in history_before.items()},'normal_legacy_install_not_signed_catalogue_claim':True})
 v=catalogue('original-signed-WAF-update-offered');item,status=pair(v,'apache-waf');assert item['version']=='2.4.0'and status['installed_version']=='2.3.0'and status['update_available']
 proof['signed_WAF_update_POSTs']+=1;reply=api('one-original-signed-WAF24-update','/app-registry/apache-waf/update',{'expected_version':item['version'],'expected_sha256':item['sha256']},202,secrets.token_hex(16));wait_job('signed-WAF-update',reply['job_id'],'runtime_jobs')
 current=api('native-WAF24-actual-config','/software/apache-waf/config');assert current['status']['healthy']and current['status']['version']=='2.4.0'and current['settings'].get('body')is None
 original=json.loads(original_installed);installed=json.loads((module/'installed.json').read_bytes());assert original['installed_at']==installed['installed_at']and all((module/k).read_bytes()==v for k,v in history_before.items())
 v=catalogue('signed-update-completed-no-repeat');_,status=pair(v,'apache-waf');assert status['installed_version']=='2.4.0'and not status['update_available']
 engines=api('original-empty-engine-inventory','/software/apache-waf/body-engines');assert engines['entries']==[]
 proof['body_engine_build_POSTs']+=1;reply=api('one-original-engine-build','/software/apache-waf/body-engine/build',{},202,secrets.token_hex(16));engine_id=reply['job_id'];wait_job('original-engine-build',engine_id,'runtime_jobs')
 eng=api('actual-ready-engine','/software/apache-waf/body-engine/jobs/'+engine_id);assert eng['state']=='ready'and eng['engine_version']=='2.9.15-yz5'and eng['integrity_verified']and eng['module_abi_validated']and eng['elf_hardening_validated']and eng['compiler_groups_collected']
 book=runpy.run_path(str(payload/'casebook.py'));cases=book['request_cases'](body_marker);assert len(cases)==28
 counter=root/'private'/('qa-apache24-counter-'+nonce);assert not os.path.lexists(counter)
 with os.fdopen(os.open(counter,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600),'wb')as f:os.fchown(f.fileno(),account.pw_uid,account.pw_gid);f.flush();os.fsync(f.fileno())
 code=book['php_fixture'](php_marker,str(counter));created=api('one-owned-PHP-file-create','/sites/'+own_site+'/files/action',{'action':'create','path':probe_name,'content':code});assert created['sha256']==hashlib.sha256(code.encode()).hexdigest()
 original=api('original-before-body-modes','/software/apache-waf/config');save('before-real-body-requests.json',snapshot())
 for mode in('observe','block','off'):
  cfg=api('mode-'+mode+'-current-config','/software/apache-waf/config');settings=copy.deepcopy(cfg['settings'])
  settings['body']={'engine_job_id':engine_id,'sites':[{'site_id':own_site,'policy':{'mode':mode,'paranoia_level':1,'inbound_threshold':5,'body_limit_kib':128,'non_file_limit_kib':64,'json_depth':64,'argument_limit':256}}]}
  pv=api('mode-'+mode+'-readonly-preview','/software/apache-waf/preview',{'settings':settings});assert pv['read_only']and pv['implementation_version']=='2.4.0'
  proof['body_configure_POSTs']+=1;reply=api('mode-'+mode+'-one-original-configure','/software/apache-waf/configure',{'settings':settings},202,secrets.token_hex(16));wait_job('mode-'+mode+'-configure',reply['job_id'],'runtime_jobs')
  actual=api('mode-'+mode+'-actual-config','/software/apache-waf/config');expected=copy.deepcopy(settings);expected['policy']['revision']+=1;assert actual['settings']==expected and actual['status']['healthy']
  for port in(19080,front_port):
   for c in cases:request_once(mode,port,c)
  save('mode-'+mode+'-actual-PHP-counter.json',{'rows':counter_rows(),'expected':len(reached)})
 assert proof['synthetic_HTTP_requests']==168 and len(reached)==136
 cfg=api('before-explicit-body-removal','/software/apache-waf/config');restore=copy.deepcopy(original['settings']);restore['policy']['revision']=cfg['settings']['policy']['revision'];restore['body']={'engine_job_id':engine_id,'sites':[]}
 proof['body_configure_POSTs']+=1;reply=api('one-explicit-empty-body-sites-restoration','/software/apache-waf/configure',{'settings':restore},202,secrets.token_hex(16));wait_job('explicit-body-sites-restoration',reply['job_id'],'runtime_jobs')
 final=api('actual-restored-metadata-config','/software/apache-waf/config');expected=copy.deepcopy(restore);expected['policy']['revision']+=1;assert final['settings']==expected and final['status']['healthy']
 log=pathlib.Path('/var/lib/panel-apache-body/events.log');raw=log.read_bytes();s=log.lstat();www=pwd.getpwnam('www-data');assert stat.S_ISREG(s.st_mode)and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600 and s.st_uid==www.pw_uid and s.st_gid==www.pw_gid and 0<len(raw)<=32<<20
 assert body_marker.encode()not in raw and php_marker.encode()not in raw and domain.encode()not in raw
 numeric=[]
 for line in raw.splitlines():
  e=json.loads(line);assert set(e)=={'time_us','engine','site_id','rule_id','phase','severity','mode','blocked'}and e['engine']=='2.9.15-yz5'and e['site_id']==own_site;numeric.append(e)
 assert {'observe','block'}<={v['mode']for v in numeric}
 save('original-numeric-events.json',{'original_hex':raw.hex(),'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw),'events':numeric})
 report=api('actual-numeric-body-report','/software/apache-waf/body-report?site_id='+own_site+'&limit=1000')
 assert report['available']and not report['partial']and report['counting_contract']=='rule_matches_not_unique_requests_or_confirmed_http_blocks'and report['rule_matches']==len(numeric)and report['rejected_lines']==0
 save('actual-nonroot-FPM-processes.json',native_processes)
 fixed={}
 for directory in(module/'config-transactions',module/'config-transaction-archive'):
  if not directory.exists():continue
  st=directory.lstat();assert stat.S_ISDIR(st.st_mode)and st.st_uid==0 and not st.st_mode&0o022
  entries=list(directory.iterdir());assert len(entries)<=64
  for f in entries:
   st=f.lstat();assert re.fullmatch('[a-f0-9]{32}\\.json',f.name)and stat.S_ISREG(st.st_mode)and st.st_uid==0 and st.st_nlink==1 and stat.S_IMODE(st.st_mode)==0o600 and st.st_size<=8<<20
   raw=f.read_bytes();assert len(raw)==st.st_size;fixed[str(f)]={'original_hex':raw.hex(),'sha256':sha(f),'uid':st.st_uid,'gid':st.st_gid,'mode':stat.S_IMODE(st.st_mode)}
 save('original-native-transaction-files.json',fixed)
 save('original-engine-build-unit-resource-status.json',{'raw':command(['systemctl','show','panel-apache-body-build@'+engine_id+'.service','--property=LoadState,ActiveState,Result,ExecMainStatus,MemoryPeak,MemoryMax,MemorySwapMax,CPUUsageNSec,TasksMax,NoNewPrivileges,ProtectSystem,CapabilityBoundingSet'])})
 save('actual-cache-mount.json',{'raw':command(['findmnt','--json','--target','/var/cache/panel-apache-body'])})
 guard('all-operations-completed');save('after-real-body-requests.json',snapshot())

 save('before-numeric-maintenance.json',snapshot())
 before_lifetimes={name:unit(name)for name in('panel.service','panel-executor.service','nginx.service','panel-apache.service','panel-php@'+own_site+'-php-8.2.35.service')}
 save('before-numeric-maintenance-lifetimes.json',before_lifetimes)
 numeric_log=pathlib.Path('/var/lib/panel-apache-body/events.log');original_log=numeric_log.read_bytes();log_before=numeric_log.lstat();original_digest=hashlib.sha256(original_log).hexdigest()
 inventory=api('numeric-original-empty-inventory','/software/apache-waf/body-log/archives');assert inventory['archives']==inventory['recovery']==inventory['index_stages']==[]and inventory['inventory_complete']and inventory['maintenance_healthy']
 rotated=api('numeric-one-original-rotate','/software/apache-waf/body-log/rotate',{});row=rotated['archive'];assert rotated['same_inode_rotation']and rotated['no_apache_reload']and row['state']=='completed'and row['bytes']==len(original_log)and row['sha256']==original_digest and re.fullmatch('[a-f0-9]{32}',row['id'])
 log_after=numeric_log.lstat();assert log_before.st_ino==log_after.st_ino and log_before.st_dev==log_after.st_dev and log_before.st_mode==log_after.st_mode and log_before.st_uid==log_after.st_uid and log_before.st_gid==log_after.st_gid and log_after.st_size==0
 original_snapshot=pathlib.Path('/var/lib/panel-apache-body/archives')/(row['id']+'.log');original_index=original_snapshot.with_suffix('.json')
 copied=original_snapshot.read_bytes();copy_stat=original_snapshot.lstat();assert copied==original_log and copy_stat.st_uid==0 and stat.S_IMODE(copy_stat.st_mode)==0o600 and copy_stat.st_nlink==1
 save('actual-numeric-original-live-and-copy.json',{'archive':row,'live_before':{'ino':log_before.st_ino,'dev':log_before.st_dev,'uid':log_before.st_uid,'gid':log_before.st_gid,'mode':log_before.st_mode,'bytes':log_before.st_size},'live_after':{'ino':log_after.st_ino,'dev':log_after.st_dev,'uid':log_after.st_uid,'gid':log_after.st_gid,'mode':log_after.st_mode,'bytes':log_after.st_size},'original_hex':copied.hex(),'sha256':original_digest})
 inventory=api('numeric-actual-post-rotate-inventory','/software/apache-waf/body-log/archives');assert inventory['archives']==[row]and inventory['maintenance_healthy']and inventory['inventory_complete']
 exported=api('numeric-one-original-selected-export','/software/apache-waf/body-log/archives/'+row['id']);assert exported['archive']==row and exported['selected_snapshot_digest_verified']and exported['inventory_not_claimed_complete']and exported['metadata']['log_bytes']==len(original_log)and len(exported['metadata']['events'])==len(numeric)and exported['metadata']['rejected_lines']==0 and not exported['metadata']['partial']
 import datetime
 expected_events=[]
 for event in reversed(numeric):
  seconds,micro=divmod(event['time_us'],1000000);stamp=datetime.datetime.fromtimestamp(seconds,datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%S')+('.'+str(micro).zfill(6).rstrip('0')if micro else'')+'Z'
  expected_events.append({'time':stamp,'engine_version':event['engine'],'site_id':event['site_id'],'rule_id':event['rule_id'],'phase':event['phase'],'severity':event['severity'],'mode':event['mode'],'intercepted_mark':event['blocked']})
 assert exported['metadata']['events']==expected_events
 index_before=original_index.read_bytes()
 api('numeric-one-wrong-digest-remove','/software/apache-waf/body-log/archives/'+row['id']+'/remove',{'sha256':'0'*64,'confirm_delete':True},409)
 assert original_snapshot.read_bytes()==original_log and original_snapshot.lstat().st_ino==copy_stat.st_ino and original_index.read_bytes()==index_before
 removed=api('numeric-one-original-digest-remove','/software/apache-waf/body-log/archives/'+row['id']+'/remove',{'sha256':original_digest,'confirm_delete':True});assert removed=={'removed':True,'archive_id':row['id'],'sha256':original_digest,'current_log_untouched':True}
 assert not os.path.lexists(original_snapshot)and not os.path.lexists(original_index)
 inventory=api('numeric-actual-final-inventory','/software/apache-waf/body-log/archives');assert inventory['archives']==inventory['recovery']==inventory['index_stages']==[]and inventory['maintenance_healthy']and inventory['inventory_complete']
 final_log=numeric_log.lstat();assert final_log.st_ino==log_before.st_ino and final_log.st_mode==log_before.st_mode and final_log.st_uid==log_before.st_uid and final_log.st_gid==log_before.st_gid and final_log.st_size==0
 after_lifetimes={name:unit(name)for name in before_lifetimes};save('after-numeric-maintenance-lifetimes.json',after_lifetimes);assert before_lifetimes==after_lifetimes
 guard('numeric-maintenance-completed');save('after-numeric-maintenance.json',snapshot())
 proof.update(actual_numeric_rotation_original_digest_export_and_removal=True,numeric_rotation_POSTs=1,numeric_wrong_digest_remove_POSTs=1,numeric_confirmed_remove_POSTs=1,numeric_original_snapshots_retained_in_encrypted_evidence=True,numeric_services_original_lifetimes_unchanged=True,numeric_cold_powerloss_pending=True)
 verify_actual_automatic_rotation()
 proof.update(ok=True,normal_original_signed_programme_installed=True,all203_installed_entries_verified=True,legacy_metadata_WAF_version='2.3.0',legacy_install_not_signed_catalogue_claim=True,normal_signed_WAF_update_version='2.4.0',legacy_history_and_installed_at_preserved=True,actual_UID=account.pw_uid,actual_primary_GID=account.pw_gid,PHP_requests_168=True,PHP_reached_136=True,blocked_32_never_reached_PHP=True,explicit_empty_sites_restoration=True,body_engine_job_id=engine_id,numeric_rule_matches=len(numeric),actual_cold_boot_pending=True,full_SQL_row_independent_reconciliation_pending=True)
except BaseException:save('original-failure.json',{'traceback':traceback.format_exc()})
finally:
 if csrf:
  try:api('logout','/logout',{});csrf=''
  except BaseException:proof['logout_unknown_observe_only']=True;proof['ok']=False
 save('automatic-read-only-contentions.json',{'observations':automatic_read_contentions,'only_fixed_GET_conflicts_observed':True,'application_mutating_request_replays':0})
 save('HTTP-events.json',events);save('request-summary.json',requests);save('proof.json',proof)
 print(json.dumps({'ok':proof['ok'],'base':str(base),'proof_sha256':sha(evidence/'proof.json'),'source_inputs_sha256':SOURCE,'architecture':'amd64','Main_changed':False,'all50_commercial':False}),flush=True)
sys.exit(0 if proof['ok']else 1)
