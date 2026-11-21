"""Current signed integrity apps: actual owned full native guest and hard cold."""
from pathlib import Path
import socket,base64,contextlib,hashlib,http.cookiejar,json,os,platform,re,secrets,stat,subprocess,sys,time,traceback,urllib.request,urllib.error
os.umask(0o077);assert os.geteuid()==0 and len(sys.argv)in(2,3,4)
payload=Path(sys.argv[1]).resolve(strict=True);pins=json.loads((payload/'assets.json').read_bytes());arch={'aarch64':'arm64','x86_64':'amd64'}[platform.machine()];case=pins['OS_case']
assert pins['architecture']==arch and Path('/etc/hostname').read_text().strip()==case['hostname']and case['hostname'].startswith('c326-load-balance-')
source='b592e7dbf00bd59908a500292e76587abeba5f4c0a7f574924b0763c657bba50';assert pins['source_inputs_sha256']==source
base=Path(sys.argv[2]).resolve(strict=True)if len(sys.argv)>2 else Path('/opt/panel-load-balance-c326-qa-'+secrets.token_hex(16));assert base.parent==Path('/opt')and re.fullmatch('panel-load-balance-c326-qa-[a-f0-9]{32}',base.name)
evidence=base/'evidence'
if len(sys.argv)==2:evidence.mkdir(mode=0o700,parents=True)
phase='prepare'if len(sys.argv)==2 else sys.argv[3]if len(sys.argv)==4 else'cold';assert phase in('prepare','pre-powerloss','cold','post-cold-browser')
boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip();counter=0;csrf='';origin='http://127.0.0.1:19100'
def sha(p):
 h=hashlib.sha256()
 with Path(p).open('rb')as f:
  for b in iter(lambda:f.read(1<<20),b''):h.update(b)
 return h.hexdigest()
def save(n,v):
 with(evidence/n).open('x')as f:json.dump(v,f,indent=2,sort_keys=True);f.write('\n');f.flush();os.fsync(f.fileno())
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*a,**kw):raise AssertionError('Unexpected redirect')
client=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect(),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
def api(label,path,body=None,expected=200,key=None):
 global counter
 n=phase+'-%04d-'%counter+label;counter+=1
 raw=None if body is None else json.dumps(body,separators=(',',':')).encode()
 if raw is not None:save(n+'-intent.json',{'path':path,'body_sha256':hashlib.sha256(raw).hexdigest(),'body':{'private':True}if path in('/login','/app-modules/files-sync/save-remote')else body,'key':key,'maximum_submissions':1})
 headers={'Origin':origin,'Content-Type':'application/json','X-CSRF-Token':csrf}
 if key:headers['Idempotency-Key']=key
 try:
  with client.open(urllib.request.Request(origin+'/api'+path,raw,headers),timeout=80)as r:status=r.status;data=r.read((8<<20)+1)
 except urllib.error.HTTPError as r:status=r.code;data=r.read((8<<20)+1)
 assert len(data)<=8<<20;value=json.loads(data);save(n+'-response.json',{'status':status,'value':{'private_login_redacted':True}if path=='/login'else value});assert status==expected,(path,status,value.get('error'));return value
def ready():
 for _ in range(100):
  try:
   with urllib.request.urlopen(origin+'/api/ready',timeout=2)as r:
    if r.status==200:return
  except Exception:pass
  time.sleep(1)
 raise TimeoutError('Normal installed panel not ready')
def login():
 global csrf
 access=json.loads(Path('/etc/panel/first-login.json').read_bytes())
 try:csrf=api('login','/login',{k:access[k]for k in('username','password')})['csrf']
 finally:access.clear()
import pwd

def command(label,args,input=None,timeout=60):
 save(label+'-command-intent.json',{'args':args,'maximum_submissions':1})
 r=subprocess.run(args,input=input,capture_output=True,timeout=timeout);save(label+'-command-outcome.json',{'exit':r.returncode,'stdout_sha256':hashlib.sha256(r.stdout).hexdigest(),'stderr_sha256':hashlib.sha256(r.stderr).hexdigest()});assert r.returncode==0,(label,r.stderr[-500:]);return r.stdout

def job(label,path,body):
 accepted=api(label,path,body,202,secrets.token_hex(16));identity=accepted['job_id'];assert re.fullmatch('[a-f0-9]{32}',identity)
 for _ in range(1800):
  v=api(label+'-poll','/jobs/'+identity)
  if v['state']not in('queued','running'):
   assert v['state']=='succeeded',(label,v.get('error'));return v
  time.sleep(1)
 raise TimeoutError('Original job unresolved; no replay')

def module(label,action,body):return api(label,'/app-modules/files-sync/'+action,body)
def remotequeue(label,site,tid):
 rid=secrets.token_hex(16);body={'site_id':site,'remote_target_id':tid,'expected_revision':1,'remote_request_id':rid,'excludes':[]};v=module(label,'queue-remote',body);assert v['queued']and v['job']['remote_request_id']==rid
 for _ in range(180):
  v=module(label+'-poll','remote-job',{'remote_request_id':rid})['job']
  if v['state']not in('queued','running'):return v
  time.sleep(1)
 raise TimeoutError('Original SFTP task unresolved; no replay')
def snapshot(roots):
 rows={}
 for root in roots:
  root=Path(root);assert root.is_dir()and not root.is_symlink()
  for p in sorted(root.rglob('*')):
   s=p.lstat();assert not stat.S_ISLNK(s.st_mode)
   if not stat.S_ISREG(s.st_mode):continue
   assert s.st_nlink==1 or '/srv/panel-c303-sftp/' in str(p)
   rows[str(p)]={'sha256':sha(p),'bytes':s.st_size,'uid':s.st_uid,'gid':s.st_gid,'mode':stat.S_IMODE(s.st_mode),'inode':s.st_ino,'nlink':s.st_nlink}
 return rows

def write_nonroot(label,path,data,user):
 return command(label,['/usr/sbin/runuser','-u',user,'--','/usr/bin/python3','-I','-B','-c','import os,sys; f=os.open(sys.argv[1],os.O_WRONLY|os.O_NOFOLLOW); os.ftruncate(f,0); os.write(f,sys.argv[2].encode()); os.fsync(f); os.close(f)',str(path),data])

import sqlite3

def stable_files():
 roots=[Path('/etc/panel/load-balance-stream'),Path('/etc/panel/security-apps/modules/load-balance')]+[p for p in Path('/var/lib/panel-executor').glob('load-balance-stream-*')if p.is_dir()]
 files={}
 for root in roots:
  assert root.is_dir()and not root.is_symlink()
  for p in root.rglob('*'):
   if 'http-health'in p.parts or (root==Path('/etc/panel/security-apps/modules/load-balance')and p.name in('last-report.json','history.json','history.sqlite')):continue
   st=p.lstat();assert not stat.S_ISLNK(st.st_mode)
   if not stat.S_ISREG(st.st_mode):continue
   assert st.st_nlink==1;files[str(p)]={'sha256':sha(p),'bytes':st.st_size,'uid':st.st_uid,'gid':st.st_gid,'mode':stat.S_IMODE(st.st_mode),'inode':st.st_ino,'nlink':st.st_nlink}
 for p in Path('/etc/panel/sites-enabled').glob('load-balance-*.conf'):
  st=p.lstat();assert stat.S_ISREG(st.st_mode)and st.st_nlink==1;files[str(p)]={'sha256':sha(p),'bytes':st.st_size,'uid':st.st_uid,'gid':st.st_gid,'mode':stat.S_IMODE(st.st_mode),'inode':st.st_ino,'nlink':st.st_nlink}
 assert files;return files

def sql_originals():
 with sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True)as db:
  db.execute('PRAGMA query_only=ON');return json.loads(json.dumps({t:db.execute('SELECT *FROM '+t+' ORDER BY 1').fetchall()for t in('runtime_jobs','app_registry_receipts','app_registry_install_requests','load_balance_stream_install_requests','load_balance_stream_controls','sites')}))

def module_ledger():
 root=Path('/etc/panel/security-apps/modules/load-balance');metadata={}
 for name in('history.sqlite','history.json','last-report.json'):
  p=root/name;st=p.lstat();assert stat.S_ISREG(st.st_mode)and st.st_uid==0 and st.st_nlink==1 and stat.S_IMODE(st.st_mode)==0o600;metadata[name]={'uid':st.st_uid,'gid':st.st_gid,'mode':stat.S_IMODE(st.st_mode),'inode':st.st_ino,'nlink':st.st_nlink}
 with sqlite3.connect('file:'+str(root/'history.sqlite')+'?mode=ro',uri=True)as db:
  db.execute('PRAGMA query_only=ON');assert db.execute('PRAGMA quick_check').fetchone()==('ok',);events=db.execute('SELECT *FROM module_events ORDER BY seq').fetchall();meta=db.execute('SELECT *FROM metadata ORDER BY key').fetchall()
 return json.loads(json.dumps({'events':events,'metadata':meta,'legacy_summaries':json.loads((root/'history.json').read_bytes()),'private_file_identities':metadata,'last_report_sha256':sha(root/'last-report.json')}))

def original_HTTP_traffic():
 observations=[];direct=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
 for i in range(12):
  path='/after-real-power-loss?sample='+str(i)
  with direct.open(urllib.request.Request('http://127.0.0.1:41090'+path,headers={'Host':'http-c317.example.test'}),timeout=10)as r:assert r.status==200;v=json.load(r)
  assert v['path']==path;observations.append(v)
 assert {x['backend']for x in observations}=={31091,31092};save(phase+'-actual-HTTP-traffic.json',observations)

controls=[]
def traffic(proto,port,expected):
 tags=[]
 for i in range(64 if proto=='udp'else 8):
  data=(bytes(range(256))*513)[:131076]if proto=='tcp'else(bytes(range(256))*193)[:49152 if i%2 else 16]
  with socket.socket(socket.AF_INET,socket.SOCK_STREAM if proto=='tcp'else socket.SOCK_DGRAM)as s:
   s.settimeout(10);s.connect(('127.0.0.1',port));tag=b''
   if proto=='tcp':
    while len(tag)<6:
     part=s.recv(6-len(tag));assert part,'Backend closed tag';tag+=part
    s.sendall(data);s.shutdown(socket.SHUT_WR);raw=b''
    while True:
     b=s.recv(65536)
     if not b:break
     raw+=b;assert len(raw)<=len(data)
   else:s.sendall(data);reply=s.recv(65536);tag,raw=reply[:6],reply[6:]
  save('actual-'+proto+'-'+str(len(controls))+'-sample-'+str(i)+'.json',{'sent_bytes':len(data),'received_bytes':len(raw),'sent_sha256':hashlib.sha256(data).hexdigest(),'received_sha256':hashlib.sha256(raw).hexdigest(),'tag':tag.decode()});assert raw==data and tag.decode()in expected;tags.append(tag.decode())
 save('real-'+proto+'-traffic-'+str(len(controls))+'.json',{'tags':tags,'payload_exact':True,'TCP_half_close':proto=='tcp'});assert set(tags)==set(expected),(proto,tags)

def readonly_native_failure_snapshot():
 import pwd,grp
 target=evidence/(phase+'-readonly-original-failure');target.mkdir(mode=0o700)
 records=[];total=0;directories=[p for p in Path('/var/lib/panel-executor').glob('load-balance-stream-*')if p.is_dir()and not p.is_symlink()]+[Path('/etc/panel/load-balance-stream')]
 for directory in directories:
  if not directory.exists():continue
  for p in directory.rglob('*'):
   st=p.lstat();row={'path':str(p),'uid':st.st_uid,'gid':st.st_gid,'mode':st.st_mode,'inode':st.st_ino,'device':st.st_dev,'nlink':st.st_nlink,'bytes':st.st_size};records.append(row);assert len(records)<2048
   if not stat.S_ISREG(st.st_mode)or st.st_nlink!=1 or st.st_size>1<<20:continue
   fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
   try:
    before=os.fstat(fd);data=b''
    while True:
     chunk=os.read(fd,65536)
     if not chunk:break
     data+=chunk;assert len(data)<=1<<20
    after=os.fstat(fd)
   finally:os.close(fd)
   row['read_identity_unchanged']=(before.st_dev,before.st_ino,before.st_mode,before.st_size,before.st_mtime_ns)==(after.st_dev,after.st_ino,after.st_mode,after.st_size,after.st_mtime_ns);row['sha256']=hashlib.sha256(data).hexdigest();total+=len(data);assert total<32<<20;dest=target/'original-private-records'/str(p).lstrip('/');dest.parent.mkdir(parents=True,exist_ok=True,mode=0o700);dest.open('xb').write(data)
 (target/'original-native-files-metadata.json').open('x').write(json.dumps(records,indent=2)+'\n');db=sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True);db.execute('PRAGMA query_only=ON');tables={r[0]for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")};rows={t:db.execute('SELECT *FROM '+t+' ORDER BY 1').fetchall()for t in('runtime_jobs','app_registry_receipts','app_registry_pending','app_registry_install_requests','load_balance_stream_install_requests','load_balance_stream_controls')if t in tables};(target/'original-selected-Core-SQL.json').open('x').write(json.dumps(rows,indent=2)+'\n');ids=[r[0]for r in rows['runtime_jobs']if re.fullmatch('[a-f0-9]{32}',r[0])and r[1]=='load-balance'];db.close();units=['panel.service','panel-executor.service','panel-load-balance-stream.service']
 for jobid in ids:units.extend(['panel-lbstream-install@'+jobid+'.service','panel-lbstream-account-create@'+jobid+'.service'])
 def observe(label,cmd):
  r=subprocess.run(cmd,capture_output=True,timeout=20);assert len(r.stdout)+len(r.stderr)<8<<20;(target/(label+'.stdout')).open('xb').write(r.stdout);(target/(label+'.stderr')).open('xb').write(r.stderr);(target/(label+'.json')).open('x').write(json.dumps({'args':cmd,'exit':r.returncode})+'\n');return r.stdout
 for unit in units:
  raw=observe(unit+'-manager',['systemctl','show','--all',unit]);observe(unit+'-journal',['journalctl','-b','--no-pager','-n','180','-u',unit]);props=dict(line.split('=',1)for line in raw.decode(errors='replace').splitlines()if'='in line);pid=props.get('MainPID','0')
  if pid.isdigit()and int(pid)>1:
   for name in('status','cgroup','limits','mountinfo'):
    path=Path('/proc')/pid/name
    try:(target/(unit+'-proc-'+name)).open('xb').write(path.read_bytes())
    except FileNotFoundError:pass
 observe('nft-original-owned-table-text',['nft','-s','-a','list','table','inet','panel_lbstream']);observe('actual-initgroups',['/usr/bin/getent','initgroups','panel-lbstream']);observe('nft-original-owned-table',['nft','-s','-a','-j','list','table','inet','panel_lbstream']);observe('systemd-version',['systemctl','--version']);observe('kernel',['uname','-a']);accounts={}
 for name in('root','panel','panel-lbstream'):
  try:u=pwd.getpwnam(name);accounts[name]={'uid':u.pw_uid,'gid':u.pw_gid,'home':u.pw_dir,'shell':u.pw_shell,'group':grp.getgrgid(u.pw_gid).gr_name}
  except KeyError:accounts[name]={'absent':True}
 (target/'original-account-identities-no-password-material.json').open('x').write(json.dumps(accounts,indent=2)+'\n');save(phase+'-readonly-diagnostics-collected.json',{'ok':True,'records':len(records),'bytes':total,'commands_read_only':True,'no_old_operation_replay':True})

proof={'ok':False,'phase':phase,'architecture':arch,'base':str(base),'source_inputs_sha256':source,'boot':boot,'Main_changed':False,'all40_commercial':False}
try:
 if phase=='prepare':
  for n,h in pins['files'].items():assert sha(payload/n)==h,n
  assert not any(os.path.lexists(p)for p in('/opt/panel','/etc/panel','/var/lib/panel'))
  verified=base/'verified-input';verified.mkdir(mode=0o700)
  for n,h in pins['files'].items():
   p=payload/n;s=p.lstat();assert stat.S_ISREG(s.st_mode)and not p.is_symlink()
   with(verified/n).open('xb')as f:f.write(p.read_bytes());f.flush();os.fsync(f.fileno())
   s=(verified/n).lstat();assert s.st_uid==s.st_gid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600 and sha(verified/n)==h
  archive=verified/('panel-'+pins['version']+'-linux-'+arch+'.tar.gz');save('normal-signed-install-intent.json',{'archive_sha256':sha(archive),'maximum_submissions':1})
  with(evidence/'normal-signed-install.stdout').open('xb')as o,(evidence/'normal-signed-install.stderr').open('xb')as e:r=subprocess.run([sys.executable,'-I','-B',str(verified/'signed-release.py'),'install',str(archive),'--public-key',str(verified/'release-signing-dev.pub')],stdout=o,stderr=e,timeout=1800)
  save('normal-signed-install-outcome.json',{'exit':r.returncode});assert r.returncode==0
  assert json.loads(Path('/opt/panel/current/SOURCE_INPUTS.json').read_bytes())['inputs_sha256']==source
  ready();login();cohort=json.loads((verified/'cohort.json').read_bytes());catalogue=api('ordinary-signed-source-refresh','/app-registry?refresh=1');assert catalogue['source']['resolved_commit']==cohort['served_head']and not catalogue['source']['stale']and len(catalogue['catalog']['apps'])==40
  app=cohort['items']['load-balance'];assert next(x for x in catalogue['catalog']['apps']if x['id']=='load-balance')==app and app['version']=='1.9.0'
  before=api('before-original-install-workspace','/app-registry/load-balance/stream/workspace');save('original-preinstall-native-workspace.json',before)
  nginx=cohort['items']['nginx'];native=job('normal-managed-nginx1306-install','/app-registry/nginx/install',{'expected_version':nginx['version'],'expected_sha256':nginx['sha256']});api('normal-nginx-installed-discovery','/app-registry?refresh=1')
  installed=job('original-signed-LB190-install','/app-registry/load-balance/install',{'expected_version':app['version'],'expected_sha256':app['sha256']})
  state=api('ordinary-installed-discovery','/app-registry?refresh=1');current=next(x for x in state['status']if x['id']=='load-balance');assert current['state_known']and current['installed']and current['installed_version']=='1.9.0'and not current['update_available']
  workspace=api('actual-original-installed-stream-workspace','/app-registry/load-balance/stream/workspace');save('actual-native-install-workspace.json',workspace);assert workspace['available']and workspace['state']=='empty'
  business_evidence=base/'evidence'/'business-evidence'
  with(evidence/'actual-business.stdout').open('xb')as o,(evidence/'actual-business.stderr').open('xb')as e:actual=subprocess.run([sys.executable,'-I','-B',str(verified/'load-balance-business.py'),str(base)],stdout=o,stderr=e,timeout=3600)
  assert actual.returncode==0,'Actual original business failed; no mutation replay';business_proof=json.loads((business_evidence/'actual-original-business-proof.json').read_bytes());assert business_proof['ok']
  import pwd
  native_identity=pwd.getpwnam('panel-lbstream');native_groups=subprocess.run(['/usr/bin/getent','initgroups','panel-lbstream'],capture_output=True,timeout=10);save('actual-native-initgroups.json',{'exit':native_groups.returncode,'stdout':native_groups.stdout.decode(),'stderr':native_groups.stderr.decode(),'uid':native_identity.pw_uid,'gid':native_identity.pw_gid,'primary_identity_is_verified_separately':True});assert native_groups.returncode==0 and native_groups.stderr==b''and native_groups.stdout.decode().split()==['panel-lbstream']
  for label,args in [('actual-native-nft-JSON',['nft','-s','-a','-j','list','table','inet','panel_lbstream']),('actual-native-nft-text',['nft','-s','-a','list','table','inet','panel_lbstream'])]:
   observed=subprocess.run(args,capture_output=True,timeout=10);assert len(observed.stdout)+len(observed.stderr)<1<<20;save(label+'.json',{'exit':observed.returncode,'stdout':observed.stdout.decode(),'stderr':observed.stderr.decode()});assert observed.returncode==0
  save('prepared.json',{'ok':True,'boot':boot,'source_inputs_sha256':source,'normal_signed_programme_installs':1,'normal_managed_Nginx1306_install_job':native,'normal_signed_original_LB190_install':installed,'installed_status':current,'business':business_proof});proof.update(ok=True,load_balance_prepared=True,immediate_power_loss_ready=True,normal_signed_programmes=1,installed_version='1.9.0',actual_stream_workspace=business_proof['workspace'])
  save('original-stable-files-before-powerloss.json',stable_files());save('original-SQL-before-powerloss.json',sql_originals());save('original-module-ledger-before-browser.json',module_ledger())
 elif phase=='pre-powerloss':
  prepared=json.loads((evidence/'prepared.json').read_bytes());assert prepared['boot']==boot;actual=stable_files();sql=sql_originals();ledger=module_ledger();assert actual==json.loads((evidence/'original-stable-files-before-powerloss.json').read_bytes());assert sql==json.loads((evidence/'original-SQL-before-powerloss.json').read_bytes());old=json.loads((evidence/'original-module-ledger-before-browser.json').read_bytes());assert all(x in ledger['events']for x in old['events']);assert all(x in ledger['legacy_summaries']for x in old['legacy_summaries']);save('powerloss-sealed-original-stable-files.json',actual);save('powerloss-sealed-original-SQL.json',sql);save('powerloss-sealed-original-module-ledger.json',ledger);proof.update(ok=True,original_report_ledger_rows_preserved_after_browser=True,application_outputs_globally_flushed=False,only_readonly_original_census_after_browser=True)
 else:
  ready();login();prepared=json.loads((evidence/'prepared.json').read_bytes());assert prepared['boot']!=boot
  original=json.loads((evidence/'powerloss-sealed-original-stable-files.json').read_bytes());before_sql=json.loads((evidence/'powerloss-sealed-original-SQL.json').read_bytes());original_ledger=json.loads((evidence/'powerloss-sealed-original-module-ledger.json').read_bytes());actual_ledger=module_ledger();save(phase+'-actual-module-ledger.json',actual_ledger);actual=stable_files();sql=sql_originals();save(phase+'-actual-stable-files.json',actual);save(phase+'-actual-original-SQL.json',sql)
  if phase=='cold':
   assert actual==original,'Original stable file bytes/ownership/inodes changed across actual power loss';assert sql==before_sql,'Original SQL history changed across actual power loss';assert actual_ledger==original_ledger,'Original complete logical report ledger or private identity changed across actual power loss';workspace=api('actual-cold-workspace','/app-registry/load-balance/stream/workspace');assert workspace['available']and workspace['state']=='cold-boot-ready'and workspace['generation']==3 and workspace['entries']==prepared['business']['workspace']['entries'];original_HTTP_traffic();save('cold-original-workspace.json',workspace);proof.update(ok=True,prior_boot=prepared['boot'],actual_real_kernel_reboot=True,actual_original_LB_records_after_cold=True,original_operations_and_Root_bytes_owners_inodes_preserved=True,cold_originals_readonly_no_replay=True,stable_original_file_count=len(original),cold_state='cold-boot-ready')
  else:
   assert all(x in actual_ledger['events']for x in original_ledger['events']);assert all(x in actual_ledger['legacy_summaries']for x in original_ledger['legacy_summaries'])
   for table,rows in before_sql.items():
    if table=='load_balance_stream_controls':assert len(sql[table])==len(rows)+1 and all(x in sql[table]for x in rows)
    else:assert sql[table]==rows
   workspace=api('actual-browser-resumed-workspace','/app-registry/load-balance/stream/workspace');assert workspace['state']=='running'and workspace['configuration_verified']and workspace['generation']==4;traffic('tcp',41080,('31082|','31083|'));traffic('udp',41081,('31084|','31085|'));original_HTTP_traffic();proof.update(ok=True,prior_boot=prepared['boot'],actual_browser_original_policy_restore_real_traffic=True,original_prior_SQL_rows_preserved=True,actual_TCP_half_close_sessions=8,actual_UDP_datagrams=64,current_workspace=workspace)
  api('logout','/logout',{})
except BaseException as e:
 proof['failure']=str(e)[:1600];save(phase+'-failure.json',{'type':type(e).__name__,'traceback':traceback.format_exc()[-7000:]})
 try:readonly_native_failure_snapshot()
 except BaseException as diagnostic:save(phase+'-readonly-diagnostic-failure.json',{'type':type(diagnostic).__name__,'traceback':traceback.format_exc()[-5000:]})
finally:save(phase+'-result.json',proof);print(json.dumps(proof),flush=True)
sys.exit(0 if proof['ok']else 1)
