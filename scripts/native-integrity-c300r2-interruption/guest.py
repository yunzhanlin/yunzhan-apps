"""Current signed integrity apps: actual owned full native guest and hard cold."""
from pathlib import Path
import base64,contextlib,hashlib,http.cookiejar,json,os,platform,re,secrets,stat,subprocess,sys,time,traceback,urllib.request,urllib.error
os.umask(0o077);assert os.geteuid()==0 and len(sys.argv)in(2,3,4)
payload=Path(sys.argv[1]).resolve(strict=True);pins=json.loads((payload/'assets.json').read_bytes());arch={'aarch64':'arm64','x86_64':'amd64'}[platform.machine()];case=pins['OS_case']
assert pins['architecture']==arch and Path('/etc/hostname').read_text().strip()==case['hostname']and case['hostname'].startswith('c300-crossfs-')
source='af14b76961beba70011ec424ab4cd5b58f4d61afc2322604d7cc248ad3d40639';assert pins['source_inputs_sha256']==source
base=Path(sys.argv[2]).resolve(strict=True)if len(sys.argv)>2 else Path('/opt/panel-crossfs-c300-qa-'+secrets.token_hex(16));assert base.parent==Path('/opt')and re.fullmatch('panel-crossfs-c300-qa-[a-f0-9]{32}',base.name)
evidence=base/'evidence'
if len(sys.argv)==2:evidence.mkdir(mode=0o700,parents=True)
phase='prepare'if len(sys.argv)==2 else sys.argv[3]if len(sys.argv)==4 else'cold';assert phase in('prepare','cold','release','released-cold')
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
 if raw is not None:save(n+'-intent.json',{'path':path,'body_sha256':hashlib.sha256(raw).hexdigest(),'body':{'private':True}if path=='/login'else body,'key':key,'maximum_submissions':1})
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
def state(app,site):
 v=api('status-'+app,'/app-modules/'+app+'/kernel?site_id='+site);assert v['app_version']=='1.5.0'and v['cap_linux_immutable']and v['site_id']==site;return v
def mutate(app,action,v):
 site=v['site_id'];body={'site_id':site,'expected_revision':v['revision'],'expected_app_version':'1.5.0','baseline_sha':'','source_operation':'','source_sha':'','confirm':''}
 if action=='enable':body.update(baseline_sha=v['baseline_sha'],confirm='PROTECT SITE '+site)
 else:body.update(source_operation=v['latest']['request']['id'],source_sha=v['latest']['request_sha256'],confirm='RELEASE SITE '+site)
 answer=api(app+'-'+action,'/app-modules/'+app+'/kernel/'+action,body,202,secrets.token_hex(16));identity=answer['request']['id'];assert re.fullmatch('[a-f0-9]{32}',identity)
 for _ in range(180):
  v=state(app,site)
  if v.get('latest')and v['latest']['request']['id']==identity and v['latest']['state']not in('queued','running'):
   assert v['latest']['state']=='succeeded'and v['state']==('enabled'if action=='enable'else'released');return v
  time.sleep(1)
 raise TimeoutError('Original kernel operation unresolved; no replay')
def records():
 root=Path('/etc/panel/security-apps/modules/website-tamper-proof/kernel-protection');rows={};assert root.is_dir()and not root.is_symlink()
 for p in sorted(root.rglob('*')):
  s=p.lstat();assert not stat.S_ISLNK(s.st_mode)
  if stat.S_ISDIR(s.st_mode):continue
  assert stat.S_ISREG(s.st_mode)and s.st_uid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600 and s.st_size<16<<20 and len(rows)<1000
  raw=p.read_bytes();rows[str(p)]={'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw),'uid':s.st_uid,'gid':s.st_gid,'mode':stat.S_IMODE(s.st_mode),'inode':s.st_ino,'content_base64':base64.b64encode(raw).decode()}
 assert rows;return rows
def site_files(site):
 root=Path('/srv/panel/sites')/site/'public';result={}
 for p in sorted(root.rglob('*')):
  s=p.lstat();assert stat.S_ISDIR(s.st_mode)or stat.S_ISREG(s.st_mode)
  result[str(p)]={'uid':s.st_uid,'gid':s.st_gid,'mode':stat.S_IMODE(s.st_mode),'inode':s.st_ino,'bytes':s.st_size,'sha256':sha(p)if p.is_file()else''}
 return result
def writer(site,blocked):
 root=Path('/srv/panel/sites')/site/'public';code=r'''import errno,json,os,pwd,sys
u=pwd.getpwnam('www-data');os.setgroups([]);os.setgid(u.pw_gid);os.setuid(u.pw_uid);assert os.geteuid()!=0
out={}
for label,path,value in [('static',sys.argv[1],b'A'),('excluded',sys.argv[2],b'B')]:
 try:
  f=os.open(path,os.O_WRONLY|os.O_NOFOLLOW)
  try:os.pwrite(f,value,0);os.fsync(f)
  finally:os.close(f)
  out[label]=0
 except OSError as e:out[label]=e.errno
print(json.dumps(out))
'''
 r=subprocess.run(['/usr/bin/python3','-I','-B','-c',code,str(root/'static-qa.txt'),str(root/'uploads-qa/dynamic-qa.txt')],capture_output=True,timeout=20)
 assert r.returncode==0;actual=json.loads(r.stdout);assert actual=={'static':1 if blocked else 0,'excluded':0};save(phase+'-actual-nonroot-writer.json',actual)

def read_command(args):
 r=subprocess.run(args,stdin=subprocess.DEVNULL,capture_output=True,text=True,timeout=30);assert r.returncode==0,(args[0],r.returncode,r.stderr[-500:]);assert len(r.stdout)<4<<20;return r.stdout
def native_mutation(label,args):
 save(label+'-intent.json',{'args':args,'maximum_submissions':1})
 r=subprocess.run(args,stdin=subprocess.DEVNULL,capture_output=True,timeout=60);save(label+'-outcome.json',{'exit':r.returncode,'stdout_sha256':hashlib.sha256(r.stdout).hexdigest(),'stderr_sha256':hashlib.sha256(r.stderr).hexdigest()});assert r.returncode==0
def job(label,path,body):
 accepted=api(label,path,body,202,secrets.token_hex(16));identity=accepted['job_id'];assert re.fullmatch('[a-f0-9]{32}',identity)
 for _ in range(360):
  v=api(label+'-poll','/jobs/'+identity)
  if v['state']not in('queued','running'):
   assert v['state']=='succeeded',(label,v.get('error'));return v
  time.sleep(1)
 raise TimeoutError('Original job unresolved; no replay')
def mount_state(public):
 value=json.loads(read_command(['/usr/bin/findmnt','--json','--target',str(public),'--output','SOURCE,FSTYPE,OPTIONS,UUID,TARGET']))['filesystems'];assert len(value)==1
 v=value[0];assert v['target']==str(public)and v['fstype']=='ext4'and 'commit=60'in v['options'].split(',');return v
def flags(public):
 return {n:'i'in read_command(['/usr/bin/lsattr','-d',str(public/n)]).split()[0]for n in('.', 'index.html','static-qa.txt')}

application=case['kernel_app'];assert application in('website-tamper-proof','enterprise-tamper-proof')
other_application=next(a for a in('website-tamper-proof','enterprise-tamper-proof')if a!=application)
def all_target_flags(public,plan):
 import array,fcntl
 result={}
 for target in plan['targets']:
  n=target['path'];p=public/n
  fd=os.open(p,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW|os.O_CLOEXEC|(os.O_DIRECTORY if target['directory']else 0))
  try:
   value=array.array('i',[0]);fcntl.ioctl(fd,0x80086601,value,True);result[n]=bool(value[0]&16)
  finally:os.close(fd)
 return result
def partial_enable(site):
 import signal
 before=state(application,site);body={'site_id':site,'expected_revision':before['revision'],'expected_app_version':'1.5.0','baseline_sha':before['baseline_sha'],'source_operation':'','source_sha':'','confirm':'PROTECT SITE '+site}
 answer=api('one-original-partial-enable','/app-modules/'+application+'/kernel/enable',body,202,secrets.token_hex(16));identity=answer['request']['id'];assert re.fullmatch('[a-f0-9]{32}',identity)
 directory=Path('/etc/panel/security-apps/modules/website-tamper-proof/kernel-protection')/identity
 pid=int(read_command(['/usr/bin/systemctl','show','panel-executor.service','--property=MainPID','--value']).strip());assert pid>1 and Path('/proc/'+str(pid)+'/comm').read_text().strip()=='panel-executor'
 deadline=time.monotonic()+60
 while time.monotonic()<deadline:
  try:
   raw=(directory/'progress.jsonl').read_bytes();lines=[line for line in raw.splitlines(keepends=True)if line.endswith(b'\n')];rows=[json.loads(line)for line in lines]
   count=sum(r['stage']=='verified'for r in rows)
   if count>=8:
    save('stop-only-owned-guest-executor-intent.json',{'pid':pid,'operation':identity,'signal':'SIGSTOP','maximum_submissions':1})
    os.kill(pid,signal.SIGSTOP);break
  except FileNotFoundError:pass
  time.sleep(.001)
 else:raise TimeoutError('Original operation never reached actual partial progress; no replay')
 for _ in range(100):
  status=Path('/proc/'+str(pid)+'/status').read_text()
  if re.search(r'^State:\s+T ',status,re.M):break
  time.sleep(.001)
 else:raise AssertionError('Owned Root worker did not stop')
 assert not(directory/'result.json').exists()
 plan=json.loads((directory/'plan.json').read_bytes());raw=(directory/'progress.jsonl').read_bytes();lines=raw.splitlines(keepends=True)
 if lines and not lines[-1].endswith(b'\n'):lines.pop()
 # Every complete row before the final complete row preceded a subsequent
 # append, so its fsync returned successfully in the unchanged journal code.
 durable=b''.join(lines[:-1]);rows=[json.loads(line)for line in durable.splitlines()];verified=[r['index']for r in rows if r['stage']=='verified']
 assert len(verified)>=5 and len(verified)<len(plan['targets'])//2 and len(plan['targets'])>1000
 save('actual-partial-operation-stop.json',{'pid':pid,'state':'T','operation':identity,'plan_targets':len(plan['targets']),'durable_prefix_base64':base64.b64encode(durable).decode(),'durable_prefix_sha256':hashlib.sha256(durable).hexdigest(),'durable_verified_indexes':verified,'original_result_absent':True,'final_row_not_claimed_durable':True})
 return answer,plan

def verify_no_replay(site,original):
 before=records();a=state(application,site);assert a['state']=='needs-attention'and a['latest']['request']['id']==original['operation']and a['latest']['state']=='needs-attention'
 assert state(other_application,site)['state']=='other-application';time.sleep(1);b=state(application,site);after=records();assert a['latest']==b['latest']and before==after
 assert all(not n.endswith('/result.json')for n in after)
 return b,after

proof={'ok':False,'phase':phase,'architecture':arch,'base':str(base),'source_inputs_sha256':source,'boot':boot,'Main_changed':False,'all40_commercial':False}
try:
 for n,h in pins['files'].items():assert sha(payload/n)==h,n
 if phase=='prepare':
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
  ready();login();cohort=json.loads((verified/'cohort.json').read_bytes());catalogue=api('normal-source-refresh','/app-registry?refresh=1');assert catalogue['source']['resolved_commit']==cohort['served_head']and not catalogue['source']['stale']and len(catalogue['catalog']['apps'])==40
  for app in cohort['items'].values():
   assert next(x for x in catalogue['catalog']['apps']if x['id']==app['id'])==app and app['version']=='1.5.0'
   job('signed-install-'+app['id'],'/app-registry/'+app['id']+'/install',{'expected_version':app['version'],'expected_sha256':app['sha256']})
  observed=api('ordinary-signed-receipt-discovery','/app-registry?refresh=1');assert observed['source']['resolved_commit']==cohort['served_head']and not observed['source']['stale']
  for app in cohort['items'].values():
   installed=next(x for x in observed['status']if x['id']==app['id']);assert installed['state_known']and installed['installed']and installed['installed_version']==app['version']
  slug='c300-'+secrets.token_hex(6);made=job('owned-site','/sites',{'name':'C300 separate filesystem QA','slug':slug,'domain':slug+'.localhost'});site=made['site_id'];assert re.fullmatch('[a-f0-9]{32}',site)
  public=Path('/srv/panel/sites')/site/'public';assert json.loads((public.parent/'.panel-site.json').read_bytes())['id']==site
  original_index=(public/'index.html').read_bytes();assert 0<len(original_index)<1<<20
  device=Path('/dev/disk/by-id/virtio-c300-owned-data');assert device.is_symlink()and device.resolve(strict=True).is_block_device()
  actual=device.resolve(strict=True);block=json.loads(read_command(['/usr/bin/lsblk','--bytes','--json','--nodeps','--output','NAME,TYPE,SIZE,SERIAL,FSTYPE',str(actual)]))['blockdevices'];assert len(block)==1
  b=block[0];assert b['serial']=='c300-owned-data'and b['type']=='disk'and b['size']==256<<20 and not b.get('fstype')and not b.get('children')
  save('owned-original-empty-data-device.json',{'resolved_device':str(actual),'block':b,'only_new_synthetic_256MiB_disk':True})
  native_mutation('format-only-owned-empty-secondary-disk',['/usr/sbin/mkfs.ext4','-q','-F','-L','c300-data',str(actual)])
  uuid=read_command(['/usr/sbin/blkid','-s','UUID','-o','value',str(actual)]).strip();assert re.fullmatch('[a-f0-9-]{36}',uuid)
  fstab=Path('/etc/fstab');before=fstab.lstat();assert stat.S_ISREG(before.st_mode)and before.st_uid==0 and before.st_nlink==1 and not before.st_mode&0o022
  old_fstab=fstab.read_bytes();line='UUID='+uuid+' '+str(public)+' ext4 noatime,nodev,nosuid,commit=60 0 2\n';assert uuid.encode()not in old_fstab and str(public).encode()not in old_fstab
  save('owned-guest-data-mount-fstab-intent.json',{'original_sha256':hashlib.sha256(old_fstab).hexdigest(),'new_line':line,'maximum_submissions':1,'Main_changed':False})
  with os.fdopen(os.open(fstab,os.O_WRONLY|os.O_APPEND|os.O_NOFOLLOW|os.O_CLOEXEC),'wb')as f:f.write(line.encode());f.flush();os.fsync(f.fileno())
  assert fstab.read_bytes()==old_fstab+line.encode()and fstab.stat().st_ino==before.st_ino
  native_mutation('mount-only-owned-secondary-site-data',['/usr/bin/mount','-t','ext4','-o','noatime,nodev,nosuid,commit=60',str(device),str(public)])
  mount=mount_state(public);assert mount['uuid']==uuid
  assert public.stat().st_dev!=Path('/etc/panel/security-apps').stat().st_dev
  for name,content,uid in(('index.html',original_index,0),('static-qa.txt',b'A'*4096,33)):
   target=public/name
   with target.open('xb')as f:f.write(content);f.flush();os.fsync(f.fileno())
   os.chown(target,uid,uid);os.chmod(target,0o644)
   with target.open('rb')as f:os.fsync(f.fileno())
  uploads=public/'uploads-qa';uploads.mkdir(mode=0o755);os.chown(uploads,33,33);dynamic=uploads/'dynamic-qa.txt'
  with dynamic.open('xb')as f:f.write(b'B'*4096);f.flush();os.fsync(f.fileno())
  os.chown(dynamic,33,33);os.chmod(dynamic,0o644)
  with dynamic.open('rb')as f:os.fsync(f.fileno())
  bulk=public/'bulk-qa';bulk.mkdir(mode=0o755);os.chown(bulk,33,33)
  for i in range(1024):
   p=bulk/('file-%04d.txt'%i)
   with p.open('xb')as f:f.write(b'A'*4096);f.flush();os.fsync(f.fileno())
   os.chown(p,33,33);os.chmod(p,0o644)
   with p.open('rb')as f:os.fsync(f.fileno())
  preexisting=public/'preexisting-qa.txt'
  with preexisting.open('xb')as f:f.write(b'PREEXISTING C300');f.flush();os.fsync(f.fileno())
  native_mutation('set-only-owned-synthetic-preexisting-flag',['/usr/bin/chattr','+i',str(preexisting)])
  with preexisting.open('rb')as f:os.fsync(f.fileno())
  for directory in(bulk,uploads,public):
   fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
   try:os.fsync(fd)
   finally:os.close(fd)
  native_mutation('refresh-only-owned-guest-service-mount-namespaces',['/usr/bin/systemctl','restart','panel-executor.service','panel.service','nginx.service'])
  ready()
  observed=api('ordinary-post-restart-signed-source-discovery','/app-registry?refresh=1');assert observed['source']['resolved_commit']==cohort['served_head']and not observed['source']['stale']
  for app in cohort['items'].values():
   installed=next(x for x in observed['status']if x['id']==app['id']);assert installed['state_known']and installed['installed']and installed['installed_version']==app['version']
  for app in('website-tamper-proof','enterprise-tamper-proof'):
   v=api('baseline-'+app,'/app-modules/'+app+'/baseline',{'site_id':site,'excludes':['uploads-qa','lost+found'],'interval':3600,'realtime':False});assert v['sites'][0]['site_id']==site
  before_files=site_files(site);save('cross-filesystem-original-seeded-data.json',{'files':before_files,'mount':mount,'UUID':uuid,'journal_device':Path('/etc/panel/security-apps').stat().st_dev,'data_device':public.stat().st_dev})
  accepted,plan=partial_enable(site);physical=all_target_flags(public,plan);partial=json.loads((evidence/'actual-partial-operation-stop.json').read_bytes());verified=partial['durable_verified_indexes']
  assert all(physical[plan['targets'][i]['path']]for i in verified)and physical['preexisting-qa.txt']and 5<sum(physical.values())<len(physical)//2
  original_records=records();assert len(original_records)==4
  save('prepared-state.json',{'site':site,'base':str(base),'boot':boot,'records':original_records,'files':before_files,'mount':mount,'UUID':uuid,'protection':accepted,'operation':accepted['request']['id'],'plan':plan,'partial':partial,'physical_flags_before_powerloss':physical,'prepared_time_ns':time.time_ns(),'application':application})
  proof.update(ok=True,normal_signed_programmes=1,integrity_prepared=True,actual_operation_started_and_stopped_in_progress=True,immediate_power_loss_ready=True,separate_site_and_journal_filesystems=True,data_mount_options=mount['options'],site=site,application=application,durable_verified_targets=len(verified),total_targets=len(plan['targets']))
 else:
  ready();login();original=json.loads((evidence/'prepared-state.json').read_bytes());assert boot!=original['boot'];site=original['site'];public=Path('/srv/panel/sites')/site/'public';mount=mount_state(public);assert mount['uuid']==original['UUID']and public.stat().st_dev!=Path('/etc/panel/security-apps').stat().st_dev
  plan=original['plan'];physical=all_target_flags(public,plan);actual_files=site_files(site);assert actual_files==original['files'];actual_records=records()
  if phase=='cold':
   durable=base64.b64decode(original['partial']['durable_prefix_base64'],validate=True);assert hashlib.sha256(durable).hexdigest()==original['partial']['durable_prefix_sha256']
   for name,before in original['records'].items():
    after=actual_records[name]
    assert all(before[k]==after[k]for k in ('uid','gid','mode','inode'))
    if name.endswith('/progress.jsonl'):assert base64.b64decode(after['content_base64'],validate=True).startswith(durable)
    else:assert before==after
   assert set(actual_records)==set(original['records'])
   assert all(physical[plan['targets'][i]['path']]for i in original['partial']['durable_verified_indexes'])and physical['preexisting-qa.txt']and sum(physical.values())<len(physical)//2
   v,unchanged=verify_no_replay(site,original);assert unchanged==actual_records
   save('cold-original-data-and-private-records.json',{'records':actual_records,'files':actual_files,'mount':mount,'physical_flags_after_powerloss':physical,'actual_API_state':v})
   save('interrupted-cold-checkpoint.json',{'boot':boot,'records':actual_records,'physical_flags':physical})
   proof.update(ok=True,prior_boot=original['boot'],actual_real_kernel_reboot=True,actual_original_protection_after_cold=False,original_operations_and_Root_bytes_owners_inodes_preserved=True,original_durable_progress_prefix_preserved=True,actual_unknown_status_not_success=True,actual_no_original_operation_replay=True,source_operation=original['operation'],site=site,application=application,separate_site_and_journal_filesystems=True,actual_API_state_after_cold=v['state'],physical_flags_before=original['physical_flags_before_powerloss'],physical_flags_after=physical)
  elif phase=='release':
   cold=json.loads((evidence/'interrupted-cold-checkpoint.json').read_bytes());assert boot==cold['boot']and actual_records==cold['records']and physical==cold['physical_flags']
   released=mutate(application,'release',state(application,site));after=records();assert all(after[n]==v for n,v in cold['records'].items());physical=all_target_flags(public,plan)
   assert physical['preexisting-qa.txt']and sum(physical.values())==1 and state(other_application,site)['state']=='ready'
   writer(site,False);assert site_files(site)==original['files']
   save('released-state.json',{'boot':boot,'records':after,'files':site_files(site),'UUID':original['UUID'],'protection':released,'physical_flags':physical})
   proof.update(ok=True,immediate_power_loss_ready=True,separate_site_and_journal_filesystems=True,explicit_release_of_original_interrupted_task_once=True,original_partial_records_preserved=True,preexisting_flag_preserved=True,all_owned_flags_released=True,site=site,application=application)
  else:
   released=json.loads((evidence/'released-state.json').read_bytes());assert boot!=released['boot']and actual_records==released['records']and actual_files==released['files']and physical==released['physical_flags']and physical['preexisting-qa.txt']and sum(physical.values())==1
   v=state(application,site);assert v['state']=='released'and state(other_application,site)['state']=='ready';writer(site,False)
   save('released-cold-original-records-and-data.json',{'records':actual_records,'files':actual_files,'mount':mount,'flags':physical,'actual_API_state':v})
   proof.update(ok=True,prior_boot=released['boot'],actual_real_kernel_reboot=True,actual_released_state_durable=True,all_original_records_bytes_owners_modes_and_inodes_preserved=True,preexisting_flag_preserved=True,site=site,application=application,actual_API_state_after_cold=v['state'])
except BaseException:proof['failure']=traceback.format_exc()
finally:
 if csrf:
  with contextlib.suppress(Exception):api('logout','/logout',{})
 save('original-'+phase+'-proof.json',proof);print(json.dumps(proof),flush=True)
sys.exit(0 if proof['ok']else 1)
