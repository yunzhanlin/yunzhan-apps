"""Current signed integrity apps: actual owned full native guest and hard cold."""
from pathlib import Path
import base64,contextlib,hashlib,http.cookiejar,json,os,platform,re,secrets,stat,subprocess,sys,time,traceback,urllib.request,urllib.error
os.umask(0o077);assert os.geteuid()==0 and len(sys.argv)in(2,3,4)
payload=Path(sys.argv[1]).resolve(strict=True);pins=json.loads((payload/'assets.json').read_bytes());arch={'aarch64':'arm64','x86_64':'amd64'}[platform.machine()];case=pins['OS_case']
assert pins['architecture']==arch and Path('/etc/hostname').read_text().strip()==case['hostname']and case['hostname'].startswith('c303-files-sync-')
source='af14b76961beba70011ec424ab4cd5b58f4d61afc2322604d7cc248ad3d40639';assert pins['source_inputs_sha256']==source
base=Path(sys.argv[2]).resolve(strict=True)if len(sys.argv)>2 else Path('/opt/panel-files-sync-c303-qa-'+secrets.token_hex(16));assert base.parent==Path('/opt')and re.fullmatch('panel-files-sync-c303-qa-[a-f0-9]{32}',base.name)
evidence=base/'evidence'
if len(sys.argv)==2:evidence.mkdir(mode=0o700,parents=True)
phase='prepare'if len(sys.argv)==2 else sys.argv[3]if len(sys.argv)==4 else'cold';assert phase in('prepare','cold')
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
 for _ in range(360):
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

proof={'ok':False,'phase':phase,'architecture':arch,'base':str(base),'source_inputs_sha256':source,'boot':boot,'Main_changed':False,'all40_commercial':False};writer=None
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
  app=cohort['items']['files-sync'];assert next(x for x in catalogue['catalog']['apps']if x['id']=='files-sync')==app
  installed=job('signed-install','/app-registry/files-sync/install',{'expected_version':app['version'],'expected_sha256':app['sha256']});assert json.loads(Path('/etc/panel/security-apps/modules/files-sync/installed.json').read_bytes())['version']=='2.0.1'
  slug='c303-'+secrets.token_hex(6);site=job('owned-site','/sites',{'name':'C303 actual SFTP QA','slug':slug,'domain':slug+'.localhost'})['site_id'];public=Path('/srv/panel/sites')/site/'public';assert public.is_dir()
  api('new-local-file','/sites/'+site+'/files/action',{'action':'create','path':'copy.txt','content':'old'})
  api('conflict-local-file','/sites/'+site+'/files/action',{'action':'create','path':'conflict.txt','content':'local'})
  user='panelc303sftp';assert user not in {x.pw_name for x in pwd.getpwall()};remote=Path('/srv/panel-c303-sftp');remote.mkdir(mode=0o755);remote.chmod(0o755)
  command('owned-account',['/usr/sbin/useradd','--no-create-home','--system','--shell','/usr/sbin/nologin','--user-group','--home-dir',str(remote),user]);u=pwd.getpwnam(user);password=secrets.token_hex(30);hashed=subprocess.check_output(['/usr/bin/openssl','passwd','-6','-stdin'],input=(password+'\n').encode()).strip();command('owned-password',['/usr/sbin/chpasswd','-e'],user.encode()+b':'+hashed+b'\n')
  target=remote/'public';backup=remote/'private'
  for d in(target,backup):d.mkdir(mode=0o700);os.chown(d,u.pw_uid,u.pw_gid)
  for name,data in [('conflict.txt',b'external'),('target-only.txt',b'preserve')]:
   p=target/name;p.write_bytes(data);p.chmod(0o644);os.chown(p,u.pw_uid,u.pw_gid)
  key=base/'owned_host_ed25519';command('owned-hostkey',['/usr/bin/ssh-keygen','-q','-t','ed25519','-N','','-f',str(key)]);config=base/'owned_sshd.conf';config.write_text('\n'.join(['AddressFamily inet','ListenAddress 127.0.0.1','Port 39303','HostKey '+str(key),'UsePAM no','PermitRootLogin no','AllowUsers '+user,'PasswordAuthentication yes','KbdInteractiveAuthentication no','PubkeyAuthentication no','ForceCommand internal-sftp','Subsystem sftp internal-sftp','DisableForwarding yes','PermitTTY no','LogLevel ERROR'])+'\n');command('sshd-config-check',['/usr/sbin/sshd','-t','-f',str(config)])
  unit='panel-qa-c303-owned-sftp.service';unitpath=Path('/etc/systemd/system')/unit;assert not unitpath.exists();unitpath.write_text('[Unit]\nAfter=network.target\n[Service]\nType=exec\nExecStart=/usr/sbin/sshd -D -e -f '+str(config)+'\nRestart=no\n[Install]\nWantedBy=multi-user.target\n');command('owned-sftp-daemon-reload',['/usr/bin/systemctl','daemon-reload']);command('owned-sftp-enable',['/usr/bin/systemctl','enable','--now',unit])
  tid='qa-c303';conn={'remote_target_id':tid,'remote_target':{'address':'127.0.0.1','port':39303,'username':user,'root':str(target),'backup_root':str(backup),'host_key':key.with_suffix('.pub').read_text().strip()},'expected_revision':0,'enabled':True,'password':password};module('saved-connection','save-remote',conn);password='';conn.clear();probe=module('pinned-native-probe','probe-remote',{'remote_target_id':tid,'expected_revision':1});assert probe['ssh_host_key_verified']and probe['sftp_subsystem']
  preview=module('before-first-preview','remote-preview',{'site_id':site,'remote_target_id':tid,'expected_revision':1})['remote_sync_preview'];assert preview['counts']=={'create':2,'update':0,'unchanged':0,'conflict':1}
  first=remotequeue('first-actual-transfer',site,tid);assert first['state']=='conflicts'and first['copied_count']==2 and first['conflicts']==['conflict.txt'];assert(target/'copy.txt').read_bytes()==b'old'and(target/'conflict.txt').read_bytes()==b'external'and(target/'target-only.txt').read_bytes()==b'preserve'
  write_nonroot('local-incremental-edit',public/'copy.txt','new-content','www-data');second=remotequeue('second-incremental-transfer',site,tid);assert second['state']=='conflicts'and second['copied_count']==1;assert(target/'copy.txt').read_bytes()==b'new-content'
  write_nonroot('external-remote-edit',target/'copy.txt','third-party',user);write_nonroot('local-concurrent-edit',public/'copy.txt','local-third','www-data');third=remotequeue('conflict-preservation',site,tid);assert third['state']=='conflicts'and sorted(third['conflicts'])==['conflict.txt','copy.txt']and third['copied_count']==0;assert(target/'copy.txt').read_bytes()==b'third-party'
  active=backup/('yunzhan-sync-'+tid);candidates=[p for p in active.iterdir()if p.is_dir()and(p/'staged').exists()and(p/'staged').read_bytes()==b'old'];assert len(candidates)==1;transaction=candidates[0].name;select={'remote_target_id':tid,'expected_revision':1,'resource_id':transaction};row=module('archive-source-review','remote-backup-preview',select)['backup_maintenance'];assert row['content_verified']and row['backup_archive_state']=='reviewed';rsha=row['backup_snapshot_sha256'];module('archive-original-backup','archive-remote-backup',{**select,'expected_sha':rsha,'confirm':'ARCHIVE BACKUP '+transaction});archived=backup/('yunzhan-backup-archive-'+tid)/transaction/'files'/'staged';assert archived.read_bytes()==b'old'
  # Hold an actual unprivileged writer open before the independent copy.
  writer=subprocess.Popen(['/usr/sbin/runuser','-u',user,'--','/usr/bin/python3','-I','-B','-u','-c','import os,sys; f=os.open(sys.argv[1],os.O_RDWR|os.O_NOFOLLOW); print("READY",flush=True); assert sys.stdin.readline().strip()=="WRITE"; os.pwrite(f,b"BAD",0); os.fsync(f); os.close(f); print("WROTE",flush=True)',str(archived)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True);assert writer.stdout.readline().strip()=='READY'
  copied=module('Root-independent-copy','copy-remote-backup',{**select,'expected_sha':rsha,'confirm':'COPY BACKUP '+transaction})['independent_backup'];assert copied['content_verified']and copied['independent_copy_state']=='committed';localbase=Path('/etc/panel/security-apps/modules/files-sync/remote/independent-backups')/tid/transaction;localfiles=[p for p in localbase.rglob('staged')if p.is_file()];assert len(localfiles)==1;local=localfiles[0];s=local.lstat();assert s.st_uid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600 and local.read_bytes()==b'old'
  writer.stdin.write('WRITE\n');writer.stdin.flush();assert writer.stdout.readline().strip()=='WROTE';assert writer.wait(timeout=15)==0;writer=None;assert archived.read_bytes()==b'BAD'and local.read_bytes()==b'old';verify=module('independent-copy-after-old-writer','verify-remote-copy',select);assert verify['independent_backup']['content_verified']
  checkpoint=Path('/etc/panel/security-apps/modules/files-sync/remote/checkpoints')/(tid+'.json');assert json.loads(checkpoint.read_bytes())['pending'] is None
  roots=[str(public),str(remote),'/etc/panel/security-apps/modules/files-sync/remote'];stable=snapshot(roots);save('business-before-service-restart.json',{'roots':roots,'records':stable});command('owned-executor-core-restart',['/usr/bin/systemctl','restart','panel-executor.service','panel.service']);ready();login();assert snapshot(roots)==stable;assert module('postrestart-independent-copy','verify-remote-copy',select)['independent_backup']['content_verified']
  save('prepared.json',{'ok':True,'boot':boot,'site':site,'target':tid,'transaction':transaction,'roots':roots,'records':stable,'jobs':[first,second,third],'select':select,'local_copy':str(local),'held_nonroot_remote_writer_cannot_change_Root_independent_copy':True,'original_signed_install':installed,'real_SFTP_conflict_and_incremental_transfer':True,'signed_app':'2.0.1'});proof.update(files_sync_prepared=True,normal_signed_programmes=1,immediate_power_loss_ready=True,separate_site_and_journal_filesystems=False,site=site,target=tid,transaction=transaction)
 else:
  original=json.loads((evidence/'prepared.json').read_bytes());assert original['boot']!=boot;ready();login();assert snapshot(original['roots'])==original['records'];assert Path(original['local_copy']).read_bytes()==b'old';assert module('cold-independent-copy','verify-remote-copy',original['select'])['independent_backup']['content_verified'];probe=module('cold-real-SFTP-probe','probe-remote',{'remote_target_id':original['target'],'expected_revision':1});assert probe['ssh_host_key_verified']and probe['sftp_subsystem'];current=api('cold-signed-store','/app-registry?refresh=1');status=next(x for x in current['status']if x['id']=='files-sync');assert status['state_known']and status['installed']and status['installed_version']=='2.0.1'and not status['update_available'];proof.update(prior_boot=original['boot'],actual_real_kernel_reboot=True,original_operations_and_Root_bytes_owners_inodes_preserved=True,actual_original_protection_after_cold=True,site=original['site'],target=original['target'],transaction=original['transaction'],files_sync_cold_passed=True)
 proof['ok']=True
except BaseException as e:
 proof['failure']=str(e)[:1600];save(phase+'-failure.json',{'type':type(e).__name__,'traceback':traceback.format_exc()[-7000:]})
finally:
 if writer is not None:
  writer.terminate()
  try:writer.wait(timeout=10)
  except subprocess.TimeoutExpired:writer.kill();writer.wait(timeout=10)
 save(phase+'-result.json',proof);print(json.dumps(proof),flush=True)
sys.exit(0 if proof['ok']else 1)
