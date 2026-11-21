"""Current signed integrity apps: actual owned full native guest and hard cold."""
from pathlib import Path
import base64,contextlib,hashlib,http.cookiejar,json,os,platform,re,secrets,stat,subprocess,sys,time,traceback,urllib.request,urllib.error
os.umask(0o077);assert os.geteuid()==0 and len(sys.argv)in(2,3,4)
payload=Path(sys.argv[1]).resolve(strict=True);pins=json.loads((payload/'assets.json').read_bytes());arch={'aarch64':'arm64','x86_64':'amd64'}[platform.machine()];case=pins['OS_case']
assert pins['architecture']==arch and Path('/etc/hostname').read_text().strip()==case['hostname']and case['hostname'].startswith('c301-legacy-')
source='af14b76961beba70011ec424ab4cd5b58f4d61afc2322604d7cc248ad3d40639';assert pins['source_inputs_sha256']==source
base=Path(sys.argv[2]).resolve(strict=True)if len(sys.argv)>2 else Path('/opt/panel-legacy-integrity-c301-qa-'+secrets.token_hex(16));assert base.parent==Path('/opt')and re.fullmatch('panel-legacy-integrity-c301-qa-[a-f0-9]{32}',base.name)
evidence=base/'evidence'
if len(sys.argv)==2:evidence.mkdir(mode=0o700,parents=True)
phase='prepare'if len(sys.argv)==2 else sys.argv[3]if len(sys.argv)==4 else'cold';assert phase in('prepare','after-app-upgrade','cold')
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

applications=('website-tamper-proof','enterprise-tamper-proof')
legacy_source=pins['legacy_source_inputs_sha256'];assert legacy_source=='8e9a4a7c5b409be22ceb21d28965c3f9e20f49d1a5820bce3ca440f6abd3b4f3'
verified=base/'verified-input'
def installed_versions():
 result={}
 for app in applications:
  p=Path('/etc/panel/security-apps/modules')/app/'installed.json';r=json.loads(p.read_bytes());assert r['id']==app;result[app]=r['version']
 return result

def normal_install(label,version,expected_source):
 archive=verified/('panel-'+version+'-linux-'+arch+'.tar.gz')
 save(label+'-normal-signed-install-intent.json',{'archive_sha256':sha(archive),'maximum_submissions':1,'version':version,'source_inputs_sha256':expected_source})
 with(evidence/(label+'-normal-signed-install.stdout')).open('xb')as o,(evidence/(label+'-normal-signed-install.stderr')).open('xb')as e:r=subprocess.run([sys.executable,'-I','-B',str(verified/'signed-release.py'),'install',str(archive),'--public-key',str(verified/'release-signing-dev.pub')],stdout=o,stderr=e,timeout=1800)
 save(label+'-normal-signed-install-outcome.json',{'exit':r.returncode});assert r.returncode==0
 assert json.loads(Path('/opt/panel/current/SOURCE_INPUTS.json').read_bytes())['inputs_sha256']==expected_source
 ready()

def file_pin(p,raw=False):
 s=p.lstat();assert stat.S_ISREG(s.st_mode)and not p.is_symlink()and s.st_nlink==1
 value={'uid':s.st_uid,'gid':s.st_gid,'mode':stat.S_IMODE(s.st_mode),'inode':s.st_ino,'bytes':s.st_size,'sha256':sha(p)}
 if raw:
  assert s.st_size<8<<20;value['content_base64']=base64.b64encode(p.read_bytes()).decode()
 return value

def baseline_originals(site):
 result={}
 for app in applications:
  root=Path('/etc/panel/security-apps/modules')/app/'baselines'/site;assert root.is_dir()and not root.is_symlink()
  for p in root.rglob('*'):
   st=p.lstat();assert stat.S_ISREG(st.st_mode)or stat.S_ISDIR(st.st_mode)
   if p.is_file()and p.name!='monitoring.json':
    value=file_pin(p,True);assert value['uid']==0 and value['mode']==0o600;result[str(p)]=value
  assert str(root/'baseline.json')in result
 key=Path('/etc/panel/security-apps/modules/integrity-key');result[str(key)]=file_pin(key,False);assert result[str(key)]['uid']==0 and result[str(key)]['mode']==0o600
 return result

def db_originals(before=None):
 import sqlite3
 result={}
 with contextlib.closing(sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True))as db:
  db.execute('PRAGMA query_only=ON');assert db.execute('PRAGMA quick_check').fetchone()==('ok',)
  for table in ('sites','users','runtime_installations','app_registry_receipts'):
   columns=[r[1]for r in db.execute('PRAGMA table_info('+table+')')];assert columns
   if before:assert all(c in columns for c in before[table]['columns']);columns=before[table]['columns']
   quoted=','.join('"'+c.replace('"','""')+'"'for c in columns);rows=[]
   for row in db.execute('SELECT '+quoted+' FROM '+table+' ORDER BY rowid'):
    rows.append([{'bytes_sha256':hashlib.sha256(v).hexdigest()}if isinstance(v,bytes)else v for v in row])
   result[table]={'columns':columns,'rows':len(rows),'sha256':hashlib.sha256(json.dumps(rows,sort_keys=True,separators=(',',':')).encode()).hexdigest()}
 return result

def histories(label):
 result={}
 for app in applications:
  r=api(label+'-'+app,'/app-modules/'+app+'/history',{'limit':100});assert isinstance(r['history'],list);result[app]=r['history']
 return result

def original_history_present(old,new):
 for app,rows in old.items():
  current={r['id']:r for r in new[app]};assert len(current)==len(new[app])
  for r in rows:assert r['id']in current and all(current[r['id']].get(k)==v for k,v in r.items())

def site_ingress(site,domain):
 paths={}
 p=Path('/etc/panel/sites-enabled')/(site+'.conf');assert p.parent.is_dir()and not p.parent.is_symlink()and p.is_file()and not p.is_symlink()and domain.encode()in p.read_bytes();paths[str(p)]=file_pin(p)
 assert len(paths)==1
 unit=read_command(['/usr/bin/systemctl','show','nginx.service','--property=MainPID,InvocationID,ActiveState']).strip();assert 'ActiveState=active'in unit
 req=urllib.request.Request('http://127.0.0.1/',headers={'Host':domain})
 with urllib.request.urlopen(req,timeout=10)as r:raw=r.read(1<<20);assert r.status==200
 return {'configs':paths,'unit':unit,'HTTP_status':200,'HTTP_bytes':len(raw),'HTTP_sha256':hashlib.sha256(raw).hexdigest()}

proof={'ok':False,'phase':phase,'architecture':arch,'base':str(base),'source_inputs_sha256':source,'legacy_source_inputs_sha256':legacy_source,'boot':boot,'Main_changed':False,'all40_commercial':False}
try:
 for n,h in pins['files'].items():assert sha(payload/n)==h,n
 if phase=='prepare':
  assert not any(os.path.lexists(p)for p in('/opt/panel','/etc/panel','/var/lib/panel'));verified.mkdir(mode=0o700)
  for n,h in pins['files'].items():
   p=payload/n;st=p.lstat();assert stat.S_ISREG(st.st_mode)and not p.is_symlink()
   with(verified/n).open('xb')as f:f.write(p.read_bytes());f.flush();os.fsync(f.fileno())
   st=(verified/n).lstat();assert st.st_uid==st.st_gid==0 and st.st_nlink==1 and stat.S_IMODE(st.st_mode)==0o600 and sha(verified/n)==h
  normal_install('legacy',pins['legacy_version'],legacy_source);login()
  for app in applications:job('original-legacy-builtin-install-'+app,'/software/'+app+'/install',{'settings':{}})
  assert installed_versions()==dict.fromkeys(applications,'1.4.1')
  slug='c301-'+secrets.token_hex(6);domain=slug+'.localhost';made=job('owned-legacy-site','/sites',{'name':'C301 original legacy integrity data','slug':slug,'domain':domain});site=made['site_id'];assert re.fullmatch('[a-f0-9]{32}',site)
  public=Path('/srv/panel/sites')/site/'public';assert json.loads((public.parent/'.panel-site.json').read_bytes())['id']==site
  static=public/'static-qa.txt'
  with static.open('xb')as f:f.write(b'A'*4096);f.flush();os.fsync(f.fileno())
  os.chown(static,33,33);os.chmod(static,0o644);uploads=public/'uploads-qa';uploads.mkdir(mode=0o755);os.chown(uploads,33,33);dynamic=uploads/'dynamic-qa.txt'
  with dynamic.open('xb')as f:f.write(b'B'*4096);f.flush();os.fsync(f.fileno())
  os.chown(dynamic,33,33);os.chmod(dynamic,0o644)
  baseline_signatures={}
  for app in applications:
   r=api('original-legacy-baseline-'+app,'/app-modules/'+app+'/baseline',{'site_id':site,'excludes':['uploads-qa'],'interval':3600,'realtime':False});row=r['sites'][0];assert row['site_id']==site and re.fullmatch('[a-f0-9]{64}',row['signature']);baseline_signatures[app]=row['signature']
  with static.open('r+b')as f:f.write(b'C'*4096);f.flush();os.fsync(f.fileno())
  for app in applications:
   changed=api('original-legacy-detect-'+app,'/app-modules/'+app+'/check',{'site_id':site});assert any(c['path']=='static-qa.txt'and c['kind']=='modified'for c in changed['sites'][0]['changes'])
  restored=api('original-legacy-explicit-restore','/app-modules/website-tamper-proof/restore',{'site_id':site,'path':'static-qa.txt'});assert 'static-qa.txt'in restored['sites'][0]['restored']and static.read_bytes()==b'A'*4096
  for app in applications:assert api('original-legacy-clean-'+app,'/app-modules/'+app+'/check',{'site_id':site})['sites'][0]['changes']==[]
  old_history=histories('original-legacy-history');assert all(len(rows)>=3 for rows in old_history.values());baseline_pins=baseline_originals(site);data=site_files(site);database=db_originals();nss={n:hashlib.sha256(read_command(['/usr/bin/getent',n]).encode()).hexdigest()for n in('passwd','group')};ingress=site_ingress(site,domain)
  save('original-legacy-data-before-programme-upgrade.json',{'site':site,'domain':domain,'source_inputs_sha256':legacy_source,'files':data,'baseline_and_backup_originals':baseline_pins,'baseline_signatures':baseline_signatures,'history':old_history,'database':database,'NSS':nss,'ingress':ingress,'versions':installed_versions(),'boot':boot})
  api('logout-before-normal-programme-upgrade','/logout',{});csrf=''
  normal_install('current',pins['version'],source)
  assert site_files(site)==data and baseline_originals(site)==baseline_pins and db_originals(database)==database
  assert {n:hashlib.sha256(read_command(['/usr/bin/getent',n]).encode()).hexdigest()for n in('passwd','group')}==nss and site_ingress(site,domain)==ingress
  login();after_history=histories('current-programme-original-legacy-history');original_history_present(old_history,after_history)
  current=api('ordinary-current-store-old-version-discovery','/app-registry?refresh=1');assert current['source']['resolved_commit']==pins['served_head']and not current['source']['stale']and len(current['catalog']['apps'])==40
  for app in applications:
   status=next(r for r in current['status']if r['id']==app);assert status['state_known']and status['installed']and status['installed_version']=='1.4.1'and status['update_available']and status['update_supported'],status
  save('prepared-state.json',{'site':site,'base':str(base),'domain':domain,'boot':boot,'legacy_versions':installed_versions(),'baseline_signatures':baseline_signatures,'ordinary_current_store_statuses':{a:next(r for r in current['status']if r['id']==a)for a in applications},'legacy_source_inputs_sha256':legacy_source,'source_inputs_sha256':source})
  proof.update(ok=True,normal_signed_programmes=2,integrity_prepared=True,legacy_upgrade_ready=True,legacy_versions=installed_versions(),actual_original_legacy_detection_and_restore_passed=True,old_data_baselines_backups_history_NSS_ingress_and_business_rows_preserved_by_programme_upgrade=True,site=site)
 else:
  ready();login();initial=json.loads((evidence/'prepared-state.json').read_bytes());old=json.loads((evidence/'original-legacy-data-before-programme-upgrade.json').read_bytes());site=old['site'];assert baseline_originals(site)==old['baseline_and_backup_originals']and site_files(site)==old['files'];ingress=site_ingress(site,old['domain']);assert all(ingress[k]==v for k,v in old['ingress'].items()if k!='unit');assert phase=='cold'or ingress['unit']==old['ingress']['unit']
  assert {n:hashlib.sha256(read_command(['/usr/bin/getent',n]).encode()).hexdigest()for n in('passwd','group')}==old['NSS']
  observed=api('ordinary-current-post-app-upgrade-store-discovery','/app-registry?refresh=1');assert observed['source']['resolved_commit']==pins['served_head']and not observed['source']['stale']
  assert installed_versions()==dict.fromkeys(applications,'1.5.0')
  for app in applications:
   status=next(r for r in observed['status']if r['id']==app);assert status['state_known']and status['installed']and status['installed_version']=='1.5.0'and not status['update_available'];item=next(r for r in observed['catalog']['apps']if r['id']==app);assert item['version']=='1.5.0'
  original_history_present(old['history'],histories(phase+'-original-history'))
  if phase=='after-app-upgrade':
   assert boot==initial['boot']
   for app in applications:
    clean=api('current-legacy-baseline-clean-'+app,'/app-modules/'+app+'/check',{'site_id':site});assert clean['sites'][0]['changes']==[]
    before=state(app,site);assert before['baseline_sha']==old['baseline_signatures'][app]
    enabled=mutate(app,'enable',before);released=mutate(app,'release',enabled);assert released['state']=='released'
   assert not any(flags(Path('/srv/panel/sites')/site/'public').values());assert site_files(site)==old['files']and baseline_originals(site)==old['baseline_and_backup_originals'];kernel=records();assert len(kernel)==20
   save('upgraded-state-before-cold.json',{'boot':boot,'site':site,'kernel_records':kernel,'files':site_files(site),'baseline_and_backup_originals':baseline_originals(site),'history':histories('current-final-history'),'versions':installed_versions()})
   proof.update(ok=True,normal_signed_versions=installed_versions(),old_legacy_baselines_used_for_both_signed_150_kernel_enable_release=True,original_legacy_data_and_original_signatures_preserved=True,immediate_power_loss_ready=True,site=site)
  else:
   checkpoint=json.loads((evidence/'upgraded-state-before-cold.json').read_bytes());assert boot!=checkpoint['boot']and records()==checkpoint['kernel_records']and site_files(site)==checkpoint['files']and baseline_originals(site)==checkpoint['baseline_and_backup_originals'];assert len(checkpoint['kernel_records'])==20
   original_history_present(checkpoint['history'],histories('cold-original-current-history'))
   assert state('website-tamper-proof',site)['state']=='ready'and state('enterprise-tamper-proof',site)['state']=='released';assert not any(flags(Path('/srv/panel/sites')/site/'public').values())
   save('cold-original-upgraded-data-and-private-records.json',{'kernel_records':records(),'files':site_files(site),'baseline_and_backup_originals':baseline_originals(site),'versions':installed_versions()})
   proof.update(ok=True,prior_boot=checkpoint['boot'],actual_real_kernel_reboot=True,actual_complete_upgrade_after_cold=True,all_original_legacy_data_baselines_backups_and_twenty_kernel_records_preserved=True,ordinary_store_versions_known_and_no_false_update=True,site=site)
except BaseException:proof['failure']=traceback.format_exc()
finally:
 if csrf:
  with contextlib.suppress(Exception):api('logout','/logout',{})
 save('original-'+phase+'-proof.json',proof);print(json.dumps(proof),flush=True)
sys.exit(0 if proof['ok']else 1)
