"""Only new owned NFS reference, external-mount and directory-identity cases."""
from pathlib import Path
import contextlib,hashlib,http.cookiejar,json,os,platform,re,secrets,sqlite3,stat,subprocess,sys,time,traceback,urllib.error,urllib.request
os.umask(0o077);assert os.geteuid()==0 and len(sys.argv)in(2,3)
arch={'aarch64':'arm64','x86_64':'amd64'}[platform.machine()]
inputs=Path(sys.argv[1]).resolve(strict=True);pins=json.loads((inputs/'assets.json').read_bytes());assert pins['architecture']==arch
assert pins['source_inputs_sha256']=='7de34e3479a9c161e48303178648805bb0e03946e65a76c2445c15a2ccfc04e2'
fresh=len(sys.argv)==2;hostname=Path('/etc/hostname').read_text().strip()
assert hostname.startswith('yunzhan-qa-nfs-c208-')if fresh else hostname=='yunzhan-qa-nfs-c204-ubuntu24-arm64'
base=Path('/opt/panel-nfs-c207-qa-'+secrets.token_hex(16))if fresh else Path(sys.argv[2]).resolve(strict=True)
assert base.parent==Path('/opt') and re.fullmatch('panel-nfs-c20[47]-qa-[a-f0-9]{32}',base.name)
if fresh:base.mkdir(mode=0o700)
assert base.lstat().st_uid==0 and stat.S_IMODE(base.lstat().st_mode)==0o700
out=base/'evidence'/'c207-guards';out.mkdir(mode=0o700,parents=True)
def save(n,v):
 with(out/(n+'.json')).open('x')as f:json.dump(v,f,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
sha=lambda b:hashlib.sha256(b).hexdigest()
def command(label,args,timeout=80):
 with(out/(label+'.stdout')).open('xb')as a,(out/(label+'.stderr')).open('xb')as b:p=subprocess.run(args,stdin=subprocess.DEVNULL,stdout=a,stderr=b,timeout=timeout)
 assert p.returncode==0,(label,p.returncode)
origin='http://127.0.0.1:19100';client=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()));csrf='';events=[]
def api(label,path,body=None,allowed=(200,),key=None,method=None,with_csrf=True):
 headers={'Origin':origin,'Content-Type':'application/json'}
 if csrf and with_csrf:headers['X-CSRF-Token']=csrf
 if key:headers['Idempotency-Key']=key
 if body is not None and path!='/login':save(label+'-intent',{'path':path,'body':body,'key':key,'method':method or 'POST','maximum_submissions':1})
 request=urllib.request.Request(origin+'/api'+path,None if body is None else json.dumps(body).encode(),headers,method=method)
 try:
  with client.open(request,timeout=150)as response:status,value=response.status,json.load(response)
 except urllib.error.HTTPError as error:status,value=error.code,json.loads(error.read(16384))
 events.append({'method':request.get_method(),'path':path,'status':status});assert status in allowed,(label,status,value.get('error'))
 if path!='/login':save(label+'-response',{'status':status,'value':value})
 return value
def action(label,name,body=None,allowed=(200,)):return api(label,'/app-modules/nfs-manager/'+name,{}if body is None else body,allowed)
def report(label):return action(label,'server-report')
def wait_job(label,identity,table):
 assert re.fullmatch('[a-f0-9]{32}',identity) and table in ('jobs','runtime_jobs');states=[];end=time.monotonic()+1000
 while time.monotonic()<end:
  with contextlib.closing(sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True))as db:
   db.execute('PRAGMA query_only=ON');row=db.execute('SELECT state,error FROM '+table+' WHERE id=?',(identity,)).fetchone()
  assert row;states.append(row)
  if row[0]not in('queued','running'):
   save(label+'-original-job',{'id':identity,'table':table,'observed':states});assert row==('succeeded',''),row;return
  time.sleep(1)
 raise TimeoutError('Original job unresolved; not resubmitted')
def files(root):
 result={}
 for p in root.rglob('*'):
  s=p.lstat()
  if stat.S_ISDIR(s.st_mode):continue
  assert stat.S_ISREG(s.st_mode) and s.st_nlink==1
  result[str(p.relative_to(root))]={'sha256':sha(p.read_bytes()),'uid':s.st_uid,'gid':s.st_gid,'mode':stat.S_IMODE(s.st_mode),'device':s.st_dev,'inode':s.st_ino}
 return result
def kernel(target):
 rows=[line for line in Path('/proc/self/mountinfo').read_text().splitlines()if len(line.split())>=6 and line.split()[4]==str(target)];assert len(rows)<=1;return rows
module=Path('/etc/panel/security-apps/modules/nfs-manager');public=None;mounted=None;mount_line=None;backup=None;replacement=None;started=False
proof={'ok':False,'architecture':arch,'source_inputs_sha256':pins['source_inputs_sha256'],'signed_nfs_version':'1.3.2','Main_changed':False,'all50_commercial':False,'original_unknown_requests_replayed':False,'base':str(base)}
try:
 if fresh:assert not any(os.path.lexists(p)for p in('/opt/panel','/etc/panel','/var/lib/panel'))
 else:
  original=json.loads((base/'evidence/owned-website-fixture.json').read_bytes());public=Path(original['public']);before_existing={'website':files(public),'native_sha256':sha((module/'native-runtime.json').read_bytes()),'server':sha((module/'server.json').read_bytes())};save('before-normal-programme-upgrade',before_existing)
 trusted=base/'c207-verified-input';trusted.mkdir(mode=0o700)
 for name,digest in pins['files'].items():
  assert re.fullmatch('[A-Za-z0-9._-]+',name)
  with os.fdopen(os.open(inputs/name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC),'rb')as f:
   st=os.fstat(f.fileno());assert stat.S_ISREG(st.st_mode) and st.st_nlink==1 and st.st_size<=64<<20;raw=f.read((64<<20)+1)
  assert len(raw)==st.st_size and sha(raw)==digest
  with(trusted/name).open('xb')as f:f.write(raw);f.flush();os.fsync(f.fileno())
 assert sha((trusted/'release-signing-dev.pub').read_bytes())=='4ccfcc861d56a41e3ba7f7ace7e2432c815f366c58448d783df92c6632f01339'
 archive=trusted/('panel-'+pins['version']+'-linux-'+arch+'.tar.gz');signer=['python3','-I','-B',str(trusted/'signed-release.py')];trust=['--public-key',str(trusted/'release-signing-dev.pub')]
 command('normal-signed-verification',signer+['verify',str(archive)]+trust)
 command('normal-signed-programme-install-or-upgrade',signer+['install',str(archive)]+trust,1800)
 assert all(sha((Path('/opt/panel/current/bin')/name).read_bytes())==digest for name,digest in pins['programmes'].items())
 if not fresh:
  after_existing={'website':files(public),'native_sha256':sha((module/'native-runtime.json').read_bytes()),'server':sha((module/'server.json').read_bytes())};assert before_existing==after_existing;save('after-normal-programme-upgrade',after_existing)
 creds=json.loads(Path('/etc/panel/first-login.json').read_bytes());csrf=api('login','/login',{k:creds[k]for k in('username','password')})['csrf'];creds.clear()
 if fresh:
  page=api('current-signed-catalogue','/app-registry?refresh=1');item,=[a for a in page['catalog']['apps']if a['id']=='nfs-manager'];assert item==pins['nfs'] and item['version']=='1.3.2' and not page['source']['stale']
  install_key=secrets.token_hex(16);binding={'expected_version':item['version'],'expected_sha256':item['sha256']};accepted=api('normal-NFS-install','/app-registry/nfs-manager/install',binding,(202,),install_key);wait_job('normal-NFS-install',accepted['job_id'],'runtime_jobs')
  ready_until=time.monotonic()+1000
  while time.monotonic()<ready_until:
   ready=report('fresh-runtime-ready-'+str(time.monotonic_ns()))
   if ready.get('runtime_ready') and ready.get('private_client_ready'):break
   time.sleep(2)
  else:raise TimeoutError('Original NFS runtime preparation unresolved; install not replayed')
  with sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True)as db:
   db.execute('PRAGMA query_only=ON');original_job=db.execute('SELECT * FROM runtime_jobs WHERE id=?',(accepted['job_id'],)).fetchone();original_jobs_count=db.execute('SELECT count(*) FROM runtime_jobs').fetchone()[0]
  replay=api('signed-completed-install-replay','/app-registry/nfs-manager/install',binding,(202,),install_key);assert replay['job_id']==accepted['job_id']
  api('signed-replay-current-CSRF-required','/app-registry/nfs-manager/install',binding,(403,),install_key,with_csrf=False)
  api('signed-replay-changed-digest-refused','/app-registry/nfs-manager/install',{**binding,'expected_sha256':'0'*64},(409,),install_key)
  api('signed-replay-changed-version-refused','/app-registry/nfs-manager/install',{**binding,'expected_version':'1.3.1'},(409,),install_key)
  with sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True)as db:
   db.execute('PRAGMA query_only=ON');assert original_job==db.execute('SELECT * FROM runtime_jobs WHERE id=?',(accepted['job_id'],)).fetchone() and original_jobs_count==db.execute('SELECT count(*) FROM runtime_jobs').fetchone()[0]
  save('signed-completed-replay-original-job-preserved',{'job_id':accepted['job_id'],'original_and_final_runtime_job':original_job,'original_and_final_runtime_job_count':original_jobs_count,'ok':True})
  slug='nfsguard-'+secrets.token_hex(4);created=api('owned-website-create','/sites',{'name':'Owned NFS reference guard','slug':slug,'domain':slug+'.localhost','php_version_id':''},(202,),secrets.token_hex(16));wait_job('owned-website-create',created['job_id'],'jobs')
  with sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True)as db:db.execute('PRAGMA query_only=ON');site=db.execute('SELECT site_id FROM jobs WHERE id=?',(created['job_id'],)).fetchone()[0]
  public=Path('/srv/panel/sites')/site/'public';st=public.lstat();assert st.st_uid>0 and st.st_gid>0
  marker=public/'nfs-read-marker.txt'
  with os.fdopen(os.open(marker,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600),'wb')as f:os.fchown(f.fileno(),st.st_uid,st.st_gid);f.write(b'owned C207 NFS read marker\n');f.flush();os.fsync(f.fileno())
  fixture={'site_id':site,'public':str(public)};save('owned-website-fixture',fixture)
 else:fixture=original;site=fixture['site_id']
 assert re.fullmatch('[a-f0-9]{32}',site) and public==Path('/srv/panel/sites')/site/'public'
 protected=files(public);public_identity=public.lstat();native_sha=sha((module/'native-runtime.json').read_bytes());native=json.loads((module/'native-runtime.json').read_bytes());assert native['format']==2 and native['architecture']==arch
 before=report('original-server-state');config=before['config'];assert before['runtime_ready'] and before['private_client_ready'] and not before['service_active'] and not before['boot_enabled'] and config['exports']==[]
 original_config=json.loads(json.dumps(config));share='c207-share-'+secrets.token_hex(4);port=config['port']
 if port==2049:
  configured=action('owned-custom-port','server-config',{'bind_address':'127.0.0.1','port':24270,'expected_revision':config['revision']});config=configured['config'];port=config['port']
 saved=action('owned-RO-export','export-save',{'resource_id':share,'site_id':site,'path':'','client_allow':['127.0.0.1'],'read_only':True,'expected_revision':config['revision']});config=saved['config'];assert len(config['exports'])==1
 sites=api('owned-site-read','/sites');owned,=[row for row in sites if row['id']==site];site_before=json.loads(json.dumps(owned))
 action('owned-server-start','server-start');started=True;time.sleep(32)
 def deny_archive(label):
  with sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True)as db:db.execute('PRAGMA query_only=ON');count=db.execute('SELECT count(*) FROM jobs').fetchone()[0]
  response=api(label,'/sites/'+site,{'confirm_domain':owned['domain']},(409,),secrets.token_hex(16),method='DELETE');assert 'NFS'in response['error']
  with sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True)as db:db.execute('PRAGMA query_only=ON');assert db.execute('SELECT count(*) FROM jobs').fetchone()[0]==count
  again=api(label+'-site-preserved','/sites');assert next(row for row in again if row['id']==site)==site_before and files(public)==protected
 deny_archive('active-export-site-archive-refused')
 resource='c207-outside-'+secrets.token_hex(4);target=Path('/srv/panel/nfs')/resource;assert not os.path.lexists(target);target.mkdir(mode=0o700,parents=True);target_before=target.lstat()
 prefix=native['prefix'];assert re.fullmatch('apt-[a-f0-9]{16}',prefix);helper=Path('/opt/panel/app-modules/nfs-manager')/prefix/'bin/mount.nfs';assert sha(helper.read_bytes())==native['files']['bin/mount.nfs']
 source='127.0.0.1:/'+share;command('owned-outside-mount',[str(helper),source,str(target),'-n','-o','ro,nosuid,nodev,noexec,vers=4.2,proto=tcp,port='+str(port)+',timeo=50,retrans=2,sec=sys'],70)
 mounted=target;mount_line=kernel(target);assert len(mount_line)==1 and ' - nfs4 '+source+' 'in mount_line[0]
 marker_sha=sha((public/'nfs-read-marker.txt').read_bytes());assert sha((target/'nfs-read-marker.txt').read_bytes())==marker_sha
 deny=action('outside-mount-adoption-refused','mount',{'resource_id':resource,'source':source,'port':port,'read_only':True},(409,));assert '不接管' in deny['error']
 deny=action('outside-mount-unmount-refused','unmount',{'resource_id':resource},(409,));assert '挂载不存在' in deny['error']
 assert kernel(target)==mount_line and not (module/'mounts'/(resource+'.json')).exists() and sha((target/'nfs-read-marker.txt').read_bytes())==marker_sha
 save('actual-outside-mount-preserved',{'ok':True,'before_and_after_kernel_mount':mount_line,'marker_sha256':marker_sha,'no_managed_record_created':True})
 command('normal-owned-outside-unmount',['/usr/bin/umount',str(target)]);assert not kernel(target);mounted=None;assert target.lstat().st_ino==target_before.st_ino;target.rmdir()
 action('owned-server-stop','server-stop');started=False;deny_archive('stopped-export-site-archive-refused')
 backup=public.with_name('.c207-preserved-public-'+secrets.token_hex(4));assert not os.path.lexists(backup);public.rename(backup);public.mkdir(mode=stat.S_IMODE(public_identity.st_mode));os.chown(public,public_identity.st_uid,public_identity.st_gid);os.chmod(public,stat.S_IMODE(public_identity.st_mode));replacement=public.lstat()
 assert replacement.st_ino!=public_identity.st_ino
 denied=action('replaced-directory-start-refused','server-start',{},(409,));assert '目录'in denied['error'] or '身份'in denied['error']
 rejected=report('after-directory-refusal');assert not rejected['service_active'] and rejected['config']==config
 assert public.lstat().st_ino==replacement.st_ino and list(public.iterdir())==[];public.rmdir();backup.rename(public);backup=None;replacement=None
 assert public.lstat().st_ino==public_identity.st_ino and public.lstat().st_dev==public_identity.st_dev and files(public)==protected
 removed=action('remove-only-owned-export','export-remove',{'resource_id':share,'expected_revision':config['revision']});config=removed['config'];assert config['exports']==[] and not removed['service_active']
 if config['port']!=original_config['port']:
  config=action('restore-original-listener','server-config',{'bind_address':original_config['bind_address'],'port':original_config['port'],'expected_revision':config['revision']})['config']
 final=report('final-preserved-state');expected={**original_config,'revision':config['revision']};assert final['config']==expected and not final['service_active'] and not final['boot_enabled']
 assert files(public)==protected and sha((module/'native-runtime.json').read_bytes())==native_sha
 save('original-and-final-protected-state',{'website_files':protected,'native_runtime_sha256':native_sha,'original_config':original_config,'final_config':final['config'],'site':site_before,'original_public_identity':[public_identity.st_dev,public_identity.st_ino]})
 proof.update(ok=True,base=str(base),normal_signed_current_programme_verified=True,active_and_stopped_NFS_references_blocked_site_archive_without_job=True,real_external_NFS_kernel_mount_not_adopted_or_unmounted=True,replaced_export_directory_refused_before_start=True,original_website_files_owners_modes_inodes_and_native_preserved=True,owned_mount_and_export_cleaned_normally=True,final_original_listener_exports_and_stopped_state_restored=True)
except BaseException:proof['failure']=traceback.format_exc()
finally:
 if mounted is not None:
  try:
   assert kernel(mounted)==mount_line;command('failure-cleanup-own-mounted-resource',['/usr/bin/umount',str(mounted)])
  except Exception:proof['owned_mount_cleanup_unconfirmed']=True
 if started:
  try:action('failure-cleanup-own-server-stop','server-stop')
  except Exception:proof['owned_server_cleanup_unconfirmed']=True
 if backup is not None:
  try:
   assert public.lstat().st_ino==replacement.st_ino and list(public.iterdir())==[];public.rmdir();backup.rename(public)
  except Exception:proof['owned_original_directory_restore_unconfirmed']=True
 if csrf:
  try:api('logout','/logout',{})
  except Exception:proof['ok']=False
 proof['requests']=events;save('original-result',proof);print(json.dumps(proof),flush=True)
sys.exit(0 if proof['ok']else 1)
