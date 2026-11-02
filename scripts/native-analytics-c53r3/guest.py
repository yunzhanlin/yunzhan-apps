"""Fresh normal signed C52 install, preserving C53r3 upgrade and actual Nginx analytics.

The 2.3.1 baseline uses the original compiled default install API. It is not
claimed as a historical signed-catalogue install. Only the new2.3.2 app update
uses the current original-key signed catalogue. Every mutation is once-only.
"""
import ast,contextlib,copy,hashlib,http.client,http.cookiejar,json,os,pathlib,platform,re,runpy,secrets,sqlite3,stat,subprocess,sys,tarfile,time,traceback,urllib.error,urllib.parse,urllib.request
os.umask(0o077);assert len(sys.argv)==2 and os.geteuid()==0
payload=pathlib.Path(sys.argv[1]).resolve(strict=True);pins=json.loads((payload/'assets.json').read_bytes())
OLD='44fa6a9522dbf207647c5664d05fbfbdc9f348e4bd2b66560373e1140805ba72';NEW='5205013d8b65fea12a4f3dd584c3a6cc49afa3bd7582c59e5f3c917cac36bb87'
OLD_VERSION='0.1.0-dev.proapps24apachewriterbusycandidate52';VERSION='0.1.0-dev.proapps24analyticsidentitycandidate53r3'
assert platform.machine()=='x86_64'and pins['architecture']=='amd64'and pins['source_inputs_sha256']==NEW and pins['version']==VERSION and pins['baseline_source_inputs_sha256']==OLD and pins['baseline_version']==OLD_VERSION
case=pins['OS_case'];assert case['architecture']=='amd64'and case['platform']in('debian-12','debian-13','ubuntu-22.04','ubuntu-24.04','ubuntu-26.04')
assert pathlib.Path('/etc/hostname').read_text().strip()==case['hostname']and 'VERSION_ID="'+case['version_id']+'"'in pathlib.Path('/usr/lib/os-release').read_text()and pathlib.Path('/proc/1/comm').read_text().strip()=='systemd'
base=pathlib.Path('/opt/panel-analytics-c53r3-native-qa-'+secrets.token_hex(16));base.mkdir(mode=0o700);evidence=base/'evidence';evidence.mkdir(mode=0o700)
def sha(path):return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()
def save(name,value):
 assert re.fullmatch('[A-Za-z0-9._-]+',name)
 with os.fdopen(os.open(evidence/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600),'w')as f:json.dump(value,f,sort_keys=True,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
verified=base/'verified-input';verified.mkdir(mode=0o700)
for name,digest in pins['files'].items():
 assert re.fullmatch('[A-Za-z0-9._-]+',name)
 with os.fdopen(os.open(payload/name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC),'rb')as f:
  s=os.fstat(f.fileno());assert stat.S_ISREG(s.st_mode)and s.st_nlink==1 and 0<s.st_size<=64<<20;raw=f.read((64<<20)+1);z=os.fstat(f.fileno());assert len(raw)==s.st_size and hashlib.sha256(raw).hexdigest()==digest and(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)==(z.st_dev,z.st_ino,z.st_size,z.st_mtime_ns,z.st_ctime_ns)
 with os.fdopen(os.open(verified/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600),'wb')as f:f.write(raw);f.flush();os.fsync(f.fileno())
payload=verified
assert sha(payload/'signed-release.py')=='fe128e82b4e11345b320cd782134768bfe1a4df14947c425d7494873a7a7b7b5'
assert sha(payload/'release-signing-dev.pub')=='4ccfcc861d56a41e3ba7f7ace7e2432c815f366c58448d783df92c6632f01339'
names={'command','unit','snapshot','api','NoRedirect'};nodes=[n for n in ast.parse((payload/'capture.py').read_bytes()).body if isinstance(n,(ast.FunctionDef,ast.ClassDef))and n.name in names];assert len(nodes)==len(names);exec(compile(ast.Module(body=nodes,type_ignores=[]),'<original-full113-observer-and-once-HTTP-client>','exec'),globals())
qualify=runpy.run_path(str(payload/'preservation.py'))['qualify_background'];boot=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip();p={'boot':boot};own_site=None;secret=secrets.token_hex(32)
origin='http://127.0.0.1:19100';csrf='';events=[];logged=False
client=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect(),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
proof={'ok':False,'architecture':'amd64','base':str(base),'source_inputs_sha256':NEW,'OS_case':case,'normal_C52_programme_first_install_submissions':0,'normal_C53r3_programme_upgrade_submissions':0,'baseline_231_compiled_default_install_POSTs':0,'historical_signed_231_baseline_claim':False,'original_operations_replayed':False,'Main_changed':False,'all50_commercial':False,'actual_browser_UI_acceptance':False}
def wait_job(label,jid,table,wanted='succeeded'):
 assert re.fullmatch('[a-f0-9]{32}',jid)and table in('jobs','runtime_jobs')and wanted in('succeeded','failed');deadline=time.monotonic()+900;seen=[]
 while True:
  with contextlib.closing(sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True,timeout=3))as db:
   db.row_factory=sqlite3.Row;db.execute('PRAGMA query_only=ON');row=dict(db.execute('SELECT *FROM '+table+' WHERE id=?',(jid,)).fetchone())
  if not seen or seen[-1]['state']!=row['state']:seen.append({'state':row['state'],'at':time.time()})
  if row['state']not in('queued','running'):break
  assert time.monotonic()<deadline,'Original job unresolved; no replay';time.sleep(.5)
 save(label+'-original-observations.json',seen);save(label+'-original-terminal.json',row);assert row['state']==wanted and bool(row['error'])==(wanted=='failed'),(label,row['state']);return row
def guard(label):
 for i in range(9):
  r=subprocess.run(['/opt/panel/current/bin/panel-executor','--check-program-upgrade-queues'],capture_output=True,timeout=35);u=unit('panel-mysql-overwrite-recovery.service');save(label+'-guard-'+str(i)+'.json',{'exit':r.returncode,'stdout_hex':r.stdout.hex(),'stderr_hex':r.stderr.hex(),'recovery_unit':u})
  if r.returncode==0:assert r.stdout==r.stderr==b'';return
  assert i<8 and r.stdout==b''and b'panel-mysql-overwrite-recovery.service'in r.stderr and u['ActiveState']=='activating'and u['SubState']=='condition'and u['MainPID']=='0';time.sleep(1)
def run_once(label,args,timeout):
 save(label+'-once-intent.json',{'args':args,'maximum_submissions':1,'unknown_observe_only':True})
 with(evidence/(label+'.stdout.log')).open('xb')as out,(evidence/(label+'.stderr.log')).open('xb')as err:r=subprocess.run(args,stdin=subprocess.DEVNULL,stdout=out,stderr=err,timeout=timeout)
 save(label+'-original-outcome.json',{'exit':r.returncode,'stdout_sha256':sha(evidence/(label+'.stdout.log')),'stderr_sha256':sha(evidence/(label+'.stderr.log'))});assert r.returncode==0,'Original operation failed; no replay: '+label
def installed_archive(label,version,source):
 archive=payload/('panel-'+version+'-linux-amd64.tar.gz');assert sha(archive)==pins['files'][archive.name];root=pathlib.Path('/opt/panel/current').resolve(strict=True);assert str(root)=='/opt/panel/releases/'+version;entries=[];prefix='panel-'+version+'-linux-amd64'
 with tarfile.open(archive,'r:gz')as tar:
  for member in tar:
   assert member.name==prefix or member.name.startswith(prefix+'/');relative=member.name[len(prefix):].lstrip('/');f=root/relative;s=f.lstat();assert s.st_uid==0 and stat.S_IMODE(s.st_mode)==member.mode;record={'path':relative,'mode':member.mode,'uid':s.st_uid,'gid':s.st_gid,'inode':s.st_ino}
   if member.isfile():assert stat.S_ISREG(s.st_mode)and s.st_nlink==1;record.update(type='file',bytes=s.st_size,sha256=sha(f));assert hashlib.sha256(tar.extractfile(member).read()).hexdigest()==record['sha256']
   else:assert member.isdir()and stat.S_ISDIR(s.st_mode);record['type']='directory'
   entries.append(record)
 assert len(entries)==203 and {''}|{str(f.relative_to(root))for f in root.rglob('*')}=={r['path']for r in entries}
 assert json.loads((root/'SOURCE_INPUTS.json').read_bytes())['inputs_sha256']==source
 save(label+'-entire-normal-installed-tree.json',{'ok':True,'source_inputs_sha256':source,'archive_sha256':sha(archive),'entries':entries,'count':203})
 return {r['path'][4:]:r['sha256']for r in entries if r['path'].startswith('bin/')and r['type']=='file'}
def preserving_programme_compare(before,after,target_programmes=None):
 for key in('nss','packages','NFS_state','schema','boot'):assert before[key]==after[key],key
 def protected(s):return{n:v for n,v in s['protected_files'].items()if not any(n==path or n.startswith(path+'/')for path in('/opt/panel/current/bin','/opt/panel/current/web'))}
 assert protected(before)==protected(after);reference=copy.deepcopy(before)
 if target_programmes:
  for unit_name,binary in(('panel.service','panel'),('panel-executor.service','panel-executor')):
   assert before['lifetimes'][unit_name]!=after['lifetimes'][unit_name]and after['lifetimes'][unit_name]['exe_sha256']==target_programmes[binary];reference['lifetimes'][unit_name]=copy.deepcopy(after['lifetimes'][unit_name])
 else:assert before['protected_files']==after['protected_files']
 assert reference['lifetimes']==after['lifetimes'];delta=qualify(reference,after)
 return {'ok':True,'all113_tables_qualified':True,'old_protected_nonprogramme_entries_identical':len(protected(before)),'NSS_packages_NFS_and_other_service_lifetimes_identical':True,'only_two_expected_programme_lifetimes_changed':bool(target_programmes),'typed_background_delta':delta}
try:
 assert all(not os.path.lexists(n)for n in('/opt/panel','/var/lib/panel','/var/lib/panel-executor','/etc/panel-release','/etc/nginx/nginx.conf'))
 signer=['python3','-I','-B',str(payload/'signed-release.py')];key=['--public-key',str(payload/'release-signing-dev.pub')];old=payload/('panel-'+OLD_VERSION+'-linux-amd64.tar.gz');new=payload/('panel-'+VERSION+'-linux-amd64.tar.gz')
 run_once('original-C52-signature-verify',signer+['verify',str(old)]+key,30);proof['normal_C52_programme_first_install_submissions']+=1;run_once('one-original-C52-programme-first-install',signer+['install',str(old)]+key,1800)
 assert not os.path.lexists('/opt/panel/DEVELOPMENT_RELEASE');installed_archive('actual-C52',OLD_VERSION,OLD);guard('C52-ready');save('C52-before-apps-entire113.json',snapshot())
 access_file=pathlib.Path('/etc/panel/first-login.json');s=access_file.lstat();assert stat.S_ISREG(s.st_mode)and s.st_uid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600;access=json.loads(access_file.read_bytes())
 try:csrf=api('one-login','/login',{k:access[k]for k in('username','password')})['csrf'];logged=True
 finally:access.clear()
 proof['baseline_231_compiled_default_install_POSTs']+=1;reply=api('one-original-compiled231-install','/software/website-analytics/install',{},202,secrets.token_hex(16));legacy_job=wait_job('compiled231-baseline-install',reply['job_id'],'runtime_jobs');assert legacy_job['kind']=='software_install'
 module=pathlib.Path('/etc/panel/security-apps/modules/website-analytics');installed_original=(module/'installed.json').read_bytes();assert json.loads(installed_original)['version']=='2.3.1'
 nonce=secrets.token_hex(16);domain='qa-analytics-c53-'+nonce[:12]+'.example.test';reply=api('one-original-legacy-site-create','/sites',{'name':'Analytics native legacy upgrade acceptance','slug':'qa-analytics-c53-'+nonce[:12],'domain':domain,'php_version_id':''},202,secrets.token_hex(16));site_job=wait_job('legacy-site-create',reply['job_id'],'jobs');own_site=site_job['site_id'];assert re.fullmatch('[a-f0-9]{32}',own_site)
 cfg=api('legacy-original-disabled-config','/analytics/sites/'+own_site+'/config');assert not cfg['enabled']and cfg['revision']==0
 reply=api('one-original-legacy-collector-enable','/analytics/sites/'+own_site+'/config',{'enabled':True,'clicks':False,'retention_days':30,'revision':0,'auto_inject_html':False},202,secrets.token_hex(16));wait_job('legacy-collector-enable',reply['job_id'],'jobs');cfg=api('actual-original-legacy-config','/analytics/sites/'+own_site+'/config');assert cfg['enabled']and cfg['revision']==1 and cfg['proxy_endpoint']=='127.0.0.1:19100'
 vhost=pathlib.Path('/etc/panel/sites-enabled')/(own_site+'.conf');original_vhost=vhost.read_bytes();assert re.search(rb'^\s*listen 127\.0\.0\.1:19101;',original_vhost,re.M)and b'analytics-ingress'not in original_vhost and b'X-Yunzhan-Analytics'not in original_vhost
 for i,address in enumerate(('127.0.0.21','127.0.0.22')):
  event={'id':secrets.token_hex(16),'page_id':secrets.token_hex(16),'visitor':secrets.token_hex(16),'session':secrets.token_hex(16),'kind':'pageview','path':'/legacy-'+str(i),'title':'Original compiled231 native baseline'};raw=json.dumps(event,separators=(',',':')).encode();save('legacy-event-'+str(i)+'-once-intent.json',{'maximum_POSTs':1,'source_loopback':address,'original_request_body_hex':raw.hex()});connection=http.client.HTTPConnection('127.0.0.1',19101,source_address=(address,0),timeout=10)
  try:
   connection.request('POST','/__yunzhan/analytics/event?'+urllib.parse.urlencode({'site':own_site,'key':cfg['key']}),raw,{'Host':domain,'Origin':'http://'+domain,'Content-Type':'application/json','User-Agent':'Mozilla/5.0 Chrome/123.0 native legacy acceptance'});r=connection.getresponse();body=r.read(8193);status=r.status;headers=r.getheaders()
  finally:connection.close()
  save('legacy-event-'+str(i)+'-original-HTTP-response.json',{'status':status,'original_body_hex':body.hex(),'headers':headers});assert status==204 and body==b''and not any(k.lower()=='set-cookie'for k,v in headers)
 report=api('actual-legacy231-two-event-report','/analytics/sites/'+own_site+'/report');assert report['overview']['pv']==report['overview']['uv']==2 and report['overview']['unique_network_peers']==1 and 'client_addresses'not in report
 guard('before-programme-upgrade');before=snapshot();save('before-C53r3-upgrade-entire113.json',before)
 with contextlib.closing(sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True))as db:legacy_rows=db.execute('SELECT id,data,ip_hash FROM analytics_events WHERE site_id=?ORDER BY id',(own_site,)).fetchall()
 assert len(legacy_rows)==2 and all('client_address'not in x[1]for x in legacy_rows)
 save('original-compiled231-baseline.json',{'normal_compiled_default_install_not_historical_signed_catalogue_claim':True,'original_job':legacy_job,'site_id':own_site,'domain':domain,'original_installed_hex':installed_original.hex(),'original_vhost_hex':original_vhost.hex(),'original_legacy_rows':legacy_rows})
 run_once('original-C53r3-signature-verify',signer+['verify',str(new)]+key,30);run_once('C53r3-upgrade-preflight',signer+['install',str(new)]+key+['--preflight-only'],900);pre=snapshot();save('after-preflight-entire113.json',pre);save('normal-preflight-qualified.json',preserving_programme_compare(before,pre))
 proof['normal_C53r3_programme_upgrade_submissions']+=1;run_once('one-original-C53r3-programme-upgrade',signer+['install',str(new)]+key,1200);target=installed_archive('actual-C53r3',VERSION,NEW);after=snapshot();save('after-programme-upgrade-entire113.json',after);save('normal-programme-upgrade-qualified.json',preserving_programme_compare(before,after,target));guard('after-programme-upgrade')
 assert (module/'installed.json').read_bytes()==installed_original and vhost.read_bytes()==original_vhost
 result=runpy.run_path(str(payload/'business.py'))['run_live_case'](api,wait_job,save,evidence,own_site,domain,nonce);assert result['ok'];proof.update(result);proof.update(normal_original_key_C52_first_install_and_C53r3_upgrade=True,both_actual203_entry_installed_trees_verified=True,all113_tables_preserved_during_programme_upgrade=True,original_compiled231_baseline_preserved_before_signed232_update=True)
except BaseException:save('failure.json',{'traceback':traceback.format_exc()})
finally:
 if logged:
  try:api('one-logout','/logout',{})
  except BaseException:proof['ok']=False;save('logout-failure.json',{'traceback':traceback.format_exc()})
 try:guard('final');save('after-all-business-entire113.json',snapshot())
 except BaseException:proof['ok']=False;save('final-observation-failure.json',{'traceback':traceback.format_exc()})
 save('all-original-admin-HTTP-events.json',events);save('proof.json',proof);print(json.dumps({'ok':proof['ok'],'base':str(base),'proof_sha256':sha(evidence/'proof.json'),'source_inputs_sha256':NEW,'Main_changed':False}),flush=True)
sys.exit(0 if proof['ok']else 1)
