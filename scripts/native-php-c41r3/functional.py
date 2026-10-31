"""Owned current-source PHP custom-vhost and CAS acceptance; never Main."""
import contextlib,hashlib,http.cookiejar,json,os,pathlib,platform,pwd,grp,re,secrets,sqlite3,stat,subprocess,sys,time,traceback,urllib.error,urllib.request
os.umask(0o077);assert os.geteuid()==0 and len(sys.argv)==2
base=pathlib.Path(sys.argv[1]);assert re.fullmatch('/opt/panel-php-c41r3-functional-[a-f0-9]{32}',str(base))
for parent in(base,*base.parents):
 s=parent.lstat();assert stat.S_ISDIR(s.st_mode)and s.st_uid==0 and not s.st_mode&0o022
plan=json.loads((base/'intent.json').read_bytes());assert plan['base']==str(base)and pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()==plan['boot'];arch={'aarch64':'arm64','x86_64':'amd64'}[platform.machine()];assert arch==plan['architecture']and type(plan['prepare_apps'])is bool
SOURCE='757e1941dc2e3e138cef458eb52114545d168ee41286872012e100770c50a1fb';assert json.loads(pathlib.Path('/opt/panel/current/SOURCE_INPUTS.json').read_bytes())['inputs_sha256']==SOURCE
for name,digest in plan['files'].items():
 f=base/name;s=f.lstat();assert re.fullmatch('[A-Za-z0-9._-]+',name)and stat.S_ISREG(s.st_mode)and s.st_uid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600 and hashlib.sha256(f.read_bytes()).hexdigest()==digest
for name,digest in plan['programme_binaries'].items():assert name in('panel','panel-executor','panel-start-guard')and hashlib.sha256(pathlib.Path('/opt/panel/current/bin',name).read_bytes()).hexdigest()==digest
evidence=base/'evidence';evidence.mkdir(mode=0o700)
origin='http://127.0.0.1:19100';client=None;csrf='';http_events=[]

def sha(p):return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()

def save(n,v):
 assert re.fullmatch('[A-Za-z0-9._-]+',n)
 with os.fdopen(os.open(evidence/n,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600),'w')as f:json.dump(v,f,sort_keys=True,indent=2);f.write(chr(10));f.flush();os.fsync(f.fileno())

def command(label,args,timeout,env=None):
 save(label+'-once-intent.json',{'maximum_submissions':1,'args':args,'unknown_outcome_observe_only':True})
 with(evidence/(label+'.stdout.log')).open('xb')as out,(evidence/(label+'.stderr.log')).open('xb')as err:r=subprocess.run(args,stdin=subprocess.DEVNULL,stdout=out,stderr=err,timeout=timeout,env=env)
 save(label+'-outcome.json',{'exit':r.returncode,'stdout_sha256':sha(evidence/(label+'.stdout.log')),'stderr_sha256':sha(evidence/(label+'.stderr.log'))});assert r.returncode==0,'Original normal operation failed; no replay: '+label

def guard(label):
 for i in range(9):
  r=subprocess.run(['/opt/panel/current/bin/panel-executor','--check-program-upgrade-queues'],capture_output=True,timeout=30)
  u=dict(v.split('=',1)for v in subprocess.check_output(['systemctl','show','panel-mysql-overwrite-recovery.service','--property=LoadState,ActiveState,SubState,MainPID,ControlPID'],text=True,timeout=5).splitlines())
  save(label+'-guard-'+str(i)+'.json',{'exit':r.returncode,'stdout_hex':r.stdout.hex(),'stderr_hex':r.stderr.hex(),'fixed_recovery_unit':u})
  if r.returncode==0:assert r.stdout==r.stderr==b'';return
  assert i<8 and r.stdout==b''and b'panel-mysql-overwrite-recovery.service'in r.stderr and u['LoadState']=='loaded'and u['ActiveState']=='activating'and u['SubState']=='condition'and u['MainPID']=='0'
  time.sleep(1)

def lifetime(unit):
 pid=subprocess.check_output(['systemctl','show',unit,'--property=MainPID','--value'],text=True,timeout=5).strip();assert int(pid)>1
 return {'pid':pid,'start_ticks':pathlib.Path('/proc/'+pid+'/stat').read_text().rsplit(')',1)[1].split()[19],'exe_sha256':sha('/proc/'+pid+'/exe')}

def nss():return{n:{'entries':{line.split(':',1)[0]:hashlib.sha256(line.encode()).hexdigest()for line in pathlib.Path('/etc/'+n).read_text().splitlines()},'sha256':sha('/etc/'+n),'mode':pathlib.Path('/etc/'+n).stat().st_mode,'uid':pathlib.Path('/etc/'+n).stat().st_uid,'gid':pathlib.Path('/etc/'+n).stat().st_gid}for n in('passwd','group','shadow','gshadow','nsswitch.conf')}

class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*args,**kwargs):raise AssertionError('Authentication redirect refused')

def api(path,body=None,key=None,allowed=(200,202)):
 headers={'Origin':origin,'Content-Type':'application/json','X-CSRF-Token':csrf}
 if key:headers['Idempotency-Key']=key
 req=urllib.request.Request(origin+'/api'+path,data=None if body is None else json.dumps(body,separators=(',',':')).encode(),headers=headers)
 try:
  with client.open(req,timeout=35)as r:status=r.status;raw=r.read((4<<20)+1)
 except urllib.error.HTTPError as e:status=e.code;raw=e.read((4<<20)+1)
 assert len(raw)<=4<<20;value=json.loads(raw);http_events.append({'path':path,'method':'GET'if body is None else'POST','status':status})
 if status not in allowed:save('HTTP-refusal-'+secrets.token_hex(8)+'.json',{'path':path,'status':status,'value':value});raise AssertionError('Original HTTP refusal '+str(status)+':'+path)
 return status,value

def job(label,identity,expected="succeeded"):
 assert re.fullmatch('[a-f0-9]{32}',identity);observed=[];deadline=time.monotonic()+1800
 while True:
  with contextlib.closing(sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True,timeout=3))as db:
   db.row_factory=sqlite3.Row;db.execute('PRAGMA query_only=ON');rows=[(name,db.execute('SELECT * FROM '+name+' WHERE id=?',(identity,)).fetchone())for name in('jobs','runtime_jobs')];found=[(name,dict(row))for name,row in rows if row is not None]
  assert len(found)==1;table,row=found[0];observed.append({'state':row['state'],'error':row.get('error',''),'at':time.time()})
  if row['state']in('succeeded','failed','needs_attention','cancelled','canceled'):break
  assert time.monotonic()<deadline,'Original job unresolved; observe only';time.sleep(1)
 save(label+'-original-job-observations.json',observed);save(label+'-original-Core-terminal.json',{'table':table,'row':row})
 if expected=='failed':
  assert table=='jobs'and row['state']=='failed'and '配置已发生变化'in row['error'];path=pathlib.Path('/var/lib/panel-executor')/(identity+'.json');assert not os.path.lexists(path);save(label+'-original-native-refusal.json',{'expected_before_effects_SHA_conflict':True,'original_native_commit_ledger_absent':True});return row
 assert expected=='succeeded'and row['state']=='succeeded'and not row.get('error'),'Original job refused; no reset or replay'
 native=pathlib.Path('/var/lib/panel-executor/installs'if table=='runtime_jobs'else'/var/lib/panel-executor')/(identity+'.json');assert native.is_file();raw=native.read_bytes();assert len(raw)<2<<20;save(label+'-original-native-terminal.json',{'path':str(native),'sha256':sha(native),'value':json.loads(raw)});return row

def submit(label,path,body,wait=True):
 key=secrets.token_hex(16);save(label+'-once-intent.json',{'path':path,'body':body,'idempotency_key':key,'maximum_POSTs':1,'unknown_outcome_observe_only':True});status,value=api(path,body,key);save(label+'-original-accepted.json',{'status':status,'value':value})
 if wait:assert status==202 and re.fullmatch('[a-f0-9]{32}',value['job_id']);job(label,value['job_id'])
 return value

def kernel_rules():
 r=subprocess.run(['nft','-j','list','ruleset'],capture_output=True,text=True,timeout=5);assert r.returncode==0
 def normalize(v):
  if isinstance(v,list):return[normalize(x)for x in v]
  if isinstance(v,dict):return{k:({'packets':0,'bytes':0}if k=='counter'and isinstance(x,dict)and set(x)=={'packets','bytes'}else normalize(x))for k,x in v.items()}
  return v
 return normalize(json.loads(r.stdout))

def website(site,path,body=None,content_type=None):
 headers={'Host':site['domain'],'User-Agent':'yunzhan-owned-native-PHP-QA'}
 if content_type:headers['Content-Type']=content_type
 with web.open(urllib.request.Request('http://127.0.0.1:19101'+path,data=body,headers=headers),timeout=15)as response:assert response.status==200;raw=response.read(65537)
 assert len(raw)<=65536;return raw

def verify_site(label,site,version):
 account=pwd.getpwnam('ps'+site['id'][:24]);group=grp.getgrnam(account.pw_name);assert account.pw_uid!=0 and account.pw_gid==group.gr_gid!=0;user={'uid':account.pw_uid,'primary_gid':account.pw_gid,'export_gid':grp.getgrnam('www-data').gr_gid}
 def check(actual):
  assert actual['php']==version and actual['redis']=='6.3.0'and actual['uid']==user['uid']and actual['gid']==user['primary_gid']and actual['enabled']is False and actual['memory']=='256M'and actual['time']=='120'and actual['upload']=='16M'and actual['post']=='32M'and actual['timezone']=='UTC',actual
 actual=json.loads(website(site,'/session-upload.php'));check(actual);assert actual['files']==0
 token=secrets.token_hex(16);boundary='yunzhan'+token;sample=b'normal-upload\n'*128
 body=('--'+boundary+'\r\nContent-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nowned-probe\r\n--'+boundary+'\r\nContent-Disposition: form-data; name="sample"; filename="sample.txt"\r\nContent-Type: text/plain\r\n\r\n').encode()+sample+('\r\n--'+boundary+'--\r\n').encode();uploaded=json.loads(website(site,'/session-upload.php',body,'multipart/form-data; boundary='+boundary));check(uploaded);assert uploaded['files']==1 and uploaded['error']==0 and uploaded['sha256']==hashlib.sha256(sample).hexdigest()
 cli="echo json_encode(['php'=>PHP_VERSION,'redis'=>phpversion('redis'),'uid'=>posix_geteuid(),'gid'=>posix_getegid(),'enabled'=>filter_var(ini_get('session.upload_progress.enabled'),FILTER_VALIDATE_BOOL),'memory'=>ini_get('memory_limit'),'time'=>ini_get('max_execution_time'),'upload'=>ini_get('upload_max_filesize'),'post'=>ini_get('post_max_size'),'timezone'=>ini_get('date.timezone')]);";r=subprocess.run(['/opt/panel/current/bin/panel-executor','--site-cli='+site['id'],'--','-r',cli],capture_output=True,text=True,timeout=20);assert r.returncode==0 and not r.stderr;actual_cli=json.loads(r.stdout);check(actual_cli)
 with contextlib.closing(sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True))as db:
  db.row_factory=sqlite3.Row;db.execute('PRAGMA query_only=ON');row=dict(db.execute('SELECT * FROM sites WHERE id=?',(site['id'],)).fetchone())
 assert row['status']=='running'and row['php_version_id']=='php-'+version
 instance=row['runtime_instance_id'];config=pathlib.Path('/etc/panel/php-sites')/instance/'fpm.conf';manifest=config.parent/'pool.json';nginx=pathlib.Path('/etc/panel/sites-enabled')/(site['id']+'.conf');save(label+'-actual-site-and-upload.json',{'site':row,'account':user,'actual_GET':actual,'actual_multipart':uploaded,'actual_CLI':actual_cli,'FPM_configuration_sha256':sha(config),'FPM_manifest_sha256':sha(manifest),'nginx_sha256':sha(nginx)});return {'nginx':sha(nginx),'FPM':sha(config),'manifest':sha(manifest)}
def cmd(args):
 r=subprocess.run(args,capture_output=True,text=True,timeout=30);assert r.returncode==0,(args[0],r.returncode);assert len(r.stdout)<1<<20;return r.stdout

def snapshot():
 data={}
 with contextlib.closing(sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True,timeout=3))as db:
  db.execute('PRAGMA query_only=ON');db.execute('BEGIN');schema=db.execute("SELECT type,name,tbl_name,sql FROM sqlite_master WHERE name NOT LIKE'sqlite_%'ORDER BY type,name").fetchall()
  for name, in db.execute("SELECT name FROM sqlite_master WHERE type='table'AND name NOT LIKE'sqlite_%'ORDER BY name").fetchall():
   assert re.fullmatch('[a-z0-9_]+',name);cols=[v[1]for v in db.execute('PRAGMA table_info("'+name+'")')];rows=[]
   for row in db.execute('SELECT * FROM "'+name+'"'):
    rows.append([{'blob_hex':v.hex()}if isinstance(v,bytes)else v for v in row]);assert len(rows)<=100000
   rows.sort(key=lambda v:json.dumps(v,sort_keys=True,separators=(',',':')));data[name]={'columns':cols,'rows':rows}
 nss={}
 for n in('passwd','group','shadow','gshadow','nsswitch.conf'):
  f=pathlib.Path('/etc')/n;nss[n]={'sha256':sha(f),'entries':{v.split(':',1)[0]:hashlib.sha256(v.encode()).hexdigest()for v in f.read_text().splitlines()}}
 return {'at':time.time(),'boot':plan['boot'],'schema':schema,'tables':data,'nss':nss,'lifetimes':{u:lifetime(u)for u in('panel.service','panel-executor.service','nginx.service','ssh.service','fail2ban.service')}}
web=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
def ordinary_raw(path, limit=65536):
 s=path.lstat();assert stat.S_ISREG(s.st_mode)and s.st_uid==0 and s.st_nlink==1 and 0<s.st_size<=limit
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
 with os.fdopen(fd,'rb')as f:
  raw=f.read(limit+1);after=os.fstat(f.fileno());assert len(raw)==s.st_size and(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns)==(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns)
 return raw

def tree_of(paths):
 result={};total=0
 def walk(f):
  nonlocal total
  s=f.lstat();v={'dev':s.st_dev,'ino':s.st_ino,'mode':s.st_mode,'uid':s.st_uid,'gid':s.st_gid,'links':s.st_nlink}
  if stat.S_ISREG(s.st_mode):assert s.st_size<128<<20;total+=s.st_size;assert total<1<<30;v.update(sha256=sha(f),bytes=s.st_size)
  elif stat.S_ISLNK(s.st_mode):v['target']=os.readlink(f)
  else:assert stat.S_ISDIR(s.st_mode)
  result[str(f)]=v;assert len(result)<30000
  if stat.S_ISDIR(s.st_mode):
   for child in sorted(f.iterdir()):walk(child)
 for name in paths:
  f=pathlib.Path(name)
  if os.path.lexists(f):walk(f)
 return result

def current_site(identity):
 _,sites=api('/sites');rows=[v for v in sites if v['id']==identity];assert len(rows)==1;return rows[0]

def direct_http(site,path,expected):
 request=urllib.request.Request('http://127.0.0.1:19101'+path,headers={'Host':site['domain'],'User-Agent':'yunzhan-owned-config-preservation'})
 try:
  with web.open(request,timeout=15)as r:status=r.status;raw=r.read(65537);headers=dict(r.headers.items())
 except urllib.error.HTTPError as e:status=e.code;raw=e.read(65537);headers=dict(e.headers.items())
 if status!=expected or len(raw)>65536:save('unexpected-HTTP-'+secrets.token_hex(8)+'.json',{'path':path,'expected':expected,'status':status,'headers':headers,'body_sha256':hashlib.sha256(raw).hexdigest()})
 assert status==expected and len(raw)<=65536
 return {'status':status,'body_sha256':hashlib.sha256(raw).hexdigest(),'headers':headers}

def check_custom(label,site):
 denied=direct_http(site,'/c41-guarded.txt',404);cached=direct_http(site,'/c41-cache.txt',200);home=direct_http(site,'/',200)
 h=lambda data:{k.lower():v for k,v in data['headers'].items()}
 assert cached['body_sha256']==hashlib.sha256(marker.encode()).hexdigest()and h(cached).get('x-c41-cache')==marker and h(cached).get('cache-control')=='max-age=604800'
 assert h(home).get('x-c41-private')==marker
 save(label+'-actual-custom-HTTP.json',{'guarded_existing_file':denied,'cached_existing_file':cached,'homepage':home});return {'guard':denied['status'],'cache_body':cached['body_sha256'],'cache_header':h(cached)['x-c41-cache'],'cache_control':h(cached)['cache-control'],'home_header':h(home)['x-c41-private']}

def replace_owned_config(label,site,content,reload):
 path=pathlib.Path('/etc/panel/sites-enabled')/(site['id']+'.conf');old=ordinary_raw(path);assert len(content)<=65536 and content.startswith(('# managed by panel; site='+site['id']).encode())
 with(evidence/(label+'-original.conf')).open('xb')as f:f.write(old);f.flush();os.fsync(f.fileno())
 save(label+'-once-intent.json',{'site_id':site['id'],'before_sha256':hashlib.sha256(old).hexdigest(),'candidate_sha256':hashlib.sha256(content).hexdigest(),'QA_fixture_only':True,'maximum_writes':1,'reload':reload})
 def write(raw):
  tmp=path.parent/('.'+site['id']+'-c41-'+secrets.token_hex(8));fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  with os.fdopen(fd,'wb')as f:f.write(raw);f.flush();os.fchmod(f.fileno(),0o644);os.fsync(f.fileno())
  os.replace(tmp,path)
  d=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY);os.fsync(d);os.close(d)
 write(content)
 try:
  command(label+'-syntax',['/usr/sbin/nginx','-t'],30)
  if reload:command(label+'-reload',['/usr/bin/systemctl','reload','nginx'],30)
 except BaseException:
  write(old);save(label+'-original-fixture-restored.json',{'restored_sha256':sha(path),'original_sha256':hashlib.sha256(old).hexdigest()});raise
 assert ordinary_raw(path)==content

def preview_switch(label,site,target):
 status,value=api('/sites/'+site['id']+'/php/preview',{'release_id':target});save(label+'-original-preview.json',value)
 assert status==200 and value['protocol']=='php-vhost-switch-v1'and value['site_id']==site['id']and value['release_id']==target and value['preserves_custom_config']is True
 path=pathlib.Path('/etc/panel/sites-enabled')/(site['id']+'.conf');assert value['config_sha']==sha(path)and value['current'].encode()==ordinary_raw(path)
 assert '# C41 private fixture '+marker in value['candidate']and 'if ($uri = /c41-guarded.txt)'in value['candidate']and 'location = /c41-cache.txt'in value['candidate']
 # Independent fixture oracle: exact original bytes with only the known
 # real upstream arguments and the two managed health values substituted.
 current=current_site(site['id']);instance=current['runtime_instance_id'];prefix=site['id']+'-'+current['php_version_id'];assert instance.startswith(prefix)and re.fullmatch('-cfg-[a-f0-9]{24}',instance[len(prefix):]);new_instance=site['id']+'-'+target+instance[len(prefix):]
 old_socket='unix:/run/panel-php-'+instance+'/fpm.sock';new_socket='unix:/run/panel-php-'+new_instance+'/fpm.sock';pattern=re.compile(r'(?m)^(\s*fastcgi_pass )'+re.escape(old_socket)+r'(;)$');expected,count=pattern.subn(lambda m:m[1]+new_socket+m[2],value['current']);assert 1<=count<=16
 def health(release):return 'panel:'+site['id']+':'+hashlib.sha256(json.dumps({'Settings':current['settings'],'PHP':release},ensure_ascii=False,separators=(',',':')).encode()).hexdigest()
 old_body=health(current['php_version_id']);new_body=health(target);old_return='return 200 "'+old_body+'";';new_return='return 200 "'+new_body+'";';old_header='add_header X-Panel-Config "'+hashlib.sha256(old_body.encode()).hexdigest()+'" always;';new_header='add_header X-Panel-Config "'+hashlib.sha256(new_body.encode()).hexdigest()+'" always;';assert expected.count(old_return)==expected.count(old_header)==1;expected=expected.replace(old_return,new_return,1).replace(old_header,new_header,1);assert value['candidate']==expected,'Preview changed bytes outside owned upstream/health tokens'
 return value

def refusal_state(site):
 row=current_site(site['id']);path=pathlib.Path('/etc/panel/sites-enabled')/(site['id']+'.conf');s=path.lstat();unit='panel-php@'+row['runtime_instance_id']+'.service';cfg=pathlib.Path('/etc/panel/php-sites')/row['runtime_instance_id']
 return {'site':{k:v for k,v in row.items()if k!='updated_at'},'nginx_file':[s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,str(s.st_mtime_ns),sha(path)],'FPM':lifetime(unit),'FPM_config_sha256':sha(cfg/'fpm.conf'),'FPM_manifest_sha256':sha(cfg/'pool.json'),'binding_sha256':sha(pathlib.Path('/etc/panel/php-sites/bindings')/(site['id']+'.json'))}

proof={'ok':False,'source_inputs_sha256':SOURCE,'architecture':arch,'scope':'actual signed PHP Redis, configured owned website, custom protection/cache byte preservation, normal cross-version switch, explicit stale-SHA refusal and separate fresh return','all50_commercial':False,'Main_changed':False,'automatic_retry_or_original_job_replay':False,'normal_application_install_POSTs':0,'normal_extension_install_POSTs':0,'normal_site_create_POSTs':0,'normal_site_configure_POSTs':0,'normal_PHP_switch_POSTs':0,'QA_custom_config_writes':0}
try:
 guard('initial');before=snapshot();save('before.json',before);original_nss=nss();save('original-nss-before.json',original_nss);original_kernel=kernel_rules();save('original-kernel-before.json',original_kernel)
 existing_sites=[v.name for v in pathlib.Path('/srv/panel/sites').iterdir()if re.fullmatch('[a-f0-9]{32}',v.name)];original_confs=sorted(str(v)for v in pathlib.Path('/etc/panel/sites-enabled').iterdir()if v.name.endswith('.conf'))
 protected_paths=['/etc/nginx','/etc/panel/security-apps/modules/nfs-manager','/opt/panel/app-modules/nfs-manager','/etc/systemd/system/panel-nfs-server.service',*original_confs,*['/srv/panel/sites/'+v for v in existing_sites]]
 with contextlib.closing(sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True))as db:
  db.execute('PRAGMA query_only=ON')
  for binary, in db.execute("SELECT binary_path FROM runtime_installations WHERE status='installed'AND version_id LIKE 'php-%'"):
   prefix=pathlib.Path(binary).parent.parent;assert str(prefix).startswith('/opt/panel/runtimes/php/')and prefix.resolve(strict=True)==prefix;protected_paths.append(str(prefix))
 original_files=tree_of(protected_paths);save('protected-before.json',original_files)
 login=pathlib.Path('/etc/panel/first-login.json');ls=login.lstat();assert stat.S_ISREG(ls.st_mode)and ls.st_uid==0 and ls.st_nlink==1 and stat.S_IMODE(ls.st_mode)==0o600;access=json.loads(login.read_bytes());client=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect(),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
 try:status,value=api('/login',{k:access[k]for k in('username','password')});assert status==200;csrf=value['csrf']
 finally:access.clear()
 _,catalogue=api('/app-registry?refresh=1');save('original-signed-catalogue.json',catalogue);assert len(catalogue['catalog']['apps'])==50 and catalogue['host']=={'platform':plan['platform'],'architecture':arch}and not catalogue['source']['stale'];items={v['id']:v for v in catalogue['catalog']['apps']}
 versions=[('php-82','8.2.35'),('php-83','8.3.36')]
 for app,version in versions:
  item=items[app];assert item['version']==version+'-compat2'
  if plan['prepare_apps']:
   proof['normal_application_install_POSTs']+=1;submit(app+'-runtime-install','/app-registry/'+app+'/install',{'expected_version':item['version'],'expected_sha256':item['sha256'],'settings':{}})
  else:
   rows=[v for v in catalogue['status']if v['id']==app];assert len(rows)==1 and rows[0]['state_known']and rows[0]['installed']and rows[0]['healthy']and rows[0]['installed_version']==item['version']
  proof['normal_extension_install_POSTs']+=1;submit(app+'-redis-install','/php/extensions/php-'+version+'/install',{'extension_id':'redis-6.3.0'})
 nonce=secrets.token_hex(8);slug='php41-'+nonce;marker='C41-private-'+nonce;proof['normal_site_create_POSTs']=1;submit('site-create','/sites',{'name':'C41 private PHP preservation','slug':slug,'domain':slug+'.localhost','php_version_id':'php-8.2.35'})
 _,sites=api('/sites');site=next(v for v in sites if v['slug']==slug);proof['site_id']=site['id'];_,settings=api('/sites/'+site['id']+'/settings');config=settings['settings'];config['php']={'extensions':['redis-6.3.0'],'memory_mb':256,'max_execution_seconds':120,'upload_mb':16,'post_mb':32,'timezone':'UTC','display_errors':False,'max_children':2,'max_requests':500}
 body={'settings':config,'expected_revision':settings['settings_revision']};_,candidate=api('/sites/'+site['id']+'/settings/preview',body);body['expected_config_sha']=candidate['config_sha'];save('site-original-settings-preview.json',candidate);proof['normal_site_configure_POSTs']=1;submit('site-configure','/sites/'+site['id']+'/settings',body)
 code="<?php header('Content-Type: application/json'); echo json_encode(['php'=>PHP_VERSION,'redis'=>phpversion('redis'),'uid'=>posix_geteuid(),'gid'=>posix_getegid(),'enabled'=>filter_var(ini_get('session.upload_progress.enabled'),FILTER_VALIDATE_BOOL),'memory'=>ini_get('memory_limit'),'time'=>ini_get('max_execution_time'),'upload'=>ini_get('upload_max_filesize'),'post'=>ini_get('post_max_size'),'timezone'=>ini_get('date.timezone'),'files'=>count($_FILES),'error'=>$_FILES['sample']['error']??-1,'sha256'=>isset($_FILES['sample']['tmp_name'])?hash_file('sha256',$_FILES['sample']['tmp_name']):'']);"
 for name,content in [('session-upload.php',code),('c41-guarded.txt',marker),('c41-cache.txt',marker)]:submit('site-file-'+name.replace('.','-'),'/sites/'+site['id']+'/files/action',{'action':'create','path':name,'content':content},False)
 # The guarded file must really be accessible before adding the independent
 # custom rule, otherwise a generic404 would not establish preservation.
 assert direct_http(site,'/c41-guarded.txt',200)['body_sha256']==hashlib.sha256(marker.encode()).hexdigest()
 cfg=pathlib.Path('/etc/panel/sites-enabled')/(site['id']+'.conf');raw=ordinary_raw(cfg);custom=('  # C41 private fixture '+marker+'\n  if ($uri = /c41-guarded.txt) { return 404; }\n  add_header X-C41-Private "'+marker+'" always;\n  location = /c41-cache.txt { expires 7d; add_header X-C41-Cache "'+marker+'" always; try_files $uri =404; }\n').encode();assert raw.count(b'server {\n')==1;with_custom=raw.replace(b'server {\n',b'server {\n'+custom,1);proof['QA_custom_config_writes']+=1;replace_owned_config('owned-custom-fixture',site,with_custom,True)
 initial=verify_site('initial82',site,'8.2.35')
 readiness=[]
 for attempt in range(40):
  try:initial_custom=check_custom('initial82',site);readiness.append({'attempt':attempt,'ready':True,'at':time.time()});break
  except AssertionError:
   readiness.append({'attempt':attempt,'ready':False,'at':time.time()})
   if attempt==39:save('custom-fixture-readiness.json',readiness);raise
   time.sleep(.25)
 save('custom-fixture-readiness.json',readiness);original_cfg=ordinary_raw(cfg)
 preview=preview_switch('switch83',site,'php-8.3.36');proof['normal_PHP_switch_POSTs']+=1;submit('switch83','/sites/'+site['id']+'/php',{'release_id':'php-8.3.36','expected_config_sha':preview['config_sha']});assert ordinary_raw(cfg)==preview['candidate'].encode();verify_site('after83',site,'8.3.36');assert check_custom('after83',site)==initial_custom
 stale=preview_switch('stale-return82',site,'php-8.2.35');comment=('# C41 independent external comment '+nonce+'\n').encode();proof['QA_custom_config_writes']+=1;replace_owned_config('owned-comment-fixture',site,ordinary_raw(cfg)+comment,False);state_before=refusal_state(site);save('stale-original-before.json',state_before)
 proof['normal_PHP_switch_POSTs']+=1;failed=submit('stale-return82','/sites/'+site['id']+'/php',{'release_id':'php-8.2.35','expected_config_sha':stale['config_sha']},False);assert re.fullmatch('[a-f0-9]{32}',failed['job_id']);job('stale-return82',failed['job_id'],'failed');state_after=refusal_state(site);save('stale-original-after.json',state_after);assert state_before==state_after;proof['expected_stale_job_id']=failed['job_id'];assert check_custom('after-stale',site)==initial_custom
 fresh=preview_switch('fresh-return82',site,'php-8.2.35');assert fresh['config_sha']!=stale['config_sha'];proof['normal_PHP_switch_POSTs']+=1;submit('fresh-return82','/sites/'+site['id']+'/php',{'release_id':'php-8.2.35','expected_config_sha':fresh['config_sha']});assert ordinary_raw(cfg)==fresh['candidate'].encode();returned=verify_site('returned82',site,'8.2.35');assert returned['FPM']==initial['FPM']and returned['manifest']==initial['manifest']and ordinary_raw(cfg)==original_cfg+comment and check_custom('returned82',site)==initial_custom
 after_files=tree_of(protected_paths);save('protected-after.json',after_files);assert original_files==after_files;assert set(str(v)for v in pathlib.Path('/etc/panel/sites-enabled').iterdir()if v.name.endswith('.conf'))==set(original_confs)|{str(cfg)}
 after_nss=nss();save('original-nss-after.json',after_nss);after_kernel=kernel_rules();save('original-kernel-after.json',after_kernel);assert after_kernel==original_kernel
 for name,v in original_nss.items():
  assert all(after_nss[name]['entries'][key]==value for key,value in v['entries'].items())
  for key in('mode','uid','gid'):assert after_nss[name][key]==v[key]
 api('/logout',{});csrf='';after=snapshot();save('after.json',after);assert before['schema']==after['schema']and before['lifetimes']==after['lifetimes'];guard('final')
 proof.update(ok=True,actual_HTTP_multipart_and_CLI_versions_extensions_UID_primaryGID_and_startup_guard=True,custom_guard_and_static_cache_and_header_preserved=True,only_exact_owned_socket_and_health_values_change=True,exact_config_roundtrip_plus_explicit_comment_and_FPM_pool_manifest_roundtrip=True,stale_SHA_failed_original_preserved_without_side_effects=True,fresh_separate_return_after_verified_original_refusal=True,all_original_protected_files_and_five_lifetimes_preserved=True,full113_snapshots_retained_for_independent_qualification=True,normal_own_logout=True)
except BaseException:save('original-failure.json',{'traceback':traceback.format_exc()})
finally:
 if csrf:
  try:api('/logout',{});csrf=''
  except BaseException:save('logout-failure.json',{'traceback':traceback.format_exc()})
 save('http-events.json',http_events);save('proof.json',proof);print(json.dumps({'ok':proof['ok'],'base':str(base),'proof_sha256':sha(evidence/'proof.json'),'source_inputs_sha256':SOURCE,'architecture':arch,'Main_changed':False,'all50_commercial':False}),flush=True)
sys.exit(0 if proof['ok']else 1)
