from pathlib import Path
import http.client,contextlib,hashlib,http.cookiejar,json,os,re,secrets,sqlite3,stat,subprocess,sys,time,traceback,urllib.request,urllib.error
os.umask(0o077);payload=Path(sys.argv[1]);plan=json.loads((payload/'plan.json').read_bytes());assert os.geteuid()==0 and os.uname().machine in('aarch64','x86_64');assert Path('/etc/hostname').read_text().strip()==plan['host']and hashlib.sha256(Path('/etc/machine-id').read_bytes()).hexdigest()==plan['machine'];old=Path('/opt/panel/current').resolve(strict=True);assert json.loads((old/'SOURCE_INPUTS.json').read_bytes())['inputs_sha256']==plan['source'];base=Path('/var/lib/panel-executor')/('c512-PHP82-83-site-switch-'+secrets.token_hex(16));base.mkdir(mode=0o700);evidence=base/'evidence';evidence.mkdir(mode=0o700)
def sha(p):
 h=hashlib.sha256()
 with Path(p).open('rb')as f:
  for b in iter(lambda:f.read(1<<20),b''):h.update(b)
 return h.hexdigest()
def save(n,v):
 with(evidence/n).open('x')as f:json.dump(v,f,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
def rows():
 with contextlib.closing(sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True))as db:
  db.execute('PRAGMA query_only=ON');assert db.execute('PRAGMA quick_check').fetchone()==('ok',);out={}
  for t in('runtime_jobs','runtime_installations','app_registry_install_requests','app_registry_receipts','sites'):
   c=[r[1]for r in db.execute('PRAGMA table_info('+t+')')];out[t]={'columns':c,'rows':db.execute('SELECT *FROM '+t+' ORDER BY 1').fetchall()}
  return json.loads(json.dumps(out))
def snapshot():
 out={};roots=[old,Path('/etc/panel/security-apps/modules/apache-waf'),Path('/srv/panel/sites'),Path('/opt/panel/runtimes'),Path('/opt/panel/app-modules/apache-waf/engines'),Path('/var/lib/panel-executor/apache-body-builds'),Path('/var/lib/panel-apache-body/cc-archives'),Path('/var/lib/panel-apache-body/cc-archive-history')];paths=[Path('/etc/panel/first-login.json'),Path('/etc/panel/apache/httpd.conf'),Path('/etc/panel/apache/waf.conf'),Path('/etc/panel/security-apps/modules/apache-waf/installed.json')]
 for root in roots:
  if root.exists():
   assert root.is_dir()and not root.is_symlink();paths.extend(root.rglob('*'))
 for p in paths:
  if not os.path.lexists(p):continue
  st=p.lstat();v={'mode':stat.S_IMODE(st.st_mode),'uid':st.st_uid,'gid':st.st_gid,'dev':st.st_dev,'inode':st.st_ino,'links':st.st_nlink}
  if stat.S_ISLNK(st.st_mode):v['link']=os.readlink(p)
  elif stat.S_ISREG(st.st_mode):v.update(bytes=st.st_size,sha256=sha(p))
  elif stat.S_ISDIR(st.st_mode):continue
  else:raise AssertionError('Unexpected original special file '+str(p))
  out[str(p)]=v;assert len(out)<40000
 return out
def process():
 r=subprocess.run(['systemctl','show','panel-apache','-p','MainPID,InvocationID,ActiveState,LoadState'],capture_output=True,text=True,timeout=15);v=dict(l.split('=',1)for l in r.stdout.splitlines());assert r.returncode==0 or(v.get('LoadState')=='not-found'and v.get('MainPID')=='0');v['exe']=os.readlink('/proc/'+v['MainPID']+'/exe')if int(v['MainPID'])>1 else None;return v
proof={'ok':False,'base':str(base),'scope':'One new owned PHP82 site, ordinary previewed switch to PHP83 and back82, actual HTTP/FPM/extension/session/body and custom configuration preservation. Original sites, runtimes, Root WAF copies and failed verdicts preserved. No Main changes.','original_operation_replays':0,'all40_commercial':False};csrf=''
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*a,**kw):raise AssertionError('Unexpected redirect refused')
origin='http://127.0.0.1:19100';opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect(),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
def api(label,path,body=None,expected=(200,),key=None):
 raw=None if body is None else json.dumps(body).encode();headers={'Origin':origin,'Content-Type':'application/json','X-CSRF-Token':csrf}
 if key:headers['Idempotency-Key']=key
 if body is not None:save(label+'-intent.json',{'path':path,'maximum_submissions':1,'body':'private-redacted'if path=='/login'else body})
 try:
  with opener.open(urllib.request.Request(origin+'/api'+path,raw,headers),timeout=80)as r:status=r.status;data=r.read((8<<20)+1)
 except urllib.error.HTTPError as r:status=r.code;data=r.read((8<<20)+1)
 assert len(data)<=8<<20;v=json.loads(data)
 if path!='/login':save(label+'-response.json',{'status':status,'value':v})
 assert status in expected,(path,status,v.get('error'));return v
counter=0
def call(label,path,body=None,expected=(200,),key=None):
 global counter
 counter+=1;return api('%04d-'%counter+label,path,body,expected,key)
def job(label,path,body,want='succeeded'):
 v=call(label,path,body,(202,),secrets.token_hex(16));identity=v['job_id'];assert re.fullmatch('[a-f0-9]{32}',identity)
 for n in range(600):
  v=call(label+'-original-poll','/jobs/'+identity)
  if v['state']not in('queued','running'):assert v['state']==want,(label,v);return v
  time.sleep(1)
 raise TimeoutError('Original site job unresolved, never requeued')
def filemeta(p):
 st=p.lstat();assert stat.S_ISREG(st.st_mode)and st.st_nlink==1;return {'dev':st.st_dev,'inode':st.st_ino,'uid':st.st_uid,'gid':st.st_gid,'mode':stat.S_IMODE(st.st_mode),'bytes':st.st_size,'sha256':sha(p)}
def jobcount():
 with contextlib.closing(sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True))as db:return db.execute('SELECT count(*)FROM jobs').fetchone()[0]
cookie='';http_count=0;session_id=''
try:
 for _ in range(100):
  try:
   with opener.open(origin+'/api/ready',timeout=2)as r:
    if r.status==200:break
  except Exception:pass
  time.sleep(1)
 else:raise TimeoutError('Core readiness unresolved before login or site operation')
 assert Path('/opt/panel/runtimes/php/8.3.36/bin/php').is_file()
 access=json.loads(Path('/etc/panel/first-login.json').read_bytes());csrf=call('login','/login',{k:access[k]for k in('username','password')})['csrf'];access.clear();call('prebaseline-store-materialization','/app-registry?refresh=1')
 before_rows=rows();before_files=snapshot();before_process=process();save('original-SQL-before.json',before_rows);save('original-files-before.json',before_files);save('original-Apache-before.json',before_process)
 nonce=secrets.token_hex(16);slug='c512-'+secrets.token_hex(6);domain=slug+'.example.test';created=job('new-owned-PHP82-site','/sites',{'name':'C512 PHP8 site switch','slug':slug,'domain':domain,'php_version_id':'php-8.2.35'});site=created['site_id'];assert re.fullmatch('[a-f0-9]{32}',site)
 public=Path('/srv/panel/sites')/site/'public';index=public/'index.html';index_before=filemeta(index);php='switch-'+nonce+'.php'
 code='<?php header("Content-Type: application/json"); session_start(); $_SESSION["c512"] = ($_SESSION["c512"] ?? 0)+1; echo json_encode(["marker"=>"'+nonce+'","php"=>PHP_VERSION,"pid"=>getmypid(),"session"=>session_id(),"count"=>$_SESSION["c512"],"method"=>$_SERVER["REQUEST_METHOD"],"query"=>$_GET["keep"]??null,"body_sha256"=>hash("sha256",file_get_contents("php://input")),"extensions"=>array_map("strtolower",get_loaded_extensions()),"pdo_drivers"=>PDO::getAvailableDrivers(),"mysql_client"=>mysqli_get_client_info(),"sqlite"=>(new PDO("sqlite::memory:"))->query("SELECT 42")->fetchColumn()]);'
 call('new-owned-PHP-script','/sites/'+site+'/files/action',{'action':'create','path':php,'content':code});script_before=filemeta(public/php)
 config=Path('/etc/panel/sites-enabled')/(site+'.conf');text=config.read_text();assert text.startswith('# managed by panel; site='+site)and text.count('server {')==1
 # Only this new QA site's operator-owned config is extended, without editing
 # original sites or protected data. Ordinary PHP-switch must preserve it.
 custom='  location = /c512-config-probe { return 200 "'+nonce+'"; }\n';text=text.replace('server {','server {\n'+custom,1);fd=os.open(config,os.O_WRONLY|os.O_TRUNC|os.O_NOFOLLOW)
 with os.fdopen(fd,'wb')as f:f.write(text.encode());f.flush();os.fsync(f.fileno())
 save('owned-custom-config-before.json',{'sha256':sha(config),'text':text})
 def traffic(label,version):
  global cookie,http_count,session_id
  for n in range(4):
   body=('C512 ordinary POST '+str(http_count)+' '+nonce).encode();conn=http.client.HTTPConnection('127.0.0.1',19101,timeout=15)
   try:
    headers={'Host':domain,'Content-Type':'application/octet-stream'}
    if cookie:headers['Cookie']=cookie
    conn.request('POST','/'+php+'?keep=query-'+str(http_count),body=body,headers=headers);r=conn.getresponse();raw=r.read((1<<20)+1);assert r.status==200 and len(raw)<=1<<20,(label,r.status,raw[:300]);v=json.loads(raw);set_cookie=r.getheader('Set-Cookie')
    if set_cookie:cookie=set_cookie.split(';',1)[0]
   finally:conn.close()
   assert v['marker']==nonce and v['php']==version and v['method']=='POST'and v['query']=='query-'+str(http_count)and v['body_sha256']==hashlib.sha256(body).hexdigest();assert all(x in v['extensions']for x in('pdo','pdo_mysql','mysqli','mysqlnd','openssl','curl','mbstring','dom','json','session','pdo_sqlite'));assert 'mysql'in v['pdo_drivers']and 'sqlite'in v['pdo_drivers']and v['mysql_client']=='mysqlnd '+version and int(v['sqlite'])==42
   http_count+=1;assert v['count']==http_count
   if not session_id:session_id=v['session']
   assert v['session']==session_id and len(session_id)>5
   status=Path('/proc/'+str(v['pid'])+'/status').read_text();uid=[int(x)for x in next(x for x in status.splitlines()if x.startswith('Uid:')).split()[1:]];assert len(uid)==4 and all(x>0 for x in uid);exe=os.readlink('/proc/'+str(v['pid'])+'/exe');assert exe=='/opt/panel/runtimes/php/'+version+'/sbin/php-fpm';save(label+'-HTTP-'+str(n)+'.json',{'response':v,'actual_FPM_Uids':uid,'actual_FPM_exe':exe})
 traffic('initial82','8.2.35');switches=[]
 for release,version in [('php-8.3.36','8.3.36'),('php-8.2.35','8.2.35')]:
  prior_config=config.read_bytes();prior_count=jobcount();preview=call('readonly-preview-'+release,'/sites/'+site+'/php/preview',{'release_id':release});assert preview['protocol']=='php-vhost-switch-v1'and preview['site_id']==site and preview['release_id']==release and preview['preserves_custom_config'];assert preview['config_sha']==hashlib.sha256(prior_config).hexdigest()and preview['current'].encode()==prior_config and custom in preview['candidate'];assert jobcount()==prior_count and config.read_bytes()==prior_config
  result=job('owned-switch-'+release,'/sites/'+site+'/php',{'release_id':release,'expected_config_sha':preview['config_sha']});assert config.read_text()==preview['candidate'];current=call('actual-site-'+release,'/sites/'+site+'/settings');assert current['php_version_id']==release and current['status']=='running';traffic('actual-'+release,version)
  conn=http.client.HTTPConnection('127.0.0.1',19101,timeout=15)
  try:conn.request('GET','/c512-config-probe',headers={'Host':domain});r=conn.getresponse();assert r.status==200 and r.read()==nonce.encode()
  finally:conn.close()
  switches.append({'release_id':release,'job_id':result['id'],'actual_version':version})
 # Malformed CAS is rejected before queueing; no original failed operation is
 # replayed, and no deliberately stale accepted job alters the site state.
 before_count=jobcount();before_config=filemeta(config);call('invalid-config-digest-refused','/sites/'+site+'/php',{'release_id':'php-8.3.36','expected_config_sha':'invalid-digest'},(409,),secrets.token_hex(16));assert jobcount()==before_count and filemeta(config)==before_config
 after_rows=rows();after_files=snapshot();save('original-SQL-after.json',after_rows);save('original-files-after.json',after_files)
 for t,prior in before_rows.items():
  current=after_rows[t];indices=[current['columns'].index(c)for c in prior['columns']];projected=[[r[i]for i in indices]for r in current['rows']];assert all(r in projected for r in prior['rows']),t
 assert all(after_files.get(k)==v for k,v in before_files.items())and before_process==process()and index_before==filemeta(index)and script_before==filemeta(public/php)
 proof.update(ok=True,source_inputs_sha256=plan['source'],architecture={'aarch64':'arm64','x86_64':'amd64'}[os.uname().machine],boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip(),site_id=site,site_domain=domain,normal_site_creates=1,normal_site_switches=switches,actual_POST_PHP_requests=http_count,actual_nonRoot_FPM=True,actual_mysqlnd_and_PDO_extensions=True,actual_session_continuity_82_83_82=True,custom_Nginx_location_preserved_and_served=True,invalid_CAS_rejected_before_queue=True,original_preserved_files=len(before_files),original_selected_SQL_rows_preserved=True,original_Apache_process_unchanged=True,MySQL_server_query_claim=False)
except BaseException:
 proof['failure']=traceback.format_exc()[-7000:]
finally:
 if csrf:
  try:call('logout','/logout',{})
  except BaseException:proof['ok']=False;proof['logout_failure']=True
 save('original-proof.json',proof);print(json.dumps(proof),flush=True)
sys.exit(0 if proof['ok']else 1)
