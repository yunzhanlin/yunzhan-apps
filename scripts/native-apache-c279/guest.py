"""Once-only signed Apache/WAF runtime upgrade in a fresh owned Linux guest."""
from pathlib import Path
import ast,contextlib,copy,hashlib,http.cookiejar,json,os,platform,pwd,re,runpy,secrets,sqlite3,stat,subprocess,sys,time,traceback,types,urllib.error,urllib.request
os.umask(0o077)
assert os.geteuid()==0 and len(sys.argv)in(2,3,4)
payload=Path(sys.argv[1]).resolve(strict=True);pins=json.loads((payload/'assets.json').read_bytes());arch={'x86_64':'amd64','aarch64':'arm64'}[platform.machine()];assert pins['architecture']==arch
case=pins['OS_case'];assert Path('/etc/hostname').read_text().strip()==case['hostname']and case['hostname'].startswith('c279-apache-')
osinfo=dict(line.split('=',1)for line in Path('/etc/os-release').read_text().splitlines()if'='in line and not line.startswith('#'))
assert osinfo['ID'].strip('"')==case['distribution']and osinfo['VERSION_ID'].strip('"')==case['version_id']
base=Path(sys.argv[2]).resolve(strict=True)if len(sys.argv)>=3 else Path('/opt/panel-apache-c279-qa-'+secrets.token_hex(16));assert base.parent==Path('/opt')and re.fullmatch('panel-apache-c279-qa-[a-f0-9]{32}',base.name)
evidence=base/'evidence'
if len(sys.argv)==2:evidence.mkdir(mode=0o700,parents=True)
assert base.stat().st_uid==evidence.stat().st_uid==0 and stat.S_IMODE(evidence.stat().st_mode)==0o700
oldsource='7fcf5fe021cefe421ecf1da4c8ac1c5c81e95b075416dbb79dbd11dc92d00830';target='eef9d1e3c4b96390c77a8ea9f121a67986a152a60149acd026246d71e601a481';assert pins['source_inputs_sha256']==target
origin='http://127.0.0.1:19100';csrf='';events=[];secret=secrets.token_hex(32)
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*a,**k):raise AssertionError('unexpected redirect')
client=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect(),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
def sha(path):
 h=hashlib.sha256()
 with Path(path).open('rb')as f:
  for chunk in iter(lambda:f.read(65536),b''):h.update(chunk)
 return h.hexdigest()
def save(name,value):
 assert re.fullmatch('[A-Za-z0-9._-]+',name)
 with(evidence/name).open('x')as f:json.dump(value,f,sort_keys=True,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
def command(args,timeout=30):
 r=subprocess.run(args,capture_output=True,text=True,timeout=timeout);assert r.returncode==0,(args[0],r.returncode,r.stderr[-1400:]);assert len(r.stdout)<4<<20;return r.stdout
def unit(name):return dict(v.split('=',1)for v in command(['systemctl','show',name,'--property=LoadState,MainPID,InvocationID,ActiveState,SubState,UnitFileState']).splitlines())
def api(label,path,body=None,expected=200,key=None):
 headers={'Origin':origin,'Content-Type':'application/json','X-CSRF-Token':csrf}
 if key:headers['Idempotency-Key']=key
 if body is not None:save(label+'-intent.json',{'path':path,'body':{'private_login_redacted':True}if path=='/login'else body,'key':key,'maximum_submissions':1})
 req=urllib.request.Request(origin+'/api'+path,None if body is None else json.dumps(body,separators=(',',':')).encode(),headers)
 try:
  with client.open(req,timeout=90)as res:status=res.status;raw=res.read((8<<20)+1)
 except urllib.error.HTTPError as e:status=e.code;raw=e.read((8<<20)+1)
 assert len(raw)<=8<<20;answer=json.loads(raw);save(label+'-response.json',{'status':status,'value':{'csrf_issued':bool(answer.get('csrf'))}if path=='/login'else answer});events.append({'path':path,'status':status,'method':'GET'if body is None else'POST'})
 assert status==expected,(path,status,answer);return answer
def login(label):
 global csrf
 credentials=json.loads(Path('/etc/panel/first-login.json').read_bytes())
 try:csrf=api(label,'/login',{k:credentials[k]for k in('username','password')})['csrf']
 finally:credentials.clear()
def wait_job(label,job,table):
 assert re.fullmatch('[a-f0-9]{32}',job)and table in('jobs','runtime_jobs');end=time.monotonic()+5*3600;observations=[]
 while time.monotonic()<end:
  value=api(label+'-poll-'+str(len(observations)),'/jobs/'+job);observations.append({'state':value['state'],'at':time.time()})
  if value['state']not in('queued','running'):
   save(label+'-terminal.json',value);assert value['state']=='succeeded'and not value['error'],(label,value['state'],value['error']);return value
  time.sleep(3)
 raise TimeoutError('original job unresolved, no replay')
def job(label,path,body,table='runtime_jobs'):
 reply=api(label,path,body,202,secrets.token_hex(16));return wait_job(label,reply['job_id'],table)
def run_once(label,args,timeout=1800):
 save(label+'-intent.json',{'args':args,'maximum_submissions':1})
 with(evidence/(label+'.stdout')).open('xb')as out,(evidence/(label+'.stderr')).open('xb')as err:r=subprocess.run(args,stdin=subprocess.DEVNULL,stdout=out,stderr=err,timeout=timeout)
 save(label+'-exit.json',{'exit':r.returncode});assert r.returncode==0,(label,(evidence/(label+'.stderr')).read_text(errors='replace')[-1500:])
def ready():
 for _ in range(90):
  try:
   with urllib.request.urlopen(origin+'/api/ready',timeout=3)as r:
    if r.status==200:return
  except Exception:pass
  time.sleep(1)
 raise TimeoutError('panel not ready')
def current_source():return json.loads(Path('/opt/panel/current/SOURCE_INPUTS.json').read_bytes())['inputs_sha256']
def record_witness(path):
 path=Path(path);fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  before=os.fstat(fd);assert stat.S_ISREG(before.st_mode)and before.st_uid==0 and before.st_nlink==1 and stat.S_IMODE(before.st_mode)==0o600 and before.st_size<16<<20
  with os.fdopen(fd,'rb',closefd=False)as f:raw=f.read((16<<20)+1)
  after=os.fstat(fd);assert(before.st_ino,before.st_dev,before.st_size,before.st_mtime_ns)==(after.st_ino,after.st_dev,after.st_size,after.st_mtime_ns)
 finally:os.close(fd)
 return {'uid':before.st_uid,'gid':before.st_gid,'mode':stat.S_IMODE(before.st_mode),'inode':before.st_ino,'dev':before.st_dev,'links':before.st_nlink,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
def original_history_row(label,identity):
 assert re.fullmatch('[a-f0-9]{32}',identity)
 for offset in range(0,613,32):
  page=api(label+'-page-'+str(offset),'/software/apache-waf/transactions?limit=32&offset='+str(offset));assert page['records_retained']and not page['configuration_changed']and not page['pending']and 0<page['total']<=612
  found=[row for row in page['apache_transactions']if row['transaction_id']==identity]
  if found:assert len(found)==1 and found[0]['transaction_state']=='committed';return found[0]
  if offset+32>=page['total']:break
 raise AssertionError('Original runtime transition missing from complete authenticated history')
def protected_snapshot():
 paths={}
 def walk(p):
  s=p.lstat();v={'uid':s.st_uid,'gid':s.st_gid,'mode':stat.S_IMODE(s.st_mode),'inode':s.st_ino,'dev':s.st_dev,'links':s.st_nlink}
  if stat.S_ISREG(s.st_mode):assert s.st_size<128<<20;v.update(bytes=s.st_size,sha256=sha(p))
  elif stat.S_ISLNK(s.st_mode):v['target']=os.readlink(p)
  else:assert stat.S_ISDIR(s.st_mode)
  paths[str(p)]=v;assert len(paths)<50000
  if stat.S_ISDIR(s.st_mode):
   for child in sorted(p.iterdir()):walk(child)
 for name in('/srv/panel/sites','/opt/panel/runtimes','/opt/panel/app-modules','/etc/panel/php-sites'):
  if Path(name).exists():walk(Path(name))
 with contextlib.closing(sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True))as db:
  db.execute('PRAGMA query_only=ON');rows={n:[[{'blob_hex':v.hex()}if isinstance(v,bytes)else v for v in row]for row in db.execute('SELECT *FROM '+n+' ORDER BY 1')]for n in('sites','users','app_user_roles','app_user_menus','runtime_installations')}
 return {'files':paths,'rows':rows,'NSS':{n:sha('/etc/'+n)for n in('passwd','group','shadow','gshadow')},'Apache':unit('panel-apache.service')}
def actual_apache(version):
 u=unit('panel-apache.service');assert u['ActiveState']=='active'and int(u['MainPID'])>1
 binary=os.readlink('/proc/'+u['MainPID']+'/exe');assert binary=='/opt/panel/runtimes/apache/'+version+'/bin/httpd';return u
phase='prepare'if len(sys.argv)==2 else'after-browser'if len(sys.argv)==4 and sys.argv[3]=='after-browser'else'cold'
for name,digest in pins['files'].items():assert sha(payload/name)==digest,name
proof={'ok':False,'base':str(base),'architecture':arch,'source_inputs_sha256':target,'phase':phase,'Main_changed':False,'all40_commercial':False,'powerloss_ready':False,'boot':Path('/proc/sys/kernel/random/boot_id').read_text().strip()}
def web_checks(sites,label):
 values=[]
 for site in sites:
  for suffix,status,body in [('/ui-original',200,site['body']),('/ui-proof.txt',200,site['body']),('/.hidden-ui',403,None),('/ui-link.txt',403,None)]:
   conn=__import__('http.client',fromlist=['HTTPConnection']).HTTPConnection('127.0.0.1',19080,timeout=5)
   try:
    conn.request('GET',suffix,headers={'Host':site['domain'],'User-Agent':'Yunzhan-owned-UI-acceptance'});r=conn.getresponse();raw=r.read(65537);assert len(raw)<=65536 and r.status==status,(label,suffix,r.status)
    if body is not None:assert raw==body.encode()
    values.append({'site':site['id'],'path':suffix,'status':r.status,'sha256':hashlib.sha256(raw).hexdigest()})
   finally:conn.close()
 save(label+'-real-static-rewrite-hidden-and-no-follow-responses.json',values);return values
def static_sites():
 values=[]
 for i in range(2):
  nonce=secrets.token_hex(8);domain='c279-ui-'+str(i)+'-'+nonce+'.example.test';id=job('old-static-site-'+str(i),'/sites',{'name':'Owned Apache UI acceptance '+str(i),'slug':'c279-ui-'+nonce,'domain':domain,'php_version_id':''},'jobs')['site_id'];cur=api('old-static-settings-'+str(i),'/sites/'+id+'/settings');draft=copy.deepcopy(cur['settings']);draft.update(web_server='apache',rewrite='custom',rules=[{'pattern':'^/ui-original$','replacement':'/ui-proof.txt','flag':'last'}]);preview=api('old-static-preview-'+str(i),'/sites/'+id+'/settings/preview',{'settings':draft,'expected_revision':cur['settings_revision']});job('old-static-bind-'+str(i),'/sites/'+id+'/settings',{'settings':draft,'expected_revision':cur['settings_revision'],'expected_config_sha':preview['config_sha']},'jobs')
  doc=Path('/srv/panel/sites')/id/'public';owner=doc.stat();body='Owned Apache UI '+nonce+'\n'
  for name in ['ui-proof.txt','.hidden-ui']:
   with os.fdopen(os.open(doc/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o644),'wb')as f:os.fchown(f.fileno(),owner.st_uid,owner.st_gid);f.write(body.encode());f.flush();os.fsync(f.fileno())
  os.symlink('ui-proof.txt',doc/'ui-link.txt');values.append({'id':id,'domain':domain,'body':body})
 return values
try:
 if phase=='prepare':
  assert not any(os.path.lexists(n)for n in('/opt/panel','/var/lib/panel','/etc/panel'));verified=base/'verified-input';verified.mkdir(mode=0o700)
  for name,digest in pins['files'].items():
   f=payload/name;st=f.lstat();assert stat.S_ISREG(st.st_mode)and st.st_nlink==1 and 0<st.st_size<=64<<20 and sha(f)==digest;(verified/name).open('xb').write(f.read_bytes())
  payload=verified;assert sha(payload/'signed-release.py')=='fe128e82b4e11345b320cd782134768bfe1a4df14947c425d7494873a7a7b7b5'and sha(payload/'release-signing-dev.pub')=='4ccfcc861d56a41e3ba7f7ace7e2432c815f366c58448d783df92c6632f01339'
  signer=[sys.executable,'-I','-B',str(payload/'signed-release.py')];key=['--public-key',str(payload/'release-signing-dev.pub')];old=payload/('panel-'+pins['previous_version']+'-linux-'+arch+'.tar.gz');new=payload/('panel-'+pins['version']+'-linux-'+arch+'.tar.gz')
  run_once('old-normal-signed-install',signer+['install',str(old)]+key,1800);ready();assert current_source()==oldsource;login('old-login');job('old-reviewed-Apache68-install','/runtimes/install',{'release_id':'apache-2.4.68'});sites=static_sites();web_checks(sites,'old68')
  job('old-built-in-WAF230','/software/apache-waf/install',{});cat=api('old-WAF251-catalogue','/app-registry?refresh=1');assert cat['source']['resolved_commit']==pins['served_head']and not cat['source']['stale'];waf=next(x for x in cat['catalog']['apps']if x['id']=='apache-waf');assert waf['version']=='2.5.1';job('old-reviewed-WAF251-update','/app-registry/apache-waf/update',{'expected_version':waf['version'],'expected_sha256':waf['sha256']})
  before=protected_snapshot();waf_before=api('old-current-WAF','/software/apache-waf/config');assert waf_before['status']['healthy'];save('original-before-programme-upgrade.json',before);api('old-logout','/logout',{});csrf='';run_once('old-complete-queue-guard',['/opt/panel/current/bin/panel-executor','--check-program-upgrade-queues'],120)
  run_once('new-normal-signed-programme-upgrade',signer+['install',str(new)]+key,1800);ready();assert current_source()==target and protected_snapshot()==before
  with(base/'ui-intent.json').open('x')as f:json.dump({'sites':sites,'before':before,'waf_settings':waf_before['settings'],'boot':proof['boot']},f,sort_keys=True);f.flush();os.fsync(f.fileno())
  proof.update(ok=True,ui_prepared=True,normal_signed_programmes=2,original_sites_files_NSS_and_Apache_PID_preserved=True)
 elif phase=='after-browser':
  assert current_source()==target;intent=json.loads((base/'ui-intent.json').read_bytes());sites=intent['sites'];assert proof['boot']==intent['boot'];actual=actual_apache('2.4.71');assert actual['InvocationID']!=intent['before']['Apache']['InvocationID']
  with contextlib.closing(sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True))as db:
   db.execute('PRAGMA query_only=ON');rows=db.execute("SELECT id,idempotency_key,payload,state FROM runtime_jobs WHERE kind='switch_apache'").fetchall();assert len(rows)==1;identity,nonce,payload_json,state=rows[0];assert re.fullmatch('[a-f0-9]{32}',nonce)and state=='succeeded';dispatch=json.loads(payload_json);assert dispatch['job_id']==identity and dispatch['release_id']=='apache-2.4.71'and dispatch['engine_job_id']==''
   receipt=db.execute("SELECT version,sha256 FROM app_registry_receipts WHERE app_id='apache'AND scope='apache-2.4.71'").fetchall();assert receipt==[('2.4.71-compat1','aadc8489fe1e4e9bb40310bafdba7a8385fd11aabe7dd97758c17b45ba98ff53')]
  after=protected_snapshot();assert after['rows']['sites']==intent['before']['rows']['sites']and after['NSS']==intent['before']['NSS']
  for path,value in intent['before']['files'].items():
   if path=='/opt/panel/runtimes/apache':assert all(value[k]==after['files'][path][k]for k in value if k!='links')and after['files'][path]['links']==value['links']+1
   else:assert after['files'].get(path)==value,path
  login('after-browser-login');status=api('after-browser-runtime','/runtimes/apache');assert status['selected_id']==status['running_id']=='apache-2.4.71'and not status['activation_needed']and not status['native_engine_required'];current=api('after-browser-WAF','/software/apache-waf/config');settings=copy.deepcopy(intent['waf_settings']);settings['policy']['revision']+=1;assert current['status']['healthy']and current['settings']==settings
  responses=web_checks(sites,'new71');op=Path('/var/lib/panel-executor/apache-runtime-switches')/(identity+'.json');op_data=json.loads(op.read_bytes());assert op_data['state']=='committed';tx=op_data['transaction_id'];transaction=Path('/etc/panel/security-apps/modules/apache-waf/config-transactions')/(tx+'.json');records={str(p):record_witness(p)for p in [op,transaction]}
  for label,p in [('operation',op),('transaction',transaction)]:
   (evidence/('original-Root-'+label+'-raw.json')).open('xb').write(p.read_bytes())
  history=original_history_row('after-browser-original-history',tx);cold={'boot':proof['boot'],'source':target,'sites':sites,'settings':current['settings'],'protected':protected_snapshot(),'records':records,'transaction_id':tx,'history':history,'original_UI_job':identity,'original_UI_key':nonce}
  save('original-cold-intent-witness.json',cold)
  with(base/'cold-intent.json').open('x')as f:json.dump(cold,f,sort_keys=True);f.flush();os.fsync(f.fileno())
  fd=os.open(base,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
  api('after-browser-logout','/logout',{});csrf='';proof.update(ok=True,powerloss_ready=True,actual_browser_store_update_and_runtime_switch=True,actual_32_hex_UI_nonce=True,original_UI_job=identity,old_sites_files_and_NSS_preserved=True,actual_new_rewrite_and_no_follow_responses=len(responses),original_committed_history_readable=True)
 else:
  assert current_source()==target;intent=json.loads((base/'cold-intent.json').read_bytes());assert intent['boot']!=proof['boot'];actual_apache('2.4.71');after=protected_snapshot();assert after['files']==intent['protected']['files']and after['rows']==intent['protected']['rows']and after['NSS']==intent['protected']['NSS']
  for path,witness in intent['records'].items():assert record_witness(path)==witness,path
  login('cold-login');status=api('cold-runtime','/runtimes/apache');assert status['selected_id']==status['running_id']=='apache-2.4.71'and not status['activation_needed'];waf=api('cold-WAF','/software/apache-waf/config');assert waf['status']['healthy']and waf['settings']==intent['settings'];assert original_history_row('cold-original-history',intent['transaction_id'])==intent['history'];responses=web_checks(intent['sites'],'cold71');api('cold-logout','/logout',{});csrf='';proof.update(ok=True,prior_boot=intent['boot'],actual_real_kernel_and_service_reboot=True,current_Apache_271_and_WAF_healthy=True,old_records_and_Root_private_archives_preserved=True,original_runtime_history_readable_after_cold=True,original_history_bytes_UID_GID_and_inode_preserved=True,original_sites_files_NSS_and_rewrite_no_follow_preserved=True,actual_cold_site_responses=len(responses),original_UI_job=intent['original_UI_job'])
except BaseException:save('original-failure-'+secrets.token_hex(4)+'.json',{'traceback':traceback.format_exc()})
finally:
 if csrf:
  try:api('failure-owned-session-logout','/logout',{});csrf=''
  except BaseException:proof['ok']=False
 save('proof-'+phase+'.json',proof);save('HTTP-events-'+phase+'.json',events);print(json.dumps(proof),flush=True)
sys.exit(0 if proof['ok']else 1)
