from pathlib import Path
import copy,hashlib,http.client,http.cookiejar,json,os,re,secrets,sqlite3,stat,subprocess,sys,time,urllib.request,urllib.error
os.umask(0o077);base=Path(sys.argv[1]);evidence=base/'evidence'/'business-evidence';evidence.mkdir(mode=0o700);source='00b06c3f1793b60fc41e50256d99fc2211a2a4899d11390ac059434816e6e01a';assert json.loads(Path('/opt/panel/current/SOURCE_INPUTS.json').read_bytes())['inputs_sha256']==source;origin='http://127.0.0.1:19100';csrf='';counter=0
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*a,**k):raise AssertionError('Redirect refused')
client=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect(),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
def save(n,v):
 with(evidence/n).open('x')as f:json.dump(v,f,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
def api(label,path,body=None,expected=(200,),key=None):
 global counter
 name='%04d-'%counter+label;counter+=1;raw=None if body is None else json.dumps(body,separators=(',',':')).encode();headers={'Origin':origin,'Content-Type':'application/json','X-CSRF-Token':csrf}
 if key:headers['Idempotency-Key']=key
 if raw is not None:save(name+'-intent.json',{'path':path,'body':{'private':True}if path=='/login'else body,'maximum_submissions':1,'key':key})
 try:
  with client.open(urllib.request.Request(origin+'/api'+path,raw,headers),timeout=100)as r:status=r.status;v=json.load(r)
 except urllib.error.HTTPError as r:status=r.code;v=json.load(r)
 save(name+'-response.json',{'status':status,'value':{'private_login_redacted':True}if path=='/login'else v});assert status in expected,(path,status,v.get('error'));return v

def job(label,path,body):
 v=api(label,path,body,(202,),secrets.token_hex(16));identity=v['job_id'];assert re.fullmatch('[a-f0-9]{32}',identity)
 for _ in range(600):
  v=api(label+'-original-readonly-poll','/jobs/'+identity)
  if v['state']not in('queued','running'):assert v['state']=='succeeded',(label,v);return v
  time.sleep(1)
 raise TimeoutError('Original job unresolved; no replay')
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def meta(p):
 s=Path(p).lstat();assert stat.S_ISREG(s.st_mode)and s.st_nlink==1;return {'dev':s.st_dev,'inode':s.st_ino,'uid':s.st_uid,'gid':s.st_gid,'mode':stat.S_IMODE(s.st_mode),'bytes':s.st_size,'sha256':sha(p)}
def rows():
 with sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True)as db:
  db.execute('PRAGMA query_only=ON');return {t:db.execute('SELECT *FROM '+t+' ORDER BY 1').fetchall()for t in('runtime_jobs','app_registry_receipts','app_registry_install_requests','sites')}
def command(label,args):
 r=subprocess.run(args,capture_output=True,timeout=30);save(label+'.json',{'args':args,'exit':r.returncode,'stdout':r.stdout.decode(errors='replace'),'stderr':r.stderr.decode(errors='replace')});assert r.returncode==0;return r.stdout.decode()
credentials=json.loads(Path('/etc/panel/first-login.json').read_bytes());csrf=api('login','/login',{k:credentials[k]for k in('username','password')})['csrf'];credentials.clear();prior=rows();save('original-business-rows-before.json',prior)
slug='c407-'+secrets.token_hex(6);domain=slug+'.example.test';created=job('new-owned-PHP-site','/sites',{'name':'C407 Apache native PHP business','slug':slug,'domain':domain,'php_version_id':'php-8.2.35'});site=created['site_id'];assert re.fullmatch('[a-f0-9]{32}',site);public=Path('/srv/panel/sites')/site/'public';index=public/'index.html';before_index=meta(index);nonce=secrets.token_hex(16);php='owned-'+nonce+'.php';sentinel='owned symlink restricted '+nonce;plain='ordinary-'+nonce+'.txt'
code='<?php header("Content-Type: application/json"); echo json_encode(["marker"=>"'+nonce+'","php"=>PHP_VERSION,"id"=>$_GET["id"]??null,"keep"=>$_GET["keep"]??null,"method"=>$_SERVER["REQUEST_METHOD"],"body_sha256"=>hash("sha256",file_get_contents("php://input")),"pid"=>getmypid()]);'
for name,content in [(php,code),(plain,sentinel)]:api('owned-site-create-'+name,'/sites/'+site+'/files/action',{'action':'create','path':name,'content':content})
# Only two fresh owned links are added. The original index and all preexisting
# files remain unchanged; links deliberately test the normal installed policy.
link=public/('forbidden-'+nonce+'.txt');os.symlink(plain,link);hidden=public/('.owned-'+nonce);fd=os.open(hidden,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
with os.fdopen(fd,'wb')as f:f.write(sentinel.encode());f.flush();os.fchown(f.fileno(),before_index['uid'],before_index['gid']);os.fchmod(f.fileno(),0o644);os.fsync(f.fileno())
def traffic(label,path,method='GET',body=None,want=(200,),json_body=False):
 c=http.client.HTTPConnection('127.0.0.1',19101,timeout=12)
 try:
  c.request(method,path,body=body,headers={'Host':domain,'Content-Type':'application/octet-stream'});r=c.getresponse();data=r.read((1<<20)+1);assert len(data)<=1<<20;row={'status':r.status,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),'path':path,'method':method};save(label+'.json',row);assert r.status in want,row
  if json_body:
   v=json.loads(data);save(label+'-PHP-response.json',v);assert v['marker']==nonce and v['php']=='8.2.35'and v['pid']>1 and v['body_sha256']==hashlib.sha256(body or b'').hexdigest();return v
  return data
 finally:c.close()
assert traffic('original-Nginx-static','/index.html')==index.read_bytes();traffic('original-Nginx-PHP','/'+php+'?keep=original',json_body=True)
original=api('original-site-settings','/sites/'+site+'/settings');assert original['status']=='running'and original['settings']['web_server']=='nginx'and original['php_version_id']=='php-8.2.35';settings=copy.deepcopy(original['settings']);settings.update(web_server='apache',rewrite='custom',rules=[{'pattern':'^/catalog/([0-9]+)$','replacement':'/'+php+'?id=$1&$args','flag':'last'}]);preview=api('owned-Apache-site-readonly-preview','/sites/'+site+'/settings/preview',{'settings':settings,'expected_revision':original['settings_revision']});assert preview['revision']==original['settings_revision']and hashlib.sha256(preview['current'].encode()).hexdigest()==preview['config_sha']and 'proxy_pass http://127.0.0.1:19080;'in preview['candidate'];saved=job('one-owned-Apache-settings-commit','/sites/'+site+'/settings',{'settings':settings,'expected_revision':original['settings_revision'],'expected_config_sha':preview['config_sha']})
runtime=api('actual-selected-running-Apache','/runtimes/apache');assert runtime['selected_id']==runtime['running_id']=='apache-2.4.71'and runtime['service_state']=='active'and not runtime['activation_needed']
config=Path('/etc/panel/apache/httpd.conf');text=config.read_text();assert 'Options -Indexes -FollowSymLinks'in text and 'SymLinksIfOwnerMatch'not in text and 'Options +FollowSymLinks'not in text;assert 'RewriteRule ^/catalog/([0-9]+)$'in text
for directory in text.split('<Directory ')[1:]:assert 'RewriteRule'not in directory.split('</Directory>',1)[0]
exe='/opt/panel/runtimes/apache/2.4.71/bin/httpd';version=command('actual-Apache-binary-version',[exe,'-v']);assert 'Apache/2.4.71'in version;command('actual-Apache-config-parse',[exe,'-t','-f',str(config)]);modules=command('actual-Apache-modules',[exe,'-M','-f',str(config)]);assert 'rewrite_module'in modules and 'proxy_fcgi_module'in modules
pid=int(command('actual-Apache-main-PID',['systemctl','show','panel-apache','--property=MainPID','--value']).strip());assert pid>1 and os.path.realpath('/proc/'+str(pid)+'/exe')==exe
assert traffic('actual-Apache-static','/index.html')==index.read_bytes();assert traffic('actual-Apache-regular-public','/'+plain)==sentinel.encode()
for i in range(12):
 payload=('ordinary owned POST '+str(i)+' '+nonce).encode();v=traffic('actual-Apache-rewrite-PHP-'+str(i),'/catalog/'+str(21+i)+'?keep=query-'+str(i),'POST',payload,json_body=True);assert v['id']==str(21+i)and v['keep']=='query-'+str(i)and v['method']=='POST'
for label,path in [('actual-Apache-symlink-denied','/'+link.name),('actual-Apache-hidden-denied','/'+hidden.name)]:assert sentinel.encode()not in traffic(label,path,want=(403,404))
current=api('actual-committed-site-settings','/sites/'+site+'/settings');assert current['settings']==settings and current['settings_revision']==original['settings_revision']+1;config_before_conflict=meta(config)
api('original-stale-settings-commit-refused','/sites/'+site+'/settings',{'settings':settings,'expected_revision':original['settings_revision'],'expected_config_sha':preview['config_sha']},(409,),secrets.token_hex(16));assert meta(config)==config_before_conflict and meta(index)==before_index and link.is_symlink()and os.readlink(link)==plain
post=rows();assert all(all(row in post[t]for row in data)for t,data in prior.items());save('original-business-rows-after.json',post)
proof={'ok':True,'source_inputs_sha256':source,'architecture':{'aarch64':'arm64','x86_64':'amd64'}[os.uname().machine],'scope':'Normal signed Apache2.4.71 source install and normal PHP8.2.35 install, managed Nginx to Apache per-site selection; static and 12 actual POST custom rewrite PHP requests with exact body and query; symlink and hidden-file denial, module/config/version checks and stale CAS refusal. No WAN TLS or cold claim.','site_id':site,'site_domain':domain,'normal_site_create_submissions':1,'normal_site_settings_commits':1,'stale_commit_refused_not_replayed':True,'original_index_and_original_rows_preserved':True,'actual_Apache_runtime':runtime,'actual_Apache_PID':pid,'actual_rewrite_PHP_POST_requests':12,'symlink_restrictions_preserved_and_actual_denial':True,'all40_commercial':False};save('actual-original-business-proof.json',proof);api('logout','/logout',{});print(json.dumps(proof))
