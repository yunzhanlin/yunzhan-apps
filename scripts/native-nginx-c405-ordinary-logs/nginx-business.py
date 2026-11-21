from pathlib import Path
import hashlib,http.client,http.cookiejar,json,os,re,secrets,sqlite3,stat,subprocess,sys,time,urllib.request,urllib.error
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

def rows():
 with sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True)as db:
  db.execute('PRAGMA query_only=ON');return {t:db.execute('SELECT *FROM '+t+' ORDER BY 1').fetchall()for t in('runtime_jobs','app_registry_receipts','app_registry_install_requests','sites')}
def digest(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def meta(p):
 p=Path(p);s=p.lstat();assert stat.S_ISREG(s.st_mode)and s.st_nlink==1;return {'dev':s.st_dev,'inode':s.st_ino,'uid':s.st_uid,'gid':s.st_gid,'mode':stat.S_IMODE(s.st_mode),'bytes':s.st_size,'sha256':digest(p)}
def master():
 r=subprocess.run(['systemctl','show','nginx','--property=MainPID','--value'],capture_output=True,text=True,timeout=10);assert r.returncode==0;pid=int(r.stdout.strip());assert pid>1;statdata=Path('/proc/'+str(pid)+'/stat').read_text();return {'pid':pid,'start':statdata.rsplit(')',1)[1].split()[19],'executable':os.readlink('/proc/'+str(pid)+'/exe')}
def job(label,path,body):
 v=api(label,path,body,(202,),secrets.token_hex(16));identity=v['job_id'];assert re.fullmatch('[a-f0-9]{32}',identity)
 for _ in range(600):
  v=api(label+'-original-readonly-poll','/jobs/'+identity)
  if v['state']not in('queued','running'):assert v['state']=='succeeded',(label,v);return v
  time.sleep(1)
 raise TimeoutError('Original site job unresolved; no replay')
credentials=json.loads(Path('/etc/panel/first-login.json').read_bytes());csrf=api('login','/login',{k:credentials[k]for k in('username','password')})['csrf'];credentials.clear();prior=rows();save('original-business-rows-before.json',prior)
slug='c399-'+secrets.token_hex(6);domain=slug+'.example.test';created=job('new-owned-static-site','/sites',{'name':'C399 owned Nginx log inspection','slug':slug,'domain':domain});site=created['site_id'];assert re.fullmatch('[a-f0-9]{32}',site);public=Path('/srv/panel/sites')/site/'public';index=public/'index.html';before_index=meta(index);config=Path('/etc/panel/sites-enabled')/(site+'.conf');assert 'disable_symlinks on;'in config.read_text();site_config=meta(config)
def traffic(label,count):
 marker=label+'-'+secrets.token_hex(8);responses=[];probe=public/(marker+'.txt');payload=('Owned Nginx log probe '+marker+'\n').encode();fd=os.open(probe,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb')as f:f.write(payload);f.flush();os.fchown(f.fileno(),before_index['uid'],before_index['gid']);os.fchmod(f.fileno(),0o644);os.fsync(f.fileno())
 for i in range(count):
  c=http.client.HTTPConnection('127.0.0.1',19101,timeout=8)
  try:
   c.request('GET','/'+probe.name,headers={'Host':domain});r=c.getresponse();body=r.read(1<<20);responses.append({'status':r.status,'bytes':len(body),'sha256':hashlib.sha256(body).hexdigest()});assert r.status==200 and body==payload
  finally:c.close()
 save(label+'-actual-HTTP.json',{'marker':marker,'responses':responses});return marker
before_marker=traffic('before-original-log-task',12);log=Path('/var/log/nginx')/('panel-'+site+'.access.log')
for i in range(40):
 if log.exists()and before_marker.encode()in log.read_bytes():break
 assert i<39;time.sleep(.1)
before_bytes=log.read_bytes();before_log=meta(log);before_master=master();save('owned-site-index-before.json',before_index);save('owned-site-config-before.json',site_config);save('original-log-before.json',before_log);save('original-Nginx-master-before.json',before_master)
name='C399 日志保全验收 '+slug;schedule=api('new-owned-disabled-log-schedule','/schedules',{'name':name,'kind':'log_cleanup','target_id':site,'schedule_type':'daily','timezone':'UTC','minute':0,'hour':3,'weekday':0,'retention_count':7,'enabled':False},(201,));sid=schedule['id'];assert re.fullmatch('[a-f0-9]{32}',sid);run=api('original-one-log-run','/schedules/'+sid+'/run',{},(202,));rid=run['id'];assert re.fullmatch('[a-f0-9]{32}',rid)
for i in range(180):
 observed=api('original-run-readonly-observation','/schedules/runs?limit=100');matches=[x for x in observed['runs']if x['id']==rid];assert len(matches)==1;run=matches[0]
 if run['state']not in('queued','running'):break
 assert i<179;time.sleep(1)
assert run['state']=='succeeded',run;checked=api('original-readonly-log-inspection','/schedules/runs/'+rid+'/log-cleanup');assert checked['request_id']==rid and checked['site_id']==site and checked['state']=='completed'and checked['read_only']and checked['result']['rotated']>=1 and checked['result']['deleted']==0
archives=list(Path('/var/log/nginx').glob('panel-'+site+'.access.log.*'));assert len(archives)==1;archive=archives[0];after_archive=meta(archive);assert after_archive['dev']==before_log['dev']and after_archive['inode']==before_log['inode']and archive.read_bytes().startswith(before_bytes);assert meta(log)['inode']!=before_log['inode'];archive_before_probe=meta(archive)
after_marker=traffic('after-original-log-task',12)
for i in range(40):
 if after_marker.encode()in log.read_bytes():break
 assert i<39;time.sleep(.1)
assert after_marker.encode()not in archive.read_bytes();assert meta(archive)==archive_before_probe;assert master()==before_master;assert meta(index)==before_index and meta(config)==site_config
checked_again=api('same-original-readonly-inspection','/schedules/runs/'+rid+'/log-cleanup');assert checked_again==checked;assert meta(archive)==archive_before_probe;after=rows();assert all(all(row in after[t]for row in data)for t,data in prior.items());save('original-business-rows-after.json',after)
proof={'ok':True,'source_inputs_sha256':source,'architecture':{'aarch64':'arm64','x86_64':'amd64'}[os.uname().machine],'scope':'Normal signed Nginx site HTTP, one actual normal Core schedule log operation, archive inode/content preservation, actual reopen and repeat readonly inspection; actual browser pending','normal_owned_site_id':site,'normal_owned_site_domain':domain,'normal_owned_schedule_id':sid,'normal_owned_schedule_name':name,'normal_original_run_id':rid,'normal_log_operation_submissions':1,'only_2_owned_probe_files_added':True,'original_archive':after_archive,'actual_result':checked,'original_Nginx_master_identity_unchanged':True,'site_index_config_and_symlink_restriction_preserved':True,'post_rotation_12_requests_written_only_to_new_log':True,'old_job_receipt_site_rows_preserved':True,'all40_commercial':False};save('actual-original-business-proof.json',proof);api('logout','/logout',{});print(json.dumps(proof))
