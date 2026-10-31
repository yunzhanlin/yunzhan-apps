"""Bound native observer definitions reused by C42 QA; only the fixture runner executes selected definitions."""
import contextlib,hashlib,http.cookiejar,http.server,json,os,pathlib,pwd,re,secrets,socket,sqlite3,stat,subprocess,sys,time,traceback,urllib.error,urllib.request
os.umask(0o077);base=pathlib.Path(sys.argv[1]);assert re.fullmatch('/opt/panel-pm2-c42-baseline-[a-f0-9]{32}',str(base));p=json.loads((base/'intent.json').read_bytes());evidence=base/'evidence';evidence.mkdir(mode=0o700);assert pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()==p['boot'];SOURCE='757e1941dc2e3e138cef458eb52114545d168ee41286872012e100770c50a1fb';assert json.loads(pathlib.Path('/opt/panel/current/SOURCE_INPUTS.json').read_bytes())['inputs_sha256']==SOURCE
def sha(f):return hashlib.sha256(pathlib.Path(f).read_bytes()).hexdigest()
def save(n,value):
 assert re.fullmatch('[A-Za-z0-9._-]+',n)
 with(evidence/n).open('x')as f:json.dump(value,f,indent=2,sort_keys=True);f.write('\n');f.flush();os.fsync(f.fileno())
def command(args,timeout=30):
 r=subprocess.run(args,capture_output=True,text=True,timeout=timeout);assert r.returncode==0,(args[0],r.returncode,r.stderr[-1500:]);assert len(r.stdout)<4<<20;return r.stdout
def unit(name):return dict(v.split('=',1)for v in command(['systemctl','show',name,'--property=LoadState,MainPID,InvocationID,ActiveState,SubState,UnitFileState']).splitlines())
def snapshot():
 with contextlib.closing(sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True,timeout=3))as db:
  db.execute('PRAGMA query_only=ON');db.execute('BEGIN');schema=db.execute("SELECT type,name,tbl_name,sql FROM sqlite_master WHERE name NOT LIKE'sqlite_%'ORDER BY type,name").fetchall();tables={}
  for name, in db.execute("SELECT name FROM sqlite_master WHERE type='table'AND name NOT LIKE'sqlite_%'ORDER BY name").fetchall():
   assert re.fullmatch('[a-z0-9_]+',name);cols=[v[1]for v in db.execute('PRAGMA table_info("'+name+'")')];rows=[[{'blob_hex':v.hex()}if isinstance(v,bytes)else v for v in row]for row in db.execute('SELECT *FROM "'+name+'"')];assert len(rows)<=100000;rows.sort(key=lambda v:json.dumps(v,sort_keys=True,separators=(',',':')));tables[name]={'columns':cols,'rows':rows}
 assert len(tables)==113;files={}
 def walk(f):
  if not os.path.lexists(f):files[str(f)]={'exists':False};return
  s=f.lstat();v={'mode':s.st_mode,'uid':s.st_uid,'gid':s.st_gid,'ino':s.st_ino,'dev':s.st_dev,'links':s.st_nlink}
  if stat.S_ISREG(s.st_mode):assert s.st_size<512<<20;v.update(bytes=s.st_size,sha256=sha(f))
  elif stat.S_ISLNK(s.st_mode):v['target']=os.readlink(f)
  else:assert stat.S_ISDIR(s.st_mode)
  files[str(f)]=v;assert len(files)<65000
  if stat.S_ISDIR(s.st_mode):
   for child in sorted(f.iterdir()):walk(child)
 for name in('/etc/panel','/etc/nginx','/etc/ssh','/etc/fail2ban','/etc/systemd/system','/srv/panel/sites','/opt/panel/current/bin','/opt/panel/current/web','/opt/panel/app-modules','/opt/panel/runtimes','/opt/panel/php-extensions','/var/lib/panel-executor/installs','/usr/bin/node'):walk(pathlib.Path(name))
 lifetimes={}
 for name in('panel.service','panel-executor.service','nginx.service','ssh.service','fail2ban.service'):
  v=unit(name);assert v['ActiveState']=='active'and int(v['MainPID'])>1;process=pathlib.Path('/proc')/v['MainPID'];v.update(exe_sha256=sha(process/'exe'),start_ticks=process.joinpath('stat').read_text().rsplit(')',1)[1].split()[19]);lifetimes[name]=v
 nss={n:{'sha256':sha('/etc/'+n),'entries':{line.split(':',1)[0]:hashlib.sha256(line.encode()).hexdigest()for line in pathlib.Path('/etc/'+n).read_text().splitlines()}}for n in('passwd','group','shadow','gshadow','nsswitch.conf')}
 packages=command(['dpkg-query','-W','-f=${Package}\t${Version}\t${db:Status-Status}\n']);return{'at':time.time(),'boot':p['boot'],'schema':schema,'tables':tables,'protected_files':files,'lifetimes':lifetimes,'nss':nss,'packages':packages,'NFS_state':unit('panel-nfs-server.service')}
def guard():
 r=subprocess.run(['/opt/panel/current/bin/panel-executor','--check-program-upgrade-queues'],capture_output=True,timeout=35);assert r.returncode==0 and r.stdout==r.stderr==b''
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*args,**kwargs):raise AssertionError('Unexpected authentication redirect')
origin='http://127.0.0.1:19100';client=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect(),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()));csrf='';events=[];secret=p['synthetic_environment'];app_created=False;stop_after_observation=False;own_site=None
def api(label,path,body=None,expected=200,key=None):
 headers={'Origin':origin,'Content-Type':'application/json','X-CSRF-Token':csrf}
 if key:headers['Idempotency-Key']=key
 if body is not None:
  safe=json.loads(json.dumps(body))
  if path=='/login':safe={'credentials':'existing Root-private first login, never logged'}
  if'environment_patch'in safe:safe['environment_patch']={k:{'sha256':hashlib.sha256(v.encode()).hexdigest(),'write_only':True}for k,v in body['environment_patch'].items()}
  save(label+'-once-intent.json',{'path':path,'body':safe,'maximum_POSTs':1,'idempotency_key':key,'no_unknown_outcome_replay':True})
 request=urllib.request.Request(origin+'/api'+path,data=None if body is None else json.dumps(body,separators=(',',':')).encode(),headers=headers)
 try:
  with client.open(request,timeout=80)as response:status=response.status;raw=response.read((8<<20)+1)
 except urllib.error.HTTPError as e:status=e.code;raw=e.read((8<<20)+1)
 assert len(raw)<=8<<20 and secret.encode()not in raw;value=json.loads(raw);events.append({'path':path,'method':'GET'if body is None else'POST','status':status,'at':time.time()});stored=value if path!='/login'else{'csrf_issued':bool(value.get('csrf'))};save(label+'-original-response.json',{'status':status,'value':stored});assert status==expected,(path,status,value);return value
def wait_job(label,identity,table):
 assert re.fullmatch('[a-f0-9]{32}',identity)and table in('jobs','runtime_jobs');deadline=time.monotonic()+900;states=[]
 while True:
  with contextlib.closing(sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True))as db:
   db.row_factory=sqlite3.Row;db.execute('PRAGMA query_only=ON');row=dict(db.execute('SELECT *FROM '+table+' WHERE id=?',(identity,)).fetchone())
  states.append({'state':row['state'],'at':time.time()})
  if row['state']not in('queued','running'):break
  assert time.monotonic()<deadline,'Original job unresolved, observe only';time.sleep(.5)
 save(label+'-original-observations.json',states);save(label+'-original-terminal.json',row);assert row['state']=='succeeded'and not row['error'];return row
def probe(label):
 app=json.loads(pathlib.Path('/etc/panel/security-apps/modules/pm2-manager/apps',p['resource_id']+'.json').read_bytes());name='panel-pm2@'+p['resource_id']+'.service';state=unit(name);assert state['ActiveState']=='active'
 opener=urllib.request.build_opener(urllib.request.ProxyHandler({}));
 with opener.open('http://127.0.0.1:'+str(p['port'])+'/',timeout=5)as response:assert response.status==200;body=response.read(4097);assert len(body)<=4096
 answer=json.loads(body);account=pwd.getpwnam('ps'+own_site[:24]);assert answer['marker']==p['marker']and answer['environment_sha256']==hashlib.sha256(secret.encode()).hexdigest()and answer['uid']==account.pw_uid and answer['gid']==account.pw_gid and account.pw_uid>0 and account.pw_gid>0;process=pathlib.Path('/proc')/str(answer['pid']);status=dict(line.split(':',1)for line in(process/'status').read_text().splitlines()if':'in line);assert status['NoNewPrivs'].strip()=='1'and all(int(status[k],16)==0 for k in('CapInh','CapPrm','CapEff','CapAmb'));cgroup=(process/'cgroup').read_text();assert name in cgroup and sha(process/'exe')==sha('/opt/panel/app-modules/pm2/node/bin/node' if p['platform']=='ubuntu-22.04' else '/usr/bin/node');result={'app':{k:v for k,v in app.items()if k!='environment_cipher'},'actual_HTTP':answer,'unit':state,'primary_GID':account.pw_gid,'nonroot_UID':account.pw_uid,'NoNewPrivs':1,'capabilities_zero':True,'cgroup':cgroup,'Node_binary_sha256':sha('/opt/panel/app-modules/pm2/node/bin/node' if p['platform']=='ubuntu-22.04' else '/usr/bin/node')};save(label+'-actual.json',result);return result
proof={'ok':False,'purpose':'Original C41 commercial stopped-state gap reproduction, not commercial acceptance','source_inputs_sha256':SOURCE,'architecture':'arm64','platform':'ubuntu-26.04','normal_install_POSTs':0,'normal_site_create_POSTs':0,'normal_PM2_create_POSTs':0,'Main_changed':False,'all50_commercial':False,'original_mutations_replayed':False}
try:
 guard();before=snapshot();save('before.json',before);assert before['NFS_state']['ActiveState']=='inactive'and before['NFS_state']['UnitFileState']=='disabled';assert not pathlib.Path('/etc/panel/security-apps/modules/pm2-manager/installed.json').exists()
 access_path=pathlib.Path('/etc/panel/first-login.json');s=access_path.lstat();assert stat.S_ISREG(s.st_mode)and s.st_uid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600;access=json.loads(access_path.read_bytes())
 try:login=api('login','/login',{k:access[k]for k in('username','password')});csrf=login['csrf']
 finally:access.clear()
 catalog=api('signed-catalogue','/app-registry?refresh=1');assert len(catalog['catalog']['apps'])==50 and not catalog['source']['stale']and catalog['host']=={'platform':'ubuntu-26.04','architecture':'arm64'};item=next(v for v in catalog['catalog']['apps']if v['id']=='pm2-manager');status=next(v for v in catalog['status']if v['id']=='pm2-manager');assert item['version']=='7.0.4-compat5'and status['state_known']and not status['installed'];proof['normal_install_POSTs']+=1;accepted=api('PM2-normal-install','/app-registry/pm2-manager/install',{'settings':{},'expected_version':item['version'],'expected_sha256':item['sha256']},202,p['install_key']);proof['original_install_job_id']=accepted['job_id'];wait_job('PM2-normal-install',accepted['job_id'],'runtime_jobs');catalog=api('post-install-normal-shop-receipt','/app-registry');status=next(v for v in catalog['status']if v['id']=='pm2-manager');assert status['installed']and status['healthy']and status['installed_version']==item['version']
 proof['normal_site_create_POSTs']+=1;accepted=api('normal-site-create','/sites',{'name':'Owned PM2 C42 stopped state','slug':p['resource_id'],'domain':p['resource_id']+'.localhost','php_version_id':''},202,p['site_key']);job=wait_job('normal-site-create',accepted['job_id'],'jobs');own_site=job['site_id'];proof['owned_site_id']=own_site
 code="'use strict';const fs=require('node:fs'),path=require('node:path'),http=require('node:http'),crypto=require('node:crypto');const counter=path.join(process.env.HOME,'qa-c42-start-count');let count=fs.existsSync(counter)?Number(fs.readFileSync(counter,'utf8')):0;if(!Number.isSafeInteger(count)||count<0)throw Error('Invalid counter');count++;const tmp=counter+'.'+process.pid;let fd=fs.openSync(tmp,'wx',0o600);fs.writeFileSync(fd,String(count));fs.fsyncSync(fd);fs.closeSync(fd);fs.renameSync(tmp,counter);fd=fs.openSync(path.dirname(counter),'r');fs.fsyncSync(fd);fs.closeSync(fd);http.createServer((req,res)=>{res.writeHead(200,{'Content-Type':'application/json','Cache-Control':'no-store'});res.end(JSON.stringify({marker:"+json.dumps(p['marker'])+",pid:process.pid,uid:process.getuid(),gid:process.getgid(),start_count:count,environment_sha256:crypto.createHash('sha256').update(process.env.QA_PM2_CANARY||'').digest('hex')}));}).listen(Number(process.env.PORT),process.env.HOST||'127.0.0.1');";entry=api('normal-entry-create','/sites/'+own_site+'/files/action',{'action':'create','path':p['entry'],'content':code});assert entry['sha256']==hashlib.sha256(code.encode()).hexdigest();proof['entry_sha256']=entry['sha256']
 proof['normal_PM2_create_POSTs']+=1;created=api('normal-PM2-create','/app-modules/pm2-manager/create',{'resource_id':p['resource_id'],'site_id':own_site,'entry':p['entry'],'port':p['port'],'instances':1,'memory_mb':128,'environment_patch':{'QA_PM2_CANARY':secret}});assert created['ok']and created['app']['revision']==1 and 'environment_cipher'not in created['app'];app_created=True;initial=probe('initial-running');api('original-PM2-stop','/app-modules/pm2-manager/stop',{'resource_id':p['resource_id']});name='panel-pm2@'+p['resource_id']+'.service';stopped=unit(name);save('original-stopped-unit.json',stopped);assert stopped['ActiveState']=='inactive'and stopped['MainPID']=='0';proof['stopped_project_boot_would_restart']=stopped['UnitFileState']=='enabled'
 updated=api('original-stopped-config-update','/app-modules/pm2-manager/update',{'resource_id':p['resource_id'],'expected_revision':1,'memory_mb':160});assert updated['ok']and updated['app']['revision']==2;after_update=probe('after-stopped-save');proof['stopped_update_started_service']=after_update['unit']['ActiveState']=='active';proof['unexpected_start_count_delta']=after_update['actual_HTTP']['start_count']-initial['actual_HTTP']['start_count'];assert proof['stopped_update_started_service']and proof['stopped_project_boot_would_restart']and proof['unexpected_start_count_delta']==1
 stop_after_observation=True;api('owned-fixture-final-stop','/app-modules/pm2-manager/stop',{'resource_id':p['resource_id']});stopped=unit(name);assert stopped['ActiveState']=='inactive'and stopped['MainPID']=='0';save('owned-fixture-disable-once-intent.json',{'unit':name,'maximum_submissions':1,'only_owned_QA_fixture_boot_cleanup':True});command(['systemctl','disable',name]);assert unit(name)['UnitFileState']=='disabled';proof.update(ok=True,original_two_stopped_state_gaps_reproduced=True,fixture_retained_stopped_boot_disabled=True)
except BaseException:proof['failure']=traceback.format_exc().replace(secret,'[synthetic-environment-redacted]')
finally:
 if csrf:
  try:api('logout','/logout',{});csrf=''
  except BaseException:proof['logout_failure']=traceback.format_exc().replace(secret,'[redacted]')
 try:save('after.json',snapshot());guard();proof['after_full113_and_protected_files_retained']=True
 except BaseException:proof['after_capture_failure']=traceback.format_exc()
 save('HTTP-events.json',events);save('proof.json',proof);print(json.dumps({'ok':proof['ok'],'purpose':proof['purpose'],'base':str(base),'proof_sha256':sha(evidence/'proof.json'),'PM2_install_job':proof.get('original_install_job_id'),'two_state_gaps_reproduced':proof.get('original_two_stopped_state_gaps_reproduced'),'Main_changed':False,'all50_commercial':False}),flush=True)
sys.exit(0 if proof['ok']else 1)
