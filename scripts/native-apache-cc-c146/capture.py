"""Bound, side effect free observer definitions for original C43 native QA."""
import contextlib,hashlib,http.cookiejar,http.server,json,os,pathlib,pwd,re,secrets,socket,sqlite3,stat,subprocess,sys,time,traceback,urllib.error,urllib.request

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
 assert len(tables)==114;files={}
 def walk(f):
  if not os.path.lexists(f):files[str(f)]={'exists':False};return
  s=f.lstat();v={'mode':s.st_mode,'uid':s.st_uid,'gid':s.st_gid,'ino':s.st_ino,'dev':s.st_dev,'links':s.st_nlink}
  if stat.S_ISREG(s.st_mode):assert s.st_size<512<<20;v.update(bytes=s.st_size,sha256=sha(f))
  elif stat.S_ISLNK(s.st_mode):v['target']=os.readlink(f)
  elif stat.S_ISSOCK(s.st_mode):
   assert own_site and re.fullmatch('[a-f0-9]{32}',own_site)and re.fullmatch('qa-c(?:42-[a-f0-9]{12}|43-[a-f0-9]{16})',p['resource_id'])
   account=pwd.getpwnam('ps'+own_site[:24]);home=pathlib.Path('/srv/panel/sites')/own_site/'private'/('pm2-'+p['resource_id'])
   assert f in(home/'rpc.sock',home/'pub.sock')and s.st_uid==account.pw_uid and s.st_gid==account.pw_gid
   v['owned_PM2_IPC_socket']=True
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

def history(label):
 directory=pathlib.Path('/etc/panel/security-apps/modules/pm2-manager')
 result={'read_only':True,'files':{},'ledger_tables':{}}
 if not os.path.lexists(directory):
  result['module_directory_exists']=False;save(label+'.json',result);return result
 for ancestor in[directory,*directory.parents]:
  s=ancestor.lstat();assert stat.S_ISDIR(s.st_mode)and s.st_uid==0 and not s.st_mode&0o022
 result['module_directory_exists']=True
 def verified_read(file):
  with os.fdopen(os.open(file,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC),'rb')as src:
   s=os.fstat(src.fileno());assert stat.S_ISREG(s.st_mode)and s.st_uid==0 and s.st_nlink==1 and not s.st_mode&0o077 and s.st_size<=8<<20
   raw=src.read((8<<20)+1);z=os.fstat(src.fileno());visible=file.lstat()
   assert len(raw)==s.st_size and(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)==(z.st_dev,z.st_ino,z.st_size,z.st_mtime_ns,z.st_ctime_ns)and(visible.st_dev,visible.st_ino)==(s.st_dev,s.st_ino)
   return raw
 for name in('history.json','last-report.json'):
  file=directory/name
  if not os.path.lexists(file):result['files'][name]={'exists':False};continue
  raw=verified_read(file);result['files'][name]={'exists':True,'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw),'original_hex':raw.hex(),'value':json.loads(raw)}
 ledger=directory/'history.sqlite'
 if os.path.lexists(ledger):
  for name in('history.sqlite','history.sqlite-journal','history.sqlite-wal','history.sqlite-shm'):
   file=directory/name
   if not os.path.lexists(file):continue
   s=file.lstat();assert stat.S_ISREG(s.st_mode)and s.st_uid==0 and s.st_nlink==1 and not s.st_mode&0o077 and s.st_size<=64<<20
  with contextlib.closing(sqlite3.connect('file:'+str(ledger)+'?mode=ro',uri=True,timeout=3))as db:
   db.execute('PRAGMA query_only=ON');db.execute('BEGIN')
   for name, in db.execute("SELECT name FROM sqlite_master WHERE type='table'AND name NOT LIKE'sqlite_%'ORDER BY name").fetchall():
    assert name in('metadata','module_events')
    columns=[v[1]for v in db.execute('PRAGMA table_info("'+name+'")')]
    rows=db.execute('SELECT *FROM "'+name+'"').fetchall();assert len(rows)<=100000
    rows=[[{'blob_hex':v.hex()}if isinstance(v,bytes)else v for v in row]for row in rows];rows.sort(key=lambda v:json.dumps(v,sort_keys=True,separators=(',',':')))
    result['ledger_tables'][name]={'columns':columns,'rows':rows}
 raw=json.dumps(result,sort_keys=True)
 assert len(raw.encode())<=16<<20
 for key in('synthetic_environment','replacement_environment','failed_candidate_environment'):
  if key in p:assert p[key]not in raw
 save(label+'.json',result);return result

def owned_journal(label):
 assert re.fullmatch('qa-c(?:42-[a-f0-9]{12}|43-[a-f0-9]{16})',p['resource_id'])
 name='panel-pm2@'+p['resource_id']+'.service'
 observed=subprocess.run(['journalctl','--boot='+p['boot'].replace('-',''),'--unit='+name,'--output=json','--lines=6000','--no-pager'],capture_output=True,timeout=30)
 assert observed.returncode==0 and len(observed.stdout)<=8<<20
 raw=observed.stdout.decode();records=[json.loads(line)for line in raw.splitlines()if line];assert len(records)<6000
 for record in records:
  assert record['_BOOT_ID']==p['boot'].replace('-','')
  assert name in(record.get('_SYSTEMD_UNIT'),record.get('UNIT'),record.get('OBJECT_SYSTEMD_UNIT'))
 for key in('synthetic_environment','replacement_environment','failed_candidate_environment'):
  if key in p:assert p[key]not in raw
 state=dict(v.split('=',1)for v in command(['systemctl','show',name,'--property=NRestarts,ExecMainPID,ExecMainStartTimestampMonotonic,ExecMainExitTimestampMonotonic']).splitlines())
 result={'read_only':True,'unit':name,'boot':p['boot'],'records':records,'count':len(records),'complete_since_boot':True,'unit_start_properties':state}
 save(label+'.json',result);return result

def fixture_source(p):
    return "'use strict';const fs=require('node:fs'),path=require('node:path'),http=require('node:http'),crypto=require('node:crypto');const counter=path.join(process.env.HOME,'qa-c43-start-count');let count=fs.existsSync(counter)?Number(fs.readFileSync(counter,'utf8')):0;if(!Number.isSafeInteger(count)||count<0)throw Error('Invalid counter');count++;const tmp=counter+'.'+process.pid;let fd=fs.openSync(tmp,'wx',0o600);fs.writeFileSync(fd,String(count));fs.fsyncSync(fd);fs.closeSync(fd);fs.renameSync(tmp,counter);fd=fs.openSync(path.dirname(counter),'r');fs.fsyncSync(fd);fs.closeSync(fd);http.createServer((req,res)=>{res.writeHead(200,{'Content-Type':'application/json','Cache-Control':'no-store'});res.end(JSON.stringify({marker:" + json.dumps(p['marker']) + ",pid:process.pid,uid:process.getuid(),gid:process.getgid(),start_count:count,environment_sha256:crypto.createHash('sha256').update(process.env.QA_PM2_CANARY||'').digest('hex')}));}).listen(Number(process.env.PORT),process.env.HOST||'127.0.0.1');"
