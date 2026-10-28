"""One original signed disk-analysis store install in this owned fresh QA guest."""
import base64,contextlib,hashlib,http.cookiejar,json,os,pathlib,platform,secrets,sqlite3,stat,subprocess,sys,time,traceback,urllib.error,urllib.request
os.umask(0o077);base=pathlib.Path(sys.argv[1]);assert len(sys.argv)==2 and os.geteuid()==0
intent=json.loads((base/'intent.json').read_bytes());assert platform.machine()=='x86_64' and pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()==intent['peer']['boot']
assert hashlib.sha256(pathlib.Path('/etc/machine-id').read_bytes()).hexdigest()==intent['peer']['machine_id_sha256']
def save(n,v):
 with os.fdopen(os.open(base/n,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600),'w')as o:json.dump(v,o,sort_keys=True);o.write(chr(10));o.flush();os.fsync(o.fileno())
def sha(p):return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
def capture():
 out={};db=sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True,timeout=3)
 try:
  db.execute('PRAGMA query_only=ON');db.execute('BEGIN')
  for name,sql in db.execute("SELECT name,sql FROM sqlite_schema WHERE type='table' ORDER BY name").fetchall():
   q='"'+name.replace('"','""')+'"';cur=db.execute('SELECT * FROM '+q)
   enc=lambda v:{'blob_base64':base64.b64encode(v).decode()}if isinstance(v,bytes)else v
   out[name]={'sql':sql,'columns':[x[0]for x in cur.description],'rows':sorted([[enc(v)for v in row]for row in cur.fetchall()],key=lambda v:json.dumps(v,sort_keys=True))}
 finally:db.close()
 return out
proof={'ok':False,'scope':'actual original disk1.4 signed store installation and host inventory only','Main_changed':False,'all50_commercial':False,'real_host_scan_acceptance':False};csrf='';opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*args,**kwargs):raise AssertionError('API redirect refused')
opener.add_handler(NoRedirect())
def api(path,body=None,key=None):
 h={'Origin':'http://127.0.0.1:19100','X-CSRF-Token':csrf,'Content-Type':'application/json'}
 if key:h['Idempotency-Key']=key
 req=urllib.request.Request('http://127.0.0.1:19100/api'+path,data=None if body is None else json.dumps(body,separators=(',',':')).encode(),headers=h)
 try:
  with opener.open(req,timeout=40)as r:
   b=r.read((4<<20)+1);assert len(b)<=4<<20
   return r.status,json.loads(b)
 except urllib.error.HTTPError as e:
  save('http-error-'+secrets.token_hex(6)+'.json',{'path':path,'status':e.code,'body':e.read(8192).decode('utf8','replace')});raise AssertionError('API status '+str(e.code)+' at '+path)from None
try:
 assert sha(base/'guest.py')==intent['files']['guest.py']
 assert json.loads(pathlib.Path('/opt/panel/current/SOURCE_INPUTS.json').read_bytes())['inputs_sha256']=='8f8efc19a9ee70b5e8cd5753a16119185cfedc1a785f13c33148d255dab476dd'
 before=capture();save('before-all-Core-fields.json',before)
 s=pathlib.Path('/etc/panel/first-login.json').lstat();assert stat.S_ISREG(s.st_mode)and s.st_uid==0 and stat.S_IMODE(s.st_mode)==0o600
 access=json.loads(pathlib.Path('/etc/panel/first-login.json').read_bytes())
 try:status,login=api('/login',{k:access[k]for k in('username','password')})
 finally:access.clear()
 assert status==200 and login['csrf'];csrf=login['csrf']
 status,page=api('/app-registry?refresh=1');assert status==200 and page['source']['stale'] is False
 item=next(x for x in page['catalog']['apps']if x['id']=='disk-analysis');current=next(x for x in page['status']if x['id']=='disk-analysis')
 assert item['provider']=='panel-module' and item['version']=='1.4.1'and current['installed'] is False
 save('signed-store-before.json',{'item':item,'status':current,'source':page['source'],'host':page['host']})
 key='disk-native-'+secrets.token_hex(16);body={'expected_version':item['version'],'expected_sha256':item['sha256']}
 save('original-store-once-intent.json',{'POST_maximum':1,'key':key,'body':body})
 status,reply=api('/app-registry/disk-analysis/install',body,key);save('original-store-response.json',{'status':status,'response':reply})
 assert status==202 and reply['provider']=='panel-module'and reply['target']=='disk-analysis';job=reply['job_id'];assert len(job)==32
 observed=[]
 for n in range(181):
  with contextlib.closing(sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True,timeout=3))as db:
   db.row_factory=sqlite3.Row;db.execute('PRAGMA query_only=ON');row=db.execute('SELECT * FROM runtime_jobs WHERE id=?',(job,)).fetchone();assert row;row=dict(row)
  assert row['target_id']=='disk-analysis'and row['idempotency_key']==key
  observed.append({'at':time.time(),'row':row})
  if row['state']in('succeeded','failed','cancelled','needs_attention'):break
  assert row['state']in('queued','running')and n<180
  time.sleep(1)
 save('original-store-job-observations.json',observed);assert row['state']=='succeeded'and row['error']=='','Original job not successful; no replay'
 status,page=api('/app-registry');current=next(x for x in page['status']if x['id']=='disk-analysis')
 save('signed-store-after.json',{'status':current,'source':page['source']})
 assert status==200 and current['installed_version']==current['latest_version']=='1.4.1' and all(current[k]is True for k in('installed','healthy','version_known','state_known')) and current['update_available'] is False
 status,host=api('/software/disk-analysis/host');save('original-host-inventory.json',{'status':status,'value':host});assert status==200 and host['installed']is True
 proof.update(ok=True,original_store_job_id=job,normal_signed_store_install_completed=True,installed_version='1.4.1',host_inventory_verified=True)
except BaseException:save('failure.json',{'traceback':traceback.format_exc()})
finally:
 if csrf:
  try:status,_=api('/logout',{});assert status==200;proof['own_session_logged_out']=True
  except BaseException:proof['ok']=False;save('logout-failure.json',{'traceback':traceback.format_exc()})
 after=capture();save('after-all-Core-fields.json',after);save('Core-changed-table-names.json',{'changed':sorted(k for k in set(before)|set(after)if before.get(k)!=after.get(k))}if 'before'in locals()else{})
 save('proof.json',proof)
print(json.dumps(proof));sys.exit(0 if proof['ok']else 1)
