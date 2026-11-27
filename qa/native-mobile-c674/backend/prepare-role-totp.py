from pathlib import Path
import base64,contextlib,hashlib,hmac,http.cookiejar,json,os,re,secrets,sqlite3,struct,sys,time,urllib.error,urllib.request
os.umask(0o077);assert os.geteuid()==0 and os.environ.get('GITHUB_ACTIONS')=='true'and os.environ.get('GITHUB_REPOSITORY')=='yunzhanlin/yunzhan-apps';private=Path(sys.argv[1]).resolve(strict=True);owner=private.stat();setup=json.loads((private/'real-panel-setup.json').read_bytes());assert setup['ok']and setup['programme_source_inputs_sha256']=='b223c28247d9d20e50a356643a9744a9ab174068dd567a2c57f15c342934c15f';assert json.loads(Path('/opt/panel/current/SOURCE_INPUTS.json').read_bytes())['inputs_sha256']==setup['programme_source_inputs_sha256'];origin=setup['panel_origin'];assert origin=='http://127.0.0.1:19100';csrf='';events=[];client=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
def save(n,v,runner=False):
 with(private/n).open('x')as f:json.dump(v,f,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
 if runner:os.chown(private/n,owner.st_uid,owner.st_gid)
def api(path,body=None,expected=200):
 headers={'Origin':origin,'X-CSRF-Token':csrf,'Content-Type':'application/json'}
 if body is not None:headers['Idempotency-Key']=secrets.token_hex(16)
 request=urllib.request.Request(origin+'/api'+path,None if body is None else json.dumps(body).encode(),headers)
 try:
  with client.open(request,timeout=90)as r:status=r.status;raw=r.read((4<<20)+1)
 except urllib.error.HTTPError as e:status=e.code;raw=e.read((4<<20)+1)
 assert len(raw)<=4<<20;events.append({'path':path,'method':'GET'if body is None else'POST','status':status});assert status==expected,'Original role/TOTP request returned unexpected status, no replay: '+path;return json.loads(raw)
def wait_job(job):
 assert re.fullmatch('[a-f0-9]{32}',job);deadline=time.monotonic()+900
 while time.monotonic()<deadline:
  with sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True)as db:r=db.execute('SELECT state,error FROM runtime_jobs WHERE id=?',(job,)).fetchone()
  if r and r[0]not in('queued','running'):assert r==('succeeded','');return
  time.sleep(1)
 raise TimeoutError('Original user manager install pending, no replay')
def otp(secret,step):
 raw=base64.b32decode(secret+'='*((8-len(secret)%8)%8));v=hmac.new(raw,struct.pack('>Q',step),hashlib.sha1).digest();n=v[-1]&15;return str((int.from_bytes(v[n:n+4],'big')&0x7fffffff)%1000000).zfill(6)
proof={'ok':False,'Main_changed':False,'all40_commercial':False,'role_user_created':0,'original_requests_replayed':0}
try:
 access=json.loads((private/'device-credentials.json').read_bytes());csrf=api('/login',{k:access[k]for k in('username','password')})['csrf'];access.clear();catalog=api('/app-registry?refresh=1');assert len(catalog['catalog']['apps'])==40 and catalog['source']['resolved_commit']=='16eca3277e3846c38d2a075f35c4dd27827261bf'and not catalog['source']['stale'];item=next(x for x in catalog['catalog']['apps']if x['id']=='user-manager');job=api('/app-registry/user-manager/install',{'expected_version':item['version'],'expected_sha256':item['sha256']},202);wait_job(job['job_id']);catalog=api('/app-registry');status=next(x for x in catalog['status']if x['id']=='user-manager');assert status['installed']and status['installed_version']==item['version']
 username='c674viewer';password=secrets.token_urlsafe(24);api('/app-modules/user-manager/create',{'username':username,'password':password,'role':'viewer','site_ids':[setup['site']]});proof['role_user_created']=1;api('/logout',{});csrf='';client=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()));csrf=api('/login',{'username':username,'password':password})['csrf'];me=api('/me');save('original-role-actual-me.json',me)
 assert me['role']=='viewer'and isinstance(me['menu_ids'],list);sites=api('/sites');assert len(sites)==1 and sites[0]['id']==setup['site'];assert not(Path('/srv/panel/sites')/setup['site']/'public/c674-forbidden-write.txt').exists();api('/sites/'+setup['site']+'/files/action',{'action':'create','path':'c674-forbidden-write.txt','content':'must not be created'},403);assert not(Path('/srv/panel/sites')/setup['site']/'public/c674-forbidden-write.txt').exists();forbidden=secrets.token_hex(16);assert forbidden!=setup['site'];api('/sites/'+forbidden+'/files?path=.',expected=403)
 factor=api('/account/setup',{'password':password});secret=factor['secret'];assert re.fullmatch('[A-Z2-7]+',secret)
 # Use an ordinary fresh valid time step; no factor state or server clock changes.
 while time.time()%30>15:time.sleep(.3)
 confirmed=api('/account/confirm',{'password':password,'code':otp(secret,int(time.time())//30)});csrf=confirmed['csrf'];assert csrf;codes=confirmed['recovery_codes'];assert len(codes)==10 and len(set(codes))==10;state=api('/account');assert state['totp_enabled']and state['recovery_remaining']==10;api('/logout',{});csrf=''
 save('viewer-device-credentials.json',{'username':username,'password':password,'totp_secret':secret,'recovery_codes':codes,'allowed_site':setup['site'],'forbidden_site':forbidden},True)
 proof.update(ok=True,source_inputs_sha256=setup['programme_source_inputs_sha256'],original_user_manager_install_job=job['job_id'],signed_user_manager_version=item['version'],signed_user_manager_manifest_sha256=item['sha256'],ordinary_admin_create_and_viewer_login=True,actual_viewer_own_site_only=True,actual_readonly_mutation_403_without_file_creation=True,actual_cross_site_403=True,actual_ordinary_TOTP_setup_and_confirm=True,all_ten_recovery_codes_issued=True,device_native_UI_still_pending=True);save('original-role-TOTP-setup-proof.json',proof,True)
finally:
 if csrf:
  try:api('/logout',{})
  except Exception:proof['ok']=False
 save('original-role-TOTP-HTTP-observations.json',events,True)
print(json.dumps({k:v for k,v in proof.items()if k not in('signed_user_manager_manifest_sha256',)}));sys.exit(0 if proof['ok']else 1)
