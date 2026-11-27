from pathlib import Path
import base64,contextlib,hashlib,hmac,http.cookiejar,json,os,platform,re,secrets,sqlite3,struct,sys,time,urllib.error,urllib.parse,urllib.request
os.umask(0o077);base=Path(sys.argv[1]).resolve(strict=True);plan=json.loads((base/'plan.json').read_bytes());assert os.geteuid()==0 and platform.machine()=='x86_64'and Path('/etc/hostname').read_text().strip()==plan['expected_hostname'];assert Path('/proc/sys/kernel/random/boot_id').read_text().strip()==plan['expected_boot'];source=json.loads(Path('/opt/panel/current/SOURCE_INPUTS.json').read_bytes())['inputs_sha256'];assert source==plan['source_inputs_sha256']=='b223c28247d9d20e50a356643a9744a9ab174068dd567a2c57f15c342934c15f';assert base.parent==Path('/var/lib/panel-executor')and re.fullmatch('c766-local-only-[a-f0-9]{32}',base.name);origin='http://127.0.0.1:19100';csrf='';events=[];client=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def save(n,v):
 with(base/n).open('x')as f:json.dump(v,f,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
def api(path,body=None,status=200,binary=None):
 h={'Origin':origin,'X-CSRF-Token':csrf,'Content-Type':'application/octet-stream'if binary is not None else'application/json'};raw=binary
 if body is not None:raw=json.dumps(body).encode()
 if raw is not None:h['Idempotency-Key']=secrets.token_hex(16)
 request=urllib.request.Request(origin+'/api'+path,raw,h)
 try:
  with client.open(request,timeout=90)as r:code=r.status;data=r.read((8<<20)+1)
 except urllib.error.HTTPError as r:code=r.code;data=r.read((8<<20)+1)
 events.append({'path':path,'method':'GET'if raw is None else'POST','status':code});assert len(data)<=8<<20 and code==status,'Original owned local API outcome unexpected; no automatic mutation replay: '+path;return json.loads(data)
def wait(table,job):
 assert table in('jobs','runtime_jobs')and re.fullmatch('[a-f0-9]{32}',job);end=time.monotonic()+900
 while True:
  with contextlib.closing(sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True))as db:
   db.row_factory=sqlite3.Row;db.execute('PRAGMA query_only=ON');row=db.execute('SELECT *FROM '+table+' WHERE id=?',(job,)).fetchone();value=dict(row)if row else None
  if value and value['state']not in('queued','running'):assert value['state']=='succeeded'and value['error']=='';return value
  assert time.monotonic()<end,'Original owned operation unresolved; no replay';time.sleep(.5)
def otp(secret,step):
 raw=base64.b32decode(secret+'='*((8-len(secret)%8)%8));digest=hmac.new(raw,struct.pack('>Q',step),hashlib.sha1).digest();offset=digest[-1]&15;return str((int.from_bytes(digest[offset:offset+4],'big')&0x7fffffff)%1000000).zfill(6)
def sdk_snapshot():
 root=Path('/opt/panel/current').resolve(strict=True);values={}
 for f in sorted(root.rglob('*')):
  st=f.lstat();assert __import__('stat').S_ISREG(st.st_mode)or __import__('stat').S_ISDIR(st.st_mode);value={'uid':st.st_uid,'gid':st.st_gid,'mode':__import__('stat').S_IMODE(st.st_mode),'inode':st.st_ino,'directory':f.is_dir()}
  if f.is_file():value.update(bytes=st.st_size,sha256=sha(f))
  values[str(f.relative_to(root))]=value
 return values
proof={'ok':False,'local_Mac_and_owned_guest_only':True,'cross_CI_or_public_factor_export':False,'Main_changes':0,'all40_commercial':False}
try:
 save('original-inherited-SDK-before.json',sdk_snapshot())
 access=json.loads(Path('/etc/panel/first-login.json').read_bytes());csrf=api('/login',{k:access[k]for k in('username','password')})['csrf'];access.clear();oldsites=api('/sites');assert len(oldsites)==1;before={}
 for row in oldsites:
  root=Path('/srv/panel/sites')/row['id']/'public';marker=root/plan['original_marker'];conf=Path('/etc/panel/sites-enabled')/(row['id']+'.conf');assert marker.is_file()and conf.is_file();before[row['id']]={'site':row,'marker_path':str(marker),'marker_sha256':sha(marker),'config_path':str(conf),'config_sha256':sha(conf)}
 save('original-inherited-sites-before.json',before);catalog=api('/app-registry?refresh=1');assert len(catalog['catalog']['apps'])==40 and catalog['source']['resolved_commit']=='16eca3277e3846c38d2a075f35c4dd27827261bf'and not catalog['source']['stale'];mobile=next(x for x in catalog['catalog']['apps']if x['id']=='mobile');assert mobile['version']=='1.3.3';mobile_install=api('/app-registry/mobile/install',{'expected_version':mobile['version'],'expected_sha256':mobile['sha256']},202);wait('runtime_jobs',mobile_install['job_id']);mobile_status=next(x for x in api('/app-registry')['status']if x['id']=='mobile');assert mobile_status['installed']and mobile_status['installed_version']=='1.3.3';save('original-normal-mobile133-installed.json',{'job':mobile_install['job_id'],'status':mobile_status});app=next(x for x in catalog['catalog']['apps']if x['id']=='user-manager');status=next(x for x in catalog['status']if x['id']=='user-manager');assert status['state_known']and not status['installed']and app['version']=='1.3.2'and app['sha256']=='44be1434c6d4f1ed8c47a1f8134173cb59fb827a6b55c073793d988f22b8ec84';install=api('/app-registry/user-manager/install',{'expected_version':app['version'],'expected_sha256':app['sha256']},202);wait('runtime_jobs',install['job_id']);status=next(x for x in api('/app-registry')['status']if x['id']=='user-manager');assert status['installed']and status['installed_version']=='1.3.2'
 slug='c766-native-'+secrets.token_hex(6);created=api('/sites',{'name':'C766 owned local native MFA','slug':slug,'domain':slug+'.localhost','php_version_id':''},202);job=wait('jobs',created['job_id']);site=job['site_id'];assert site not in before;payload=bytes((n*31)&255 for n in range(131137));filename='C766-native.bin';uploaded=api('/sites/'+site+'/files/upload?'+urllib.parse.urlencode({'path':filename}),binary=payload,status=201);assert uploaded['bytes']==131137 and uploaded['sha256']==hashlib.sha256(payload).hexdigest();name='c766viewer';password=secrets.token_urlsafe(24);api('/app-modules/user-manager/create',{'username':name,'password':password,'role':'viewer','site_ids':[site]});api('/logout',{});csrf='';client=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()));csrf=api('/login',{'username':name,'password':password})['csrf'];me=api('/me');assert me['role']=='viewer';sites=api('/sites');assert len(sites)==1 and sites[0]['id']==site;api('/sites/'+site+'/files/action',{'action':'create','path':'c766-forbidden-write.txt','content':'must not be created'},403)
 for other in before:api('/sites/'+other+'/files?path=.',status=403)
 secret=api('/account/setup',{'password':password})['secret'];assert re.fullmatch('[A-Z2-7]+',secret)
 while time.time()%30>15:time.sleep(.3)
 confirmed_step=int(time.time())//30;confirmed=api('/account/confirm',{'password':password,'code':otp(secret,confirmed_step)});csrf=confirmed['csrf'];codes=confirmed['recovery_codes'];assert len(codes)==10 and len(set(codes))==10;state=api('/account');assert state['totp_enabled']and state['recovery_remaining']==10;api('/logout',{});csrf=''
 save('local-viewer-device-credentials.json',{'username':name,'password':password,'totp_secret':secret,'setup_confirmed_totp_step':confirmed_step,'recovery_code':codes[0],'site':site,'filename':filename,'bytes':131137,'sha256':uploaded['sha256']})
 save('owned-local-server-setup.json',{'site':site,'filename':filename,'bytes':131137,'sha256':uploaded['sha256'],'UserManager_install_job':install['job_id'],'own_site_job':job['id'],'original_site_ids':list(before),'source_inputs_sha256':source,'local_only':True})
 proof.update(ok=True,source_inputs_sha256=source,actual_owned_ARM64_Ubuntu24=True,normal_signed_UserManager132_install=True,actual_existing_other_site_403=True,actual_viewer_write_403=True,normal_self_TOTP_setup_and_confirm=True,recovery_codes_issued=10,all_factor_data_stays_inside_user_Mac=True)
except BaseException:
 save('original-local-preparation-failure.json',{'traceback':__import__('traceback').format_exc()});raise
finally:
 if csrf:
  try:api('/logout',{})
  except Exception:proof['ok']=False
 save('original-local-HTTP-observations.json',events);save('original-local-preparation-proof.json',proof)
print(json.dumps(proof))
