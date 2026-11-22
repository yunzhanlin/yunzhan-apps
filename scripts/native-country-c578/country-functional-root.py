from pathlib import Path
import hashlib,http.cookiejar,importlib.util,json,os,platform,re,secrets,sys,time,traceback,urllib.request
os.umask(0o077);inp=Path(sys.argv[1]);plan=json.loads((inp/'plan.json').read_bytes());assert os.geteuid()==0 and Path('/etc/hostname').read_text().strip()==plan['host'];source=json.loads(Path('/opt/panel/current/SOURCE_INPUTS.json').read_bytes())['inputs_sha256'];assert source==plan['source'];arch={'aarch64':'arm64','x86_64':'amd64'}[platform.machine()];origin='http://127.0.0.1:19100';csrf=''
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*a,**kw):raise AssertionError('Redirect refused')
client=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect(),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
base=Path('/opt/panel-country-native-qa-'+secrets.token_hex(16));base.mkdir(mode=0o700);prep=base/'preparation';prep.mkdir(mode=0o700)
def save(n,v):
 with(prep/n).open('x')as f:json.dump(v,f,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
def api(path,body=None,key=None,expected=200):
 raw=None if body is None else json.dumps(body).encode();headers={'Origin':origin,'Content-Type':'application/json','X-CSRF-Token':csrf}
 if key:headers['Idempotency-Key']=key
 with client.open(urllib.request.Request(origin+'/api'+path,raw,headers),timeout=80)as r:assert r.status==expected;return json.load(r)
proof={'ok':False,'base':str(base),'architecture':arch,'source_inputs_sha256':source,'Main_changes':0,'all40_commercial':False}
try:
 for _ in range(100):
  try:
   with urllib.request.urlopen(origin+'/api/ready',timeout=2)as r:
    if r.status==200:break
  except Exception:pass
  time.sleep(1)
 else:raise TimeoutError('Owned Core not ready')
 access=json.loads(Path('/etc/panel/first-login.json').read_bytes());csrf=api('/login',{k:access[k]for k in('username','password')})['csrf'];access.clear();sites=api('/sites');assert len(sites)==1 and sites[0]['domain'].startswith('c567-owned-waf-');first=sites[0]
 slug='c577-country-'+secrets.token_hex(6);body={'name':slug,'slug':slug,'domain':slug+'.example.test','php_version_id':''};key=secrets.token_hex(16);save('one-new-owned-site-intent.json',{'body':body,'key':key,'maximum_submissions':1});accepted=api('/sites',body,key,202);save('original-new-site-accepted.json',accepted)
 for _ in range(180):
  j=api('/jobs/'+accepted['job_id'])
  if j['state']not in('queued','running'):break
  time.sleep(1)
 save('original-new-site-final.json',j);assert j['state']=='succeeded';second=next(x for x in api('/sites')if x['slug']==slug);api('/logout',{});csrf=''
 modulefile=inp/'country-functional.py';assert hashlib.sha256(modulefile.read_bytes()).hexdigest()==plan['module_sha256'];spec=importlib.util.spec_from_file_location('current_owned_country_case',modulefile);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);functional=m.run(base,arch,plan['app_manifest_sha256'],[first['id'],second['id']]);assert functional['ok'];proof.update(ok=True,country_business=functional,original_data_and_policy_requests_replayed=0)
except BaseException:save('original-wrapper-failure.json',{'traceback':traceback.format_exc()});proof['failure']=traceback.format_exc()[-2000:]
finally:
 if csrf:
  try:api('/logout',{})
  except Exception:pass
 save('proof.json',proof);print(json.dumps(proof),flush=True)
sys.exit(0 if proof['ok']else 1)
