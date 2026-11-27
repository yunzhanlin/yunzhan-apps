from pathlib import Path
import hashlib,http.cookiejar,json,os,platform,re,secrets,stat,subprocess,sys,time,traceback,urllib.request,urllib.error
os.umask(0o077);payload=Path(sys.argv[1]);pins=json.loads((payload/'assets.json').read_bytes());case=pins['OS_case'];arch={'aarch64':'arm64','x86_64':'amd64'}[platform.machine()];assert os.geteuid()==0 and arch==pins['architecture']and Path('/etc/hostname').read_text().strip()==case['hostname'];source=pins['source_inputs_sha256'];assert source=='b223c28247d9d20e50a356643a9744a9ab174068dd567a2c57f15c342934c15f';base=Path('/opt/panel-platform-native-peer-'+secrets.token_hex(16));base.mkdir(mode=0o700);ev=base/'evidence';ev.mkdir(mode=0o700);origin='http://127.0.0.1:19100';csrf=''
def sha(p):
 h=hashlib.sha256()
 with Path(p).open('rb')as f:
  for b in iter(lambda:f.read(1<<20),b''):h.update(b)
 return h.hexdigest()
def save(n,v):
 with(ev/n).open('x')as f:json.dump(v,f,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*a,**kw):raise AssertionError('Unexpected redirect refused')
client=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect(),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
def api(label,path,body=None,expected=200):
 h={'Origin':origin,'Content-Type':'application/json','X-CSRF-Token':csrf};raw=None
 if body is not None:
  key=secrets.token_hex(16);h['Idempotency-Key']=key;raw=json.dumps(body).encode();save(label+'-intent.json',{'path':path,'key':key,'maximum_submissions':1,'body':'redacted'if path=='/login'else body})
 try:
  with client.open(urllib.request.Request(origin+'/api'+path,raw,h),timeout=100)as r:status=r.status;b=r.read((8<<20)+1)
 except urllib.error.HTTPError as r:status=r.code;b=r.read((8<<20)+1)
 assert len(b)<=8<<20;v=json.loads(b)
 if path!='/login':save(label+'-response.json',{'status':status,'value':v})
 assert status==expected,(label,status,v);return v

def job(label,path,body):
 accepted=api(label,path,body,202);jid=accepted['job_id'];assert re.fullmatch('[a-f0-9]{32}',jid)
 for _ in range(5400):
  row=api(label+'-poll-'+str(_),'/jobs/'+jid)
  if row['state']not in('queued','running'):save(label+'-original-terminal.json',row);assert row['state']=='succeeded',(label,row);return row
  time.sleep(1)
 raise TimeoutError('Original operation unresolved; never repeat POST')
proof={'ok':False,'base':str(base),'source_inputs_sha256':source,'architecture':arch,'Main_changes':0,'all40_commercial':False,'original_operation_replays':0}
try:
 assert not any(os.path.lexists(p)for p in('/opt/panel','/etc/panel','/var/lib/panel'))
 for n,h in pins['files'].items():assert sha(payload/n)==h
 verified=base/'verified-input';verified.mkdir(mode=0o700)
 for n,h in pins['files'].items():
  assert re.fullmatch('[A-Za-z0-9._-]+',n)
  with(verified/n).open('xb')as f:f.write((payload/n).read_bytes());f.flush();os.fsync(f.fileno())
  assert sha(verified/n)==h
 archive=verified/('panel-'+pins['version']+'-linux-'+arch+'.tar.gz');save('one-normal-signed-programme-install-intent.json',{'archive_sha256':sha(archive),'maximum_submissions':1})
 with(ev/'normal-signed-install.stdout').open('xb')as o,(ev/'normal-signed-install.stderr').open('xb')as e:r=subprocess.run([sys.executable,'-I','-B',str(verified/'signed-release.py'),'install',str(archive),'--public-key',str(verified/'release-signing-dev.pub')],stdout=o,stderr=e,timeout=1800)
 save('normal-signed-programme-install-outcome.json',{'exit':r.returncode});assert r.returncode==0
 assert json.loads(Path('/opt/panel/current/SOURCE_INPUTS.json').read_bytes())['inputs_sha256']==source
 for _ in range(120):
  try:
   with urllib.request.urlopen(origin+'/api/ready',timeout=2)as r:
    if r.status==200:break
  except Exception:pass
  time.sleep(1)
 else:raise TimeoutError('Core not ready')
 access=json.loads(Path('/etc/panel/first-login.json').read_bytes());csrf=api('login','/login',{k:access[k]for k in('username','password')})['csrf'];access.clear();catalogue=api('original-normal-current-signed-source','/app-registry?refresh=1');assert catalogue['source']['resolved_commit']=='16eca3277e3846c38d2a075f35c4dd27827261bf'and not catalogue['source']['stale']and len(catalogue['catalog']['apps'])==40;assert not any(re.fullmatch('php-[57][0-9]',a['id'])for a in catalogue['catalog']['apps']);installs={}
 for appid in('nginx','platform-ops'):
  app=next(a for a in catalogue['catalog']['apps']if a['id']==appid);state=next(a for a in catalogue['status']if a['id']==appid);assert state['state_known']and not state['installed']and state['supported'];row=job('one-normal-'+appid+'-install','/app-registry/'+appid+'/install',{'expected_version':app['version'],'expected_sha256':app['sha256']});installs[appid]={'job_id':row['id'],'version':app['version'],'manifest_sha256':app['sha256']}
 module=api('original-current-installed-platform-module','/app-modules/platform-ops');state=module['status'];assert state['healthy']and state['version']=='1.3.1'and re.fullmatch('[a-f0-9]{32}',state['installation_id'])
 slug='c610-owned-platform-'+secrets.token_hex(6);created=job('one-new-owned-static-site','/sites',{'name':slug,'slug':slug,'domain':slug+'.example.test','php_version_id':''});sites=api('own-sites','/sites');assert len(sites)==1 and sites[0]['slug']==slug;site=sites[0];marker='C610 original native platform site '+secrets.token_hex(16);api('one-owned-static-file','/sites/'+site['id']+'/files/action',{'action':'create','path':'c610-original.txt','content':marker});req=urllib.request.Request('http://127.0.0.1:19101/c610-original.txt',headers={'Host':site['domain']})
 with client.open(req,timeout=15)as r:assert r.status==200 and r.read(1<<20).decode()==marker
 pid=int(subprocess.check_output(['systemctl','show','nginx.service','-p','MainPID','--value'],text=True));assert pid>1;proc=Path('/proc')/str(pid);nginx={'pid':pid,'start':(proc/'stat').read_text().rsplit(')',1)[1].split()[19],'exe':os.readlink(proc/'exe'),'exe_sha256':sha(proc/'exe'),'configuration_sha256':sha('/etc/nginx/nginx.conf')}
 proof.update(ok=True,boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip(),installation_id=state['installation_id'],version=state['version'],normal_signed_programme_installs=1,normal_current_store_installs=installs,original_owned_site=site,original_owned_file={'path':'/srv/panel/sites/'+site['id']+'/public/c610-original.txt','sha256':hashlib.sha256(marker.encode()).hexdigest()},actual_Nginx=nginx,actual_static_HTTP200=True,paired_TLS_business_pending=True)
except BaseException:proof['failure']=traceback.format_exc()[-6000:]
finally:
 if csrf:
  try:api('logout','/logout',{})
  except Exception:proof['ok']=False
 save('proof.json',proof);print(json.dumps(proof),flush=True)
sys.exit(0 if proof['ok']else 1)
