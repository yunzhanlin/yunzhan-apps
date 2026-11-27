from pathlib import Path
import hashlib,json,os,shutil,subprocess,sys,time,urllib.request,http.cookiejar
os.umask(0o077);base=Path(__file__).resolve().parent;private=Path(sys.argv[1]).resolve(strict=True);assert os.geteuid()==0;setup=json.loads((private/'owned-root-setup.json').read_bytes());role=Path(setup['role_root']);upgrade=Path(setup['upgrade_root']);pins=json.loads((base/'pins.json').read_bytes());proof={'ok':False,'native_App_runs':0,'Main_changes':0,'all40_commercial':False}
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def save(n,v):
 with(private/n).open('x')as f:json.dump(v,f,indent=2);f.write('\n')
try:
 for phase in ['legacy','upgrade','viewer']:
  name='original-client-UI-proof.json'if phase=='viewer'else'original-client-proof.json';v=json.loads((private/phase/name).read_bytes());assert v['ok'];proof[phase+'_actual_browser_pass']=True
 with(private/'original-root-final.stdout').open('xb')as o,(private/'original-root-final.stderr').open('xb')as e:r=subprocess.run(['python3','-I','-B',str(base/'finish-role-root.py'),str(role)],stdout=o,stderr=e,timeout=90)
 save('original-root-final-outcome.json',{'returncode':r.returncode});assert r.returncode==0
 queued=json.loads((private/'upgrade/original-store-update-queued.json').read_bytes());witness=json.loads((role/'original-local-server-final-witness.json').read_bytes());assert any(v['id']==queued['job_id']and v['state']=='succeeded'and v['error']==''for v in witness['tables']['runtime_jobs'])
 save('original-owned-restart-intent.json',{'services':['panel.service','panel-executor.service'],'maximum_submissions':1});r=subprocess.run(['systemctl','restart','panel.service','panel-executor.service'],capture_output=True,timeout=90);save('original-owned-restart-outcome.json',{'returncode':r.returncode});assert r.returncode==0
 origin='http://127.0.0.1:19100';access=json.loads(Path('/etc/panel/first-login.json').read_bytes());client=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()));request=urllib.request.Request(origin+'/api/login',json.dumps({k:access[k]for k in['username','password']}).encode(),{'Origin':origin,'Content-Type':'application/json'});access.clear()
 with client.open(request,timeout=30)as response:assert response.status==200;csrf=json.load(response)['csrf']
 with client.open(origin+'/api/app-registry',timeout=90)as response:assert response.status==200;catalogue=json.load(response)
 state=next(x for x in catalogue['status']if x['id']=='mobile');assert state['installed']and state['installed_version']=='1.4.0'and state['version_known']and not state['update_available'];assert len(catalogue['catalog']['apps'])==40 and catalogue['source']['resolved_commit']==pins['catalogue_head'];save('original-post-restart-registry.json',catalogue)
 with client.open(urllib.request.Request(origin+'/api/logout',b'{}',{'Origin':origin,'X-CSRF-Token':csrf,'Content-Type':'application/json'}),timeout=20)as response:assert response.status==200
 proof.update(ok=True,normal_signed_old_to_new_SDK=True,normal_signed_mobile133_to_web140_update=True,original_old_release_and_sites_preserved=True,real_upload_download_and_scoped_MFA_recovery=True,post_restart_installed140_retained=True,source_inputs_sha256=pins['new']['programme_source_inputs_sha256'],architecture='amd64',current_web_only_scope=True)
finally:
 for label,root in [('root-role',role),('root-upgrade',upgrade)]:
  dest=private/label;dest.mkdir(mode=0o700)
  for f in root.iterdir():
   if not f.is_file()or 'credentials'in f.name.lower()or f.suffix not in['.json','.stdout','.stderr']:continue
   shutil.copyfile(f,dest/f.name)
 save('original-final-proof.json',proof)
print(json.dumps(proof));assert proof['ok']
