"""One temporary HTTPS tunnel for a new CI-only signed panel and owned site."""
import hashlib,json,os,pathlib,re,runpy,subprocess,sys,time,urllib.error,urllib.request
os.umask(0o077)
base=pathlib.Path(__file__).resolve().parent;pins=json.loads((base/'pins.json').read_bytes());private=pathlib.Path(sys.argv[1]).resolve(strict=True)
assert os.environ.get('GITHUB_ACTIONS')=='true'and os.environ.get('GITHUB_REPOSITORY')=='yunzhanlin/yunzhan-apps'
setup=json.loads((private/'real-panel-setup.json').read_bytes());assert setup['ok']and setup['real_file_manager_backend']and setup['native_source_inputs_sha256']==pins['native_source_inputs_sha256']
asset=pins['cloudflared'];binary=private/'original-cloudflared-linux-amd64';h=hashlib.sha256();count=0
with urllib.request.urlopen(asset['url'],timeout=90)as response,binary.open('xb')as f:
 assert response.status==200 and response.url.startswith('https://')
 for chunk in iter(lambda:response.read(1<<20),b''):
  count+=len(chunk);assert count<=asset['bytes'];h.update(chunk);f.write(chunk)
assert count==asset['bytes']and h.hexdigest()==asset['sha256'];binary.chmod(0o700)
args=[str(binary),'tunnel','--no-autoupdate','--url','http://127.0.0.1:19100','--loglevel','info','--metrics','127.0.0.1:23236']
with(private/'original-cloudflared.stdout').open('xb')as out,(private/'original-cloudflared.stderr').open('xb')as err:process=subprocess.Popen(args,stdin=subprocess.DEVNULL,stdout=out,stderr=err,start_new_session=True)
with(private/'original-cloudflared-intent.json').open('x')as f:json.dump({'pid':process.pid,'args':args,'one_temporary_CI_panel_only':True,'no_account_or_production_credentials':True,'original_binary_sha256':asset['sha256'],'certificate_validation_unchanged':True},f,indent=2)
end=time.monotonic()+90
while True:
 assert process.poll()is None,'Original tunnel exited; retain outcome without recreating'
 raw=(private/'original-cloudflared.stderr').read_text(errors='replace');urls=re.findall(r'https://[a-z0-9-]+\.trycloudflare\.com',raw)
 if urls:break
 assert time.monotonic()<end;time.sleep(1)
origin=urls[0];assert all(v==origin for v in urls)
observations=[];ready=False
for _ in range(12):
 try:
  with urllib.request.urlopen(origin+'/',timeout=15)as response:
   raw=response.read((4<<20)+1);assert response.status==200 and len(raw)<4<<20 and response.url==origin+'/'
   assert b'<html'in raw.lower()and b'<div id="app"'in raw;ready=True;observations.append({'status':response.status,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'ordinary_public_TLS':True});break
 except (OSError,urllib.error.URLError)as error:observations.append({'transport_error_type':type(error).__name__})
 time.sleep(2)
with(private/'original-tunnel-GET-observations.json').open('x')as f:json.dump(observations,f,indent=2)
assert ready,'Original ordinary public HTTPS did not become ready'
with(private/'original-HTTPS-origin.json').open('x')as f:json.dump({'ok':True,'origin':origin,'source_inputs_sha256':pins['native_source_inputs_sha256'],'ordinary_public_TLS':True,'one_temporary_CI_panel_only':True,'Main_changed':False,'all50_commercial':False},f,indent=2)
print(json.dumps({'ok':True,'one_temporary_CI_HTTPS_tunnel_ready':True,'ordinary_OS_trust_unchanged':True,'Main_changed':False}))
