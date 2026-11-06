"""Retrieve only the already accepted C67 signed programme for fresh CI QA."""
import hashlib,json,os,pathlib,subprocess,sys,urllib.request
assert os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('GITHUB_REPOSITORY')=='yunzhanlin/yunzhan-apps'
os.umask(0o077)
base=pathlib.Path(__file__).resolve().parent;pins=json.loads((base/'pins.json').read_bytes())
out=pathlib.Path(sys.argv[1]);out.mkdir(mode=0o700)
release=json.loads(subprocess.check_output(['gh','api','repos/yunzhanlin/yunzhan-apps/releases/'+str(pins['programme_release_id'])],timeout=60))
assert release['id']==pins['programme_release_id'] and release['tag_name']==pins['programme_tag'] and release['target_commitish']==pins['programme_source_head'] and not release['draft']
actual={a['name']:a for a in release['assets']}
for name,pin in pins['programme_assets'].items():
 a=actual[name];assert a['id']==pin['id'] and a['size']==pin['bytes'] and a['digest']=='sha256:'+pin['sha256']
 h=hashlib.sha256();count=0
 with urllib.request.urlopen(a['browser_download_url'],timeout=90)as response,(out/name).open('xb')as f:
  assert response.status==200 and response.url.startswith('https://')
  for chunk in iter(lambda:response.read(1<<20),b''):
   count+=len(chunk);assert count<=pin['bytes'];h.update(chunk);f.write(chunk)
 assert count==pin['bytes'] and h.hexdigest()==pin['sha256']
assert hashlib.sha256((base/'original-signed-release.py').read_bytes()).hexdigest()==pins['original_verifier_sha256']
with(out/'original-downloads.json').open('x')as f:json.dump({'ok':True,'release_id':release['id'],'all_original_asset_ids_lengths_and_hashes_verified':True,'install_pending':True},f)
