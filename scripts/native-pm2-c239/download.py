"""Pin original public release assets and exact owned KVM fixture before dispatch."""
from pathlib import Path
import hashlib,json,os,subprocess,sys
os.umask(0o077);assert len(sys.argv)==2 and os.environ.get('GITHUB_ACTIONS')=='true'and os.environ.get('GITHUB_REPOSITORY')=='yunzhanlin/yunzhan-apps'
source=Path(__file__).resolve().parent;plan=json.loads((source/'dispatch.json').read_bytes());assert subprocess.check_output(['git','rev-parse','HEAD^'],text=True).strip()==plan['parent']
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
for n,pin in plan['fixture_files'].items():assert sha(source/n)==pin,n
release=json.loads(subprocess.check_output(['gh','api','repos/yunzhanlin/yunzhan-apps/releases/'+str(plan['release_id'])],timeout=90));assert release['tag_name']==plan['tag']and release['target_commitish']=='e9781747c48247344dbb25788ba45f320185773e'and release['prerelease']and not release['draft']
actual={a['name']:a for a in release['assets']};assert set(actual)==set(plan['assets']);out=Path(sys.argv[1]);out.mkdir(mode=0o700)
payload=json.loads((source/'payload.json').read_bytes())
for n,pin in payload['files'].items():
 p=out/n
 if n in plan['assets']:
  a=actual[n];expected=plan['assets'][n];assert a['id']==expected['id']and a['size']==expected['bytes']and a['digest']=='sha256:'+pin
  with p.open('xb')as f,(out/(n+'.private-download.stderr')).open('xb')as err:r=subprocess.run(['gh','api','-H','Accept: application/octet-stream','repos/yunzhanlin/yunzhan-apps/releases/assets/'+str(a['id'])],stdout=f,stderr=err,timeout=180)
  assert r.returncode==0,'Original encrypted/private transport error retained locally';assert p.stat().st_size==expected['bytes']
 else:p.write_bytes((source/n).read_bytes())
 assert sha(p)==pin
(out/'assets.json').write_bytes((source/'payload.json').read_bytes())
print(json.dumps({'ok':True,'original_release_id':release['id'],'source_inputs_sha256':payload['source_inputs_sha256'],'native_architecture':'amd64','Main_changed':False}))
