"""Retrieve immutable release and browser inputs on a fresh owned CI runner."""
import hashlib,json,os,pathlib,platform,re,subprocess,sys,urllib.request
os.umask(0o077)
assert os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('GITHUB_REPOSITORY')=='yunzhanlin/yunzhan-apps'
assert len(sys.argv)==3
source=pathlib.Path(__file__).resolve().parent
dispatch=json.loads((source/'dispatch.json').read_bytes())
assert dispatch['format']==1 and dispatch['source_inputs_sha256']=='eba559f9773a13be628ff2c70a496da245dec82ebdf8d94fc3e2bf93c20932d3'
assert subprocess.check_output(['git','rev-parse','HEAD^'],text=True).strip()==dispatch['source_head']
extra=dispatch['qa7_payload_files'];assert set(extra)=={'.github/workflows/native-analytics-c66-browser-qa7.yml','scripts/native-analytics-c66/download-qa7.py','scripts/native-analytics-c66/prepare-qa7.py'}
assert set(subprocess.check_output(['git','diff','--name-only','HEAD^','HEAD'],text=True).splitlines())==set(extra)|{'scripts/native-analytics-c66/dispatch.json'}
for name,digest in extra.items():assert hashlib.sha256(pathlib.Path(name).read_bytes()).hexdigest()==digest
arch={'x86_64':'amd64','aarch64':'arm64'}[platform.machine()]
out=pathlib.Path(sys.argv[1]);out.mkdir(mode=0o700)
private=pathlib.Path(sys.argv[2]);private.mkdir(mode=0o700)
def sha(p):return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
def save(name,value):
 with(private/name).open('x')as f:json.dump(value,f,indent=2);f.write('\n')
def gh(path):return json.loads(subprocess.check_output(['gh','api','repos/yunzhanlin/yunzhan-apps/'+path],timeout=45))
run=gh('actions/runs/'+str(dispatch['source_ci_run']))
assert run['head_sha']==dispatch['source_head'] and run['status']=='completed' and run['conclusion']=='success' and run['run_attempt']==1
save('original-source-CI.json',run)
tree=subprocess.check_output(['git','rev-parse','HEAD:candidate/panel-integration-load-balance'],text=True).strip()
assert tree==dispatch['source_sdk_tree']
release=gh('releases/'+str(dispatch['release_id']))
assert release['id']==dispatch['release_id'] and release['tag_name']==dispatch['tag'] and release['target_commitish']==dispatch['source_head'] and release['prerelease']
save('original-release.json',release)
assets={a['name']:a for a in release['assets']}
assert set(assets)==set(dispatch['release_assets'])
chosen=[dispatch['cohorts'][arch]['archive']+suffix for suffix in ('','.manifest','.sig')]+['release-signing-dev.pub']
for name in chosen:
 pin=dispatch['release_assets'][name];asset=assets[name]
 assert re.fullmatch('[a-zA-Z0-9._-]+',name) and asset['id']==pin['id'] and asset['size']==pin['bytes'] and asset.get('digest')=='sha256:'+pin['sha256']
 with(out/name).open('xb')as f:r=subprocess.run(['gh','api','-H','Accept: application/octet-stream','repos/yunzhanlin/yunzhan-apps/releases/assets/'+str(pin['id'])],stdout=f,stderr=subprocess.PIPE,timeout=180)
 assert r.returncode==0 and (out/name).stat().st_size==pin['bytes'] and sha(out/name)==pin['sha256']
browser=json.loads((source/'browser-pins.json').read_bytes())[arch]
h=hashlib.sha256();size=0
with urllib.request.urlopen(browser['url'],timeout=90)as response,(out/'chromium.zip').open('xb')as f:
 assert response.status==200 and response.geturl().startswith('https://')
 for chunk in iter(lambda:response.read(1<<20),b''):
  size+=len(chunk);assert size<=browser['bytes'];h.update(chunk);f.write(chunk)
assert size==browser['bytes'] and h.hexdigest()==browser['sha256']
verifier=source/'original-signed-release.py'
assert sha(verifier)=='fe128e82b4e11345b320cd782134768bfe1a4df14947c425d7494873a7a7b7b5'
with(out/'signed-release.py').open('xb')as f:f.write(verifier.read_bytes())
assert sha(out/'release-signing-dev.pub')=='4ccfcc861d56a41e3ba7f7ace7e2432c815f366c58448d783df92c6632f01339'
save('original-download-proof.json',{'ok':True,'architecture':arch,'source_head':dispatch['source_head'],'source_inputs_sha256':dispatch['source_inputs_sha256'],'source_sdk_tree':tree,'release_id':release['id'],'browser':browser,'actual_install_and_BFCache_pending':True})
print(json.dumps({'ok':True,'architecture':arch,'signed_assets_downloaded':4,'browser_archive_sha256':browser['sha256'],'install_pending':True}))
