"""Fetch only the independently pinned public signed upgrade inputs."""
import hashlib,json,os,pathlib,platform,subprocess,sys
os.umask(0o077)
assert len(sys.argv)==2 and os.environ.get('GITHUB_ACTIONS')=='true'and os.environ.get('GITHUB_REPOSITORY')=='yunzhanlin/yunzhan-apps'
source=pathlib.Path(__file__).resolve().parent;plan=json.loads((source/'upgrade.json').read_bytes());arch={'x86_64':'amd64','aarch64':'arm64'}[platform.machine()]
out=pathlib.Path(sys.argv[1]);out.mkdir(mode=0o700)
def gh(path):return json.loads(subprocess.check_output(['gh','api','repos/yunzhanlin/yunzhan-apps/'+path],timeout=90))
release=gh('releases/'+str(plan['release_id']));assert release['id']==plan['release_id']and release['tag_name']==plan['tag']and release['target_commitish']==plan['head']and release['prerelease']and not release['draft']
assets={a['name']:a for a in release['assets']};assert set(assets)==set(plan['assets'])
name='panel-'+plan['version']+'-linux-'+arch+'.tar.gz'
for n in [name+s for s in('','.manifest','.sig')]+['release-signing-dev.pub']:
 pin=plan['assets'][n];actual=assets[n];assert actual['id']==pin['id']and actual['size']==pin['bytes']and actual['digest']=='sha256:'+pin['sha256']and actual['state']=='uploaded'
 with(out/n).open('xb')as f:subprocess.run(['gh','api','-H','Accept: application/octet-stream','repos/yunzhanlin/yunzhan-apps/releases/assets/'+str(actual['id'])],stdout=f,check=True,timeout=180)
 assert(out/n).stat().st_size==pin['bytes']and hashlib.sha256((out/n).read_bytes()).hexdigest()==pin['sha256']
print(json.dumps({'ok':True,'architecture':arch,'release':plan['release_id'],'source_inputs_sha256':plan['source_inputs_sha256'],'actual_signature_verification_on_Root_host_next':True}))
