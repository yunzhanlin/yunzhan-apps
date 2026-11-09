"""Retrieve exact original release inputs before any installer or application action."""
import hashlib,json,os,pathlib,platform,re,subprocess,sys
os.umask(0o077)
assert len(sys.argv)==4 and os.environ.get('GITHUB_ACTIONS')=='true'and os.environ.get('GITHUB_REPOSITORY')=='yunzhanlin/yunzhan-apps'
source=pathlib.Path(__file__).resolve().parent;cohort=json.loads((source/'cohort.json').read_bytes());bootstrap=json.loads((source/'dispatch.json').read_bytes())
arch={'x86_64':'amd64','aarch64':'arm64'}[platform.machine()]
oldout=pathlib.Path(sys.argv[1]);newout=pathlib.Path(sys.argv[2]);private=pathlib.Path(sys.argv[3])
for d in(oldout,newout,private):d.mkdir(mode=0o700)
def sha(p):return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
def save(n,v):
 with(private/n).open('x')as f:json.dump(v,f,indent=2);f.write('\n')
def gh(path):
 r=subprocess.run(['gh','api','repos/yunzhanlin/yunzhan-apps/'+path],capture_output=True,timeout=90);assert r.returncode==0,r.stderr[-1200:];return json.loads(r.stdout)
assert subprocess.check_output(['git','rev-parse','HEAD^'],text=True).strip()==cohort['source_head']
changes=set(subprocess.check_output(['git','diff','--name-only','-z','HEAD^','HEAD']).decode().split('\0'))
assert changes-{''}==set(cohort['payload_files'])|{'scripts/native-pm2-c70/cohort.json'}
for n,h in cohort['payload_files'].items():assert sha(pathlib.Path(n))==h,n
assert subprocess.check_output(['git','rev-parse','HEAD:candidate/panel-integration-pm2-root-vendor-r2'],text=True).strip()==cohort['source_sdk_tree']
for name in['capture.py','phase1.py','phase2.py','finish.py','bootstrap-original-install.py','original-signed-release.py','recipient.pem']:
 assert sha(source/name)==cohort['files'][name]
run=gh('actions/runs/'+str(cohort['source_ci_run']));assert run['head_sha']==cohort['source_head']and run['status']=='completed'and run['conclusion']=='success'and run['run_attempt']==1
save('original-new-source-CI.json',run)
run=gh('actions/runs/'+str(bootstrap['source_ci_run']));assert run['head_sha']==bootstrap['source_head']and run['status']=='completed'and run['conclusion']=='success'and run['run_attempt']==1
save('original-old-source-CI.json',run)
for kind,expected,out in[
 ('old',{'id':bootstrap['release_id'],'tag':bootstrap['tag'],'head':bootstrap['source_head'],'assets':bootstrap['release_assets'],'archive':bootstrap['cohorts'][arch]['archive']},oldout),
 ('new',{'id':cohort['new_release_id'],'tag':cohort['new_release_tag'],'head':cohort['source_head'],'assets':cohort['new_release_assets'],'archive':cohort['cohorts'][arch]['archive']},newout)]:
 release=gh('releases/'+str(expected['id']));assert release['id']==expected['id']and release['tag_name']==expected['tag']and release['target_commitish']==expected['head']and not release['draft']and release['prerelease']
 assets={v['name']:v for v in release['assets']};assert set(assets)==set(expected['assets'])
 save('original-'+kind+'-release.json',release)
 chosen=[expected['archive']+suffix for suffix in('','.manifest','.sig')]+['release-signing-dev.pub']
 for n in chosen:
  pin=expected['assets'][n];asset=assets[n];assert re.fullmatch('[a-zA-Z0-9._-]+',n)and asset['id']==pin['id']and asset['state']=='uploaded'and asset['size']==pin['bytes']and asset['digest']=='sha256:'+pin['sha256']
  with(out/n).open('xb')as f:r=subprocess.run(['gh','api','-H','Accept: application/octet-stream','repos/yunzhanlin/yunzhan-apps/releases/assets/'+str(pin['id'])],stdout=f,stderr=subprocess.PIPE,timeout=180)
  assert r.returncode==0 and(out/n).stat().st_size==pin['bytes']and sha(out/n)==pin['sha256']
 assert sha(out/'release-signing-dev.pub')=='4ccfcc861d56a41e3ba7f7ace7e2432c815f366c58448d783df92c6632f01339'
verifier=source/'original-signed-release.py';assert sha(verifier)=='fe128e82b4e11345b320cd782134768bfe1a4df14947c425d7494873a7a7b7b5'
(oldout/'signed-release.py').open('xb').write(verifier.read_bytes())
save('original-download-proof.json',{'ok':True,'architecture':arch,'source_head':cohort['source_head'],'source_inputs_sha256':cohort['source_inputs_sha256'],'source_sdk_tree':cohort['source_sdk_tree'],'old_original_release_id':bootstrap['release_id'],'new_original_release_id':cohort['new_release_id'],'original_signed_assets_each_arch':8,'installer_or_app_mutations':0,'all50_commercial':False})
print(json.dumps({'ok':True,'architecture':arch,'original_signed_inputs_verified':True,'installer_submissions':0}))
