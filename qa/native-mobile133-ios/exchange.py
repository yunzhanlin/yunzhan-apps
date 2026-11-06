"""Exchange only current-run, immutable, digest-checked GitHub artifacts."""
import hashlib,json,os,pathlib,subprocess,time,zipfile
assert os.environ.get('GITHUB_ACTIONS')=='true'and os.environ.get('GITHUB_REPOSITORY')=='yunzhanlin/yunzhan-apps'
def api(path):return json.loads(subprocess.check_output(['gh','api','repos/yunzhanlin/yunzhan-apps/'+path],timeout=45))
def wait(name,out,allowed,seconds=1000):
 out=pathlib.Path(out);out.mkdir(mode=0o700);end=time.monotonic()+seconds;observations=[]
 while True:
  rows=api('actions/runs/'+os.environ['GITHUB_RUN_ID']+'/artifacts')['artifacts'];found=[v for v in rows if v['name']==name]
  assert len(found)<=1,'Current-run artifact name must have one immutable identity'
  observations.append({'at':time.time(),'found':bool(found)})
  if found:break
  failed_peer='c68-ios-backend-result-'if name.startswith('c68-ios-backend-dispatch-')else'c68-ios-client-result-'
  if any(v['name']==failed_peer+os.environ['GITHUB_RUN_ID']for v in rows):raise AssertionError('Original peer finished before issuing the requested artifact')
  assert time.monotonic()<end,'Original peer artifact unresolved; do not replay peer mutations';time.sleep(4)
 a=found[0];assert not a['expired']and a['workflow_run']['head_sha']==os.environ['GITHUB_SHA']and a['size_in_bytes']<64<<20
 archive=out/'original-peer-artifact.zip'
 with archive.open('xb')as f:r=subprocess.run(['gh','api','repos/yunzhanlin/yunzhan-apps/actions/artifacts/'+str(a['id'])+'/zip'],stdin=subprocess.DEVNULL,stdout=f,stderr=subprocess.PIPE,timeout=300)
 assert r.returncode==0 and hashlib.sha256(archive.read_bytes()).hexdigest()==a['digest'].removeprefix('sha256:')
 with zipfile.ZipFile(archive)as z:
  assert set(z.namelist())==set(allowed)
  for name in z.namelist():
   assert pathlib.PurePosixPath(name).name==name and z.getinfo(name).file_size<64<<20
   with(out/name).open('xb')as f:f.write(z.read(name))
 with(out/'original-exchange-provenance.json').open('x')as f:json.dump({'artifact_id':a['id'],'name':a['name'],'head':a['workflow_run']['head_sha'],'server_digest':a['digest'],'original_observations':observations},f,indent=2)
 return out
