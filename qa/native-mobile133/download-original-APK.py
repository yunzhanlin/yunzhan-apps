"""Require the original successful source run and digest-pinned APK artifact."""
import hashlib,json,os,pathlib,subprocess,sys,zipfile
os.umask(0o077)
assert os.environ.get('GITHUB_ACTIONS')=='true'and os.environ.get('GITHUB_REPOSITORY')=='yunzhanlin/yunzhan-apps'
base=pathlib.Path(__file__).resolve().parent;pins=json.loads((base/'pins.json').read_bytes());private=pathlib.Path(sys.argv[1]).resolve(strict=True)
run=json.loads(subprocess.check_output(['gh','api','repos/yunzhanlin/yunzhan-apps/actions/runs/'+str(pins['native_source_CI_run'])],timeout=60))
assert run['head_sha']==pins['native_source_CI_head']and run['run_attempt']==1 and run['status']=='completed'and run['conclusion']=='success'
pin=pins['native_Android_artifact'];meta=json.loads(subprocess.check_output(['gh','api','repos/yunzhanlin/yunzhan-apps/actions/artifacts/'+str(pin['artifact_id'])],timeout=60))
assert meta['workflow_run']['head_sha']==pins['native_source_CI_head']and not meta['expired']and meta['digest']=='sha256:'+pin['original_server_digest_verified']and meta['size_in_bytes']==pin['bytes']
archive=private/'original-Android-source-CI-artifact.zip'
with archive.open('xb')as f:r=subprocess.run(['gh','api','repos/yunzhanlin/yunzhan-apps/actions/artifacts/'+str(pin['artifact_id'])+'/zip'],stdin=subprocess.DEVNULL,stdout=f,stderr=subprocess.PIPE,timeout=300)
assert r.returncode==0 and archive.stat().st_size==pin['bytes']and hashlib.sha256(archive.read_bytes()).hexdigest()==pin['original_server_digest_verified']
originals={}
with zipfile.ZipFile(archive)as z:
 for name,record in pins['native_APKs'].items():
  member=name.removeprefix('app/build/');assert member.startswith('outputs/apk/')and member.endswith('.apk');info=z.getinfo(member);assert info.file_size==record['bytes'];raw=z.read(info);assert hashlib.sha256(raw).hexdigest()==record['sha256']
  filename='original-debug.apk'if'/debug/'in name else'original-release-unsigned.apk'
  with(private/filename).open('xb')as f:f.write(raw)
  originals[filename]=record
with(private/'original-APK-provenance.json').open('x')as f:json.dump({'ok':True,'original_run':run['id'],'original_head':run['head_sha'],'source_inputs_sha256':pins['native_source_inputs_sha256'],'original_Android_artifact_id':meta['id'],'original_server_artifact_digest_verified':True,'original_APKs':originals,'UI_test_overlays':0,'original_debug_signature_is_not_publisher_signature':True},f,indent=2)
