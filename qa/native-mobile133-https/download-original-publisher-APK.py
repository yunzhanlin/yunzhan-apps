"""Read the exact retained-publisher APK from its owned draft asset."""
import hashlib,json,os,pathlib,subprocess,sys
os.umask(0o077)
assert os.environ.get('GITHUB_ACTIONS')=='true'and os.environ.get('GITHUB_REPOSITORY')=='yunzhanlin/yunzhan-apps'
base=pathlib.Path(__file__).resolve().parent;pins=json.loads((base/'pins.json').read_bytes());private=pathlib.Path(sys.argv[1]).resolve(strict=True)
release=json.loads(subprocess.check_output(['gh','api','repos/yunzhanlin/yunzhan-apps/releases/'+str(pins['release_id'])],timeout=60));assert release['id']==pins['release_id']and release['draft']and release['prerelease']and release['tag_name']==pins['release_tag']and release['target_commitish']==pins['release_target']
pin=pins['publisher_APK'];asset=next(v for v in release['assets']if v['id']==pin['id']);assert asset['name']=='yunzhan-mobile-1.3.3-android.apk'and asset['size']==pin['bytes']and asset['digest']=='sha256:'+pin['sha256']and asset['state']=='uploaded'
target=private/'original-publisher.apk'
with target.open('xb')as out,(private/'original-publisher-asset-download.stderr').open('xb')as err:r=subprocess.run(['gh','api','repos/yunzhanlin/yunzhan-apps/releases/assets/'+str(asset['id']),'-H','Accept: application/octet-stream'],stdin=subprocess.DEVNULL,stdout=out,stderr=err,timeout=180)
assert r.returncode==0 and target.stat().st_size==pin['bytes']and hashlib.sha256(target.read_bytes()).hexdigest()==pin['sha256']
with(private/'original-publisher-APK-provenance.json').open('x')as f:json.dump({'ok':True,'original_release_id':release['id'],'original_draft_asset_id':asset['id'],'bytes':pin['bytes'],'sha256':pin['sha256'],'source_inputs_sha256':pins['native_source_inputs_sha256'],'retained_publisher_certificate_sha256':pins['original_publisher_certificate_sha256'],'source_or_APK_overlays':0,'signed_or_resigned_in_CI':False,'publisher_private_key_copied_or_uploaded':False,'Main_changed':False,'all50_commercial':False},f,indent=2)
