"""Acquire an official upstream prebuilt for one disposable API30 CI case.

This is a compatibility fixture, not the current stable WebView and not a
production dependency, product download, security patch or provider bypass.
"""
import base64,hashlib,json,os,pathlib,subprocess,sys,urllib.request
os.umask(0o077)
assert os.geteuid()!=0 and os.environ.get('GITHUB_ACTIONS')=='true'and os.environ.get('GITHUB_REPOSITORY')=='yunzhanlin/yunzhan-apps'and os.environ['C68_UI_API']=='30'
private=pathlib.Path(sys.argv[1]).resolve(strict=True)
pin=json.loads((pathlib.Path(__file__).parent/'pins.json').read_bytes())['API30_owned_CI_WebView_fixture']
assert pin['source_commit']=='27ac2bdb9a1a4e55dc65bb6cdc752dbfdea3b9f4'and pin['source_blob']=='fcd919744aaba4ff5f9d30701e0f1e135cbf0ad6'and pin['bytes']==261423172
url='https://android.googlesource.com/platform/external/chromium-webview/+/27ac2bdb9a1a4e55dc65bb6cdc752dbfdea3b9f4/128.0.6613.88/x86_64/webview.apk?format=TEXT'
assert url==pin['official_original_URL']
encoded=private/'original-owned-AOSP-WebView128.base64';apk=private/'original-owned-AOSP-WebView128.apk';total=0;decoded=0;pending=b'';digest=hashlib.sha256();blob=hashlib.sha1(b'blob '+str(pin['bytes']).encode()+b'\0')
with urllib.request.urlopen(url,timeout=120)as response,encoded.open('xb')as raw_output,apk.open('xb')as output:
 assert response.status==200 and response.url==url
 while True:
  block=response.read(1<<20)
  if not block:break
  total+=len(block);assert total<512<<20;raw_output.write(block);pending+=block;size=len(pending)//4*4;value=base64.b64decode(pending[:size],validate=True);pending=pending[size:];decoded+=len(value);assert decoded<=pin['bytes'];digest.update(value);blob.update(value);output.write(value)
 assert not pending
assert decoded==pin['bytes']and digest.hexdigest()==pin['sha256']and blob.hexdigest()==pin['source_blob']
tools=pathlib.Path(os.environ['ANDROID_HOME'])/'build-tools/36.0.0'
def observe(label,args):
 with(private/(label+'.stdout')).open('xb')as out,(private/(label+'.stderr')).open('xb')as err:result=subprocess.run([str(v)for v in args],stdin=subprocess.DEVNULL,stdout=out,stderr=err,timeout=120)
 with(private/(label+'-outcome.json')).open('x')as f:json.dump({'exit':result.returncode,'original_readonly_verification':True},f)
 assert result.returncode==0
 return(private/(label+'.stdout')).read_text()
signer=observe('original-official-AOSP-WebView128-signature',[tools/'apksigner','verify','--min-sdk-version','30','--max-sdk-version','30','--verbose','--print-certs',apk]);assert 'Signer #1 certificate SHA-256 digest: '+pin['certificate_sha256']in signer
metadata=observe('original-official-AOSP-WebView128-metadata',[tools/'aapt2','dump','badging',apk]);assert "package: name='com.android.webview' versionCode='661308807' versionName='128.0.6613.88'"in metadata and "minSdkVersion:'26'"in metadata and "native-code: 'x86_64'"in metadata
with(private/'original-official-AOSP-WebView128-provenance.json').open('x')as f:json.dump({'ok':True,'official_source_commit':pin['source_commit'],'official_source_blob':blob.hexdigest(),'bytes':decoded,'sha256':digest.hexdigest(),'certificate_sha256':pin['certificate_sha256'],'owned_CI_compatibility_fixture_only':True,'not_current_stable_or_production_WebView_recommendation':True,'installed_or_provider_selected_by_this_acquisition_helper':False,'Main_changed':False},f,indent=2)
