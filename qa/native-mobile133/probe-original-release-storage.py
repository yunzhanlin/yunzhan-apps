"""Diagnose platform APIs inside the test-signed original release sandbox.

The independent instrumentation package has no product classes or network
credentials. Its disposable signer matches the already installed CI test copy,
not the publisher. No production device or original product source is changed.
"""
import json,os,pathlib,subprocess,sys,zipfile
os.umask(0o077)
assert os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('GITHUB_REPOSITORY')=='yunzhanlin/yunzhan-apps'
private=pathlib.Path(sys.argv[1]).resolve(strict=True);sdk=pathlib.Path(os.environ['ANDROID_HOME']);base=pathlib.Path(__file__).resolve().parent
assert os.environ['C68_UI_COHORT']=='QA8'
out=private/'independent-storage-probe';out.mkdir(mode=0o700);classes=out/'classes';classes.mkdir();dex=out/'dex';dex.mkdir()
tools=sdk/'build-tools/36.0.0';android=sdk/'platforms/android-37.0/android.jar';adb=sdk/'platform-tools/adb'
def once(label,args):
 with(private/(label+'.stdout')).open('xb')as stdout,(private/(label+'.stderr')).open('xb')as stderr:r=subprocess.run([str(v)for v in args],stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr,timeout=90)
 with(private/(label+'-outcome.json')).open('x')as f:json.dump({'exit':r.returncode,'maximum_submissions':1},f)
 assert r.returncode==0,label+' failed; original retained'
manifest=out/'AndroidManifest.xml';manifest.write_text('''<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="icu.yunzhan.qa.storage"><uses-sdk android:minSdkVersion="30" android:targetSdkVersion="37"/><application android:label="C68 independent storage probe" android:allowBackup="false"/><instrumentation android:name="icu.yunzhan.qa.storage.StorageProbe" android:targetPackage="icu.yunzhan.panel" android:functionalTest="true"/></manifest>''')
once('original-platform-probe-javac',['javac','-encoding','UTF-8','-source','17','-target','17','-classpath',android,'-d',classes,base/'StorageProbe.java'])
once('original-platform-probe-dex',[tools/'d8','--min-api','30','--lib',android,'--output',dex,classes/'icu/yunzhan/qa/storage/StorageProbe.class'])
unsigned=out/'unsigned.apk';once('original-platform-probe-package',[tools/'aapt2','link','-I',android,'--manifest',manifest,'-o',unsigned])
with zipfile.ZipFile(unsigned,'a')as archive:archive.write(dex/'classes.dex','classes.dex')
aligned=out/'aligned.apk';once('original-platform-probe-align',[tools/'zipalign','-p','-f','4',unsigned,aligned])
signed=out/'probe.apk';once('original-platform-probe-disposable-sign',[tools/'apksigner','sign','--ks',private/'owned-release-test.p12','--ks-pass','pass:owned-test-only','--key-pass','pass:owned-test-only','--ks-key-alias','owned-qa','--out',signed,aligned])
once('original-platform-probe-signature-verify',[tools/'apksigner','verify','--verbose','--print-certs',signed])
once('one-independent-platform-probe-install',[adb,'-s','emulator-5554','install',signed])
once('one-original-target-sandbox-storage-probe',[adb,'-s','emulator-5554','shell','am','instrument','-w','icu.yunzhan.qa.storage/icu.yunzhan.qa.storage.StorageProbe'])
raw=(private/'one-original-target-sandbox-storage-probe.stdout').read_text()
assert 'actual_target_UID=true'in raw and 'owned_empty_child_removed=true'in raw and 'probe_failure_class'not in raw and 'cleanup_failure_class'not in raw, 'Original platform diagnosis incomplete'
with(private/'original-platform-probe-scope.json').open('x')as f:json.dump({'actual_original_release_variant_sandbox':True,'original_product_code_overlays':0,'disposable_CI_signature_only':True,'publisher_key_used':False,'platform_diagnosis_only_not_native_business_acceptance':True,'Main_changed':False},f,indent=2)
