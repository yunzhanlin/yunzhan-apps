"""Boot one new CI-only API37 emulator; never discover or reuse user devices."""
import hashlib,json,os,pathlib,subprocess,sys,time
os.umask(0o077)
assert os.environ.get('GITHUB_ACTIONS')=='true'and os.environ.get('GITHUB_REPOSITORY')=='yunzhanlin/yunzhan-apps'
private=pathlib.Path(sys.argv[1]).resolve(strict=True);sdk=pathlib.Path(os.environ['ANDROID_HOME']);cohort=os.environ['C68_UI_COHORT'];assert cohort=='QA3';name='Yunzhan_C68_owned_'+cohort
env=dict(os.environ);env['ANDROID_AVD_HOME']=str(private/'owned-avds');env['ANDROID_USER_HOME']=str(private/'owned-android-user');env['ANDROID_EMULATOR_HOME']=str(private/'owned-emulator-home')
for key in('ANDROID_AVD_HOME','ANDROID_USER_HOME','ANDROID_EMULATOR_HOME'):pathlib.Path(env[key]).mkdir(mode=0o700)
adb=str(sdk/'platform-tools/adb')
def once(label,args,input=None,timeout=90):
 with(private/(label+'.stdout')).open('xb')as out,(private/(label+'.stderr')).open('xb')as err:r=subprocess.run(args,input=input,env=env,stdout=out,stderr=err,timeout=timeout)
 with(private/(label+'-outcome.json')).open('x')as f:json.dump({'exit':r.returncode,'maximum_submissions':1},f)
 assert r.returncode==0,(label,r.returncode)
assert pathlib.Path('/dev/kvm').exists()and os.access('/dev/kvm',os.R_OK|os.W_OK)
devices=subprocess.check_output([adb,'devices'],env=env,text=True);assert devices.strip()=='List of devices attached'
once('one-owned-AVD-create',[str(sdk/'cmdline-tools/latest/bin/avdmanager'),'create','avd','--name',name,'--package','system-images;android-37.0;default;x86_64','--device','pixel_6'],input=b'no\n')
args=[str(sdk/'emulator/emulator'),'-avd',name,'-port','5554','-no-window','-no-audio','-no-boot-anim','-no-snapshot','-no-snapshot-save','-no-metrics','-memory','2048','-cores','2','-gpu','swiftshader','-netdelay','none','-netspeed','full']
with(private/'owned-emulator.stdout').open('xb')as out,(private/'owned-emulator.stderr').open('xb')as err:process=subprocess.Popen(args,env=env,stdin=subprocess.DEVNULL,stdout=out,stderr=err,start_new_session=True)
with(private/'owned-emulator-intent.json').open('x')as f:json.dump({'args':args,'pid':process.pid,'one_new_CI_emulator_only':True,'no_local_or_retained_guest_changed':True},f,indent=2)
deadline=time.monotonic()+300;observations=[]
while True:
 assert process.poll()is None,'Original emulator exited; do not replay'
 r=subprocess.run([adb,'-s','emulator-5554','shell','getprop','sys.boot_completed'],env=env,capture_output=True,text=True,timeout=10);observations.append({'exit':r.returncode,'boot_completed':r.stdout.strip(),'at':time.time()})
 if r.returncode==0 and r.stdout.strip()=='1':break
 assert time.monotonic()<deadline,'Original emulator boot unresolved';time.sleep(2)
with(private/'owned-emulator-boot-observations.json').open('x')as f:json.dump(observations,f,indent=2)
once('owned-emulator-display-size',[adb,'-s','emulator-5554','shell','wm','size','1080x2400'])
once('owned-emulator-display-density',[adb,'-s','emulator-5554','shell','wm','density','420'])
once('owned-emulator-initial-unlock',[adb,'-s','emulator-5554','shell','input','keyevent','82'])
once('owned-emulator-real-panel-reverse',[adb,'-s','emulator-5554','reverse','tcp:19100','tcp:19100'])
assert subprocess.check_output([adb,'-s','emulator-5554','shell','pm','list','packages','icu.yunzhan.panel'],env=env,text=True).strip()==''
once('one-original-debug-APK-install',[adb,'-s','emulator-5554','install',str(private/'original-debug.apk')])
# The original release bytes are tested with a separate disposable CI key.
# This deliberately cannot stand in for the retained publisher certificate.
once('owned-release-test-key',['keytool','-genkeypair','-keystore',str(private/'owned-release-test.p12'),'-storetype','PKCS12','-storepass','owned-test-only','-keypass','owned-test-only','-alias','owned-qa','-dname','CN=Disposable C68 release UI fixture','-keyalg','EC','-groupname','secp256r1','-validity','1'])
signer=str(sdk/'build-tools/36.0.0/apksigner')
once('owned-release-test-sign',[signer,'sign','--ks',str(private/'owned-release-test.p12'),'--ks-pass','pass:owned-test-only','--key-pass','pass:owned-test-only','--ks-key-alias','owned-qa','--out',str(private/'owned-release-test.apk'),str(private/'original-release-unsigned.apk')])
once('owned-release-test-signature-verify',[signer,'verify','--verbose','--print-certs',str(private/'owned-release-test.apk')])
certificate=(private/'owned-release-test-signature-verify.stdout').read_text();assert '0ba923afca85db94f4bdabd6d235fcf1c7088bb167ace661bf21781d1c7f0bd5'not in certificate
once('one-release-variant-owned-test-signature-install',[adb,'-s','emulator-5554','install',str(private/'owned-release-test.apk')])
with(private/'original-emulator-environment.json').open('x')as f:json.dump({'ok':True,'API':subprocess.check_output([adb,'-s','emulator-5554','shell','getprop','ro.build.version.sdk'],env=env,text=True).strip(),'name':name,'one_original_debug_APK_installed':True,'one_original_release_variant_with_disposable_test_signer_installed':True,'publisher_key_used':False,'physical_device':False},f,indent=2)
