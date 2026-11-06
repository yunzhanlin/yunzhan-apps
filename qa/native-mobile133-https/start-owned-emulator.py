"""Boot one new CI-only API37 emulator; never discover or reuse user devices."""
import hashlib,json,os,pathlib,subprocess,sys,time
os.umask(0o077)
assert os.environ.get('GITHUB_ACTIONS')=='true'and os.environ.get('GITHUB_REPOSITORY')=='yunzhanlin/yunzhan-apps'
private=pathlib.Path(sys.argv[1]).resolve(strict=True);sdk=pathlib.Path(os.environ['ANDROID_HOME']);cohort=os.environ['C68_UI_COHORT'];assert cohort=='HTTPSQA8';api=int(os.environ['C68_UI_API']);assert api in(30,37);platform={30:'android-30',37:'android-37.0'}[api];name='Yunzhan_C68_owned_'+cohort+'_API'+str(api)
env=dict(os.environ);env['ANDROID_AVD_HOME']=str(private/'owned-avds');env['ANDROID_USER_HOME']=str(private/'owned-android-user');env['ANDROID_EMULATOR_HOME']=str(private/'owned-emulator-home')
for key in('ANDROID_AVD_HOME','ANDROID_USER_HOME','ANDROID_EMULATOR_HOME'):pathlib.Path(env[key]).mkdir(mode=0o700)
adb=str(sdk/'platform-tools/adb')
def once(label,args,input=None,timeout=90):
 with(private/(label+'.stdout')).open('xb')as out,(private/(label+'.stderr')).open('xb')as err:r=subprocess.run(args,input=input,env=env,stdout=out,stderr=err,timeout=timeout)
 with(private/(label+'-outcome.json')).open('x')as f:json.dump({'exit':r.returncode,'maximum_submissions':1},f)
 assert r.returncode==0,(label,r.returncode)
assert pathlib.Path('/dev/kvm').exists()and os.access('/dev/kvm',os.R_OK|os.W_OK)
devices=subprocess.check_output([adb,'devices'],env=env,text=True);assert devices.strip()=='List of devices attached'
once('one-owned-AVD-create',[str(sdk/'cmdline-tools/latest/bin/avdmanager'),'create','avd','--name',name,'--package','system-images;'+platform+';default;x86_64','--device','pixel_6'],input=b'no\n')
args=[str(sdk/'emulator/emulator'),'-avd',name,'-port','5554','-no-window','-no-audio','-no-boot-anim','-no-snapshot','-no-snapshot-save','-no-metrics','-memory','3072','-cores','2','-gpu','swiftshader','-netdelay','none','-netspeed','full']
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
assert subprocess.check_output([adb,'-s','emulator-5554','shell','pm','list','packages','icu.yunzhan.panel'],env=env,text=True).strip()==''
once('original-publisher-APK-signer-verification',[str(sdk/'build-tools/36.0.0/apksigner'),'verify','--min-sdk-version','30','--max-sdk-version','37','--verbose','--print-certs',str(private/'original-publisher.apk')])
certificate=(private/'original-publisher-APK-signer-verification.stdout').read_text();assert 'Signer #1 certificate SHA-256 digest: 0ba923afca85db94f4bdabd6d235fcf1c7088bb167ace661bf21781d1c7f0bd5'in certificate
once('one-original-retained-publisher-APK-install',[adb,'-s','emulator-5554','install',str(private/'original-publisher.apk')])
# Finish the fresh system launch before beginning any product acceptance.
# An OS launcher ANR is retained as a failure, never dismissed or counted as an
# application pass. This changes only the new disposable CI emulator.
once('original-owned-system-home-ready',[adb,'-s','emulator-5554','shell','am','start','-W','-a','android.intent.action.MAIN','-c','android.intent.category.HOME'])
once('original-owned-system-home-window',[adb,'-s','emulator-5554','shell','dumpsys','window'])
window=(private/'original-owned-system-home-window.stdout').read_text()
assert 'Application Not Responding:'not in window and 'Application Error:'not in window,'Original owned system UI unhealthy; no product acceptance started'
with(private/'original-emulator-environment.json').open('x')as f:json.dump({'ok':True,'API':subprocess.check_output([adb,'-s','emulator-5554','shell','getprop','ro.build.version.sdk'],env=env,text=True).strip(),'name':name,'one_original_retained_publisher_Release_APK_installed':True,'CI_fixture_signer_used':False,'publisher_key_used':False,'physical_device':False},f,indent=2)

once('original-owned-WebView-before-UI',[adb,'-s','emulator-5554','shell','dumpsys','webviewupdate'])
