"""Read the untouched provider from one official disposable API35 SDK image.

No private keys, resigning, provider selection, system replacement, root adb,
or production runtime. Stop this one emulator before the API30 case starts.
"""
import hashlib,json,os,pathlib,re,subprocess,sys,time
os.umask(0o077)
assert os.geteuid()!=0 and os.environ.get('GITHUB_ACTIONS')=='true'and os.environ.get('GITHUB_REPOSITORY')=='yunzhanlin/yunzhan-apps'and os.environ['C68_UI_API']=='30'
private=pathlib.Path(sys.argv[1]).resolve(strict=True);sdk=pathlib.Path(os.environ['ANDROID_HOME']);adb=sdk/'platform-tools/adb';name='C68_owned_provider35_'+os.environ['GITHUB_RUN_ID'];env=dict(os.environ)
for variable,directory in [('ANDROID_AVD_HOME','provider35-avds'),('ANDROID_USER_HOME','provider35-user'),('ANDROID_EMULATOR_HOME','provider35-home')]:
 env[variable]=str(private/directory);pathlib.Path(env[variable]).mkdir(mode=0o700)
def observe(label,args,input=None,timeout=90):
 stream={'input':input}if input is not None else{'stdin':subprocess.DEVNULL}
 with(private/(label+'.stdout')).open('xb')as out,(private/(label+'.stderr')).open('xb')as err:result=subprocess.run([str(v)for v in args],env=env,stdout=out,stderr=err,timeout=timeout,**stream)
 with(private/(label+'-outcome.json')).open('x')as f:json.dump({'exit':result.returncode,'maximum_submissions':1},f)
 assert result.returncode==0,label+' failed; retain original'
 return(private/(label+'.stdout')).read_text()
assert subprocess.check_output([str(adb),'devices'],env=env,text=True).strip()=='List of devices attached'
observe('one-owned-provider35-create',[sdk/'cmdline-tools/latest/bin/avdmanager','create','avd','--name',name,'--package','system-images;android-35;default;x86_64','--device','pixel_6'],input=b'no\n')
args=[sdk/'emulator/emulator','-avd',name,'-port','5554','-no-window','-no-audio','-no-boot-anim','-no-snapshot','-no-snapshot-save','-no-metrics','-memory','2048','-cores','2','-gpu','swiftshader']
process=None
try:
 with(private/'original-owned-provider35-boot.stdout').open('xb')as out,(private/'original-owned-provider35-boot.stderr').open('xb')as err:process=subprocess.Popen([str(v)for v in args],env=env,stdin=subprocess.DEVNULL,stdout=out,stderr=err,start_new_session=True)
 deadline=time.monotonic()+300
 while True:
  assert process.poll()is None,'Original owned provider35 emulator exited'
  result=subprocess.run([str(adb),'-s','emulator-5554','shell','getprop','sys.boot_completed'],capture_output=True,text=True,timeout=10,env=env)
  if result.returncode==0 and result.stdout.strip()=='1':break
  assert time.monotonic()<deadline;time.sleep(2)
 assert subprocess.check_output([str(adb),'-s','emulator-5554','emu','avd','name'],env=env,text=True).splitlines()[0]==name
 observe('original-owned-provider35-runtime',[adb,'-s','emulator-5554','shell','dumpsys','webviewupdate'])
 source=observe('original-owned-provider35-APK-path',[adb,'-s','emulator-5554','shell','pm','path','com.android.webview']).strip().splitlines();assert len(source)==1 and source[0].startswith(('package:/system/','package:/product/'))and source[0].endswith('.apk')
 original_path=source[0].removeprefix('package:')
 observe('original-owned-provider35-adb-version',[adb,'version'])
 observe('original-owned-provider35-file-metadata',[adb,'-s','emulator-5554','shell','ls','-l',original_path])
 observe('original-owned-provider35-file-digest',[adb,'-s','emulator-5554','shell','sha256sum',original_path])
 apk=private/'original-owned-SDK-WebView35.apk';available=os.statvfs(private);before_available=available.f_bavail*available.f_frsize
 assert before_available>512<<20,'Owned CI host has insufficient space for this read-only fixture'
 # The SDK sync pull intermittently ended with exit1 and a partial progress
 # line. Read the same ordinary shell-readable bytes through exec-out and
 # independently require the original on-device digest below.
 with apk.open('xb')as output,(private/'original-owned-provider35-APK-read.stderr').open('xb')as error:copied=subprocess.run([str(adb),'-s','emulator-5554','exec-out','cat',original_path],stdin=subprocess.DEVNULL,stdout=output,stderr=error,env=env,timeout=180)
 available=os.statvfs(private)
 with(private/'original-owned-provider35-APK-read-outcome.json').open('x')as f:json.dump({'exit':copied.returncode,'bytes_read':apk.stat().st_size,'host_available_before':before_available,'host_available_after':available.f_bavail*available.f_frsize,'original_readonly_shell_stream':True,'maximum_submissions':1},f)
 assert copied.returncode==0 and apk.is_file()and not apk.is_symlink()and apk.stat().st_nlink==1 and 0<apk.stat().st_size<512<<20
 tools=sdk/'build-tools/36.0.0';signer=observe('original-owned-provider35-signature',[tools/'apksigner','verify','--min-sdk-version','30','--max-sdk-version','37','--verbose','--print-certs',apk]);cert=re.findall(r'^Signer #1 certificate SHA-256 digest: ([a-f0-9]{64})$',signer,re.M);assert len(cert)==1
 metadata=observe('original-owned-provider35-metadata',[tools/'aapt2','dump','badging',apk]);version=re.search(r"package: name='com.android.webview' versionCode='([0-9]+)' versionName='([0-9.]+)'",metadata);minimum=re.search(r"minSdkVersion:'([0-9]+)'",metadata);assert version and minimum
 digest=hashlib.sha256()
 with apk.open('rb')as f:
  for block in iter(lambda:f.read(1<<20),b''):digest.update(block)
 record={'ok':int(minimum[1])<=30 and int(version[2].split('.')[0])>=111,'original_official_SDK_package':'system-images;android-35;default;x86_64','source_properties':(sdk/'system-images/android-35/default/x86_64/source.properties').read_text(),'package':'com.android.webview','version_code':version[1],'version':version[2],'min_sdk':int(minimum[1]),'bytes':apk.stat().st_size,'sha256':digest.hexdigest(),'certificate_sha256':cert[0],'original_provider_only_read_not_changed':True,'owned_CI_fixture_only_not_production_browser_recommendation':True,'no_resigning_or_provider_selection_or_root_adb':True}
 assert record['sha256']==(private/'original-owned-provider35-file-digest.stdout').read_text().split()[0]
 with(private/'original-official-SDK-WebView35-provenance.json').open('x')as f:json.dump(record,f,indent=2)
 assert record['ok'],'Official SDK provider is not compatible with this API30 test'
finally:
 if process is not None and process.poll()is None:
  assert subprocess.check_output([str(adb),'-s','emulator-5554','emu','avd','name'],env=env,text=True).splitlines()[0]==name
  observe('one-owned-provider35-shutdown',[adb,'-s','emulator-5554','emu','kill'])
  process.wait(timeout=40)
  deadline=time.monotonic()+20
  while subprocess.check_output([str(adb),'devices'],env=env,text=True).strip()!='List of devices attached':assert time.monotonic()<deadline;time.sleep(.3)
