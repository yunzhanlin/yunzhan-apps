"""Build the unchanged Release client and drive its actual system UI in CI."""
import hashlib,json,os,pathlib,plistlib,runpy,subprocess,sys,time,traceback
os.umask(0o077)
assert os.environ.get('GITHUB_ACTIONS')=='true'and os.environ.get('GITHUB_REPOSITORY')=='yunzhanlin/yunzhan-apps'
base=pathlib.Path(__file__).resolve().parent;repo=base.parents[1];private=pathlib.Path(sys.argv[1]).resolve(strict=True);public_key=pathlib.Path(sys.argv[2]).resolve(strict=True);pins=json.loads((base/'pins.json').read_bytes());proof={'ok':False,'actual_iOS_UI_acceptance':False,'physical_device_acceptance':False,'biometric_success_acceptance':False,'Main_changed':False,'all50_commercial':False};device=None
def sha(f):return hashlib.sha256(pathlib.Path(f).read_bytes()).hexdigest()
def save(name,value):
 with(private/name).open('x')as f:json.dump(value,f,indent=2,sort_keys=True);f.write('\n')
def original(label,args,timeout=180):
 proof['last_original_stage']=label
 save(label+'-intent.json',{'args':args,'maximum_submissions':1})
 with(private/(label+'.stdout')).open('xb')as out,(private/(label+'.stderr')).open('xb')as err:r=subprocess.run(args,stdin=subprocess.DEVNULL,stdout=out,stderr=err,timeout=timeout,cwd=repo)
 save(label+'-outcome.json',{'exit':r.returncode,'stdout_sha256':sha(private/(label+'.stdout')),'stderr_sha256':sha(private/(label+'.stderr'))});assert r.returncode==0,label+' failed; retain original without replay'
 return(private/(label+'.stdout')).read_bytes()
try:
 exchange=runpy.run_path(str(base/'exchange.py'));peer=exchange['wait']('c68-ios-backend-dispatch-'+os.environ['GITHUB_RUN_ID'],private/'original-backend-dispatch',{'original-backend-dispatch.json','client-credentials.cms'})
 dispatch=json.loads((peer/'original-backend-dispatch.json').read_bytes());assert dispatch['head']==os.environ['GITHUB_SHA']and dispatch['run_id']==os.environ['GITHUB_RUN_ID']and dispatch['source_inputs_sha256']==pins['native_source_inputs_sha256']and dispatch['recipient_certificate_sha256']==sha(public_key/'client-public.pem')and dispatch['encrypted_credentials_sha256']==sha(peer/'client-credentials.cms')
 openssl=json.loads((private/'original-peer-key-provenance.json').read_bytes())['openssl'];credentials=private/'client-credentials.json'
 original('original-peer-envelope-decrypt',[openssl,'cms','-decrypt','-binary','-inform','DER','-in',str(peer/'client-credentials.cms'),'-recip',str(public_key/'client-public.pem'),'-inkey',str(private/'client-private.key'),'-out',str(credentials)])
 value=json.loads(credentials.read_bytes());assert value['panel_origin'].startswith('https://')and value['panel_origin'].endswith('.trycloudflare.com')and value['bytes']==131137 and value['native_source_inputs_sha256']==pins['native_source_inputs_sha256']
 original('original-Xcode-version',['/usr/bin/xcodebuild','-version'])
 runtimes=json.loads(subprocess.check_output(['xcrun','simctl','list','runtimes','--json']))['runtimes'];runtime=next(v for v in runtimes if v['identifier']=='com.apple.CoreSimulator.SimRuntime.iOS-18-5'and v['isAvailable'])
 device=subprocess.check_output(['xcrun','simctl','create','C68_owned_iOS_'+os.environ['GITHUB_RUN_ID'],'com.apple.CoreSimulator.SimDeviceType.iPhone-16-Pro',runtime['identifier']],text=True).strip();save('original-owned-simulator.json',{'UDID':device,'runtime':runtime,'one_new_CI_simulator':True,'no_local_or_retained_guest_changed':True})
 original('one-owned-simulator-boot',['xcrun','simctl','boot',device]);original('original-owned-simulator-boot-status',['xcrun','simctl','bootstatus',device,'-b'],240)
 original('original-source-integrity-before',['node','--test','tests/mobile-client-133.test.mjs'])
 client=private/'client-build';harness=private/'harness-build';destination='platform=iOS Simulator,id='+device
 original('original-Release-client-simulator-build',['xcodebuild','-quiet','-project','native-client-1.3.3/mobile/ios/YunzhanMobile.xcodeproj','-scheme','YunzhanMobile','-configuration','Release','-destination',destination,'-derivedDataPath',str(client),'-jobs','2','CODE_SIGNING_ALLOWED=NO','CODE_SIGNING_REQUIRED=NO','SWIFT_TREAT_WARNINGS_AS_ERRORS=YES','build'],900)
 original('original-independent-UI-runner-build',['xcodebuild','-quiet','-project','qa/native-mobile133-ios/C68NativeQA.xcodeproj','-scheme','C68NativeQA','-configuration','Release','-destination',destination,'-derivedDataPath',str(harness),'-jobs','2','CODE_SIGNING_ALLOWED=NO','CODE_SIGNING_REQUIRED=NO','build-for-testing'],900)
 app=client/'Build/Products/Release-iphonesimulator/YunzhanMobile.app';receiver=harness/'Build/Products/Release-iphonesimulator/C68 Receiver.app';info=plistlib.loads((app/'Info.plist').read_bytes());assert info['CFBundleShortVersionString']=='1.3.3'and info['CFBundleVersion']=='133'and info['CFBundleIdentifier']=='icu.yunzhan.panel'
 receiver_info=plistlib.loads((receiver/'Info.plist').read_bytes());assert receiver_info['CFBundleIdentifier']=='icu.yunzhan.qa.receiver'and receiver_info['CFBundleDisplayName']=='C68 Receiver'and receiver_info['UIFileSharingEnabled']is True and receiver_info['LSSupportsOpeningDocumentsInPlace']is True
 save('original-compiled-receiver-Info-metadata.json',{'Info_plist_sha256':sha(receiver/'Info.plist'),'CFBundleIdentifier':receiver_info['CFBundleIdentifier'],'CFBundleDisplayName':receiver_info['CFBundleDisplayName'],'UIFileSharingEnabled':receiver_info['UIFileSharingEnabled'],'LSSupportsOpeningDocumentsInPlace':receiver_info['LSSupportsOpeningDocumentsInPlace'],'DTXcode':receiver_info['DTXcode'],'DTSDKName':receiver_info['DTSDKName']})
 original('one-original-product-install',['xcrun','simctl','install',device,str(app)]);original('one-owned-provider-receiver-install',['xcrun','simctl','install',device,str(receiver)]);original('one-owned-provider-receiver-launch',['xcrun','simctl','launch',device,'icu.yunzhan.qa.receiver'])
 receiver_data=pathlib.Path(subprocess.check_output(['xcrun','simctl','get_app_container',device,'icu.yunzhan.qa.receiver','data'],text=True).strip())/'Documents';marker=receiver_data/'C68-original-receiver-marker.txt';end=time.monotonic()+20
 while not marker.exists():assert time.monotonic()<end;time.sleep(.3)
 assert marker.read_bytes()==b'C68 owned provider original marker\n';marker_original={'bytes':marker.read_bytes().hex(),'inode':marker.stat().st_ino,'mtime_ns':marker.stat().st_mtime_ns};save('original-receiver-before-UI.json',marker_original)
 candidates=list((harness/'Build/Products').glob('*.xctestrun'));assert len(candidates)==1;xctest=plistlib.loads(candidates[0].read_bytes());targets=[v for k,v in xctest.items()if k!='__xctestrun_metadata__'];assert len(targets)==1 and targets[0]['BlueprintName']=='C68NativeUITests'and targets[0]['IsUITestBundle']and targets[0]['UseUITargetAppProvidedByTests']
 targets[0]['EnvironmentVariables'].update({'C68_PANEL_HTTPS':value['panel_origin'],'C68_PANEL_USERNAME':value['username'],'C68_PANEL_PASSWORD':value['password'],'C68_ATTACHMENT_FILENAME':value['filename']});candidates[0].write_bytes(plistlib.dumps(xctest))
 result=private/'original-native-UI.xcresult'
 original('one-original-Release-HTTPS-native-UI',['xcodebuild','-quiet','test-without-building','-xctestrun',str(candidates[0]),'-destination',destination,'-parallel-testing-enabled','NO','-maximum-concurrent-test-simulator-destinations','1','-resultBundlePath',str(result)],900)
 summary=json.loads(original('original-XCTest-result-summary',['xcrun','xcresulttool','get','test-results','summary','--path',str(result)]));save('original-XCTest-summary.json',summary)
 assert summary['totalTestCount']==summary['passedTests']==1 and summary['failedTests']==summary['skippedTests']==0
 exported=receiver_data/value['filename'];end=time.monotonic()+20
 while not(exported.exists()and exported.stat().st_size==value['bytes']):assert time.monotonic()<end;time.sleep(.3)
 assert exported.is_file()and exported.stat().st_nlink==1 and sha(exported)==value['sha256']
 assert {'bytes':marker.read_bytes().hex(),'inode':marker.stat().st_ino,'mtime_ns':marker.stat().st_mtime_ns}==marker_original
 native_data=pathlib.Path(subprocess.check_output(['xcrun','simctl','get_app_container',device,'icu.yunzhan.panel','data'],text=True).strip());cache=native_data/'Library/Caches/native-downloads';assert cache.is_dir()and cache.stat().st_mode&0o777==0o700 and not list(cache.iterdir())
 save('original-independent-system-provider-bytes.json',{'bytes':exported.stat().st_size,'sha256':sha(exported),'original_receiver_marker_preserved':True,'product_private_cache_empty_after_explicit_disconnect':True,'ordinary_system_file_provider':True,'public_TLS_real_signed_Linux_panel':True,'native_product_source_overlays':0,'iOS_provider_ack_is_not_product_readback_or_cloud_sync_guarantee':True})
 original('original-source-integrity-after',['node','--test','tests/mobile-client-133.test.mjs'])
 proof.update(ok=True,actual_iOS_UI_acceptance=True,actual_iOS_simulator='18.5',original_Release_client=True,ordinary_OS_public_TLS_real_panel_login=True,actual_file_manager_download_and_system_provider_export=True,independent_provider_original_bytes_verified=True,cancel_and_resave_and_actual_background_accessibility_concealment=True,actual_release_HTTP_refusal=True,source_inputs_sha256=pins['native_source_inputs_sha256'],original_XCTest_total=1,original_XCTest_passed=1,original_XCTest_skipped=0)
except BaseException:
 save('original-client-UI-failure.json',{'traceback':traceback.format_exc()})
 print(json.dumps({'original_failure_stage':proof.get('last_original_stage','original-peer-or-platform-preparation'),'original_outcome_replayed':False}),flush=True)
 raise
finally:
 # Keep the original XCTest outcome diagnosable even when xcodebuild failed.
 # These are bounded reads of the completed result, never another test run.
 try:
  if 'result'in locals()and result.is_dir():
   def read_result(label,arguments,json_output=True):
    save(label+'-intent.json',{'args':arguments,'readonly_original_result':True,'maximum_submissions':1})
    with(private/(label+'.stdout')).open('xb')as out,(private/(label+'.stderr')).open('xb')as err:r=subprocess.run(arguments,stdin=subprocess.DEVNULL,stdout=out,stderr=err,timeout=60,cwd=repo)
    save(label+'-outcome.json',{'exit':r.returncode,'stdout_sha256':sha(private/(label+'.stdout')),'stderr_sha256':sha(private/(label+'.stderr'))})
    assert r.returncode==0,'Original XCTest diagnostic read failed'
    raw=(private/(label+'.stdout')).read_bytes()
    return json.loads(raw)if json_output else raw
   read_result('original-XCTest-final-summary',['xcrun','xcresulttool','get','test-results','summary','--path',str(result)])
   tree=read_result('original-XCTest-final-tree',['xcrun','xcresulttool','get','test-results','tests','--path',str(result)])
   identifiers=set()
   def visit(value):
    if isinstance(value,dict):
     identity=value.get('nodeIdentifier')
     if isinstance(identity,str)and 'testOriginalReleaseHTTPSFileManagementExportAndBackgroundPrivacy'in identity:identifiers.add(identity)
     for child in value.values():visit(child)
    elif isinstance(value,list):
     for child in value:visit(child)
   visit(tree);assert len(identifiers)==1,'Original test identifier must be unique'
   read_result('original-XCTest-final-details',['xcrun','xcresulttool','get','test-results','test-details','--path',str(result),'--test-id',next(iter(identifiers))])
   exports=private/'original-AX-exports'
   read_result('original-XCTest-export-attachments',['xcrun','xcresulttool','export','attachments','--path',str(result),'--output-path',str(exports)],False)
   attachment_index=json.loads((exports/'manifest.json').read_bytes());copied=[];total=0
   for test in attachment_index:
    for attachment in test['attachments']:
     if 'original-accessibility'not in attachment['suggestedHumanReadableName']:continue
     name=attachment['exportedFileName'];assert len(pathlib.PurePosixPath(name).parts)==1 and name.endswith('.txt')
     source=exports/name;assert source.is_file()and not source.is_symlink()and source.stat().st_nlink==1 and source.stat().st_size<1<<20
     raw=source.read_bytes();total+=len(raw);assert total<4<<20 and len(copied)<64
     target='original-UI-accessibility-%03d.stdout'%len(copied)
     with(private/target).open('xb')as f:f.write(raw)
     copied.append({'original_attachment':attachment,'exact_copied_member':target,'sha256':sha(source),'bytes':len(raw)})
   save('original-XCTest-accessibility-copies.json',{'original_manifest_sha256':sha(exports/'manifest.json'),'byte_exact_original_attachments':copied})
 except BaseException:save('original-XCTest-final-diagnostic-read-failure.json',{'traceback':traceback.format_exc()})
 try:
  if 'receiver_data'in locals()and receiver_data.is_dir():
   entries=list(receiver_data.iterdir());assert len(entries)<=128
   save('original-system-provider-final-observation.json',{f.name:{'bytes':f.stat().st_size,'sha256':sha(f),'inode':f.stat().st_ino,'mtime_ns':f.stat().st_mtime_ns}for f in entries if f.is_file()and f.stat().st_size<16<<20})
 except BaseException:save('original-provider-final-observation-failure.json',{'traceback':traceback.format_exc()})
 if device:
  r=subprocess.run(['xcrun','simctl','shutdown',device],stdin=subprocess.DEVNULL,capture_output=True,timeout=60);proof['owned_simulator_shutdown_exit']=r.returncode
  if r.returncode!=0:proof['ok']=False
 save('original-client-UI-proof.json',proof)
print(json.dumps(proof))
