#!/usr/bin/env python3
"""Validate actual native132 build outputs, not an assertion copied from logs."""
import argparse,json,os,pathlib,plistlib,re,subprocess,xml.etree.ElementTree as ET
a=argparse.ArgumentParser();a.add_argument('--android',type=pathlib.Path);a.add_argument('--swift-log',type=pathlib.Path);a.add_argument('--ios-bundle',type=pathlib.Path);args=a.parse_args()
if args.android:
 assert args.swift_log is None and args.ios_bundle is None
 root=args.android;out={'android_tests':{},'android_lint':{}}
 for variant in('Debug','Release'):
  files=sorted((root/'app/build/test-results'/('test'+variant+'UnitTest')).glob('TEST-*.xml'));assert len(files)==2
  total=0
  for file in files:
   suite=ET.parse(file).getroot();assert suite.tag=='testsuite'
   assert all(int(suite.attrib.get(k,'0'))==0 for k in('failures','errors','skipped'));total+=int(suite.attrib['tests'])
  assert total==16,(variant,total)
  out['android_tests'][variant]={'passed':total,'failed':0,'skipped':0}
 for variant in('debug','release'):
  report=ET.parse(root/('app/build/reports/lint-results-'+variant+'.xml')).getroot();assert report.tag=='issues'
  # A newline after "<issue" is ordinary XML. Never search only "<issue ".
  issues=report.findall('issue');assert not issues,[(v.get('id'),v.get('severity'))for v in issues]
  out['android_lint'][variant]={'issues':len(issues)}
 apk=root/'app/build/outputs/apk/release/app-release-unsigned.apk';assert apk.is_file()and 10000<apk.stat().st_size<4*1024*1024 and apk.read_bytes()[:4]==b'PK\x03\x04'
 metadata=json.loads((apk.parent/'output-metadata.json').read_bytes());assert metadata['applicationId']=='icu.yunzhan.panel'and metadata['variantName']=='release'and len(metadata['elements'])==1
 item=metadata['elements'][0];assert item['versionCode']==132 and item['versionName']=='1.3.2'
 tools=pathlib.Path(os.environ['ANDROID_HOME'])/'build-tools/36.0.0'
 manifest=subprocess.check_output([str(tools/'aapt2'),'dump','badging',str(apk)],text=True)
 assert re.search(r"^(?:minSdkVersion|sdkVersion):'30'$",manifest,re.M)and re.search(r"^targetSdkVersion:'37'$",manifest,re.M)and'application-debuggable'not in manifest
 signature=subprocess.run([str(tools/'apksigner'),'verify',str(apk)],capture_output=True,text=True);assert signature.returncode!=0 and'DOES NOT VERIFY'in signature.stderr
 out.update(ok=True,unsigned_release_APK_compiled=True,android_minSDK=30,android_targetSDK=37,release_debuggable=False,release_unsigned_verified=True,physical_device_or_biometric_acceptance=False)
else:
 assert args.swift_log and args.ios_bundle
 text=args.swift_log.read_text();assert 'Executed 16 tests, with 0 failures'in text and len(re.findall(r'Test Case .* started\.',text))==16
 bundle=args.ios_bundle;info=plistlib.loads((bundle/'Info.plist').read_bytes());assert info['CFBundleVersion']=='132'and info['CFBundleShortVersionString']=='1.3.2'and info['CFBundleIdentifier']=='icu.yunzhan.panel'
 binary=bundle/info['CFBundleExecutable'];arch=subprocess.check_output(['/usr/bin/lipo','-archs',str(binary)],text=True).strip();assert arch=='arm64'
 signature=subprocess.run(['/usr/bin/codesign','-dv',str(bundle)],capture_output=True,text=True);assert signature.returncode!=0 and 'not signed'in signature.stderr and not(bundle/'_CodeSignature').exists()
 out={'ok':True,'swift_tests':{'passed':16,'failed':0},'ios_unsigned_device_build':{'version':'1.3.2','arch':arch,'signed':False},'physical_device_or_biometric_acceptance':False}
print(json.dumps(out,sort_keys=True))
