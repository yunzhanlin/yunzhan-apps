"""Parse actual nonempty platform outputs; source checks never replace UI tests."""
import argparse,hashlib,json,pathlib,plistlib,re,subprocess,xml.etree.ElementTree as ET
p=argparse.ArgumentParser();p.add_argument('--android');p.add_argument('--swift-log');p.add_argument('--ios-bundle');a=p.parse_args()
assert bool(a.android)!=bool(a.swift_log or a.ios_bundle)
sha=lambda f:hashlib.sha256(pathlib.Path(f).read_bytes()).hexdigest()
records={}
if a.android:
 root=pathlib.Path(a.android)
 for variant in ('Debug','Release'):
  reports=sorted((root/'app/build/test-results'/('test'+variant+'UnitTest')).glob('TEST-*.xml'));assert len(reports)==5
  cases=[]
  for report in reports:
   suite=ET.parse(report).getroot();rows=suite.findall('testcase');assert rows and len(rows)==int(suite.attrib['tests'])
   assert all(int(suite.attrib.get(name,0))==0 for name in ('failures','errors','skipped'))
   cases.extend(v.attrib['classname']+'.'+v.attrib['name']for v in rows)
  assert len(cases)==len(set(cases))==38
  for name,total in [('ForegroundDownloadTest',13),('DownloadMetadataTest',4),('DownloadCacheTest',5),('PanelAddressTest',3),('SessionCallbacksTest',13)]:assert sum('.'+name+'.'in value for value in cases)==total,(name,cases)
  lint=root/'app/build/reports'/('lint-results-'+variant.lower()+'.xml');assert lint.is_file()and not ET.parse(lint).getroot().findall('issue')
  records[variant]={'tests':38,'failed':0,'skipped':0,'lint_issues':0,'cases':cases,'lint_sha256':sha(lint)}
 apks={}
 for name in ['app/build/outputs/apk/debug/app-debug.apk','app/build/outputs/apk/release/app-release-unsigned.apk']:
  f=root/name;assert f.is_file();apks[name]={'bytes':f.stat().st_size,'sha256':sha(f)}
 records['APKs']=apks
else:
 assert a.swift_log and a.ios_bundle;log=pathlib.Path(a.swift_log).read_text();assert 'Executed 36 tests, with 0 failures'in log
 started=re.findall(r"Test Case '([^']+)' started",log);passed=re.findall(r"Test Case '([^']+)' passed",log);assert len(started)==len(set(started))==len(passed)==36 and sorted(started)==sorted(passed)
 for name,total in [('NativeDownloadTests',11),('NativeDownloadMetadataTests',4),('NativeDownloadCacheTests',5),('PanelAddressTests',3),('SessionCallbacksTests',13)]:assert sum('.'+name+' 'in row for row in passed)==total,(name,passed)
 app=pathlib.Path(a.ios_bundle);info=plistlib.loads((app/'Info.plist').read_bytes());assert info['CFBundleShortVersionString']=='1.3.3'and info['CFBundleVersion']=='133'
 binary=app/info['CFBundleExecutable'];arch=subprocess.check_output(['/usr/bin/lipo','-archs',str(binary)],text=True).strip();assert arch=='arm64'
 result=subprocess.run(['/usr/bin/codesign','-dv',str(app)],capture_output=True,text=True);assert result.returncode!=0 and 'not signed at all'in result.stderr
 privacy=plistlib.loads((app/'PrivacyInfo.xcprivacy').read_bytes());assert privacy['NSPrivacyTracking']is False and len(privacy['NSPrivacyAccessedAPITypes'])==3
 records={'Swift_tests':36,'failed':0,'actual_test_cases':passed,'arm64_unsigned':True,'version':'1.3.3','binary_sha256':sha(binary),'privacy_sha256':sha(app/'PrivacyInfo.xcprivacy')}
print(json.dumps({'ok':True,'original_platform_outputs':records,'real_native_UI_or_device_acceptance':False,'all50_commercial':False},sort_keys=True))
