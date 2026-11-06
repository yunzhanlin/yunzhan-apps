"""Use real Android OS controls against the original APK and real panel.

This is a disposable API37 emulator using the unchanged publisher-signed Release APK and ordinary public HTTPS, not physical-device or iOS acceptance.
No JavaScript injection, web debugging, session injection or app test overlay.
"""
import hashlib,json,os,pathlib,re,secrets,shlex,subprocess,sys,time,traceback,xml.etree.ElementTree as ET
os.umask(0o077)
assert os.environ.get('GITHUB_ACTIONS')=='true'and os.environ.get('GITHUB_REPOSITORY')=='yunzhanlin/yunzhan-apps'
private=pathlib.Path(sys.argv[1]).resolve(strict=True);adb=os.environ['ANDROID_HOME']+'/platform-tools/adb';serial='emulator-5554';package='icu.yunzhan.panel'
setup=json.loads((private/'real-panel-setup.json').read_bytes());access=json.loads((private/'device-credentials.json').read_bytes());assert setup['real_file_manager_backend'] and setup['panel_origin']=='http://127.0.0.1:19100'
https=json.loads((private/'original-HTTPS-origin.json').read_bytes());assert https['ok']and https['origin'].startswith('https://')and https['origin'].endswith('.trycloudflare.com')and https['source_inputs_sha256']==setup['native_source_inputs_sha256']
setup={**setup,'panel_origin':https['origin']}
pin=None;events=[];sequence=0;reads=0;commands=0
def command(*args,raw=False):
 global commands
 r=subprocess.run([adb,'-s',serial,*args],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=40)
 if args[0]=='pull'or args[:2]==('shell','uiautomator')or r.returncode!=0:
  commands+=1
  def redacted(data):
   value=data.decode(errors='replace')
   for secret in[access['password'],pin]:
    if secret:value=value.replace(secret,'[private]')
   return value
  save('original-adb-command-%05d.json'%commands,{'operation':args[0],'exit':r.returncode,'original_stdout_redacted':redacted(r.stdout),'original_stderr_redacted':redacted(r.stderr)})
 assert r.returncode==0,'Owned emulator command failed: '+args[0]
 if args[:2]==('shell','uiautomator'):return(r.stdout.decode(),r.stderr.decode())
 return r.stdout if raw else r.stdout.decode()
api=int(os.environ['C68_UI_API']);assert api in(30,37)and command('shell','getprop','ro.build.version.sdk').strip()==str(api)
cohort=os.environ['C68_UI_COHORT'];assert cohort=='UPGRADEQA1'
assert command('emu','avd','name').strip().splitlines()[0]=='Yunzhan_C68_owned_'+cohort+'_API'+str(api)
def save(name,value):
 with(private/name).open('x')as f:json.dump(value,f,indent=2,ensure_ascii=False);f.write('\n')
def snapshot(label=None):
 global sequence,reads
 reads+=1;original=private/('original-UI-read-%05d.xml'%reads)
 end=time.monotonic()+45
 while True:
  outcome,error=command('shell','uiautomator','dump','/data/local/tmp/c68-owned-UI.xml')
  if 'dumped to:'in outcome:break
  # A cold activity can still be in its SplashScreen transition. Preserve the
  # actual null-root observation and repeat only this read; never manufacture
  # a hierarchy, authorize a tap, or relaunch the app as a substitute.
  assert not outcome.strip()and error.strip()=='ERROR: null root node returned by UiTestAutomationBridge.','Original UI dump failed for an unqualified reason'
  assert time.monotonic()<end,'Original activity never produced a real UI root';time.sleep(.5)
 # File-sync transport preserves the actual XML bytes, rather than combining
 # an exec-out shell's diagnostics with its file content. Keep every original.
 command('pull','/data/local/tmp/c68-owned-UI.xml',str(original));original.chmod(0o600)
 assert original.is_file()and original.stat().st_nlink==1 and 0<original.stat().st_size<1<<20
 raw=original.read_bytes();root=ET.fromstring(raw)
 for n in root.iter('node'):
  for key,value in list(n.attrib.items()):
   for secret in [access['password'],pin]:
    if secret:value=value.replace(secret,'[private]')
   if n.attrib.get('password')=='true' and key in('text','content-desc'):value='[secure field]'
   n.set(key,value)
 if label:
  sequence+=1;save('%03d-%s-AX.json'%(sequence,label),[n.attrib for n in root.iter('node')])
 return root
def nodes(root,predicate):return[n for n in root.iter('node')if predicate(n.attrib)]
def matches(n,text):
 if n.get('text')==text or n.get('content-desc')==text:return True
 # The original Material native Button transforms its English source string
 # to uppercase in the accessibility tree. Do not fold filenames, URLs, web
 # fields, or other text; those must still preserve their exact original case.
 return text.isascii()and n.get('class')=='android.widget.Button'and(n.get('text')==text.upper()or n.get('content-desc')==text.upper())
def wait(label,predicate,seconds=50):
 end=time.monotonic()+seconds
 while True:
  root=snapshot()
  if predicate(root):snapshot(label);return root
  if time.monotonic()>=end:snapshot('FAILED-'+label);raise AssertionError('Original UI condition did not occur: '+label)
  time.sleep(.4)
def point(n):
 b=re.fullmatch(r'\[(\d+),(\d+)\]\[(\d+),(\d+)\]',n.attrib['bounds']);assert b
 x1,y1,x2,y2=map(int,b.groups());assert x2>x1 and y2>y1
 return((x1+x2)//2,(y1+y2)//2)
def tap_node(n,label):
 x,y=point(n);command('shell','input','tap',str(x),str(y));events.append({'action':label,'one_tap':True})
def tap(text,root=None):
 root=snapshot()if root is None else root;found=nodes(root,lambda n:matches(n,text));assert len(found)==1,'Observed UI target must be unique: '+text;tap_node(found[0],text)
def type_ascii(value):
 assert re.fullmatch('[A-Za-z0-9_:/.-]+',value),'Only owned ASCII fixture input'
 command('shell','input','text',value)
def key(code):command('shell','input','keyevent',str(code))
def start():command('shell','am','start','-W','-n',package+'/icu.yunzhan.panel.PanelActivity')
def has(root,text):return bool(nodes(root,lambda n:matches(n,text)))
def web_scroll():
 root=snapshot();views=nodes(root,lambda n:n.get('class')=='android.webkit.WebView');assert views
 b=re.findall(r'\d+',views[0].attrib['bounds']);x1,y1,x2,y2=map(int,b);command('shell','input','swipe',str((x1+x2)//2),str(y2-30),str((x1+x2)//2),str(y1+30),'350')
def login():
 root=wait('real-panel-login-form',lambda r:bool(nodes(r,lambda n:n.get('resource-id')=='username'or n.get('text')=='管理员用户名')))
 user=nodes(root,lambda n:n.get('resource-id')=='username'or n.get('text')=='管理员用户名');assert len(user)==1
 existing=user[0].attrib.get('text','')
 if existing!=access['username']:
  tap_node(user[0],'owned-web-username')
  if existing not in('','管理员用户名'):
   assert len(existing)<=64;key(123);command('shell','input','keyevent',*(['67']*(len(existing)+1)))
  type_ascii(access['username'])
 else:events.append({'action':'original-prefilled-username-already-exact','extra_characters_entered':0})
 root=snapshot();passwords=nodes(root,lambda n:n.get('password')=='true'and n.get('class')=='android.widget.EditText');assert len(passwords)==1;tap_node(passwords[0],'owned-web-password');type_ascii(access['password']);key(4)
 for _ in range(5):
  root=snapshot();buttons=nodes(root,lambda n:matches(n,'进入工作台'))
  if len(buttons)==1:
   try:point(buttons[0]);break
   except AssertionError:pass
  web_scroll()
 else:raise AssertionError('Real login submit not visible')
 tap('进入工作台',root);wait('real-panel-authenticated-menu',lambda r:has(r,'展开导航')or has(r,'收起导航'),90)
def open_files():
 root=snapshot()
 if has(root,'展开导航'):tap('展开导航',root)
 root=wait('real-panel-files-navigation',lambda r:has(r,'文件'));tap('文件',root)
 for _ in range(6):
  root=snapshot()
  if has(root,setup['filename']):break
  web_scroll()
 else:raise AssertionError('Original real file listing not visible')
 snapshot('real-owned-binary-listed')
def download():
 root=snapshot();parents={c:p for p in root.iter()for c in p};found=nodes(root,lambda n:matches(n,setup['filename']));assert len(found)==1
 ancestor=found[0];target=None
 while ancestor in parents:
  ancestor=parents[ancestor];links=nodes(ancestor,lambda n:matches(n,'下载')and n.get('clickable')=='true')
  if len(links)==1:target=links[0];break
 assert target is not None,'Original real file download control must belong to its row';tap_node(target,'real-file-download')
 root=wait('native-download-confirmation',lambda r:has(r,'Confirm'));tap('Confirm',root)
 wait('native-download-ready',lambda r:bool(nodes(r,lambda n:matches(n,'Choose save location')and n.get('enabled')=='true')))
def lock_assert(label):
 root=wait(label,lambda r:has(r,'Unlock panel'))
 assert not nodes(root,lambda n:n.get('class')=='android.webkit.WebView')
 assert not any(setup['filename']in(n.get('text','')+n.get('content-desc',''))for n in root.iter('node'))
 assert not has(root,'Choose save location')
def unlock():
 tap('Unlock panel');root=wait('system-device-authentication',lambda r:has(r,'Unlock Yunzhan Panel')or bool(nodes(r,lambda n:n.get('package')=='com.android.systemui'and n.get('password')=='true')))
 fields=nodes(root,lambda n:n.get('package')=='com.android.systemui'and n.get('password')=='true')
 if len(fields)==1:tap_node(fields[0],'system-device-PIN');type_ascii(pin);key(66)
 else:
  assert has(root,'Unlock Yunzhan Panel')
  for digit in pin:
   keys=nodes(root,lambda n:n.get('package')=='com.android.systemui'and n.get('text')==digit);assert len(keys)==1;tap_node(keys[0],'system-device-credential-key')
  tap('Enter',root)
 wait('same-session-unlocked',lambda r:has(r,'Clear session'))
def chosen_file(name):
 assert name in(setup['filename'],'C68-late-result.bin')
 listing=command('shell','find','/sdcard/Download','-maxdepth','1','-type','f').splitlines();paths=[s for s in listing if pathlib.PurePosixPath(s).name==name];assert len(paths)<=1
 return None if not paths else command('exec-out','cat',paths[0],raw=True)
def owned_app_pid():
 r=subprocess.run([adb,'-s',serial,'shell','pidof',package],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=15)
 value=r.stdout.decode().strip();assert r.returncode in(0,1)and not r.stderr.strip()
 if not value:assert r.returncode==1;return None
 assert r.returncode==0 and re.fullmatch('[1-9][0-9]*',value),'Only one exact owned app process is allowed'
 return value
def picker():
 tap('Choose save location');root=wait('system-create-document',lambda r:bool(nodes(r,lambda n:'documentsui'in n.get('package',''))))
 return root
def choose_downloads(root):
 controls=nodes(root,lambda n:n.get('content-desc')in('Show roots','Open navigation drawer'))
 assert len(controls)==1,'Original DocumentsUI navigation control required';tap_node(controls[0],'system-document-roots')
 # The original OS exposes "Downloads" in its toolbar, breadcrumb and root
 # drawer. Select the observed drawer item, never an arbitrary text match.
 def roots(r):return nodes(r,lambda n:n.get('package')=='com.android.documentsui'and n.get('resource-id')=='android:id/title'and n.get('text')=='Downloads')
 root=wait('system-downloads-root',lambda r:len(roots(r))==1);tap_node(roots(root)[0],'system-Downloads-directory-item')
 return wait('system-downloads-save',lambda r:not roots(r)and(has(r,'SAVE')or has(r,'Save')))

proof={'ok':False,'actual_Android_emulator_API':api,'physical_device_acceptance':False,'Main_changed':False,'all50_commercial':False}
try:
 start();root=wait('original132-native-start',lambda r:has(r,'Connect'))
 fields=nodes(root,lambda n:n.get('class')=='android.widget.EditText'and n.get('enabled')=='true');assert len(fields)==1;tap_node(fields[0],'original132-owned-panel-endpoint');type_ascii(setup['panel_origin']+'/');key(4);tap('Connect')
 login();snapshot('original132-actual-HTTPS-authenticated-before-upgrade')
 old_pid=owned_app_pid();assert old_pid is not None
 old_uid=command('shell','cmd','package','list','packages','-U',package).strip();assert re.fullmatch(r'package:icu\.yunzhan\.panel uid:[0-9]+',old_uid)
 old_metadata=command('shell','dumpsys','package',package);assert 'versionCode=132'in old_metadata and 'versionName=1.3.2'in old_metadata
 save('original132-package-before-upgrade.json',{'pid':old_pid,'UID_line':old_uid,'original_package_metadata':old_metadata,'ordinary_HTTPS_authenticated_UI_observed':True})
 key(3)
 # The package manager's ordinary preserving upgrade, not reinstall-after-
 # uninstall, data clearing, downgrade flags or a debug-signed substitute.
 result=command('install','-r',str(private/'original-publisher.apk'));assert 'Success'in result
 save('one-original-normal-APK-upgrade.json',{'maximum_submissions':1,'original_stdout':result,'original_old_PID':old_pid,'data_clear_or_uninstall_or_resigning':False})
 new_uid=command('shell','cmd','package','list','packages','-U',package).strip();assert new_uid==old_uid
 new_metadata=command('shell','dumpsys','package',package);assert 'versionCode=133'in new_metadata and 'versionName=1.3.3'in new_metadata
 start();root=wait('original133-no-implicit-old-WebView',lambda r:has(r,'Connect')and not nodes(r,lambda n:n.get('class')=='android.webkit.WebView'))
 fields=nodes(root,lambda n:n.get('class')=='android.widget.EditText'and n.get('enabled')=='true');assert len(fields)==1 and fields[0].attrib.get('text')==setup['panel_origin']+'/'
 new_pid=owned_app_pid();assert new_pid is not None and new_pid!=old_pid
 save('original133-package-after-preserving-upgrade.json',{'pid':new_pid,'UID_line':new_uid,'original_package_metadata':new_metadata,'saved_original_endpoint_preference_preserved':True,'initial_WebViews':0,'original_endpoint':setup['panel_origin']+'/'})
 tap('Connect',root)
 root=wait('original133-requires-original-normal-login-again',lambda r:bool(nodes(r,lambda n:n.get('resource-id')=='username'or n.get('text')=='管理员用户名')))
 assert nodes(root,lambda n:n.get('password')=='true'and n.get('class')=='android.widget.EditText')
 proof.update(ok=True,actual_132_to133_normal_APK_upgrade=True,private_endpoint_preference_preserved=True,original_device_UID_preserved=True,old_process_gone_and_original_new_process_observed=True,original_login_not_restored_implicitly=True,original_new_APK_and_publisher_same=True,ordinary_public_HTTPS_before_and_after=True,source_inputs_sha256=setup['native_source_inputs_sha256'])
except BaseException:save('original-UI-failure.json',{'traceback':traceback.format_exc()});raise
finally:
 save('original-device-events.json',events);save('original-device-UI-proof.json',proof)
print(json.dumps(proof));sys.exit(0 if proof['ok']else 1)
