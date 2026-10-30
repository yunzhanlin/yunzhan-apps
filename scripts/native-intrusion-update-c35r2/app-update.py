"""One normal original-key signed110-to111 Core application-store update.
Capture full original state and retain every original job; no unknown retry.
"""
import ast,base64,contextlib,hashlib,http.cookiejar,json,os,pathlib,re,runpy,secrets,sqlite3,stat,subprocess,sys,time,traceback,urllib.error,urllib.request
os.umask(0o077);assert os.geteuid()==0 and len(sys.argv)==2;root=pathlib.Path(sys.argv[1]);p=json.loads((root/'intent.json').read_bytes());assert re.fullmatch('/var/tmp/yunzhan-intrusion-c35r2-update-app-[a-f0-9]{32}',str(root));assert pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()==p['peer']['boot'];source=pathlib.Path(p['programme_case'])
def checked(name):
 f=source/name;s=f.lstat();assert stat.S_ISREG(s.st_mode)and s.st_uid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600 and hashlib.sha256(f.read_bytes()).hexdigest()==p['programme_files'][name];return f
for n in('guest.py','business.py','capture-model.py'):checked(n)
old_worker=root/'old110-source.py';assert hashlib.sha256(old_worker.read_bytes()).hexdigest()==p['old110_source_sha256']
base=root/'evidence';base.mkdir(mode=0o700);evidence=base
lib=runpy.run_path(str(checked('business.py')));scope={'pathlib':pathlib,'subprocess':subprocess,'json':json,'re':re,'sha':lambda f:hashlib.sha256(pathlib.Path(f).read_bytes()).hexdigest()}
for name in('nginx','nft','nft_clean'):
 t=ast.parse(checked('capture-model.py').read_text());fn=next(n for n in t.body if isinstance(n,ast.FunctionDef)and n.name==name);exec(compile(ast.Module(body=[fn],type_ignores=[]),'<pinned-original-readonly-NFT>','exec'),scope)
t=ast.parse(checked('guest.py').read_text());names={'sha','save','tree','lifetime','guard','snapshot'};nodes=[n for n in t.body if isinstance(n,ast.FunctionDef)and n.name in names];assert len(nodes)==len(names);exec(compile(ast.Module(body=nodes,type_ignores=[]),'<pinned-original-readonly-state>','exec'),globals())
t=ast.parse(old_worker.read_text());names={'api','job'};nodes=[n for n in t.body if isinstance(n,ast.FunctionDef)and n.name in names or isinstance(n,ast.ClassDef)and n.name=='NoRedirect'];assert len(nodes)==3;exec(compile(ast.Module(body=nodes,type_ignores=[]),'<pinned-normal-Core-client>','exec'),globals())
origin='http://127.0.0.1:19100';client=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect(),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()));csrf='';http_events=[]
def details(label):
 manifest=json.loads(pathlib.Path('/etc/panel/security-apps/intrusion-prevention.json').read_bytes());records={}
 for f in sorted(pathlib.Path('/etc/panel/security-apps/intrusion-transactions').iterdir()):
  s=f.lstat();assert re.fullmatch(r'[a-f0-9]{32}\.json',f.name)and stat.S_ISREG(s.st_mode)and s.st_uid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600 and s.st_size<2<<20
  raw=f.read_bytes();records[f.name]={'sha256':hashlib.sha256(raw).hexdigest(),'base64':base64.b64encode(raw).decode()}
 v={'manifest':manifest,'terminals':records,'filter_values':{n:subprocess.check_output(['fail2ban-client','get','sshd',n],text=True,timeout=5)for n in('usedns','prefregex','failregex','ignoreregex','maxlines','maxmatches','ignorecommand','ignorecache','ignoreself','ignoreip','logencoding','logtimezone')},'five_lifetimes':{n:lifetime(n)for n in('panel.service','panel-executor.service','nginx.service','ssh.service','fail2ban.service')}}
 save(label+'-application-private-details.json',v);return v
proof={'ok':False,'source_inputs_sha256':'3c8dbb9dacc68ad23a5904c99303f421703e48db39e3f4d0215d5013603b48a8','scope':'actual normal signed110-to111 Core update after original110 installation and preserved programme upgrade','app_update_POSTs':0,'Main_changed':False,'all50_commercial':False,'failed_or_unknown_requests_replayed':False}
try:
 assert json.loads(pathlib.Path('/opt/panel/current/SOURCE_INPUTS.json').read_bytes())['inputs_sha256']=='3c8dbb9dacc68ad23a5904c99303f421703e48db39e3f4d0215d5013603b48a8'
 f=pathlib.Path('/etc/panel/first-login.json');s=f.lstat();assert stat.S_ISREG(s.st_mode)and s.st_uid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600;access=json.loads(f.read_bytes())
 try:status,login=api('/login',{k:access[k]for k in('username','password')});assert status==200;csrf=login['csrf']
 finally:access.clear()
 status,page=api('/app-registry?refresh=1');save('actual-update-offered.json',page);item=next(v for v in page['catalog']['apps']if v['id']=='anti-intrusion');state=next(v for v in page['status']if v['id']=='anti-intrusion');assert len(page['catalog']['apps'])==50 and not page['source']['stale']and item['version']=='1.1.1'and item['sha256']=='6d612505ac72ec97fdafdbc0eb8dae999df296e5203bb47058f799dd2aa6f01e'and state['state_known']and state['installed']and state['installed_version']=='1.1.0'and state['update_available']and state['update_supported']
 guard('before');before=snapshot('before');old=details('before');assert old['manifest']['version']=='1.1.0'and len(old['terminals'])==2 and '2001:db8:35::2 \t'in before['ban_times']
 key=secrets.token_hex(16);body={'expected_version':item['version'],'expected_sha256':item['sha256']};save('normal-app-update-once-intent.json',{'body':body,'key':key,'maximum_POSTs':1});proof['app_update_POSTs']=1
 status,accepted=api('/app-registry/anti-intrusion/update',body,key);save('normal-app-update-original-response.json',{'status':status,'body':accepted});assert status==202 and accepted['provider']=='panel-module';identity=accepted['job_id'];proof['job']=identity;job('update',identity)
 after=snapshot('after');new=details('after');expected=dict(old['manifest']);expected['version']='1.1.1';assert new['manifest']==expected and old['filter_values']==new['filter_values']and old['five_lifetimes']==new['five_lifetimes']and before['ban_times']==after['ban_times']and before['nginx']==after['nginx']and before['actions']==after['actions']
 assert set(new['terminals'])-set(old['terminals'])=={identity+'.json'}and all(new['terminals'][n]==v for n,v in old['terminals'].items())
 status,work=api('/software/intrusion-prevention/workspace');save('actual111-after-update-workspace.json',work);assert work['state_known']and work['pending']is None and work['retained_temporaries']==0 and work['current']['version']=='1.1.1'and work['current']['healthy']and work['current']['settings']==old['manifest']['settings']and len(work['history'])==3
 status,page=api('/app-registry?refresh=1');save('actual111-after-update-store.json',page);state=next(v for v in page['status']if v['id']=='anti-intrusion');assert not page['source']['stale']and state['state_known']and state['installed']and state['installed_version']==state['latest_version']=='1.1.1'and state['healthy']and not state['update_available']
 guard('final');status,_=api('/logout',{});assert status==200;csrf=''
 proof.update(ok=True,actual_signed_store_update_offered_and_completed=True,old_install_time_settings_Jail_policy_and_history_preserved=True,original_ban_expiry_filters_and_five_lifetimes_preserved=True,original110_history_and_new111_receipt_visible=True,normal_own_session_logged_out=True,complete_guard_exit=0,independent_full_snapshot_qualification_pending=True)
except BaseException:save('failure.json',{'traceback':traceback.format_exc()})
finally:
 if csrf:
  try:status,_=api('/logout',{});assert status==200;proof['normal_own_session_logged_out']=True
  except BaseException:proof['ok']=False;save('logout-failure.json',{'traceback':traceback.format_exc()})
 save('HTTP-events.json',http_events);save('proof.json',proof);print(json.dumps({'ok':proof['ok'],'base':str(root),'evidence':str(base),'proof_sha256':sha(base/'proof.json'),'job':proof.get('job')}),flush=True)
sys.exit(0 if proof['ok']else 1)
