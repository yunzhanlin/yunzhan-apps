"""Normal signed C28 to C29r8 upgrade and first real country task in fresh KVM.
A terminal or uncertain original operation is retained, never replayed.
"""
import ast,contextlib,hashlib,json,os,pathlib,platform,re,runpy,secrets,shutil,sqlite3,stat,subprocess,sys,time,traceback
os.umask(0o077);assert os.geteuid()==0 and platform.machine()=='x86_64'and len(sys.argv)==2
payload=pathlib.Path(sys.argv[1]).resolve(strict=True);pins=json.loads((payload/'assets.json').read_bytes());assert pins['format']==1 and pins['architecture']=='amd64'and pins['harness_revision']==5
base=pathlib.Path('/opt/panel-country-native-qa-'+secrets.token_hex(16));base.mkdir(mode=0o700);evidence=base/'evidence';evidence.mkdir(mode=0o700)
def sha(p):
 h=hashlib.sha256()
 with pathlib.Path(p).open('rb')as f:
  for b in iter(lambda:f.read(1<<20),b''):h.update(b)
 return h.hexdigest()
def save(n,v):
 assert re.fullmatch('[A-Za-z0-9._-]+',n)
 with(evidence/n).open('x')as f:json.dump(v,f,sort_keys=True,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
for n,h in pins['files'].items():
 assert re.fullmatch('[A-Za-z0-9._-]+',n);p=payload/n;s=p.lstat();assert stat.S_ISREG(s.st_mode)and s.st_nlink==1 and sha(p)==h
 shutil.copyfile(p,base/n,follow_symlinks=False);os.chmod(base/n,0o600)
assert sha(base/'programme.pub')=='4ccfcc861d56a41e3ba7f7ace7e2432c815f366c58448d783df92c6632f01339'and sha(base/'signed-release.py')=='fe128e82b4e11345b320cd782134768bfe1a4df14947c425d7494873a7a7b7b5'
old='0.1.0-dev.proapps24filtercandidate28';new='0.1.0-dev.proapps24countrycandidate29r8';SOURCE='68468005b42fec5b774aa9d1be6cc39a85fc87f5733633030bd2452239254cfd'
assert pins['programme_update_version']==new and pins['source_inputs_sha256']==pins['programme_update_source_inputs_sha256']==SOURCE
assert not pathlib.Path('/etc/panel-release').exists()and not pathlib.Path('/opt/panel').exists()
lib=runpy.run_path(str(base/'business.py'));obs=runpy.run_path(str(base/'observations.py'));boot=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip();plan={'peer':{'boot':boot}}
# Reuse the byte-pinned complete protected-file and Nginx/kernel capture.
s=(base/'capture-model.py').read_text();capture_ast=ast.parse(s)
for name in('tree','nginx','nft','nft_clean'):
 f=next(v for v in capture_ast.body if isinstance(v,ast.FunctionDef)and v.name==name);exec(compile(ast.Module(body=[f],type_ignores=[]),'original-private-capture','exec'),globals())
kernel=['net/ipv4/ip_forward','net/ipv4/conf/all/accept_redirects','net/ipv4/conf/default/accept_redirects','net/ipv4/conf/all/send_redirects','net/ipv4/conf/default/send_redirects','net/ipv4/conf/all/accept_source_route','net/ipv4/conf/default/accept_source_route','net/ipv4/conf/all/rp_filter','net/ipv4/conf/default/rp_filter','net/ipv4/tcp_syncookies','net/ipv6/conf/all/accept_redirects','net/ipv6/conf/default/accept_redirects','net/ipv6/conf/all/accept_source_route','net/ipv6/conf/default/accept_source_route','kernel/kptr_restrict']
def capture(label):
 v={'core':lib['capture_core'](),'files':globals()['tree'](),'nginx':nginx(),'kernel':{n:pathlib.Path('/proc/sys/'+n).read_text()for n in kernel},'nft':nft(),'source_inputs':json.loads(pathlib.Path('/opt/panel/current/SOURCE_INPUTS.json').read_bytes())['inputs_sha256']};save(label+'.json',v);return v
source=(base/'business.py').read_text();parsed=ast.parse(source);f=next(v for v in parsed.body if isinstance(v,ast.FunctionDef)and v.name=='compare_core');function=''.join(source.splitlines(True)[f.lineno-1:f.end_lineno]);needle="        else:raise AssertionError('Unrelated old business table changed: '+name)";assert function.count(needle)==1
function=function.replace(needle,"        elif name in OBSERVED:\n            assert observations['ok']\n"+needle);g={**lib,'OBSERVED':{'database_connection_samples','monitor_samples','monitor_conditions','monitor_services','notification_dispatch_status','sqlite_sequence'}};exec(function,g)
def preserved(a,z,migrate):
 assert a['files']==z['files']and a['nginx']==z['nginx']and a['kernel']==z['kernel']
 x=[];y=[];assert nft_clean(a['nft'],x)==nft_clean(z['nft'],y)and len(x)==len(y)and all(b[0]>=c[0]and b[1]>=c[1]for c,b in zip(x,y))
 observations=obs['observation_deltas'](a['core'],z['core'],boot,lib['stamp']);g['observations']=observations
 if migrate:result=g['compare_core'](a['core'],z['core'])
 else:
  assert a['core']['schema']==z['core']['schema']and a['core']['columns']==z['core']['columns']
  for n,rows in a['core']['rows'].items():
   current=z['core']['rows'][n]
   if rows!=current and n not in g['OBSERVED']:
    assert n=='load_balance_traffic_source'and len(rows)==len(current)==1 and rows[0][:3]==current[0][:3]
    assert rows[0][3][0]==current[0][3][0]=='text'and lib['stamp'](rows[0][3][1])<=lib['stamp'](current[0][3][1])<=z['core']['at']+1
  result={'ok':True,'readonly_preflight_schema_and_business_preserved':True}
 return {'Core':result,'all_actual_SQLite_tables':len(z['core']['rows']),'background_observations':observations,'NSS_configs_native_files_Nginx_lifetime_kernel_and_NFT_preserved':True}
def command(label,args,timeout=1200):
 save(label+'-once-intent.json',{'args':args,'attempts':1,'unknown_outcome_observe_only':True})
 with(evidence/(label+'.log')).open('xb')as f:r=subprocess.run(args,stdin=subprocess.DEVNULL,stdout=f,stderr=subprocess.STDOUT,timeout=timeout)
 save(label+'-outcome.json',{'status':r.returncode,'log_sha256':sha(evidence/(label+'.log'))});assert r.returncode==0,'Original operation failed; no replay: '+label
proof={'ok':False,'base':str(base),'architecture':'amd64','actual_KVM_guest':True,'normal_signed_C28_to_C29r8':False,'Main_changed':False,'all50_commercial':False}
try:
 for v in(old,new):command(v+'-verify',['python3','-I','-B',str(base/'signed-release.py'),'verify',str(base/('panel-'+v+'-linux-amd64.tar.gz')),'--public-key',str(base/'programme.pub')],30)
 command('normal-C28-first-install',['python3','-I','-B',str(base/'signed-release.py'),'install',str(base/('panel-'+old+'-linux-amd64.tar.gz')),'--public-key',str(base/'programme.pub')])
 # Give the newly installed real collector an actual baseline sample.
 for _ in range(45):
  with contextlib.closing(sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True))as db:
   count=db.execute('SELECT count(*) FROM monitor_samples').fetchone()[0];clock=db.execute('SELECT last_check_at FROM notification_dispatch_status WHERE id=1').fetchone()[0]
  if count>0 and re.fullmatch(r'20\d\d-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z',clock):break
  time.sleep(1)
 assert count>0 and clock
 before=capture('C28-before');assert before['source_inputs']=='a90b74709a04c646ede65f499286046d7ef43bb80265b4afc3e121177f7d48bc'
 args=['python3','-I','-B',str(base/'signed-release.py'),'install',str(base/('panel-'+new+'-linux-amd64.tar.gz')),'--public-key',str(base/'programme.pub')]
 command('normal-C29r8-preflight',args+['--preflight-only'],900);checked=capture('C28-after-preflight');assert checked['source_inputs']==before['source_inputs'];save('preflight-preservation.json',preserved(before,checked,False))
 command('normal-C29r8-upgrade',args,1000);after=capture('C29r8-after-upgrade');assert after['source_inputs']==SOURCE;save('upgrade-preservation.json',preserved(before,after,True));proof['normal_signed_C28_to_C29r8']=True
 functional=runpy.run_path(str(base/'functional.py'))['run'](base,'amd64',pins['app_manifest_sha256']);proof['functional']=functional;assert functional['ok'];proof.update(ok=True,normal_signed_store_and_original_first_country_account_and_data_task=True,actual_country_Nginx_controls=True)
except BaseException:save('failure.json',{'traceback':traceback.format_exc()})
finally:
 if(base/'country-functional').is_dir():shutil.copytree(base/'country-functional',evidence/'country-functional')
 save('proof.json',proof)
 print(json.dumps({'ok':proof['ok'],'base':str(base),'proof_sha256':sha(evidence/'proof.json'),'normal_signed_C28_to_C29r8':proof['normal_signed_C28_to_C29r8'],'all50_commercial':False,'Main_changed':False}),flush=True)
sys.exit(0 if proof['ok']else 1)
