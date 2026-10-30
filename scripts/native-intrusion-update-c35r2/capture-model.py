"""Once-only normal signed C29 programme upgrade in the existing owned ARM QA.
Full typed database, private file identities and live Nginx lifetime are retained.
No WAF app update, country task, new account, native control or reboot is issued.
"""
import contextlib,hashlib,json,os,pathlib,re,runpy,sqlite3,stat,subprocess,sys,time,traceback
os.umask(0o077);assert len(sys.argv)==2 and os.geteuid()==0
base=pathlib.Path(sys.argv[1]);assert re.fullmatch('/opt/panel-c29-upgrade-[a-f0-9]{32}',str(base))
plan=json.loads((base/'intent.json').read_bytes())
def sha(p):
 h=hashlib.sha256()
 with pathlib.Path(p).open('rb')as f:
  for b in iter(lambda:f.read(1<<20),b''):h.update(b)
 return h.hexdigest()
for name,spec in plan['files'].items():
 p=base/name;s=p.lstat();assert stat.S_ISREG(s.st_mode)and s.st_uid==s.st_gid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600 and s.st_size==spec['bytes']and sha(p)==spec['sha256']
assert pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()==plan['peer']['boot']
assert sha('/etc/machine-id')==plan['peer']['machine_id_sha256']
lib=runpy.run_path(str(base/'business.py'));obs=runpy.run_path(str(base/'observations.py'))
def save(n,v):
 with(base/n).open('x')as f:json.dump(v,f,sort_keys=True,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
def tree():
 roots=['/etc/panel','/etc/nginx','/srv/panel/sites']+['/etc/'+n for n in('passwd','group','shadow','gshadow','nsswitch.conf')]
 roots += [str(p)for p in pathlib.Path('/var/lib/panel-executor').glob('load-balance-stream*')]
 roots += ['/etc/systemd/system/nginx.service.d/panel.conf']
 entries={};size=0
 def entry(p):
  nonlocal size
  s=p.lstat();info={'mode':s.st_mode,'uid':s.st_uid,'gid':s.st_gid,'links':s.st_nlink}
  if stat.S_ISREG(s.st_mode):
   size+=s.st_size;assert size<=1<<30 and s.st_size<=128<<20;info.update(bytes=s.st_size,sha256=sha(p))
  elif stat.S_ISLNK(s.st_mode):info['target']=os.readlink(p)
  else:assert stat.S_ISDIR(s.st_mode),'Unexpected protected special file '+str(p)
  entries[str(p)]=info;assert len(entries)<=100000
  if stat.S_ISDIR(s.st_mode):
   for child in sorted(p.iterdir()):entry(child)
 for name in sorted(set(roots)):
  p=pathlib.Path(name)
  if os.path.lexists(p):entry(p)
  else:entries[name]={'absent':True}
 return entries
kernel=['net/ipv4/ip_forward','net/ipv4/conf/all/accept_redirects','net/ipv4/conf/default/accept_redirects','net/ipv4/conf/all/send_redirects','net/ipv4/conf/default/send_redirects','net/ipv4/conf/all/accept_source_route','net/ipv4/conf/default/accept_source_route','net/ipv4/conf/all/rp_filter','net/ipv4/conf/default/rp_filter','net/ipv4/tcp_syncookies','net/ipv6/conf/all/accept_redirects','net/ipv6/conf/default/accept_redirects','net/ipv6/conf/all/accept_source_route','net/ipv6/conf/default/accept_source_route','kernel/kptr_restrict']
def nginx():
 r=subprocess.run(['systemctl','show','nginx.service','-p','MainPID','--value'],capture_output=True,text=True,timeout=5);assert r.returncode==0 and r.stdout.strip().isdigit();pid=r.stdout.strip();assert int(pid)>1
 raw=pathlib.Path('/proc/'+pid+'/stat').read_text();at=raw.rfind(')');fields=raw[at+2:].split();assert len(fields)>19
 return {'pid':pid,'start_ticks':fields[19],'executable_sha256':sha('/proc/'+pid+'/exe'),'boot':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()}
def nft():
 r=subprocess.run(['nft','-j','list','ruleset'],capture_output=True,text=True,timeout=5);assert r.returncode==0;return json.loads(r.stdout)
def snap(label):
 v={'core':lib['capture_core'](),'files':tree(),'nginx':nginx(),'kernel':{n:pathlib.Path('/proc/sys/'+n).read_text()for n in kernel},'nft':nft(),'source_inputs':json.loads(pathlib.Path('/opt/panel/current/SOURCE_INPUTS.json').read_bytes())['inputs_sha256']};save(label+'.json',v);return v
def nft_clean(value,counters):
 if type(value)is list:return[nft_clean(v,counters)for v in value]
 if type(value)is not dict:return value
 out={}
 for k,v in value.items():
  if k=='counter'and type(v)is dict and set(v)=={'packets','bytes'}:
   assert all(type(a)is int and a>=0 for a in v.values());counters.append((v['packets'],v['bytes']));out[k]={'packets':'observed','bytes':'observed'}
  else:out[k]=nft_clean(v,counters)
 return out
def preserved(a,z,core_migration):
 assert a['files']==z['files']and a['nginx']==z['nginx']and a['kernel']==z['kernel']
 x=[];y=[];assert nft_clean(a['nft'],x)==nft_clean(z['nft'],y)and len(x)==len(y)and all(b[0]>=c[0]and b[1]>=c[1]for c,b in zip(x,y))
 before=a['core'];after=z['core'];assert before['schema']==after['schema']and before['columns']==after['columns']and before['rows'].keys()==after['rows'].keys()
 observations=obs['observation_deltas'](before,after,plan['peer']['boot'],lib['stamp'])
 allowed={'database_connection_samples','monitor_samples','monitor_conditions','monitor_services','notification_dispatch_status','sqlite_sequence'}
 for name,rows in before['rows'].items():
  current=after['rows'][name]
  if rows!=current:
   if name in allowed:assert observations['ok']
   else:
    assert name=='load_balance_traffic_source'and len(rows)==len(current)==1 and rows[0][:3]==current[0][:3]
    assert rows[0][3][0]==current[0][3][0]=='text'and lib['stamp'](rows[0][3][1])<=lib['stamp'](current[0][3][1])<=after['at']+1
 return {'ok':True,'all_actual_SQLite_tables_included':len(after['rows']),'no_schema_or_business_mutation':True,'background_observations':observations}
proof={'ok':False,'normal_original_key_signed_C29r5_programme':False,'WAF260_app_updated':False,'country_account_created':False,'native_controls_submitted':0,'reboots':0,'Main_changed':False,'all50_commercial':False}
try:
 assert pathlib.Path('/etc/panel-release').read_text()=='version=0.1.0-dev.proapps24countrycandidate29r4\narch=arm64\n'
 manifest=pathlib.Path('/etc/panel/security-apps/nginx-waf.json');assert json.loads(manifest.read_bytes())['version']=='2.5.2'
 for n in('waf_country_requests','waf_country_results'):
  with contextlib.closing(sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True))as db:assert db.execute('SELECT count(*) FROM sqlite_master WHERE type="table" AND name=?',(n,)).fetchone()[0]==1
  with contextlib.closing(sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True))as db:assert db.execute('SELECT count(*) FROM '+n).fetchone()[0]==0
 before=snap('before');assert before['source_inputs']=='e94f0e0884ebb40e6f55b43ddc251effd50e169b64521b0296fbe8f0a812aff8'
 command=['/usr/bin/python3','-I','-B',str(base/'signed-release.py'),'install',str(base/plan['archive']),'--public-key',str(base/'programme.pub')]
 for name,extra in(('preflight',['--preflight-only']),('install',[])):
  save(name+'-once-intent.json',{'archive':plan['archive'],'attempts':1,'original_DEV_QA_key_only':True,'unknown_outcome_observe_only':True})
  with(base/(name+'.stdout.log')).open('xb')as out,(base/(name+'.stderr.log')).open('xb')as err:r=subprocess.run(command+extra,stdin=subprocess.DEVNULL,stdout=out,stderr=err,timeout=900)
  save(name+'-outcome.json',{'status':r.returncode,'stdout_sha256':sha(base/(name+'.stdout.log')),'stderr_sha256':sha(base/(name+'.stderr.log'))});assert r.returncode==0,'Original signed operation failed or unknown; observe original only'
  after=snap('after-'+name);result=preserved(before,after,name=='install');save(name+'-preservation.json',result)
  assert after['source_inputs']==(plan['source_inputs_sha256']if name=='install'else before['source_inputs'])
 assert json.loads(manifest.read_bytes())['version']=='2.5.2'
 assert not pathlib.Path('/etc/panel/security-apps/modules/nginx-waf/country-network-account.json').exists()
 for unit,name in(('panel.service','panel'),('panel-executor.service','panel-executor')):
  r=subprocess.run(['systemctl','show',unit,'-p','MainPID','--value'],capture_output=True,text=True,timeout=5);assert r.returncode==0 and int(r.stdout)>1;assert sha('/proc/'+r.stdout.strip()+'/exe')==plan['programme_binaries'][name]
 proof.update(ok=True,normal_original_key_signed_C29r5_programme=True,source_inputs_sha256=after['source_inputs'],Core=result,protected_files=len(after['files']),NSS_configs_native_data_Nginx_lifetime_kernel_NFT_preserved=True,normal_WAF252_policy_still_unchanged=True)
except BaseException:save('failure.json',{'traceback':traceback.format_exc()})
finally:save('proof.json',proof)
print(json.dumps({'ok':proof['ok'],'root':str(base),'proof_sha256':sha(base/'proof.json'),'normal_programme_only':True,'Main_changed':False,'all50_commercial':False}));sys.exit(0 if proof['ok']else 1)
