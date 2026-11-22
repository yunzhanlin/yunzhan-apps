from pathlib import Path
import base64,copy,grp,http.client,runpy,types,contextlib,hashlib,http.cookiejar,json,os,re,secrets,sqlite3,stat,subprocess,sys,time,traceback,urllib.request,urllib.error
os.umask(0o077);payload=Path(sys.argv[1]);plan=json.loads((payload/'plan.json').read_bytes());assert os.geteuid()==0 and {'aarch64':'arm64','x86_64':'amd64'}[os.uname().machine]==plan['architecture'];assert Path('/etc/hostname').read_text().strip()==plan['host']and hashlib.sha256(Path('/etc/machine-id').read_bytes()).hexdigest()==plan['machine'];old=Path('/opt/panel/current').resolve(strict=True);assert json.loads((old/'SOURCE_INPUTS.json').read_bytes())['inputs_sha256']==plan['source_before'];base=Path(sys.argv[2])/'native-current-Apache-WAF-business';base.mkdir(mode=0o700);evidence=base/'evidence';evidence.mkdir(mode=0o700)
def sha(p):
 h=hashlib.sha256()
 with Path(p).open('rb')as f:
  for b in iter(lambda:f.read(1<<20),b''):h.update(b)
 return h.hexdigest()
def save(n,v):
 with(evidence/n).open('x')as f:json.dump(v,f,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
def rows():
 with contextlib.closing(sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True))as db:
  db.execute('PRAGMA query_only=ON');assert db.execute('PRAGMA quick_check').fetchone()==('ok',);out={}
  for t in('runtime_jobs','runtime_installations','app_registry_install_requests','app_registry_receipts','sites'):
   c=[r[1]for r in db.execute('PRAGMA table_info('+t+')')];out[t]={'columns':c,'rows':db.execute('SELECT *FROM '+t+' ORDER BY 1').fetchall()}
  return json.loads(json.dumps(out))
def snapshot():
 out={};roots=[old,Path('/etc/panel/security-apps/modules/apache-waf'),Path('/srv/panel/sites'),Path('/opt/panel/runtimes'),Path('/opt/panel/app-modules/apache-waf/engines'),Path('/var/lib/panel-executor/apache-body-builds'),Path('/var/lib/panel-apache-body/cc-archives'),Path('/var/lib/panel-apache-body/cc-archive-history')];paths=[Path('/etc/panel/first-login.json'),Path('/etc/panel/apache/httpd.conf'),Path('/etc/panel/apache/waf.conf'),Path('/etc/panel/security-apps/modules/apache-waf/installed.json')]
 for root in roots:
  if root.exists():
   assert root.is_dir()and not root.is_symlink();paths.extend(root.rglob('*'))
 for p in paths:
  if not os.path.lexists(p):continue
  st=p.lstat();v={'mode':stat.S_IMODE(st.st_mode),'uid':st.st_uid,'gid':st.st_gid,'dev':st.st_dev,'inode':st.st_ino,'links':st.st_nlink}
  if stat.S_ISLNK(st.st_mode):v['link']=os.readlink(p)
  elif stat.S_ISREG(st.st_mode):v.update(bytes=st.st_size,sha256=sha(p))
  elif stat.S_ISDIR(st.st_mode):continue
  else:raise AssertionError('Unexpected original special file '+str(p))
  out[str(p)]=v;assert len(out)<40000
 return out
def process():
 v=dict(l.split('=',1)for l in subprocess.check_output(['systemctl','show','panel-apache','-p','MainPID,InvocationID,ActiveState'],text=True).splitlines());v['exe']=os.readlink('/proc/'+v['MainPID']+'/exe');return v
proof={'ok':False,'base':str(base),'scope':'Fresh normal signed-store Apache WAF2.5.1 installation and current Apache2.4.71 native engine build, actual body and per-site CC plus independent Root copy with a held UID33 descriptor on new owned data; original PHP business site and signed runtime rows preserved. No runtime upgrade or cold claim.','original_operation_replays':0,'all40_commercial':False};csrf=''
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*a,**kw):raise AssertionError('Unexpected redirect refused')
origin='http://127.0.0.1:19100';opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect(),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
def api(label,path,body=None,expected=200,key=None):
 raw=None if body is None else json.dumps(body).encode();headers={'Origin':origin,'Content-Type':'application/json','X-CSRF-Token':csrf}
 if key:headers['Idempotency-Key']=key
 if body is not None:save(label+'-intent.json',{'path':path,'maximum_submissions':1,'idempotency_key':key,'body':'private-redacted'if path=='/login'else body})
 try:
  with opener.open(urllib.request.Request(origin+'/api'+path,raw,headers),timeout=80)as r:status=r.status;data=r.read((8<<20)+1)
 except urllib.error.HTTPError as r:status=r.code;data=r.read((8<<20)+1)
 assert len(data)<=8<<20;v=json.loads(data)
 if path!='/login':save(label+'-response.json',{'status':status,'value':v})
 assert status==expected,(path,status,v.get('error'));return v


def wait_job(label,jid,table='runtime_jobs',expect='succeeded'):
 assert re.fullmatch('[a-f0-9]{32}',jid)and table in('runtime_jobs','jobs');print(json.dumps({'phase':label,'original_job':jid}),flush=True);deadline=time.monotonic()+1800
 while time.monotonic()<deadline:
  with contextlib.closing(sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True))as db:
   db.row_factory=sqlite3.Row;row=dict(db.execute('SELECT *FROM '+table+' WHERE id=?',(jid,)).fetchone())
  if row['state']not in('queued','running'):
   save(label+'-original-terminal.json',row);assert row['state']==expect,(label,row['state'],row['error']);return row
  time.sleep(1)
 raise TimeoutError('Original operation unresolved; no replay')
def unit(name):return dict(l.split('=',1)for l in subprocess.check_output(['systemctl','show',name,'-p','LoadState,MainPID,InvocationID,ActiveState,SubState,UnitFileState'],text=True).splitlines())
def identity(path,private=False):
 p=Path(path);s=p.lstat();assert stat.S_ISREG(s.st_mode)and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600
 if private:assert s.st_uid==0 and s.st_gid==grp.getgrnam('panel').gr_gid
 return {'uid':s.st_uid,'gid':s.st_gid,'mode':stat.S_IMODE(s.st_mode),'bytes':s.st_size,'device':s.st_dev,'inode':s.st_ino,'sha256':sha(p)}
def archive(label,allow_incomplete=False):
 current=api(label+'-current-policy','/software/apache-waf/config');source=identity('/var/lib/panel-apache-body/cc-events.log');assert source['uid']==source['gid']==33 and 0<source['bytes']<=32<<20;rid=secrets.token_hex(16);row=api(label+'-one-original-archive','/software/apache-waf/cc-log/archive',{'request_id':rid,'expected_revision':current['settings']['policy']['revision'],'allow_incomplete':allow_incomplete},200,rid);assert row['state']=='completed'and row['id']==rid;directory=Path('/var/lib/panel-apache-body/cc-archives')/rid;sealed=identity(directory/'data.log',True);original=identity(directory/'next.log',True);assert sealed['sha256']==original['sha256']==source['sha256']and sealed['bytes']==original['bytes']==source['bytes']and sealed['inode']!=source['inode']==original['inode'];assert identity('/var/lib/panel-apache-body/cc-events.log')['bytes']==0;return {'id':rid,'source':source,'copy':sealed,'source_preserved_path':str(directory/'next.log'),'copy_path':str(directory/'data.log')}

child=None
try:
 assert plan['source_before']==plan['source_after']=='b223c28247d9d20e50a356643a9744a9ab174068dd567a2c57f15c342934c15f';assert all(sha(payload/n)==h for n,h in plan['files'].items());before_files=snapshot();before_rows=rows();save('original-files-before.json',before_files);save('original-SQL-before.json',before_rows);access=json.loads(Path('/etc/panel/first-login.json').read_bytes());csrf=api('login','/login',{k:access[k]for k in('username','password')})['csrf'];access.clear();catalogue=api('fresh-original-current-store','/app-registry?refresh=1');assert catalogue['source']['resolved_commit']==plan['catalogue']and not catalogue['source']['stale']and len(catalogue['catalog']['apps'])==40;cohort=json.loads((payload/'cohort.json').read_bytes());item=next(x for x in catalogue['catalog']['apps']if x['id']=='apache-waf');assert item==cohort['items']['apache-waf'];state=next(x for x in catalogue['status']if x['id']=='apache-waf');assert state['state_known']and not state['installed'];waf=api('one-fresh-normal-signed-WAF-install','/app-registry/apache-waf/install',{'expected_version':item['version'],'expected_sha256':item['sha256']},202,secrets.token_hex(16));wait_job('fresh-normal-WAF-install',waf['job_id']);cfg=api('fresh-installed-WAF','/software/apache-waf/config');assert cfg['status']['healthy']and cfg['status']['version']=='2.5.1';engine=api('one-fresh-normal-native-engine-build','/software/apache-waf/body-engine/build',{},202,secrets.token_hex(16))['job_id'];wait_job('fresh-normal-native-engine-build',engine);detail=api('fresh-original-ready-engine','/software/apache-waf/body-engine/jobs/'+engine);assert detail['state']=='ready'and detail['apache_version']=='2.4.71'and detail['engine_version']=='2.9.15-yz5'and detail['native_cc_version']=='1.1.0'and all(detail[k]for k in('module_abi_validated','integrity_verified','elf_hardening_validated','compiler_groups_collected'));actual=process();assert actual['ActiveState']=='active'and actual['exe']=='/opt/panel/runtimes/apache/2.4.71/bin/httpd';runtime=api('fresh-original-current-runtime','/runtimes/apache');assert runtime['running_id']==runtime['selected_id']=='apache-2.4.71'and not runtime['activation_needed'];assert not os.path.lexists('/var/lib/panel-apache-body/cc-events.log'),'The fresh current runtime must not inherit a foreign CC event sink'
 # Reuse only the earlier independent QA casebook, never product substitutes.
 # It creates two new sites through normal Core and verifies each raw response,
 # actual isolated PHP UID/GID/capabilities, and the application-side counters.
 h=types.SimpleNamespace(payload=payload,evidence=evidence,source=plan['source_after'],api=api,save=save,wait_job=wait_job,unit=unit,proof=proof,continue_after_shared_budget=False);a=runpy.run_path(str(payload/'acceptance.py'))['Acceptance'](h,engine);a.create_sites();a.rewrite_and_no_follow();a.body_cases();a.configure('current-explicit-native-CC-for-new-sites',lambda s:(a.site_policy(s),a.rule(s)));site,other=a.sites
 assert not (a.last.get('trusted_proxy')or{}).get('enabled',False)
 default_replies,default_elapsed=a.burst('current-default-untrusted-forwarding-shares-quota',site,amount=5,vary_spoof=True);default_codes=[r['status']for r in default_replies];assert 3<=default_codes.count(200)<=3+int(default_elapsed)and 429 in default_codes
 a.configure('current-explicit-owned-loopback-trusted-proxy',lambda s:s.update(trusted_proxy={'enabled':True,'header':'X-Forwarded-For','recursive':True,'trusted_cidrs':['127.0.0.1/32'],'acknowledge_header_control':True}))
 for label,target,path,xff in [('first-site-quota',site,'/cc56/quota','198.51.100.101'),('independent-second-site',other,'/cc56/quota','198.51.100.101'),('independent-first-site-path',site,'/cc56/ordinary','198.51.100.101'),('independent-second-client',site,'/cc56/quota','198.51.100.102')]:
  replies,elapsed=a.burst('current-'+label,target,path=path,amount=5,xff=xff)
  codes=[r['status']for r in replies]
  if target is site and path=='/cc56/quota':assert 3<=codes.count(200)<=3+int(elapsed)and 429 in codes
  else:assert codes==[200]*5
 a.configure('current-new-sites-observe',lambda s:a.site_policy(s,'observe'));a.burst('current-observe-quota-records-and-continues',site,amount=5,xff='198.51.100.103',allowed=5);a.configure('current-new-sites-off',lambda s:a.site_policy(s,'off'));a.burst('current-off-quota-continues',site,amount=5,xff='198.51.100.104',allowed=5);a.configure('current-new-sites-block',lambda s:a.site_policy(s,'block'));a.counters();log=Path('/var/lib/panel-apache-body/cc-events.log');genuine=log.read_bytes();assert genuine and a.private_marker.encode()not in genuine;events=[json.loads(l)for l in genuine.splitlines()];assert events and all(v['site_id']in{site['id'],other['id']}and '?'not in v['path']for v in events);save('actual-current-native-CC-events.json',events);worker=r"""import json,os,sys
assert os.geteuid()==os.getegid()==33
fd=os.open('/var/lib/panel-apache-body/cc-events.log',os.O_WRONLY|os.O_APPEND|os.O_NOFOLLOW)
print('READY',flush=True)
for l in sys.stdin:
 c=json.loads(l)
 if c['op']=='append':os.write(fd,b'owned C460 held writer appended only original inode\n');os.fsync(fd)
 elif c['op']=='private-open':
  try:other=os.open(c['path'],os.O_WRONLY|os.O_NOFOLLOW)
  except PermissionError:pass
  else:os.close(other);raise AssertionError('Worker opened private Root copy')
 else:raise AssertionError('Unknown own control')
 print('DONE',flush=True)
os.close(fd)
""";child=subprocess.Popen([sys.executable,'-I','-B','-c',worker],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,user=33,group=33,extra_groups=[]);assert child.stdout.readline()=='READY\n';sealed=archive('new-owned-genuine-events-held-FD');assert sealed['source']['sha256']==hashlib.sha256(genuine).hexdigest();before_private=identity(sealed['copy_path'],True)
 for command in({'op':'private-open','path':sealed['copy_path']},{'op':'append'}):child.stdin.write(json.dumps(command)+'\n');child.stdin.flush();assert child.stdout.readline()=='DONE\n'
 assert identity(sealed['copy_path'],True)==before_private and identity(sealed['source_preserved_path'],True)['sha256']!=sealed['source']['sha256'];download=api('new-owned-sealed-genuine-download','/software/apache-waf/cc-log/archives/'+sealed['id']+'/chunks/0');raw=base64.b64decode(download['data_base64'],validate=True);assert raw==genuine and download['sha256']==hashlib.sha256(genuine).hexdigest();child.stdin.close();assert child.wait(timeout=10)==0;child=None;save('actual-current-held-UID33-FD-private-copy.json',{'ok':True,'new_owned_source_only':True,'actual_uid':33,'old_held_writer_modified_source':True,'private_copy_unchanged':True,'fresh_worker_private_open_denied':True,'archive':sealed,'download_sha256':hashlib.sha256(raw).hexdigest()})
 after_files=snapshot();save('original-files-after.json',after_files);allowed={'/etc/panel/apache/httpd.conf','/etc/panel/security-apps/modules/apache-waf/rules.conf','/etc/panel/security-apps/modules/apache-waf/installed.json'};assert all(after_files.get(p)==v for p,v in before_files.items()if p not in allowed);after_rows=rows();save('original-SQL-after.json',after_rows)
 for t in('sites','runtime_jobs','runtime_installations','app_registry_install_requests','app_registry_receipts'):
  prior=before_rows[t];current=after_rows[t];indices=[current['columns'].index(c)for c in prior['columns']];got={json.dumps([r[i]for i in indices],sort_keys=True)for r in current['rows']};assert all(json.dumps(r,sort_keys=True)in got for r in prior['rows']),t
 final_cfg=api('final-original-WAF','/software/apache-waf/config');assert final_cfg['status']['healthy'];proof.update(ok=True,source_inputs_sha256=plan['source_after'],original_preserved_files=sum(p not in allowed for p in before_files),original_site_and_job_rows_preserved=True,normal_signed_WAF_install_job=waf['job_id'],normal_native_engine_build_job=engine,new_current_engine=engine,actual_Apache=actual,actual_body_HTTP=168,body_blocked_never_reached_PHP=32,own_HTTP_requests=len(a.requests),new_owned_sites=[s['id']for s in a.sites],current_native_CC_site_path_client_isolation=True,current_default_untrusted_headers_share_budget=True,current_native_CC_observe_and_off=True,actual_held_UID33_FD_private_copy=True,normal_programme_installs=0,engine_build_replays=0,original_archive_replays=0,architecture=plan['architecture'],platform=plan['platform'])
except BaseException:
 proof['failure']=traceback.format_exc()[-7000:]
finally:
 if child and child.poll()is None:child.kill();child.wait()
 if csrf:
  try:api('logout','/logout',{})
  except BaseException:proof['ok']=False;proof['logout_failure']=True
 save('original-proof.json',proof);print(json.dumps(proof),flush=True)
sys.exit(0 if proof['ok']else 1)
