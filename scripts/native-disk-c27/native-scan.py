"""One original signed disk-analysis store install in this owned fresh QA guest."""
import base64,contextlib,hashlib,http.cookiejar,json,os,pathlib,platform,secrets,sqlite3,stat,subprocess,sys,time,traceback,urllib.error,urllib.request
os.umask(0o077);base=pathlib.Path(sys.argv[1]);assert len(sys.argv)==2 and os.geteuid()==0
intent=json.loads((base/'intent.json').read_bytes());assert platform.machine()=='x86_64' and pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()==intent['peer']['boot']
assert hashlib.sha256(pathlib.Path('/etc/machine-id').read_bytes()).hexdigest()==intent['peer']['machine_id_sha256']
def save(n,v):
 with os.fdopen(os.open(base/n,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600),'w')as o:json.dump(v,o,sort_keys=True);o.write(chr(10));o.flush();os.fsync(o.fileno())
def sha(p):return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
def capture():
 out={};db=sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True,timeout=3)
 try:
  db.execute('PRAGMA query_only=ON');db.execute('BEGIN')
  for name,sql in db.execute("SELECT name,sql FROM sqlite_schema WHERE type='table' ORDER BY name").fetchall():
   q='"'+name.replace('"','""')+'"';cur=db.execute('SELECT * FROM '+q)
   enc=lambda v:{'blob_base64':base64.b64encode(v).decode()}if isinstance(v,bytes)else v
   out[name]={'sql':sql,'columns':[x[0]for x in cur.description],'rows':sorted([[enc(v)for v in row]for row in cur.fetchall()],key=lambda v:json.dumps(v,sort_keys=True))}
 finally:db.close()
 return out
proof={'ok':False,'scope':'actual original host subtree scan with independent sparse inode and exact integer fixture','Main_changed':False,'all50_commercial':False,'real_host_scan_acceptance':False};csrf='';opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*args,**kwargs):raise AssertionError('API redirect refused')
opener.add_handler(NoRedirect())
def api(path,body=None,key=None):
 h={'Origin':'http://127.0.0.1:19100','X-CSRF-Token':csrf,'Content-Type':'application/json'}
 if key:h['Idempotency-Key']=key
 req=urllib.request.Request('http://127.0.0.1:19100/api'+path,data=None if body is None else json.dumps(body,separators=(',',':')).encode(),headers=h)
 try:
  with opener.open(req,timeout=40)as r:
   b=r.read((4<<20)+1);assert len(b)<=4<<20
   return r.status,json.loads(b)
 except urllib.error.HTTPError as e:
  save('http-error-'+secrets.token_hex(6)+'.json',{'path':path,'status':e.code,'body':e.read(8192).decode('utf8','replace')});raise AssertionError('API status '+str(e.code)+' at '+path)from None
try:
 assert sha(base/'guest.py')==intent['files']['guest.py']
 assert json.loads(pathlib.Path('/opt/panel/current/SOURCE_INPUTS.json').read_bytes())['inputs_sha256']=='3905be8250f8927d651ab90ec2b2bedafb737f2a4e4bb607b79fd1a18057a6c9'
 before=capture();save('before-all-Core-fields.json',before)
 fixture=pathlib.Path('/srv/yunzhan-qa-disk-'+secrets.token_hex(16));assert not os.path.lexists(fixture);fixture.mkdir(mode=0o700);tree=fixture/'tree';tree.mkdir(mode=0o700);(tree/'sub').mkdir(mode=0o700)
 (tree/'data.bin').write_bytes(b'a'*17);(tree/'sub/nested.bin').write_bytes(b'b'*23);outside=fixture/'outside-sentinel';outside.write_bytes(b'outside subtree sentinel: do not follow symbolic links\n')
 sparse=tree/'sparse-8TiB.dat'
 with sparse.open('xb')as o:o.truncate(1<<43)
 assert sparse.stat().st_size==1<<43 and sparse.stat().st_blocks==0
 for n in range(1024):os.link(sparse,tree/('hardlink-%04d'%n))
 (tree/'escape').symlink_to(outside);os.mkfifo(tree/'fifo',0o600)
 def metadata():
  out={}
  for p in [tree,*sorted(tree.rglob('*')),outside]:
   s=p.lstat();out[str(p)]={k:getattr(s,k)for k in('st_mode','st_dev','st_ino','st_nlink','st_size','st_blocks','st_mtime_ns','st_ctime_ns')}
  return out
 original_metadata=metadata();outside_sha=sha(outside)
 save('fixture-before-metadata.json',original_metadata)
 unique={}
 for p,s in original_metadata.items():
  if stat.S_ISREG(s['st_mode'])and str(tree)+'/'in p:unique[(s['st_dev'],s['st_ino'])]=s
 expected={'regular_file_entries':str(1027),'unique_regular_files':'3','duplicate_regular_inodes':'1024','regular_logical_entry_bytes':str((1<<43)*1025+40),'regular_unique_logical_bytes':str((1<<43)+40),'regular_allocated_bytes':str(sum(s['st_blocks']*512 for s in unique.values())),'symbolic_links':'1','special_nodes':'1'}
 assert int(expected['regular_logical_entry_bytes'])>1<<53 and len(unique)==3
 save('fixture-exact-independent-expectations.json',{'expected_report':expected,'large_counter_exceeds_JS_safe_integer':True,'outside_sha256':outside_sha,'fixture':str(fixture),'sparse_unique_physical_bytes':0})
 access=json.loads(pathlib.Path('/etc/panel/first-login.json').read_bytes())
 try:status,login=api('/login',{k:access[k]for k in('username','password')})
 finally:access.clear()
 assert status==200 and login['csrf'];csrf=login['csrf']
 status,host=api('/software/disk-analysis/host');save('actual-current-host-inventory.json',{'status':status,'value':host});assert status==200 and host['installed']is True and host['app_version']=='1.4.1'
 mount=next(m for m in host['inventory']['inventory']['mounts']if m['mount_point']=='/'and m['filesystem']=='ext4')
 assert mount['filesystem_class']=='local'and mount['path_actionable']is True and not mount['stacked_mount_point']
 selection={**host['inventory']['host'],'mount_id':mount['mount_id'],'mount_binding_sha256':mount['binding_sha256'],'relative_directory':str(tree).lstrip('/'),'app_version':host['app_version'],'installation_id':host['installation_id'],'app_manifest_sha256':host['app_manifest_sha256']}
 key=secrets.token_hex(16);save('original-host-job-once-intent.json',{'POST_maximum':1,'idempotency_key':key,'selection':selection})
 status,reply=api('/software/disk-analysis/host/jobs',selection,key);save('original-host-job-response.json',{'status':status,'value':reply})
 assert status==202 and reply['replayed']is False
 job=reply['job']['id'];assert len(job)==32
 proof['original_job_id']=job;proof['original_submit_key']=key
 for n in range(181):
  status,detail=api('/software/disk-analysis/host/jobs/'+job);save('original-observation-%03d.json'%n,{'status':status,'value':detail});assert status==200 and detail['job']['id']==job
  if detail['terminal_verified']:break
  assert n<180;time.sleep(1)
 assert detail['terminal_verified']is True and detail['job']['state']=='complete', 'Original native scan did not complete; preserve original outcome'
 status,final=api('/software/disk-analysis/host/jobs/'+job);save('actual-terminal-original-result.json',final)
 assert status==200 and final['terminal_verified']is True and final['job']['id']==job
 result=final.get('result')or final.get('observation',{}).get('result');assert result and result['state']=='complete'and result['error_code']==''
 report=result['report'];assert report['state']=='complete'and report['enumeration_complete']is True and report['snapshot_consistent']is False and report['exclusive_physical_bytes']is False
 for k,v in expected.items():assert type(report[k])is str and report[k]==v, 'Independent exact counter mismatch '+k
 assert report['excluded_child_mounts']=='0' and report['unavailable_metadata_entries']=='0'and report['partial_reasons']==[]
 assert metadata()==original_metadata and sha(outside)==outside_sha
 save('fixture-after-metadata.json',metadata());save('exact-integer-export.json',report)
 status,found=api('/software/disk-analysis/host/requests/'+key);save('read-only-original-key-lookup.json',found);assert status==200 and found['found']is True and found['job']['id']==job
 guard=subprocess.run(['/opt/panel/current/bin/panel-executor','--check-program-upgrade-queues'],capture_output=True,timeout=20);save('complete-guard-after-native-job.json',{'exit':guard.returncode,'stderr_sha256':hashlib.sha256(guard.stderr).hexdigest()});assert guard.returncode==0
 proof.update(ok=True,actual_native_host_subtree_scan_complete=True,exact_large_integer_counter_verified=True,actual_sparse_and_1024_hardlinks_deduplicated=True,actual_fifo_not_opened_and_symbolic_link_not_followed=True,fixture_metadata_and_sentinel_unchanged=True,read_only_original_request_lookup_verified=True,complete_guard_exit=0,all50_commercial=False)
except BaseException:save('failure.json',{'traceback':traceback.format_exc()})
finally:
 if csrf:
  try:status,_=api('/logout',{});assert status==200;proof['own_session_logged_out']=True
  except BaseException:proof['ok']=False;save('logout-failure.json',{'traceback':traceback.format_exc()})
 after=capture();save('after-all-Core-fields.json',after);save('Core-changed-table-names.json',{'changed':sorted(k for k in set(before)|set(after)if before.get(k)!=after.get(k))}if 'before'in locals()else{})
 save('proof.json',proof)
print(json.dumps(proof));sys.exit(0 if proof['ok']else 1)

