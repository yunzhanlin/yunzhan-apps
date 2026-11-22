from pathlib import Path
import contextlib,copy,hashlib,http.cookiejar,json,os,re,secrets,sqlite3,stat,subprocess,sys,time,traceback,urllib.request,urllib.error
os.umask(0o077);inp=Path(sys.argv[1]);plan=json.loads((inp/'plan.json').read_bytes());assert os.geteuid()==0 and Path('/etc/hostname').read_text().strip()==plan['host'];source=json.loads(Path('/opt/panel/current/SOURCE_INPUTS.json').read_bytes())['inputs_sha256'];assert source==plan['source'];assert hashlib.sha256(Path('/etc/machine-id').read_bytes()).hexdigest()==plan['machine'];base=Path(plan['case_base']);assert base.parent==Path('/var/lib/panel-executor')and re.fullmatch('c592-owned-apache-replay-[a-f0-9]{32}',base.name);base.mkdir(mode=0o700);evidence=base/'evidence';evidence.mkdir(mode=0o700);backup=base/'private-managed-file-copies';backup.mkdir(mode=0o700)
paths=[Path(p)for p in('/etc/panel/apache/httpd.conf','/etc/panel/security-apps/modules/apache-waf/rules.conf','/etc/panel/security-apps/modules/apache-waf/installed.json')]
def sha(p):
 h=hashlib.sha256()
 with Path(p).open('rb')as f:
  for b in iter(lambda:f.read(1<<20),b''):h.update(b)
 return h.hexdigest()
def save(n,v):
 with(evidence/n).open('x')as f:json.dump(v,f,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
def stable(p):
 with os.fdopen(os.open(p,os.O_RDONLY|os.O_NOFOLLOW),'rb')as f:
  s=os.fstat(f.fileno());assert stat.S_ISREG(s.st_mode)and s.st_uid==0 and s.st_nlink==1 and s.st_size<=4<<20;raw=f.read((4<<20)+1);assert len(raw)==s.st_size
 return raw,{'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw),'uid':s.st_uid,'gid':s.st_gid,'mode':stat.S_IMODE(s.st_mode),'inode':s.st_ino,'dev':s.st_dev,'links':s.st_nlink}
def snapshot(label):
 raw={};meta={};d=backup/label;d.mkdir(mode=0o700)
 for i,p in enumerate(paths):
  b,v=stable(p);raw[str(p)]=b;meta[str(p)]=v
  with(d/(str(i)+'.bin')).open('xb')as f:f.write(b);f.flush();os.fsync(f.fileno())
 save(label+'-managed-files.json',meta);return raw,meta

def same_snapshot(raw,meta):return all(stable(p)==(raw[str(p)],meta[str(p)])for p in paths)
def restore_bytes(target_raw,expected_raw,expected_meta):
 # Only the new guest's three fixed files are written, after an exact precondition check.
 # Original parent disks are separately forced read-only by QEMU.
 assert same_snapshot(expected_raw,expected_meta)
 for p in paths:
  fd=os.open(p,os.O_WRONLY|os.O_NOFOLLOW)
  try:
   st=os.fstat(fd);assert st.st_uid==0 and st.st_nlink==1 and st.st_ino==expected_meta[str(p)]['inode']and stat.S_ISREG(st.st_mode)
   with os.fdopen(fd,'wb',closefd=False)as f:f.write(target_raw[str(p)]);f.truncate();f.flush();os.fsync(fd)
  finally:os.close(fd)
 assert all(stable(p)[0]==target_raw[str(p)]for p in paths)
def preserved():
 out={}
 for root in('/opt/panel/current','/opt/panel/runtimes','/srv/panel/sites','/var/lib/panel-apache-body/cc-archives','/var/lib/panel-apache-body/cc-archive-history'):
  d=Path(root)
  if not d.exists():continue
  for p in d.rglob('*'):
   s=p.lstat()
   if stat.S_ISREG(s.st_mode):out[str(p)]={'sha256':sha(p),'bytes':s.st_size,'uid':s.st_uid,'gid':s.st_gid,'mode':stat.S_IMODE(s.st_mode),'inode':s.st_ino,'links':s.st_nlink}
   elif stat.S_ISLNK(s.st_mode):out[str(p)]={'link':os.readlink(p)}
   else:assert stat.S_ISDIR(s.st_mode)
 assert len(out)<40000;return out

def rows():
 with contextlib.closing(sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True))as db:
  db.execute('PRAGMA query_only=ON');assert db.execute('PRAGMA quick_check').fetchone()==('ok',);db.row_factory=sqlite3.Row
  return {t:[dict(r)for r in db.execute('SELECT *FROM '+t+' ORDER BY 1')]for t in('runtime_jobs','runtime_installations','sites','app_registry_install_requests','app_registry_receipts')}
def daemon():
 v=dict(l.split('=',1)for l in subprocess.check_output(['systemctl','show','panel-apache','-p','MainPID,InvocationID,ActiveState,ExecMainStartTimestampMonotonic'],text=True).splitlines());assert v['ActiveState']=='active'and int(v['MainPID'])>1;v['exe']=os.readlink('/proc/'+v['MainPID']+'/exe');assert v['exe']=='/opt/panel/runtimes/apache/2.4.71/bin/httpd';v['processes']={}
 for p in Path('/proc').iterdir():
  if not p.name.isdigit():continue
  try:
   if os.readlink(p/'exe')==v['exe']:v['processes'][p.name]=(p/'stat').read_text().rsplit(')',1)[1].split()[19]
  except (FileNotFoundError,ProcessLookupError,PermissionError):pass
 return v
origin='http://127.0.0.1:19100';csrf=''
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*a,**kw):raise AssertionError('Unexpected redirect')
client=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect(),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
def api(label,path,body=None,status=200):
 headers={'Origin':origin,'Content-Type':'application/json','X-CSRF-Token':csrf};raw=None
 if body is not None:
  key=secrets.token_hex(16);headers['Idempotency-Key']=key;raw=json.dumps(body).encode();save(label+'-intent.json',{'path':path,'key':key,'maximum_submissions':1,'body':'redacted'if path=='/login'else body})
 try:
  with client.open(urllib.request.Request(origin+'/api'+path,raw,headers),timeout=80)as r:got=r.status;b=r.read((8<<20)+1)
 except urllib.error.HTTPError as r:got=r.code;b=r.read((8<<20)+1)
 assert len(b)<=8<<20;v=json.loads(b)
 if path!='/login':save(label+'-response.json',{'status':got,'value':v})
 assert got==status,(label,got,v);return v

def wait(label,jid,expected):
 assert re.fullmatch('[a-f0-9]{32}',jid)
 for _ in range(240):
  with contextlib.closing(sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True))as db:
   db.row_factory=sqlite3.Row;r=dict(db.execute('SELECT *FROM runtime_jobs WHERE id=?',(jid,)).fetchone())
  if r['state']not in('queued','running'):save(label+'-original-terminal.json',r);assert r['state']==expected,(label,r);return r
  time.sleep(1)
 raise TimeoutError('Original job remains unresolved; never repeat POST')
def apply(label,settings,expected='succeeded'):
 r=api(label,'/software/apache-waf/configure',{'settings':settings},202);return wait(label,r['job_id'],expected)
proof={'ok':False,'base':str(base),'source_inputs_sha256':source,'Main_changes':0,'all40_commercial':False,'original_operation_replays':0};needs_restore=False
try:
 for _ in range(120):
  try:
   with urllib.request.urlopen(origin+'/api/ready',timeout=2)as r:
    if r.status==200:break
  except Exception:pass
  time.sleep(1)
 else:raise TimeoutError('Owned Core not ready')
 before=rows();assert all(r['state']in('succeeded','failed','cancelled','canceled')for r in before['runtime_jobs']);save('original-preserved-SQL.json',before);files=preserved();save('original-preserved-files.json',files)
 access=json.loads(Path('/etc/panel/first-login.json').read_bytes());csrf=api('login','/login',{k:access[k]for k in('username','password')})['csrf'];access.clear();original=api('initial-original-healthy','/software/apache-waf/config');assert original['status']['healthy']and original['status']['version']=='2.5.1';settings0=copy.deepcopy(original['settings']);assert settings0['apache_cc']['engine_job_id'];snap0=snapshot('original');master=daemon()
 first=apply('first-known-successful-identical-policy',settings0);one=api('first-healthy','/software/apache-waf/config');settings1=one['settings'];assert one['status']['healthy']and settings1['policy']['revision']==settings0['policy']['revision']+1;snap1=snapshot('first-known-successful')
 second=apply('second-known-successful-identical-policy',settings1);two=api('second-healthy','/software/apache-waf/config');settings2=two['settings'];assert two['status']['healthy']and settings2['policy']['revision']==settings1['policy']['revision']+1;snap2=snapshot('second-known-successful')
 for s in(settings1,settings2):c=copy.deepcopy(s);c['policy']['revision']=settings0['policy']['revision'];assert c==settings0
 assert snap1[0]!=snap2[0];time.sleep(2);identity_before=daemon();assert identity_before['MainPID']==master['MainPID']and identity_before['InvocationID']==master['InvocationID']
 restore_bytes(snap1[0],*snap2);needs_restore=True;stale_disk=snapshot('only-new-COW-stale-persisted-files')
 mismatch=api('actual-live-and-disk-mismatch','/software/apache-waf/config');assert not mismatch['status']['healthy'];assert mismatch['settings']==settings1
 bad=apply('new-key-known-successful-input-with-mismatched-live-daemon',settings0,'failed');assert 'Apache 原生原请求字节已提交但实际加载未核实，未重载、重写或冒充成功：' in bad['error']and '实际加载指纹与配置不一致'in bad['error'];assert same_snapshot(*stale_disk);assert daemon()==identity_before;save('actual-mismatch-refused-without-writes-or-reload.json',{'ok':True,'job_id':bad['id'],'original_error':bad['error'],'all_three_bytes_and_metadata_exact':True,'actual_processes_and_master_exact':True})
 restore_bytes(snap2[0],*stale_disk);needs_restore=False;known_restored=snapshot('known-current-disk-restored');restored=api('healthy-after-byte-restoration-without-reload','/software/apache-waf/config');assert restored['status']['healthy']and restored['settings']==settings2;assert daemon()==identity_before
 good=apply('new-key-known-successful-input-with-matched-live-daemon',settings1);assert same_snapshot(*known_restored)and daemon()==identity_before;save('actual-matched-readonly-confirmation.json',{'ok':True,'job_id':good['id'],'all_three_bytes_and_metadata_exact':True,'actual_processes_and_master_exact':True});final=api('final-healthy','/software/apache-waf/config');assert final['status']['healthy']and final['settings']==settings2
 after_files=preserved();save('preserved-files-after.json',after_files);assert after_files==files;after=rows();save('preserved-SQL-after.json',after)
 for t in before:
  if t=='runtime_jobs':
   prior={r['id']:r for r in before[t]};current={r['id']:r for r in after[t]};assert all(current.get(k)==v for k,v in prior.items()),t
  else:assert after[t]==before[t],t
 assert len(after['runtime_jobs'])==len(before['runtime_jobs'])+4
 proof.update(ok=True,architecture={'aarch64':'arm64','x86_64':'amd64'}[os.uname().machine],original_boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip(),actual_signed_app_version='2.5.1',actual_Apache='2.4.71',actual_live_mismatch_failed_job=bad['id'],actual_matched_readonly_replay_job=good['id'],actual_live_fingerprint_mismatch_refused=True,failed_request_did_not_rewrite_or_reload=True,matched_readonly_replay_did_not_rewrite_or_reload=True,original_policy_semantics_preserved_with_two_legitimate_revision_increments=True,original_preserved_files=len(files),original_SQL_rows_exact=True,all_original_sites_and_archives_preserved=True,new_independent_requests=4,original_Apache_master_preserved=True)
except BaseException:proof['failure']=traceback.format_exc()[-6000:]
finally:
 if needs_restore:
  try:restore_bytes(snap2[0],*stale_disk);proof['known_current_files_restored_after_failed_test']=True
  except BaseException:proof['restoration_failure']=traceback.format_exc()[-2000:]
 if csrf:
  try:api('logout','/logout',{})
  except BaseException:proof['ok']=False;proof['logout_failure']=True
 save('proof.json',proof);print(json.dumps(proof),flush=True)
sys.exit(0 if proof['ok']else 1)
