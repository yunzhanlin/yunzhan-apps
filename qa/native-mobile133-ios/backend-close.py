"""Observe the original client result, preserve original site bytes, close once."""
import contextlib,hashlib,json,os,pathlib,runpy,signal,sqlite3,stat,subprocess,sys,time,traceback
os.umask(0o077)
assert os.environ.get('GITHUB_ACTIONS')=='true'and os.environ.get('GITHUB_REPOSITORY')=='yunzhanlin/yunzhan-apps'
base=pathlib.Path(__file__).resolve().parent;private=pathlib.Path(sys.argv[1]).resolve(strict=True);proof={'ok':False,'Main_changed':False,'all50_commercial':False,'physical_device_acceptance':False}
def sha(f):return hashlib.sha256(pathlib.Path(f).read_bytes()).hexdigest()
def save(name,value):
 with(private/name).open('x')as f:json.dump(value,f,indent=2,sort_keys=True);f.write('\n')
try:
 assert(private/'original-backend-dispatch-issued.json').is_file(),'No original HTTPS dispatch was issued; preserve failure and close without waiting for UI'
 # The sealed final diagnostic artifact carries the original public outcome.
 # Do not transfer its potentially large xcresult/video envelope to a peer
 # that cannot decrypt it. Full originals remain in their separate artifact.
 exchange=runpy.run_path(str(base/'exchange.py'));peer=exchange['wait']('c68-ios-client-diagnostics-'+os.environ['GITHUB_RUN_ID'],private/'original-client-diagnostics',{'original-public-proof.json','original-diagnostics.cms'},seconds=1600)
 result=json.loads((peer/'original-public-proof.json').read_bytes());assert result['role']=='client'and result['head']==os.environ['GITHUB_SHA']and result['run_id']==os.environ['GITHUB_RUN_ID']
 setup=json.loads((private/'real-panel-setup.json').read_bytes());site=pathlib.Path('/srv/panel/sites')/setup['site']/'public'/setup['filename'];s=site.lstat();assert stat.S_ISREG(s.st_mode)and s.st_nlink==1 and s.st_size==setup['bytes']and sha(site)==setup['sha256']
 old=json.loads((private/'original-installed-204-entries.json').read_bytes());installed=pathlib.Path('/opt/panel/current').resolve(strict=True);assert len(old)==204
 for name,value in old.items():
  f=installed/name;st=f.lstat();assert st.st_uid==0 and not st.st_mode&0o022
  if value=='directory':assert stat.S_ISDIR(st.st_mode)
  else:assert stat.S_ISREG(st.st_mode)and st.st_nlink==1 and sha(f)==value
 with contextlib.closing(sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True))as db:
  db.row_factory=sqlite3.Row;db.execute('PRAGMA query_only=ON');rows={n:[dict(v)for v in db.execute('SELECT *FROM '+n)]for n in('sites','jobs','runtime_jobs','audit_logs')}
 assert len(rows['sites'])==len(rows['jobs'])==1 and rows['sites'][0]['id']==setup['site']and rows['sites'][0]['status']=='running'and rows['jobs'][0]['state']=='succeeded'and not rows['runtime_jobs']
 save('original-backend-after-real-iOS-UI.json',{'tables':rows,'original_owned_attachment':{'bytes':s.st_size,'sha256':sha(site),'inode':s.st_ino,'dev':s.st_dev},'original_programme_204_entries_unchanged':True,'original_client_finished':result})
 proof.update(ok=bool(result['ok']and result['actual_iOS_UI_acceptance']),actual_iOS_UI_acceptance=bool(result['actual_iOS_UI_acceptance']),original_owned_site_file_preserved=True,original_signed_programme_204_entries_preserved=True,normal_signed_programme_installs=1,source_inputs_sha256=setup['native_source_inputs_sha256'])
except BaseException:save('original-backend-final-observation-failure.json',{'traceback':traceback.format_exc()})
finally:
 try:
  intent=private/'original-cloudflared-intent.json'
  if intent.exists():
   value=json.loads(intent.read_bytes());pid=value['pid'];proc=pathlib.Path('/proc')/str(pid)
   if proc.exists():
    assert(proc/'exe').resolve(strict=True)==pathlib.Path(value['args'][0]).resolve(strict=True)and(proc/'cmdline').read_bytes().split(b'\0')[:-1]==[v.encode()for v in value['args']]
    os.kill(pid,signal.SIGTERM);end=time.monotonic()+20
    while proc.exists():
     state=(proc/'stat').read_text().rsplit(')',1)[1].split()[0]
     if state=='Z':break
     assert time.monotonic()<end;time.sleep(.2)
   proof['original_temporary_tunnel_closed']=True
 except BaseException:proof['ok']=False;save('original-tunnel-close-failure.json',{'traceback':traceback.format_exc()})
 save('original-backend-final-proof.json',proof)
print(json.dumps(proof));sys.exit(0 if proof['ok']else 1)
