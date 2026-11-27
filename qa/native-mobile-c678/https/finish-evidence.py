"""Retain original device failures and reconcile owned backend files, then seal."""
import contextlib,hashlib,json,os,pathlib,sqlite3,stat,subprocess,sys,tarfile,traceback
os.umask(0o077)
assert os.geteuid()==0 and os.environ.get('GITHUB_ACTIONS')=='true'and os.environ.get('GITHUB_REPOSITORY')=='yunzhanlin/yunzhan-apps'
base=pathlib.Path(__file__).resolve().parent;pins=json.loads((base.parent/'backend/pins.json').read_bytes());private=pathlib.Path(sys.argv[1]).resolve(strict=True);public=pathlib.Path(sys.argv[2]).resolve(strict=True);owner=public.stat()
def sha(p):return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
def save(name,value):
 with(private/name).open('x')as f:json.dump(value,f,indent=2);f.write('\n')
proof={'ok':False,'physical_device_acceptance':False,'iOS_UI_acceptance':False,'release_trusted_HTTPS_business_acceptance':False,'Main_changed':False,'all50_commercial':False,'original_outcomes_replayed':False}
try:
 setup=json.loads((private/'real-panel-setup.json').read_bytes());assert setup['ok']
 old=json.loads((private/'original-installed-213-entries.json').read_bytes());installed=pathlib.Path('/opt/panel/current').resolve(strict=True);assert len(old)==pins['programme_expected_entries']
 for name,value in old.items():
  f=installed/name;s=f.lstat();assert s.st_uid==0 and not s.st_mode&0o022
  if value=='directory':assert stat.S_ISDIR(s.st_mode)
  else:assert stat.S_ISREG(s.st_mode)and s.st_nlink==1 and sha(f)==value
 original=pathlib.Path('/srv/panel/sites')/setup['site']/'public'/setup['filename'];st=original.lstat();assert stat.S_ISREG(st.st_mode)and st.st_nlink==1 and st.st_size==setup['bytes']and sha(original)==setup['sha256']
 with contextlib.closing(sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True))as db:
  db.row_factory=sqlite3.Row;db.execute('PRAGMA query_only=ON');sites=[dict(r)for r in db.execute('SELECT *FROM sites')];jobs=[dict(r)for r in db.execute('SELECT *FROM jobs')];runtimes=[dict(r)for r in db.execute('SELECT *FROM runtime_jobs')];audit=[dict(r)for r in db.execute('SELECT *FROM audit_logs')]
 assert len(sites)==1 and sites[0]['id']==setup['site']and sites[0]['status']=='running';assert len(jobs)==1 and jobs[0]['state']=='succeeded'and len(runtimes)==1 and runtimes[0]['state']=='succeeded'
 downloads=[r for r in audit if r['action']=='file.download'and r['target']==setup['site']+':'+setup['filename']and r['result']=='success']
 save('original-backend-after-device-UI.json',{'sites':sites,'jobs':jobs,'runtime_jobs':runtimes,'audit_logs':audit,'original_site_file':{'bytes':st.st_size,'sha256':sha(original),'inode':st.st_ino,'dev':st.st_dev,'uid':st.st_uid,'gid':st.st_gid,'mode':stat.S_IMODE(st.st_mode)},'original_programme_213_entries_unchanged':True})
 role_setup=json.loads((private/'original-role-TOTP-setup-proof.json').read_bytes());assert role_setup['ok'];assert runtimes[0]['id']==role_setup['original_user_manager_install_job']and runtimes[0]['state']=='succeeded'
 viewer='c678viewer';viewer_downloads=[r for r in downloads if r['actor']==viewer];assert viewer_downloads
 with contextlib.closing(sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True))as db:
  db.execute('PRAGMA query_only=ON');state=db.execute('SELECT r.role,r.site_ids,a.last_step FROM users u JOIN app_user_roles r ON r.user_id=u.id JOIN account_security a ON a.user_id=u.id WHERE u.username=?',(viewer,)).fetchone();codes=db.execute('SELECT count(*),sum(CASE WHEN used_at>0 THEN 1 ELSE 0 END)FROM account_recovery WHERE user_id=(SELECT id FROM users WHERE username=?)',(viewer,)).fetchone()
 assert state and state[0]=='viewer'and json.loads(state[1])==[setup['site']]and state[2]>0 and codes==(10,1);assert not(pathlib.Path('/srv/panel/sites')/setup['site']/'public/c678-forbidden-write.txt').exists()
 save('actual-original-viewer-factor-and-permission-final.json',{'role':state[0],'site_ids':json.loads(state[1]),'factor_last_step':state[2],'recovery_codes_issued':codes[0],'recovery_codes_consumed':codes[1],'actual_native_viewer_downloads':len(viewer_downloads),'forbidden_write_absent':True,'UserManager_original_install_job':runtimes[0]['id']})
 # Preserve the independent original backend observations even when the
 # native UI failed. A failed UI never prevents diagnosis or becomes a pass.
 api=int(os.environ['C68_UI_API']);assert api in(30,37)
 ui=json.loads((private/'original-device-UI-proof.json').read_bytes());assert ui['actual_Android_emulator_API']==api and ui['ok']and ui['release_trusted_HTTPS_business_acceptance']and ui['retained_publisher_signature_acceptance']and ui['native_source_inputs_sha256']==pins['native_source_inputs_sha256']and ui['programme_source_inputs_sha256']==pins['programme_source_inputs_sha256']
 assert ui['actual_normal_native_correct_TOTP_login']and ui['actual_normal_native_viewer_wrong_TOTP_refusal']and ui['actual_native_viewer_mutation_controls_disabled']and ui['actual_native_authorized_viewer_download']and ui['actual_native_recovery_code_login']and ui['actual_native_used_recovery_code_refused']and ui['actual_local_cookie_and_pending_download_clear']and all(ui['cleanup'].values())
 proof.update(ok=True,actual_Android_emulator_API=api,release_trusted_HTTPS_business_acceptance=True,actual_retained_publisher_signature_and_real_file_management_UI=True,actual_native_viewer_role_and_TOTP=True,actual_recovery_code_single_use=True,actual_native_authorized_read_and_disabled_write_controls=True,native_source_inputs_sha256=pins['native_source_inputs_sha256'],programme_source_inputs_sha256=pins['programme_source_inputs_sha256'],normal_signed_programme_installs=1,owned_site_and_original_attachment_retained=True)
except BaseException:save('original-independent-reconciliation-failure.json',{'traceback':traceback.format_exc()})
finally:
 try:
  value=json.loads((private/'original-cloudflared-intent.json').read_bytes());process=pathlib.Path('/proc')/str(value['pid'])
  if process.exists():
   assert(process/'exe').resolve(strict=True)==pathlib.Path(value['args'][0]).resolve(strict=True)and(process/'cmdline').read_bytes().split(b'\0')[:-1]==[v.encode()for v in value['args']]
   os.kill(value['pid'],__import__('signal').SIGTERM);deadline=__import__('time').monotonic()+20
   while process.exists():
    if(process/'stat').read_text().rsplit(')',1)[1].split()[0]=='Z':break
    assert __import__('time').monotonic()<deadline;__import__('time').sleep(.2)
  proof['original_temporary_tunnel_closed']=True
 except FileNotFoundError:
  if(private/'original-cloudflared-intent.json').exists():proof['ok']=False;save('original-tunnel-close-failure.json',{'traceback':traceback.format_exc()})
 except BaseException:proof['ok']=False;save('original-tunnel-close-failure.json',{'traceback':traceback.format_exc()})
 try:
  cert=base.parent/'backend/recipient.pem';assert sha(cert)==pins['recipient_sha256'];envelope=private/'original-private-evidence.tar.gz';count=0
  with tarfile.open(envelope,'x:gz')as t:
   for f in sorted(private.iterdir()):
    if f.name in('device-credentials.json','viewer-device-credentials.json',envelope.name)or not f.is_file()or f.suffix not in('.json','.stdout','.stderr','.xml','.log'):continue
    s=f.lstat();assert stat.S_ISREG(s.st_mode)and s.st_nlink==1 and not s.st_mode&0o077 and s.st_size<128<<20;t.add(f,arcname=f.name,recursive=False);count+=1
  sealed=public/'original-private-evidence.cms';r=subprocess.run(['openssl','cms','-encrypt','-binary','-aes-256-gcm','-in',str(envelope),'-outform','DER','-out',str(sealed),'-recip',str(cert),'-keyopt','rsa_padding_mode:oaep','-keyopt','rsa_oaep_md:sha256'],capture_output=True,timeout=90);assert r.returncode==0
  os.chown(sealed,owner.st_uid,owner.st_gid);proof['private_evidence']={'encrypted':True,'sha256':sha(sealed),'bytes':sealed.stat().st_size,'plaintext_sha256':sha(envelope),'original_files':count,'device_credentials_excluded':True,'recipient_sha256':sha(cert)}
 except BaseException:proof['ok']=False;save('original-evidence-sealing-failure.json',{'traceback':traceback.format_exc()})
 with(public/'original-public-proof.json').open('x')as f:json.dump(proof,f,indent=2);f.write('\n')
 os.chown(public/'original-public-proof.json',owner.st_uid,owner.st_gid)
print(json.dumps(proof));sys.exit(0 if proof['ok']else 1)
