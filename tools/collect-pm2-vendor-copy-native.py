import hashlib,json,os,pathlib,stat,sys,tarfile,traceback
os.umask(0o077);assert os.geteuid()==0 and len(sys.argv)==3
private=pathlib.Path(sys.argv[1]);public=pathlib.Path(sys.argv[2]);owner=public.parent.stat();assert owner.st_uid>0 and owner.st_gid>0;public.mkdir(mode=0o700)
proof={'ok':False,'Main_changed':False,'all50_commercial':False,'private_key_uploaded':False}
try:
 files={}
 for n in('original-go.stdout.jsonl','original-go.stderr.log','original-proof.json','original-real-builder-files.json','original-system-program-links.stdout.jsonl'):
  f=private/n;s=f.lstat();assert stat.S_ISREG(s.st_mode)and s.st_uid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600 and s.st_size<64<<20;raw=f.read_bytes();assert len(raw)==s.st_size;files[n]={'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'uid':s.st_uid,'gid':s.st_gid,'mode':stat.S_IMODE(s.st_mode),'inode':s.st_ino}
 archive=public/'original-Root-evidence.tar.gz'
 with tarfile.open(archive,'x:gz')as tar:
  for n in sorted(files):tar.add(private/n,arcname=n,recursive=False)
 actual=json.loads((private/'original-proof.json').read_bytes());proof.update(ok=True,original_test_outcome=actual,original_private_file_metadata=files,archive_bytes=archive.stat().st_size,archive_sha256=hashlib.sha256(archive.read_bytes()).hexdigest(),original_Root_files_retained_without_permission_changes=True)
except BaseException:proof['collection_failure']=traceback.format_exc()
with(public/'original-public-proof.json').open('x')as f:json.dump(proof,f,indent=2);f.write('\n')
for f in public.iterdir():f.chmod(0o600);os.chown(f,owner.st_uid,owner.st_gid)
os.chown(public,owner.st_uid,owner.st_gid);print(json.dumps({'ok':proof['ok'],'original_test_ok':proof.get('original_test_outcome',{}).get('ok'),'Main_changed':False}),flush=True);sys.exit(0 if proof['ok']else 1)
