"""Preserve original Root source outputs in an archive readable by the runner."""
import hashlib,io,json,os,pathlib,re,stat,sys,tarfile,traceback
os.umask(0o077)
assert os.geteuid()==0 and len(sys.argv)==5
source=pathlib.Path(sys.argv[1]);public=pathlib.Path(sys.argv[2]);head=sys.argv[3];run=sys.argv[4]
assert re.fullmatch('[a-f0-9]{40}',head)and run.isdecimal()
parent=public.parent.stat();assert parent.st_uid>0 and parent.st_gid>0
public.mkdir(mode=0o700)
proof={'ok':False,'source_fixture_only_not_installed_PM2':True,'head':head,'run':int(run),'all50_commercial':False}
def sha(p):return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
try:
 st=source.lstat();assert stat.S_ISDIR(st.st_mode)and st.st_uid==0 and stat.S_IMODE(st.st_mode)==0o700 and not source.is_symlink()
 files=sorted(source.iterdir());assert 1<=len(files)<=32
 entries={};total=0;archive=public/'original-Root-source-outputs.tar.gz'
 with tarfile.open(archive,'x:gz',dereference=False)as tar:
  for f in files:
   before=f.lstat();assert re.fullmatch('[A-Za-z0-9._-]+',f.name)and stat.S_ISREG(before.st_mode)and before.st_uid==0 and before.st_nlink==1 and not before.st_mode&0o077 and before.st_size<=128<<20
   with os.fdopen(os.open(f,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC),'rb')as src:raw=src.read((128<<20)+1);opened=os.fstat(src.fileno())
   after=f.lstat()
   identity=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
   assert identity(before)==identity(opened)==identity(after)and len(raw)==before.st_size
   total+=len(raw);assert total<=192<<20
   info=tarfile.TarInfo(f.name);info.size=len(raw);info.mode=stat.S_IMODE(before.st_mode);info.uid=before.st_uid;info.gid=before.st_gid;info.mtime=before.st_mtime
   tar.addfile(info,io.BytesIO(raw))
   entries[f.name]={'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'mode':info.mode,'uid':info.uid,'gid':info.gid,'mtime_ns':before.st_mtime_ns}
 assert 'original-proof.json'in entries
 actual=json.loads((source/'original-proof.json').read_bytes());proof.update(ok=actual['ok']is True,original_proof=actual,archive_bytes=archive.stat().st_size,archive_sha256=sha(archive),all_original_bytes_and_Root_metadata_retained=entries,original_Root_output_directory_unchanged=True)
except BaseException:
 proof['collector_failure']=traceback.format_exc()
finally:
 with(public/'original-collection-proof.json').open('x')as f:json.dump(proof,f,indent=2);f.write('\n')
 for f in public.iterdir():
  assert f.is_file()and not f.is_symlink();f.chmod(0o600);os.chown(f,parent.st_uid,parent.st_gid)
 os.chown(public,parent.st_uid,parent.st_gid)
 print(json.dumps({'ok':proof['ok'],'actual_original_source_outcome':proof.get('original_proof',{}).get('ok'),'archive_bytes':proof.get('archive_bytes',0),'original_output_count':len(proof.get('all_original_bytes_and_Root_metadata_retained',{})),'all50_commercial':False}),flush=True)
sys.exit(0 if proof['ok']else 1)

