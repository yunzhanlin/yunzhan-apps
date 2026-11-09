"""Encrypt complete original native evidence for the retained private recipient."""
import hashlib,io,json,os,pathlib,re,stat,subprocess,sys,tarfile,traceback
os.umask(0o077)
assert os.geteuid()==0 and len(sys.argv)==4
private=pathlib.Path(sys.argv[1]).absolute();public=pathlib.Path(sys.argv[2]);phase=sys.argv[3];assert phase in('phase1','phase2')
parent=public.parent.stat();assert parent.st_uid>0 and parent.st_gid>0
public.mkdir(mode=0o700)
source=pathlib.Path(__file__).resolve().parent;recipient=source/'recipient.pem'
sha=lambda f:hashlib.sha256(pathlib.Path(f).read_bytes()).hexdigest()
assert sha(recipient)=='55ac5d4129117009583d47c47442bd07cc1de997e6a2a10b5652b3cb7fa54495'
proof={'ok':False,'phase':phase,'Main_changed':False,'all50_commercial':False}
clear=pathlib.Path('/var/lib/c70-'+phase+'-original-evidence-'+os.urandom(16).hex()+'.tar.gz')
try:
 private=private.resolve(strict=True)
 cohort=json.loads((source/'cohort.json').read_bytes());proof.update(source_inputs_sha256=cohort['source_inputs_sha256'],source_head=cohort['source_head'])
 original=private/('business-'+phase)/'original-proof.json'
 if original.exists():actual=json.loads(original.read_bytes());proof.update(ok=actual.get('ok')is True,actual_original_outcome=actual)
 else:proof['actual_original_outcome']={'ok':False,'not_reached_or_original_process_failed':True}
 files=sorted(f for f in private.rglob('*')if f.is_file()or f.is_symlink());assert 1<=len(files)<=1200
 entries={};total=0
 with tarfile.open(clear,'x:gz')as tar:
  for f in files:
   name=f.relative_to(private).as_posix();before=f.lstat();assert re.fullmatch('[A-Za-z0-9._/-]+',name)and '..'not in pathlib.PurePosixPath(name).parts
   assert stat.S_ISREG(before.st_mode)and before.st_nlink==1 and not before.st_mode&0o077 and before.st_uid in(0,parent.st_uid)and before.st_size<=64<<20
   with os.fdopen(os.open(f,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC),'rb')as src:raw=src.read((64<<20)+1);opened=os.fstat(src.fileno())
   after=f.lstat();identity=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
   assert identity(before)==identity(opened)==identity(after)and len(raw)==before.st_size
   total+=len(raw);assert total<=256<<20
   info=tarfile.TarInfo(name);info.size=len(raw);info.mode=stat.S_IMODE(before.st_mode);info.uid=before.st_uid;info.gid=before.st_gid;info.mtime=before.st_mtime;tar.addfile(info,io.BytesIO(raw))
   entries[name]={'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'mode':info.mode,'uid':info.uid,'gid':info.gid,'mtime_ns':before.st_mtime_ns}
 cms=public/('original-'+phase+'-private-evidence.tar.gz.cms')
 args=['/usr/bin/openssl','cms','-encrypt','-binary','-aes-256-cbc','-outform','DER','-in',str(clear),'-out',str(cms),str(recipient)]
 r=subprocess.run(args,capture_output=True,timeout=120);assert r.returncode==0,r.stderr[-1000:]
 proof.update(original_file_count=len(entries),original_private_files=entries,original_clear_archive_bytes=clear.stat().st_size,original_clear_archive_sha256=sha(clear),encrypted_archive_bytes=cms.stat().st_size,encrypted_archive_sha256=sha(cms),original_clear_archive_retained_privately=str(clear),recipient_sha256=sha(recipient),private_key_uploaded=False)
except BaseException:
 proof.update(ok=False,collection_failure=traceback.format_exc())
finally:
 p=public/'original-public-proof.json'
 with p.open('x')as f:json.dump(proof,f,indent=2);f.write('\n')
 for f in public.iterdir():f.chmod(0o600);os.chown(f,parent.st_uid,parent.st_gid)
 os.chown(public,parent.st_uid,parent.st_gid)
 print(json.dumps({'ok':proof['ok'],'phase':phase,'original_file_count':proof.get('original_file_count',0),'encrypted_bytes':proof.get('encrypted_archive_bytes',0),'private_key_uploaded':False,'all50_commercial':False}),flush=True)
sys.exit(0 if proof['ok']else 1)
