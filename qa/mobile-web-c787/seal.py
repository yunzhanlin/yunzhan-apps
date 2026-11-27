from pathlib import Path
import hashlib,io,json,os,stat,subprocess,sys,tarfile
os.umask(0o077);assert os.geteuid()==0 and os.environ.get('GITHUB_ACTIONS')=='true';base=Path(__file__).resolve().parent;private=Path(sys.argv[1]).resolve(strict=True);public=Path(sys.argv[2]).resolve(strict=True);owner=public.stat();cert=base/'recipient.pem';sha=lambda f:hashlib.sha256(Path(f).read_bytes()).hexdigest();assert sha(cert)=='55ac5d4129117009583d47c47442bd07cc1de997e6a2a10b5652b3cb7fa54495';p={'ok':False,'run_id':os.environ['GITHUB_RUN_ID'],'head':os.environ['GITHUB_SHA'],'native_App_runs':0,'Main_changes':0,'all40_commercial':False}
f=private/'original-final-proof.json'
if f.is_file():p.update(json.loads(f.read_bytes()))
packet=io.BytesIO();included=[]
with tarfile.open(fileobj=packet,mode='w:gz')as t:
 for f in sorted(private.rglob('*')):
  if not f.is_file()or 'credentials'in f.name.lower()or f.suffix in['.sqlite','.key','.cms','.bin']or f.name=='proxy-config.json':continue
  st=f.lstat();assert stat.S_ISREG(st.st_mode)and st.st_nlink==1 and st.st_size<16<<20;t.add(f,arcname=str(f.relative_to(private)),recursive=False);included.append(str(f.relative_to(private)))
raw=packet.getvalue();assert len(raw)<32<<20;envelope=public/'original-web-evidence.cms';r=subprocess.run(['openssl','cms','-encrypt','-binary','-aes-256-gcm','-outform','DER','-out',str(envelope),'-recip',str(cert),'-keyopt','rsa_padding_mode:oaep','-keyopt','rsa_oaep_md:sha256'],input=raw,capture_output=True,timeout=120);assert r.returncode==0;os.chown(envelope,owner.st_uid,owner.st_gid);p['evidence']={'sha256':sha(envelope),'bytes':envelope.stat().st_size,'files':len(included),'credentials_factors_keys_and_databases_excluded':True,'plaintext_sha256':hashlib.sha256(raw).hexdigest()};out=public/'original-public-proof.json';out.open('x').write(json.dumps(p,indent=2)+'\n');os.chown(out,owner.st_uid,owner.st_gid);print(json.dumps(p));assert p['ok']
