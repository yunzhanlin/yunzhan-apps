"""Seal CI originals to the existing user recipient; no private keys shipped."""
import hashlib,json,os,pathlib,stat,subprocess,sys,tarfile,traceback
os.umask(0o077)
assert os.environ.get('GITHUB_ACTIONS')=='true'and os.environ.get('GITHUB_REPOSITORY')=='yunzhanlin/yunzhan-apps'
base=pathlib.Path(__file__).resolve().parent;private=pathlib.Path(sys.argv[1]).resolve(strict=True);public=pathlib.Path(sys.argv[2]).resolve(strict=True);owner=public.stat();role=sys.argv[3];assert role in('client','backend')
cert=base.parent/'native-mobile133/recipient.pem';assert hashlib.sha256(cert.read_bytes()).hexdigest()=='55ac5d4129117009583d47c47442bd07cc1de997e6a2a10b5652b3cb7fa54495'
proof={'ok':False,'role':role,'head':os.environ['GITHUB_SHA'],'run_id':os.environ['GITHUB_RUN_ID'],'Main_changed':False,'all50_commercial':False,'physical_device_acceptance':False,'biometric_success_acceptance':False}
try:
 result=private/('original-client-UI-proof.json'if role=='client'else'original-backend-final-proof.json')
 if result.is_file():proof.update(json.loads(result.read_bytes()))
 if sys.platform=='darwin':openssl=subprocess.check_output(['brew','--prefix','openssl@3'],text=True).strip()+'/bin/openssl'
 else:openssl='openssl'
 envelope=private/'original-private-evidence.tar.gz';included=[];total=0
 with tarfile.open(envelope,'x:gz')as t:
  for f in sorted(private.rglob('*')):
   relative=f.relative_to(private)
   if not f.is_file()or any(v in('client-build','harness-build')for v in relative.parts)or f.name in('client-private.key','client-credentials.json','device-credentials.json','client-credential-envelope.json','original-cloudflared-linux-amd64','original-peer-artifact.zip',envelope.name)or f.suffix=='.cms':continue
   s=f.lstat();assert stat.S_ISREG(s.st_mode)and s.st_nlink==1 and s.st_size<128<<20;total+=s.st_size;assert total<512<<20 and len(included)<8192
   t.add(f,arcname=str(relative),recursive=False);included.append({'name':str(relative),'bytes':s.st_size,'sha256':hashlib.sha256(f.read_bytes()).hexdigest()})
 sealed=public/'original-private-evidence.cms';r=subprocess.run([openssl,'cms','-encrypt','-binary','-aes-256-gcm','-in',str(envelope),'-outform','DER','-out',str(sealed),'-recip',str(cert),'-keyopt','rsa_padding_mode:oaep','-keyopt','rsa_oaep_md:sha256'],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=120);assert r.returncode==0
 proof['private_evidence']={'encrypted':True,'sha256':hashlib.sha256(sealed.read_bytes()).hexdigest(),'bytes':sealed.stat().st_size,'plaintext_sha256':hashlib.sha256(envelope.read_bytes()).hexdigest(),'original_files':len(included),'private_keys_and_credential_envelopes_excluded':True}
 if os.geteuid()==0:os.chown(sealed,owner.st_uid,owner.st_gid)
except BaseException:
 proof['ok']=False
 with(private/'original-evidence-sealing-failure.json').open('x')as f:json.dump({'traceback':traceback.format_exc()},f)
with(public/'original-public-proof.json').open('x')as f:json.dump(proof,f,indent=2);f.write('\n')
if os.geteuid()==0:os.chown(public/'original-public-proof.json',owner.st_uid,owner.st_gid)
if role=='client':
 with(public/'client-finished.json').open('x')as f:json.dump({'finished':True,'ok':proof['ok'],'head':os.environ['GITHUB_SHA'],'run_id':os.environ['GITHUB_RUN_ID'],'actual_iOS_UI_acceptance':proof.get('actual_iOS_UI_acceptance',False),'physical_device_acceptance':False},f)
print(json.dumps(proof));sys.exit(0 if proof['ok']else 1)
