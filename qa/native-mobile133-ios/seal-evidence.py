"""Seal CI originals to the existing user recipient; no private keys shipped."""
import hashlib,io,json,os,pathlib,stat,subprocess,sys,tarfile,traceback
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
   if not f.is_file()or any(v in('client-build','harness-build','original-AX-exports')for v in relative.parts)or f.name in('client-private.key','client-credentials.json','device-credentials.json','client-credential-envelope.json','original-cloudflared-linux-amd64','original-peer-artifact.zip',envelope.name)or f.suffix=='.cms':continue
   s=f.lstat();assert stat.S_ISREG(s.st_mode)and s.st_nlink==1 and s.st_size<128<<20;total+=s.st_size;assert total<512<<20 and len(included)<8192
   t.add(f,arcname=str(relative),recursive=False);included.append({'name':str(relative),'bytes':s.st_size,'sha256':hashlib.sha256(f.read_bytes()).hexdigest()})
 sealed=public/'original-private-evidence.cms';r=subprocess.run([openssl,'cms','-encrypt','-binary','-aes-256-gcm','-in',str(envelope),'-outform','DER','-out',str(sealed),'-recip',str(cert),'-keyopt','rsa_padding_mode:oaep','-keyopt','rsa_oaep_md:sha256'],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=120);assert r.returncode==0
 proof['private_evidence']={'encrypted':True,'sha256':hashlib.sha256(sealed.read_bytes()).hexdigest(),'bytes':sealed.stat().st_size,'plaintext_sha256':hashlib.sha256(envelope.read_bytes()).hexdigest(),'original_files':len(included),'private_keys_and_credential_envelopes_excluded':True}
 if os.geteuid()==0:os.chown(sealed,owner.st_uid,owner.st_gid)
 # A small diagnostic envelope contains exact members of the full originals.
 # The complete xcresult, screenshots and all failures remain retained above.
 wanted={v['name']:v for v in included if len(pathlib.PurePosixPath(v['name']).parts)==1 and pathlib.PurePosixPath(v['name']).suffix in('.json','.stdout','.stderr','.png')and v['bytes']<1<<20}
 diagnostics=private/'original-diagnostics.tar.gz';selected=[];total=0
 with tarfile.open(envelope,'r:gz')as source,tarfile.open(diagnostics,'x:gz')as dest:
  for member in source:
   if member.name not in wanted:continue
   raw=source.extractfile(member).read();pin=wanted[member.name];assert len(raw)==pin['bytes']and hashlib.sha256(raw).hexdigest()==pin['sha256'];total+=len(raw);assert total<8<<20;dest.addfile(member,io.BytesIO(raw));selected.append(pin)
  index=json.dumps({'original_full_plaintext_sha256':proof['private_evidence']['plaintext_sha256'],'exact_original_members':selected},indent=2).encode();member=tarfile.TarInfo('original-diagnostic-members.json');member.mode=0o600;member.size=len(index);dest.addfile(member,io.BytesIO(index))
 diagnostic_cipher=public/'original-diagnostics.cms';r=subprocess.run([openssl,'cms','-encrypt','-binary','-aes-256-gcm','-in',str(diagnostics),'-outform','DER','-out',str(diagnostic_cipher),'-recip',str(cert),'-keyopt','rsa_padding_mode:oaep','-keyopt','rsa_oaep_md:sha256'],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=60);assert r.returncode==0
 proof['original_diagnostics']={'sha256':hashlib.sha256(diagnostic_cipher.read_bytes()).hexdigest(),'bytes':diagnostic_cipher.stat().st_size,'plaintext_sha256':hashlib.sha256(diagnostics.read_bytes()).hexdigest(),'exact_original_members':len(selected),'full_original_evidence_retained':True}
 if os.geteuid()==0:os.chown(diagnostic_cipher,owner.st_uid,owner.st_gid)
except BaseException:
 proof['ok']=False
 with(private/'original-evidence-sealing-failure.json').open('x')as f:json.dump({'traceback':traceback.format_exc()},f)
with(public/'original-public-proof.json').open('x')as f:json.dump(proof,f,indent=2);f.write('\n')
if os.geteuid()==0:os.chown(public/'original-public-proof.json',owner.st_uid,owner.st_gid)
if role=='client':
 with(public/'client-finished.json').open('x')as f:json.dump({'finished':True,'ok':proof['ok'],'head':os.environ['GITHUB_SHA'],'run_id':os.environ['GITHUB_RUN_ID'],'actual_iOS_UI_acceptance':proof.get('actual_iOS_UI_acceptance',False),'physical_device_acceptance':False},f)
print(json.dumps(proof));sys.exit(0 if proof['ok']else 1)
