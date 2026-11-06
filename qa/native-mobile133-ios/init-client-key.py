"""Create an ephemeral CI peer recipient; never upload its private key."""
import hashlib,json,os,pathlib,subprocess,sys
os.umask(0o077)
assert os.environ.get('GITHUB_ACTIONS')=='true'and os.environ.get('GITHUB_REPOSITORY')=='yunzhanlin/yunzhan-apps'
private=pathlib.Path(sys.argv[1]);public=pathlib.Path(sys.argv[2]);private.mkdir(mode=0o700);public.mkdir(mode=0o700)
prefix=subprocess.check_output(['brew','--prefix','openssl@3'],text=True).strip();openssl=prefix+'/bin/openssl';assert pathlib.Path(openssl).is_file()
args=[openssl,'req','-x509','-newkey','rsa:3072','-nodes','-days','1','-subj','/CN=Ephemeral C68 owned CI recipient','-keyout',str(private/'client-private.key'),'-out',str(public/'client-public.pem')]
with(private/'original-peer-key-generation.stdout').open('xb')as out,(private/'original-peer-key-generation.stderr').open('xb')as err:r=subprocess.run(args,stdin=subprocess.DEVNULL,stdout=out,stderr=err,timeout=45)
assert r.returncode==0 and (private/'client-private.key').stat().st_mode&0o777==0o600
with(private/'original-peer-key-provenance.json').open('x')as f:json.dump({'openssl':openssl,'public_certificate_sha256':hashlib.sha256((public/'client-public.pem').read_bytes()).hexdigest(),'private_key_not_uploaded':True,'no_TLS_trust_store_changed':True},f,indent=2)
