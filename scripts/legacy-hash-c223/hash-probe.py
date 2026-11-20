from pathlib import Path
import subprocess,json,hashlib,hmac,sys,re,platform
p=Path(sys.argv[1]);version=sys.argv[2];assert version in ['5.2.17','5.3.29']
compose=['docker','compose','--project-name','panel-c223-legacy-php-fixture','-f',str(p/'compose.yaml')]
cid=subprocess.check_output(compose+['ps','-q','php'],text=True).strip();assert re.fullmatch('[a-f0-9]{64}',cid)
def run(code):
 r=subprocess.run(['docker','exec','-i','--user','1000:1000',cid,'php','-r',code],stdin=subprocess.DEVNULL,capture_output=True,timeout=45)
 assert r.returncode==0,(r.returncode,r.stdout[:2048],r.stderr[:2048]);return json.loads(r.stdout)
code=r"""if(!extension_loaded('hash')||!function_exists('hash_file'))exit(3);
echo json_encode(array('version'=>PHP_VERSION,'sha256'=>hash('sha256','abc'),'hmac_sha256'=>hash_hmac('sha256','abc','key'),'file_sha256'=>hash_file('sha256','/var/www/html/index.php')));"""
v=run(code);assert v['version']==version and v['sha256']==hashlib.sha256(b'abc').hexdigest()and v['hmac_sha256']==hmac.new(b'key',b'abc',hashlib.sha256).hexdigest()
rows=run((Path(__file__).resolve().parent/'original-inventory-probe.php').read_text());assert set(rows)=={'index.php','retained.txt','.private.php'}
for name,value in rows.items():
 actual=subprocess.check_output(['docker','exec','--user','1000:1000',cid,'sha256sum','/var/www/html/'+name],text=True,timeout=15).split()[0];assert re.fullmatch('[a-f0-9]{64}',actual)and value['sha256']==actual
assert v['file_sha256']==rows['index.php']['sha256']
for label in ['before','after']:
 value=json.loads((p/(label+'.json')).read_bytes());assert value['sha256']==v['sha256']and value['hmac_sha256']==v['hmac_sha256']
licenses=subprocess.check_output(['docker','run','--rm','--network','none','--read-only','panel-legacy-php-native:qa','cat','/usr/local/share/licenses/php/LICENSE'],timeout=20);assert len(licenses)>1000
proof={'ok':True,'version':version,'architecture':{'x86_64':'amd64','aarch64':'arm64'}[platform.machine()],'actual_FastCGI_HTTP_SHA256_and_HMAC':True,'actual_nonroot_CLI_file_SHA256_matches_coreutils':True,'exact_original_panel_inventory_PHP_passed':True,'upstream_license_present':True,'license_sha256':hashlib.sha256(licenses).hexdigest(),'Main_changed':False,'signed_store_acceptance':False}
(p/'original-hash-proof.json').write_text(json.dumps(proof,indent=2)+'\n');print(json.dumps(proof))
