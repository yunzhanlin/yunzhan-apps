"""Retrieve the pinned signed programme and verify this isolated fixture before use."""
import base64,hashlib,json,os,pathlib,platform,re,subprocess,sys,urllib.request
os.umask(0o077)
assert len(sys.argv)==3 and os.environ.get('GITHUB_ACTIONS')=='true'and os.environ.get('GITHUB_REPOSITORY')=='yunzhanlin/yunzhan-apps'
source=pathlib.Path(__file__).resolve().parent
cohort=json.loads((source/'cohort.json').read_bytes())
dispatch=json.loads((source/'dispatch.json').read_bytes())
assert cohort['source_head']==dispatch['source_head']and cohort['source_inputs_sha256']==dispatch['source_inputs_sha256']and cohort['version']==dispatch['version']
arch={'x86_64':'amd64','aarch64':'arm64'}[platform.machine()]
out=pathlib.Path(sys.argv[1]);private=pathlib.Path(sys.argv[2]);out.mkdir(mode=0o700);private.mkdir(mode=0o700)
def save(n,v):
 with(private/n).open('x')as f:json.dump(v,f,indent=2);f.write('\n')
def sha(f):return hashlib.sha256(pathlib.Path(f).read_bytes()).hexdigest()
def gh(path):
 r=subprocess.run(['gh','api','repos/yunzhanlin/yunzhan-apps/'+path],capture_output=True,timeout=90)
 assert r.returncode==0;return json.loads(r.stdout)
parent=subprocess.check_output(['git','rev-parse','HEAD^'],text=True).strip()
assert parent==cohort.get('native_fixture_parent', cohort['source_head'])
changes={os.fsdecode(p)for p in subprocess.check_output(['git','diff','--name-only','-z','HEAD^','HEAD']).split(b'\0')if p}
assert changes==set(cohort.get('changed_payload_files', cohort['payload_files']))|{'scripts/native-rabbitmq-c71/cohort.json'}
for n,h in cohort['payload_files'].items():assert sha(n)==h,n
tree=subprocess.check_output(['git','rev-parse',parent+':candidate/panel-integration-compose-signed-image'],text=True).strip()
assert tree==dispatch['source_sdk_tree']
rid=dispatch['release_id'];release=gh('releases/'+str(rid))
assert release['id']==rid and release['tag_name']==dispatch['tag']and release['target_commitish']==dispatch['source_head']and not release['draft']and release['prerelease']
assets={a['name']:a for a in release['assets']};expected=dispatch['release_assets'];assert set(assets)==set(expected)
save('original-programme-release.json',release)
for n in [dispatch['cohorts'][arch]['archive']+s for s in('','.manifest','.sig')]+['release-signing-dev.pub']:
 pin=expected[n];a=assets[n]
 assert a['id']==pin['id']and a['state']=='uploaded'and a['size']==pin['bytes']and a['digest']=='sha256:'+pin['sha256']
 with(out/n).open('xb')as f:r=subprocess.run(['gh','api','-H','Accept: application/octet-stream','repos/yunzhanlin/yunzhan-apps/releases/assets/'+str(a['id'])],stdout=f,stderr=subprocess.PIPE,timeout=180)
 assert r.returncode==0 and (out/n).stat().st_size==pin['bytes']and sha(out/n)==pin['sha256']
assert sha(out/'release-signing-dev.pub')=='4ccfcc861d56a41e3ba7f7ace7e2432c815f366c58448d783df92c6632f01339'
verifier=source/'original-signed-release.py'
assert sha(verifier)=='fe128e82b4e11345b320cd782134768bfe1a4df14947c425d7494873a7a7b7b5'
(out/'signed-release.py').open('xb').write(verifier.read_bytes())
save('original-download-proof.json',{'ok':True,'original_release_id':rid,'architecture':arch,'source_head':dispatch['source_head'],'source_inputs_sha256':dispatch['source_inputs_sha256'],'original_exact_assets':4,'installer_submissions':0,'all50_commercial':False})

catalog44=cohort['signed_catalogue44']
head=catalog44['head']
assert re.fullmatch('[a-f0-9]{40}',head)
base='https://raw.githubusercontent.com/yunzhanlin/yunzhan-apps/'+head+'/'
catalogue_asset='candidate/dist/catalog-v1.json'
signature_asset='candidate/signatures/catalog-v1.sig'
manifest_asset='candidate/dist/apps/rabbitmq/4.4.0-compat1/manifest.json'
key_asset='candidate/signatures/catalog-v1.pub.pem'
pins={name:catalog44['files'][name] for name in (catalogue_asset,signature_asset,manifest_asset)}
pins[key_asset]='659ea4edcecaf23a586e2ff371616fde5f6ee7c219fb70fa978816e2b10acf75'
signed_files={}
for name, digest in pins.items():
 with urllib.request.urlopen(base+name,timeout=25) as reply:
  assert reply.geturl()==base+name
  raw=reply.read((1<<20)+1)
 assert len(raw)<=1<<20 and hashlib.sha256(raw).hexdigest()==digest
 file=out/pathlib.PurePosixPath(name).name
 file.open('xb').write(raw); signed_files[name]=file
signature=out/'catalogue-ed25519.bin'
signature.open('xb').write(base64.b64decode(signed_files[signature_asset].read_bytes().strip(),validate=True))
subprocess.run(['/usr/bin/openssl','pkeyutl','-verify','-rawin','-pubin','-inkey',str(signed_files[key_asset]),
                '-in',str(signed_files[catalogue_asset]),'-sigfile',str(signature)],check=True,timeout=15)
catalogue=json.loads(signed_files[catalogue_asset].read_bytes())
item,=[item for item in catalogue['apps'] if item['id']=='rabbitmq']
assert len(catalogue['apps'])==50 and item==catalog44['item'] and item['sha256']==pins[manifest_asset]
manifest=json.loads(signed_files[manifest_asset].read_bytes())
assert manifest['id']==item['id'] and manifest['version']==item['version']
assert manifest['delivery']=={'provider':'compose','target':'rabbitmq-440','image':cohort['image44'],'manage_route':'docker'}
save('candidate-44-catalogue-verified-independently.json',{'ok':True,'architecture':arch,'head':head,'item':item,'scope':'signed isolated candidate bytes'})
