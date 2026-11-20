from pathlib import Path
import json,hashlib,subprocess,sys,os,platform,re,urllib.request,urllib.error,urllib.parse,zipfile,stat
assert os.environ.get('GITHUB_ACTIONS')=='true'and os.environ.get('GITHUB_REPOSITORY')=='yunzhanlin/yunzhan-apps'
root=Path.cwd();source=Path(__file__).resolve().parent;plan=json.loads((source/'index-plan.json').read_bytes());sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
assert subprocess.check_output(['git','rev-parse','HEAD^'],text=True).strip()==plan['parent']
assert set(subprocess.check_output(['git','diff','--name-only','HEAD^','HEAD'],text=True).splitlines())==set(plan['files'])|{'scripts/legacy-hash-c223/index-plan.json'}
for n,h in plan['files'].items():assert sha(root/n)==h
assert subprocess.check_output(['git','rev-parse','HEAD:candidate/panel-integration-compose-signed-image'],text=True).strip()==plan['unchanged_sdk_tree']
out=Path(sys.argv[1]);out.mkdir(mode=0o700);slot=sys.argv[2];assert slot in ['52','53'];version={'52':'5.2.17','53':'5.3.29'}[slot];v=plan['versions'][version];image='ghcr.io/yunzhanlin/yunzhan-apps-php'+slot;assert v['image']==image and set(v['architectures'])=={'amd64','arm64'}
def gh(path):return json.loads(subprocess.check_output(['gh','api','repos/yunzhanlin/yunzhan-apps/'+path],timeout=90))
original_run=gh('actions/runs/'+str(plan['native_run']));assert original_run['conclusion']=='success'and original_run['head_sha']==plan['parent']
for arch,pin in v['architectures'].items():
 a=gh('actions/artifacts/'+str(pin['artifact']['id']));assert not a['expired']
 for key,value in pin['artifact'].items():assert a[key]==value
 p=out/arch;p.mkdir(mode=0o700);z=p/'original.zip'
 with z.open('xb')as f:subprocess.run(['gh','api','repos/yunzhanlin/yunzhan-apps/actions/artifacts/'+str(a['id'])+'/zip'],stdout=f,check=True,timeout=180)
 assert a['digest']=='sha256:'+sha(z)and z.stat().st_size==a['size_in_bytes']
 with zipfile.ZipFile(z)as zz:
  assert len(zz.infolist())<=100 and sum(x.file_size for x in zz.infolist())<=64<<20
  names=['original-hash-proof.json','original-published-image.json','original-proof.json','original-db.json','original-remote-manifest.json'];records={}
  for n in names:
   item=zz.getinfo(n);assert not stat.S_ISLNK(item.external_attr>>16);raw=zz.read(item);(p/n).write_bytes(raw);records[n]=raw
 hp=json.loads(records['original-hash-proof.json']);pub=json.loads(records['original-published-image.json']);smoke=json.loads(records['original-proof.json']);db=json.loads(records['original-db.json']);assert pub==pin['published']and hp['ok']and smoke['ok']and hp['architecture']==arch and hp['version']==version and pub['source_head']==plan['parent']
 assert db=={'php':version,'pdo_write_mysqli_read':True,'mysqli_update_pdo_read':True}
 assert hashlib.sha256(records['original-remote-manifest.json']).hexdigest()==pub['digest'].removeprefix('sha256:')and json.loads(records['original-remote-manifest.json'])['config']['digest']==pub['image_id']
repository=image.removeprefix('ghcr.io/');tokenURL='https://ghcr.io/token?'+urllib.parse.urlencode({'service':'ghcr.io','scope':'repository:'+repository+':pull'})
with urllib.request.urlopen(tokenURL,timeout=30)as r:token=json.load(r)['token']
accept='application/vnd.oci.image.index.v1+json,application/vnd.docker.distribution.manifest.list.v2+json';url='https://ghcr.io/v2/'+repository+'/manifests/'+v['tag'];headers={'Authorization':'Bearer '+token,'Accept':accept}
try:
 with urllib.request.urlopen(urllib.request.Request(url,headers=headers),timeout=30)as r:old=r.read(1<<20)
 raise AssertionError('New index tag already exists; no overwrite submitted')
except urllib.error.HTTPError as e:
 assert e.code==404;error=json.loads(e.read(65536));assert error['errors']and all(x['code']in ['MANIFEST_UNKNOWN','NAME_UNKNOWN']for x in error['errors'])
args=['docker','buildx','imagetools','create','--tag',image+':'+v['tag']]+[image+'@'+v['architectures'][a]['published']['digest']for a in ['amd64','arm64']]
with(out/'original-index-push.stdout').open('xb')as f:subprocess.run(args,stdout=f,check=True,timeout=180)
with urllib.request.urlopen(urllib.request.Request(url,headers=headers),timeout=30)as r:
 raw=r.read((2<<20)+1);header=r.headers['Docker-Content-Digest'];assert header=='sha256:'+hashlib.sha256(raw).hexdigest()
entries=json.loads(raw)['manifests'];assert len(entries)==2 and all(x['platform']['os']=='linux'for x in entries);peers={x['platform']['architecture']:x['digest']for x in entries};assert peers=={a:v['architectures'][a]['published']['digest']for a in ['amd64','arm64']}
(out/'original-index.json').write_bytes(raw);result={'ok':True,'version':version,'app_version':v['app_version'],'image':image,'tag':v['tag'],'index_digest':header,'exact_reference':image+':'+v['tag']+'@'+header,'architectures':peers,'native_run':plan['native_run'],'native_source_head':plan['parent'],'index_source_head':os.environ['GITHUB_SHA'],'original_native_artifacts':[p['artifact']['id']for p in v['architectures'].values()],'old_tags_changed':False,'Main_changed':False,'new_signed_app_manifest_published':False}
(out/'original-index-proof.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
