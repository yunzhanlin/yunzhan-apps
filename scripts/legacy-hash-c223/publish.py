from pathlib import Path
import json,hashlib,subprocess,sys,os,platform,re,urllib.request,urllib.error,urllib.parse
p=Path(sys.argv[1]);version,slot=sys.argv[2:];assert(version,slot)in [('5.2.17','52'),('5.3.29','53')]
assert os.environ.get('GITHUB_ACTIONS')=='true'and os.environ.get('GITHUB_REPOSITORY')=='yunzhanlin/yunzhan-apps'
arch={'x86_64':'amd64','aarch64':'arm64'}[platform.machine()];head=os.environ['GITHUB_SHA'];assert re.fullmatch('[a-f0-9]{40}',head)
proof=json.loads((p/'original-hash-proof.json').read_bytes());assert proof['ok']and proof['architecture']==arch and proof['version']==version
smoke=json.loads((p/'original-proof.json').read_bytes());assert smoke['ok']and smoke['architecture']==arch and smoke['version']==version
sql=json.loads((p/'original-db.json').read_bytes());assert sql=={'php':version,'pdo_write_mysqli_read':True,'mysqli_update_pdo_read':True}
image='ghcr.io/yunzhanlin/yunzhan-apps-php'+slot;tag=version+'-compat3-c223-'+head[:12]+'-'+arch;repository=image.removeprefix('ghcr.io/')
url='https://ghcr.io/token?'+urllib.parse.urlencode({'service':'ghcr.io','scope':'repository:'+repository+':pull'})
with urllib.request.urlopen(url,timeout=30)as r:token=json.load(r)['token']
request=urllib.request.Request('https://ghcr.io/v2/'+repository+'/manifests/'+tag,headers={'Authorization':'Bearer '+token,'Accept':'application/vnd.oci.image.manifest.v1+json,application/vnd.docker.distribution.manifest.v2+json'})
try:
 with urllib.request.urlopen(request,timeout=30)as r:existing=r.read(1<<20)
 raise AssertionError('New immutable staging tag already exists; no overwrite submitted')
except urllib.error.HTTPError as e:
 assert e.code==404;body=json.loads(e.read(65536));assert body['errors']and all(x['code']in ['MANIFEST_UNKNOWN','NAME_UNKNOWN']for x in body['errors'])
del token
expected=(p/'image-id').read_text().strip();assert re.fullmatch('sha256:[a-f0-9]{64}',expected)
subprocess.run(['docker','tag','panel-legacy-php-native:qa',image+':'+tag],check=True)
assert subprocess.check_output(['docker','image','inspect','-f','{{.Id}}',image+':'+tag],text=True).strip()==expected
with(p/'original-registry-push.stdout').open('xb')as out:subprocess.run(['docker','push',image+':'+tag],stdout=out,check=True,timeout=240)
raw=subprocess.check_output(['docker','buildx','imagetools','inspect','--raw',image+':'+tag],timeout=60);manifest=json.loads(raw);assert manifest['config']['digest']==expected
(p/'original-remote-manifest.json').write_bytes(raw);digest='sha256:'+hashlib.sha256(raw).hexdigest();published={'ok':True,'architecture':arch,'version':version,'app_version':version+'-compat3','tag':tag,'image':image,'digest':digest,'image_id':expected,'source_head':head,'all_original_native_checks_passed':True,'old_tags_changed':False,'Main_changed':False}
(p/'original-published-image.json').write_text(json.dumps(published,indent=2)+'\n');print(json.dumps(published))
