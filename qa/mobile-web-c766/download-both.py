from pathlib import Path
import hashlib,json,os,subprocess,sys,urllib.request
os.umask(0o077);assert os.environ.get('GITHUB_ACTIONS')=='true'and os.environ.get('GITHUB_REPOSITORY')=='yunzhanlin/yunzhan-apps';base=Path(__file__).resolve().parent;pins=json.loads((base/'pins.json').read_bytes());out=Path(sys.argv[1]);out.mkdir(mode=0o700)
for cohort in ['old','new']:
 p=pins[cohort];dest=out/cohort;dest.mkdir(mode=0o700);release=json.loads(subprocess.check_output(['gh','api','repos/yunzhanlin/yunzhan-apps/releases/'+str(p['programme_release_id'])],timeout=90));assert release['id']==p['programme_release_id']and release['tag_name']==p['programme_tag']and release['target_commitish']==p['programme_source_head']and not release['draft'];actual={a['name']:a for a in release['assets']}
 for name,pin in p['programme_assets'].items():
  a=actual[name];assert a['id']==pin['id']and a['size']==pin['bytes']and a['digest']=='sha256:'+pin['sha256'];h=hashlib.sha256();size=0
  with urllib.request.urlopen(a['browser_download_url'],timeout=120)as response,(dest/name).open('xb')as f:
   assert response.status==200 and response.url.startswith('https://')
   for b in iter(lambda:response.read(1<<20),b''):size+=len(b);assert size<=pin['bytes'];h.update(b);f.write(b)
  assert size==pin['bytes']and h.hexdigest()==pin['sha256']
 (dest/'original-downloads.json').open('x').write(json.dumps({'ok':True,'release_id':release['id'],'original_asset_ids_lengths_digests_exact':True}))
print(json.dumps({'ok':True,'cohorts':['old','new'],'native_App_runs':0}))
