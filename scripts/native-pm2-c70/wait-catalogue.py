"""Read-only wait for the exact approved official signed catalogue publication."""
import hashlib,json,os,pathlib,sys,time,urllib.request
os.umask(0o077)
assert len(sys.argv)==2 and os.environ.get('GITHUB_ACTIONS')=='true'and os.environ.get('GITHUB_REPOSITORY')=='yunzhanlin/yunzhan-apps'
source=pathlib.Path(__file__).resolve().parent;cohort=json.loads((source/'cohort.json').read_bytes())
private=pathlib.Path(sys.argv[1]);deadline=time.monotonic()+1200
url='https://raw.githubusercontent.com/yunzhanlin/yunzhan-apps/refs/heads/codex/app-candidate/candidate/signatures/catalog-v1.bundle.json'
observations=[]
while True:
 try:
  with urllib.request.urlopen(url,timeout=20)as response:assert response.status==200 and response.geturl()==url;raw=response.read((2<<20)+1)
  assert 0<len(raw)<=2<<20
  digest=hashlib.sha256(raw).hexdigest();assert digest in(cohort['old_catalogue_bundle_sha256'],cohort['new_catalogue_bundle_sha256']),'Unknown publication cannot be substituted'
  observations.append({'at':time.time(),'bundle_sha256':digest})
  if digest==cohort['new_catalogue_bundle_sha256']:
   value=json.loads(raw);assert hashlib.sha256(value['catalog'].encode()).hexdigest()==cohort['new_catalogue_sha256']
   with(private/'original-approved-served-catalogue-observation.json').open('x')as f:json.dump({'ok':True,'observations':observations,'normal_TLS_unchanged':True,'GET_only':True,'product_or_install_request_submissions':0},f,indent=2);f.write('\n')
   print(json.dumps({'ok':True,'original_exact_official_catalogue_observed':True,'normal_TLS_unchanged':True}));break
 except (urllib.error.URLError,TimeoutError)as exc:
  observations.append({'at':time.time(),'ordinary_GET_transport_error_type':type(exc).__name__})
 assert time.monotonic()<deadline,'Original publication wait expired; no app update or fallback was dispatched'
 time.sleep(5)
