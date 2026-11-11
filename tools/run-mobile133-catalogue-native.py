"""Actual native signed-catalogue ABI; no installed acceptance claim."""
import hashlib,io,json,os,pathlib,stat,subprocess,sys,tarfile
assert os.environ.get('GITHUB_ACTIONS')=='true'and os.environ.get('GITHUB_REPOSITORY')=='yunzhanlin/yunzhan-apps'and sys.platform=='linux'
os.umask(0o077);repo=pathlib.Path(__file__).resolve().parents[1];out=pathlib.Path(sys.argv[1]);out.mkdir(mode=0o700);original='5f8457971e3ca4868d85c70d3f854d5773f25c8f';tree='c07c9c047359fa6696fa3eb73eef721ec0429ab0';scope='candidate/panel-integration-load-balance';read=lambda f:json.loads(pathlib.Path(f).read_bytes());sha=lambda f:hashlib.sha256(pathlib.Path(f).read_bytes()).hexdigest()
def save(name,value):
 with(out/name).open('x')as f:json.dump(value,f,indent=2);f.write('\n')
def snapshot(root):
 index=read(root/'source-sha256.json');files=index['files'];assert 2400<len(files)<2600
 for n,d in files.items():
  f=root/n;s=f.lstat();assert stat.S_ISREG(s.st_mode)and not f.is_symlink()and s.st_nlink==1 and f.resolve()==f and sha(f)==d,n
 return{'source_index_sha256':sha(root/'source-sha256.json'),'files':files}
def git(*args):
 return subprocess.check_output(['git',*args],cwd=repo,timeout=90)

def extract(raw,directory):
 assert len(raw)<64<<20
 directory.mkdir(mode=0o700)
 with tarfile.open(fileobj=io.BytesIO(raw))as archive:
  for m in archive:
   n=pathlib.PurePosixPath(m.name)
   assert not n.is_absolute()and all(v not in('.','..')for v in n.parts)and(m.isdir()or m.isfile())
   f=directory/str(n)
   if m.isdir():f.mkdir(mode=0o700,parents=True,exist_ok=True)
   else:
    assert m.size<8<<20;f.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    with f.open('xb')as stream:stream.write(archive.extractfile(m).read())

assert git('rev-parse',original+':'+scope).decode().strip()==tree
raw=git('archive','--format=tar',original+':'+scope)
old=out/'original-C67-source'
extract(raw,old)
current=repo/scope
latest=repo/'candidate/panel-integration-compose-signed-image'
assert git('rev-parse','HEAD:'+scope).decode().strip()=='0754086b782f551323285bd885f1901c93b5391d'
sources={'C67':old,'C68r3':current,'latest':latest}
before={key:snapshot(source)for key,source in sources.items()}
historical='fdb6be9f2ee650ca0ed37b213256151f397a7599'
if subprocess.run(['git','cat-file','-e',historical+'^{commit}'],cwd=repo,capture_output=True,timeout=30).returncode:
 assert git('remote','get-url','origin').decode().strip().removesuffix('.git')=='https://github.com/yunzhanlin/yunzhan-apps'
 git('fetch','--no-tags','--depth=1','origin',historical)
catalogue=out/'original-C68r3-catalogue'
extract(git('archive','--format=tar',historical+':candidate','dist','signatures'),catalogue)
assert sha(catalogue/'dist/catalog-v1.json')=='83a95dd32a768165c563f76dc13267b1961f592b237b7b3bd937c46b3982666f'
retained=repo/'registry/reviewed-catalogs/before-mobile-native133-c68r3'
current_catalogue=repo/'candidate'
assert next(a for a in read(retained/'dist/catalog-v1.json')['apps']if a['id']=='mobile')['version']=='1.3.2'
assert next(a for a in read(catalogue/'dist/catalog-v1.json')['apps']if a['id']=='mobile')['version']=='1.3.3'
save('original-intent.json',{'original_C67_head':original,'original_C67_sdk_tree':tree,
 'original_C67_git_archive_sha256':hashlib.sha256(raw).hexdigest(),
 'current_source_inputs_sha256':read(current/'source-sha256.json')['release']['frozen_inputs_sha256'],
 'latest_source_inputs_sha256':read(latest/'source-sha256.json')['release']['frozen_inputs_sha256'],
 'original_C68r3_catalogue_commit':historical,'one_execution_each':['retained132','C67-refuses133','current133','latest-signed'],
 'catalogue_sha256':{'retained132':sha(retained/'dist/catalog-v1.json'),'current133':sha(catalogue/'dist/catalog-v1.json'),
                     'latest-signed':sha(current_catalogue/'dist/catalog-v1.json')},
 'source_before':{k:{'source_index_sha256':v['source_index_sha256'],'files':len(v['files'])}for k,v in before.items()},
 'source_overlays':0,'installed_acceptance':False})
proofs={}
for label,source,registry,expected in[('retained132',old,retained,0),('C67-refuses133',old,catalogue,1),('current133',current,catalogue,0),
                                      ('latest-signed',latest,current_catalogue,0)]:
 args=['go','test','-json','-count=1','-p','1',"-ldflags=-X=local/panel/internal/appcatalog.officialCatalogChannel=candidate",'./internal/appcatalog','-run','^TestPublishedCandidateRepositoryCurrentSignedManifestABI$','-published-candidate-app-registry-root='+str(registry)]
 save(label+'-intent.json',{'args':args,'maximum_submissions':1,'expected_original_exit':expected})
 with(out/(label+'.jsonl')).open('xb')as stdout,(out/(label+'.stderr')).open('xb')as stderr:r=subprocess.run(args,cwd=source,env={**os.environ,'CGO_ENABLED':'0'},stdout=stdout,stderr=stderr,timeout=600)
 save(label+'-outcome.json',{'exit':r.returncode,'stdout_sha256':sha(out/(label+'.jsonl')),'stderr_sha256':sha(out/(label+'.stderr'))});assert r.returncode==expected,label
 result=subprocess.check_output(['node',str(repo/'tools/check-mobile133-catalogue-native.mjs'),str(out/(label+'.jsonl')),str(registry/'dist/catalog-v1.json'),label],cwd=repo,text=True,timeout=30);proofs[label]=json.loads(result);assert proofs[label]['ok']
after={key:snapshot(source)for key,source in sources.items()};assert before==after
latest_proof=proofs.pop('latest-signed')
save('qualified.json',{'ok':True,'native_architecture':os.uname().machine,'cohorts':proofs,'latest_signed_catalogue':latest_proof,'zero_source_overlays':True,'original_complete_source_bytes_unchanged':True,'actual_native_original_C67_compiler_control':True,'actual_signed50_current_and_retained':True,'not_installed_acceptance':True,'all50_commercial':False});print(json.dumps({'ok':True,'native_architecture':os.uname().machine,'actual_current50':50,'actual_latest50':50,'actual_retained50':50,'actual_old_refused_only133':True}))
