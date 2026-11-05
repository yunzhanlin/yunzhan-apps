"""Add only the current regression test to an immutable predecessor checkout."""
import hashlib,json,os,pathlib,stat,sys

assert len(sys.argv)==4 and sys.argv[3]in('stage','verify')
workspace=pathlib.Path(sys.argv[1]).resolve(strict=True)
original=pathlib.Path(sys.argv[2]).resolve(strict=True)
assert original==workspace/'original-publication-defect/candidate/panel-integration-load-balance'
read=lambda p:json.loads(p.read_bytes())
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
contract=read(workspace/'tools/kernel-publication-original-defect.json')
assert sha(original/'source-sha256.json')==contract['original_source_index_sha256']
assert sha(original/'release-source-inputs.json')==contract['original_release_source_index_sha256']
index=read(original/'source-sha256.json')
assert index['release']['frozen_inputs_sha256']==contract['original_source_inputs_sha256']
assert len(index['files'])==contract['original_source_sdk_files']==2413
for name,digest in index['files'].items():
 relative=pathlib.PurePosixPath(name)
 assert not relative.is_absolute()and'..'not in relative.parts
 f=original/name;s=f.lstat()
 assert stat.S_ISREG(s.st_mode)and not f.is_symlink()and s.st_nlink==1 and sha(f)==digest,name
for name,digest in contract['original_production_files'].items():
 assert index['files'][name]==digest and sha(original/name)==digest
name=contract['test_overlay_path'];assert name=='internal/executor/integrity_kernel_publication_linux_test.go'and name not in index['files']
current=workspace/'candidate/panel-integration-load-balance'/name
newindex=read(workspace/'candidate/panel-integration-load-balance/source-sha256.json')
assert sha(workspace/'candidate/panel-integration-load-balance/source-sha256.json')==contract['published_source_index_sha256']
assert newindex['release']['frozen_inputs_sha256']==contract['published_source_inputs_sha256']and len(newindex['files'])==contract['published_source_sdk_files']==2414
assert sha(current)==newindex['files'][name]==contract['test_overlay_sha256']
target=original/name
if sys.argv[3]=='stage':
 assert not os.path.lexists(target)
 with os.fdopen(os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o644),'wb')as f:
  f.write(current.read_bytes());f.flush();os.fsync(f.fileno())
else:assert target.is_file()and not target.is_symlink()
assert sha(target)==contract['test_overlay_sha256']
actual={str(f.relative_to(original))for f in original.rglob('*')if f.is_file()or f.is_symlink()}
assert actual==set(index['files'])|{'source-sha256.json','release-source-inputs.json',name}
print(json.dumps({'ok':True,'phase':sys.argv[3],'original_production_source_files_unchanged':2413,'explicit_regression_test_only_overlay_files':1,'normal_candidate_source_overlays':0,'installed_acceptance':False}))
