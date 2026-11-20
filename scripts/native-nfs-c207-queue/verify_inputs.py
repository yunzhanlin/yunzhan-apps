from pathlib import Path
import json,hashlib,stat,sys
sdk=Path(sys.argv[1]);fixture=Path(sys.argv[2]);phase=sys.argv[3];assert phase in ('original','reviewed')
p=json.loads((fixture/'dispatch.json').read_bytes());meta=json.loads((sdk/'source-sha256.json').read_bytes())
assert hashlib.sha256((sdk/'source-sha256.json').read_bytes()).hexdigest()==p['original_sdk_manifest_sha256'] and meta['release']['frozen_inputs_sha256']==p['programme_source_inputs_sha256']
assert len(meta['files'])==2634
for name,want in meta['files'].items():
 assert not Path(name).is_absolute() and '..'not in Path(name).parts
 file=sdk/name;s=file.lstat();assert stat.S_ISREG(s.st_mode) and s.st_nlink==1
 if phase=='reviewed' and name==p['only_reviewed_test_path']:want=p['reviewed_test_sha256']
 assert hashlib.sha256(file.read_bytes()).hexdigest()==want,name
assert {str(file.relative_to(sdk))for file in sdk.rglob('*.go')}=={name for name in meta['files']if name.endswith('.go')}
print(json.dumps({'ok':True,'phase':phase,'programme_source_inputs_sha256':p['programme_source_inputs_sha256'],'all2633_other_source_files_unchanged':True,'production_code_changed':False}))
