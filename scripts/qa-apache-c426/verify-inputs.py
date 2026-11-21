from pathlib import Path
import hashlib,json,stat
root=Path('candidate/panel-integration-compose-signed-image');index=json.loads((root/'SOURCE_INPUTS.json').read_bytes())
expected='5e51a17605fc0c32214e520533e246d9c22b8e7649ba12595768be867ad3f4ae'
assert index['format']==1 and index['inputs_sha256']==expected
assert hashlib.sha256(json.dumps(index['files'],sort_keys=True,separators=(',',':')).encode()).hexdigest()==expected
sdk={n:v for n,v in index['files'].items()if not n.startswith('web/node_modules/')}
for name,info in sdk.items():
 p=root/name;s=p.lstat();assert stat.S_ISREG(s.st_mode)and not p.is_symlink()and s.st_size==info['bytes'],name
 assert hashlib.sha256(p.read_bytes()).hexdigest()==info['sha256'],name
 assert bool(s.st_mode&0o111)==bool(info['mode']&0o111),name
print(json.dumps({'ok':True,'frozen_programme_inputs_sha256':expected,'SDK_bytes_and_executable_modes_verified':len(sdk),'NPM_dependency_bytes_not_reconstructed_by_this_Go_unit_job':True,'scope':'native Linux source download policy regression only; signed normal Apache source install and business qualification are separate','Main_changes':0,'all40_commercial':False}))
