from pathlib import Path
import hashlib,json,stat
root=Path('candidate/panel-integration-compose-signed-image');index=json.loads((root/'SOURCE_INPUTS.json').read_bytes())
expected='08f92b1d4a0c1029bff666de6cc32b4bba43a831d4e0cbd29392d7f88c9d4593'
assert index['format']==1 and index['inputs_sha256']==expected
assert hashlib.sha256(json.dumps(index['files'],sort_keys=True,separators=(',',':')).encode()).hexdigest()==expected
sdk={n:v for n,v in index['files'].items()if not n.startswith('web/node_modules/')}
for name,info in sdk.items():
 p=root/name;s=p.lstat();assert stat.S_ISREG(s.st_mode)and not p.is_symlink()and s.st_size==info['bytes'],name
 assert hashlib.sha256(p.read_bytes()).hexdigest()==info['sha256'],name
 assert bool(s.st_mode&0o111)==bool(info['mode']&0o111),name
print(json.dumps({'ok':True,'frozen_programme_inputs_sha256':expected,'SDK_bytes_and_executable_modes_verified':len(sdk),'NPM_dependency_bytes_not_reconstructed_by_this_Go_unit_job':True,'scope':'native Linux unit and filesystem journal fixtures only; no installed Apache qualification','Main_changes':0,'all40_commercial':False}))
