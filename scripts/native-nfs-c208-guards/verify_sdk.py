from pathlib import Path
import hashlib,json,sys,platform
assert platform.machine()=='x86_64'
sdk=Path(sys.argv[1]);src=json.loads((sdk/'source-sha256.json').read_bytes());dispatch=json.loads(Path(sys.argv[2]).read_bytes())
assert src['release']['frozen_inputs_sha256']==dispatch['source_inputs_sha256'] and len(src['files'])==2637
for name,digest in src['files'].items():
 p=sdk/name;assert p.is_file()and not p.is_symlink() and hashlib.sha256(p.read_bytes()).hexdigest()==digest,name
print(json.dumps({'ok':True,'original_SDK_files':len(src['files']),'source_inputs_sha256':dispatch['source_inputs_sha256']}))
