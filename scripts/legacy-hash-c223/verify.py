from pathlib import Path
import json,hashlib,os,subprocess
assert os.environ.get('GITHUB_ACTIONS')=='true'and os.environ.get('GITHUB_REPOSITORY')=='yunzhanlin/yunzhan-apps'
p=Path(__file__).resolve().parent;root=Path.cwd();c=json.loads((p/'cohort.json').read_bytes())
assert subprocess.check_output(['git','rev-parse','HEAD^'],text=True).strip()==c['parent']
assert set(subprocess.check_output(['git','diff','--name-only','HEAD^','HEAD'],text=True).splitlines())==set(c['files'])|{'scripts/legacy-hash-c223/cohort.json'}
for name,digest in c['files'].items():assert hashlib.sha256((root/name).read_bytes()).hexdigest()==digest,name
assert subprocess.check_output(['git','rev-parse','HEAD:candidate/panel-integration-compose-signed-image'],text=True).strip()==c['unchanged_sdk_tree']
print('Exact pinned source, patch inputs and unchanged panel SDK verified')
