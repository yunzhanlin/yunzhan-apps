from pathlib import Path
import json,os,subprocess,time
assert os.environ.get('GITHUB_ACTIONS')=='true';base=Path(__file__).resolve().parent;p=json.loads((base/'pins.json').read_bytes());deadline=time.monotonic()+1800
while True:
 value=json.loads(subprocess.check_output(['gh','api','-H','Cache-Control: no-cache','repos/yunzhanlin/yunzhan-apps/git/ref/heads/codex/app-candidate'],timeout=90));head=value['object']['sha'];assert head in[p['old_catalogue_head'],p['catalogue_head']],'Unexpected catalogue head; no deployment'
 if head==p['catalogue_head']:break
 assert time.monotonic()<deadline,'Signed catalogue was not published; no store update submitted';time.sleep(5)
print(json.dumps({'ok':True,'catalogue':head,'only_readonly_ref_GETs':True}))
