#!/usr/bin/env python3
"""Exercise fixed sync programs on all 12 cached legacy PHP engines, never user data."""
import base64, hashlib, json, os, pathlib, re, uuid
from panel_client import PanelClient
assert os.environ.get('PANEL_VM')=='panel-store-apps-debian13','Isolated AMD64 QA required'
root=pathlib.Path(__file__).resolve().parents[1]
code=(root/'internal/executor/app_legacy_sync_linux.go').read_text()
writer=re.search(r'const legacyWritePHP = `([\s\S]*?)`',code).group(1)
inventory=re.search(r'const legacyInventoryPHP = `([\s\S]*?)`',code).group(1)
images=re.findall(r'"(php-legacy-\d+)":\s*"([^"]+)"',(root/'internal/core/app_compose_templates.go').read_text())
assert len(images)==12
p=PanelClient();checks=[]
def digest(data):return hashlib.sha256(data.encode()).hexdigest()
try:
 for template,image in images:
  name='qa-reliability-'+uuid.uuid4().hex[:12];created=False
  try:
   p.vm('sudo','docker','run','-d','--pull=never','--name',name,'--network=none','--memory=128m','--cpus=.5','--cap-drop=ALL','--security-opt=no-new-privileges','--read-only','--tmpfs','/var/www/html:rw,uid=1000,gid=1000,mode=0755','--user','1000:1000','--entrypoint','php',image,'-r','sleep(240);');created=True
   def php(program,input=None,check=True):return p.vm('sudo','docker','exec','-i','--user','1000:1000',name,'php','-r',program,input=input,check=check)
   def put(data,expected='',expected_mode=0,expected_size=0,mode=0o600):
    return php(writer,json.dumps(dict(path='proof.txt',data=base64.b64encode(data.encode()).decode(),expected=expected,expected_mode=expected_mode,expected_size=expected_size,mode=mode,sha256=digest(data))),check=False)
   assert put('first').returncode==0
   actual=json.loads(php(inventory).stdout)['proof.txt'];assert actual['mode']==0o600 and actual['sha256']==digest('first')
   assert put('second',digest('first'),0o600,5,0o644).returncode==0
   assert put('should-not-write',digest('first'),0o644,6,0o644).returncode!=0
   actual=json.loads(php(inventory).stdout)['proof.txt'];assert actual['sha256']==digest('second') and actual['mode']==0o644
   php("chmod('/var/www/html/proof.txt',0640);")
   assert put('should-not-write',digest('second'),0o644,6,0o644).returncode!=0
   actual=json.loads(php(inventory).stdout)['proof.txt'];assert actual['sha256']==digest('second') and actual['mode']==0o640
   checks.append(template+' real new/existing writes, permissions, changed SHA/mode rejection');print('PASS',checks[-1],flush=True)
  finally:
   if created:p.vm('sudo','docker','rm','-f',name)
 (root/'.local/app-legacy-write-functions4.json').write_text(json.dumps({'passed':True,'checks':checks,'temporary_containers_removed':True},indent=2)+'\n')
finally:p.close()
