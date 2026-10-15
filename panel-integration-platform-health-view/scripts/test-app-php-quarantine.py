#!/usr/bin/env python3
"""Real PHP website/HTTP and controlled quarantine on two isolated QA servers."""
import hashlib,json,os,pathlib,sys,uuid
from panel_client import PanelClient

assert os.environ.get('PANEL_VM') in ('panel-compat-ubuntu24','panel-store-apps-debian13'), 'explicit isolated VM required'
ROOT=pathlib.Path(__file__).resolve().parents[1]
arch='arm64' if os.environ['PANEL_VM'].endswith('ubuntu24') else 'amd64'
phase=os.environ.get('PANEL_PHP_QA_PHASE','prototype')
assert phase in ('prototype','signed')
state_path=ROOT/'.local'/('php-quarantine-fixture-'+arch+'.json')
report_path=ROOT/'.local'/('php-quarantine-live-'+arch+'-'+phase+'.json')
p=PanelClient();report={'passed':False,'checks':[],'phase':phase}
def save():report_path.parent.mkdir(exist_ok=True);report_path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n');report_path.chmod(0o600)
def passed(name):report['checks'].append(name);save();print('PASS '+name,flush=True)
def module(action,**body):return p.api('/app-modules/php-code-security/'+action,body)
def reject(action,word,**body):
 try:module(action,**body)
 except RuntimeError as error:assert word in str(error),str(error);return
 raise AssertionError('unsafe action accepted: '+action)
def snapshot():
 code="""import hashlib,json,pathlib,subprocess
out={}
for name in ('panel-nfs-server.service','panel-pure-ftpd.service','nfs-server.service'):
 r=subprocess.run(['systemctl','show','--property=MainPID,ActiveState,ExecMainStartTimestampMonotonic',name],text=True,capture_output=True)
 out[name]=r.stdout
for f in (pathlib.Path('/etc/panel/security-apps/modules/nfs-manager/server.json'),pathlib.Path('/etc/exports')):
 if f.is_file():out[str(f)]=hashlib.sha256(f.read_bytes()).hexdigest()
print(json.dumps(out))"""
 return json.loads(p.vm('sudo','python3','-c',code).stdout)
def http(site):
 result=p.vm('curl','-sS','--max-time','10','-H','Host: '+site['domain'],'-w','\n%{http_code}','http://127.0.0.1:19101/risk.php')
 body,code=result.stdout.rsplit('\n',1);return int(code),body
def current_record(id):return next(row for row in module('quarantine-list',site_id=site['id'],limit=200)['quarantine'] if row['id']==id)
def restore_input(row,recover=False):return {'site_id':row['site_id'],'resource_id':row['id'],'path':row['path'],'expected_sha':row['sha256'],'expected_revision':row['revision'],'confirm':('RECOVER PHP ' if recover else 'RESTORE PHP ')+row['id']}
try:
 assert p.api('/app-modules/php-code-security')['status']['installed']
 inventory={r['id']:r for r in p.api('/runtimes')['installed']}
 assert inventory['php-8.4.25']['status']=='installed'
 if state_path.exists():
  fixture=json.loads(state_path.read_text());site=next(s for s in p.api('/sites') if s['id']==fixture['site']['id'])
  assert site['domain'].startswith('php-security-') and site['php_version_id']=='php-8.4.25'
 else:
  slug='php-security-'+uuid.uuid4().hex[:8]
  p.wait(p.api('/sites',{'name':slug,'slug':slug,'domain':slug+'.example.test','php_version_id':'php-8.4.25'})['job_id'],timeout=180)
  site=next(s for s in p.api('/sites') if s['slug']==slug)
  content="<?php /* eval('review only'); legitimate static false-positive sample */ header('Content-Type: text/plain'); echo 'php-quarantine-safe-"+uuid.uuid4().hex+"'; ?>"
  p.api('/sites/'+site['id']+'/files/action',{'action':'create','path':'risk.php','content':content})
  fixture={'site':site,'sha256':hashlib.sha256(content.encode()).hexdigest(),'body':content.split("echo '",1)[1].split("';",1)[0]}
  state_path.write_text(json.dumps(fixture,indent=2)+'\n');state_path.chmod(0o600)
 report['site_id']=site['id'];report['before']=snapshot();save()
 assert http(site)==(200,fixture['body'])
 scan=module('run',site_id=site['id'],search='risk.php',severity='high');finding=next(row for row in scan['findings'] if row['path']=='risk.php')
 assert finding['site_id']==site['id'] and finding['sha256']==fixture['sha256'] and finding['severity']=='high'
 passed('actual PHP-FPM HTTP 200 and static evidence correctly identifies a legitimate comment sample')
 reject('quarantine','摘要已变化',site_id=site['id'],path='risk.php',expected_sha='0'*64,confirm='QUARANTINE risk.php')
 reject('quarantine','QUARANTINE',site_id=site['id'],path='risk.php',expected_sha=fixture['sha256'],confirm='yes')
 assert http(site)==(200,fixture['body']);passed('stale digest and inexact confirmation rejected without changing website')
 q=module('quarantine',site_id=site['id'],path='risk.php',expected_sha=fixture['sha256'],confirm='QUARANTINE risk.php')['record'];report['record_id']=q['id'];save()
 assert q['state']=='quarantined' and http(site)[0]==404
 row=current_record(q['id']);assert row['backup_verified'] and not row['source_present']
 passed('actual atomic isolation removes direct PHP HTTP entry and verifies independent private backup')
 stale=restore_input(row);stale['expected_revision']-=1;reject('restore-quarantine','修订号',**stale)
 p.api('/sites/'+site['id']+'/files/action',{'action':'create','path':'risk.php','content':"<?php echo 'replacement-preserved'; ?>"})
 reject('restore-quarantine','原位置已存在',**restore_input(row));assert http(site)==(200,'replacement-preserved')
 p.api('/sites/'+site['id']+'/files/action',{'action':'rename','path':'risk.php','destination':'replacement-retained-'+uuid.uuid4().hex[:8]+'.php'})
 passed('revision conflict and recreated original location rejected; replacement preserved separately')
 fault="""import json,pathlib,sys,os
assert pathlib.Path('/etc/hostname').read_text().strip() in ('lima-panel-compat-ubuntu24','lima-panel-store-apps-debian13')
site,id=sys.argv[1:];assert len(site)==32 and len(id)==32
record=json.loads((pathlib.Path('/etc/panel/security-apps/modules/php-code-security/quarantine')/(id+'.json')).read_text());assert record['site_id']==site and record['path']=='risk.php' and record['state']=='quarantined'
root=pathlib.Path('/srv/panel/sites')/site;owner=json.loads((root/'.panel-site.json').read_text());assert owner['domain'].startswith('php-security-')
directory=root/'.panel-files/php-quarantine'/id;backup=directory/'backup.bin';retained=directory/'backup-original-retained.bin';assert not retained.exists()
backup.rename(retained);backup.write_bytes(b'owned QA damaged backup');backup.chmod(0o600)
print('owned private backup fault injected; original retained')"""
 p.vm('sudo','python3','-c',fault,site['id'],q['id'])
 reject('restore-quarantine','备份损坏',**restore_input(row));assert http(site)[0]==404
 row=current_record(q['id']);assert row['state']=='restoring' and not row['backup_verified'];passed('damaged backup blocks publication and exposes truthful interrupted state')
 assert not p.api('/app-modules/php-code-security')['status']['healthy']
 repair="""import pathlib,sys,json
site,id=sys.argv[1:];assert len(site)==32 and len(id)==32
root=pathlib.Path('/srv/panel/sites')/site;assert json.loads((root/'.panel-site.json').read_text())['domain'].startswith('php-security-')
d=root/'.panel-files/php-quarantine'/id;assert not (d/'backup-fault-retained.bin').exists();(d/'backup.bin').rename(d/'backup-fault-retained.bin');(d/'backup-original-retained.bin').rename(d/'backup.bin')
print('owned valid backup reinstated; damaged bytes retained separately')"""
 p.vm('sudo','python3','-c',repair,site['id'],q['id'])
 restored=module('recover-quarantine',**restore_input(row,True))['record'];assert restored['state']=='restored'
 assert http(site)==(200,fixture['body']);row=current_record(q['id']);assert row['backup_verified'] and row['source_present']
 passed('explicit interrupted restore publishes reviewed content without overwrite; real PHP HTTP 200 returns')
 after=snapshot();assert report['before']==after,'unrelated FTP/NFS services or system exports changed';report['after']=after
 report['passed']=True;save();passed('unrelated native service identities/configurations and all evidence retained')
 print('PASS complete real PHP isolation/restore acceptance '+arch+' '+phase,flush=True)
finally:p.close()
