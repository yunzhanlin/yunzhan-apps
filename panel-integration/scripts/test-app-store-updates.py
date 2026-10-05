#!/usr/bin/env python3
"""Real GitHub manifest upgrades on explicitly isolated application QA hosts."""
import json, os, pathlib, sys, time
from panel_client import PanelClient
assert os.environ.get('PANEL_VM') in ('panel-compat-ubuntu24','panel-compat-ubuntu22','panel-store-apps-debian13'), 'Isolated QA host required'
p=PanelClient();state=pathlib.Path(os.environ.get('STORE_UPDATE_STATE','.local/store-update-acceptance.json'))
def snapshot(id):
 script='''import hashlib,json,pathlib,sys
p=pathlib.Path('/etc/panel/security-apps/modules')/sys.argv[1]
v=json.loads((p/'installed.json').read_text())
files={str(f.relative_to(p)):hashlib.sha256(f.read_bytes()).hexdigest() for f in p.rglob('*') if f.is_file() and not f.is_symlink() and f.name!='installed.json' and f.stat().st_size<4194304}
print(json.dumps({'manifest':v,'files':files}))'''
 return json.loads(p.vm('sudo','python3','-c',script,id).stdout)
def save(v):
 state.parent.mkdir(parents=True,exist_ok=True);state.write_text(json.dumps(v,indent=2)+'\n');state.chmod(0o600)
try:
 phase=sys.argv[1] if len(sys.argv)>1 else 'update'
 if phase=='prepare':
  assert not state.exists(),'Inspect existing acceptance state before rerunning'
  catalog=p.api('/app-registry');apps=[a for a in catalog['catalog']['apps'] if a['provider']=='panel-module' and a['target'] not in ('nginx-waf','system-hardening','intrusion-prevention')]
  installed={s['id']:s for s in catalog['status']};apps=[a for a in apps if installed[a['id']]['installed']]
  old=snapshot('files-sync')['manifest'];settings=old.get('settings',{});settings['interval']=600;settings['excludes']=['qa-update-preserved']
  p.wait(p.api('/software/files-sync/configure',{'settings':settings})['job_id'],timeout=90)
  v={'before':{a['id']:snapshot(a['target'])['manifest'] for a in apps},'checks':[],'passed':False};save(v)
  print('PASS isolated upgrade fixture prepared without changing plans, baselines or data',flush=True)
 else:
  v=json.loads(state.read_text());catalog=p.api('/app-registry?refresh=1');assert not catalog['source']['stale'],catalog['source']
  for app in catalog['catalog']['apps']:
   if app['id'] not in v['before']:continue
   status=next(s for s in catalog['status'] if s['id']==app['id'])
   before=snapshot(app['target'])
   if status['update_available']:
    assert status['update_supported'],status
    p.wait(p.api('/app-registry/'+app['id']+'/update',{'expected_version':app['version'],'expected_sha256':app['sha256']})['job_id'],timeout=90)
    after=snapshot(app['target']);assert before['files']==after['files'],app['id']+' changed reports/data during update'
   else:after=before
   original=v['before'][app['id']]
   assert after['manifest'].get('settings')==original.get('settings') and after['manifest'].get('installed_at')==original.get('installed_at'),app['id']+' reset configuration/install time'
   assert after['manifest']['version']==app['version'],(app['id'],after['manifest']['version'],app['version'])
   v['checks'].append(app['id']+' verified signed upgrade, preserved configuration and reports');save(v);print('PASS',app['id'],'upgrade and preservation',flush=True)
  final=p.api('/app-registry?refresh=1');assert not final['source']['stale']
  for id in v['before']:
   status=next(s for s in final['status'] if s['id']==id);assert not status['update_available'] and status['version_known'],status
  app=next(a for a in final['catalog']['apps'] if a['id']=='files-sync')
  try:p.api('/app-registry/files-sync/update',{'expected_version':'0.0','expected_sha256':app['sha256']})
  except RuntimeError as e:assert 'HTTP 409' in str(e)
  else:raise AssertionError('stale version request accepted')
  v['passed']=True;v['updated_apps']=len(v['before']);save(v);print('PASS update badges cleared only after actual successful jobs; stale requests rejected',flush=True)
finally:p.close()
