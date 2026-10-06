#!/usr/bin/env python3
"""Uninstall/reinstall audited modules without deleting reports or site data."""
import pathlib,json,os
from panel_client import PanelClient
assert os.environ.get('PANEL_VM') in ('panel-compat-ubuntu24','panel-store-apps-debian13'), 'Explicit isolated application QA required'
ROOT=pathlib.Path(__file__).resolve().parents[1];c=PanelClient();out={'modules':{}}
try:
 ids=[a['id'] for a in c.api('/software')['catalog'] if a['family']=='module']
 assert len(ids)==20
 existing={s['id'] for s in c.api('/software')['status'] if s['installed']}
 for id in ids:
  if id in existing:
   print('SKIP existing software; only this run owns lifecycle fixtures:',id,flush=True);continue
  c.wait(c.api('/software/'+id+'/install',{'settings':{}})['job_id'],timeout=900)
  c.wait(c.api('/software/'+id+'/uninstall',{'settings':{}})['job_id'])
  assert not c.api('/app-modules/'+id)['status']['installed']
  c.wait(c.api('/software/'+id+'/install',{'settings':{}})['job_id'],timeout=900)
  assert c.api('/app-modules/'+id)['status']['installed'] and c.api('/app-modules/'+id)['status']['healthy']
  out['modules'][id]={'uninstall':True,'reinstall':True,'healthy':True}
  (ROOT/'.local/app-module-lifecycle-acceptance.json').write_text(json.dumps(out,ensure_ascii=False,indent=2)+'\n');print('PASS lifecycle',id,flush=True)
finally:c.close()
