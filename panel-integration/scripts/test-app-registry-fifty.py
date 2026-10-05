#!/usr/bin/env python3
"""Fetch all published packages; actually submit signed native/module installs."""
import json,pathlib,hashlib,urllib.request,concurrent.futures,os
from panel_client import PanelClient
c=PanelClient();root=pathlib.Path(__file__).resolve().parents[1]
try:
 page=c.api('/app-registry');apps=page['catalog']['apps'];assert len(apps)==50 and all(a['stage']=='ready' for a in apps)
 assert page['source']['source'] in ['github','verified-cache'] and not page['source']['stale']
 def fetch(app):
  assert app['package_url'].startswith('https://raw.githubusercontent.com/yunzhanlin/yunzhan-apps/main/dist/apps/')
  with urllib.request.urlopen(app['package_url'],timeout=60) as response:raw=response.read(262145)
  assert hashlib.sha256(raw).hexdigest()==app['sha256'],app['id']
  manifest=json.loads(raw);assert manifest['stage']=='ready' and manifest['id']==app['id'];return app['id']
 with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:downloaded=list(pool.map(fetch,apps))
 group=os.environ.get('APP_REGISTRY_GROUP','panel-module');installed=[]
 for app in apps:
  if app['provider']!=group:continue
  job=c.api('/app-registry/'+app['id']+'/install',{});c.wait(job['job_id'],timeout=900);installed.append(app['id']);print('SIGNED INSTALL',app['id'],flush=True)
 report={'passed':True,'verified_package_count':len(downloaded),'package_ids':sorted(downloaded),'provider':group,'signed_installs':installed}
 (root/('.local/app-registry-fifty-'+group+'.json')).write_text(json.dumps(report,indent=2)+'\n')
 print('PASS 50 real GitHub package hashes and '+str(len(installed))+' signed '+group+' installations',flush=True)
finally:c.close()
