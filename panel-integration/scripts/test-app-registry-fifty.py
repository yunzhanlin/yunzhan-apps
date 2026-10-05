#!/usr/bin/env python3
"""Fetch all published packages; actually submit signed native/module installs."""
import json,pathlib,hashlib,urllib.request,concurrent.futures,os,time
from panel_client import PanelClient
c=PanelClient();root=pathlib.Path(__file__).resolve().parents[1]
try:
 page=c.api('/app-registry');apps=page['catalog']['apps'];assert len(apps)==50 and all(a['stage']=='ready' for a in apps)
 assert page['source']['source'] in ['github','verified-cache'] and not page['source']['stale']
 def fetch(app):
  assert app['package_url'].startswith('https://raw.githubusercontent.com/yunzhanlin/yunzhan-apps/main/dist/apps/')
  for attempt in range(6):
   with urllib.request.urlopen(urllib.request.Request(app['package_url'],headers={'Cache-Control':'no-cache'}),timeout=60) as response:raw=response.read(262145)
   if hashlib.sha256(raw).hexdigest()==app['sha256']:break
   if attempt==5:raise AssertionError('Unmatched real GitHub package digest: '+app['id'])
   time.sleep(10)
  manifest=json.loads(raw);assert manifest['stage']=='ready' and manifest['id']==app['id'];return app['id']
 with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:downloaded=list(pool.map(fetch,apps))
 group=os.environ.get('APP_REGISTRY_GROUP','panel-module');installed=[]
 for app in apps:
  if app['provider']!=group:continue
  if group=='panel-module' and app['target'] in ['intrusion-prevention','system-hardening','nginx-waf']:
   status=next(s for s in c.api('/software')['status'] if s['id']==app['target'])
   if status['installed']:c.wait(c.api('/software/'+app['target']+'/uninstall',{})['job_id'],timeout=900)
  job=c.api('/app-registry/'+app['id']+'/install',{});c.wait(job['job_id'],timeout=900);installed.append(app['id']);print('SIGNED INSTALL',app['id'],flush=True)
 report={'passed':True,'verified_package_count':len(downloaded),'package_ids':sorted(downloaded),'provider':group,'signed_installs':installed}
 (root/('.local/app-registry-fifty-'+group+'.json')).write_text(json.dumps(report,indent=2)+'\n')
 print('PASS 50 real GitHub package hashes and '+str(len(installed))+' signed '+group+' installations',flush=True)
finally:c.close()
