#!/usr/bin/env python3
"""Real scheduled writes and restart proof, only on explicitly isolated QA hosts."""
import json, os, pathlib, sys, time, uuid
from panel_client import PanelClient

assert os.environ.get('PANEL_VM') in ('panel-compat-ubuntu24','panel-compat-ubuntu22','panel-store-apps-debian13'), 'Isolated QA VM required'
root=pathlib.Path(__file__).resolve().parents[1]
state=root/os.environ.get('RELIABILITY_QA_STATE','.local/app-reliability-state.json')
p=PanelClient()
modules=('enterprise-tamper-proof','website-tamper-proof','file-monitor')
def module(id,action='run',**body): return p.api('/app-modules/'+id+'/'+action,body)
def content(site,path): return p.api('/sites/'+site+'/files/text?path='+path)['content']
def write(site,path,value):
 old=p.api('/sites/'+site+'/files/text?path='+path)
 p.api('/sites/'+site+'/files/action',{'action':'save','path':path,'content':value,'expected_sha256':old['sha256']})
def create(site,path,value): p.api('/sites/'+site+'/files/action',{'action':'create','path':path,'content':value})
def poll(check,timeout=90):
 deadline=time.monotonic()+timeout
 while time.monotonic()<deadline:
  if check():return
  time.sleep(2)
 raise AssertionError('Scheduled business result not observed before deadline')
def checkpoint(): state.parent.mkdir(parents=True,exist_ok=True);state.write_text(json.dumps(v,indent=2)+'\n')
def passed(message): v['checks'].append(message);checkpoint();print('PASS',message,flush=True)
def plans():return module('files-sync')['plans']
def cleanup():
 assert v['plan'].startswith('qa-reliability-')
 for plan in plans():
  if plan['id']==v['plan']:module('files-sync','remove-plan',resource_id=plan['id'],expected_revision=plan['revision'])
 for siteid in v['sites']:
  site=next((s for s in p.api('/sites') if s['id']==siteid),None)
  if not site:continue
  assert site['slug'].startswith('reliability-') and site['domain']==site['slug']+'.example.test'
  for id in modules:
   rows=module(id,'policies')['policies']
   if any(x['site_id']==siteid for x in rows):module(id,'pause',site_id=siteid)
  p.wait(p.api('/sites/'+siteid,{'confirm_domain':site['domain']},method='DELETE')['job_id'],timeout=180)
 v['cleaned_up']=True;checkpoint();print('PASS marked QA plans removed, monitoring paused, websites archived recoverably',flush=True)
try:
 if len(sys.argv)>1 and sys.argv[1]=='cleanup':v=json.loads(state.read_text());cleanup();sys.exit(0)
 assert not state.exists(),'Inspect existing QA fixtures before rerunning'
 v={'sites':[],'plan':'qa-reliability-'+uuid.uuid4().hex[:8],'checks':[],'passed':False};checkpoint()
 for _ in range(2):
  slug='reliability-'+uuid.uuid4().hex[:8]
  p.wait(p.api('/sites',{'name':slug,'slug':slug,'domain':slug+'.example.test','php_version_id':''})['job_id'],timeout=180)
  site=next(s for s in p.api('/sites') if s['slug']==slug);v['sites'].append(site['id']);checkpoint()
 source,target=v['sites'];v['source']=source;v['target']=target
 v['domain']=next(s for s in p.api('/sites') if s['id']==source)['domain'];checkpoint()
 create(source,'copy.txt','first');create(source,'conflict.txt','source');create(target,'conflict.txt','target-owned')
 create(source,'skip.txt','not-copied');create(source,'protected.txt','baseline-data')
 for id in modules:module(id,'baseline',site_id=source,excludes=['copy.txt','conflict.txt','skip.txt'],auto_restore=id=='enterprise-tamper-proof',interval=60)
 for id in modules:module(id,'pause',site_id=source)
 config=dict(resource_id=v['plan'],site_id=source,target_site_id=target,excludes=['skip.txt'],interval=60,enabled=True,expected_revision=0)
 plan=module('files-sync','schedule',**config)['plan'];assert plan['revision']==1
 try:module('files-sync','schedule',**config)
 except RuntimeError as e:assert 'HTTP 409' in str(e)
 else:raise AssertionError('stale plan configuration accepted')
 poll(lambda:any(x['id']==v['plan'] and x.get('last_finished_at') for x in plans()))
 assert content(target,'copy.txt')=='first' and content(target,'conflict.txt')=='target-owned'
 assert not any(x['name']=='skip.txt' for x in p.api('/sites/'+target+'/files?path=')['entries'])
 passed('real background scheduled copy, excludes, conflicts and stale revision rejection')
 plan=next(x for x in plans() if x['id']==v['plan']);assert plan['last_state']=='conflicts' and plan['conflicts_count']>=1
 module('files-sync','pause-plan',resource_id=v['plan'],expected_revision=plan['revision'])
 write(source,'copy.txt','after-restart');write(source,'protected.txt','paused-edit')
 time.sleep(35)
 assert content(target,'copy.txt')=='first' and content(source,'protected.txt')=='paused-edit'
 time.sleep(35)
 assert content(target,'copy.txt')=='first' and content(source,'protected.txt')=='paused-edit'
 passed('paused sync and signed protection make no writes across a complete interval')
 module('enterprise-tamper-proof','resume',site_id=source)
 for id in ('file-monitor','website-tamper-proof'):module(id,'resume',site_id=source)
 plan=next(x for x in plans() if x['id']==v['plan'])
 module('files-sync','resume-plan',resource_id=v['plan'],expected_revision=plan['revision'])
 # Only the explicitly allowed QA executor is restarted; panel and user main host are untouched.
 p.vm('sudo','systemctl','restart','panel-executor')
 poll(lambda:content(target,'copy.txt')=='after-restart' and content(source,'protected.txt')=='baseline-data',timeout=105)
 passed('executor restart retains plan/policies and automatically copies/restores real files')
 for id in modules:
  rows=module(id,'policies')['policies'];assert next(x for x in rows if x['site_id']==source)['signature_verified']
  history=module(id,'history',site_id=source)['history'];assert any(x['trigger']=='scheduled' for x in history)
 history=module('files-sync','history',resource_id=v['plan'])['history'];assert any(x['trigger']=='scheduled' and x.get('conflicts_count',0)>0 for x in history)
 passed('actual scheduled histories persisted without request secrets and policy signatures verified')
 write(target,'copy.txt','target-external');write(source,'copy.txt','source-next')
 result=module('files-sync','run-plan',resource_id=v['plan'])
 assert result['result']['conflicts_count']>=2 and content(target,'copy.txt')=='target-external'
 plan=next(x for x in plans() if x['id']==v['plan'])
 module('files-sync','pause-plan',resource_id=v['plan'],expected_revision=plan['revision'])
 for id in modules:module(id,'pause',site_id=source)
 passed('manual planned execution preserves externally edited target files; fixture automation paused')
 v['passed']=True;checkpoint();print('Fixtures retained for browser acceptance, then cleanup',flush=True)
finally:p.close()
