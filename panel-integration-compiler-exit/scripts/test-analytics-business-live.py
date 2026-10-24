"""Owned QA website only: real Nginx collection, INP and funnel business workflow.

Prepare/verify are separated so a real browser can navigate between pages. No
artificial telemetry is inserted. Disabling restores the site's original config.
"""
import hashlib,json,os,pathlib,re,sys,uuid,urllib.parse
from panel_client import PanelClient
assert os.environ.get('PANEL_VM') in ('panel-compat-ubuntu24','panel-store-apps-debian13')
root=pathlib.Path(__file__).resolve().parents[1]
arch='arm64' if os.environ['PANEL_VM'].endswith('ubuntu24') else 'amd64'
attempt=os.environ.get('PANEL_ANALYTICS_QA_ATTEMPT','')
assert not attempt or re.fullmatch('[0-9a-f]{8}',attempt)
state=root/'.local'/('analytics-business-'+arch+('-'+attempt if attempt else '')+'.json');phase=sys.argv[1]
p=PanelClient()
def save():state.write_text(json.dumps(v,ensure_ascii=False,indent=2)+'\n');state.chmod(0o600)
def snapshot(exclude):
 code="""import hashlib,json,pathlib,subprocess,sys
assert pathlib.Path('/etc/hostname').read_text().strip() in ('lima-panel-compat-ubuntu24','lima-panel-store-apps-debian13')
out={};exclude=sys.argv[1];live=set()
for module in ('enterprise-tamper-proof','website-tamper-proof','file-monitor'):
 base='/etc/panel/security-apps/modules/'+module+'/'
 live.update(base+name for name in ('history.sqlite','history.json','last-report.json'))
 live.update(base+'baselines/080e8b1cace24105f6c1d84ebfd2fb01/'+name for name in ('monitoring.json','last-check.json'))
for unit in ('nginx','panel-executor','panel-nfs-server','panel-pure-ftpd','nfs-server'):
 out[unit]=subprocess.check_output(['systemctl','show','-p','MainPID,ActiveState,ExecMainStartTimestampMonotonic',unit],text=True)
for directory in (pathlib.Path('/etc/nginx'),pathlib.Path('/etc/panel')):
 for f in sorted(directory.rglob('*')):
  if f.is_file() and not f.is_symlink() and exclude not in str(f):
   out[str(f)]='named-live-monitor-record' if str(f) in live else hashlib.sha256(f.read_bytes()).hexdigest()
print(json.dumps(out))"""
 return json.loads(p.vm('sudo','python3','-c',code,exclude).stdout)
try:
 if phase=='prepare':
  assert not state.exists();assert p.api('/app-modules/website-analytics')['status']['installed']
  slug='analytics-business-'+uuid.uuid4().hex[:8]
  p.wait(p.api('/sites',{'name':slug,'slug':slug,'domain':slug+'.localhost','php_version_id':''})['job_id'],timeout=180)
  site=next(s for s in p.api('/sites') if s['slug']==slug)
  ident=site['id'];cfg=p.api('/analytics/sites/'+ident+'/config')
  v={'passed':False,'site':site,'config_before':p.api('/sites/'+ident+'/config')['content'],'unrelated_before':snapshot(ident),'protection_contract':'native identities and all unrelated configs unchanged except 15 explicitly named live monitor records; paths remain present'};save()
  cfg['enabled']=True;cfg['clicks']=False;cfg['retention_days']=1
  p.wait(p.api('/analytics/sites/'+ident+'/config',cfg)['job_id'],timeout=120)
  cfg=p.api('/analytics/sites/'+ident+'/config');assert cfg['enabled']
  for name,nextpage,label in [('entry','checkout','前往结算'),('checkout','done','确认完成'),('done','entry','返回入口')]:
   content='<!doctype html><html lang="zh"><meta charset="utf-8"><title>云栈真实网站分析验收 '+name+'</title><style>body{max-width:800px;margin:70px auto;font:18px system-ui;color:#203047}button,a{display:inline-block;padding:15px;background:#0aab66;border:0;border-radius:6px;color:white;text-decoration:none;font-size:18px}textarea{display:block;margin:30px 0;width:90%}</style><h1>真实网站分析 · '+name+'</h1><p>独立 QA 网站，经 Nginx 同源代理采集。不修改主面板。</p><button id="interaction">执行 250 ms 真实交互</button><textarea data-analytics-ignore>never-collected-business-private-text</textarea><p><a href="/'+nextpage+'.html">'+label+'</a></p><script defer src="/__yunzhan/analytics/tracker.js?site='+ident+'&amp;key='+cfg['key']+'"></script><script>document.querySelector("#interaction").addEventListener("click",()=>{const end=performance.now()+250;while(performance.now()<end){};document.querySelector("#interaction").textContent="真实交互已执行";});</script></html>'
   p.api('/sites/'+ident+'/files/action',{'action':'create','path':name+'.html','content':content})
  assert snapshot(ident)==v['unrelated_before'];v['enabled_config']=cfg;save()
  # The AMD guest website listener is forwarded separately. Host 19101 is
  # the protected main FeiFeiCMS site and must never be used for this fixture.
  port='19221' if arch=='arm64' else '19229'
  print('PASS own real website/proxy prepared; browser entry http://'+site['domain']+':'+port+'/entry.html',flush=True)
 elif phase=='verify':
  v=json.loads(state.read_text());site=v['site'];assert site['domain'].startswith('analytics-business-')
  query=urllib.parse.urlencode([('step','/entry.html'),('step','/checkout.html'),('step','/done.html'),('window_minutes','30')])
  report=p.api('/analytics/sites/'+site['id']+'/report');funnel=p.api('/analytics/sites/'+site['id']+'/funnel?'+query)
  assert not funnel['partial'] and funnel['completed_sessions']>=1 and all(s['sessions']>=1 for s in funnel['steps'])
  assert report['performance']['inp']['samples']>=1 and report['performance']['inp']['p75']>=40
  code="""import sqlite3,pathlib,sys,json
assert pathlib.Path('/etc/hostname').read_text().strip() in ('lima-panel-compat-ubuntu24','lima-panel-store-apps-debian13')
db=sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True)
leaked=db.execute("SELECT count(*) FROM analytics_events WHERE site_id=? AND (data LIKE '%never-collected-business-private-text%' OR data LIKE '%interactionId%' OR data LIKE '%target%')",(sys.argv[1],)).fetchone()[0]
print(json.dumps({'private_content_or_target_leaks':leaked}))"""
  privacy=json.loads(p.vm('sudo','python3','-c',code,site['id']).stdout);assert privacy['private_content_or_target_leaks']==0
  assert snapshot(site['id'])==v['unrelated_before'];v.update(report=report,funnel=funnel,privacy=privacy,real_browser_verified=True);save()
  print(json.dumps({'passed':True,'architecture':arch,'source':'real browser -> real Nginx same-origin proxy -> authenticated report/funnel','completed_sessions':funnel['completed_sessions'],'inp':report['performance']['inp'],'privacy':privacy},ensure_ascii=False),flush=True)
 elif phase=='disable':
  v=json.loads(state.read_text());assert v['real_browser_verified'];site=v['site'];ident=site['id']
  cfg=p.api('/analytics/sites/'+ident+'/config');cfg['enabled']=False
  p.wait(p.api('/analytics/sites/'+ident+'/config',cfg)['job_id'],timeout=120)
  assert p.api('/sites/'+ident+'/config')['content']==v['config_before']
  assert snapshot(ident)==v['unrelated_before'];assert p.api('/analytics/sites/'+ident+'/report')['overview']['pv']>=3
  v['passed']=True;v['disabled_original_config_restored']=True;save()
  print('PASS collector disabled, exact original site config restored; real history and unrelated services/configurations preserved',flush=True)
 else:raise AssertionError('unknown phase')
finally:p.close()
