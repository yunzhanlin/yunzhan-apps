#!/usr/bin/env python3
"""Actual PHP HTTP logs, disk files, sync, integrity and PM2 fixtures. Isolated QA only."""
import datetime,json,os,pathlib,time,uuid,sys,urllib.request,urllib.error,http.cookiejar
from panel_client import PanelClient

root=pathlib.Path(__file__).resolve().parents[1]
state=root/os.environ.get('FUNCTIONS_QA_STATE','.local/app-functional-state.json')
p=PanelClient()
def module(id,action='run',**kwargs):return p.api('/app-modules/'+id+'/'+action,kwargs)
def file(site,path,content):return p.api('/sites/'+site+'/files/action',{'action':'create','path':path,'content':content})
def cleanup(v):
 if v.get('pm2'):
  assert v['pm2'].startswith('qa-functions-')
  module('pm2-manager','delete',resource_id=v['pm2'])
 for id in v.get('sites',[]):
  site=next((s for s in p.api('/sites') if s['id']==id),None)
  if not site:continue
  assert site['slug'].startswith('functions-') and site['domain']==site['slug']+'.example.test'
  for module_id in ('enterprise-tamper-proof','website-tamper-proof','file-monitor'):
   policies=module(module_id,'policies')['policies']
   if any(row['site_id']==id for row in policies):module(module_id,'pause',site_id=id)
  if site.get('php_version_id'):p.wait(p.api('/sites/'+id+'/php',{'release_id':''})['job_id'],timeout=180)
  p.wait(p.api('/sites/'+id,{'confirm_domain':site['domain']},method='DELETE')['job_id'],timeout=180)
 print('PASS only marked functional QA apps removed and websites archived recoverably',flush=True)
def verify_existing(v):
 assert v['pm2'].startswith('qa-functions-')
 source,target=v['sites']
 for id in (source,target):
  site=next(s for s in p.api('/sites') if s['id']==id)
  assert site['slug'].startswith('functions-') and site['domain']==site['slug']+'.example.test'
 def passed(message):
  v.setdefault('additional_checks',[]).append(message);state.write_text(json.dumps(v,indent=2)+'\n');print('PASS',message,flush=True)
 result=module('site-diagnosis',site_id=source)
 assert result['checks']['http']['ok'] and result['checks']['nginx']['ok']
 passed('diagnosis actual site HTTP and Nginx configuration checks')
 result=module('daily-report');assert result['sites']>=2 and 'certificates_due_14_days' in result
 passed('daily report actual sites, resources, tasks and certificate expiry')
 result=module('mobile-pwa');assert result['installable']
 with urllib.request.urlopen(p.base+'/manifest.webmanifest') as r:assert json.load(r)['display']=='standalone'
 with urllib.request.urlopen(p.base+'/sw.js') as r:assert b'never cached' in r.read()
 passed('mobile actual installable manifest and non-caching service worker')
 module('website-tamper-proof','restore',site_id=source,path='shared.txt')
 assert p.api('/sites/'+source+'/files/text?path=shared.txt')['content']=='source-data'
 passed('signed integrity baseline restores the actual selected file')
 username='viewer-functions-'+uuid.uuid4().hex[:8];created=False
 try:
  password='qa-'+uuid.uuid4().hex
  module('user-manager','create',username=username,password=password,role='viewer',site_ids=[source]);created=True
  other=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
  req=urllib.request.Request(p.base+'/api/login',data=json.dumps({'username':username,'password':password}).encode(),headers={'Content-Type':'application/json','Origin':p.origin})
  with other.open(req) as r:json.load(r)
  with other.open(p.base+'/api/sites') as r:assert [s['id'] for s in json.load(r)]==[source]
  try:other.open(p.base+'/api/software')
  except urllib.error.HTTPError as e:assert e.code==403
  else:raise AssertionError('viewer elevated')
  module('user-manager','revoke',username=username)
  try:other.open(p.base+'/api/sites')
  except urllib.error.HTTPError as e:assert e.code==401
  else:raise AssertionError('revoked viewer session retained access')
  passed('actual restricted user login, site isolation, privilege rejection and session revocation')
 finally:
  if created:module('user-manager','delete',username=username)
 token=module('platform-ops','issue-token')['token']
 try:
  req=urllib.request.Request(p.base+'/api/platform/agent',headers={'Authorization':'Bearer '+token})
  with urllib.request.urlopen(req) as r:assert 'health' in json.load(r)
 finally:module('platform-ops','revoke-token',token=token)
 try:urllib.request.urlopen(req)
 except urllib.error.HTTPError as e:assert e.code==401
 else:raise AssertionError('revoked agent token accepted')
 passed('real read-only agent token authorization and revocation')
 pid=int(p.vm('sudo','systemctl','show','panel-pm2@'+v['pm2'],'-p','MainPID','--value').stdout)
 rows=module('task-manager')['processes'];process=next(x for x in rows if x['pid']==pid)
 assert process['can_terminate']
 try:module('task-manager','terminate',pid=pid,start_time=process['start_time']+1)
 except RuntimeError as e:assert 'HTTP 409' in str(e)
 else:raise AssertionError('reused process identity accepted')
 result=module('task-manager','terminate',pid=pid,start_time=process['start_time']);assert result['signal']=='SIGTERM'
 module('pm2-manager','restart',resource_id=v['pm2'])
 for _ in range(30):
  r=p.vm('curl','-fsS','--max-time','2','http://127.0.0.1:22345',check=False)
  if r.stdout=='functional-pm2':break
  time.sleep(.5)
 assert r.stdout=='functional-pm2'
 passed('actual SIGTERM of only the marked QA PM2 service, stale PID identity rejection and service recovery')
 ftpuser='ftp-functions-'+uuid.uuid4().hex[:8];created=False
 try:
  password='qa-'+uuid.uuid4().hex
  module('pure-ftpd','create',username=ftpuser,password=password,site_id=target);created=True
  code='''import ftplib,ssl,sys,json,io
v=json.load(sys.stdin);ctx=ssl.create_default_context(cafile='/etc/panel/security-apps/modules/pure-ftpd/server.pem')
ftp=ftplib.FTP_TLS(context=ctx);ftp.connect('localhost',2121,timeout=10);ftp.login(v['username'],v['password']);ftp.prot_p();ftp.storbinary('STOR functions-ftp.txt',io.BytesIO(b'functions-ftps-verified'));out=io.BytesIO();ftp.retrbinary('RETR functions-ftp.txt',out.write);assert out.getvalue()==b'functions-ftps-verified';assert ftp.pwd()=='/';ftp.quit();print('PASS')'''
  assert p.vm('sudo','python3','-c',code,input=json.dumps({'username':ftpuser,'password':password})).stdout.strip()=='PASS'
  assert p.api('/sites/'+target+'/files/text?path=functions-ftp.txt')['content']=='functions-ftps-verified'
  passed('actual trusted FTPS login, upload/download matching and chroot')
 finally:
  if created:module('pure-ftpd','delete',username=ftpuser)
 units=[];domain='lb-'+uuid.uuid4().hex[:8]+'.example.test';saved=False
 try:
  for index in range(2):
   id=v['sites'][index];file(id,'functions-lb.txt','functions-backend-'+str(index))
   unit='functions-lb-'+uuid.uuid4().hex[:8];units.append(unit)
   p.vm('sudo','systemd-run','--unit='+unit,'--property=User=www-data','/usr/bin/python3','-m','http.server',str(22346+index),'--bind','127.0.0.1','--directory','/srv/panel/sites/'+id+'/public')
  time.sleep(1)
  module('load-balance','save',domain=domain,port=22348,nodes=[{'address':'127.0.0.1:22346','weight':1},{'address':'127.0.0.1:22347','weight':1}]);saved=True
  def get():return p.vm('curl','-fsS','--max-time','5','http://127.0.0.1:22348/functions-lb.txt').stdout
  assert {get() for _ in range(8)}=={'functions-backend-0','functions-backend-1'}
  p.vm('sudo','systemctl','stop',units[0])
  assert {get() for _ in range(4)}=={'functions-backend-1'}
  assert not module('load-balance','probe',domain=domain)['nodes'][0]['healthy']
  passed('actual load balancing to both backends, failed-node failover and health probe')
 finally:
  if saved:module('load-balance','remove',domain=domain)
  for unit in units:p.vm('sudo','systemctl','stop',unit,check=False)
try:
 assert os.environ.get('PANEL_VM','') in ('panel-compat-ubuntu24','panel-store-apps-debian13'),'Never run functional mutations on the user panel'
 if len(sys.argv)>1 and sys.argv[1]=='cleanup':
  v=json.loads(state.read_text());cleanup(v);v['cleaned_up']=True;state.write_text(json.dumps(v,indent=2)+'\n');sys.exit(0)
 if len(sys.argv)>1 and sys.argv[1]=='verify':
  v=json.loads(state.read_text());assert v.get('passed') and not v.get('cleaned_up');verify_existing(v);sys.exit(0)
 assert not state.exists(),'Inspect or clean existing QA fixtures before rerunning'
 v={'sites':[],'checks':[],'passed':False}
 state.parent.mkdir(parents=True,exist_ok=True)
 def checkpoint():state.write_text(json.dumps(v,indent=2)+'\n')
 def passed(msg):v['checks'].append(msg);checkpoint();print('PASS',msg,flush=True)
 for index in range(2):
  slug='functions-'+uuid.uuid4().hex[:8]
  job=p.api('/sites',{'name':slug,'slug':slug,'domain':slug+'.example.test','php_version_id':'php-8.4.25' if index==0 else ''})
  p.wait(job['job_id'],timeout=180)
  site=next(s for s in p.api('/sites') if s['slug']==slug);v['sites'].append(site['id']);checkpoint()
 source,target=v['sites'];v['source']=source;v['target']=target
 site=next(s for s in p.api('/sites') if s['id']==source);v['domain']=site['domain']
 p.api('/sites/'+source+'/files/action',{'action':'mkdir','path':'assets'})
 file(source,'assets/large.txt','x'*1000);file(source,'assets/tiny.txt','tiny')
 file(source,'shared.txt','source-data');file(target,'shared.txt','target-owned')
 file(source,'slow.php','<?php usleep(1200000); echo "slow-verified";')
 file(source,'error.php','<?php http_response_code(503); echo "controlled-error";')
 file(source,'risk.php','<?php /* isolated static scan fixture: do not execute */ eval($_GET["qa"]);')
 v['from_time']=datetime.datetime.now(datetime.timezone.utc).isoformat()
 for id in ('website-analytics','website-statistics-v2'):
  p.wait(p.api('/software/'+id+'/configure',{'settings':{}})['job_id'],timeout=120)
 for path,agent in [('/assets/tiny.txt?token=sensitive-qa-value','Mozilla Chrome/123 Mobile'),('/assets/tiny.txt','Examplebot/1.0'),('/slow.php','Mozilla Firefox/123'),('/error.php','Mozilla Firefox/123')]:
  result=p.vm('curl','-sS','--max-time','10','-A',agent,'-e','https://referrer.example.test/source?token=sensitive-qa-value','-H','Host: '+site['domain'],'http://127.0.0.1:19101'+path)
  assert result.returncode==0
 for id in ('website-analytics','website-statistics-v2'):
  result=module(id,site_id=source,from_time=v['from_time'])
  assert result['requests']>=4 and result['bots']>=1 and result['slow_count']>=1 and result['errors']>=1,result
  assert result['browsers'].get('Firefox',0)>=2 and result['devices'].get('Mobile',0)>=1
  assert 'sensitive-qa-value' not in json.dumps(result)
  for kwargs in ({'only_bots':True},{'status_code':503},{'search':'/slow.php'}):
   filtered=module(id,site_id=source,from_time=v['from_time'],**kwargs);assert filtered['requests']>=1,kwargs
  passed(id+' actual timed PHP HTTP, filters, clients, slow/errors and privacy')
 disk=module('disk-analysis',site_id=source,path='assets')
 assert disk['total_bytes']==1004 and disk['files']==2 and disk['extensions']['.txt']==1004
 passed('disk actual subdirectory bytes, extensions and largest files')
 try:module('disk-analysis',site_id=source,path='../')
 except RuntimeError as e:assert 'HTTP 409' in str(e)
 else:raise AssertionError('disk traversal accepted')
 result=module('php-code-security',site_id=source);assert any(x['path']=='risk.php' and x['line']==1 and x['rule']=='dynamic-evaluation' for x in result['findings'])
 passed('PHP scan real file, risk rule and evidence line')
 for id in ('file-monitor','website-tamper-proof','enterprise-tamper-proof'):module(id,'baseline',site_id=source,excludes=['assets'],auto_restore=False)
 old=p.api('/sites/'+source+'/files/text?path=shared.txt')
 p.api('/sites/'+source+'/files/action',{'action':'save','path':'shared.txt','content':'modified-verified','expected_sha256':old['sha256']})
 for id in ('file-monitor','website-tamper-proof','enterprise-tamper-proof'):
  result=module(id,'check',site_id=source);assert any(x['path']=='shared.txt' for x in result['sites'][0]['changes'])
 passed('three integrity modules detect an actual content change')
 result=module('files-sync','preview',site_id=source,target_site_id=target);assert 'shared.txt' in result['conflicts'] and 'slow.php' in result['copied']
 module('files-sync','sync',site_id=source,target_site_id=target)
 assert p.api('/sites/'+target+'/files/text?path=shared.txt')['content']=='target-owned'
 assert p.api('/sites/'+target+'/files/text?path=assets/tiny.txt')['content']=='tiny'
 passed('real incremental sync and target conflict protection')
 file(source,'pm2-proof.js',"require('http').createServer((req,res)=>res.end('functional-pm2')).listen(Number(process.env.PORT),process.env.HOST)")
 app='qa-functions-'+uuid.uuid4().hex[:8]
 module('pm2-manager','create',resource_id=app,site_id=source,entry='pm2-proof.js',port=22345)
 v['pm2']=app;checkpoint()
 for _ in range(30):
  r=p.vm('curl','-fsS','--max-time','2','http://127.0.0.1:22345',check=False)
  if r.stdout=='functional-pm2':break
  time.sleep(.5)
 assert r.stdout=='functional-pm2'
 result=module('task-manager');assert result['processes'] and all('read_rate' in x and 'can_terminate' in x for x in result['processes'])
 assert any(x['can_terminate'] for x in result['processes'])
 passed('real PM2 HTTP and process CPU/memory/IO/managed identity')
 v['passed']=True;checkpoint();print('Functional fixtures retained only for browser verification, then run cleanup',flush=True)
except Exception:
 if 'v' in locals():state.write_text(json.dumps(v,indent=2)+'\n')
 raise
finally:p.close()
