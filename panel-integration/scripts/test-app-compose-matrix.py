#!/usr/bin/env python3
"""Real install/HTTP/restart/cleanup matrix for the new isolated applications."""
import json,pathlib,time,os,uuid
from panel_client import PanelClient
from test_app_registry_common import wait_job

ROOT=pathlib.Path(__file__).resolve().parents[1]
assert os.environ.get('PANEL_VM') == 'panel-store-apps-debian13', 'Explicit isolated amd64 application QA VM required; never run on the user panel'
path=ROOT/'.local/app-compose-matrix-acceptance.json'
report=json.loads(path.read_text()) if path.exists() else {'apps':{}}
c=PanelClient()
source_id=report.get('source_site_id')
if not source_id or not any(s['id']==source_id for s in c.api('/sites')):
 slug='legacy-source-'+uuid.uuid4().hex[:8]
 c.wait(c.api('/sites',{'name':'隔离 PHP 部署验收源','slug':slug,'domain':slug+'.example.test','php_version_id':''})['job_id'])
 source_id=next(s['id'] for s in c.api('/sites') if s['slug']==slug);report['source_site_id']=source_id
 c.api('/sites/'+source_id+'/files/action',{'action':'create','path':'index.php','content':'<?php header("Content-Type: application/json"); echo json_encode(array("deployed"=>true,"version"=>PHP_VERSION)); ?>'})
assert next(s for s in c.api('/sites') if s['id']==source_id)['slug'].startswith('legacy-source-'), 'Only a marked QA source may be used'
selected=os.environ.get('APP_MATRIX_IDS','php-legacy-52,php-legacy-53,php-legacy-54,php-legacy-55,php-legacy-56,php-legacy-70,php-legacy-71,php-legacy-72,php-legacy-73,php-legacy-74,php-legacy-80,php-legacy-81,rabbitmq,openlitespeed').split(',')
def record():path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
def guest(*args,**kw):
 kw.setdefault('check',False);result=c.vm(*args,**kw)
 if result.returncode:raise AssertionError(result.stderr[-2000:])
 return result.stdout.strip()
def wait_healthy(project_id,timeout=600):
 deadline=time.monotonic()+timeout
 while time.monotonic()<deadline:
  project=next(p for p in c.api('/docker/projects')['projects'] if p['id']==project_id)
  if project['state']=='running' and project['healthy']==project['services']:return project
  time.sleep(2)
 raise AssertionError('Container health timeout: '+c.api('/docker/projects/'+project_id+'/logs')['logs'][-2000:])
for index,app in enumerate(selected):
 if app in report['apps'] and report['apps'][app].get('passed') and os.environ.get('APP_MATRIX_FORCE')!='1':continue
 created=None;bound_site=None
 try:
  port=23000+index*2
  resumed=os.environ.get('APP_MATRIX_RESUME_JOB') if app=='php-legacy-70' else None
  body={'name':'matrix-'+app+'-'+uuid.uuid4().hex[:6],'host_port':port}
  if os.environ.get('APP_MATRIX_USE_REGISTRY')=='1':
   app_id=app.replace('php-legacy-','php-')
   job=c.api('/app-registry/'+app_id+'/install',body)
  else:
   body['template_id']=app
   job=c.api('/docker/jobs/'+resumed) if resumed else c.api('/docker/projects',body)
  print('INSTALL',app,job['job_id'][:8],flush=True);wait_job(c,job)
  created=next(p for p in c.api('/docker/projects')['projects'] if p['id']==job['project_id'])
  created=wait_healthy(created['id'])
  if app.startswith('php-legacy-'):
   content=json.loads(guest('curl','-fsS','http://127.0.0.1:'+str(port)+'/'))
   digits=app.rsplit('-',1)[-1];assert content['version'].startswith(digits[0]+'.'+digits[1]+'.') and content['sapi']==('cgi-fcgi' if digits=='52' else 'fpm-fcgi'),content
   processes=guest('sudo','docker','top',created['engine_name']+'-php-1','-eo','pid,comm')
   assert ('php-cgi' if digits=='52' else 'php-fpm') in processes,processes
   assert content['mysqli'] and content['pdo_mysql'],content
   check=json.loads(guest('curl','-fsS','http://127.0.0.1:'+str(port)+'/.__cloudstack_health'));assert check['ok']
   report['apps'][app]={'version':content['version'],'http_php_fpm':True,'mysql_extensions':True}
   synced=c.api('/app-modules/files-sync/sync',{'site_id':source_id,'target_project_id':created['id']});assert 'index.php' in synced['copied'] and not synced['conflicts'],synced
   deployed=json.loads(guest('curl','-fsS','http://127.0.0.1:'+str(port)+'/'));assert deployed['deployed'] and deployed['version']==content['version']
   slug='bound-'+uuid.uuid4().hex[:12];domain=slug+'.example.test'
   c.wait(c.api('/docker/projects/'+created['id']+'/sites',{'name':'隔离PHP域名验收','slug':slug,'domain':domain})['job_id'])
   bound_site=next(s for s in c.api('/sites') if s['slug']==slug)
   assert json.loads(guest('curl','-fsS','-H','Host: '+domain,'http://127.0.0.1:19101/'))['deployed']
   report['apps'][app].update(real_site_deployment=True,domain_binding=True)
  elif app=='openlitespeed':
   raw=guest('curl','-fsS','http://127.0.0.1:'+str(port)+'/');assert 'LiteSpeed' in raw
   phpinfo=guest('curl','-fsS','http://127.0.0.1:'+str(port)+'/phpinfo.php');assert 'PHP Version 8.3.' in phpinfo and 'LiteSpeed' in phpinfo
   guest('sudo','docker','exec',created['engine_name']+'-openlitespeed-1','/usr/local/lsws/lsphp83/bin/php','-r',"file_put_contents('/var/www/vhosts/cloudstack/html/cloudstack-persistence.txt','ols-persistence-verified');")
   assert guest('curl','-fsS','http://127.0.0.1:'+str(port)+'/cloudstack-persistence.txt')=='ols-persistence-verified'
   credentials=c.api('/docker/projects/'+created['id']+'/credentials',{})
   assert len(credentials['credentials']['CLOUDSTACK_ADMIN_PASSWORD'])==64
   admin=guest('curl','-k','-L','-fsS','https://127.0.0.1:'+str(port+1)+'/');assert 'login' in admin.lower()
   login_code='''import json,sys,ssl,urllib.request,urllib.parse,http.cookiejar
v=json.load(sys.stdin);base='https://127.0.0.1:'+str(v['port']);jar=http.cookiejar.CookieJar();client=urllib.request.build_opener(urllib.request.HTTPSHandler(context=ssl._create_unverified_context()),urllib.request.HTTPCookieProcessor(jar));client.addheaders=[('Referer',base+'/login.php')];client.open(base+'/login.php',timeout=20).close();data=urllib.parse.urlencode({'userid':'admin','pass':v['password']}).encode()
with client.open(base+'/login.php',data,timeout=20) as res:page=res.read().decode();assert res.url.endswith('/index.php'),res.url
assert len(list(jar))>0
with client.open(base+'/index.php',timeout=20) as res:assert not res.url.endswith('/login.php')
print('OpenLiteSpeed authenticated administration verified')'''
   assert 'verified' in guest('python3','-c',login_code,input=json.dumps({'port':port+1,'password':credentials['credentials']['CLOUDSTACK_ADMIN_PASSWORD']}))
   slug='ols-bound-'+uuid.uuid4().hex[:10];domain=slug+'.example.test'
   c.wait(c.api('/docker/projects/'+created['id']+'/sites',{'name':'OpenLiteSpeed 域名验收','slug':slug,'domain':domain})['job_id'])
   bound_site=next(s for s in c.api('/sites') if s['slug']==slug)
   assert 'LiteSpeed' in guest('curl','-fsS','-H','Host: '+domain,'http://127.0.0.1:19101/')
   report['apps'][app]={'http_server':True,'php_lsapi':True,'https_admin':True,'authenticated_admin':True,'random_admin_password':True,'domain_binding':True}
  else:
   credentials=c.api('/docker/projects/'+created['id']+'/credentials',{})['credentials']
   verify_code='''import json,sys,urllib.request,base64,socket
v=json.load(sys.stdin);auth=base64.b64encode((v['user']+':'+v['password']).encode()).decode();base='http://127.0.0.1:'+str(v['port'])
def call(method,path,data=None):
 req=urllib.request.Request(base+path,data=json.dumps(data).encode() if data is not None else None,method=method,headers={'Authorization':'Basic '+auth,'Content-Type':'application/json'})
 with urllib.request.urlopen(req,timeout=30) as r:
  raw=r.read();return json.loads(raw) if raw else None
if v['phase']=='publish':
 call('PUT','/api/queues/%2F/cloudstack-qa',{'durable':True,'auto_delete':False,'arguments':{}})
 result=call('POST','/api/exchanges/%2F/amq.default/publish',{'properties':{'delivery_mode':2},'routing_key':'cloudstack-qa','payload':'rabbitmq-verified','payload_encoding':'string'});assert result['routed']
 with socket.create_connection(('127.0.0.1',v['port']+1),5):pass
else:
 result=call('POST','/api/queues/%2F/cloudstack-qa/get',{'count':1,'ackmode':'ack_requeue_false','encoding':'auto','truncate':100});assert result[0]['payload']=='rabbitmq-verified';call('DELETE','/api/queues/%2F/cloudstack-qa')
print('RabbitMQ message roundtrip passed')'''
   values={'user':credentials['RABBITMQ_DEFAULT_USER'],'password':credentials['RABBITMQ_DEFAULT_PASS'],'port':port,'phase':'publish'}
   assert 'passed' in guest('python3','-c',verify_code,input=json.dumps(values))
   report['apps'][app]={'authenticated_publish':True,'amqp_listener':True}
  wait_job(c,c.api('/docker/projects/'+created['id']+'/stop',{}));wait_job(c,c.api('/docker/projects/'+created['id']+'/start',{}))
  current=wait_healthy(created['id']);assert current['healthy']==current['services']
  if app=='openlitespeed':
   assert guest('curl','-fsS','http://127.0.0.1:'+str(port)+'/cloudstack-persistence.txt')=='ols-persistence-verified'
   report['apps'][app]['site_data_after_restart']=True
  if app.startswith('php-legacy-'):
   assert json.loads(guest('curl','-fsS','http://127.0.0.1:'+str(port)+'/'))==deployed
   assert json.loads(guest('curl','-fsS','-H','Host: '+domain,'http://127.0.0.1:19101/'))==deployed
   report['apps'][app]['deployed_data_after_restart']=True
  if app=='rabbitmq':values['phase']='consume';assert 'passed' in guest('python3','-c',verify_code,input=json.dumps(values));report['apps'][app]['durable_message_after_restart']=True
  report['apps'][app].update(passed=True,restart_healthy=True,signed_registry_install=os.environ.get('APP_MATRIX_USE_REGISTRY')=='1');record();print('PASS',app,flush=True)
 except Exception as err:
  report['apps'].setdefault(app,{})['error']=str(err);record();raise
 finally:
  if created:
   if bound_site:c.wait(c.api('/sites/'+bound_site['id'],{'confirm_domain':bound_site['domain']},method='DELETE')['job_id'])
   wait_job(c,c.api('/docker/projects/'+created['id'],{'confirm_name':created['name']},method='DELETE'))
   for volume in c.api('/docker/volumes')['volumes']:
    name=volume['Name']
    if name.startswith(created['engine_name']+'_'):c.api('/docker/volumes/'+name,{'confirm_name':name},method='DELETE')
   report['apps'][app]['cleanup_ok']=True
  record()
c.close()
print('MATRIX PASSED',len([v for v in report['apps'].values() if v.get('passed')]),flush=True)
