#!/usr/bin/env python3
"""Real PM2 environment, frozen npm ci, failure preservation and asynchronous recovery."""
import copy,json,os,pathlib,time,uuid
from panel_client import PanelClient
assert os.environ.get('PANEL_VM') in ('panel-compat-ubuntu24','panel-store-apps-debian13'),'Isolated QA only'
root=pathlib.Path(__file__).resolve().parents[1]; state=root/os.environ.get('PM2_QA_STATE','.local/pm2-deployment-qa.json')
assert not state.exists(),'Inspect previous acceptance state before rerunning'
p=PanelClient();p.timeout=70
v={'sites':[],'app':'qa-deploy-'+uuid.uuid4().hex[:8],'checks':[],'passed':False};created=False
def save():state.parent.mkdir(parents=True,exist_ok=True);state.write_text(json.dumps(v,indent=2)+'\n');state.chmod(0o600)
def passed(text):v['checks'].append(text);save();print('PASS',text,flush=True)
def module(action='run',**body):return p.api('/app-modules/pm2-manager/'+action,body)
def rejected(call):
 try:call()
 except RuntimeError as e:assert 'HTTP 409' in str(e);return
 raise AssertionError('Unsafe/stale operation accepted')
def write(name,body):
 try:old=p.api('/sites/'+site+'/files/text?path='+name)
 except RuntimeError:p.api('/sites/'+site+'/files/action',{'action':'create','path':name,'content':body});return
 p.api('/sites/'+site+'/files/action',{'action':'save','path':name,'content':body,'expected_sha256':old['sha256']})
def request():return json.loads(p.vm('curl','-fsS','--max-time','3','http://127.0.0.1:22456').stdout)
def deployment():return module('deployment',resource_id=v['app'])['deployment']
def wait_deployment(expected):
 end=time.monotonic()+150
 while time.monotonic()<end:
  row=deployment()
  if row['state'] in ('succeeded','failed','needs_attention'):
   assert row['state']==expected,row;return row
  time.sleep(.5)
 raise AssertionError('Real dependency job did not finish')
try:
 save();status=p.api('/app-modules/pm2-manager')['status'];assert status['installed'] and status['healthy']
 slug='pm2-deploy-'+uuid.uuid4().hex[:8]
 p.wait(p.api('/sites',{'name':slug,'slug':slug,'domain':slug+'.example.test','php_version_id':''})['job_id'],timeout=180)
 site=next(s['id'] for s in p.api('/sites') if s['slug']==slug);v['sites'].append(site);save()
 body="require('http').createServer((q,r)=>{let ok=false;try{ok=require('./node_modules/is-number')('42')}catch{};r.end(JSON.stringify({value:process.env.QA_SECRET||'',empty:process.env.QA_EMPTY===undefined?null:process.env.QA_EMPTY,dependency:ok,uid:process.getuid(),groups:process.getgroups()}))}).listen(Number(process.env.PORT),process.env.HOST);console.log('pm2-deployment-ready');"
 write('app.js',body);secret=uuid.uuid4().hex
 app=module('create',resource_id=v['app'],site_id=site,entry='app.js',port=22456,environment_patch={'QA_SECRET':secret,'QA_EMPTY':''})['app'];created=True
 assert app['revision']==1 and app['environment_keys']==['QA_EMPTY','QA_SECRET']
 assert request()['value']==secret and request()['empty']=='' and request()['uid']>0 and 0 not in request()['groups']
 assert request()['dependency'] is False
 raw=p.vm('sudo','cat','/etc/panel/security-apps/modules/pm2-manager/apps/'+v['app']+'.json').stdout
 assert secret not in raw and 'environment_cipher' in raw
 assert secret not in json.dumps(module()) and secret not in json.dumps(p.api('/app-modules/pm2-manager'))
 new_secret=uuid.uuid4().hex
 updated=module('update',resource_id=v['app'],expected_revision=1,environment_patch={'QA_SECRET':new_secret,'QA_EMPTY':None})['app']
 assert updated['revision']==2 and request()['value']==new_secret and request()['empty'] is None
 rejected(lambda:module('update',resource_id=v['app'],expected_revision=1,environment_patch={'QA_SECRET':'stale'}))
 rejected(lambda:module('update',resource_id=v['app'],expected_revision=2,environment_patch={'NODE_OPTIONS':'--require /evil'}))
 write('bad.js',"throw new Error('controlled startup failure');")
 rejected(lambda:module('update',resource_id=v['app'],expected_revision=2,entry='bad.js',environment_patch={'QA_SECRET':'failed-update'}))
 current=next(x['app'] for x in module()['apps'] if x['app']['id']==v['app'])
 assert current==updated and request()['value']==new_secret
 passed('real Node environment patch/deletion, encrypted private manifest, write-only API, reserved/stale rejection and failed-start secret rollback')
 package={'name':'qa-pm2-deployment','version':'1.0.0','private':True,'dependencies':{'is-number':'7.0.0'},'scripts':{'postinstall':'node -e "require(\'fs\').writeFileSync(\'HOOK-RAN\',\'bad\')"'}}
 lock={'name':package['name'],'version':'1.0.0','lockfileVersion':3,'requires':True,'packages':{'':{'name':package['name'],'version':'1.0.0','dependencies':package['dependencies']},'node_modules/is-number':{'version':'7.0.0','resolved':'https://registry.npmjs.org/is-number/-/is-number-7.0.0.tgz','integrity':'sha512-41Cifkg6e8TylSpdtTpeLVMqvSBEVzTttHvERD741+pnZ8ANv0004MRL43QKPDlK9cGvNp6NZWZUBlbGXYxxng=='}}}
 write('package.json',json.dumps(package));write('package-lock.json',json.dumps(lock))
 queued=module('dependencies',resource_id=v['app'],expected_revision=2)['deployment'];v['deployment']=queued['id'];save()
 assert queued['state']=='queued' and 'package' not in queued and 'lock' not in queued
 assert request()['value']==new_secret
 done=wait_deployment('succeeded');assert request()['dependency'] and request()['value']==new_secret
 stage_path='/srv/panel/sites/'+site+'/private/pm2-deploy-'+done['id']
 assert p.vm('sudo','test','-e',stage_path+'/HOOK-RAN',check=False).returncode!=0
 assert p.vm('sudo','test','-e',stage_path+'/node_modules/.package-lock.json',check=False).returncode!=0
 assert 0 not in request()['groups']
 assert new_secret not in json.dumps(p.api('/app-modules/pm2-manager/history'))
 passed('real asynchronous public npm tarball install, SHA-512 verification, no lifecycle hook, preserved secret and actual application require')
 old_inode=p.vm('sudo','stat','-c','%d:%i','/srv/panel/sites/'+site+'/public/node_modules').stdout
 bad=copy.deepcopy(lock);bad['packages']['node_modules/is-number']['integrity']='sha512-'+'A'*86+'=='
 write('package-lock.json',json.dumps(bad));module('dependencies',resource_id=v['app'],expected_revision=2)
 failed=wait_deployment('failed');assert request()['dependency'] and request()['value']==new_secret
 assert p.vm('sudo','stat','-c','%d:%i','/srv/panel/sites/'+site+'/public/node_modules').stdout==old_inode
 passed('actual integrity-failed npm job leaves running service and exact previous dependency directory intact')

 # A valid npm installation can still break application startup. The new
 # empty dependency set must be rolled back after a real Node require error.
 write('app.js',"require('./node_modules/is-number');"+body);module('restart',resource_id=v['app'])
 empty_package=copy.deepcopy(package);empty_package['dependencies']={}
 empty_lock=copy.deepcopy(lock);empty_lock['packages']={'':{'name':package['name'],'version':'1.0.0'}}
 write('package.json',json.dumps(empty_package));write('package-lock.json',json.dumps(empty_lock))
 module('dependencies',resource_id=v['app'],expected_revision=2)
 failed_start=wait_deployment('failed');assert request()['dependency'] and request()['value']==new_secret
 assert p.vm('sudo','stat','-c','%d:%i','/srv/panel/sites/'+site+'/public/node_modules').stdout==old_inode
 assert '新依赖启动失败' in failed_start['error']
 assert p.vm('sudo','test','-d','/srv/panel/sites/'+site+'/private/pm2-deploy-'+failed_start['id']+'/failed-node_modules').returncode==0
 passed('real successful npm ci followed by broken Node startup restores exact old dependencies and running HTTP service; failed set retained')

 write('package.json',json.dumps(package))
 invalid=copy.deepcopy(lock);invalid['packages']['node_modules/is-number']['resolved']='https://secret:credential@registry.npmjs.org/x.tgz'
 write('package-lock.json',json.dumps(invalid));rejected(lambda:module('dependencies',resource_id=v['app'],expected_revision=2))
 assert deployment()==failed_start
 passed('credential-bearing/custom sources rejected without replacing previous deployment record')
 write('package-lock.json',json.dumps(lock))
 # Hold only the next QA dependency worker at its systemd startup boundary.
 # No actual package hooks or arbitrary API shell commands are involved.
 override='/etc/systemd/system/panel-pm2-deploy@.service.d/zz-qa-deployment-delay.conf'
 assert p.vm('sudo','test','-e',override,check=False).returncode!=0,'An existing QA delay override must be inspected first'
 own_override=False
 try:
  p.vm('sudo','install','-d','-m','0755','/etc/systemd/system/panel-pm2-deploy@.service.d')
  guest_root=os.environ.get('PANEL_GUEST_PROJECT_ROOT','/workspace')
  p.vm('sudo','install','-m','0644',guest_root+'/dev/qa-pm2-deployment-delay.conf',override);own_override=True
  p.vm('sudo','systemctl','daemon-reload')
  queued=module('dependencies',resource_id=v['app'],expected_revision=2)['deployment']
  rejected(lambda:module('update',resource_id=v['app'],expected_revision=2,instances=2))
  rejected(lambda:module('dependencies',resource_id=v['app'],expected_revision=2))
  assert request()['dependency'] and request()['value']==new_secret
  recovered=module('cancel-deployment',resource_id=v['app'])['deployment']
  assert recovered['id']==queued['id'] and recovered['state']=='failed'
  assert request()['dependency'] and request()['value']==new_secret
  assert p.vm('sudo','stat','-c','%d:%i','/srv/panel/sites/'+site+'/public/node_modules').stdout==old_inode
  passed('actual pending systemd deployment prevents concurrent edits/duplicate jobs; cancellation recovers record without disturbing running application')
 finally:
  if own_override:p.vm('sudo','mv',override,'/var/lib/panel-executor/qa-pm2-delay-'+uuid.uuid4().hex+'.conf')
  p.vm('sudo','systemctl','daemon-reload')
 module('stop',resource_id=v['app']);module('start',resource_id=v['app']);assert request()['value']==new_secret and request()['dependency']
 passed('actual service restart retains encrypted environment and deployed dependencies')

 package['scripts']['postinstall']='node -e "require(\'fs\').writeFileSync(\'HOOK-RAN\',JSON.stringify({uid:process.getuid(),groups:process.getgroups(),secret:process.env.QA_SECRET||null}))"'
 write('package.json',json.dumps(package));module('dependencies',resource_id=v['app'],expected_revision=2,allow_install_scripts=True)
 built=wait_deployment('succeeded');assert built['allow_install_scripts'] is True
 hook=json.loads(p.vm('sudo','cat','/srv/panel/sites/'+site+'/private/pm2-deploy-'+built['id']+'/HOOK-RAN').stdout)
 assert hook['uid']==request()['uid'] and 0 not in hook['groups'] and hook['secret'] is None
 assert request()['value']==new_secret and request()['dependency']
 passed('explicit opt-in lifecycle build actually runs as website non-root UID, without root groups or application secrets')

 archived=module('archive-deployments',resource_id=v['app'])
 assert archived['archived']>=3 and archived['records_retained'] and archived['dependency_directories_retained']
 assert deployment()==built and request()['dependency']
 passed('finished older job records recoverably archived; latest deployment and live dependencies retained')
 v['passed']=True;save()
finally:
 if created:
  try:module('delete',resource_id=v['app'])
  except RuntimeError:
   module('cancel-deployment',resource_id=v['app']);module('delete',resource_id=v['app'])
 for id in v['sites']:
  own=next((s for s in p.api('/sites') if s['id']==id),None)
  if own:
   assert own['slug'].startswith('pm2-deploy-') and own['domain']==own['slug']+'.example.test'
   p.wait(p.api('/sites/'+id,{'confirm_domain':own['domain']},method='DELETE')['job_id'],timeout=180)
 v['cleaned_up']=True;save();p.close()
