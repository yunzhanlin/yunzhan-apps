#!/usr/bin/env python3
"""Two-phase whole-VM reboot proof. Uses only this task's retained QA sites."""
import json,pathlib,time,uuid,sys,os
from panel_client import PanelClient
assert os.environ.get('PANEL_VM') in ('panel-compat-ubuntu24','panel-store-apps-debian13'), 'Explicit isolated application QA required'
root=pathlib.Path(__file__).resolve().parents[1];state=root/'.local/app-reboot-private.json';result=root/'.local/app-reboot-acceptance.json'
c=PanelClient()
def module(id,action='run',**values):return c.api('/app-modules/'+id+'/'+action,values)
def guest(*args,**kw):return c.vm(*args,**kw).stdout.strip()
def http():
 for _ in range(60):
  value=c.vm('curl','-fsS','--max-time','2','http://127.0.0.1:22011',check=False)
  if value.returncode==0:return json.loads(value.stdout)
  time.sleep(1)
 raise AssertionError('PM2 did not resume')
try:
 if sys.argv[1]=='prepare':
  assert not state.exists(),'Reboot fixture already exists; inspect before preparing another'
  sites=json.loads((root/'.local/app-modules-acceptance.json').read_text())['sites'];site=sites[-1];app='qa-boot-'+uuid.uuid4().hex[:8]
  entry='qa-reboot.js';content="const child=require('child_process').spawn('/usr/bin/sleep',['300']);require('http').createServer((req,res)=>{res.setHeader('Content-Type','application/json');res.end(JSON.stringify({marker:'reboot-verified',pid:process.pid,child:child.pid}))}).listen(Number(process.env.PORT),process.env.HOST);"
  c.api('/sites/'+site+'/files/action',{'action':'create','path':entry,'content':content})
  module('pm2-manager','create',resource_id=app,site_id=site,entry=entry,port=22011)
  value=http();assert value['marker']=='reboot-verified';pid=value['child']
  start=int(guest('python3','-c','import sys,pathlib;pid=json_input=int(sys.stdin.read());print(pathlib.Path("/proc/"+str(pid)+"/stat").read_text().split()[21])',input=str(pid)))
  try:module('task-manager','terminate',pid=pid,start_time=start+1)
  except RuntimeError:pass
  else:raise AssertionError('Changed PID identity not rejected')
  assert module('task-manager','terminate',pid=pid,start_time=start)['signal']=='SIGTERM'
  time.sleep(.5);assert guest('python3','-c','import sys,pathlib;print(pathlib.Path("/proc/"+sys.stdin.read()).exists())',input=str(pid))=='False'
  module('nfs-manager','mount',resource_id='qa-reboot-nfs',source='127.0.0.1:/',read_only=True)
  username='boot-'+uuid.uuid4().hex[:8];password='FTP-'+uuid.uuid4().hex
  module('pure-ftpd','create',username=username,password=password,site_id=site)
  before=guest('cat','/proc/sys/kernel/random/boot_id')
  state.write_text(json.dumps({'app':app,'site':site,'username':username,'password':password,'boot_id':before,'pid_identity_refusal':True,'actual_sigterm':True}));state.chmod(0o600)
  print('PREPARED managed process SIGTERM, PM2, NFS and FTP restart fixtures',flush=True)
 else:
  v=json.loads(state.read_text());assert guest('cat','/proc/sys/kernel/random/boot_id')!=v['boot_id'],'No actual reboot occurred'
  assert http()['marker']=='reboot-verified'
  for _ in range(60):
   marker=c.vm('sudo','cat','/srv/panel/nfs/qa-reboot-nfs/marker.txt',check=False)
   if marker.returncode==0:break
   time.sleep(1)
  assert marker.stdout.strip()=='nfs-verified'
  options=guest('findmnt','-n','-o','OPTIONS','/srv/panel/nfs/qa-reboot-nfs');assert all(x in options.split(',') for x in ['ro','nosuid','nodev','noexec'])
  code='''import json,sys,ssl,ftplib
v=json.load(sys.stdin);ctx=ssl.create_default_context(cafile='/etc/panel/security-apps/modules/pure-ftpd/server.pem');ftp=ftplib.FTP_TLS(context=ctx);ftp.connect('localhost',2121,timeout=15);ftp.login(v['username'],v['password']);ftp.prot_p();assert ftp.pwd()=='/';ftp.quit();print('verified')'''
  assert 'verified' in guest('sudo','python3','-c',code,input=json.dumps({'username':v['username'],'password':v['password']}))
  ids=['pure-ftpd','pm2-manager','nfs-manager','enterprise-tamper-proof','daily-report','user-manager'];assert all(c.api('/app-modules/'+id)['status']['healthy'] for id in ids)
  module('pure-ftpd','delete',username=v['username']);module('pm2-manager','delete',resource_id=v['app']);module('nfs-manager','unmount',resource_id='qa-reboot-nfs')
  result.write_text(json.dumps({'passed':True,'whole_vm_reboot':True,'actual_sigterm':True,'pid_identity_refusal':True,'pm2_http_resumed':True,'nfs_resumed':True,'ftp_tls_login_resumed':True,'persistent_module_health':ids},indent=2)+'\n')
  state.unlink();print('PASS whole VM reboot, actual managed SIGTERM and persistent services',flush=True)
finally:c.close()
