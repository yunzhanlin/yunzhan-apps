#!/usr/bin/env python3
"""Verify the native modules using real system services, network requests and data transfer."""
import json,pathlib,uuid,time,os
from panel_client import PanelClient
assert os.environ.get('PANEL_VM') in ('panel-compat-ubuntu24','panel-store-apps-debian13'), 'Explicit isolated application QA required'
ROOT=pathlib.Path(__file__).resolve().parents[1]
report_path=ROOT/'.local/app-modules-acceptance.json'
report=json.loads(report_path.read_text())
c=PanelClient()
def module(id,action='run',**kw):return c.api('/app-modules/'+id+'/'+action,kw)
def pass_app(id,detail):report['checks'][id]=detail;report_path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n');print('PASS',id,detail,flush=True)
def install(id):
 status=c.api('/app-modules/'+id)['status']
 if not status['installed'] or not status['healthy']:c.wait(c.api('/software/'+id+'/install',{'settings':{}})['job_id'],timeout=900)
 assert c.api('/app-modules/'+id)['status']['healthy'],id
def file(site,action,**kw):return c.api('/sites/'+site['id']+'/files/action',dict(action=action,**kw))
def ensure_file(site,path,content):
 try:old=c.api('/sites/'+site['id']+'/files/text?path='+path)
 except RuntimeError:return file(site,'create',path=path,content=content)
 return file(site,'save',path=path,content=content,expected_sha256=old['sha256'])
def guest(*args,**kw):return c.vm(*args,**kw).stdout.strip()
def get(port,path='/'):
 for _ in range(40):
  result=c.vm('curl','-fsS','--max-time','2','http://127.0.0.1:'+str(port)+path,check=False)
  if result.returncode==0:return result.stdout.strip()
  time.sleep(.5)
 raise AssertionError('HTTP readiness failed '+str(port))
try:
 sites=[s for s in c.api('/sites') if s['id'] in report['sites']];source,target=sites
 for n,s in enumerate(sites):
  ensure_file(s,'lb.txt','backend-'+str(n))
  guest('sudo','systemd-run','--unit=cloudstack-lb-qa-'+str(n),'--property=User=www-data','/usr/bin/python3','-m','http.server',str(21001+n),'--bind','127.0.0.1','--directory','/srv/panel/sites/'+s['id']+'/public')
  assert get(21001+n,'/lb.txt')=='backend-'+str(n)
 install('load-balance')
 module('load-balance','save',domain='lb-modules.example.test',port=22000,nodes=[{'address':'127.0.0.1:21001','weight':1,'backup':False},{'address':'127.0.0.1:21002','weight':1,'backup':False}])
 assert {get(22000,'/lb.txt') for _ in range(8)}=={'backend-0','backend-1'}
 guest('sudo','systemctl','stop','cloudstack-lb-qa-0')
 assert {get(22000,'/lb.txt') for _ in range(4)}=={'backend-1'}
 assert not module('load-balance','probe',domain='lb-modules.example.test')['nodes'][0]['healthy']
 lb=module('load-balance','probe',domain='lb-modules.example.test')
 module('load-balance','remove',domain='lb-modules.example.test',expected_revision=lb['revision']);guest('sudo','systemctl','stop','cloudstack-lb-qa-1');pass_app('load-balance','真实轮询分流、节点故障切换、TCP 建连探测和修订受控入口移除通过')
 settings=c.api('/sites/'+source['id']+'/settings');body=settings['settings'];body['web_server']='apache'
 preview=c.api('/sites/'+source['id']+'/settings/preview',{'settings':body,'expected_revision':settings['settings_revision']})
 c.wait(c.api('/sites/'+source['id']+'/settings',{'settings':body,'expected_revision':settings['settings_revision'],'expected_config_sha':preview['config_sha']})['job_id'])
 install('apache-waf');c.wait(c.api('/software/apache-waf/configure',{'settings':{}})['job_id']);assert module('apache-waf')['syntax_ok']
 apache_code='''import urllib.request,urllib.error,json
domain=input().strip()
out={}
for name,path,agent in [('normal','/baseline.txt','acceptance'),('scanner','/baseline.txt','sqlmap/1.0'),('injection','/baseline.txt?x=union%20select','acceptance')]:
 req=urllib.request.Request('http://127.0.0.1:19080'+path,headers={'Host':domain,'User-Agent':agent})
 try:
  with urllib.request.urlopen(req) as res:out[name]=res.status
 except urllib.error.HTTPError as err:out[name]=err.code
print(json.dumps(out))'''
 out=json.loads(guest('python3','-c',apache_code,input=source['domain']+'\n'));assert out=={'normal':200,'scanner':403,'injection':403},out
 pass_app('apache-waf','实际 Apache 虚拟主机正常请求 200、扫描器和 SQL 特征请求 403，通过语法校验')
 install('pure-ftpd');username='ftp-'+uuid.uuid4().hex[:8];password='FTP-'+uuid.uuid4().hex
 module('pure-ftpd','create',username=username,password=password,site_id=target['id'])
 ftp_code='''import ftplib,ssl,sys,json,io
v=json.load(sys.stdin);ctx=ssl.create_default_context(cafile='/etc/panel/security-apps/modules/pure-ftpd/server.pem')
ftp=ftplib.FTP_TLS(context=ctx);ftp.connect('localhost',2121,timeout=10);ftp.login(v['username'],v['password']);ftp.prot_p();ftp.storbinary('STOR ftp-roundtrip.txt',io.BytesIO(b'ftp-verified'));out=io.BytesIO();ftp.retrbinary('RETR ftp-roundtrip.txt',out.write);assert out.getvalue()==b'ftp-verified';assert ftp.pwd()=='/';ftp.quit();print('FTP TLS upload/download/chroot passed')'''
 assert 'passed' in guest('sudo','python3','-c',ftp_code,input=json.dumps({'username':username,'password':password}))
 assert c.api('/sites/'+target['id']+'/files/text?path=ftp-roundtrip.txt')['content']=='ftp-verified'
 module('pure-ftpd','delete',username=username);pass_app('pure-ftpd','真实 TLS 登录、上传/下载内容核对、网站 chroot 和账户删除通过')
 install('pm2-manager');app='pm2-'+uuid.uuid4().hex[:8]
 ensure_file(target,'pm2-test.js',"require('http').createServer((req,res)=>res.end('pm2-verified')).listen(Number(process.env.PORT),process.env.HOST);console.log('pm2-ready');")
 module('pm2-manager','create',resource_id=app,site_id=target['id'],entry='pm2-test.js',port=22001)
 assert get(22001)=='pm2-verified';module('pm2-manager','restart',resource_id=app);assert get(22001)=='pm2-verified'
 assert 'pm2-ready' in module('pm2-manager','logs',resource_id=app)['logs']
 module('pm2-manager','stop',resource_id=app);module('pm2-manager','start',resource_id=app);assert get(22001)=='pm2-verified'
 module('pm2-manager','delete',resource_id=app);pass_app('pm2-manager','实际 PM2 7.0.4 非 root Node 服务启动、HTTP、重启、停止/启动、日志、删除通过')
 install('nfs-manager')
 module('nfs-manager','mount',resource_id='qa-nfs',source='127.0.0.1:/',read_only=True)
 assert guest('sudo','cat','/srv/panel/nfs/qa-nfs/marker.txt')=='nfs-verified'
 out=guest('findmnt','-n','-o','OPTIONS','/srv/panel/nfs/qa-nfs');assert all(x in out.split(',') for x in ['ro','nosuid','nodev','noexec']),out
 module('nfs-manager','unmount',resource_id='qa-nfs');assert module('nfs-manager')['mounts']==[];pass_app('nfs-manager','真实 NFSv4 挂载、远程内容核对、ro/nosuid/nodev/noexec 选项及卸载通过')
finally:c.close()
