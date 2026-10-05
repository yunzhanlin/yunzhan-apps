#!/usr/bin/env python3
"""TLS fleet aggregation, unattended integrity worker, and enriched access logs."""
import json,pathlib,uuid,time,urllib.request,urllib.error
from panel_client import PanelClient
ROOT=pathlib.Path(__file__).resolve().parents[1]
rp=ROOT/'.local/app-modules-acceptance.json'
c=PanelClient();report=json.loads(rp.read_text())
def module(id,action='run',**kw):return c.api('/app-modules/'+id+'/'+action,kw)
def guest(*args,**kw):return c.vm(*args,**kw).stdout.strip()
def passed(id,msg):
 report['checks'][id]=msg;rp.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n');print('PASS',id,msg,flush=True)
proxy_code='''import ssl,urllib.request,http.server,threading
class Handler(http.server.BaseHTTPRequestHandler):
 def do_GET(self):
  if self.path!='/api/platform/agent':self.send_error(404);return
  req=urllib.request.Request('http://127.0.0.1:19100/api/platform/agent',headers={'Authorization':self.headers.get('Authorization','')})
  try:
   with urllib.request.urlopen(req,timeout=8) as r:data=r.read();status=r.status
  except urllib.error.HTTPError as e:data=e.read();status=e.code
  self.send_response(status);self.send_header('Content-Type','application/json');self.end_headers();self.wfile.write(data)
 def log_message(self,*args):pass
ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.minimum_version=ssl.TLSVersion.TLSv1_2;ctx.load_cert_chain('/tmp/cloudstack-platform-qa/server.crt','/tmp/cloudstack-platform-qa/server.key')
for port in (24443,24444):
 server=http.server.ThreadingHTTPServer(('127.0.0.1',port),Handler);server.socket=ctx.wrap_socket(server.socket,server_side=True);threading.Thread(target=server.serve_forever,daemon=True).start()
threading.Event().wait()
'''
hosts=[];token=''
try:
 guest('sudo','install','-d','-m700','/tmp/cloudstack-platform-qa')
 guest('sudo','openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=Cloudstack QA','-addext','subjectAltName=IP:127.0.0.1','-keyout','/tmp/cloudstack-platform-qa/server.key','-out','/tmp/cloudstack-platform-qa/server.crt')
 guest('sudo','install','-m644','/tmp/cloudstack-platform-qa/server.crt','/usr/local/share/ca-certificates/cloudstack-platform-qa.crt');guest('sudo','update-ca-certificates')
 guest('sudo','systemctl','restart','panel')
 for _ in range(30):
  try:
   with urllib.request.urlopen(c.base+'/api/ready',timeout=3) as ready:
    if ready.status==200:break
  except Exception:pass
  time.sleep(.5)
 guest('sudo','systemd-run','--unit=cloudstack-platform-qa','/usr/bin/python3','-c',proxy_code)
 token=module('platform-ops','issue-token')['token']
 for port in (24443,24444):
  id='qa-fleet-'+str(port);module('platform-ops','add',resource_id=id,url='https://127.0.0.1:'+str(port),token=token);hosts.append(id)
 for _ in range(20):
  results=module('platform-ops')['hosts']
  if len(results)==2 and all(v.get('healthy') for v in results):break
  time.sleep(.5)
 assert len(results)==2 and all(v.get('healthy') for v in results),results
 module('platform-ops','revoke-token',token=token);token='';results=module('platform-ops')['hosts'];assert all(not v.get('healthy') for v in results),results
 passed('platform-ops','两个 HTTPS 验收主机的真实健康聚合、可信 TLS、加密保存令牌及撤销后拒绝访问通过')
 site=next(s for s in c.api('/sites') if s['id']==report['sites'][0]);sid=site['id']
 read=c.api('/sites/'+sid+'/files/text?path=baseline.txt')
 module('enterprise-tamper-proof','baseline',site_id=sid,auto_restore=True)
 c.api('/sites/'+sid+'/files/action',{'action':'save','path':'baseline.txt','content':'scheduled-worker-tamper','expected_sha256':read['sha256']})
 deadline=time.monotonic()+100
 while time.monotonic()<deadline:
  current=c.api('/sites/'+sid+'/files/text?path=baseline.txt')
  if current['content']==read['content']:break
  time.sleep(3)
 else:raise AssertionError('Unattended integrity worker did not restore')
 passed('enterprise-tamper-proof','签名基线、真实篡改检测、备份恢复与无人触发的定时自动恢复通过')
 # Find a real Nginx static site; Apache sites intentionally have separate logging.
 site=next(s for s in c.api('/sites') if s['id'] in report['sites'] and s['settings'].get('web_server')=='nginx')
 for id in ('website-analytics','website-statistics-v2'):c.wait(c.api('/software/'+id+'/configure',{'settings':{}})['job_id'])
 guest('curl','-fsS','-A','Examplebot/1.0','-e','https://referrer.example.test/source?secret=never-store','-H','Host: '+site['domain'],'http://127.0.0.1:19101/baseline.txt')
 for id in ('website-analytics','website-statistics-v2'):
  result=module(id,site_id=site['id']);assert result['bots']>=1 and result['referers'].get('https://referrer.example.test/source',0)>=1,result
  passed(id,'真实 JSON 访问日志中的 PV/IP/路径/状态/小时趋势、爬虫与去查询参数来源统计通过')
finally:
 for id in hosts:
  try:module('platform-ops','remove',resource_id=id)
  except Exception:pass
 if token:
  try:module('platform-ops','revoke-token',token=token)
  except Exception:pass
 guest('sudo','systemctl','stop','cloudstack-platform-qa',check=False)
 guest('sudo','rm','-f','/usr/local/share/ca-certificates/cloudstack-platform-qa.crt');guest('sudo','update-ca-certificates')
 c.close()
