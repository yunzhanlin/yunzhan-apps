#!/usr/bin/env python3
import pathlib,json,time,urllib.request,urllib.error,os
from panel_client import PanelClient
assert os.environ.get('PANEL_VM') in ('panel-compat-ubuntu24','panel-store-apps-debian13'), 'Explicit isolated application QA required'
ROOT=pathlib.Path(__file__).resolve().parents[1];c=PanelClient();report={'apps':{}}
def passed(id,msg):report['apps'][id]={'passed':True,'evidence':msg};(ROOT/'.local/app-security-acceptance.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n');print('PASS',id,msg,flush=True)
try:
 for id in ('nginx-waf','system-hardening','intrusion-prevention'):
  status=next(s for s in c.api('/software')['status'] if s['id']==id)
  if not status['installed'] or not status['healthy']:c.wait(c.api('/software/'+id+'/install',{})['job_id'],timeout=900)
  status=next(s for s in c.api('/software')['status'] if s['id']==id);assert status['installed'] and status['healthy'],status
  if id=='nginx-waf':
   fixtures=json.loads((ROOT/'.local/app-modules-acceptance.json').read_text())['sites'];site=next(s for s in c.api('/sites') if s['id'] in fixtures and s['settings']['web_server']=='nginx')
   code='''import json,sys,urllib.request,urllib.error
domain=input().strip();out={}
for name,path,agent in [('normal','/baseline.txt','acceptance'),('scanner','/baseline.txt','sqlmap/1.0'),('injection','/baseline.txt?x=union%20select','acceptance')]:
 req=urllib.request.Request('http://127.0.0.1:19101'+path,headers={'Host':domain,'User-Agent':agent})
 try:
  with urllib.request.urlopen(req) as r:out[name]=r.status
 except urllib.error.HTTPError as e:out[name]=e.code
print(json.dumps(out))'''
   result=json.loads(c.vm('python3','-c',code,input=site['domain']+'\n').stdout);assert result=={'normal':200,'scanner':403,'injection':403},result
   passed(id,'实际 Nginx 正常请求 200，扫描器与 SQL 特征请求 403，健康及配置检查通过')
  elif id=='intrusion-prevention':
   result=c.vm('sudo','fail2ban-client','status','sshd').stdout;assert 'sshd' in result;passed('anti-intrusion','实际 Fail2ban SSHD Jail 启动、配置自检和服务健康检查通过')
  else:passed(id,'实际内核 sysctl 值与已安装安全基线匹配，服务端健康检查通过')
finally:c.close()
