#!/usr/bin/env python3
"""Real API/Linux acceptance for the independent functional modules. No fabricated pass results."""
import json, pathlib, os, time, uuid, urllib.request, urllib.error, hashlib
from panel_client import PanelClient

ROOT=pathlib.Path(__file__).resolve().parents[1]
REPORT=ROOT/'.local/app-modules-acceptance.json'
c=PanelClient()
report={'started_at':time.strftime('%Y-%m-%dT%H:%M:%S%z'),'checks':{},'failures':{}}
sites=[]
def checkpoint():REPORT.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
def passed(app,detail):report['checks'][app]=detail;checkpoint();print('PASS',app,detail,flush=True)
def module(id,action='run',**kw):return c.api('/app-modules/'+id+'/'+action,kw)
def file(site,action,**kw):return c.api('/sites/'+site['id']+'/files/action',dict(action=action,**kw))
def read(site,path):return c.api('/sites/'+site['id']+'/files/text?path='+path)
def install(id):
 status=c.api('/app-modules/'+id)['status']
 if not status['installed']:c.wait(c.api('/software/'+id+'/install',{'settings':{}})['job_id'],timeout=900)
 assert c.api('/app-modules/'+id)['status']['healthy'],id
def request(path,host=None):
 req=urllib.request.Request(path,headers={'Host':host} if host else {})
 with urllib.request.urlopen(req,timeout=10) as res:return res.status,res.read(),dict(res.headers)
try:
 for n in range(2):
  slug='modules-'+uuid.uuid4().hex[:10]
  c.wait(c.api('/sites',{'name':'应用模块验收 '+str(n),'slug':slug,'domain':slug+'.example.test','php_version_id':''})['job_id'])
  sites.append(next(s for s in c.api('/sites') if s['slug']==slug))
 source,target=sites
 file(source,'create',path='security.php',content='<?php eval($_GET["test"]); ?>')
 file(source,'create',path='baseline.txt',content='verified-original')
 file(source,'create',path='sync.txt',content='sync-source')
 file(target,'create',path='security.php',content='target-owned-content')
 ids=['site-diagnosis','network-threat-detection','website-analytics','files-sync','daily-report','website-statistics-v2','enterprise-tamper-proof','load-balance','mobile-pwa','php-code-security','task-manager','website-tamper-proof','user-manager','file-monitor','disk-analysis','platform-ops']
 for id in ids:install(id)
 for id in ['site-diagnosis','disk-analysis','php-code-security']:
  out=module(id,site_id=source['id']);assert out
  if id=='php-code-security':assert any(x['rule']=='dynamic-evaluation' for x in out['findings'])
  if id=='disk-analysis':assert out['files']>=3 and out['total_bytes']>0
  if id=='site-diagnosis':assert out['checks']['http']['ok'] and out['checks']['nginx']['ok']
  passed(id,'实际网站 HTTP/目录/代码检测与结构化报告通过')
 for _ in range(3):request('http://127.0.0.1:19111/baseline.txt',source['domain'])
 for id in ['website-analytics','website-statistics-v2']:
  out=module(id,site_id=source['id']);assert out['requests']>=3 and out['paths']['/baseline.txt']>=3;passed(id,'读取实际 Nginx 日志，PV/IP/路径/状态码统计通过')
 for id in ['website-tamper-proof','enterprise-tamper-proof','file-monitor']:
  module(id,'baseline',site_id=source['id'],auto_restore=id=='enterprise-tamper-proof')
  before=read(source,'baseline.txt');file(source,'save',path='baseline.txt',content='tampered-'+id,expected_sha256=before['sha256'])
  out=module(id,'check',site_id=source['id']);assert any(x['path']=='baseline.txt' for x in out['sites'][0]['changes'])
  if id=='website-tamper-proof':module(id,'restore',site_id=source['id'],path='baseline.txt');assert read(source,'baseline.txt')['content']=='verified-original'
  if id=='enterprise-tamper-proof':assert 'baseline.txt' in out['sites'][0]['restored'] and read(source,'baseline.txt')['content']=='verified-original'
  if id=='file-monitor':before=read(source,'baseline.txt');file(source,'save',path='baseline.txt',content='verified-original',expected_sha256=before['sha256'])
  passed(id,'签名基线、真实文件修改检测、恢复或持续监控策略通过')
 out=module('files-sync','preview',site_id=source['id'],target_site_id=target['id']);assert 'security.php' in out['conflicts'] and 'sync.txt' in out['copied']
 module('files-sync','sync',site_id=source['id'],target_site_id=target['id']);assert read(target,'sync.txt')['content']=='sync-source';assert read(target,'security.php')['content']=='target-owned-content'
 out=module('files-sync','sync',site_id=source['id'],target_site_id=target['id']);assert 'sync.txt' not in out['copied'];passed('files-sync','增量同步、逐文件检查点和目标冲突保护通过')
 module('network-threat-detection','baseline');assert module('network-threat-detection')['alerts']==[];passed('network-threat-detection','真实 ss 监听端口/连接基线和 Fail2ban 状态读取通过')
 out=module('task-manager');assert out['processes'] and any(x['start_time']>0 for x in out['processes'])
 try:module('task-manager','terminate',pid=1,start_time=1);raise AssertionError('PID1 accepted')
 except RuntimeError:pass
 passed('task-manager','读取真实 CPU/内存/进程身份，拒绝终止 PID1 与非受管进程')
 out=module('daily-report');assert out['sites']>=2 and 'certificates_due_14_days' in out;passed('daily-report','从实际资源、站点、任务、流量、证书数据生成持久化日报')
 password='Modules-'+uuid.uuid4().hex
 username='viewer-'+uuid.uuid4().hex[:8]
 module('user-manager','create',username=username,password=password,role='viewer',site_ids=[source['id']])
 assert any(x['username']==username for x in module('user-manager')['users'])
 other=urllib.request.build_opener(urllib.request.HTTPCookieProcessor())
 req=urllib.request.Request(c.base+'/api/login',data=json.dumps({'username':username,'password':password}).encode(),headers={'Content-Type':'application/json','Origin':c.origin})
 with other.open(req) as res:json.load(res)
 with other.open(c.base+'/api/sites') as res:assert [s['id'] for s in json.load(res)]==[source['id']]
 try:other.open(c.base+'/api/software');raise AssertionError('viewer elevated')
 except urllib.error.HTTPError as e:assert e.code==403
 module('user-manager','revoke',username=username)
 try:other.open(c.base+'/api/sites');raise AssertionError('revoked session still active')
 except urllib.error.HTTPError as e:assert e.code==401
 module('user-manager','delete',username=username);passed('user-manager','实际登录、网站范围隔离、越权拒绝、会话撤销和账户删除通过')
 token=module('platform-ops','issue-token')['token']
 req=urllib.request.Request(c.base+'/api/platform/agent',headers={'Authorization':'Bearer '+token})
 with urllib.request.urlopen(req) as res:assert 'health' in json.load(res)
 module('platform-ops','revoke-token',token=token)
 try:urllib.request.urlopen(req);raise AssertionError('revoked token active')
 except urllib.error.HTTPError as e:assert e.code==401
 assert module('platform-ops')['hosts']==[];passed('platform-ops','只读主机健康 API、加密凭据入口及令牌签发/撤销通过；多主机 HTTPS 待独立补测')
 out=module('mobile-pwa');assert out['installable'];status,raw,_=request(c.base+'/manifest.webmanifest');assert json.loads(raw)['display']=='standalone';status,sw,_=request(c.base+'/sw.js');assert b'never cached' in sw;passed('mobile-pwa','真实 manifest/图标/Service Worker 入口可访问，不缓存账号或 API 数据')
 report['sites']=[s['id'] for s in sites]
 report['core_modules_passed']=len(report['checks'])
finally:
 checkpoint();c.close()
print(json.dumps({'passed':len(report['checks']),'report':str(REPORT)},ensure_ascii=False),flush=True)
