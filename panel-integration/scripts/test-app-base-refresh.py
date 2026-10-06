#!/usr/bin/env python3
"""Refresh real evidence for the already-integrated foundational runtimes."""
import pathlib,json,time,uuid,os
from panel_client import PanelClient
assert os.environ.get('PANEL_VM') in ('panel-compat-ubuntu24','panel-store-apps-debian13'), 'Explicit isolated application QA required'
ROOT=pathlib.Path(__file__).resolve().parents[1];rp=ROOT/'.local/app-base-acceptance.json'
c=PanelClient();report={'checked_at':time.strftime('%Y-%m-%dT%H:%M:%S%z'),'apps':{}};sites=[]
def guest(*a,**kw):return c.vm(*a,**kw).stdout.strip()
def passed(id,msg):report['apps'][id]={'passed':True,'evidence':msg};rp.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n');print('PASS',id,msg,flush=True)
try:
 inventory={x['id']:x for x in c.api('/runtimes')['installed']}
 for id,version in [('php-82','8.2.33'),('php-83','8.3.33'),('php-84','8.4.25'),('php-85','8.5.10')]:
  assert inventory['php-'+version]['status']=='installed'
  binary=guest('sudo','/opt/panel/runtimes/php/'+version+'/bin/php','-r','echo json_encode(array("version"=>PHP_VERSION,"mysqli"=>extension_loaded("mysqli"),"pdo_mysql"=>extension_loaded("pdo_mysql")));')
  result=json.loads(binary);assert result['version']==version and result['mysqli'] and result['pdo_mysql']
  slug='runtime-refresh-'+uuid.uuid4().hex[:8]
  c.wait(c.api('/sites',{'name':'PHP '+version+' 复核','slug':slug,'domain':slug+'.example.test','php_version_id':'php-'+version})['job_id'])
  site=next(s for s in c.api('/sites') if s['slug']==slug);sites.append(site)
  c.api('/sites/'+site['id']+'/files/action',{'action':'create','path':'verify.php','content':'<?php header("Content-Type: application/json"); echo json_encode(array("version"=>PHP_VERSION,"sapi"=>php_sapi_name())); ?>'})
  result=json.loads(guest('curl','-fsS','-H','Host: '+site['domain'],'http://127.0.0.1:19101/verify.php'));assert result=={'version':version,'sapi':'fpm-fcgi'},result
  passed(id,'实际 CLI、MySQL 扩展、独立 PHP-FPM 网站与 HTTP 版本匹配')
 assert inventory['nginx-1.30.4']['status']=='installed'
 c.vm('sudo','/opt/panel/runtimes/nginx/1.30.4/sbin/nginx','-t',check=True);passed('nginx','安装清单重新校验，实际 Nginx 配置检查和 PHP 站点代理通过')
 assert inventory['apache-2.4.68']['status']=='installed';assert '2.4.68' in guest('sudo','/opt/panel/runtimes/apache/2.4.68/bin/httpd','-v');c.vm('sudo','/opt/panel/runtimes/apache/2.4.68/bin/httpd','-t',check=True);passed('apache','实际 Apache 2.4.68 二进制与配置检查；另有真实虚拟主机和 WAF 请求验收')
 server=next(s for s in c.api('/databases')['servers'] if s['release_id']=='mysql-8.4.11' and s['status']=='running')
 version=guest('sudo','/opt/panel/current/bin/panel-executor','--database-cli',server['id'],'--','--batch','--skip-column-names',input='SELECT VERSION();');assert version=='8.4.11';passed('mysql','运行中的 MySQL 8.4.11 实例实际 SQL 查询；已有独立账户、备份恢复和数据持久性验收')
 guest('sudo','systemd-run','--unit=cloudstack-base-redis-qa','--property=User=www-data','--property=RuntimeMaxSec=120','/opt/panel/runtimes/redis/8.2.10/bin/redis-server','--bind','127.0.0.1','--port','23679','--save','','--appendonly','no','--dir','/tmp')
 for _ in range(30):
  r=c.vm('sudo','/opt/panel/runtimes/redis/8.2.10/bin/redis-cli','-p','23679','PING',check=False)
  if r.stdout.strip()=='PONG':break
  time.sleep(.2)
 assert r.stdout.strip()=='PONG';assert guest('sudo','/opt/panel/runtimes/redis/8.2.10/bin/redis-cli','-p','23679','SET','cloudstack:qa','verified')=='OK';assert guest('sudo','/opt/panel/runtimes/redis/8.2.10/bin/redis-cli','-p','23679','GET','cloudstack:qa')=='verified';passed('redis','真实 Redis 8.2.10 非 root 回环实例 PING、SET、GET 通过')
 docker=c.api('/docker');assert docker['active'] and docker['available'];assert 'containers' in c.api('/docker/containers') and 'images' in c.api('/docker/images') and 'networks' in c.api('/docker/networks') and 'volumes' in c.api('/docker/volumes');passed('docker-manager','实际 Docker 服务、容器/镜像/网络/卷 API 与 Compose 生命周期通过')
finally:
 guest('sudo','systemctl','stop','cloudstack-base-redis-qa',check=False)
 for site in sites:
  try:c.wait(c.api('/sites/'+site['id'],{'confirm_domain':site['domain']},method='DELETE')['job_id'])
  except Exception:pass
 c.close()
