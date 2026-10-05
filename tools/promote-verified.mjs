import {readFile,writeFile} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
import {pretty} from './lib.mjs';
const root=fileURLToPath(new URL('..',import.meta.url));
const panel=path.resolve(root,'../panel');
const registry=JSON.parse(await readFile(path.join(root,'registry/apps.json'),'utf8'));
const modules=JSON.parse(await readFile(path.join(panel,'.local/app-modules-acceptance.json'),'utf8'));
const matrix=JSON.parse(await readFile(path.join(panel,'.local/app-compose-matrix-acceptance.json'),'utf8'));
const go=await readFile(path.join(panel,'internal/core/app_compose_templates.go'),'utf8');
const images=Object.fromEntries([...go.matchAll(/"(php-legacy-\d+)":\s*"([^"]+)"/g)].map(v=>[v[1],v[2]]));
const capabilities={
 'pure-ftpd':['强制 TLS','虚拟账号','网站 chroot','上传下载','回环监听'],
 'site-diagnosis':['DNS 检查','HTTP 检查','TLS 检查','Nginx 配置检查'],
 'network-threat-detection':['监听端口基线','新增监听告警','实时连接','Fail2ban 状态'],
 'website-analytics':['PV 与独立 IP','状态码','小时趋势','热门路径','爬虫识别','来源统计'],
 'files-sync':['增量同步','SHA-256 校验','目标冲突保护','逐文件检查点','隔离 PHP 网站部署'],
 'daily-report':['资源摘要','任务故障摘要','流量与安全摘要','证书到期检查','每日持久化'],
 'website-statistics-v2':['小时趋势','独立 IP','爬虫识别','错误数','路径排行','来源统计'],
 'enterprise-tamper-proof':['HMAC 签名基线','内容备份','变更检测','分钟级自动恢复','恢复前留存'],
 'load-balance':['加权轮询','备用节点','IP 粘滞','节点探测','失败转移'],
 'mobile-pwa':['PWA','响应式界面','现有 TOTP 登录','不缓存 API 或凭据'],
 'apache-waf':['请求 URI 特征过滤','扫描器拦截','Apache 语法校验','失败回滚'],
 'php-code-security':['静态扫描','高风险函数','编码混淆特征','证据行号'],
 'task-manager':['实时进程','CPU 与内存','网络连接','受管非 root 进程终止'],
 'website-tamper-proof':['签名文件基线','变更事件','备份恢复','网站级策略'],
 'user-manager':['多用户','三种角色','网站权限范围','会话撤销','保留最后管理员'],
 'file-monitor':['哈希检查点','变更检测','权限变化','排除规则'],
 'disk-analysis':['目录体积','大文件排行','文件数量','有界扫描'],
 'platform-ops':['多主机 HTTPS 健康聚合','只读令牌','加密凭据','令牌撤销'],
 'nfs-manager':['NFSv4','安全挂载选项','开机恢复','活跃挂载卸载保护'],
 'pm2-manager':['实际 PM2','非 root 进程','日志','启停重启','开机恢复'],
 'openlitespeed':['HTTP 网站','LSAPI','随机管理密码','回环 HTTPS 管理','持久配置'],
};
for(const app of registry.apps){
 const id=app.id==='mobile'?'mobile-pwa':app.id;
 if(modules.checks[id]&&!String(modules.checks[id]).includes('待独立补测')){
  app.stage='ready';app.delivery={provider:'panel-module',target:id,manage_route:'app-modules'};
  app.health={probe:'panel-api',target:'/api/app-modules/'+id};
  if(capabilities[id])app.capabilities=capabilities[id];
  app.summary=modules.checks[id];app.compatibility={os:['debian-13'],architectures:['amd64']};
  if(id==='pure-ftpd')app.version='1.0.50';if(id==='pm2-manager')app.version='7.0.4';
 }
 if(app.id.startsWith('php-')&&Number(app.id.slice(4))<=81){
  const target='php-legacy-'+app.id.slice(4),proof=matrix.apps[target];
  app.delivery={provider:'compose',target,image:images[target],manage_route:'docker',isolation:'legacy-container'};
  app.compatibility={os:['debian-13'],architectures:['amd64']};app.risk='eol';
  app.summary='停止官方维护的旧版 PHP：固定摘要 PHP-FPM，独立命名卷与只读文件系统；经文件同步部署并绑定受管域名。仅用于兼容迁移。';
  app.capabilities=['固定镜像摘要','独立 PHP-FPM','独立 Nginx','网站同步部署','域名绑定','数据卷持久化'];
  app.health={probe:'http',target:'/.__cloudstack_health'};
  if(proof?.passed&&proof.real_site_deployment&&proof.domain_binding){app.stage='ready';app.version=proof.version;}
 }
 if(['rabbitmq','openlitespeed'].includes(id)&&matrix.apps[id]?.passed){app.stage='ready';if(capabilities[id])app.capabilities=capabilities[id];app.compatibility={os:['debian-13'],architectures:['amd64']};}
}
registry.generated_at=new Date().toISOString();
await writeFile(path.join(root,'registry/apps.json'),pretty(registry));
console.log('verified ready applications:',registry.apps.filter(v=>v.stage==='ready').length);
