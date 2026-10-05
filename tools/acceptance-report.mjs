import {readFile,writeFile,mkdir} from 'node:fs/promises';
import path from 'node:path';import {fileURLToPath} from 'node:url';import {pretty} from './lib.mjs';
const root=fileURLToPath(new URL('..',import.meta.url)),panel=path.resolve(root,'../panel');
const read=async name=>JSON.parse(await readFile(path.join(panel,'.local',name),'utf8'));
const registry=JSON.parse(await readFile(path.join(root,'registry/apps.json'),'utf8'));
const releaseIndex=JSON.parse(await readFile(path.join(root,'panel-integration/source-sha256.json'),'utf8')).release;
if(!releaseIndex?.archive_sha256||!releaseIndex?.frozen_inputs_sha256)throw Error('Release source snapshot not verified');
const modules=await read('app-modules-acceptance.json'),matrix=await read('app-compose-matrix-acceptance.json'),life=await read('app-module-lifecycle-acceptance.json');
const base=await read('app-base-acceptance.json'),security=await read('app-security-acceptance.json'),mongo=await read('app-registry-compose-acceptance.json'),pma=await read('app-registry-phpmyadmin-acceptance.json'),mem=await read('app-memcached-acceptance.json');
const signedModules=await read('app-registry-fifty-panel-module.json'),signedRuntimes=await read('app-registry-fifty-runtime.json'),browser=await read('app-store-50-browser/acceptance.json'),reboot=await read('app-reboot-acceptance.json');
if(!mongo.mongodb_document_after_restart||!mongo.elasticsearch_document_after_restart)throw Error('Actual restarted database documents not verified');
if(mongo.elasticsearch_qa_cpu_affinity==='0'&&mongo.elasticsearch_final_restart_count!==0)throw Error('Elasticsearch crashed under final QA CPU affinity');
if(!signedModules.passed||signedModules.verified_package_count!==50||signedModules.signed_installs.length!==23||!signedRuntimes.passed||signedRuntimes.verified_package_count!==50||signedRuntimes.signed_installs.length!==9||!browser.passed||!reboot.passed||!pma.authenticated_sql)throw Error('Signed-delivery, browser, SQL or reboot acceptance incomplete');
const rows=[];
for(const app of registry.apps){
 let evidence='',passed=false;const id=app.id==='mobile'?'mobile-pwa':app.id;
 const direct=base.apps[id]||security.apps[id]||mem.apps[id];if(direct?.passed){passed=true;evidence=direct.evidence;}
 if(modules.checks[id]&&life.modules[id]?.healthy){passed=true;evidence=modules.checks[id]+'；卸载/重装通过';}
 const proof=matrix.apps[app.delivery.target];if(proof?.passed&&proof.signed_registry_install&&proof.cleanup_ok){passed=true;evidence=app.delivery.target.startsWith('php-legacy-')?'签名拉取安装、真实 FastCGI/MySQL 扩展、网站同步、域名绑定、重启后文件保留、项目清理通过':app.id==='rabbitmq'?'签名安装、认证消息发布、重启后消费、AMQP 监听、项目清理通过':'签名安装、实际 PHP LSAPI、后台会话登录、域名绑定、重启后网站文件保留、项目清理通过';}
 if(['mongodb','elasticsearch'].includes(id)&&mongo.cleanup_ok&&mongo.apps[id]){passed=true;evidence=id==='mongodb'?'实际认证写入/读取、健康、重启后实际文档保留与清理通过':'固定镜像签名安装、单 CPU 亲和性模拟环境实际索引写入/读取、集群健康、重启后文档保留、零自动崩溃重启与清理通过';}
 if(id==='phpmyadmin'&&pma.cleanup_ok&&pma.authenticated_sql){passed=true;evidence='固定摘要签名安装、实际 Cookie 登录、SQL 建库/建表/写入/读取及独立数据库核对、健康、重启和清理通过';}
 if(id==='mobile-pwa'&&passed)evidence+='；实际浏览器移动布局、Service Worker 和断网提示通过';
 if(id==='task-manager'&&passed)evidence+='；受管非 root 进程实际 SIGTERM 与错误启动身份拒绝通过';
 if(['pure-ftpd','pm2-manager','nfs-manager'].includes(id)&&passed)evidence+='；整机重启后实际服务恢复通过';
 rows.push({id:app.id,name:app.name,version:app.version,risk:app.risk,passed:passed&&app.stage==='ready',evidence});
}
const count=rows.filter(v=>v.passed).length;
if(count!==50)throw Error('Acceptance incomplete: '+count+'/50; '+rows.filter(v=>!v.passed).map(v=>v.id).join(', '));
await mkdir(path.join(root,'docs'),{recursive:true});
await writeFile(path.join(root,'docs/acceptance-50.json'),pretty({schema_version:1,checked_at:new Date().toISOString(),passed:count,total:50,scope:'Independent documented foundational capabilities; Linux isolation QA, not commercial feature parity or production certification',environments:['Debian 13 amd64 isolated VM','Existing amd64 native runtime QA VM'],limitations:['Elasticsearch final QA uses CPU 0 affinity under cross-ISA x86 emulation; multicore production stability is not certified','Legacy PHP remains EOL and requires isolated compatibility deployment'],delivery:{real_github_package_hashes:50,signed_native_installs:9,signed_module_installs:23,signed_isolated_installs:18,browser_checks:browser.checks.length,mobile_overflow:browser.mobileOverflow,whole_vm_reboot:true,managed_sigterm:true,elasticsearch_qa_cpu_affinity:mongo.elasticsearch_qa_cpu_affinity,elasticsearch_final_restart_count:mongo.elasticsearch_final_restart_count,release:releaseIndex.archive.replace(/^panel-/,'').replace(/-linux-amd64\.tar\.gz$/,''),release_sha256:releaseIndex.archive_sha256,frozen_inputs_sha256:releaseIndex.frozen_inputs_sha256},apps:rows}));
console.log('Real acceptance evidence complete:',count+'/50');
