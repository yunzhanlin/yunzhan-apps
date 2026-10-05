import {readFile,writeFile,mkdir} from 'node:fs/promises';
import path from 'node:path';import {fileURLToPath} from 'node:url';import {pretty} from './lib.mjs';
const root=fileURLToPath(new URL('..',import.meta.url)),panel=path.resolve(root,'../panel');
const read=async name=>JSON.parse(await readFile(path.join(panel,'.local',name),'utf8'));
const registry=JSON.parse(await readFile(path.join(root,'registry/apps.json'),'utf8'));
const modules=await read('app-modules-acceptance.json'),matrix=await read('app-compose-matrix-acceptance.json'),life=await read('app-module-lifecycle-acceptance.json');
const base=await read('app-base-acceptance.json'),security=await read('app-security-acceptance.json'),mongo=await read('app-registry-compose-acceptance.json'),pma=await read('app-registry-phpmyadmin-acceptance.json'),mem=await read('app-memcached-acceptance.json');
const rows=[];
for(const app of registry.apps){
 let evidence='',passed=false;const id=app.id==='mobile'?'mobile-pwa':app.id;
 const direct=base.apps[id]||security.apps[id]||mem.apps[id];if(direct?.passed){passed=true;evidence=direct.evidence;}
 if(modules.checks[id]&&life.modules[id]?.healthy){passed=true;evidence=modules.checks[id]+'；卸载/重装通过';}
 const proof=matrix.apps[app.delivery.target];if(proof?.passed){passed=true;evidence=app.delivery.target.startsWith('php-legacy-')?'真实 FastCGI/MySQL 扩展、网站同步、域名绑定、重启、项目清理通过':'真实服务请求、认证或管理入口、重启、项目清理通过';}
 if(['mongodb','elasticsearch'].includes(id)&&mongo.cleanup_ok&&mongo.apps[id]){passed=true;evidence=id==='mongodb'?'实际认证写入/读取、健康、重启与清理通过':'实际索引写入/读取、集群健康、重启与清理通过';}
 if(id==='phpmyadmin'&&pma.cleanup_ok&&pma.checks.length>=3){passed=true;evidence='实际固定摘要镜像、phpMyAdmin HTTP 登录界面、健康、重启和清理通过';}
 rows.push({id:app.id,name:app.name,version:app.version,risk:app.risk,passed:passed&&app.stage==='ready',evidence});
}
const count=rows.filter(v=>v.passed).length;
if(count!==50)throw Error('Acceptance incomplete: '+count+'/50; '+rows.filter(v=>!v.passed).map(v=>v.id).join(', '));
await mkdir(path.join(root,'docs'),{recursive:true});
await writeFile(path.join(root,'docs/acceptance-50.json'),pretty({schema_version:1,checked_at:new Date().toISOString(),passed:count,total:50,scope:'Independent documented foundational capabilities; Linux isolation QA, not commercial feature parity or production certification',environments:['Debian 13 amd64 isolated VM','Existing amd64 native runtime QA VM'],apps:rows}));
console.log('Real acceptance evidence complete:',count+'/50');
