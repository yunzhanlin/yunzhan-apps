// Compiled App.vue browser fixture only; no proxy, native executor or installation.
import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {readFileSync,lstatSync,readdirSync,writeFileSync} from 'node:fs';
import {resolve,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import {createInterface} from 'node:readline';
const source=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const out=resolve(process.argv[2]||'');
const info=lstatSync(out);assert(info.isDirectory()&&info.uid===process.getuid()&&(info.mode&0o777)===0o700);
const dist=resolve(source,'web/dist');
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const assets=Object.fromEntries(readdirSync(resolve(dist,'assets')).map(name=>{
 assert(/^[A-Za-z0-9_-]+\.(?:js|css|woff2?|ttf|svg|png)$/.test(name));
 const bytes=readFileSync(resolve(dist,'assets',name));return [name,{bytes,sha256:sha(bytes)}];
}));
const entry=readFileSync(resolve(dist,'index.html'),'utf8');
assert.equal([...entry.matchAll(/type="module"/g)].length,1);
const banner='<aside role="note" style="padding:12px;background:#fff0c2;color:#633b00;font:600 16px system-ui;position:sticky;top:0;z-index:10000">合成界面回归 · 非实机 · 不执行软件操作</aside>';
const html=entry.replace('<body>','<body>'+banner);
assert.notEqual(html,entry);
const calls=[],commands=[];let phase='baseline',closed=false;
function receipt(){return {format:1,scope:'compiled App.vue with synthetic API; NOT installed/native/commercial all50 acceptance',source,phase,html_sha256:sha(html),source_hashes:Object.fromEntries(['web/src/App.vue','web/src/runtimeSelection.ts'].map(x=>[x,sha(readFileSync(resolve(source,x)))])),assets:Object.fromEntries(Object.entries(assets).map(([n,a])=>[n,{bytes:a.bytes.length,sha256:a.sha256}])),calls,commands,closed};}
function save(){writeFileSync(resolve(out,'fixture-observation.json'),JSON.stringify(receipt(),null,2)+'\n',{mode:0o600});}
const r=(family,version,extra={})=>({id:family+'-'+version,version,series:version.split('.').slice(0,2).join('.'),channel:'stable',source_url:'https://fixture.invalid/source',sha256:'a'.repeat(64),...extra});
const catalog=[
 ['nginx','Nginx',[r('nginx','1.30.4'),r('nginx','1.30.6'),r('nginx','1.30.8')]],
 ['apache','Apache',[r('apache','2.4.67'),r('apache','2.4.68')]],
 ['php','PHP',[r('php','8.4.25',{installation_allowed:false,security:{status:'affected',message:'合成历史安全状态',fixed_version:'8.4.27',advisory:'fixture',cves:[]}}),r('php','8.5.12',{installation_allowed:true,channel:'active'}),r('php','8.5.13',{installation_allowed:true,channel:'active'})]],
 ['mysql','MySQL',[r('mysql','8.4.11')]],['mariadb','MariaDB',[r('mariadb','11.8.3')]],
 ['redis','Redis',[r('redis','8.2.2')]],['node','Node.js',[r('node','24.10.0',{channel:'lts'})]],['docker','Docker',[r('docker','28.5.1')]],
].map(([family,name,releases])=>({family,name,releases,versions:releases.map(x=>x.version),description:'合成数据，仅用于选择显示回归；不会安装运行时。',state:'available'}));
function runtimes(){
 const ids=phase==='empty'?[]:phase==='installed-next'?['nginx-1.30.6','nginx-1.30.8','apache-2.4.67','apache-2.4.68','php-8.4.25','php-8.5.12','php-8.5.13']:['nginx-1.30.6','apache-2.4.67','php-8.4.25','php-8.5.12'];
 const installed=ids.map(id=>{const f=catalog.find(c=>c.releases.some(r=>r.id===id)),release=f.releases.find(r=>r.id===id);return {id,family:f.family,version:release.version,status:'installed',source:'fixture',binary:'/fixture-only/not-executable',extensions:[]};});
 return {catalog,installed,active_nginx:phase==='empty'?'':'nginx-1.30.6'};
}
const access={username:'synthetic-display-only',csrf:'fixture-not-a-real-session',role:'admin',menu_ids:['overview','sites','databases','files','security','runtimes','schedules','monitor','terminal','panel-access','audit','system-tools']};
function answer(path){
 if(path==='/api/bootstrap')return {initialized:true};
 if(path==='/api/me')return access;
 if(path==='/api/runtimes')return runtimes();
 if(['/api/sites','/api/certificates','/api/jobs','/api/audit'].includes(path))return [];
 if(path==='/api/software')return {catalog:[],status:[]};
 if(path==='/api/notifications')return {notifications:[],unread:0};
 if(path==='/api/app-registry')return {catalog:{schema_version:1,generated_at:new Date().toISOString(),repository:'synthetic-fixture-not-github',apps:[]},status:[],source:{source:'fixture',stale:false,checked_at:new Date().toISOString()},host:{platform:'synthetic-not-linux',architecture:'synthetic'}};
 if(path==='/api/overview')return {hostname:'SYNTHETIC-NOT-A-SERVER',os:'Synthetic browser fixture',arch:'fixture',cpu_cores:2,cpu_percent:1,cpu_available:true,memory_percent:25,memory_available:true,memory_used:536870912,memory_total:2147483648,disk_percent:10,disk_percent_available:true,disk_used:1073741824,disk_total:10737418240,disk_available:9663676416,network_rx:0,network_tx:0,uptime_seconds:60,load:'0.00',nginx_active:true,sampled_at:new Date().toISOString(),counts:{sites:0,running_sites:0,pending_jobs:0,attention_jobs:0}};
 return undefined;
}
const server=createServer((req,res)=>{
 res.setHeader('Cache-Control','no-store');res.setHeader('X-Content-Type-Options','nosniff');
 res.setHeader('Content-Security-Policy',"default-src 'self'; connect-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'");
 const json=(code,value)=>{res.statusCode=code;res.setHeader('Content-Type','application/json');res.end(JSON.stringify(value));};
 if(req.headers.host!=='runtime-picker-qa.localhost:19370')return json(421,{error:'fixture hostname required'});
 const url=new URL(req.url,'http://runtime-picker-qa.localhost:19370');
 if(url.pathname.startsWith('/api/')){
  calls.push({at:new Date().toISOString(),method:req.method,path:url.pathname+url.search,phase,cookie_present:!!req.headers.cookie,blocked:req.method!=='GET'});save();
  // Every mutation, including harmless session-activity pings, is refused.
  if(req.method!=='GET')return json(405,{error:'合成回归不执行任何写入',request_not_accepted:true});
  const result=answer(url.pathname);return result===undefined?json(404,{error:'unconfigured synthetic route'}):json(200,result);
 }
 if(req.method!=='GET')return json(405,{error:'read-only fixture'});
 if(url.pathname==='/'||url.pathname==='/index.html'){res.setHeader('Content-Type','text/html; charset=utf-8');return res.end(html);}
 const match=/^\/assets\/([A-Za-z0-9_-]+\.(?:js|css|woff2?|ttf|svg|png))$/.exec(url.pathname);
 if(match&&Object.hasOwn(assets,match[1])){const name=match[1];res.setHeader('Content-Type',name.endsWith('.js')?'text/javascript':name.endsWith('.css')?'text/css':'application/octet-stream');return res.end(assets[name].bytes);}
 if(url.pathname==='/favicon.ico'){res.statusCode=204;return res.end();}
 json(404,{error:'synthetic asset not found'});
});
const input=createInterface({input:process.stdin});
input.on('line',line=>{
 try{const command=JSON.parse(line);assert.deepEqual(Object.keys(command),['phase']);assert(['baseline','installed-next','empty'].includes(command.phase));phase=command.phase;commands.push({at:new Date().toISOString(),phase});save();console.log(JSON.stringify({phase,synthetic_only:true}));}
 catch{console.error('invalid fixture command; no state changed');}
});
server.listen(19370,'127.0.0.1',()=>{save();console.log(JSON.stringify({url:'http://runtime-picker-qa.localhost:19370/',synthetic_only:true,out}));});
process.on('SIGINT',()=>{closed=true;save();server.close(()=>process.exit(0));});
