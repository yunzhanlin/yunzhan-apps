import assert from 'node:assert/strict';
import {execFileSync,spawn} from 'node:child_process';
import {readFileSync,writeFileSync} from 'node:fs';
import {createServer,request} from 'node:http';
import {createServer as reservePort} from 'node:net';
import path from 'node:path';
import {setTimeout as delay} from 'node:timers/promises';
process.umask(0o077);
let input='';for await(const c of process.stdin){input+=c;assert(input.length<1<<20)}
const plan=JSON.parse(input);assert(['amd64','arm64'].includes(plan.arch));assert.match(plan.base,/^\/opt\/panel-files-sync-c303r2-qa-[a-f0-9]{32}$/);
const {chromium}=await import(process.env.PANEL_QA_PLAYWRIGHT_CORE_ENTRY||'file:///Users/guobinlin/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/playwright-core/index.mjs');
const readGuest=file=>JSON.parse(execFileSync('/usr/bin/ssh',[...plan.ssh.slice(1),'sudo','-n','/bin/cat',file],{timeout:25000,maxBuffer:8<<20}));
const initial=readGuest(plan.base+'/evidence/prepared.json');assert.match(initial.site,/^[a-f0-9]{32}$/);
const credentials=readGuest('/etc/panel/first-login.json');
const listen=s=>new Promise((resolve,reject)=>s.once('error',reject).listen(0,'127.0.0.1',resolve));
const socket=reservePort();await listen(socket);const port=socket.address().port;await new Promise(resolve=>socket.close(resolve));
const tunnel=spawn(plan.ssh[0],[...plan.ssh.slice(1,-1),'-oExitOnForwardFailure=yes','-N','-L','127.0.0.1:'+port+':127.0.0.1:19100',plan.ssh.at(-1)],{stdio:'ignore'});
let origin;
const relay=createServer((req,res)=>{
 if(!req.url?.startsWith('/')||req.url.startsWith('//')||req.headers.host!==new URL(origin).host||(req.headers.origin&&req.headers.origin!==origin))return res.writeHead(400).end();
 const headers={...req.headers,host:'127.0.0.1:19100'};if(headers.origin)headers.origin='http://127.0.0.1:19100';
 const upstream=request({hostname:'127.0.0.1',port,path:req.url,method:req.method,headers},reply=>{res.writeHead(reply.statusCode,reply.headers);reply.pipe(res)});upstream.on('error',()=>res.writeHead(502).end());req.pipe(upstream);
});await listen(relay);origin='http://127.0.0.1:'+relay.address().port;

const visits=[],mutations=[],webProof=new Map();let browser,page;
const record=(name,value)=>writeFileSync(path.join(plan.out,name+'.json'),JSON.stringify(value,null,2)+'\n',{flag:'wx'});
try{
 const deadline=Date.now()+25000;for(;;){assert.equal(tunnel.exitCode,null);try{if((await fetch(origin+'/',{signal:AbortSignal.timeout(1200),redirect:'error'})).ok)break}catch{}assert(Date.now()<deadline);await delay(250)}
 browser=await chromium.launch({channel:'chrome',headless:true,args:['--disable-background-networking',...(process.getuid()===0?['--no-sandbox']:[])]});
 for(const width of[1440,390]){
  const context=await browser.newContext({viewport:{width,height:width===390?844:1000},locale:'zh-CN',serviceWorkers:'block'});let csrf,passed=false;
  try{
   await context.route('**/*',route=>{const r=route.request(),u=new URL(r.url());if(u.origin!==origin)return route.abort();if(r.method()==='GET'||r.method()==='POST'&&['/api/login','/api/logout','/api/session/activity','/api/app-modules/files-sync/remote-targets','/api/app-modules/files-sync/remote-copies','/api/app-modules/files-sync/remote-copy-fragments','/api/app-modules/files-sync/verify-remote-copy'].includes(u.pathname))return route.continue();mutations.push({path:u.pathname,method:r.method(),blocked:true});return route.abort()});
   page=await context.newPage();page.setDefaultTimeout(35000);
   page.on('response',async r=>{try{const u=new URL(r.url());if(u.origin!==origin||r.status()!==200||!['/','/index.html'].includes(u.pathname)&&!u.pathname.startsWith('/assets/'))return;const rel=['/','/index.html'].includes(u.pathname)?'index.html':u.pathname.slice(1);assert(!rel.includes('..'));assert((await r.body()).equals(readFileSync(path.join(plan.web,rel))));webProof.set(rel,true)}catch(e){webProof.set('ERROR:'+String(e),false)}});
   await page.goto(origin+'/',{waitUntil:'load'});await page.getByLabel('用户名',{exact:true}).fill(credentials.username);await page.getByLabel('密码',{exact:true}).fill(credentials.password);
   const[login]=await Promise.all([page.waitForResponse(r=>r.url()===origin+'/api/login'&&r.request().method()==='POST'),page.getByRole('button',{name:'进入工作台',exact:true}).click()]);assert.equal(login.status(),200);csrf=(await login.json()).csrf;
   if(width===390&&!await page.getByRole('button',{name:'软件商店',exact:true}).isVisible())await page.getByRole('button',{name:'展开导航',exact:true}).click();await page.getByRole('button',{name:'软件商店',exact:true}).click();await page.getByRole('button',{name:'全部软件',exact:true}).click();
   const[response]=await Promise.all([page.waitForResponse(r=>r.url()===origin+'/api/app-registry?refresh=1'),page.getByRole('button',{name:'检查更新',exact:true}).click()]);assert.equal(response.status(),200);const value=await response.json();assert.equal(value.catalog.apps.length,40);assert.equal(value.source.resolved_commit,plan.catalogue);assert(!value.source.stale);record('signed-store-'+width,value);
   const app=value.catalog.apps.find(a=>a.id==='files-sync'),status=value.status.find(a=>a.id==='files-sync');assert.equal(app.version,'2.0.1');assert(status.state_known&&status.installed&&status.installed_version==='2.0.1'&&!status.update_available);
   await page.getByRole('textbox',{name:'搜索软件',exact:true}).fill(app.name);const card=page.locator('article.registry-runtime-card').filter({has:page.getByRole('heading',{name:app.name,exact:true})});await card.waitFor();assert.equal(await card.locator('.registry-update-button').count(),0);await card.getByRole('button',{name:'打开管理',exact:true}).click();const dialog=page.getByRole('dialog').filter({has:page.getByRole('tab',{name:'跨服务器增量复制',exact:true})});await dialog.waitFor();const tabs=await dialog.getByRole('tab').allTextContents();record('actual-manager-tabs-'+width,tabs);assert(tabs.some(t=>t.includes('独立备份')));await dialog.getByRole('tab',{name:/独立备份/}).click();const region=dialog.getByRole('region',{name:'本机独立备份',exact:true});await region.waitFor();await region.getByRole('button',{name:'刷新连接配置',exact:true}).click();await region.getByRole('combobox').first().click();await page.getByRole('option',{name:initial.target,exact:true}).click();await region.getByRole('button',{name:'离线刷新本机库存',exact:true}).click();const saved=region.locator('button.copy-row').filter({hasText:initial.transaction});await saved.waitFor();await saved.click();const[verified]=await Promise.all([page.waitForResponse(r=>r.url()===origin+'/api/app-modules/files-sync/verify-remote-copy'&&r.request().method()==='POST'),region.getByRole('button',{name:'离线核验完整副本',exact:true}).click()]);assert.equal(verified.status(),200);assert((await verified.json()).independent_backup.content_verified);await region.getByText('全部原文件摘要已独立核验',{exact:true}).waitFor();assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1));await page.screenshot({path:path.join(plan.out,'files-sync-independent-'+width+'.png'),animations:'disabled'});visits.push({width,known_version:'2.0.1',actual_manager_tabs:tabs,independent_backup_workspace_visible:true,false_update:false});passed=true;
  }finally{if(!passed&&page&&!page.isClosed()){record('failed-'+width+'-DOM',{text:(await page.locator('body').innerText()).slice(-18000)});await page.screenshot({path:path.join(plan.out,'failed-'+width+'.png')}).catch(()=>{})}if(csrf)await context.request.post(origin+'/api/logout',{data:{},headers:{Origin:origin,'X-CSRF-Token':csrf},maxRedirects:0,timeout:8000}).catch(()=>{});await context.close()}
 }
 assert.equal(mutations.length,0);assert(webProof.get('index.html')&&webProof.size>=3&&[...webProof.values()].every(Boolean));const proof={ok:true,architecture:plan.arch,source:plan.source,platform:plan.platform,browser:browser.version(),actual_desktop_and_fresh390_store:visits,original_signed_served_web_verified:true,served_web_files_verified:webProof.size,real_hard_cold_completed:!!plan.real_hard_cold_completed,application_mutations:0,real_SFTP_business_evidence_separate:true};record('original-browser-proof',proof);console.log(JSON.stringify(proof));
}finally{credentials.password='';await browser?.close();relay.closeAllConnections();await new Promise(resolve=>relay.close(resolve));tunnel.kill('SIGTERM')}
