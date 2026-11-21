import assert from 'node:assert/strict';
import {execFileSync,spawn} from 'node:child_process';
import {readFileSync,writeFileSync} from 'node:fs';
import {createServer,request} from 'node:http';
import {createServer as reservePort} from 'node:net';
import path from 'node:path';
import {setTimeout as delay} from 'node:timers/promises';
process.umask(0o077);
let input='';for await(const c of process.stdin){input+=c;assert(input.length<1<<20)}
const plan=JSON.parse(input);assert(['amd64','arm64'].includes(plan.arch));assert.match(plan.base,/^\/opt\/panel-integrity-c294-qa-[a-f0-9]{32}$/);
const {chromium}=await import(process.env.PANEL_QA_PLAYWRIGHT_CORE_ENTRY||'file:///Users/guobinlin/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/playwright-core/index.mjs');
const readGuest=file=>JSON.parse(execFileSync('/usr/bin/ssh',[...plan.ssh.slice(1),'sudo','-n','/bin/cat',file],{timeout:25000,maxBuffer:8<<20}));
const initial=readGuest(plan.base+'/evidence/prepared-state.json');assert.match(initial.site,/^[a-f0-9]{32}$/);
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
let browser,page;const visits=[],refused=[],webProof=new Map();
try{
 const deadline=Date.now()+25000;for(;;){assert.equal(tunnel.exitCode,null);try{if((await fetch(origin+'/',{signal:AbortSignal.timeout(1200),redirect:'error'})).ok)break}catch{}assert(Date.now()<deadline);await delay(250)}
 browser=await chromium.launch({channel:'chrome',headless:true,args:['--disable-background-networking',...(process.getuid()===0?['--no-sandbox']:[])]});
 for(const width of[1440,390]){
  const context=await browser.newContext({viewport:{width,height:width===390?844:1000},locale:'zh-CN',serviceWorkers:'block'});let csrf;
  try{
   await context.route('**/*',route=>{const r=route.request(),u=new URL(r.url());if(u.origin!==origin)return route.abort();if(r.method()==='GET'||r.method()==='POST'&&['/api/login','/api/logout','/api/session/activity'].includes(u.pathname))return route.continue();if(r.method()==='POST'&&/^\/api\/app-modules\/(website-tamper-proof|enterprise-tamper-proof)\/policies$/.test(u.pathname)&&['{}','{"expected_revision":0}'].includes(JSON.stringify(r.postDataJSON())))return route.continue();refused.push(r.method()+' '+u.pathname);return route.abort()});
   page=await context.newPage();page.setDefaultTimeout(35000);
   page.on('response',async r=>{try{const u=new URL(r.url());if(u.origin!==origin||r.status()!==200||!['/','/index.html'].includes(u.pathname)&&!u.pathname.startsWith('/assets/'))return;const rel=['/','/index.html'].includes(u.pathname)?'index.html':u.pathname.slice(1);assert(!rel.includes('..'));const expected=readFileSync(path.join(plan.web,rel)),actual=await r.body();assert(actual.equals(expected));webProof.set(rel,true)}catch(e){webProof.set('ERROR:'+String(e),false)}});
   await page.goto(origin+'/',{waitUntil:'load'});await page.getByLabel('用户名',{exact:true}).fill(credentials.username);await page.getByLabel('密码',{exact:true}).fill(credentials.password);
   const[login]=await Promise.all([page.waitForResponse(r=>r.url()===origin+'/api/login'&&r.request().method()==='POST'),page.getByRole('button',{name:'进入工作台',exact:true}).click()]);assert.equal(login.status(),200);csrf=(await login.json()).csrf;assert(csrf);
   const api=async route=>{const r=await context.request.get(origin+'/api'+route,{maxRedirects:0,timeout:25000});assert.equal(r.status(),200);return r.json()};
   const catalog=await api('/app-registry?refresh=1');assert.equal(catalog.catalog.apps.length,40);assert.equal(catalog.source.resolved_commit,plan.catalogue);assert(!catalog.source.stale);
   const site=(await api('/sites')).find(s=>s.id===initial.site);assert(site);
   await page.getByRole('button',{name:'软件商店',exact:true}).click();await page.getByRole('button',{name:'全部软件',exact:true}).click();
   for(const id of['website-tamper-proof','enterprise-tamper-proof']){
    const app=catalog.catalog.apps.find(a=>a.id===id);assert.equal(app.version,'1.5.0');await page.getByRole('textbox',{name:'搜索软件',exact:true}).fill(app.name);
    const card=page.locator('article.registry-runtime-card').filter({has:page.getByRole('heading',{name:app.name,exact:true})});await card.getByRole('button',{name:'打开管理',exact:true}).click();
    const panel=page.getByRole('dialog').filter({has:page.getByRole('tab',{name:'内核写保护',exact:true})});await panel.getByRole('tab',{name:'内核写保护',exact:true}).click();const work=panel.getByRole('region',{name:'网站内核写保护',exact:true});
    await work.locator('.el-select__wrapper').click();await work.getByRole('option',{name:site.name+' · '+site.domain,exact:true}).click();await work.getByText('签名已验证',{exact:true}).waitFor();
    const state=await api('/app-modules/'+id+'/kernel?site_id='+site.id);assert.equal(state.state,id==='website-tamper-proof'?'enabled':'other-application');assert(state.cap_linux_immutable);assert.equal(state.app_sha,app.sha256);assert.equal(state.revision,initial.protection.revision);
    assert(await work.getByRole('button',{name:'启用内核写保护',exact:true}).isDisabled());assert.equal(await work.getByRole('button',{name:'解除本应用保护',exact:true}).isEnabled(),id==='website-tamper-proof');
    for(const op of state.operations)await work.getByRole('table').getByText(op.request.id,{exact:true}).waitFor();
    assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1));await page.screenshot({path:path.join(plan.out,id+'-'+width+'.png')});visits.push({id,width,actual_state:state.state,operations:state.operations.length,release_only_original_application:id==='website-tamper-proof',actual_UI_and_API_agree:true});
    await panel.locator('.el-dialog__headerbtn').click();await panel.waitFor({state:'hidden'});
   }
  }finally{if(csrf)await context.request.post(origin+'/api/logout',{data:{},headers:{Origin:origin,'X-CSRF-Token':csrf},maxRedirects:0,timeout:8000}).catch(()=>{});await context.close()}
 }
 assert.deepEqual(refused,[]);assert(webProof.get('index.html')&&webProof.size>=3&&[...webProof.values()].every(Boolean));
 const proof={ok:true,architecture:plan.arch,source:plan.source,platform:plan.platform,browser:browser.version(),actual_desktop_and_fresh_mobile_kernel_states:visits,original_signed_served_web_verified:true,served_web_files_verified:webProof.size,real_hard_cold_completed:!!plan.real_hard_cold_completed,kernel_mutating_UI_requests:0};writeFileSync(path.join(plan.out,'original-browser-proof.json'),JSON.stringify(proof,null,2)+'\n',{flag:'wx'});console.log(JSON.stringify(proof));
}catch(e){if(page)await page.screenshot({path:path.join(plan.out,'failure.png')}).catch(()=>{});throw e}
finally{credentials.password='';await browser?.close();relay.closeAllConnections();await new Promise(resolve=>relay.close(resolve));tunnel.kill('SIGTERM')}
