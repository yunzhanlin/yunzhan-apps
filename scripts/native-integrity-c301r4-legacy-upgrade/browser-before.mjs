import assert from 'node:assert/strict';
import {execFileSync,spawn} from 'node:child_process';
import {readFileSync,writeFileSync} from 'node:fs';
import {createServer,request} from 'node:http';
import {createServer as reservePort} from 'node:net';
import path from 'node:path';
import {setTimeout as delay} from 'node:timers/promises';
process.umask(0o077);
let input='';for await(const c of process.stdin){input+=c;assert(input.length<1<<20)}
const plan=JSON.parse(input);assert(['amd64','arm64'].includes(plan.arch));assert.match(plan.base,/^\/opt\/panel-legacy-integrity-c301-qa-[a-f0-9]{32}$/);
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

assert(['upgrade','cold'].includes(plan.phase));
const targetSHA={},ids=['website-tamper-proof','enterprise-tamper-proof'],mutations=[],visits=[],webProof=new Map();let browser,page;
const record=(name,value)=>writeFileSync(path.join(plan.out,name+'.json'),JSON.stringify(value,null,2)+'\n',{flag:'wx'});
try{
 const deadline=Date.now()+25000;for(;;){assert.equal(tunnel.exitCode,null);try{if((await fetch(origin+'/',{signal:AbortSignal.timeout(1200),redirect:'error'})).ok)break}catch{}assert(Date.now()<deadline);await delay(250)}
 browser=await chromium.launch({channel:'chrome',headless:true,args:['--disable-background-networking',...(process.getuid()===0?['--no-sandbox']:[])]});
 for(const width of[1440,390]){
  const context=await browser.newContext({viewport:{width,height:width===390?844:1000},locale:'zh-CN',serviceWorkers:'block'});let csrf,contextPassed=false,updates=0;
  try{
   await context.route('**/*',route=>{const r=route.request(),u=new URL(r.url());if(u.origin!==origin)return route.abort();if(r.method()==='GET'||r.method()==='POST'&&['/api/login','/api/logout','/api/session/activity'].includes(u.pathname))return route.continue();if(plan.phase==='upgrade'&&width===1440&&r.method()==='POST'&&ids.some(id=>u.pathname==='/api/app-registry/'+id+'/update')){mutations.push({path:u.pathname,body:r.postDataJSON(),idempotency_key:r.headers()['idempotency-key']||''});return route.continue()}mutations.push({path:u.pathname,method:r.method(),blocked:true});return route.abort()});
   page=await context.newPage();page.setDefaultTimeout(35000);
   page.on('response',async r=>{try{const u=new URL(r.url());if(u.origin!==origin||r.status()!==200||!['/','/index.html'].includes(u.pathname)&&!u.pathname.startsWith('/assets/'))return;const rel=['/','/index.html'].includes(u.pathname)?'index.html':u.pathname.slice(1);assert(!rel.includes('..'));const expected=readFileSync(path.join(plan.web,rel)),actual=await r.body();assert(actual.equals(expected));webProof.set(rel,true)}catch(e){webProof.set('ERROR:'+String(e),false)}});
   await page.goto(origin+'/',{waitUntil:'load'});await page.getByLabel('用户名',{exact:true}).fill(credentials.username);await page.getByLabel('密码',{exact:true}).fill(credentials.password);
   const[login]=await Promise.all([page.waitForResponse(r=>r.url()===origin+'/api/login'&&r.request().method()==='POST'),page.getByRole('button',{name:'进入工作台',exact:true}).click()]);assert.equal(login.status(),200);csrf=(await login.json()).csrf;assert(csrf);
   const api=async route=>{const r=await context.request.get(origin+'/api'+route,{maxRedirects:0,timeout:45000});assert.equal(r.status(),200);return r.json()};
   if(width===390&&!await page.getByRole('button',{name:'软件商店',exact:true}).isVisible())await page.getByRole('button',{name:'展开导航',exact:true}).click();await page.getByRole('button',{name:'软件商店',exact:true}).click();await page.getByRole('button',{name:'全部软件',exact:true}).click();
   const refresh=async()=>{const[response]=await Promise.all([page.waitForResponse(r=>r.url()===origin+'/api/app-registry?refresh=1'),page.getByRole('button',{name:'检查更新',exact:true}).click()]);assert.equal(response.status(),200);const value=await response.json();assert.equal(value.catalog.apps.length,40);assert.equal(value.source.resolved_commit,plan.catalogue);assert(!value.source.stale);return value};
   let catalog=await refresh();record('actual-initial-store-'+width,catalog);
   for(const id of ids){
    const app=catalog.catalog.apps.find(a=>a.id===id);assert.equal(app.version,'1.5.0');if(targetSHA[id])assert.equal(targetSHA[id],app.sha256);targetSHA[id]=app.sha256;let status=catalog.status.find(s=>s.id===id);assert(status.state_known&&status.installed);
    await page.getByRole('textbox',{name:'搜索软件',exact:true}).fill(app.name);const card=page.locator('article.registry-runtime-card').filter({has:page.getByRole('heading',{name:app.name,exact:true})});await card.waitFor();await card.getByRole('button',{name:'打开管理',exact:true}).waitFor();
    if(plan.phase==='upgrade'&&width===1440){
     assert.equal(status.installed_version,'1.4.1');assert(status.update_available&&status.update_supported);assert((await card.locator('.registry-version-line').innerText()).includes('1.4.1'));const button=card.locator('.registry-update-button');assert(await button.isEnabled());assert.equal(await button.innerText(),'更新应用');await page.screenshot({path:path.join(plan.out,id+'-old-update-prompt.png')});
     const[response]=await Promise.all([page.waitForResponse(r=>r.url()===origin+'/api/app-registry/'+id+'/update'&&r.request().method()==='POST'),button.click()]);const answer=await response.json();record(id+'-original-update-response',{status:response.status(),answer});assert.equal(response.status(),202);assert.match(answer.job_id,/^[a-f0-9]{32}$/);updates++;
     const deadline=Date.now()+360000;let job;
     do{job=await api('/jobs/'+answer.job_id);if(!['queued','running'].includes(job.state))break;await delay(1000)}while(Date.now()<deadline);
     record(id+'-original-update-job',job);assert.equal(job.state,'succeeded');const drawer=page.getByRole('dialog',{name:'任务详情',exact:true});await drawer.waitFor();await drawer.locator('.el-drawer__close-btn').click();await drawer.waitFor({state:'hidden'});
     catalog=await refresh();status=catalog.status.find(s=>s.id===id);assert(status.state_known&&status.installed&&status.installed_version==='1.5.0'&&!status.update_available);assert.equal(await card.locator('.registry-update-button').count(),0);assert((await card.locator('.registry-version-line').innerText()).includes('1.5.0'));visits.push({id,width,old_version:'1.4.1',new_version:'1.5.0',actual_UI_update_prompt_and_click:true,actual_job:answer.job_id,original_update_submissions:1});
    }else{
     assert.equal(status.installed_version,'1.5.0');assert(!status.update_available);assert.equal(await card.locator('.registry-update-button').count(),0);assert((await card.locator('.registry-version-line').innerText()).includes('1.5.0'));visits.push({id,width,installed_version:'1.5.0',known_state:true,false_update:false});
    }
    assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1));await page.screenshot({path:path.join(plan.out,id+'-'+width+'-'+plan.phase+'.png')});
   }
   assert.equal(updates,plan.phase==='upgrade'&&width===1440?2:0);contextPassed=true;
  }finally{if(!contextPassed&&page&&!page.isClosed()){record('failed-'+width+'-DOM',{text:(await page.locator('body').innerText()).slice(-18000)});await page.screenshot({path:path.join(plan.out,'failed-'+width+'.png')}).catch(()=>{})}if(csrf)await context.request.post(origin+'/api/logout',{data:{},headers:{Origin:origin,'X-CSRF-Token':csrf},maxRedirects:0,timeout:8000}).catch(()=>{});await context.close()}
 }
 assert(!mutations.some(m=>m.blocked));assert.equal(mutations.length,plan.phase==='upgrade'?2:0);assert(webProof.get('index.html')&&webProof.size>=3&&[...webProof.values()].every(Boolean));
 for(const m of mutations){const id=m.path.split('/')[3];const expected=initial.ordinary_current_store_statuses[id];assert(expected);assert.equal(m.body.expected_version,'1.5.0');assert.equal(m.body.expected_sha256,targetSHA[id])}
 const proof={ok:true,architecture:plan.arch,source:plan.source,platform:plan.platform,browser:browser.version(),phase:plan.phase,normal_app_updates:mutations.length,actual_original_UI_requests:mutations,actual_desktop_and_fresh390_store:visits,original_signed_served_web_verified:true,served_web_files_verified:webProof.size,real_hard_cold_completed:!!plan.real_hard_cold_completed,actual_legacy_source_programme_generated_141_data:true};record('original-browser-proof',proof);console.log(JSON.stringify(proof));
}catch(e){throw e}
finally{credentials.password='';await browser?.close();relay.closeAllConnections();await new Promise(resolve=>relay.close(resolve));tunnel.kill('SIGTERM')}
