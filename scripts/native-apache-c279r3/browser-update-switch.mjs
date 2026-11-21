import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { createServer, request } from 'node:http';
import { createServer as reservePort } from 'node:net';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
const {chromium}=await import(process.env.PANEL_QA_PLAYWRIGHT_CORE_ENTRY||'file:///Users/guobinlin/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/playwright-core/index.mjs');

process.umask(0o077);
const plan=JSON.parse(readFileSync(0,'utf8'));
assert(['arm64','amd64'].includes(plan.arch));
const ssh=plan.ssh.slice(1,-1), target=plan.ssh.at(-1);
assert.equal(target,'qa@127.0.0.1');
assert(ssh.includes('-o') && ssh.includes('StrictHostKeyChecking=yes'));
const web=plan.web, out=plan.out;
const sha=value=>createHash('sha256').update(value).digest('hex');
const posts=[];let storeCount=0,switchCount=0;const record=(name,value)=>writeFileSync(path.join(out,name+'.json'),JSON.stringify(value,null,2)+'\n',{flag:'wx',mode:0o600});
const routePrefix='/api/runtimes/apache';
const sourceCommand = "sudo -n /usr/bin/python3 -I -B -c 'import json; print(json.load(open(\"/opt/panel/current/SOURCE_INPUTS.json\"))[\"inputs_sha256\"])'";
const actualSource=execFileSync('/usr/bin/ssh',[...ssh,target,sourceCommand],{timeout:20000,encoding:'utf8'}).trim();
assert.equal(actualSource,plan.source);
const credentials=JSON.parse(execFileSync('/usr/bin/ssh',[...ssh,target,'sudo -n /bin/cat /etc/panel/first-login.json'],{timeout:20000}));
const socket = reservePort();
const listen = server => new Promise((resolve,reject) => server.once('error',reject).listen(0,'127.0.0.1',resolve));
await listen(socket);
const port = socket.address().port;
await new Promise(resolve => socket.close(resolve));
const tunnel = spawn('/usr/bin/ssh',[...ssh,'-oExitOnForwardFailure=yes','-N','-L',
  '127.0.0.1:' + port + ':127.0.0.1:19100',target],{stdio:'ignore'});
const relay = createServer((req,res) => {
  if (!req.url?.startsWith('/') || req.url.startsWith('//') || req.headers.host !== new URL(origin).host ||
      (req.headers.origin && req.headers.origin !== origin)) return res.writeHead(400).end();
  const incoming=new URL(req.url,origin);
  if(req.method==='POST' && incoming.pathname.startsWith(routePrefix+'/')) posts.push(incoming.pathname);
  const headers = {...req.headers,host:'127.0.0.1:19100',connection:'close'};
  if (headers.origin) headers.origin = 'http://127.0.0.1:19100';
  const upstream = request({hostname:'127.0.0.1',port,path:req.url,method:req.method,headers,agent:false},reply => {
    res.writeHead(reply.statusCode,reply.headers);
    reply.pipe(res);
  });
  upstream.on('error',error => { if (!res.headersSent) res.writeHead(502); res.end(String(error.code ?? 'upstream-unavailable')); });
  req.pipe(upstream);
});
await listen(relay);
const origin = 'http://127.0.0.1:' + relay.address().port;
let browser, context, page, csrf;
try {
  const ready = Date.now() + 70_000;
  for (;;) {
    assert.equal(tunnel.exitCode,null);
    try {
      if ((await fetch('http://127.0.0.1:'+port+'/',{signal:AbortSignal.timeout(4000),redirect:'error',headers:{Connection:'close'}})).ok) break;
    } catch (error) {
      if (Date.now() >= ready) throw error;
    }
    assert(Date.now() < ready);
    await delay(250);
  }
  browser = await chromium.launch({channel:'chrome',headless:true,args:['--disable-background-networking',...(process.getuid()===0?['--no-sandbox']:[])]});
  context = await browser.newContext({viewport:{width:1280,height:960},locale:'zh-CN',serviceWorkers:'block',acceptDownloads:true});
  await context.route('**/*',route => {
    const request = route.request(), url = new URL(request.url());
    if(request.method()==='POST'&&url.pathname==='/api/app-registry/apache/update'){assert.equal(++storeCount,1);record('original-store-request',{key:request.headers()['idempotency-key'],body:JSON.parse(request.postData()),maximum_submissions:1});}
    if(request.method()==='POST'&&url.pathname==='/api/runtimes/apache/switch'){assert.equal(++switchCount,1);const key=request.headers()['idempotency-key'];assert.match(key,/^[a-f0-9]{32}$/);assert.deepEqual(JSON.parse(request.postData()),{release_id:'apache-2.4.71',engine_job_id:''});record('original-switch-request',{key,body:JSON.parse(request.postData()),maximum_submissions:1});}
    return url.origin === origin && (request.method() === 'GET' ||
      (request.method() === 'POST' && ['/api/login','/api/logout','/api/session/activity','/api/app-registry/apache/update','/api/runtimes/apache/switch'].includes(url.pathname))) ? route.continue() : route.abort();
  });
  page = await context.newPage();
  page.setDefaultTimeout(35_000);
  const html=await page.goto(origin+'/',{waitUntil:'load'});
  assert.equal(sha(await html.body()),sha(readFileSync(path.join(web,'index.html'))));
  for(const name of await page.locator('script[type=module][src]').evaluateAll(nodes=>nodes.map(node=>new URL(node.src).pathname))){
    assert.match(name,/^\/assets\/[A-Za-z0-9_.-]+\.js$/);
    const asset=await context.request.get(origin+name);
    assert.equal(sha(await asset.body()),sha(readFileSync(path.join(web,name))));
  }
  await page.getByLabel('用户名',{exact:true}).fill(credentials.username);
  await page.getByLabel('密码',{exact:true}).fill(credentials.password);
  credentials.password = '';
  const [login] = await Promise.all([
    page.waitForResponse(response => response.url() === origin + '/api/login' && response.request().method() === 'POST'),
    page.getByRole('button',{name:'进入工作台',exact:true}).click(),
  ]);
  assert.equal(login.status(),200,await login.text());
  csrf = (await login.json()).csrf;
  assert(csrf);
  await page.getByRole('button',{name:'软件商店',exact:true}).click();
  await page.getByRole('button',{name:'全部软件',exact:true}).click();
  const [checked]=await Promise.all([
    page.waitForResponse(r=>r.url()===origin+'/api/app-registry?refresh=1',{timeout:100000}),
    page.getByRole('button',{name:'检查更新',exact:true}).click(),
  ]);
  assert.equal(checked.status(),200);
  const registry=await checked.json();
  assert.deepEqual(registry.host,{platform:plan.platform,architecture:plan.arch});
  assert.equal(registry.source.resolved_commit,plan.catalogue);
  assert.equal(registry.catalog.apps.length,40);
  const retired=new Set(['php-52','php-53','php-54','php-55','php-56','php-70','php-71','php-72','php-73','php-74']);
  assert(!registry.catalog.apps.some(entry=>retired.has(entry.id)));
  const app=registry.catalog.apps.find(entry=>entry.id==='apache');
  assert.equal(app.version,'2.4.71-compat1');
  const old=registry.status.find(r=>r.id==='apache');assert(old.installed&&old.state_known&&old.installed_version==='2.4.68'&&old.update_available&&old.update_supported);
  await page.getByRole('textbox',{name:'搜索软件',exact:true}).fill(app.name);
  const card=page.locator('article.registry-runtime-card').filter({has:page.getByRole('heading',{name:app.name,exact:true})});assert(await card.locator('.registry-update-button').isEnabled());
  await page.screenshot({path:path.join(out,'original-native-Apache71-update-hint.png'),animations:'disabled'});
  const [submittedStore]=await Promise.all([page.waitForResponse(r=>r.url()===origin+'/api/app-registry/apache/update'&&r.request().method()==='POST'),card.locator('.registry-update-button').click()]);const storeResponse=await submittedStore.json();record('original-store-response',{status:submittedStore.status(),value:storeResponse});assert.equal(submittedStore.status(),202);assert.match(storeResponse.job_id,/^[a-f0-9]{32}$/);
  const wait=async(id,label)=>{let value;const deadline=Date.now()+1200000;while(Date.now()<deadline){const r=await context.request.get(origin+'/api/jobs/'+id,{maxRedirects:0});assert.equal(r.status(),200);value=await r.json();if(['succeeded','failed','needs_attention'].includes(value.state))break;await delay(1200);}record(label,value);assert.equal(value.state,'succeeded');return value;};
  const closeDrawer=async()=>{const drawer=page.locator('.el-drawer').filter({visible:true});if(await drawer.count()){await drawer.locator('.el-drawer__close-btn').click();await drawer.waitFor({state:'hidden'});}};
  await wait(storeResponse.job_id,'original-store-terminal');await closeDrawer();await page.getByRole('button',{name:'软件商店',exact:true}).click();await page.getByRole('button',{name:'全部软件',exact:true}).click();await page.getByRole('textbox',{name:'搜索软件',exact:true}).fill(app.name);
  const [beforeSwitch]=await Promise.all([page.waitForResponse(r=>r.url()===origin+'/api/runtimes/apache'),card.getByRole('button',{name:'打开管理',exact:true}).click()]);assert.equal(beforeSwitch.status(),200);const beforeRuntime=await beforeSwitch.json();record('original-installed-still-old-runtime',beforeRuntime);assert(beforeRuntime.target_installed&&beforeRuntime.activation_needed&&!beforeRuntime.native_engine_required&&beforeRuntime.selected_id==='apache-2.4.68'&&beforeRuntime.running_id==='apache-2.4.68');
  const manager=page.getByRole('dialog',{name:'Apache · 运行版本',exact:true});const activate=manager.getByRole('button',{name:'切换网站到 2.4.71',exact:true});assert(await activate.isEnabled());
  const [submittedSwitch]=await Promise.all([page.waitForResponse(r=>r.url()===origin+'/api/runtimes/apache/switch'&&r.request().method()==='POST'),activate.click()]);const switchResponse=await submittedSwitch.json();record('original-switch-response',{status:submittedSwitch.status(),value:switchResponse});assert.equal(submittedSwitch.status(),202);assert.match(switchResponse.job_id,/^[a-f0-9]{32}$/);await wait(switchResponse.job_id,'original-switch-terminal');await closeDrawer();
  assert.equal(storeCount,1);assert.equal(switchCount,1);
  const openManager=async(currentPage)=>{
    await currentPage.getByRole('textbox',{name:'搜索软件',exact:true}).fill(app.name);
    const card=currentPage.locator('article.registry-runtime-card').filter({has:currentPage.getByRole('heading',{name:app.name,exact:true})});
    const [response]=await Promise.all([
      currentPage.waitForResponse(r=>r.url()===origin+'/api/runtimes/apache'),
      card.getByRole('button',{name:'打开管理',exact:true}).click(),
    ]);
    assert.equal(response.status(),200);
    const runtime=await response.json();
    assert.equal(runtime.selected_id,'apache-2.4.71');assert.equal(runtime.running_id,'apache-2.4.71');
    assert(runtime.target_installed && !runtime.activation_needed && runtime.service_state==='active');
    const dialog=currentPage.getByRole('dialog',{name:'Apache · 运行版本',exact:true});
    await dialog.getByText('配置与实际主进程均已使用 Apache 2.4.71',{exact:true}).waitFor();
    await dialog.getByText('Apache 2.4.71 · 已完整安装',{exact:true}).waitFor();
    assert(await dialog.getByRole('button',{name:'切换网站到 2.4.71',exact:true}).isDisabled());
    return runtime;
  };
  const runtime=await openManager(page);
  await page.screenshot({path:path.join(out,'signed-Apache271-before-hard-cold-desktop.png'),animations:'disabled'});
  const mobile=await browser.newContext({viewport:{width:390,height:844},locale:'zh-CN',serviceWorkers:'block',storageState:await context.storageState()});
  await mobile.route('**/*',route=>{
    const request=route.request(),url=new URL(request.url());
    return url.origin===origin && (request.method()==='GET'||request.method()==='POST'&&url.pathname==='/api/session/activity')?route.continue():route.abort();
  });
  const mobilePage=await mobile.newPage();mobilePage.setDefaultTimeout(35000);
  const mobileHtml=await mobilePage.goto(origin+'/',{waitUntil:'load'});
  assert.equal(sha(await mobileHtml.body()),sha(readFileSync(path.join(web,'index.html'))));
  await mobilePage.getByRole('button',{name:'展开导航',exact:true}).click();
  await mobilePage.getByRole('button',{name:'软件商店',exact:true}).click();
  await mobilePage.getByRole('button',{name:'全部软件',exact:true}).click();
  await openManager(mobilePage);
  await mobilePage.getByRole('dialog',{name:'Apache · 运行版本',exact:true}).getByRole('button',{name:'切换网站到 2.4.71',exact:true}).scrollIntoViewIfNeeded();
  assert(await mobilePage.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth));
  await delay(400);
  await mobilePage.screenshot({path:path.join(out,'signed-Apache271-before-hard-cold-mobile390.png'),animations:'disabled'});
  await mobile.close();
  assert.deepEqual(posts,['/api/runtimes/apache/switch']);
  const result={ok:true,architecture:plan.arch,platform:plan.platform,source:actualSource,app_version:app.version,
    browser:browser.version(),actual_Apache_271_visible:true,real_hard_cold_completed:false,retired_PHP_absent:true,runtime,read_only:false,new_store_manifest_acceptance:true,actual_normal_signed_store_update:true,actual_normal_UI_runtime_switch:true,actual_32_hex_UI_nonce:true,original_store_job:storeResponse.job_id,original_switch_job:switchResponse.job_id,store_POST_submissions:storeCount,switch_POST_submissions:switchCount};
  writeFileSync(path.join(out,'original-browser-proof.json'),JSON.stringify(result,null,2)+'\n',{flag:'wx'});
  console.log(JSON.stringify(result));
} catch (error) {
  if(page) await page.screenshot({path:path.join(out,'failure.png')}).catch(()=>{});
  throw error;
} finally {
  if (csrf && context) await context.request.post(origin+'/api/logout',
    {data:{},headers:{Origin:origin,'X-CSRF-Token':csrf},maxRedirects:0,timeout:8000}).catch(()=>{});
  await browser?.close();
  relay.closeAllConnections();
  await new Promise(resolve => relay.close(resolve));
  tunnel.kill('SIGTERM');
}
