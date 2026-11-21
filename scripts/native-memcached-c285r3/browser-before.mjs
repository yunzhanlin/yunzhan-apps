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
const posts=[];
const routePrefix='/api/app-registry/memcached/instances';
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
  const allowed = request => {
 const url=new URL(request.url());if(url.origin!==origin)return false;
 if(request.method()==='GET')return true;
 if(request.method()!=='POST')return false;
 if(['/api/login','/api/logout','/api/session/activity'].includes(url.pathname))return true;
 const match=/^\/api\/app-registry\/memcached\/instances\/([a-f0-9]{32})\/workspace$/.exec(url.pathname);if(!match)return false;
 let body;try{body=JSON.parse(request.postData());}catch{return false;}
 return body.action==='inspect'||body.action==='cache'&&(body.cache?.action==='stats'&&body.cache.stats==='basic'||body.cache?.action==='get'&&body.cache.key_base64===Buffer.from('c285:'+match[1]+':cold').toString('base64'));
};
  await context.route('**/*',route => allowed(route.request())?route.continue():route.abort());
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
  const app=registry.catalog.apps.find(entry=>entry.id==='memcached');assert.equal(app.version,'1.6.45-compat4');
  const actual=registry.status.find(entry=>entry.id==='memcached');assert(actual.state_known&&actual.installed&&!actual.update_available);
  const reads=[];
  const openManager=async(currentPage)=>{
    await currentPage.getByRole('textbox',{name:'搜索软件',exact:true}).fill(app.name);
    const card=currentPage.locator('article.registry-runtime-card').filter({has:currentPage.getByRole('heading',{name:app.name,exact:true})});
    const [response]=await Promise.all([currentPage.waitForResponse(r=>/\/api\/app-registry\/memcached\/instances\/[a-f0-9]{32}\/workspace$/.test(new URL(r.url()).pathname)&&r.request().postDataJSON()?.action==='inspect'),card.getByRole('button',{name:'打开管理',exact:true}).click()]);
    assert.equal(response.status(),200);const workspace=await response.json();assert(workspace.state_known&&workspace.healthy&&workspace.state==='running'&&workspace.version===app.version&&workspace.network_mode==='none');
    const dialog=currentPage.getByRole('dialog',{name:'Memcached · 缓存管理',exact:true});
    await dialog.getByText('运行中 · 已核对真实进程与 Socket',{exact:true}).waitFor();
    await dialog.getByRole('tab',{name:'运行统计',exact:true}).click();
    const [stats]=await Promise.all([currentPage.waitForResponse(r=>r.url().endsWith('/workspace')&&r.request().postDataJSON()?.cache?.action==='stats'),dialog.getByRole('button',{name:'读取真实统计',exact:true}).click()]);
    assert.equal(stats.status(),200);const sv=await stats.json();assert.equal(sv.cache.statistics.version,'1.6.45');
    await dialog.getByRole('tab',{name:'缓存读写',exact:true}).click();await dialog.getByRole('textbox',{name:'缓存键',exact:true}).fill('c285:'+workspace.project_id+':cold');
    const [get]=await Promise.all([currentPage.waitForResponse(r=>r.url().endsWith('/workspace')&&r.request().postDataJSON()?.cache?.action==='get'),dialog.getByRole('button',{name:'读取当前值 / CAS',exact:true}).click()]);
    assert.equal(get.status(),200);const result=await get.json();assert.equal(result.cache.found,plan.real_hard_cold_completed!==true);
    await dialog.getByText(plan.real_hard_cold_completed?'键不存在':'已找到该键',{exact:false}).waitFor();
    reads.push({project_id:workspace.project_id,healthy:true,actual_statistics_version:'1.6.45',original_seed_found:result.cache.found,actual_UI_cache_read:true});
    return workspace;
  };
  const workspace=await openManager(page);await page.screenshot({path:path.join(out,'signed-Memcached-current-desktop.png'),animations:'disabled'});
  const mobile=await browser.newContext({viewport:{width:390,height:844},locale:'zh-CN',serviceWorkers:'block',storageState:await context.storageState()});await mobile.route('**/*',route=>allowed(route.request())?route.continue():route.abort());
  const mobilePage=await mobile.newPage();mobilePage.setDefaultTimeout(35000);const mobileHtml=await mobilePage.goto(origin+'/',{waitUntil:'load'});assert.equal(sha(await mobileHtml.body()),sha(readFileSync(path.join(web,'index.html'))));
  await mobilePage.getByRole('button',{name:'展开导航',exact:true}).click();await mobilePage.getByRole('button',{name:'软件商店',exact:true}).click();await mobilePage.getByRole('button',{name:'全部软件',exact:true}).click();await openManager(mobilePage);
  assert(await mobilePage.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth));await mobilePage.screenshot({path:path.join(out,'signed-Memcached-current-mobile390.png'),animations:'disabled'});await mobile.close();
  const result={ok:true,architecture:plan.arch,platform:plan.platform,source:actualSource,app_version:app.version,browser:browser.version(),actual_installed_cache_workspace_visible:true,actual_desktop_and_fresh_mobile_statistics_and_cache_reads:reads,real_hard_cold_completed:plan.real_hard_cold_completed===true,retired_PHP_absent:true,workspace,read_only:true,application_install_or_update_submissions:0,all40_commercial:false};
  writeFileSync(path.join(out,'original-browser-proof.json'),JSON.stringify(result,null,2)+'\n',{flag:'wx'});console.log(JSON.stringify(result));
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
