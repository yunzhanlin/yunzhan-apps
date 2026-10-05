import {chromium} from '../web/node_modules/playwright-core/index.mjs';
import fs from 'node:fs';
import path from 'node:path';

const base=process.env.PANEL_BASE||'http://127.0.0.1:19220',origin=process.env.PANEL_ORIGIN||base;
const access=JSON.parse(fs.readFileSync(process.env.PANEL_ACCESS_FILE,'utf8'));
const out=path.resolve(process.env.PANEL_BROWSER_REPORT||'.local/software-routing-browser');
fs.mkdirSync(out,{recursive:true});
const browser=await chromium.launch({channel:'chrome',headless:true});
const report={checks:[],errors:[],fixtures:[],jobs:[]};
function check(value,message){if(!value)throw Error(message);report.checks.push(message);}
try {
  // Fault injection must reach the browser route, not a service-worker fetch.
  const context=await browser.newContext({viewport:{width:1440,height:1000},serviceWorkers:'block'});
  const login=await context.request.post(base+'/api/login',{headers:{Origin:origin},data:{username:access.username,password:access.password}});
  check(login.ok(),'existing account login');const csrf=(await login.json()).csrf;
  const software=await(await context.request.get(base+'/api/software')).json();
  const modules=software.catalog.filter(a=>a.family==='module');check(modules.length===20,'20 compiled module definitions');
  const registry=await(await context.request.get(base+'/api/app-registry')).json();check(registry.catalog.apps.length===50,'50 signed registry applications');
  const page=await context.newPage();page.setDefaultTimeout(30000);page.on('pageerror',e=>report.errors.push(e.message));
  if(process.env.PANEL_CANDIDATE_WEB){
    const root=path.resolve(process.env.PANEL_CANDIDATE_WEB);report.fixtures.push('Candidate frontend assets with unchanged real server APIs');
    await page.route(base+'/**',async route=>{
      const pathname=decodeURIComponent(new URL(route.request().url()).pathname);
      if(pathname.startsWith('/api/'))return route.fallback();
      const file=path.resolve(root,'.'+(pathname==='/'?'/index.html':pathname));
      if(!file.startsWith(root+path.sep)||!fs.existsSync(file)||!fs.statSync(file).isFile())return route.fallback();
      const type=({'.html':'text/html','.js':'text/javascript','.css':'text/css','.json':'application/json','.svg':'image/svg+xml'})[path.extname(file)]||'application/octet-stream';
      await route.fulfill({contentType:type,body:fs.readFileSync(file)});
    });
  }
  let mode='normal',fixtureUninstalled=false;
  await page.route('**/api/app-registry*',async route=>{
    if(mode==='failed')return route.fulfill({status:503,contentType:'application/json',body:JSON.stringify({error:'QA simulated registry unavailable'})});
    if(mode==='empty'){const response=await route.fetch();const data=await response.json();data.catalog={...data.catalog,apps:[]};data.status=[];return route.fulfill({response,json:data});}
    return route.continue();
  });
  await page.route('**/api/software',async route=>{
    const response=await route.fetch();const data=await response.json();
    if(fixtureUninstalled)data.status=data.status.map(s=>({...s,installed:false,enabled:false}));
    await route.fulfill({response,json:data});
  });
  await page.route('**/api/app-modules/*',async route=>{
    if(!fixtureUninstalled||route.request().method()!=='GET')return route.continue();
    const response=await route.fetch();const data=await response.json();data.status={...data.status,installed:false};data.report=null;await route.fulfill({response,json:data});
  });
  async function store(){await page.goto(base,{waitUntil:'domcontentloaded'});await page.getByRole('heading',{name:'服务器总览',exact:true}).waitFor();await page.locator('nav').getByRole('button',{name:'软件商店',exact:true}).click();await page.getByRole('combobox',{name:'软件分类筛选'}).selectOption('all');}
  async function verifyModule(app,card,button,tag){
    await card.getByRole('button',{name:button,exact:true}).click();const d=page.locator('.app-module-dialog:visible');
    await d.locator('.module-fields').waitFor({state:'attached'});await d.locator('.el-loading-mask').waitFor({state:'hidden'});
    const detail=await(await context.request.get(base+'/api/app-modules/'+app.id)).json();
    check((await d.innerText()).includes(detail.definition.name),`${tag} ${app.id} correct manager`);
    check(await d.locator('.module-fields .el-form-item').count()===(detail.definition.fields||[]).length,`${tag} ${app.id} application-specific fields`);
    check(!(await d.innerText()).includes('Debian Fail2ban'),`${tag} ${app.id} no unrelated SSH template`);
    check(await page.locator('.security-app-dialog:visible').count()===0,`${tag} ${app.id} security dialog absent`);
    if(fixtureUninstalled)check(await d.getByRole('button',{name:'安装并验证',exact:true}).isVisible(),`${tag} ${app.id} can install from correct manager`);
    await d.getByRole('button',{name:'关闭',exact:true}).click();await d.waitFor({state:'hidden'});
  }
  await store();
  async function verifySearch(tag){
    await page.getByRole('button',{name:'全局搜索',exact:true}).click();const search=page.getByRole('dialog',{name:'全局搜索',exact:true});
    await search.getByRole('textbox',{name:'搜索功能、站点、文件或命令',exact:true}).fill('网站分析');
    await search.locator('.global-search-results button').filter({has:page.getByText('网站分析',{exact:true})}).click();
    check(await page.getByRole('combobox',{name:'软件分类筛选'}).inputValue()==='all',tag+' global search does not misclassify modules as security');
    check(await page.locator(mode==='normal'?'.registry-runtime-card':'.security-runtime-card').count()===1,tag+' global search locates the actual analytics card');
    await page.getByRole('textbox',{name:'搜索软件',exact:true}).clear();
  }
  await verifySearch('normal registry');
  for(const app of modules){const item=registry.catalog.apps.find(a=>a.target===app.id);const card=page.locator('.registry-runtime-card').filter({has:page.getByRole('heading',{name:item.name,exact:true})});const installed=registry.status.find(s=>s.id===item.id)?.installed;await verifyModule(app,card,installed?'打开管理':'安装','normal registry');}
  for(const id of ['nginx-waf','system-hardening','intrusion-prevention']){const item=registry.catalog.apps.find(a=>a.target===id);const card=page.locator('.registry-runtime-card').filter({has:page.getByRole('heading',{name:item.name,exact:true})});const installed=registry.status.find(s=>s.id===item.id)?.installed;await card.getByRole('button',{name:installed?'打开管理':'安装',exact:true}).click();const d=page.locator('.security-app-dialog:visible');await d.waitFor();check(await d.locator('.security-app-triple').count()===(id==='intrusion-prevention'?1:0),`${id} normal registry correct security form`);await d.getByRole('button',{name:'关闭',exact:true}).click();await d.waitFor({state:'hidden'});}
  console.log(JSON.stringify({phase:'normal registry',checks:report.checks.length}));
  for(const scenario of ['failed','empty']){
    mode=scenario;report.fixtures.push('Browser-only '+scenario+' catalog response; real module APIs and handlers');await store();
    await page.locator('.software-fallback-notice').waitFor();check(await page.locator('.security-runtime-card').count()===23,scenario+' compiled fallback catalog');
    await verifySearch(scenario+' fallback');
    for(const app of modules){const card=page.locator('.security-runtime-card').filter({has:page.getByRole('heading',{name:app.name,exact:true})});const installed=software.status.find(s=>s.id===app.id)?.installed;await verifyModule(app,card,installed?'打开管理':'安装',scenario+' fallback');if(installed)await verifyModule(app,card,'设置',scenario+' settings');}
    await page.getByRole('combobox',{name:'软件分类筛选'}).selectOption('monitoring');check(await page.locator('.security-runtime-card').filter({has:page.getByRole('heading',{name:'网站分析',exact:true})}).count()===1,scenario+' monitoring classification preserved');await page.getByRole('combobox',{name:'软件状态筛选'}).selectOption('updates');check(await page.locator('.security-runtime-card').count()===0,scenario+' unknown online updates not fabricated');
    console.log(JSON.stringify({phase:scenario+' fallback',checks:report.checks.length}));
  }
  mode='failed';fixtureUninstalled=true;report.fixtures.push('Browser-only uninstalled state on all 20 modules; no server installations changed');await store();
  for(const app of modules){const card=page.locator('.security-runtime-card').filter({has:page.getByRole('heading',{name:app.name,exact:true})});await verifyModule(app,card,'安装','uninstalled fallback');}
  const analytics=modules.find(a=>a.id==='website-analytics');const card=page.locator('.security-runtime-card').filter({has:page.getByRole('heading',{name:analytics.name,exact:true})});await card.getByRole('button',{name:'安装',exact:true}).click();const d=page.locator('.app-module-dialog:visible');await d.locator('.module-fields').waitFor();await d.locator('.el-loading-mask').waitFor({state:'hidden'});await page.screenshot({path:path.join(out,'website-analytics.png'),animations:'disabled'});await page.setViewportSize({width:390,height:844});check(await page.evaluate(()=>document.documentElement.scrollWidth-document.documentElement.clientWidth)<=1,'mobile analytics manager does not overflow');await page.screenshot({path:path.join(out,'website-analytics-mobile.png'),animations:'disabled'});
  check(report.errors.length===0,'no browser exceptions');report.passed=true;fs.writeFileSync(path.join(out,'acceptance.json'),JSON.stringify(report,null,2)+'\n');console.log(JSON.stringify({passed:true,checks:report.checks.length,fixtures:report.fixtures}));
  await context.request.post(base+'/api/logout',{headers:{Origin:origin,'X-CSRF-Token':csrf},data:{}});
}catch(e){report.passed=false;report.failure=e.message;fs.writeFileSync(path.join(out,'acceptance.json'),JSON.stringify(report,null,2)+'\n');throw e;}
finally{await browser.close();}
