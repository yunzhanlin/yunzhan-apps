import { chromium } from '../web/node_modules/playwright-core/index.mjs';
import fs from 'node:fs';import path from 'node:path';
import {execFileSync} from 'node:child_process';
const base=process.env.PANEL_BASE||'http://127.0.0.1:19110',origin=process.env.PANEL_ORIGIN||'http://127.0.0.1:19100';
const access=JSON.parse(fs.readFileSync(process.env.PANEL_ACCESS_FILE,'utf8'));
const out=path.resolve('.local/app-store-50-browser');fs.mkdirSync(out,{recursive:true});
const report={checks:[],browserErrors:[]};const browser=await chromium.launch({channel:'chrome',headless:true});
let page,forwardCancelled=false;
const sshConfig='/Volumes/MacSSD/MacData/PanelDev/lima/panel-store-apps-debian13/ssh.config';
const forward=process.env.APP_PWA_OFFLINE_FORWARD;
function forwarding(action){if(!forward||!/^\d{4,5}$/.test(forward)||!base.endsWith(':'+forward))throw Error('Dedicated offline QA forward required');execFileSync('ssh',['-F',sshConfig,'-O',action,'-L','127.0.0.1:'+forward+':127.0.0.1:19100','lima-panel-store-apps-debian13'],{stdio:'pipe'})}
function assert(value,message){if(!value)throw Error(message)}
try{
 const context=await browser.newContext({viewport:{width:1560,height:960}});
 const login=await context.request.post(base+'/api/login',{headers:{Origin:origin},data:{username:access.username,password:access.password}});assert(login.ok(),'Login failed: '+login.status()+' '+(await login.text()).slice(0,400));
 const catalog=await (await context.request.get(base+'/api/app-registry')).json();assert(catalog.catalog.apps.length===50,'Expected 50 applications');assert(catalog.catalog.apps.every(a=>a.stage==='ready'),'Unaccepted application still advertised');
 page=await context.newPage();page.setDefaultTimeout(90000);
 page.on('pageerror',e=>report.browserErrors.push(e.message));
 await page.goto(base,{waitUntil:'domcontentloaded',timeout:120000});
 await page.getByRole('heading',{name:'服务器总览',exact:true}).waitFor();
 await page.locator('nav').getByRole('button',{name:'软件商店',exact:true}).click();
 const category=page.getByRole('combobox',{name:'软件分类筛选'}),cards=page.locator('.registry-runtime-card');
 for(const [id,count] of [['all',50],['deployment',29],['professional',21]]){
  await category.selectOption(id);assert(await cards.count()===count,id+' category count');
  assert(!/(实现中|接入中)/.test(await cards.allTextContents().then(v=>v.join('\n'))),'Pending stage visible');
  report.checks.push(id+'='+count);
 }
 await category.selectOption('all');await page.screenshot({path:path.join(out,'desktop.png'),animations:'disabled'});
 const modules=catalog.catalog.apps.filter(a=>a.delivery?.provider==='panel-module'&&!['nginx-waf','system-hardening','intrusion-prevention'].includes(a.delivery.target));
 // API flattens delivery fields in some supported panel versions.
 const managed=modules.length?modules:catalog.catalog.apps.filter(a=>a.provider==='panel-module'&&!['nginx-waf','system-hardening','intrusion-prevention'].includes(a.target));
 assert(managed.length===20,'Expected 20 independent module managers');
 for(const app of managed){
  const target=app.delivery?.target||app.target;
  const detail=await (await context.request.get(base+'/api/app-modules/'+target)).json();assert(detail.status.healthy,'Module not healthy: '+target);
  const card=cards.filter({has:page.getByRole('heading',{name:app.name,exact:true})});
  await card.getByRole('button',{name:'打开管理',exact:true}).click();
  const dialog=page.locator('.app-module-dialog:visible');await dialog.getByText(detail.definition.name,{exact:true}).waitFor();
  assert(await dialog.locator('.module-actions button').count()===detail.definition.actions.length,'Missing actions: '+target);
  assert(await dialog.locator('.module-fields .el-form-item').count()===(detail.definition.fields||[]).length,'Missing fields: '+target);
  await dialog.getByRole('button',{name:'关闭',exact:true}).click();await dialog.waitFor({state:'hidden'});report.checks.push(target+' manager');
 }
 await category.selectOption('web');const search=page.getByRole('textbox',{name:'搜索软件'});await search.fill('PHP');assert(await cards.count()===16,'PHP version cards');
 await search.clear();await category.selectOption('all');await page.setViewportSize({width:390,height:844});
 assert(await category.isVisible(),'Mobile category unavailable');const overflow=await page.evaluate(()=>document.documentElement.scrollWidth-document.documentElement.clientWidth);assert(overflow<=1,'Mobile overflow: '+overflow);
 await page.screenshot({path:path.join(out,'mobile.png'),animations:'disabled'});report.checks.push('Mobile layout without horizontal overflow');
 await page.evaluate(async()=>{await navigator.serviceWorker.ready});
 await page.reload({waitUntil:'domcontentloaded'});assert(await page.evaluate(()=>Boolean(navigator.serviceWorker.controller)),'PWA worker inactive');
 assert((await page.evaluate(()=>caches.keys())).length===0,'Sensitive offline cache unexpectedly exists');
 if(forward){forwarding('cancel');forwardCancelled=true}
 await context.setOffline(true);await page.goto(base+'/?offline-qa='+Date.now(),{waitUntil:'domcontentloaded'});await page.getByRole('heading',{name:'暂时无法连接服务器'}).waitFor();
 await context.setOffline(false);report.checks.push('Actual PWA worker, offline fallback, no cached API or credentials');
 assert(report.browserErrors.length===0,JSON.stringify(report.browserErrors));report.passed=true;report.mobileOverflow=overflow;
 fs.writeFileSync(path.join(out,'acceptance.json'),JSON.stringify(report,null,2)+'\n');console.log(JSON.stringify({passed:true,checks:report.checks.length}));
}catch(error){if(page){await page.screenshot({path:path.join(out,'failure.png')}).catch(()=>{});console.log(JSON.stringify({url:page.url(),visibleText:(await page.locator('body').innerText().catch(()=>'' )).slice(0,1200)}))}throw error}
finally{if(forwardCancelled)forwarding('forward');await browser.close()}
