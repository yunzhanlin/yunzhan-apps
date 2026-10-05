import { chromium } from '../web/node_modules/playwright-core/index.mjs';
import fs from 'node:fs';import path from 'node:path';
const base=process.env.PANEL_BASE||'http://127.0.0.1:19220',origin=process.env.PANEL_ORIGIN||base;
const access=JSON.parse(fs.readFileSync(process.env.PANEL_ACCESS_FILE,'utf8'));
const out=path.resolve(process.env.PANEL_BROWSER_REPORT||'.local/store-updates-browser');fs.mkdirSync(out,{recursive:true});
const browser=await chromium.launch({channel:'chrome',headless:true});const report={checks:[],errors:[]};
function check(value,message){if(!value)throw Error(message);report.checks.push(message)}
try{
 const context=await browser.newContext({viewport:{width:1560,height:960}});
 const login=await context.request.post(base+'/api/login',{headers:{Origin:origin},data:{username:access.username,password:access.password}});check(login.ok(),'account login');
 const page=await context.newPage();page.setDefaultTimeout(60000);page.on('pageerror',e=>report.errors.push(e.message));
 await page.goto(base,{waitUntil:'domcontentloaded'});await page.getByRole('heading',{name:'服务器总览',exact:true}).waitFor();
 await page.locator('nav').getByRole('button',{name:'软件商店',exact:true}).click();
 await page.locator('.app-registry-source').getByRole('button',{name:'检查更新',exact:true}).click();
 await page.getByText(/已检查 GitHub 应用目录/).waitFor();
 const category=page.getByRole('combobox',{name:'软件分类筛选'}),filter=page.getByRole('combobox',{name:'软件状态筛选'});await category.selectOption('all');
 let registry=await (await context.request.get(base+'/api/app-registry')).json();check(registry.catalog.apps.length===50,'50 verified apps remain present');check(!registry.source.stale,'real GitHub check passed');
 const expected=registry.status.filter(s=>s.update_available).length;await filter.selectOption('updates');check(await page.locator('.registry-runtime-card').count()===expected,'update filter matches installed/server versions');
 await page.screenshot({path:path.join(out,'updates.png'),animations:'disabled'});
 const app=registry.catalog.apps.find(a=>a.id==='files-sync'),status=registry.status.find(s=>s.id==='files-sync');
 if(process.env.STORE_UPDATE_CLICK==='1'){
  check(status.update_available&&status.update_supported,'real old installation advertises new version');
  const card=page.locator('.registry-runtime-card').filter({has:page.getByRole('heading',{name:app.name,exact:true})});check((await card.innerText()).includes('→ 仓库'),'old and new versions shown');
  const response=page.waitForResponse(r=>r.url().endsWith('/api/app-registry/files-sync/update')&&r.request().method()==='POST');await card.getByRole('button',{name:'更新应用',exact:true}).click();const result=await (await response).json();check(Boolean(result.job_id),'real update job submitted');
  const deadline=Date.now()+90000;let finished=false;
  while(Date.now()<deadline){const job=await(await context.request.get(base+'/api/jobs/'+result.job_id)).json();if(job.state==='succeeded'){finished=true;break}if(['failed','needs_attention'].includes(job.state))throw Error(JSON.stringify(job));await new Promise(r=>setTimeout(r,1000));}
  check(finished,'real update completed');await page.getByRole('button',{name:'关闭',exact:true}).last().click();
  await page.locator('.app-registry-source').getByRole('button',{name:'检查更新',exact:true}).click();await page.getByText(/已检查 GitHub 应用目录/).last().waitFor();
  registry=await (await context.request.get(base+'/api/app-registry')).json();check(!registry.status.find(s=>s.id==='files-sync').update_available,'badge cleared after successful update');
 }
 await filter.selectOption('all');
 for(const item of registry.catalog.apps.filter(a=>a.provider==='panel-module'&&!['nginx-waf','system-hardening','intrusion-prevention'].includes(a.target))){
  if(!registry.status.find(s=>s.id===item.id)?.installed)continue;
  const card=page.locator('.registry-runtime-card').filter({has:page.getByRole('heading',{name:item.name,exact:true})});await card.getByRole('button',{name:'打开管理',exact:true}).click();
  const dialog=page.locator('.app-module-dialog:visible');await dialog.getByRole('tab',{name:'概览',exact:true}).click();check((await dialog.innerText()).includes('版本'),item.id+' overview');
  await dialog.getByRole('tab',{name:'配置与操作',exact:true}).click();check(await dialog.locator('.module-actions button').count()>0,item.id+' real configuration/operations');
  await dialog.getByRole('tab',{name:'报告与日志',exact:true}).click();await dialog.getByRole('heading',{name:'实际执行结果',exact:true}).waitFor();
  await dialog.getByRole('tab',{name:'版本与更新',exact:true}).click();check((await dialog.innerText()).includes(item.version),item.id+' installed/latest version page');
  await dialog.getByRole('button',{name:'关闭',exact:true}).click();await dialog.waitFor({state:'hidden'});
 }
 await page.setViewportSize({width:390,height:844});check(await page.evaluate(()=>document.documentElement.scrollWidth-document.documentElement.clientWidth)<=1,'mobile does not overflow');
 await page.screenshot({path:path.join(out,'mobile.png'),animations:'disabled'});check(report.errors.length===0,'no browser exceptions');report.passed=true;fs.writeFileSync(path.join(out,'acceptance.json'),JSON.stringify(report,null,2)+'\n');console.log(JSON.stringify({passed:true,checks:report.checks.length}));
}finally{await browser.close()}
