import {chromium} from '../web/node_modules/playwright-core/index.mjs';
import fs from 'node:fs';
import path from 'node:path';
const base=process.env.PANEL_BASE||'http://127.0.0.1:19220',origin=process.env.PANEL_ORIGIN||'http://127.0.0.1:19100';
const access=JSON.parse(fs.readFileSync(process.env.PANEL_ACCESS_FILE,'utf8'));
const state=JSON.parse(fs.readFileSync(process.env.FUNCTIONS_QA_STATE||'.local/app-functional-state.json','utf8'));
const out=process.env.FUNCTIONS_QA_REPORT||'.local/app-functional-browser';fs.mkdirSync(out,{recursive:true});
const browser=await chromium.launch({channel:'chrome',headless:true});const checks=[],errors=[];
function check(value,message){if(!value)throw Error(message);checks.push(message);console.log('PASS',message)}
try{
 const context=await browser.newContext({viewport:{width:1500,height:1000}});
 const login=await context.request.post(base+'/api/login',{headers:{Origin:origin},data:{username:access.username,password:access.password}});check(login.ok(),'real account login');
 const registry=await (await context.request.get(base+'/api/app-registry')).json();
 const page=await context.newPage();page.setDefaultTimeout(30000);page.on('pageerror',e=>errors.push(e.message));
 await page.goto(base,{waitUntil:'domcontentloaded'});await page.getByRole('heading',{name:'服务器总览',exact:true}).waitFor();
 await page.locator('nav').getByRole('button',{name:'软件商店',exact:true}).click();await page.getByRole('combobox',{name:'软件分类筛选'}).selectOption('all');
 const cards=page.locator('.registry-runtime-card');
 async function open(id){const app=registry.catalog.apps.find(x=>x.target===id);await cards.filter({has:page.getByRole('heading',{name:app.name,exact:true})}).getByRole('button',{name:'打开管理',exact:true}).click();const d=page.locator('.app-module-dialog:visible');await d.locator('.module-actions').waitFor();await d.locator('.el-loading-mask').waitFor({state:'hidden'});return d;}
 async function close(d){await d.locator('.el-loading-mask').waitFor({state:'hidden'});await d.getByRole('button',{name:'关闭',exact:true}).click();await d.waitFor({state:'hidden'});}
 const apps=registry.catalog.apps.filter(x=>x.provider==='panel-module'&&!['nginx-waf','system-hardening','intrusion-prevention'].includes(x.target));check(apps.length===20,'20 distinct module workflows');
 for(const app of apps){const response=await context.request.get(base+'/api/app-modules/'+app.target);const detail=await response.json();check(detail.status.healthy,app.target+' actual dependencies healthy');check(detail.guidance?.description&&detail.guidance?.limitations.length,app.target+' declared implemented scope');const d=await open(app.target);await d.locator('.module-workflow li').first().waitFor();check(await d.locator('.module-fields .el-form-item').count()===(detail.definition.fields||[]).length,app.target+' actionable fields');await close(d);}
 let d=await open('website-statistics-v2');await d.getByRole('heading',{name:/慢请求明细/}).waitFor();check(await d.locator('.report-metrics strong').count()>=6,'real analytics dashboard metrics');
 const statusField=d.locator('.el-form-item').filter({has:page.getByText('HTTP 状态码（0 为全部）',{exact:true})});await statusField.locator('input').fill('503');await statusField.locator('input').press('Tab');
 const siteField=d.locator('.el-form-item').filter({has:page.getByText('网站',{exact:true})});await siteField.getByRole('combobox').click();await page.getByRole('option').filter({hasText:state.domain}).click();
 const filtered=page.waitForResponse(r=>r.url().endsWith('/api/app-modules/website-statistics-v2/run')&&r.request().method()==='POST');await d.getByRole('button',{name:'刷新报告',exact:true}).click();const response=await filtered;const data=await response.json();if(!response.ok()||!data.requests||Object.keys(data.status_codes||{}).some(k=>k!=='503'))console.log(JSON.stringify({status:response.status(),input:response.request().postDataJSON(),requests:data.requests,status_codes:data.status_codes,error:data.error}));check(response.ok()&&data.requests>=1&&Object.keys(data.status_codes).every(k=>k==='503'),'real browser status-code filter');
 await page.screenshot({path:path.join(out,'analytics.png'),animations:'disabled'});await close(d);
 d=await open('disk-analysis');const diskSite=d.locator('.el-form-item').filter({has:page.getByText('网站',{exact:true})});await diskSite.getByRole('combobox').click();await page.getByRole('option').filter({hasText:state.domain}).click();
 let scan=page.waitForResponse(r=>r.url().endsWith('/api/app-modules/disk-analysis/run')&&r.request().method()==='POST');await d.getByRole('button',{name:'刷新报告',exact:true}).click();check((await (await scan).json()).total_bytes>=1004,'real disk scan from browser');
 scan=page.waitForResponse(r=>r.url().endsWith('/api/app-modules/disk-analysis/run')&&r.request().method()==='POST');await d.getByRole('row').filter({hasText:'assets/large.txt'}).getByRole('button',{name:'查看目录',exact:true}).click();const disk=await (await scan).json();check(disk.path==='assets'&&disk.total_bytes===1004&&disk.files===2,'largest-file selection scans its real parent directory');await close(d);
 d=await open('task-manager');await d.getByRole('heading',{name:/真实进程/}).waitFor();await d.getByRole('button',{name:'选择终止',exact:true}).first().waitFor();
 const buttons=d.getByRole('button',{name:'选择终止',exact:true});let selected=false;for(let i=0;i<await buttons.count();i++){if(await buttons.nth(i).isEnabled()){await buttons.nth(i).click();selected=true;break}}check(selected,'select actual managed non-root process from table');check(await d.getByRole('button',{name:'终止所选受管进程',exact:true}).isEnabled(),'PID identity filled without manual typing');
 await page.setViewportSize({width:390,height:844});check(await page.evaluate(()=>document.documentElement.scrollWidth<=document.documentElement.clientWidth+1),'mobile dialog no horizontal overflow');await page.screenshot({path:path.join(out,'process-mobile.png'),animations:'disabled'});await close(d);
 check(errors.length===0,'no browser runtime errors');fs.writeFileSync(path.join(out,'acceptance.json'),JSON.stringify({passed:true,checks,errors},null,2)+'\n');console.log(JSON.stringify({passed:true,checks:checks.length}));
 await context.request.post(base+'/api/logout',{headers:{Origin:origin,'X-CSRF-Token':(await login.json()).csrf},data:{}});
}finally{await browser.close();}
