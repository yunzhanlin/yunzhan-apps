import {chromium} from '../web/node_modules/playwright-core/index.mjs';
import fs from 'node:fs';
import path from 'node:path';
const base=process.env.PANEL_BASE,origin=process.env.PANEL_ORIGIN;
if(!['http://127.0.0.1:19220','http://127.0.0.1:19222','http://127.0.0.1:19110'].includes(base))throw Error('Isolated QA browser required');
const access=JSON.parse(fs.readFileSync(process.env.PANEL_ACCESS_FILE,'utf8'));
const state=JSON.parse(fs.readFileSync(process.env.RELIABILITY_QA_STATE||'.local/app-reliability-state.json','utf8'));
if(!state.passed||state.cleaned_up||!state.plan.startsWith('qa-reliability-'))throw Error('Valid marked QA fixture required');
const out=process.env.RELIABILITY_QA_REPORT||'.local/app-reliability-browser';fs.mkdirSync(out,{recursive:true});
const browser=await chromium.launch({channel:'chrome',headless:true}),checks=[],errors=[];
function check(value,message){if(!value)throw Error(message);checks.push(message);console.log('PASS',message)}
try{
 const context=await browser.newContext({viewport:{width:1500,height:1000}});
 const login=await context.request.post(base+'/api/login',{headers:{Origin:origin},data:{username:access.username,password:access.password}});check(login.ok(),'real account login');
 const registry=await (await context.request.get(base+'/api/app-registry')).json();
 const page=await context.newPage();page.on('pageerror',e=>errors.push(e.message));page.setDefaultTimeout(30000);
 await page.goto(base);await page.getByRole('heading',{name:'服务器总览',exact:true}).waitFor();
 await page.locator('nav').getByRole('button',{name:'软件商店',exact:true}).click();await page.getByRole('combobox',{name:'软件分类筛选'}).selectOption('all');
 async function open(id){const app=registry.catalog.apps.find(x=>x.target===id);await page.locator('.registry-runtime-card').filter({has:page.getByRole('heading',{name:app.name,exact:true})}).getByRole('button',{name:'打开管理',exact:true}).click();const d=page.locator('.app-module-dialog:visible');await d.locator('.module-actions').waitFor();await d.locator('.el-loading-mask').waitFor({state:'hidden'});return d;}
 async function close(d){await d.getByRole('button',{name:'关闭',exact:true}).click();await d.waitFor({state:'hidden'});}
 async function action(d,id,act,label){const pending=page.waitForResponse(r=>r.url().endsWith('/api/app-modules/'+id+'/'+act)&&r.request().method()==='POST');await d.getByRole('button',{name:label,exact:true}).click();const r=await pending;check(r.ok(),id+' '+act+' actual API succeeds');const data=await r.json();await d.locator('.el-loading-mask').waitFor({state:'hidden'});return data;}
 const field=(d,label)=>d.locator('.el-form-item').filter({has:page.getByText(label,{exact:true})});
 let d=await open('files-sync');let row=d.getByRole('row').filter({hasText:state.plan});await row.getByRole('button',{name:'填入表单',exact:true}).click();
 const detail=await (await context.request.get(base+'/api/app-modules/files-sync')).json();const revLabel=detail.definition.fields.find(x=>x.key==='expected_revision').label,idLabel=detail.definition.fields.find(x=>x.key==='resource_id').label;
 const rev=field(d,revLabel).locator('input'),idInput=field(d,idLabel).locator('input');
 check(await rev.getAttribute('readonly')!==null&&Number(await rev.inputValue())>0,'selected plan revision automatically filled and read-only');
 await idInput.fill('qa-reliability-new');check(await rev.inputValue()==='0','new plan ID cannot inherit stale selected revision');
 await row.getByRole('button',{name:'填入表单',exact:true}).click();
 let data=await action(d,'files-sync','resume-plan','恢复所选计划');check(data.plan.enabled&&data.plan.interval===60,'browser resumes selected persisted plan');
 data=await action(d,'files-sync','pause-plan','暂停所选计划');check(!data.plan.enabled,'browser pauses same plan with refreshed revision');
 data=await action(d,'files-sync','history','查看执行历史');check(data.history.some(x=>x.trigger==='scheduled')&&data.history.some(x=>x.outcome==='conflicts'),'browser shows actual scheduled and conflict history');
 await page.screenshot({path:path.join(out,'sync-history.png'),animations:'disabled'});await close(d);
 for(const id of ['file-monitor','website-tamper-proof','enterprise-tamper-proof']){
  d=await open(id);row=d.getByRole('row').filter({hasText:state.source});await row.getByRole('button',{name:'填入表单',exact:true}).click();
  data=await action(d,id,'resume','恢复所选监控');check(data.enabled,'browser resumes signed '+id+' policy');
  data=await action(d,id,'pause','暂停所选监控');check(!data.enabled,'browser pauses '+id+' policy without deleting baseline');
  data=await action(d,id,'history','查看执行历史');check(data.history.some(x=>x.trigger==='scheduled'),'browser views persistent '+id+' scheduled history');
  await close(d);
 }
 d=await open('files-sync');await page.setViewportSize({width:390,height:844});check(await page.evaluate(()=>document.documentElement.scrollWidth<=document.documentElement.clientWidth+1),'mobile plan table no page horizontal overflow');await page.screenshot({path:path.join(out,'sync-mobile.png'),animations:'disabled'});await close(d);
 check(errors.length===0,'no browser runtime errors');fs.writeFileSync(path.join(out,'acceptance.json'),JSON.stringify({passed:true,checks,errors},null,2)+'\n');
 await context.request.post(base+'/api/logout',{headers:{Origin:origin,'X-CSRF-Token':(await login.json()).csrf},data:{}});
}finally{await browser.close();}
