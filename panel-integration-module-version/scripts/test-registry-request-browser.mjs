import {chromium} from '../web/node_modules/playwright-core/index.mjs';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

// Fixed forwarding to our unprivileged temporary Core QA server only. Its
// SQLite queues are real; its read-only status fixture does NOT install Nginx.
const base='http://127.0.0.1:19441';
const out=fs.mkdtempSync(path.resolve('.local/registry-browser24il-'));fs.chmodSync(out,0o700);
const proof={scope:'actual browser and Core temporary SQLite queue; read-only executor status fixture; no package installation',main_panel_changed:false,checks:[],passed:false};
const browser=await chromium.launch({channel:'chrome',headless:true});let contexts=[];
function check(value,name){assert(value,name);proof.checks.push(name);}
function responseWait(page,predicate){const result=page.waitForResponse(predicate);result.catch(()=>{});return result;}
async function openStore(page){if(page.viewportSize().width<800)await page.getByRole('button',{name:'展开导航',exact:true}).click();await page.locator('nav').getByRole('button',{name:'软件商店',exact:true}).click();}
async function setup(viewport){const context=await browser.newContext({viewport});contexts.push(context);const response=await context.request.post(base+'/api/login',{headers:{Origin:base},data:{username:'registry-browser-qa',password:'access-test-password-long'}});check(response.status()===200,'actual temporary Core login');const csrf=(await response.json()).csrf;const page=await context.newPage();await page.goto(base,{waitUntil:'domcontentloaded'});await page.getByRole('heading',{name:'服务器总览',exact:true}).waitFor();await openStore(page);return{context,page,csrf};}
async function store(page){await page.getByRole('combobox',{name:'软件分类筛选'}).selectOption('all');await page.locator('.registry-runtime-card').filter({has:page.getByRole('heading',{name:'nginx',exact:true})}).waitFor();}
async function install(page){await page.locator('.registry-runtime-card').filter({has:page.getByRole('heading',{name:'nginx',exact:true})}).getByRole('button',{name:'安装',exact:true}).click();await page.getByRole('button',{name:'验签并安装',exact:true}).click();}
try{
 const first=await setup({width:1440,height:1000});await store(first.page);let received;
 await first.page.route('**/api/app-registry/nginx/install',async route=>{received={key:route.request().headers()['idempotency-key'],body:route.request().postDataJSON()};const response=await route.fetch();check(response.status()===202,'Core genuinely committed original queue before lost response');await route.abort('failed');},{times:1});
 await install(first.page);await first.page.getByText('Failed to fetch',{exact:false}).waitFor();await first.page.locator('.registry-pending').waitFor();
 const saved=await first.page.evaluate(()=>sessionStorage.getItem('panel-registry-pending-v1'));check(saved&&JSON.parse(saved).pending[0].key===received.key,'original key persisted before request');check(!saved.includes('settings'),'no raw settings stored');
 await first.page.reload({waitUntil:'domcontentloaded'});await openStore(first.page);await store(first.page);await first.page.locator('.registry-pending').waitFor();
 const closeResponse=responseWait(first.page,r=>r.url().endsWith('/close')&&r.request().method()==='POST');await first.page.getByRole('button',{name:'安全关闭未入队请求',exact:true}).click();check((await closeResponse).status()===409,'cannot close genuinely queued unknown-response job');
 const replay=responseWait(first.page,r=>r.url().endsWith('/api/app-registry/nginx/install')&&r.request().method()==='POST');await install(first.page);const response=await replay;check(response.status()===202&&response.request().headers()['idempotency-key']===received.key,'manual retry reused original key after real reload');const job=(await response.json()).job_id;
 await first.page.locator('.el-drawer:visible').waitFor();await first.page.keyboard.press('Escape');await first.page.locator('.el-drawer:visible').waitFor({state:'hidden'});
 const read=responseWait(first.page,r=>r.url().includes('/api/app-registry/nginx/requests/')&&r.request().method()==='GET');await first.page.getByRole('button',{name:'核对原任务',exact:true}).click();const readResult=await (await read).json();check(readResult.job_id===job&&readResult.state==='queued'&&readResult.state_known,'read-only status returned same real queued job');
 await first.page.screenshot({path:path.join(out,'desktop-real-core-original-job.png'),animations:'disabled'});
 const second=await setup({width:390,height:844});await store(second.page);let unsent;
 await second.page.route('**/api/app-registry/nginx/install',async route=>{unsent={key:route.request().headers()['idempotency-key'],body:route.request().postDataJSON()};await route.abort('failed');},{times:1});
 await install(second.page);await second.page.locator('.registry-pending').waitFor();await second.page.reload({waitUntil:'domcontentloaded'});await openStore(second.page);await store(second.page);
 const closedResponse=responseWait(second.page,r=>r.url().endsWith('/close')&&r.request().method()==='POST');await second.page.getByRole('button',{name:'安全关闭未入队请求',exact:true}).click();const closed=await closedResponse;check(closed.status()===200&&(await closed.json()).state==='closed_without_submission','unsubmitted request safely closed by real Core transaction');await second.page.locator('.registry-pending').waitFor({state:'detached'});
 const late=await second.context.request.post(base+'/api/app-registry/nginx/install',{headers:{Origin:base,'X-CSRF-Token':second.csrf,'Idempotency-Key':unsent.key},data:unsent.body});check(late.status()===409,'delayed original POST fenced before queue and no second installation');
 await second.page.screenshot({path:path.join(out,'mobile-real-core-unsubmitted-closed.png'),animations:'disabled'});
 const finish=await first.context.request.post(base+'/api/app-registry/nginx/qa/finish',{headers:{Origin:base,'X-CSRF-Token':first.csrf},data:{}});check(finish.status()===200,'Core independently verified one real queue/binding, one closure and no duplicate pull');proof.core=await finish.json();proof.passed=true;
 console.log(JSON.stringify({passed:true,checks:proof.checks.length,scope:proof.scope,proof:path.join(out,'proof.json')}));
}catch(error){proof.failure=error.message;for(const [index,context] of contexts.entries())for(const page of context.pages())await page.screenshot({path:path.join(out,`failure-${index}.png`),animations:'disabled'}).catch(()=>{});throw error;}
finally{fs.writeFileSync(path.join(out,'proof.json'),JSON.stringify(proof,null,2)+'\n',{mode:0o600});for(const context of contexts)await context.close();await browser.close();for(const file of fs.readdirSync(out))fs.chmodSync(path.join(out,file),0o600);}
