import {chromium} from '../web/node_modules/playwright-core/index.mjs';
import fs from 'node:fs';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
import {randomUUID} from 'node:crypto';

// This lifecycle test is deliberately restricted to the isolated Ubuntu QA VM.
const base='http://127.0.0.1:19220',origin=base;
const access=JSON.parse(fs.readFileSync('/Volumes/MacSSD/MacData/PanelDev/private/compat-ubuntu24-access.json','utf8'));
const sshArgs=['-F','/Volumes/MacSSD/MacData/PanelDev/lima/panel-compat-ubuntu24/ssh.config','lima-panel-compat-ubuntu24'];
const marker='/etc/panel/security-apps/modules/website-analytics/installed.json';
const dir=path.dirname(marker),out=path.resolve('.local/software-routing-real-install');fs.mkdirSync(out,{recursive:true});
const ssh=command=>execFileSync('ssh',[...sshArgs,command],{encoding:'utf8'}).trim();
const backup=ssh('sudo mktemp -d /var/backups/panel/system/routing-analytics.XXXXXX');
if(!/^\/var\/backups\/panel\/system\/routing-analytics\.[A-Za-z0-9]+$/.test(backup))throw Error('Unexpected QA backup path');
ssh(`sudo cp -a ${marker} ${backup}/installed.json`);
const originalMarkerSHA=ssh(`sudo sha256sum ${marker}`).split(' ')[0];
const reportSHA=ssh(`sudo find ${dir} -type f ! -name installed.json -exec sha256sum {} +`);
const report={checks:[],jobs:[],backup};const browser=await chromium.launch({channel:'chrome',headless:true});
let context,csrf;
function check(value,message){if(!value)throw Error(message);report.checks.push(message);}
async function api(url,body){const r=body===undefined?await context.request.get(base+'/api'+url):await context.request.post(base+'/api'+url,{headers:{Origin:origin,'X-CSRF-Token':csrf,'Idempotency-Key':randomUUID()},data:body});if(!r.ok())throw Error(url+': '+r.status()+' '+await r.text());return r.json();}
async function wait(id){const deadline=Date.now()+90000;while(Date.now()<deadline){const job=await api('/jobs/'+id);if(job.state==='succeeded'){report.jobs.push({id,state:job.state,kind:job.kind});return;}if(['failed','needs_attention'].includes(job.state))throw Error(JSON.stringify(job));await new Promise(r=>setTimeout(r,500));}throw Error('QA lifecycle timeout');}
try{
  context=await browser.newContext({viewport:{width:1440,height:1000}});
  const login=await context.request.post(base+'/api/login',{headers:{Origin:origin},data:{username:access.username,password:access.password}});check(login.ok(),'QA account login');csrf=(await login.json()).csrf;
  const original=await api('/software');check(original.status.find(s=>s.id==='website-analytics').installed,'existing QA application backed up');
  await wait((await api('/software/website-analytics/uninstall',{settings:{}})).job_id);
  check(!(await api('/software')).status.find(s=>s.id==='website-analytics').installed,'actual QA module uninstalled while reports retained');
  const registry=await api('/app-registry');const app=registry.catalog.apps.find(a=>a.target==='website-analytics');
  const page=await context.newPage();page.setDefaultTimeout(30000);await page.goto(base,{waitUntil:'domcontentloaded'});await page.getByRole('heading',{name:'服务器总览',exact:true}).waitFor();await page.locator('nav').getByRole('button',{name:'软件商店',exact:true}).click();await page.getByRole('combobox',{name:'软件分类筛选'}).selectOption('all');
  const card=page.locator('.registry-runtime-card').filter({has:page.getByRole('heading',{name:app.name,exact:true})});await card.getByRole('button',{name:'安装',exact:true}).click();const d=page.locator('.app-module-dialog:visible');await d.locator('.module-fields').waitFor();await d.locator('.el-loading-mask').waitFor({state:'hidden'});check(!(await d.innerText()).includes('Fail2ban'),'uninstalled module opens its real analytics form');
  const responsePromise=page.waitForResponse(r=>r.url().endsWith('/api/app-registry/'+app.id+'/install')&&r.request().method()==='POST');await d.getByRole('button',{name:'安装并验证',exact:true}).click();const response=await responsePromise;check(response.ok(),'real browser submitted signed registry installation');const body=response.request().postDataJSON();check(body.expected_version===app.version&&body.expected_sha256===app.sha256,'requested version and package digest preserved');check(!('max_retry' in body.settings),'no accidental SSH settings submitted');await wait((await response.json()).job_id);
  const installed=(await api('/software')).status.find(s=>s.id==='website-analytics');check(installed.installed&&installed.healthy&&installed.version===app.version,'actual installed module healthy at signed version');
  check(ssh(`sudo find ${dir} -type f ! -name installed.json -exec sha256sum {} +`)===reportSHA,'all existing analytics reports preserved byte for byte');
  await page.screenshot({path:path.join(out,'installation-succeeded.png'),animations:'disabled'});report.passed=true;console.log(JSON.stringify({passed:true,checks:report.checks.length,jobs:report.jobs}));
}catch(e){report.passed=false;report.failure=e.message;throw e;}
finally{
  // Restore the original QA install time/settings after verifying the real job.
  ssh(`sudo cp -a ${backup}/installed.json ${marker}`);
  check(ssh(`sudo sha256sum ${marker}`).split(' ')[0]===originalMarkerSHA,'original QA installation metadata restored');
  fs.writeFileSync(path.join(out,'acceptance.json'),JSON.stringify(report,null,2)+'\n');
  if(context&&csrf)await context.request.post(base+'/api/logout',{headers:{Origin:origin,'X-CSRF-Token':csrf},data:{}});
  await browser.close();
}
