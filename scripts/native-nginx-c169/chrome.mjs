import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync, writeFileSync, statSync} from 'node:fs';
import path from 'node:path';
import {pathToFileURL} from 'node:url';

process.umask(0o077);
assert(process.platform==='linux' && process.arch==='x64' && process.getuid()===0);
assert(process.env.GITHUB_ACTIONS==='true' && process.env.GITHUB_REPOSITORY==='yunzhanlin/yunzhan-apps');
const root=path.join(process.argv[2],'business-phase1');
const read=file=>JSON.parse(readFileSync(file,'utf8'));
const known=read(path.join(root,'browser-log-fixture.json'));
const result=read(path.join(root,'original-proof.json'));
assert(result.ok&&result.real_interrupted_log&&result.source_inputs_sha256===known.source);
assert.equal(read('/opt/panel/current/SOURCE_INPUTS.json').inputs_sha256,known.source);
const origin='http://127.0.0.1:19100';
const prefix='/api/schedules/runs/'+known.run+'/log-cleanup';
const continued=prefix+'/continue';
const creds=read('/etc/panel/first-login.json');
const {chromium}=await import(pathToFileURL(process.argv[3]));
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const browser=await chromium.launch({executablePath:'/usr/bin/google-chrome',headless:true,args:['--no-sandbox','--disable-background-networking']});
const ctx=await browser.newContext({viewport:{width:390,height:844},locale:'zh-CN',serviceWorkers:'block'});
let csrf, posts=0, responseCode, routeFailure;
await ctx.route('**/*',async route=>{
 const req=route.request(),u=new URL(req.url());
 if(u.origin!==origin)return route.abort();
 if(req.method()==='GET')return route.continue();
 if(req.method()!=='POST')return route.abort();
 if(['/api/login','/api/logout','/api/session/activity'].includes(u.pathname))return route.continue();
 if(u.pathname!==continued||++posts!==1)return route.abort();
 try {
  assert.deepEqual(req.postDataJSON(),{request_id:known.run,site_id:known.site,
     plan_sha256:known.inspection.plan_sha256,acknowledge_unknown:true});
 } catch(error){
  routeFailure=String(error);
  return route.abort();
 }
 return route.continue();
});
const page=await ctx.newPage();
page.setDefaultTimeout(35000);
try {
 const html=await page.goto(origin+'/',{waitUntil:'load'});
 assert.equal(sha(await html.body()),sha(readFileSync('/opt/panel/current/web/index.html')));
 await page.getByLabel('用户名',{exact:true}).fill(creds.username);
 await page.getByLabel('密码',{exact:true}).fill(creds.password);
 creds.password='';
 const [login]=await Promise.all([
  page.waitForResponse(r=>r.url()===origin+'/api/login'&&r.request().method()==='POST'),
  page.getByRole('button',{name:'进入工作台',exact:true}).click()
 ]);
 assert.equal(login.status(),200);
 csrf=(await login.json()).csrf;
 assert(csrf);
 await page.getByRole('button',{name:'展开导航',exact:true}).click();
 await page.getByRole('button',{name:'计划任务',exact:true}).click();
 await page.getByRole('textbox',{name:'搜索任务',exact:true}).fill(known.schedule_label);
 await page.locator('.schedule-card').filter({hasText:known.schedule_label}).getByRole('button',{name:'日志',exact:true}).click();
 const records=page.getByRole('dialog',{name:known.schedule_label+' · 执行日志',exact:true});
 const row=records.locator('.schedule-log-cards .run-card').filter({hasText:'失败'});
 const [readOnly]=await Promise.all([
  page.waitForResponse(r=>r.url()===origin+prefix&&r.request().method()==='GET'),
  row.getByRole('button',{name:'日志文件核对',exact:true}).click()
 ]);
 assert.equal(readOnly.status(),200);
 const inspected=await readOnly.json();
 assert.deepEqual(inspected,known.inspection);
 const dialog=page.getByRole('dialog',{name:'日志文件核对',exact:true});
 const fileCards=dialog.locator('.log-inspection-file');
 assert.equal(await fileCards.count(),inspected.files.length);
 assert(inspected.files.length>=2);
 assert(!(await dialog.locator('.log-inspection-table').isVisible()));
 assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth),390);
 const button=dialog.getByRole('button',{name:'核实后续可继续条件',exact:true});
 assert(await button.isDisabled());
 const label=dialog.getByText('我确认原操作仍是未知结果，只请求核实后续新任务是否可以继续',{exact:true});
 await label.scrollIntoViewIfNeeded();
 assert(await label.evaluate(e=>e.scrollWidth<=e.clientWidth));
 await dialog.screenshot({path:path.join(root,'original-390-log-unknown.png')});
 await label.click();
 assert(!(await button.isDisabled()));
 const [write,readReconciled]=await Promise.all([
  page.waitForResponse(r=>r.url()===origin+continued&&r.request().method()==='POST',{timeout:90000}),
  page.waitForResponse(r=>r.url()===origin+prefix&&r.request().method()==='GET',{timeout:90000}),
  button.click()
 ]);
 responseCode=write.status();
 assert(!routeFailure && posts===1 && responseCode>=200 && responseCode<300);
 assert.equal(readReconciled.status(),200);
 const after=await readReconciled.json();
 assert.equal(after.request_id,known.run);
 assert.equal(after.state,inspected.state);
 assert.equal(after.plan_sha256,inspected.plan_sha256);
 assert.deepEqual(after.files,inspected.files);
 assert(!after.result && /^[a-f0-9]{64}$/.test(after.continuation.evidence_sha256));
 await dialog.getByText(/已于.*核实后续新任务可继续/).waitFor();
 await dialog.screenshot({path:path.join(root,'original-390-log-reviewed.png')});
 const logs='/var/log/nginx';
 for(const [name,before] of Object.entries(known.file_before)){
  assert(name.startsWith('panel-'+known.site+'.access.log')&&!name.includes('/'));
  const file=path.join(logs,name);
  const st=statSync(file);
  assert.deepEqual({dev:st.dev,inode:st.ino,mode:st.mode&0o7777,uid:st.uid,size:st.size,sha256:sha(readFileSync(file))},before);
 }
 Object.assign(result,{browser_UI_qualified:true,real_390px_continuation:true,evidence_sha256:after.continuation.evidence_sha256,
   read_only_file_identity_and_bytes_preserved:true,unknown_not_rewritten:true,continuation_submissions:posts,browser:browser.version()});
} catch(error) {
 result.ok=false;
 result.browser_failure=(String(error)+'\n'+(error.stack||'')).slice(0,2800);
 result.continuation_response=responseCode;
} finally {
 creds.password='';
 if(csrf) {
  const logout=await ctx.request.post(origin+'/api/logout',{data:{},headers:{Origin:origin,'X-CSRF-Token':csrf},maxRedirects:0,timeout:10000}).catch(()=>null);
  result.logged_out=logout?.status()===200;
  result.ok&&=result.logged_out;
 }
 writeFileSync(path.join(root,'original-proof.json'),JSON.stringify(result,null,2)+'\n');
 await browser.close();
}
assert(result.ok&&result.browser_UI_qualified);
