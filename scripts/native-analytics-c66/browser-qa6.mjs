import {startOwnedHTTPObserver} from './wire-observer-qa6.mjs';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {spawn,spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {chromium} from 'playwright-core';

process.umask(0o077);
assert.equal(process.platform,'linux');assert(process.getuid()!==0);
assert.equal(process.env.GITHUB_ACTIONS,'true');assert.equal(process.env.GITHUB_REPOSITORY,'yunzhanlin/yunzhan-apps');
assert.equal(process.argv.length,3);
const base=path.resolve(process.argv[2]),setup=JSON.parse(fs.readFileSync(path.join(base,'browser-setup.json')));
const save=(name,value)=>fs.writeFileSync(path.join(base,name),JSON.stringify(value,null,2)+'\n',{flag:'wx',mode:0o600});
const pause=ms=>new Promise(resolve=>setTimeout(resolve,ms));
const profile=path.join(base,'browser-profile'),home=path.join(base,'browser-home');
fs.mkdirSync(profile,{mode:0o700});fs.mkdirSync(home,{mode:0o700});
let browser,visitorCDP,adminPage;const reportSaves=[],requests=[],responses=[],clicks=[],states=[],protocol=[],nativeObservations=[];
const wire=await startOwnedHTTPObserver(setup,save,{requests,responses});
const args=['--headless=new','--remote-debugging-port=0','--remote-debugging-address=127.0.0.1','--no-first-run','--no-default-browser-check','--disable-background-networking','--proxy-server='+wire.proxyURL,'--proxy-bypass-list=<-loopback>','--user-data-dir='+profile,'about:blank'];
assert(!args.some(arg=>/no-sandbox|disable.*sandbox|disable-back-forward-cache|disable-features|unsafe/.test(arg)));
save('browser-original-launch-intent.json',{executable:setup.chrome,args,framework:'public Playwright1.65.0 connectOverCDP to separately launched full Chromium',sandbox_helper:setup.sandbox,automation_default_switches_added:false,maximum_browser_launches:1});
const log=fs.openSync(path.join(base,'browser-original-process.log'),'wx',0o600);
const child=spawn(setup.chrome,args,{cwd:base,env:{PATH:'/usr/bin:/bin',HOME:home,XDG_CONFIG_HOME:home,XDG_CACHE_HOME:home,LANG:'C.UTF-8',CHROME_DEVEL_SANDBOX:setup.sandbox},stdio:['ignore',log,log]});

let reportNumber=0,requestNumber=0;
const proof={ok:false,architecture:setup.architecture,source_inputs_sha256:setup.source_inputs_sha256,actual_BFCache:false,actual_narrow_viewport:false,all50_commercial:false};
try{
 const activePort=path.join(profile,'DevToolsActivePort');
 for(let n=0;n<200&&!fs.existsSync(activePort);n++){assert(child.exitCode===null,'Original full Chromium exited; inspect retained process log, never relaunch');await pause(100);}
 assert(fs.existsSync(activePort));const [port,endpoint]=fs.readFileSync(activePort,'utf8').trim().split('\n');assert(/^\d+$/.test(port)&&endpoint.startsWith('/devtools/browser/'));
 browser=await chromium.connectOverCDP('ws://127.0.0.1:'+port+endpoint);assert(browser.version().includes(setup.browser_version));
 const context=await browser.newContext({viewport:{width:1000,height:1000},locale:'zh-CN',timezoneId:'UTC'});
 const page=await context.newPage();await page.bringToFront();const cdp=await context.newCDPSession(page);visitorCDP=cdp;
 await cdp.send('Page.enable');
 for(const event of ['Page.frameNavigated','Page.backForwardCacheNotUsed'])cdp.on(event,value=>protocol.push({event,value,at:Date.now()}));
 // Read the actual active document through the public native CDP session.
 // BFCache restores have no new load event; no lifecycle or event is simulated.
 const readVisitor=async()=>{
  const result=await cdp.send('Runtime.evaluate',{expression:'(()=>{const el=document.querySelector("#c66-state");return{url:location.href,state:el?JSON.parse(el.textContent):null,geometry:{width:innerWidth,height:innerHeight,document_width:document.documentElement.scrollWidth,document_height:document.documentElement.scrollHeight,scroll_x:scrollX,scroll_y:scrollY,path:location.pathname}}})()',returnByValue:true});
  assert(!result.exceptionDetails&&result.result?.value,'Original active visitor document cannot be read');return result.result.value;
 };
 const state=async(label)=>{
  const actual={label,...await readVisitor(),at:Date.now()};assert(actual.state);states.push(actual);save('browser-visitor-'+label+'.json',actual);return actual.state;
 };
 const geometry=async()=>(await readVisitor()).geometry;
 const nativeControl=async(selector,label)=>{
  assert(['#native-forward','nav a'].includes(selector));
  const result=await cdp.send('Runtime.evaluate',{expression:'(()=>{const el=document.querySelector('+JSON.stringify(selector)+');if(!el)return null;const r=el.getBoundingClientRect();return{x:r.x+r.width/2,y:r.y+r.height/2,width:r.width,height:r.height}})()',returnByValue:true});
  const b=result.result?.value;assert(!result.exceptionDetails&&b&&b.width>0&&b.height>0);const g=await geometry();const intent={label,geometry:g,x:b.x,y:b.y,at:Date.now()};clicks.push(intent);save('browser-original-pointer-'+String(clicks.length).padStart(4,'0')+'.json',intent);
  await cdp.send('Input.dispatchMouseEvent',{type:'mousePressed',x:b.x,y:b.y,button:'left',clickCount:1});await cdp.send('Input.dispatchMouseEvent',{type:'mouseReleased',x:b.x,y:b.y,button:'left',clickCount:1});
 };
 const waitNativeDocument=async(path,originalId,restored,label,firstProtocol)=>{
  let last;
  for(let n=0;n<300;n++){
   try{last=await readVisitor();nativeObservations.push({label,poll:n,actual:last,at:Date.now()});}catch(error){nativeObservations.push({label,poll:n,error:error.message,at:Date.now()});}
   const current=last?.state,same=current?.document_instance===originalId;
   const expectedType=restored?'BackForwardCacheRestore':'Navigation';
   const native=protocol.slice(firstProtocol).some(p=>p.event==='Page.frameNavigated'&&p.value.type===expectedType&&p.value.frame?.url===setup.visitor_origin+path);
   if(last?.url===setup.visitor_origin+path&&current&&native&&(restored?same&&current.last_pageshow_persisted===true&&current.restored_shows===1:!same&&current.last_pageshow_persisted===false)){
    save('browser-original-native-'+label+'-observations.json',nativeObservations.filter(o=>o.label===label));return;
   }
   await pause(100);
  }
  throw Error('Original native '+label+' document identity and actual pageshow/CDP restore did not qualify');
 };
 const clickAt=async(x,y,label)=>{
  const g=await geometry();const intent={label,geometry:g,x,y,at:Date.now()};clicks.push(intent);save('browser-original-pointer-'+String(clicks.length).padStart(4,'0')+'.json',intent);await page.mouse.click(x,y);await pause(110);
 };
 const clickControl=async(locator,label)=>{
  const b=await locator.boundingBox();assert(b);const g=await geometry();const intent={label,geometry:g,x:b.x+b.width/2,y:b.y+b.height/2,at:Date.now()};clicks.push(intent);save('browser-original-pointer-'+String(clicks.length).padStart(4,'0')+'.json',intent);await locator.click({noWaitAfter:true});
 };
 await page.goto(setup.visitor_origin+'/a.html',{waitUntil:'load'});await page.locator('#c66-state').waitFor();await pause(600);
 const a=await state('01-original-A');assert.equal(a.last_pageshow_persisted,false);
 for(let n=0;n<41;n++)await clickAt((2.5+(n%20)*5)*10,(12.5+Math.floor(n/20)*5)*10,'grid-'+n);
 await page.getByRole('textbox',{name:'隐私测试输入'}).fill('C66_SYNTHETIC_PRIVATE_INPUT_'+setup.nonce);
 await clickControl(page.getByRole('link',{name:'打开页面 B',exact:true}),'A-to-B');await page.waitForURL(setup.visitor_origin+'/b.html');await pause(600);
 const b=await state('02-original-B');assert.equal(b.last_pageshow_persisted,false);
 const backProtocol=protocol.length;
 await clickControl(page.getByRole('button',{name:'返回上一页',exact:true}),'B-native-back');await waitNativeDocument('/a.html',a.document_instance,true,'back-A',backProtocol);await pause(600);
 const aRestored=await state('03-real-restored-A');assert.equal(aRestored.document_instance,a.document_instance);assert.equal(aRestored.last_pageshow_persisted,true);assert.equal(aRestored.restored_shows,1);assert.equal(aRestored.shows,2);
 const forwardProtocol=protocol.length;
 await nativeControl('#native-forward','A-native-forward');await waitNativeDocument('/b.html',b.document_instance,true,'forward-B',forwardProtocol);await pause(600);
 const bRestored=await state('04-real-restored-B');assert.equal(bRestored.document_instance,b.document_instance);assert.equal(bRestored.last_pageshow_persisted,true);assert.equal(bRestored.restored_shows,1);assert.equal(bRestored.shows,2);
 const newProtocol=protocol.length;
 await nativeControl('nav a','B-new-navigation-A');await waitNativeDocument('/a.html',a.document_instance,false,'new-A',newProtocol);await pause(700);
 const aNew=await state('05-new-document-A');assert.notEqual(aNew.document_instance,a.document_instance);assert.equal(aNew.last_pageshow_persisted,false);
 const browserCDP=await browser.newBrowserCDPSession();
 const nativeProcesses=await browserCDP.send('SystemInfo.getProcessInfo');save('browser-original-SystemInfo-processes.json',nativeProcesses);
 const rendererPids=nativeProcesses.processInfo.filter(v=>v.type==='renderer').map(v=>v.id);assert(rendererPids.length>0&&rendererPids.every(v=>Number.isSafeInteger(v)&&v>1));
 const browserPin=JSON.parse(fs.readFileSync(new URL('./browser-pins.json',import.meta.url)))[setup.architecture];
 const witnessIntent={chrome:setup.chrome,sha256:browserPin.chrome_sha256,uid:process.getuid(),browser_pid:child.pid,renderer_pids:rendererPids};save('browser-original-kernel-renderer-read-intent.json',witnessIntent);
 const observed=spawnSync('/usr/bin/sudo',['-n','/usr/bin/python3','-I','-B',fileURLToPath(new URL('./renderer-witness-qa6.py',import.meta.url))],{input:JSON.stringify(witnessIntent),encoding:'utf8',timeout:30000,maxBuffer:2<<20,env:{PATH:'/usr/bin:/bin',LANG:'C.UTF-8'}});
 save('browser-original-kernel-renderer-read-outcome.json',{exit:observed.status,signal:observed.signal,stdout:observed.stdout,stderr:observed.stderr,error:observed.error?.message});assert.equal(observed.status,0,'Original native kernel renderer witness failed; retain actual process evidence');
 const kernel=JSON.parse(observed.stdout);assert(kernel.ok&&kernel.observer_uid===0&&kernel.only_read_operations&&kernel.chrome_sha256===browserPin.chrome_sha256);
 const sandboxedRenderers=kernel.renderers;assert(sandboxedRenderers.length>0);
 for(const r of sandboxedRenderers){assert.equal(Number(r.fields.Uid.split(/\s+/)[0]),process.getuid());assert.equal(BigInt('0x'+r.fields.CapEff),0n);assert.equal(r.fields.Seccomp,'2');assert.equal(r.fields.NoNewPrivs,'1');assert(r.pidfd_alive_before_and_after&&r.actual_pinned_chrome_sha256===browserPin.chrome_sha256);}
 save('browser-original-kernel-renderer-proof.json',kernel);save('browser-original-sandboxed-renderers.json',sandboxedRenderers);await browserCDP.detach();
 save('browser-original-visitor-states.json',states);save('browser-original-pointer-intents.json',clicks);save('browser-original-CDP-navigation.json',protocol);
 const visitorShot=await cdp.send('Page.captureScreenshot',{format:'png',fromSurface:true,captureBeyondViewport:false});fs.writeFileSync(path.join(base,'browser-original-visitor-final.png'),Buffer.from(visitorShot.data,'base64'),{flag:'wx',mode:0o600});
 // End the last tracked document through a real navigation. This new owned
 // fixture intentionally contains no tracker; no synthetic event is dispatched.
 await cdp.send('Page.navigate',{url:setup.visitor_origin+'/finish.html'});
 let finished=false;
 for(let n=0;n<100;n++){
  const result=await cdp.send('Runtime.evaluate',{expression:'location.pathname+"|"+document.readyState',returnByValue:true});
  if(result.result?.value==='/finish.html|complete'){finished=true;break;}await pause(100);
 }
 assert(finished);await wire.drain();await context.close();await pause(200);

 save('browser-original-collector-requests.json',requests);save('browser-original-collector-responses.json',responses);
 assert(requests.length>50&&responses.length===requests.length);assert(responses.every(r=>r.status===204&&r.actual_original_Nginx_response));assert(requests.every(r=>r.observed_before_normal_Nginx&&!r.original_headers.cookie_present&&!r.original_headers.authorization_present));
 assert(!JSON.stringify(requests).includes('C66_SYNTHETIC_PRIVATE_INPUT_'));assert(!JSON.stringify(requests).includes('c66-private-target-'));
 const adminContext=await browser.newContext({viewport:{width:1280,height:900},locale:'zh-CN',timezoneId:'UTC'});
 const admin=await adminContext.newPage();adminPage=admin;await admin.bringToFront();
 admin.on('response',response=>{
  const u=new URL(response.url());if(u.origin!==setup.panel_origin||u.pathname!=='/api/analytics/sites/'+setup.site+'/report'||response.status()!==200)return;
  const n=++reportNumber;reportSaves.push(response.text().then(raw=>save('browser-original-report-'+String(n).padStart(4,'0')+'.json',{status:response.status(),url:response.url(),raw_utf8:raw,at:Date.now()})));
 });
 await admin.goto(setup.panel_origin+'/',{waitUntil:'load'});
 const access=JSON.parse(fs.readFileSync(path.join(base,'browser-credentials.json')));
 await admin.getByLabel('用户名',{exact:true}).fill(access.username);await admin.getByLabel('密码',{exact:true}).fill(access.password);access.password='';
 await admin.getByRole('button',{name:'进入工作台',exact:true}).click();await admin.getByRole('button',{name:'软件商店',exact:true}).click();
 await admin.getByRole('button',{name:'全部软件',exact:true}).click();await admin.getByRole('textbox',{name:'搜索软件',exact:true}).fill('网站分析');
 const card=admin.locator('article').filter({has:admin.getByRole('heading',{name:/网站分析/})});await card.waitFor();assert.equal(await card.count(),1);
 await card.getByRole('button',{name:'打开管理',exact:true}).click();const workspace=admin.getByTestId('analytics-workspace');await workspace.waitFor();
 await workspace.getByRole('combobox',{name:'统计网站',exact:true}).click();await admin.getByRole('option',{name:setup.name+' · '+setup.domain,exact:true}).click();
 await workspace.getByRole('button',{name:'导出统计',exact:true}).waitFor();
 for(let n=0;n<100&&await workspace.getByRole('button',{name:'导出统计',exact:true}).isDisabled();n++)await pause(100);
 assert(await workspace.getByRole('button',{name:'导出统计',exact:true}).isEnabled());
 await workspace.getByRole('tab',{name:'点击热图',exact:true}).click();
 const selectPath=async(p)=>{await workspace.getByRole('combobox',{name:'热图页面',exact:true}).press('Enter');await admin.getByRole('option',{name:p,exact:true}).click();};
 await selectPath('/a.html');await Promise.all(reportSaves);const original=JSON.parse(JSON.parse(fs.readFileSync(path.join(base,'browser-original-report-0001.json'))).raw_utf8);
 const expected=original.heatmap.filter(p=>p.path==='/a.html').sort((a,b)=>b.count-a.count||a.x-b.x||a.y-b.y);
 assert(expected.length>=41);const count=expected.reduce((n,p)=>n+p.count,0);
 assert.equal(await workspace.getByTestId('heatmap-clicks').textContent(),String(count));assert.equal(await workspace.getByTestId('heatmap-cells').textContent(),String(expected.length));
 const table=workspace.locator('[aria-label="点击坐标明细"]'),pager=workspace.locator('[aria-label="点击坐标明细分页"]');
 const capture=async(label,expectedRows)=>{
  const actual=await workspace.evaluate(el=>{
   const graph=el.querySelector('svg.analytics-heatmap'),table=el.querySelector('[aria-label="点击坐标明细"]');const bounds=n=>{const r=n.getBoundingClientRect();return{x:r.x,y:r.y,width:r.width,height:r.height}};
   return{viewport:{width:innerWidth,height:innerHeight,document_width:document.documentElement.scrollWidth},workspace:bounds(el),svg:bounds(graph),label:graph.getAttribute('aria-label'),circles:[...graph.querySelectorAll('circle')].map(n=>({cx:n.getAttribute('cx'),cy:n.getAttribute('cy'),title:n.textContent})),rows:[...table.querySelectorAll('.el-table__body tbody tr')].map(n=>[...n.querySelectorAll('td')].map(td=>td.textContent.trim()))};
  });
  assert.deepEqual(actual.rows,expectedRows.map(p=>[p.x+'–'+Math.min(100,p.x+5)+'%',p.y+'–'+Math.min(100,p.y+5)+'%',String(p.count)]));
  assert.equal(actual.circles.length,expected.length);assert(Math.abs(actual.svg.width-actual.svg.height)<1);assert(actual.svg.width>0&&actual.svg.width<=450.5);
  save('browser-original-'+label+'-DOM.json',actual);await admin.screenshot({path:path.join(base,'browser-original-'+label+'.png'),fullPage:true});return actual;
 };
 await capture('desktop-A-first20',expected.slice(0,20));
 await admin.setViewportSize({width:390,height:844});await pause(250);await table.scrollIntoViewIfNeeded();
 const narrow=await capture('390-A-first20',expected.slice(0,20));assert.deepEqual(narrow.viewport,{width:390,height:844,document_width:390});assert(narrow.svg.width<=390);
 await pager.locator('li.number').filter({hasText:/^2$/}).click();await capture('390-A-second20',expected.slice(20,40));
 await pager.locator('li.number').filter({hasText:/^3$/}).click();await capture('390-A-last',expected.slice(40));
 await selectPath('/b.html');assert.equal(await pager.count(),0);assert.equal(await workspace.getByTestId('heatmap-clicks').textContent(),String(original.heatmap.filter(p=>p.path==='/b.html').reduce((n,p)=>n+p.count,0)));
 await selectPath('/a.html');await capture('390-A-path-reset-first20',expected.slice(0,20));
 await workspace.locator('#analytics-report-from').fill('2026-11-04 00:00:00');await workspace.locator('#analytics-report-from').press('Tab');
 for(let n=0;n<30&&await table.count();n++)await pause(100);
 assert.equal(await table.count(),0);assert.equal(await workspace.getByTestId('heatmap-clicks').count(),0);assert.equal(await workspace.getByRole('combobox',{name:'热图页面',exact:true}).count(),0);assert(await workspace.getByRole('button',{name:'导出统计',exact:true}).isDisabled());
 save('browser-original-narrow-invalid-query.json',{stale_heatmap_table:await table.count(),stale_totals:await workspace.getByTestId('heatmap-clicks').count(),stale_path_selector:await workspace.getByRole('combobox',{name:'热图页面',exact:true}).count(),export_disabled:await workspace.getByRole('button',{name:'导出统计',exact:true}).isDisabled(),original_visible_status:await workspace.innerText()});
 await admin.screenshot({path:path.join(base,'browser-original-390-invalid-query.png'),fullPage:true});await Promise.all(reportSaves);
 await adminContext.close();
 proof.ok=true;proof.actual_BFCache=true;proof.actual_narrow_viewport=true;proof.BFCache_restored_documents=2;proof.original_pointer_clicks=clicks.length;proof.original_accepted_collector_responses=responses.length;proof.actual_390_width_and_844_height=true;proof.selected_A_cells=expected.length;proof.selected_A_clicks=count;proof.real_20_20_remaining_pagination_and_path_reset=true;proof.original_raw_SQL_and_report_independent_qualification_pending=true;
}catch(error){save('browser-original-failure.json',{name:error.name,message:error.message,stack:error.stack});if(adminPage&&!adminPage.isClosed())try{save('browser-original-failed-admin-presented-state.json',{url:adminPage.url(),visible_text:await adminPage.locator('body').innerText()});await adminPage.screenshot({path:path.join(base,'browser-original-failed-admin.png'),fullPage:true});}catch(observation){save('browser-original-failed-admin-observation-error.json',{message:observation.message});}if(visitorCDP)try{const r=await visitorCDP.send('Runtime.evaluate',{expression:'({url:location.href,observed:document.querySelector("#c66-state")?.textContent})',returnByValue:true});save('browser-original-failed-current-document.json',r);}catch(observation){save('browser-original-failed-current-document-error.json',{message:observation.message});}}
finally{
 await Promise.allSettled(reportSaves);
 save('browser-original-native-document-observations.json',nativeObservations);
 for(const [name,value]of Object.entries({'browser-original-visitor-states.json':states,'browser-original-pointer-intents.json':clicks,'browser-original-CDP-navigation.json':protocol,'browser-original-collector-requests.json':requests,'browser-original-collector-responses.json':responses}))if(!fs.existsSync(path.join(base,name)))save(name,value);
 if(browser)await browser.close().catch(()=>{});
 if(child.exitCode===null){child.kill('SIGTERM');for(let n=0;n<50&&child.exitCode===null;n++)await pause(100);}
 await wire.close();fs.closeSync(log);save('browser-original-proof.json',proof);console.log(JSON.stringify(proof));
}
if(!proof.ok)process.exitCode=1;
