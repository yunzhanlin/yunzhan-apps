// Isolated component/browser QA using explicitly synthetic reports. No panel
// API proxy, authentication, application install, or visitor traffic is used.
import assert from 'node:assert/strict';
import {lstatSync,writeFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createServer} from '../web/node_modules/vite/dist/node/index.js';
import vue from '../web/node_modules/@vitejs/plugin-vue/dist/index.mjs';
import {chromium} from '../web/node_modules/playwright/index.mjs';
const dir=resolve(process.argv[2]??'');
if(!process.argv[2]||process.argv.length!==3)throw new Error('require explicit private QA output directory');
const info=lstatSync(dir);if(!info.isDirectory()||info.isSymbolicLink()||info.uid!==process.getuid()||(info.mode&0o777)!==0o700)throw new Error('unsafe QA directory');
const fixture={format:1,method:'offline_ip_network',requests:5,lookups:3,lookup_limit:5000,population_partial:false,metadata:{available:true,release:'2026-10',build_epoch:1790818881,manifest_sha256:'a'.repeat(64),sha256:'b'.repeat(64),stale:false,license:'https://creativecommons.org/licenses/by/4.0/',attribution:'IP Geolocation by DB-IP',attribution_url:'https://db-ip.com/'},counts:{located:3,non_public:1,missing_ip:1,invalid_ip:0,unavailable:0,not_found:0,lookup_error:0,lookup_limited:0},countries:[{country_code:'US',country:'美国',requests:3}],cities:[{country_code:'US',country:'美国',region:'测试区域',city:'测试城市（合成示例）',requests:1}],city_unknown_requests:1,city_other_requests:1};
const entry=`import {createApp,ref,h} from 'vue';import ElementPlus from 'element-plus';import 'element-plus/dist/index.css';import Geography from '/src/AnalyticsGeographyReport.vue';const report=ref(${JSON.stringify(fixture)});window.geoQASetReport=value=>{report.value=value};createApp({setup:()=>()=>h(Geography,{report:report.value})}).use(ElementPlus).mount('#app');window.geoQAReady=true;`;
const errors=[],requests=[],checks=[];
const server=await createServer({configFile:false,root:fileURLToPath(new URL('../web',import.meta.url)),server:{host:'127.0.0.1',port:0},plugins:[vue(),{name:'isolated-geography-qa',resolveId(id){if(id==='/qa-geography-entry.ts')return '\0qa-geography-entry';},load(id){if(id==='\0qa-geography-entry')return entry;},configureServer(server){server.middlewares.use(async(req,res,next)=>{if(req.url==='/favicon.ico'){res.statusCode=204;res.end();return;}if(req.url!=='/qa-geography/')return next();res.setHeader('content-type','text/html');res.end(await server.transformIndexHtml('/qa-geography/','<!doctype html><html lang="zh-CN"><head><meta name="viewport" content="width=device-width, initial-scale=1" /><title>地域统计隔离组件 QA</title></head><body><div id="app"></div><script type="module" src="/qa-geography-entry.ts"></script></body></html>'));});}}]});
let browser;
try{
  await server.listen();const address=server.httpServer.address();assert(address&&typeof address!=='string');const origin=`http://127.0.0.1:${address.port}`;
  browser=await chromium.launch({headless:true});const page=await browser.newPage();
  page.on('pageerror',e=>errors.push(e.message));page.on('console',m=>{if(m.type()==='error')errors.push(m.text());});page.on('request',r=>requests.push({method:r.method(),url:r.url()}));
  await page.setViewportSize({width:1440,height:1000});await page.goto(origin+'/qa-geography/',{waitUntil:'networkidle'});await page.waitForFunction(()=>window.geoQAReady===true);
  assert.equal(await page.getByRole('heading',{name:'IP 网络地域统计'}).count(),1);checks.push('component mounted');
  assert.equal(await page.getByRole('link',{name:'IP Geolocation by DB-IP'}).getAttribute('href'),'https://db-ip.com/');checks.push('fixed attribution link');
  assert.equal(await page.getByRole('link',{name:'CC BY 4.0'}).getAttribute('href'),'https://creativecommons.org/licenses/by/4.0/');checks.push('fixed license link');
  assert.match(await page.locator('section').innerText(),/本次筛选：5 个请求/);checks.push('population count visible');
  assert.equal(await page.getByText('测试城市（合成示例）',{exact:true}).count(),1);checks.push('city rank visible');
  await page.screenshot({path:resolve(dir,'geography-desktop.png'),fullPage:true});
  await page.setViewportSize({width:390,height:844});assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));checks.push('390px no horizontal overflow');
  await page.screenshot({path:resolve(dir,'geography-mobile.png'),fullPage:true});
  const long=structuredClone(fixture);long.cities[0].city='x'.repeat(240);await page.evaluate(r=>window.geoQASetReport(r),long);await page.getByText('x'.repeat(240),{exact:true}).waitFor();assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));checks.push('long city name wraps on mobile');
  const absent=structuredClone(fixture);absent.metadata={available:false};absent.counts.located=0;absent.counts.unavailable=3;absent.countries=[];absent.cities=[];absent.city_unknown_requests=0;absent.city_other_requests=0;
  await page.evaluate(r=>window.geoQASetReport(r),absent);await page.getByText(/尚无可用的已验签城市库/).waitFor();assert.equal(await page.getByText('测试城市（合成示例）',{exact:true}).count(),0);checks.push('missing data has no fabricated cities');
  const corrupt=structuredClone(fixture);corrupt.counts.located=4;await page.evaluate(r=>window.geoQASetReport(r),corrupt);await page.getByText(/地域报告格式或数量不一致/).waitFor();assert.equal(await page.locator('table').count(),0);checks.push('inconsistent counts fail closed');
  const stale=structuredClone(fixture);stale.metadata.stale=true;stale.population_partial=true;await page.evaluate(r=>window.geoQASetReport(r),stale);await page.getByText(/构建时间超过 90 天/).waitFor();await page.getByText(/仅覆盖当前读取和筛选/).waitFor();checks.push('stale and partial notices visible');
  assert.deepEqual(errors,[]);checks.push('no browser errors');assert(requests.every(r=>r.method==='GET'&&new URL(r.url).origin===origin&&!new URL(r.url).pathname.startsWith('/api/')));checks.push('no panel API calls or visitor IP uploads');
  writeFileSync(resolve(dir,'browser-qa.json'),JSON.stringify({ok:true,evidence:'isolated synthetic component only, not installed-panel acceptance',checks,requests:requests.length,errors},null,2)+'\n',{flag:'wx',mode:0o600});console.log(JSON.stringify({ok:true,checks:checks.length,evidence:'isolated synthetic component only'}));
}finally{await browser?.close();await server.close();}
