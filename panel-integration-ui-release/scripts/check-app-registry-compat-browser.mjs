import { chromium } from '../web/node_modules/playwright-core/index.mjs';
import fs from 'node:fs';
import path from 'node:path';
const base = process.env.PANEL_BASE || 'http://127.0.0.1:19100';
const origin = process.env.PANEL_ORIGIN || base;
const credentials = JSON.parse(fs.readFileSync(process.env.PANEL_ACCESS_FILE, 'utf8'));
const out = path.resolve(process.env.PANEL_BROWSER_REPORT || '.local/registry-compat-browser');
fs.mkdirSync(out, {recursive:true});
const browser = await chromium.launch({channel:'chrome',headless:true});
const report = {checks:[], errors:[]};
function check(value, message) {if (!value) throw Error(message); report.checks.push(message);}
try {
  const context = await browser.newContext({viewport:{width:1440,height:1000}});
  const login = await context.request.post(base+'/api/login', {headers:{Origin:origin},data:{username:credentials.username,password:credentials.password}});
  check(login.ok(), 'existing account login');
  const response = await context.request.get(base+'/api/app-registry');
  check(response.ok(), 'registry API');
  const registry = await response.json();
  check(registry.catalog.apps.length === 50, '50 signed applications');
  const expectedUnsupported = registry.status.filter(x=>x.supported===false).map(x=>x.id);
  const page = await context.newPage();
  page.on('pageerror', e=>report.errors.push(e.message));
  page.setDefaultTimeout(60000);
  await page.goto(base, {waitUntil:'domcontentloaded'});
  await page.getByRole('heading',{name:'服务器总览',exact:true}).waitFor();
  await page.locator('nav').getByRole('button',{name:'软件商店',exact:true}).click();
  const categories = page.getByRole('combobox',{name:'软件分类筛选'});
  const cards = page.locator('.registry-runtime-card');
  for (const [category,count] of [['all',50],['deployment',29],['professional',21]]) {
    await categories.selectOption(category);
    check(await cards.count()===count, `${category} category ${count}`);
  }
  await categories.selectOption('all');
  await page.getByText('云栈官方 GitHub 应用仓库',{exact:true}).waitFor();
  check(await page.locator('.app-registry-source').innerText().then(x=>x.includes(registry.host.architecture)), 'host architecture shown');
  for (const id of expectedUnsupported) {
    const app = registry.catalog.apps.find(x=>x.id===id);
    const card = cards.filter({has:page.getByRole('heading',{name:app.name,exact:true})});
    check(await card.getByRole('button',{name:'当前机器不支持',exact:true}).isDisabled(), `${id} cannot accidentally install`);
  }
  await page.getByRole('combobox',{name:'软件状态筛选'}).selectOption('unavailable');
  check(await cards.count()===expectedUnsupported.length, 'unsupported filter matches API');
  await page.getByRole('combobox',{name:'软件状态筛选'}).selectOption('all');
  await page.screenshot({path:path.join(out,'desktop.png'),animations:'disabled'});
  await page.setViewportSize({width:390,height:844});
  const overflow = await page.evaluate(()=>document.documentElement.scrollWidth-document.documentElement.clientWidth);
  check(overflow<=1, 'mobile has no horizontal overflow');
  await page.screenshot({path:path.join(out,'mobile.png'),animations:'disabled'});
  check(report.errors.length===0, 'no browser runtime errors');
  report.host=registry.host; report.source=registry.source; report.unsupported=expectedUnsupported;
  report.passed=true;
  fs.writeFileSync(path.join(out,'acceptance.json'),JSON.stringify(report,null,2)+'\n');
  console.log(JSON.stringify({passed:true,checks:report.checks.length,host:report.host,unsupported:expectedUnsupported.length}));
  await context.request.post(base+'/api/logout',{headers:{Origin:origin,'X-CSRF-Token':(await login.json()).csrf},data:{}});
} finally {await browser.close();}
