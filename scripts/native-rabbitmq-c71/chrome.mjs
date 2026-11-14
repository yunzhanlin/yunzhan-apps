import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

process.umask(0o077);
assert(process.platform==='linux' && process.arch==='x64' && process.getuid()===0);
assert.equal(process.env.GITHUB_ACTIONS,'true');
assert.equal(process.env.GITHUB_REPOSITORY,'yunzhanlin/yunzhan-apps');
const out=path.join(process.argv[2],'business-phase1');
const { chromium }=await import(pathToFileURL(process.argv[3]));
const read=file=>JSON.parse(readFileSync(file,'utf8'));
const fixture=read(path.join(out,'chrome-fixture.json'));
const source=read(path.join(path.dirname(fileURLToPath(import.meta.url)),'cohort.json'));
const app=source.application;
const programme={source:source.source_inputs_sha256};
const web='/opt/panel/current/web';
assert.equal(read('/opt/panel/current/SOURCE_INPUTS.json').inputs_sha256,programme.source);
const credentials=read('/etc/panel/first-login.json');
const origin='http://127.0.0.1:19100';
const queueRoute='/api/docker/projects/'+fixture.id+'/rabbitmq-queues';
const sha=value=>createHash('sha256').update(value).digest('hex');
const proof={ok:false,source:programme.source,guest:'native-ubuntu-24.04-amd64'};
let browser, context, page, csrf;
try {
  browser = await chromium.launch({executablePath:'/usr/bin/google-chrome',headless:true,args:['--no-sandbox','--disable-background-networking']});
  context = await browser.newContext({viewport:{width:1440,height:1000},locale:'zh-CN',serviceWorkers:'block',acceptDownloads:true});
  await context.route('**/*',route => {
    const request = route.request(), url = new URL(request.url());
    return url.origin === origin && (request.method() === 'GET' ||
      (request.method() === 'POST' && ['/api/login','/api/logout','/api/session/activity'].includes(url.pathname))) ? route.continue() : route.abort();
  });
  page = await context.newPage();
  page.setDefaultTimeout(35_000);
  const html=await page.goto(origin+'/',{waitUntil:'load'});
  assert.equal(sha(await html.body()),sha(readFileSync(path.join(web,'index.html'))));
  for(const name of await page.locator('script[type=module][src]').evaluateAll(nodes=>nodes.map(node=>new URL(node.src).pathname))){
    assert.match(name,/^\/assets\/[A-Za-z0-9_.-]+\.js$/);
    const asset=await context.request.get(origin+name);
    assert.equal(sha(await asset.body()),sha(readFileSync(path.join(web,name))));
  }
  await page.getByLabel('用户名',{exact:true}).fill(credentials.username);
  await page.getByLabel('密码',{exact:true}).fill(credentials.password);
  credentials.password = '';
  const [login] = await Promise.all([
    page.waitForResponse(response => response.url() === origin + '/api/login' && response.request().method() === 'POST'),
    page.getByRole('button',{name:'进入工作台',exact:true}).click(),
  ]);
  assert.equal(login.status(),200,await login.text());
  csrf = (await login.json()).csrf;
  assert(csrf);
  await page.getByRole('button',{name:'软件商店',exact:true}).click();
  await page.getByRole('button',{name:'全部软件',exact:true}).click();
  const [registry]=await Promise.all([
    page.waitForResponse(reply=>reply.url()===origin+'/api/app-registry?refresh=1',{timeout:100000}),
    page.getByRole('button',{name:'检查更新',exact:true}).click(),
  ]);
  assert.equal(registry.status(),200);
  const verified=await registry.json();
  assert.equal(verified.source.resolved_commit,source.served_head);
  assert.deepEqual(verified.catalog.apps.find(x=>x.id===app.id),app);
  const current=verified.status.find(x=>x.id===app.id);
  assert(current?.state_known && current.installed && current.installed_version==='4.1-compat1' && !current.update_available);
  await page.getByRole('textbox',{name:'搜索软件',exact:true}).fill(app.name);
  const card=page.locator('article.registry-runtime-card').filter({has:page.getByRole('heading',{name:app.name,exact:true})});
  await card.getByRole('button',{name:'打开管理',exact:true}).click();
  const panel=page.getByRole('dialog',{name:'Docker 管理',exact:true});
  const project=panel.locator('[data-compose-project="'+fixture.name+'"]');
  const [first]=await Promise.all([
    page.waitForResponse(r=>new URL(r.url()).pathname===queueRoute),
    project.getByRole('button',{name:'查看队列',exact:true}).click(),
  ]);
  assert.equal(first.status(),200);
  const snapshot=await first.json();
  assert.equal(snapshot.project_id,fixture.id);
  const dialog=page.getByRole('dialog',{name:fixture.name+' · RabbitMQ 队列',exact:true});
  const table=dialog.getByRole('table',{name:'RabbitMQ 队列表'});
  const backlog=table.getByRole('row',{name:new RegExp(fixture.queue.replaceAll('.','\\.'))});
  await backlog.waitFor();
  assert.equal(await backlog.getByRole('cell').nth(1).innerText(),String(fixture.expected_ready));
  assert.equal(await backlog.getByRole('cell').nth(2).innerText(),'0');
  assert.equal(await backlog.getByRole('cell').nth(3).innerText(),'0');
  await dialog.screenshot({path:path.join(out,'queue-backlog.png')});
  const search=dialog.getByRole('textbox',{name:'搜索队列'});
  await search.fill('no-owned-match');
  await dialog.getByText('没有匹配的队列',{exact:true}).waitFor();
  await search.clear();
  await backlog.waitFor();
  await dialog.getByRole('combobox',{name:'虚拟主机'}).click();
  const [other]=await Promise.all([
    page.waitForResponse(r=>new URL(r.url()).pathname===queueRoute && new URL(r.url()).searchParams.get('vhost')===fixture.alternate_vhost),
    page.getByRole('option',{name:fixture.alternate_vhost,exact:true}).click(),
  ]);
  assert.equal(other.status(),200);
  assert.deepEqual((await other.json()).queues,[]);
  await dialog.getByText('该虚拟主机还没有队列',{exact:true}).waitFor();
  await page.setViewportSize({width:390,height:844});
  await dialog.screenshot({path:path.join(out,'empty-vhost-390px.png')});
  const bounds=await dialog.boundingBox();
  assert(bounds && bounds.x>=0 && bounds.x+bounds.width<=391);

  Object.assign(proof,{ok:true,queue_counts_and_virtual_hosts:true,signed_frontend_bytes_verified:true,
    signed_application:app.version,queue_counts:[fixture.expected_ready,0,0],browser:browser.version(),viewport:390});
  console.log(JSON.stringify({ok:true,out}));
} catch (error) {
  if (page) { await page.screenshot({path:path.join(out,'failure.png')}).catch(() => {}); await page.getByRole('dialog').ariaSnapshot({timeout:4000}).then(snapshot=>writeFileSync(path.join(out,'failure-dialog.txt'),snapshot)).catch(()=>{}); }
  throw error;
} finally {
  if (csrf && context) {
    const logout=await context.request.post(origin+'/api/logout',
      {data:{},headers:{Origin:origin,'X-CSRF-Token':csrf},maxRedirects:0,timeout:8000}).catch(()=>null);
    proof.logged_out=logout?.status()===200;
    proof.ok=proof.ok && proof.logged_out;
  }
  writeFileSync(path.join(out,'original-browser-proof.json'),JSON.stringify(proof,null,2)+'\n',{flag:'wx'});
  await browser?.close();

}
