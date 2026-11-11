import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, openSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';
import { chromium } from 'playwright-core';

assert(process.platform === 'linux' && process.getuid() > 0 && process.env.GITHUB_ACTIONS === 'true');
assert.equal(process.env.GITHUB_REPOSITORY, 'yunzhanlin/yunzhan-apps');
process.umask(0o077);
const evidence = path.resolve(process.argv[2]);
const read = name => JSON.parse(readFileSync(path.join(evidence, name)));
const setup = read('browser-setup.json');
const business = read('business-phase1/original-proof.json');
assert(business.ok && business.architecture === setup.architecture);
const output = path.join(evidence, 'business-browser');
mkdirSync(output, { mode: 0o700 });
const profile = mkdtempSync(path.join(tmpdir(), 'c75-chromium-'));
const origin = 'http://127.0.0.1:19100';
const proof = { ok: false, architecture: setup.architecture, source_inputs_sha256: setup.source_inputs_sha256 };
const log = openSync(path.join(output, 'chromium.log'), 'wx', 0o600);
const child = spawn(setup.chrome, [
  '--headless=new', '--remote-debugging-port=0', '--remote-debugging-address=127.0.0.1',
  '--no-first-run', '--no-default-browser-check', '--disable-background-networking',
  '--user-data-dir=' + profile, 'about:blank',
], { env: { PATH: '/usr/bin:/bin', HOME: profile, LANG: 'C.UTF-8', CHROME_DEVEL_SANDBOX: setup.sandbox },
  stdio: ['ignore', log, log] });
let browser, context, csrf, password;

try {
  const endpoint = path.join(profile, 'DevToolsActivePort');
  const until = Date.now() + 20_000;
  while (!existsSync(endpoint) && Date.now() < until && child.exitCode === null) await sleep(100);
  assert(existsSync(endpoint));
  const [port, socket] = readFileSync(endpoint, 'utf8').trim().split('\n');
  assert(/^\d+$/.test(port) && socket.startsWith('/devtools/browser/'));
  browser = await chromium.connectOverCDP('ws://127.0.0.1:' + port + socket);
  assert(browser.version().includes(setup.browser_version));
  context = await browser.newContext({ viewport: { width: 1440, height: 950 }, locale: 'zh-CN' });
  await context.grantPermissions(['clipboard-read', 'clipboard-write'], { origin });
  const page = await context.newPage();
  page.setDefaultTimeout(25_000);
  await page.goto(origin + '/', { waitUntil: 'load' });
  const access = read('browser-credentials.json');
  await page.getByLabel('用户名', { exact: true }).fill(access.username);
  await page.getByLabel('密码', { exact: true }).fill(access.password);
  access.password = '';
  const [login] = await Promise.all([
    page.waitForResponse(r => r.url() === origin + '/api/login' && r.request().method() === 'POST'),
    page.getByRole('button', { name: '进入工作台', exact: true }).click(),
  ]);
  assert.equal(login.status(), 200);
  csrf = (await login.json()).csrf;
  assert(csrf);
  await page.getByRole('button', { name: '软件商店', exact: true }).click();
  await page.getByRole('button', { name: '全部软件', exact: true }).click();
  await page.getByRole('textbox', { name: '搜索软件', exact: true }).fill('Elasticsearch');
  const card = page.locator('article.registry-runtime-card').filter({ has: page.getByRole('heading', { name: 'Elasticsearch', exact: true }) });
  await card.getByRole('button', { name: '打开管理', exact: true }).click();
  const manager = page.getByRole('dialog', { name: 'Docker 管理', exact: true });
  const existing = manager.locator('.project-row[data-compose-project^="c75-existing-"]');
  const managed = manager.locator('.project-row[data-compose-project^="c75-store-"]');
  await existing.waitFor();
  assert.equal(await existing.getByRole('button', { name: '访问凭据', exact: true }).count(), 0);
  const button = managed.getByRole('button', { name: '访问凭据', exact: true });
  const dialog = page.getByRole('dialog', { name: '连接信息与初始凭据', exact: true });
  async function openCredentials() {
    const [reply] = await Promise.all([
      page.waitForResponse(r => r.url() === origin + '/api/docker/projects/' + business.project_id + '/credentials' && r.request().method() === 'POST'),
      button.click(),
    ]);
    assert.equal(reply.status(), 200);
    assert.equal(reply.headers()['cache-control'], 'no-store');
    const data = await reply.json();
    assert.equal(data.project_id, business.project_id);
    password = data.credentials.ELASTIC_PASSWORD;
    assert(/^[a-f0-9]{32,}$/.test(password));
    await dialog.getByText('已隐藏', { exact: true }).waitFor();
    assert((await dialog.innerText()).includes('检索接口（HTTP）'));
    assert((await dialog.innerText()).includes('127.0.0.1:26579'));
    await dialog.getByText('elastic', { exact: true }).waitFor();
    assert(!(await page.evaluate(value => document.body.textContent.includes(value), password)));
  }
  await openCredentials();
  await dialog.screenshot({ path: path.join(output, 'original-hidden-credentials.png') });
  await dialog.getByRole('button', { name: '显示密码', exact: true }).click();
  await dialog.getByRole('button', { name: '复制密码', exact: true }).click();
  assert(await page.evaluate(async value => (await navigator.clipboard.readText()) === value, password));
  await page.evaluate(() => navigator.clipboard.writeText(''));
  await dialog.getByRole('button', { name: '关闭', exact: true }).click();
  await dialog.waitFor({ state: 'hidden' });
  await openCredentials();
  await dialog.getByRole('button', { name: '关闭', exact: true }).click();
  proof.ok = true;
  proof.native_browser_version = browser.version();
  proof.legacy_credential_control_absent = true;
  proof.initial_password_no_store_hidden_and_copy_verified = true;
} catch (error) {
  const raw = String(error?.stack || error);
  proof.failure = password ? raw.replaceAll(password, '[private]') : raw;
} finally {
  if (csrf) {
    try {
      const logout = await context.request.post(origin + '/api/logout', { data: {}, headers: { Origin: origin, 'X-CSRF-Token': csrf } });
      proof.logged_out = logout.status() === 200;
    } catch { proof.logged_out = false; }
    proof.ok &&= proof.logged_out;
  }
  await context?.close().catch(() => {});
  await browser?.close().catch(() => {});
  if (child.exitCode === null && child.signalCode === null) {
    const exited = new Promise(resolve => child.once('exit', resolve));
    child.kill('SIGTERM');
    await Promise.race([exited, sleep(5000)]);
  }
  writeFileSync(path.join(output, 'original-proof.json'), JSON.stringify(proof, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
}
process.exitCode = proof.ok ? 0 : 1;
