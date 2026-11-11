import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, openSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';
import { chromium } from 'playwright-core';

assert.equal(process.platform, 'linux');
assert(process.getuid() > 0 && process.env.GITHUB_ACTIONS === 'true');
assert.equal(process.env.GITHUB_REPOSITORY, 'yunzhanlin/yunzhan-apps');

const evidence = path.resolve(process.argv[2]);
const setup = JSON.parse(readFileSync(path.join(evidence, 'browser-setup.json')));
const output = path.join(evidence, 'business-phase1');
mkdirSync(output, { mode: 0o700 });
const profile = mkdtempSync(path.join(tmpdir(), 'c72-chromium-'));
const origin = 'http://127.0.0.1:19100';
const proof = {
  ok: false,
  architecture: setup.architecture,
  source_inputs_sha256: setup.source_inputs_sha256,
  panel_version: setup.panel_version,
  browser_version: setup.browser_version,
  apps: {},
  Main_changed: false,
  all50_commercial: false,
};

const childLog = openSync(path.join(output, 'chromium.log'), 'wx', 0o600);
const child = spawn(setup.chrome, [
  '--headless=new', '--remote-debugging-port=0', '--remote-debugging-address=127.0.0.1',
  '--no-first-run', '--no-default-browser-check', '--disable-background-networking',
  '--user-data-dir=' + profile, 'about:blank',
], {
  env: { PATH: '/usr/bin:/bin', HOME: profile, LANG: 'C.UTF-8', CHROME_DEVEL_SANDBOX: setup.sandbox },
  stdio: ['ignore', childLog, childLog],
});
let browser;

try {
  const endpointFile = path.join(profile, 'DevToolsActivePort');
  const startupDeadline = Date.now() + 20_000;
  while (!existsSync(endpointFile) && Date.now() < startupDeadline && child.exitCode === null) await sleep(100);
  assert(existsSync(endpointFile), 'Pinned sandboxed Chromium did not start');
  const [port, socket] = readFileSync(endpointFile, 'utf8').trim().split('\n');
  assert(/^\d+$/.test(port) && socket.startsWith('/devtools/browser/'));
  browser = await chromium.connectOverCDP('ws://127.0.0.1:' + port + socket);
  assert(browser.version().includes(setup.browser_version));
  const context = await browser.newContext({ viewport: { width: 1440, height: 950 }, locale: 'zh-CN' });
  await context.grantPermissions(['clipboard-read', 'clipboard-write'], { origin });
  const page = await context.newPage();
  page.setDefaultTimeout(20_000);
  await page.goto(origin + '/', { waitUntil: 'load' });
  const access = JSON.parse(readFileSync(path.join(evidence, 'browser-credentials.json')));
  await page.getByLabel('用户名', { exact: true }).fill(access.username);
  await page.getByLabel('密码', { exact: true }).fill(access.password);
  access.password = '';
  await page.getByRole('button', { name: '进入工作台', exact: true }).click();
  await page.getByRole('button', { name: '软件商店', exact: true }).click();
  await page.getByRole('button', { name: '全部软件', exact: true }).click();

  const manager = page.getByRole('dialog', { name: 'Docker 管理', exact: true });
  const credentials = page.getByRole('dialog', { name: '连接信息与初始凭据', exact: true });
  const search = page.getByRole('textbox', { name: '搜索软件', exact: true });
  const card = app => page.locator('article.registry-runtime-card').filter({
    has: page.getByRole('heading', { name: app.name, exact: true }),
  });
  const readJSON = async route => {
    const response = await context.request.get(origin + '/api' + route);
    assert.equal(response.status(), 200, route);
    return response.json();
  };

  async function observeUntil(label, read, ready, timeoutMs = 240_000) {
    const deadline = Date.now() + timeoutMs;
    let value;
    do {
      value = await read();
      if (ready(value)) return value;
      await sleep(1500);
    } while (Date.now() < deadline);
    throw new Error(label + ' did not reach the expected state');
  }

  async function openCredentials(project, app, capture) {
    const row = manager.locator('.project-row').filter({
      has: manager.getByText(project.name, { exact: true }),
    });
    const responseWaiting = page.waitForResponse(
      response => response.url() === origin + '/api/docker/projects/' + project.id + '/credentials' &&
        response.request().method() === 'POST',
    );
    await row.getByRole('button', { name: '访问凭据', exact: true }).click();
    const response = await responseWaiting;
    assert.equal(response.status(), 200);
    assert.equal(response.headers()['cache-control'], 'no-store');
    const result = await response.json();
    assert.equal(result.project_id, project.id);
    assert.equal(result.template_id, app.id);
    assert.equal(result.host_port, app.port);
    const password = result.credentials[app.password];
    const username = app.username ? result.credentials[app.username] : 'admin';
    assert(typeof password === 'string' && password.length >= 20 && username);
    await credentials.getByRole('heading', { name: project.name, exact: true }).waitFor();
    const details = await credentials.locator('dt').evaluateAll(items => items.map(item => [
      item.textContent.trim(), item.nextElementSibling.querySelector('code')?.textContent.trim() ?? null,
    ]));
    assert.deepEqual(details, [
      ...app.addresses, ...(app.id === 'mongodb' ? [['认证数据库', 'admin']] : []),
      ['用户名', username], ['密码', null],
    ]);
    const passwordInDOM = () => page.evaluate(secret => document.body.textContent.includes(secret), password);
    assert.equal(await passwordInDOM(), false);
    assert.equal(await credentials.getByRole('button', { name: '复制密码', exact: true }).count(), 0);
    await credentials.getByRole('button', { name: '显示密码', exact: true }).click();
    assert.equal(await passwordInDOM(), true);
    await credentials.getByRole('button', { name: '复制密码', exact: true }).click();
    assert(await page.evaluate(async secret => (await navigator.clipboard.readText()) === secret, password));
    await page.evaluate(() => navigator.clipboard.writeText(''));
    await credentials.getByRole('button', { name: '隐藏密码', exact: true }).click();
    assert.equal(await passwordInDOM(), false);
    if (capture) {
      await credentials.screenshot({ path: path.join(output, app.id + '-hidden-password.png') });
      proof.apps[app.id].connection_labels = details;
      proof.apps[app.id].credential_dialog = {
        password_default_hidden: true, explicit_copy_verified: true,
        hidden_again: true, private_response_no_store: true,
      };
    }
    await credentials.getByRole('button', { name: '关闭', exact: true }).click();
    await credentials.waitFor({ state: 'hidden' });
    assert.equal(await passwordInDOM(), false);
  }

  const projects = new Map();
  for (const app of setup.apps) {
    await search.fill(app.name);
    const install = card(app).getByRole('button', { name: '安装', exact: true });
    await install.click();
    const prompt = page.locator('.el-message-box').filter({ hasText: '安装 ' + app.name });
    await prompt.getByRole('textbox').fill(String(app.port));
    const installed = page.waitForResponse(response =>
      response.url() === origin + '/api/app-registry/' + app.id + '/install' && response.request().method() === 'POST');
    await prompt.getByRole('button', { name: '验签并安装', exact: true }).click();
    const response = await installed;
    assert.equal(response.status(), 202, app.id);
    const submitted = response.request().postDataJSON();
    assert.equal(submitted.expected_version, app.version);
    assert.equal(submitted.expected_sha256, app.sha256);
    assert.equal(submitted.host_port, app.port);
    const accepted = await response.json();
    assert(/^[0-9a-f]{32}$/.test(accepted.job_id) && /^[0-9a-f]{32}$/.test(accepted.project_id));
    const job = await observeUntil(app.id + ' original install job',
      () => readJSON('/docker/job-observations/' + accepted.job_id),
      result => result.state === 'succeeded' || result.state === 'failed', 660_000);
    assert.equal(job.state, 'succeeded', app.id + ' original job failed');
    assert.equal(job.project_id, accepted.project_id);
    const project = await observeUntil(app.id + ' healthy project', async () => {
      const result = await readJSON('/docker/projects');
      return result.projects.find(item => item.id === accepted.project_id);
    }, item => item?.state === 'running' && item.healthy === 1);
    assert.equal(project.template_id, app.id);
    assert.equal(project.host_port, app.port);
    projects.set(app.id, project);
    proof.apps[app.id] = {
      original_job: accepted.job_id, original_project: project.id, app_version: app.version,
      healthy_project: true, actual_store_POST_status: response.status(),
    };
    await manager.waitFor();
    await manager.getByRole('button', { name: '刷新', exact: true }).click();
    await openCredentials(project, app, true);
    await manager.locator('.el-dialog__headerbtn').click();
    await manager.waitFor({ state: 'hidden' });
  }

  const first = setup.apps[0];
  await search.fill(first.name);
  await card(first).getByRole('button', { name: '打开管理', exact: true }).click();
  await openCredentials(projects.get(first.id), first, false);
  proof.reopen_after_other_projects_defaults_hidden = true;
  proof.ok = true;
  await context.close();
} catch (error) {
  proof.failure = String(error?.stack || error);
  process.exitCode = 1;
} finally {
  writeFileSync(path.join(output, 'original-proof.json'), JSON.stringify(proof, null, 2) + '\n', {
    flag: 'wx', mode: 0o600,
  });
  if (browser) await browser.close().catch(() => {});
  if (child.exitCode === null) child.kill('SIGTERM');
  rmSync(profile, { recursive: true, force: true });
}
