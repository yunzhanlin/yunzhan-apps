import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
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
const output = path.join(evidence, 'business-phase1');
mkdirSync(output, { mode: 0o700 });
const profile = mkdtempSync(path.join(tmpdir(), 'c76-chromium-'));
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
  const pmaOrigin = 'http://127.0.0.1:26580';
  const here = path.dirname(new URL(import.meta.url).pathname);
  const mysql = JSON.parse(readFileSync(path.join(here, 'mysql-fixture-pin.json')));
  const cohort = JSON.parse(readFileSync(path.join(here, 'cohort.json')));
  const request = async route => {
    const result = await context.request.get(origin + '/api' + route);
    assert.equal(result.status(), 200);
    return result.json();
  };
  const untilValue = async (readValue, valid, max = 240_000) => {
    const until = Date.now() + max;
    let value;
    do {
      value = await readValue();
      if (valid(value)) return value;
      await sleep(1500);
    } while (Date.now() < until);
    throw new Error('Expected original result did not settle');
  };
  await page.getByRole('button', { name: '软件商店', exact: true }).click();
  await page.getByRole('button', { name: '全部软件', exact: true }).click();
  await page.getByRole('textbox', { name: '搜索软件', exact: true }).fill('phpMyAdmin');
  const card = page.locator('article.registry-runtime-card').filter({ has: page.getByRole('heading', { name: 'phpMyAdmin', exact: true }) });
  await card.getByRole('button', { name: '安装', exact: true }).click();
  const prompt = page.locator('.el-message-box').filter({ hasText: '安装 phpMyAdmin' });
  await prompt.getByRole('textbox').fill('26580');
  const [accepted] = await Promise.all([
    page.waitForResponse(r => r.url() === origin + '/api/app-registry/phpmyadmin/install' && r.request().method() === 'POST'),
    prompt.getByRole('button', { name: '验签并安装', exact: true }).click(),
  ]);
  assert.equal(accepted.status(), 202);
  const input = accepted.request().postDataJSON();
  assert.equal(input.expected_version, cohort.application.version);
  assert.equal(input.expected_sha256, cohort.application.sha256);
  assert.equal(input.host_port, 26580);
  const receipt = await accepted.json();
  assert(/^[a-f0-9]{32}$/.test(receipt.project_id) && /^[a-f0-9]{32}$/.test(receipt.job_id));
  proof.original_install_job = receipt.job_id;
  const job = await untilValue(() => request('/docker/job-observations/' + receipt.job_id),
    v => ['succeeded', 'failed'].includes(v.state), 660_000);
  assert.equal(job.state, 'succeeded');
  assert.equal(job.project_id, receipt.project_id);
  const current = await untilValue(async () => (await request('/docker/projects')).projects.find(p => p.id === receipt.project_id),
    v => v?.state === 'running' && v?.healthy === 1);
  assert.equal(current.host_port, 26580);
  assert.equal(current.template_id, 'phpmyadmin');
  assert.equal(current.engine_name, 'panel_' + receipt.project_id.slice(0, 12));

  const runDocker = (args, input, timeout = 45_000) => spawnSync('/usr/bin/sudo', ['-n', '/usr/bin/docker', ...args],
    { input, timeout, encoding: 'utf8', maxBuffer: 1 << 20 });
  const docker = (args, stdin, timeout) => {
    const r = runDocker(args, stdin, timeout);
    assert.equal(r.status, 0, 'Fixture Docker command failed: ' + args[0]);
    return r.stdout.trim();
  };
  const ids = docker(['ps', '-aq', '--filter', 'label=com.docker.compose.project=' + current.engine_name]);
  assert(/^[a-f0-9]{12,64}$/.test(ids));
  const [pma] = JSON.parse(docker(['inspect', ids]));
  assert.equal(pma.Config.Image, cohort.image);
  assert.deepEqual(pma.HostConfig.PortBindings, { '80/tcp': [{ HostIp: '127.0.0.1', HostPort: '26580' }] });
  assert(!pma.HostConfig.Privileged);
  const networks = Object.keys(pma.NetworkSettings.Networks);
  assert.deepEqual(networks, [current.engine_name + '_default']);
  const network = networks[0];
  const [ownedNetwork] = JSON.parse(docker(['network', 'inspect', network]));
  assert.equal(ownedNetwork.Labels['com.docker.compose.project'], current.engine_name);
  password = randomBytes(24).toString('hex');
  const dbEnv = path.join(output, 'owned-mysql-fixture.env');
  writeFileSync(dbEnv, `MYSQL_ROOT_PASSWORD=${randomBytes(24).toString('hex')}\nMYSQL_ROOT_HOST=localhost\nMYSQL_DATABASE=c76fixture\nMYSQL_USER=qa_user\nMYSQL_PASSWORD=${password}\n`, { flag: 'wx', mode: 0o600 });
  const db = docker(['run', '--detach', '--name', 'c76-mysql-fixture', '--network', network,
    '--network-alias', 'qa-mysql', '--env-file', dbEnv, mysql.image], undefined, 600_000);
  assert(/^[a-f0-9]{64}$/.test(db));
  const [database] = JSON.parse(docker(['inspect', db]));
  assert.equal(database.Image, mysql.platforms[setup.architecture].config);
  assert.equal(Object.keys(database.HostConfig.PortBindings || {}).length, 0);
  function query(sql) {
    return runDocker(['exec', '-i', db, '/bin/sh', '-c',
      'IFS= read -r MYSQL_PWD; export MYSQL_PWD; exec mysql --protocol=TCP --host=127.0.0.1 -uqa_user --batch --skip-column-names c76fixture'],
      password + '\n' + sql + '\n');
  }
  const dbReady = await untilValue(() => query('SELECT @@version;'), v => v.status === 0, 120_000);
  assert.match(dbReady.stdout.trim(), /^8\.4\.13/);
  const seed = query("CREATE TABLE proof (id INT PRIMARY KEY, value VARCHAR(30) NOT NULL); INSERT INTO proof VALUES (1,'before-ui');");
  assert.equal(seed.status, 0);

  const manager = page.getByRole('dialog', { name: 'phpMyAdmin 管理', exact: true });
  await manager.waitFor();
  await manager.locator('.el-dialog__headerbtn').click();
  await manager.waitFor({ state: 'hidden' });
  await page.getByRole('button', { name: '检查更新', exact: true }).click();
  await card.getByRole('button', { name: '打开管理', exact: true }).click();
  const item = manager.locator('.project-row').filter({ hasText: current.name });
  const link = item.getByRole('link', { name: '打开 phpMyAdmin', exact: true });
  await link.waitFor();
  assert.equal(await link.getAttribute('href'), pmaOrigin + '/');
  assert.equal(await manager.locator('[data-compose-project]').count(), 1);
  await manager.screenshot({ path: path.join(output, 'original-phpmyadmin-manager.png') });
  const [view] = await Promise.all([context.waitForEvent('page'), link.click()]);
  await view.waitForLoadState('load');
  assert.equal(new URL(view.url()).origin, pmaOrigin);
  proof.scoped_manager_and_direct_browser_link = true;
  await view.locator('#serverNameInput').fill('qa-mysql');
  await view.locator('#input_username').fill('qa_user');
  await view.locator('#input_password').fill(password);
  await view.locator('#input_go').click();
  await view.locator('#pma_navigation').waitFor();
  proof.real_mysql_login = true;
  await view.goto(pmaOrigin + '/index.php?route=/database/sql&db=c76fixture', { waitUntil: 'load' });
  const sql = "UPDATE proof SET value='written-by-ui' WHERE id=1;";
  const sqlForm = view.locator('#sqlqueryform');
  await sqlForm.waitFor();
  await view.evaluate(value => {
    const mirror = document.querySelector('.CodeMirror')?.CodeMirror;
    if (mirror) mirror.setValue(value);
    document.querySelector('#sqlquery').value = value;
  }, sql);
  const [written] = await Promise.all([
    view.waitForResponse(r => new URL(r.url()).origin === pmaOrigin && r.request().method() === 'POST' && new URL(r.url()).searchParams.get('route') === '/import'),
    sqlForm.locator('#button_submit_query').click(),
  ]);
  assert.equal(written.status(), 200);
  const committed = query('SELECT id, value FROM proof WHERE id=1;');
  assert.equal(committed.status, 0);
  assert.equal(committed.stdout.trim(), '1\twritten-by-ui');
  proof.ok = true;
  proof.native_browser_version = browser.version();
  proof.scoped_manager_and_direct_browser_link = true;
  proof.owned_mysql_version = dbReady.stdout.trim();
  proof.verified_sql_write_via_real_browser = true;
  proof.backend_scope = 'isolated MySQL 8.4 fixture, original phpMyAdmin arbitrary-server connection';
  await view.close();
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
