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
const profile = mkdtempSync(path.join(tmpdir(), 'c77-chromium-'));
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
  const pmaOrigin = 'http://127.0.0.1:26581';
  const here = path.dirname(new URL(import.meta.url).pathname);
  const mysql = read('owned-mysql-browser.json');
  assert(/^[0-9a-f]{32}$/.test(mysql.server_id) && mysql.name === 'c77fixture');
  password = mysql.password;
  delete mysql.password;
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
  const [localDatabases] = await Promise.all([
    page.waitForResponse(r => r.url() === origin + '/api/databases' && r.request().method() === 'GET'),
    card.getByRole('button', { name: '安装', exact: true }).click(),
  ]);
  assert.equal(localDatabases.status(), 200);
  assert((await localDatabases.json()).servers.some(v => v.id === mysql.server_id && v.status === 'running'));
  const prompt = page.locator('.el-message-box').filter({ hasText: '安装 phpMyAdmin' });
  await prompt.getByLabel('管理端口（服务器回环）', { exact: true }).fill('26581');
  await prompt.getByLabel('数据库服务器', { exact: true }).selectOption(mysql.server_id);
  proof.local_instance_present_in_interactive_selector = true;
  await prompt.screenshot({ path: path.join(output, 'original-local-mysql-selector.png') });
  const [accepted] = await Promise.all([
    page.waitForResponse(r => r.url() === origin + '/api/app-registry/phpmyadmin/install' && r.request().method() === 'POST'),
    prompt.getByRole('button', { name: '验签并安装', exact: true }).click(),
  ]);
  assert.equal(accepted.status(), 202);
  const input = accepted.request().postDataJSON();
  assert.equal(input.expected_version, cohort.application.version);
  assert.equal(input.expected_sha256, cohort.application.sha256);
  assert.equal(input.host_port, 26581);
  assert.deepEqual(input.settings, { mysql_server_id: mysql.server_id });
  const receipt = await accepted.json();
  assert(/^[a-f0-9]{32}$/.test(receipt.project_id) && /^[a-f0-9]{32}$/.test(receipt.job_id));
  proof.original_install_job = receipt.job_id;
  const job = await untilValue(() => request('/docker/job-observations/' + receipt.job_id),
    v => ['succeeded', 'failed'].includes(v.state), 660_000);
  if (job.state === 'failed') {
    proof.original_install_job_error = job.error;
    const unit = 'panel-phpmyadmin-db@' + receipt.project_id + '-' + mysql.server_id + '.service';
    const log = spawnSync('/usr/bin/sudo', ['-n', '/usr/bin/journalctl', '--no-pager', '-n', '45', '-u', unit],
      { timeout: 20_000, encoding: 'utf8', maxBuffer: 128 << 10 });
    writeFileSync(path.join(output, 'relay-journal.txt'), log.stdout || '', { flag: 'wx', mode: 0o600 });
  }
  assert.equal(job.state, 'succeeded');
  assert.equal(job.project_id, receipt.project_id);
  const current = await untilValue(async () => (await request('/docker/projects')).projects.find(p => p.id === receipt.project_id),
    v => v?.state === 'running' && v?.healthy === 1);
  assert.equal(current.host_port, 26581);
  assert.equal(current.template_id, 'phpmyadmin');
  assert.equal(current.mysql_server_id, mysql.server_id);
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
  assert.deepEqual(pma.HostConfig.PortBindings, { '80/tcp': [{ HostIp: '127.0.0.1', HostPort: '26581' }] });
  assert(!pma.HostConfig.Privileged);
  const mount = pma.Mounts.find(v => v.Destination === '/run/panel-db');
  assert(mount?.Type === 'bind' && mount.RW === false);
  const expectedSource = '/run/panel-phpmyadmin-db-' + receipt.project_id + '-' + mysql.server_id;
  assert.equal(mount.Source, expectedSource);
  assert(pma.Config.Env.includes('PMA_HOST=localhost'));
  assert(pma.Config.Env.includes('PMA_SOCKET=/run/panel-db/mysql.sock'));
  assert(!pma.Config.Env.includes('PMA_ARBITRARY=1'));
  const root = (exe, args, input, timeout = 45_000) => {
    const r = spawnSync('/usr/bin/sudo', ['-n', exe, ...args], { input, timeout, encoding: 'utf8' });
    assert.equal(r.status, 0, 'Fixture observation failed for ' + exe);
    return r.stdout.trim();
  };
  const service = 'panel-phpmyadmin-db@' + receipt.project_id + '-' + mysql.server_id + '.service';
  assert.equal(root('/usr/bin/systemctl', ['show', service, '-p', 'DynamicUser', '--value']), 'yes');
  const relayPID = Number(root('/usr/bin/systemctl', ['show', service, '-p', 'MainPID', '--value']));
  assert(Number.isSafeInteger(relayPID) && relayPID > 1);
  assert.match(root('/usr/bin/cat', ['/proc/' + relayPID + '/status']), /^Uid:\s+[1-9][0-9]*\s/m);
  const dbSocket = '/run/panel-mysql-' + mysql.server_id + '/mysql.sock';
  const originalSocket = root('/usr/bin/stat', ['-c', '%d:%i', dbSocket]);
  const query = sql => root('/opt/panel/current/bin/panel-executor', ['--database-cli', mysql.server_id,
    '--', '--batch', '--skip-column-names', mysql.name], sql + '\n');
  assert.equal(query('SELECT value FROM proof WHERE id=1;'), 'before-ui');

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
  assert.equal(await view.locator('#serverNameInput').count(), 0);
  await view.locator('#input_username').fill(mysql.username);
  await view.locator('#input_password').fill(password);
  await view.locator('#input_go').click();
  await view.locator('#pma_navigation').waitFor();
  proof.real_mysql_login = true;
  await view.goto(pmaOrigin + '/index.php?route=/database/sql&db=c77fixture', { waitUntil: 'load' });
  async function submitSQL(sql) {
    const form = view.locator('#sqlqueryform');
    await form.waitFor();
    const action = new URL(await form.getAttribute('action'), view.url());
    assert.equal(action.origin, pmaOrigin);
    assert.equal(action.searchParams.get('route'), '/import');
    const [response] = await Promise.all([
      view.waitForResponse(r => r.url() === action.href && r.request().method() === 'POST'),
      form.evaluate((element, value) => {
        element.querySelector('textarea[name=sql_query]').value = value;
        HTMLFormElement.prototype.submit.call(element);
      }, sql),
    ]);
    assert([200, 302, 303].includes(response.status()));
    return response.status();
  }
  proof.sql_update_http = await submitSQL("UPDATE proof SET value='written-by-ui' WHERE id=1;");
  assert.equal(query('SELECT id, value FROM proof WHERE id=1;'), '1\twritten-by-ui');
  for (const action of ['stop', 'start']) {
    const mutation = await context.request.post(origin + '/api/databases/instances/' + mysql.server_id + '/' + action, {
      data: {}, headers: { Origin: origin, 'X-CSRF-Token': csrf, 'Idempotency-Key': randomBytes(16).toString('hex') },
    });
    assert.equal(mutation.status(), 202);
    const result = await mutation.json();
    assert(/^[a-f0-9]{32}$/.test(result.job_id));
    const observe = 'import json,sqlite3,sys; db=sqlite3.connect("file:/var/lib/panel/panel.db?mode=ro",uri=True); print(json.dumps(db.execute("SELECT target_id,state,error FROM mysql_jobs WHERE id=?",(sys.argv[1],)).fetchone()))';
    const state = await untilValue(() => JSON.parse(root('/usr/bin/python3', ['-I', '-B', '-c', observe, result.job_id])),
      v => v && ['succeeded', 'failed'].includes(v[1]));
    assert.deepEqual(state, [mysql.server_id, 'succeeded', '']);
    proof[action + '_database_job'] = result.job_id;
  }
  assert.notEqual(root('/usr/bin/stat', ['-c', '%d:%i', dbSocket]), originalSocket);
  assert.equal(root('/usr/bin/systemctl', ['show', service, '-p', 'MainPID', '--value']), String(relayPID));
  await view.goto(pmaOrigin + '/index.php?route=/database/sql&db=c77fixture', { waitUntil: 'load' });
  proof.sql_select_http_after_mysql_restart = await submitSQL('SELECT value FROM proof WHERE id=1;');
  await view.getByText('written-by-ui', { exact: true }).waitFor();
  proof.ok = true;
  proof.native_browser_version = browser.version();
  proof.scoped_manager_and_direct_browser_link = true;
  proof.owned_mysql_version = query('SELECT @@version;');
  proof.verified_sql_write_via_real_browser = true;
  proof.mysql_original_process_restarted_original_relay_retained = true;
  proof.mysql_signed_runtime_job = mysql.original_runtime_job;
  proof.local_unix_proxy_non_root_read_only = true;
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
