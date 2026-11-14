import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

process.umask(0o077);
assert(process.platform === "linux" && process.arch === "x64" && process.getuid() === 0);
assert.equal(process.env.GITHUB_ACTIONS, "true");
assert.equal(process.env.GITHUB_REPOSITORY, "yunzhanlin/yunzhan-apps");
const output = path.join(process.argv[2], "business-phase1");
const { chromium } = await import(pathToFileURL(process.argv[3]));
const read = file => JSON.parse(readFileSync(file, "utf8"));
const fixture = read(path.join(output, "chrome-migration-fixture.json"));
const source = read(path.join(path.dirname(fileURLToPath(import.meta.url)), "cohort.json"));
const credentials = read("/etc/panel/first-login.json");
const signedWeb = "/opt/panel/current/web";
const origin = "http://127.0.0.1:19100";
const migration = "/api/docker/projects/" + fixture.project + "/rabbitmq-migrations";
const digest = bytes => createHash("sha256").update(bytes).digest("hex");
assert.equal(read("/opt/panel/current/SOURCE_INPUTS.json").inputs_sha256, source.source_inputs_sha256);

const browser = await chromium.launch({ executablePath: "/usr/bin/google-chrome", headless: true,
  args: ["--no-sandbox", "--disable-background-networking"] });
const context = await browser.newContext({ viewport: { width: 1440, height: 1000 }, locale: "zh-CN",
  serviceWorkers: "block" });
const proof = { ok: false, source: source.source_inputs_sha256 };
let csrf, requestId, submits = 0;
const page = await context.newPage();
page.setDefaultTimeout(40000);
await context.route("**/*", route => {
  const request = route.request(), url = new URL(request.url());
  if (url.origin !== origin) return route.abort();
  if (request.method() === "GET") return route.continue();
  if (request.method() !== "POST") return route.abort();
  if (["/api/login", "/api/logout", "/api/session/activity"].includes(url.pathname)) return route.continue();
  if (url.pathname !== migration || ++submits !== 1) return route.abort();
  assert.deepEqual(request.postDataJSON(), fixture.payload);
  requestId = request.headers()["idempotency-key"];
  assert.match(requestId, /^[a-f0-9]{32}$/);
  return route.continue();
});

try {
  const html = await page.goto(origin + "/", { waitUntil: "load" });
  assert.equal(digest(await html.body()), digest(readFileSync(path.join(signedWeb, "index.html"))));
  await page.getByLabel("用户名", { exact: true }).fill(credentials.username);
  await page.getByLabel("密码", { exact: true }).fill(credentials.password);
  credentials.password = "";
  const [login] = await Promise.all([
    page.waitForResponse(r => r.url() === origin + "/api/login"),
    page.getByRole("button", { name: "进入工作台", exact: true }).click(),
  ]);
  csrf = (await login.json()).csrf;
  assert.equal(login.status(), 200);
  assert(csrf);
  await page.getByRole("button", { name: "软件商店", exact: true }).click();
  await page.getByRole("button", { name: "全部软件", exact: true }).click();
  const [registry] = await Promise.all([
    page.waitForResponse(r => r.url() === origin + "/api/app-registry?refresh=1", { timeout: 100000 }),
    page.getByRole("button", { name: "检查更新", exact: true }).click(),
  ]);
  const verified = await registry.json();
  assert.equal(verified.source.resolved_commit, source.served_head);
  assert.deepEqual(verified.catalog.apps.find(x => x.id === "rabbitmq"), source.application);
  assert(verified.status.find(x => x.id === "rabbitmq").update_available);
  await page.getByRole("textbox", { name: "搜索软件", exact: true }).fill("RabbitMQ");
  const card = page.locator("article.registry-runtime-card").filter({ has: page.getByRole("heading", { name: "RabbitMQ", exact: true }) });
  await card.getByRole("button", { name: "打开管理", exact: true }).click();
  const manager = page.getByRole("dialog", { name: "Docker 管理", exact: true });
  await manager.locator('[data-compose-project="' + fixture.name + '"]').getByRole("button", { name: "RabbitMQ 迁移", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: fixture.name + " · RabbitMQ 迁移", exact: true });
  const start = dialog.getByRole("button", { name: "开始迁移", exact: true });
  await start.waitFor();
  assert(await start.isDisabled());
  const shutdownLabel = "我已停止发件和消费任务，并确认维护停机";
  await dialog.getByText(shutdownLabel, { exact: true }).click();
  assert(await dialog.getByRole("checkbox", { name: shutdownLabel, exact: true }).isChecked());
  await page.setViewportSize({ width: 390, height: 844 });
  const bounds = await dialog.boundingBox();
  assert(bounds && bounds.x >= 0 && bounds.x + bounds.width <= 391);
  await dialog.screenshot({ path: path.join(output, "browser-migration-preflight.png") });

  const [submitted] = await Promise.all([
    page.waitForResponse(r => r.url() === origin + migration && r.request().method() === "POST", { timeout: 90000 }),
    start.click(),
  ]);
  assert.equal(submitted.status(), 202);
  const accepted = await submitted.json();
  assert.match(accepted.job_id, /^[a-f0-9]{32}$/);
  assert.equal(accepted.project_id, fixture.project);
  assert.equal(accepted.request_id, requestId);
  await dialog.getByText("已升级至 4.4.0", { exact: true }).waitFor({ timeout: 900000 });
  assert.equal(submits, 1);
  await dialog.screenshot({ path: path.join(output, "browser-migration-completed.png") });
  Object.assign(proof, { ok: true, job: accepted.job_id, request: accepted.request_id,
    project: fixture.project, viewport: 390, signed_catalogue: verified.source.resolved_commit,
    browser: browser.version(), submitted_after_explicit_downtime_consent: true });
} finally {
  if (csrf) {
    const logout = await context.request.post(origin + "/api/logout", {
      data: {}, headers: { Origin: origin, "X-CSRF-Token": csrf }, maxRedirects: 0, timeout: 8000,
    }).catch(() => null);
    proof.logged_out = logout?.status() === 200;
    proof.ok &&= proof.logged_out;
  }
  writeFileSync(path.join(output, "original-browser-migration-proof.json"), JSON.stringify(proof, null, 2) + "\n", { flag: "wx" });
  await browser.close();
}
assert(proof.ok);
