import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const catalog = JSON.parse(await readFile(new URL("../dist/catalog-v1.json", import.meta.url), "utf8"));

test("requested deployment and professional groups are complete", () => {
  assert.equal(catalog.apps.filter((item) => item.category === "deployment").length, 29);
  assert.equal(catalog.apps.filter((item) => item.category === "professional").length, 21);
});

test("only integrated packages can be advertised as ready", () => {
  for (const item of catalog.apps.filter((app) => app.stage === "ready")) {
    assert.match(item.sha256, /^[a-f0-9]{64}$/);
    assert.match(item.package_url, /^https:\/\/raw\.githubusercontent\.com\/yunzhanlin\/yunzhan-apps\/main\/dist\//);
  }
});

test("legacy PHP packages cannot use host runtimes", async () => {
  const legacy = catalog.apps.filter((item) => item.id.startsWith("php-") && Number(item.id.split("-")[1]) <= 81);
  assert.equal(legacy.length,12);
  for(const item of legacy){
    const manifest=JSON.parse(await readFile(new URL('../dist/apps/'+item.id+'/'+item.version+'/manifest.json',import.meta.url),'utf8'));
    assert.equal(manifest.risk,'eol');assert.equal(manifest.delivery.provider,'compose');assert.equal(manifest.delivery.isolation,'legacy-container');
    assert.match(manifest.delivery.image,/@sha256:[a-f0-9]{64}$/);
  }
});
