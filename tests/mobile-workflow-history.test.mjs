import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { createHash } from "node:crypto";
import { beforeNativeMobile, scopeHistoricalMobileConsumers, originalNativeMobileWorkflow, preNativeMobileRead } from "./pre-native-mobile-release.mjs";
const original = fs.readFileSync(new URL("../" + beforeNativeMobile + ".github/workflows/verify.yml", import.meta.url));
const scoped = scopeHistoricalMobileConsumers(original);
const scopedRoot = '-published-app-registry-root "$GITHUB_WORKSPACE/' + beforeNativeMobile.slice(0, -1) + '"';
test("only nine exact historical positive roots and one Nginx negative root change, preserving all old jobs", () => {
  assert.equal(scoped.toString().split(scopedRoot).length - 1, 9);
  assert(originalNativeMobileWorkflow(scoped).equals(original));
  const suffix = "\n  mobile-delivery-native-amd64:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: echo synthetic-adapter-only-not-native-acceptance\n";
  assert.equal(originalNativeMobileWorkflow(Buffer.concat([scoped, Buffer.from(suffix)])).toString(), original.toString() + suffix);
  assert(originalNativeMobileWorkflow(original).equals(original));
});
test("historical normalization refuses unrelated bytes, partial root scoping, unknown roots, deadline changes and missing original tests", () => {
  for (const text of [
    scoped.toString().replace(scopedRoot, '-published-app-registry-root "/tmp/forged"'),
    scoped.toString().replace(scopedRoot, '-published-app-registry-root "$GITHUB_WORKSPACE"'),
    scoped.toString().replace("timeout 240s sudo python3", "timeout 999s sudo python3"),
    scoped.toString().replace('sudo "$(command -v go)" test -p 1 ./... -count=1', "true"),
    scoped.toString().replace("verify-nginx-runtime-handler-boundary.mjs --repo-root", "verify-nginx-runtime-handler-boundary.mjs --skip-signature --repo-root"),
  ]) assert.throws(() => originalNativeMobileWorkflow(Buffer.from(text)));
  assert.throws(() => scopeHistoricalMobileConsumers(Buffer.from(original.toString().replace("npm test", "true"))));
});
test("historical catalog view is the actual signed predecessor, never regenerated data or executable source overlays", () => {
  const raw = preNativeMobileRead("dist/catalog-v1.json", Buffer.from("not a valid signed catalog"));
  assert.equal(createHash("sha256").update(raw).digest("hex"), "0432d210df255b06a1ce258546579f4bfa666d0b661b54fd2572e356549d5f4d");
  const catalog = JSON.parse(raw);
  assert.equal(catalog.apps.length, 50);
  assert.equal(catalog.apps.find(app => app.id === "mobile").version, "1.3.0");
  const source = Buffer.from("actual immutable code");
  assert.equal(preNativeMobileRead("panel-integration-pm2-readiness/internal/appcatalog/panel_features.go", source), source);
});
