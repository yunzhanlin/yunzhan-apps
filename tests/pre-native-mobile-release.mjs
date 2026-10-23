// Historical consumers keep their genuine signed fifty-app catalog. The new
// current catalog is tested by a separately compiled native-mobile handler.
import fs from "node:fs";
import assert from "node:assert/strict";
import { createHash, createPublicKey, verify } from "node:crypto";
export const beforeNativeMobile = "registry/reviewed-catalogs/before-native-mobile132-24bkep/";
const read = name => fs.readFileSync(new URL("../" + beforeNativeMobile + name, import.meta.url));
const sha = bytes => createHash("sha256").update(bytes).digest("hex");
const original = read(".github/workflows/verify.yml");
assert.equal(sha(original), "a596ab3db875fdbf2214e411462b12d029e4af1ada6c7c0f51878c59d8abcac5");
const catalog = read("dist/catalog-v1.json"), pub = read("signatures/catalog-v1.pub.pem");
assert.equal(sha(catalog), "0432d210df255b06a1ce258546579f4bfa666d0b661b54fd2572e356549d5f4d");
assert.equal(sha(pub), "659ea4edcecaf23a586e2ff371616fde5f6ee7c219fb70fa978816e2b10acf75");
const bundle = JSON.parse(read("signatures/catalog-v1.bundle.json"));
assert.equal(bundle.catalog, catalog.toString());
assert.equal(bundle.signature, read("signatures/catalog-v1.sig").toString().trim());
assert(verify(null, catalog, createPublicKey(pub), Buffer.from(bundle.signature, "base64")));
assert.equal(sha(read("registry/apps.json")), "efb32167e9b16fa4e86aea75ccf86248f684aaa3cdc094f23176616b6c6511fe");
const oldRoot = '-published-app-registry-root "$GITHUB_WORKSPACE"';
const scopedRoot = '-published-app-registry-root "$GITHUB_WORKSPACE/' + beforeNativeMobile.slice(0, -1) + '"';
const oldNegative = "        run: node tools/verify-nginx-runtime-handler-boundary.mjs";
const scopedNegative = oldNegative + " --repo-root " + beforeNativeMobile.slice(0, -1);
const consumers = new Map([
  ["runtime-package", 1], ["runtime-health", 1], ["nginx-runtime-signed", 2],
  ["waf-configuration-review", 1], ["waf-configuration-inspection", 1],
  ["files-sync-opening", 1], ["ids-capture-recovery", 1], ["pm2-readiness", 1],
]);
function transformJobs(text, from, to) {
  assert.equal(text.split(from).length - 1, 9, "Exactly nine historical ABI roots");
  for (const [name, count] of consumers) {
    const start = text.indexOf("\n  " + name + "-native-amd64:\n");
    assert(start > 0, name);
    const next = text.slice(start + 4).search(/\n  [a-z][a-z0-9-]+:\n/);
    const end = next < 0 ? text.length : start + 4 + next;
    const block = text.slice(start, end);
    assert.equal(block.split(from).length - 1, count, name);
    text = text.slice(0, start) + block.replaceAll(from, to) + text.slice(end);
  }
  return text;
}
export function scopeHistoricalMobileConsumers(bytes) {
  assert(bytes.equals(original), "Only exact original PR77 workflow may be scoped");
  const text = transformJobs(bytes.toString(), oldRoot, scopedRoot);
  assert.equal(text.split(oldNegative).length - 1, 1);
  return Buffer.from(text.replace(oldNegative, () => scopedNegative));
}
export function originalNativeMobileWorkflow(bytes) {
  if (bytes.equals(original)) return bytes;
  let text = bytes.toString();
  // Older normalization layers may call us again on an already restored
  // historical prefix. Its own immutable hash checks remain authoritative.
  if (!text.includes(scopedRoot) && !text.includes(scopedNegative)) return bytes;
  const at = text.indexOf("\n  mobile-delivery-native-amd64:\n");
  const suffix = at < 0 ? "" : text.slice(at);
  if (at >= 0) text = text.slice(0, at);
  text = transformJobs(text, scopedRoot, oldRoot);
  assert.equal(text.split(scopedNegative).length - 1, 1, "Only original Nginx negative root may move");
  text = text.replace(scopedNegative, () => oldNegative);
  assert(Buffer.from(text).equals(original), "Every other byte of all twenty-two historical jobs stays exact");
  return Buffer.from(text + suffix);
}
const mutable = new Set(["dist/catalog-v1.json", "dist/catalog-v1.json.sha256", "signatures/catalog-v1.sig", "signatures/catalog-v1.bundle.json", "signatures/catalog-v1.pub.pem", "registry/apps.json"]);
export function preNativeMobileRead(name, bytes) {
  if (name === ".github/workflows/verify.yml") return originalNativeMobileWorkflow(bytes);
  if (name === "tools/export-panel-source.mjs") {
    const pin = "4c52e20548d868310c16f966ae30a198df7f5a61ee00880205043e153466994e";
    if (sha(bytes) === pin) return bytes;
    const added = "normalBuildGates.add('scripts/test-mobile-navigation.mjs');\n";
    const text = bytes.toString();
    assert.equal(text.split(added).length - 1, 1);
    const original = Buffer.from(text.replace(added, ""));
    assert.equal(sha(original), pin, "No other exporter permissions or override check may change");
    return original;
  }
  return mutable.has(name) ? read(name) : bytes;
}
