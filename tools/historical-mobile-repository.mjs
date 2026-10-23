import fs from "node:fs";
import path from "node:path";
import assert from "node:assert/strict";
import { createHash, createPublicKey, verify } from "node:crypto";
const predecessor = "registry/reviewed-catalogs/before-native-mobile132-24bkep";
const sha = bytes => createHash("sha256").update(bytes).digest("hex");
// This is not a general repository override: only the genuine reviewed
// predecessor is allowed for the older Nginx-only negative ABI test.
export function historicalMobileRepository(args, root) {
  if (args.length === 0) return root;
  assert.deepEqual(args, ["--repo-root", predecessor], "Only exact signed pre-native-mobile repository is allowed");
  const base = path.resolve(root);
  assert.equal(fs.realpathSync(base), base);
  const target = path.join(base, predecessor);
  const read = name => {
    const file = path.join(target, name), stat = fs.lstatSync(file);
    assert(stat.isFile() && !stat.isSymbolicLink() && stat.nlink === 1);
    assert.equal(fs.realpathSync(file), file);
    return fs.readFileSync(file);
  };
  const raw = read("dist/catalog-v1.json"), pub = read("signatures/catalog-v1.pub.pem");
  assert.equal(sha(raw), "0432d210df255b06a1ce258546579f4bfa666d0b661b54fd2572e356549d5f4d");
  assert.equal(sha(pub), "659ea4edcecaf23a586e2ff371616fde5f6ee7c219fb70fa978816e2b10acf75");
  const signature = read("signatures/catalog-v1.sig").toString().trim();
  const bundle = JSON.parse(read("signatures/catalog-v1.bundle.json"));
  assert.equal(bundle.catalog, raw.toString());
  assert.equal(bundle.signature, signature);
  assert(verify(null, raw, createPublicKey(pub), Buffer.from(signature, "base64")));
  const catalog = JSON.parse(raw);
  assert.equal(catalog.apps.length, 50);
  assert.equal(new Set(catalog.apps.map(app => app.id)).size, 50);
  assert.equal(catalog.apps.find(app => app.id === "mobile").version, "1.3.0");
  for (const app of catalog.apps) {
    assert(/^[a-z0-9-]+$/.test(app.id) && /^[0-9A-Za-z.-]+$/.test(app.version));
    const name = "dist/apps/" + app.id + "/" + app.version + "/manifest.json";
    assert.equal(sha(read(name)), app.sha256, app.id);
    assert.equal(read(name + ".sha256").toString(), app.sha256 + "  manifest.json\n");
  }
  return target;
}
