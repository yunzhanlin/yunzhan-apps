import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { canonical, sha256, validateManifest } from "./lib.mjs";

const root = fileURLToPath(new URL("..", import.meta.url));
const catalog = JSON.parse(await readFile(path.join(root, "dist/catalog-v1.json"), "utf8"));
if (catalog.schema_version !== 1 || catalog.apps.length !== 50) throw new Error(`catalog must contain exactly 50 apps, found ${catalog.apps.length}`);
const ids = new Set();
for (const item of catalog.apps) {
  if (ids.has(item.id)) throw new Error(`duplicate id: ${item.id}`);
  ids.add(item.id);
  const manifestPath = path.join(root, "dist/apps", item.id, item.version, "manifest.json");
  const app = JSON.parse(await readFile(manifestPath, "utf8"));
  const errors = validateManifest(app);
  if (errors.length) throw new Error(`${item.id}: ${errors.join(", ")}`);
  if (sha256(canonical(app)) !== item.sha256) throw new Error(`${item.id}: digest mismatch`);
  if (app.id !== item.id || app.version !== item.version || app.stage !== item.stage) throw new Error(`${item.id}: catalog mismatch`);
}
const expected = (await readFile(path.join(root, "dist/catalog-v1.json.sha256"), "utf8")).trim().split(/\s+/)[0];
if (expected !== sha256(canonical(catalog))) throw new Error("catalog digest mismatch");
console.log(`verified ${ids.size} apps, manifests and SHA-256 links`);
