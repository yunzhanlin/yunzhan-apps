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
  const raw = await readFile(manifestPath, "utf8");
  const app = JSON.parse(raw);
  const errors = validateManifest(app);
  if (errors.length) throw new Error(`${item.id}: ${errors.join(", ")}`);
  if (sha256(raw) !== item.sha256) throw new Error(`${item.id}: digest mismatch`);
  if (app.id !== item.id || app.version !== item.version || app.stage !== item.stage) throw new Error(`${item.id}: catalog mismatch`);
  if (app.delivery.provider !== item.provider || app.delivery.target !== item.target || app.delivery.manage_route !== item.manage_route) throw new Error(`${item.id}: catalog delivery mismatch`);
}
const expected = (await readFile(path.join(root, "dist/catalog-v1.json.sha256"), "utf8")).trim().split(/\s+/)[0];
const catalogRaw = await readFile(path.join(root, "dist/catalog-v1.json"), "utf8");
if (expected !== sha256(catalogRaw)) throw new Error("catalog digest mismatch");
console.log(`verified ${ids.size} apps, manifests and SHA-256 links`);
