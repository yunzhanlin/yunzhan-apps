import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { canonical, pretty, sha256, validateManifest } from "./lib.mjs";

const root = fileURLToPath(new URL("..", import.meta.url));
const source = JSON.parse(await readFile(path.join(root, "registry/apps.json"), "utf8"));
if (source.schema_version !== 1 || !Array.isArray(source.apps)) throw new Error("registry/apps.json format is invalid");

await rm(path.join(root, "dist"), { recursive: true, force: true });
const catalog = { schema_version: 1, generated_at: source.generated_at, repository: source.repository, apps: [] };
for (const app of [...source.apps].sort((a, b) => a.id.localeCompare(b.id))) {
  const errors = validateManifest(app);
  if (errors.length) throw new Error(`${app.id || "<unknown>"}: ${errors.join(", ")}`);
  const relative = `apps/${app.id}/${app.version}/manifest.json`;
  const body = pretty(app);
  const digest = sha256(body);
  await mkdir(path.join(root, "dist", "apps", app.id, app.version), { recursive: true });
  await writeFile(path.join(root, "dist", relative), body);
  await writeFile(path.join(root, "dist", `${relative}.sha256`), `${digest}  manifest.json\n`);
  catalog.apps.push({
    id: app.id,
    name: app.name,
    category: app.category,
    version: app.version,
    summary: app.summary,
    stage: app.stage,
    risk: app.risk,
    provider: app.delivery.provider,
    target: app.delivery.target,
    manage_route: app.delivery.manage_route,
    capabilities: app.capabilities,
    package_url: `https://raw.githubusercontent.com/yunzhanlin/yunzhan-apps/main/dist/${relative}`,
    sha256: digest,
  });
}
const catalogBody = pretty(catalog);
await writeFile(path.join(root, "dist/catalog-v1.json"), catalogBody);
await writeFile(path.join(root, "dist/catalog-v1.json.sha256"), `${sha256(catalogBody)}  catalog-v1.json\n`);
console.log(`built ${catalog.apps.length} deterministic application packages`);
