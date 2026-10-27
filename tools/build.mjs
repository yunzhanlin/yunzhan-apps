import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { canonical, pretty, sha256, validateManifest } from "./lib.mjs";
import { officialCatalogBaseURL } from "./official-channel.mjs";
import { candidateSource } from "./candidate-source.mjs";
import { candidateAssets } from "./candidate-assets.mjs";

const root = fileURLToPath(new URL("..", import.meta.url));
const args=process.argv.slice(2);
if(args.length>1||args.length===1&&args[0]!=='--candidate-apps')throw Error('only the fixed --candidate-apps publisher mode is allowed');
const candidate=args.length===1;
const stable=JSON.parse(await readFile(path.join(root,"registry/apps.json"),"utf8"));
const source=candidate?candidateSource(stable,JSON.parse(await readFile(path.join(root,"registry/candidate-apps.json"),"utf8"))):stable;
const output=path.join(root,candidate?'candidate':'');
if (source.schema_version !== 1 || !Array.isArray(source.apps)) throw new Error("registry/apps.json format is invalid");
const catalogBaseURL = officialCatalogBaseURL(source.channel === undefined ? 'stable' : source.channel);
if(!candidate&&source.channel!==undefined&&source.channel!=='stable')throw Error('stable catalogue cannot select the candidate channel');
if(candidate)await candidateAssets(root);

// Keep historical version endpoints available while clients refresh signed catalogs.
await mkdir(path.join(output, "dist"), { recursive: true });
const catalog = { schema_version: 1, generated_at: source.generated_at, repository: source.repository, apps: [] };
for (const app of [...source.apps].sort((a, b) => a.id.localeCompare(b.id))) {
  const errors = validateManifest(app);
  if (errors.length) throw new Error(`${app.id || "<unknown>"}: ${errors.join(", ")}`);
  const relative = `apps/${app.id}/${app.version}/manifest.json`;
  const body = pretty(app);
  const digest = sha256(body);
  // An existing version is immutable, including for signed manifests. This
  // prevents silently changing an application without an update notification.
  try {
    const previous = await readFile(path.join(output, "dist", relative), "utf8");
    if (previous !== body) throw new Error(`${app.id}@${app.version} already exists with different content; publish a new version`);
  } catch (error) { if (error.code !== "ENOENT") throw error; }
  await mkdir(path.join(output, "dist", "apps", app.id, app.version), { recursive: true });
  await writeFile(path.join(output, "dist", relative), body);
  await writeFile(path.join(output, "dist", `${relative}.sha256`), `${digest}  manifest.json\n`);
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
    package_url: `${catalogBaseURL}/dist/${relative}`,
    sha256: digest,
  });
}
const catalogBody = pretty(catalog);
await writeFile(path.join(output, "dist/catalog-v1.json"), catalogBody);
await writeFile(path.join(output, "dist/catalog-v1.json.sha256"), `${sha256(catalogBody)}  catalog-v1.json\n`);
console.log(`built ${catalog.apps.length} deterministic application packages`);
