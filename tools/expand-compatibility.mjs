// Mechanical manifest migration: versions are immutable, so publish new paths.
import { readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
const file = fileURLToPath(new URL("../registry/apps.json", import.meta.url));
const registry = JSON.parse(await readFile(file, "utf8"));
const os = ["debian-12", "debian-13", "ubuntu-22.04", "ubuntu-24.04", "ubuntu-26.04"];
for (const app of registry.apps) {
  const next = { os, architectures: app.risk === "eol" ? ["amd64"] : ["amd64", "arm64"] };
  if (JSON.stringify(app.compatibility) === JSON.stringify(next)) continue;
  if (!/^[0-9]+(?:\.[0-9]+)*$/.test(app.version)) throw Error("unexpected existing manifest version: " + app.id);
  // Keep the upstream software version; this is a package-contract revision.
  app.version += "-compat1";
  app.compatibility = next;
}
registry.generated_at = new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
await writeFile(file, JSON.stringify(registry, null, 2) + "\n");
console.log("updated exact OS/CPU contracts for", registry.apps.length, "apps; legacy PHP remains amd64-only");
