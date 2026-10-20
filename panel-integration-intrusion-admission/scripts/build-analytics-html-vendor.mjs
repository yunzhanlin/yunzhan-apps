// Generated bundle + provenance, never a dependency installer or live mutation.
// Usage: node scripts/build-analytics-html-vendor.mjs PRIVATE_NPM_STAGE
import assert from "node:assert/strict";
import { readFile, writeFile, mkdir, readdir } from "node:fs/promises";
import { resolve, join, relative } from "node:path";
import { pathToFileURL } from "node:url";
import { createHash } from "node:crypto";

const root = resolve(import.meta.dirname, "..");
const stage = resolve(process.argv[2] || "");
assert.ok(stage !== root && stage.startsWith(join(root, ".local") + "/"), "use an isolated private dependency stage");
const pins = {
  parse5: { version: "8.0.1", integrity: "sha512-z1e/HMG90obSGeidlli3hj7cbocou0/wa5HacvI3ASx34PecNjNQeaHNo5WIZpWofN9kgkqV1q5YvXe3F0FoPw==", license: "MIT" },
  entities: { version: "8.1.0", integrity: "sha512-kxL7msIffSuh9aaFAMD7rxAIuTRMAHMeBtgHW2yUdWw732ZNh4MehkF2gdjvtdmikkaIP9bFDDJOPlsvm7avrA==", license: "BSD-2-Clause" },
  esbuild: { version: "0.28.2", integrity: "sha512-HKVLS8dvII+xoKW9kmqxbRKrnWEXfJJr/FZhhJmiqIB0e053QNYFqOBouTMO/k5sID4MvCiUCvv8b9M4h32wIA==", license: "MIT" },
};
const lock = JSON.parse(await readFile(join(stage, "package-lock.json"), "utf8"));
for (const [name, pin] of Object.entries(pins)) {
  const meta = JSON.parse(await readFile(join(stage, "node_modules", name, "package.json"), "utf8"));
  const entry = lock.packages["node_modules/" + name];
  assert.equal(meta.version, pin.version); assert.equal(meta.license, pin.license);
  assert.equal(entry.integrity, pin.integrity); assert.equal(entry.version, pin.version);
}
assert.equal(lock.packages["node_modules/parse5/node_modules/entities"], undefined, "unexpected parser dependency graph");
const esbuild = await import(pathToFileURL(join(stage, "node_modules/esbuild/lib/main.js")));
const result = await esbuild.build({
  entryPoints: [join(root, "internal/executor/analytics_html_source.mjs")],
  bundle: true, format: "esm", platform: "neutral", target: "es2020", write: false,
  nodePaths: [join(stage, "node_modules")], legalComments: "inline", minify: false,
  banner: { js: "// Generated: pinned parse5 8.0.1 (MIT), entities 8.1.0 (BSD-2-Clause).\n// See source.json and license files in this directory." },
  metafile: true,
});
const out = join(root, "internal/executor/analytics_html_vendor");
await mkdir(out, { recursive: true });
const files = {};
const save = async (name, value) => { await writeFile(join(out, name), value); files[name] = createHash("sha256").update(value).digest("hex"); };
await save("analytics-html.js", result.outputFiles[0].contents);
for (const name of ["parse5", "entities"]) await save(name + "-LICENSE", await readFile(join(stage, "node_modules", name, "LICENSE")));
const inputs = {};
for (const filename of Object.keys(result.metafile.inputs).sort()) {
  const absolute = resolve(filename);
  const normalized = absolute.startsWith(stage + "/") ? "npm/" + relative(join(stage, "node_modules"), absolute) : relative(root, absolute);
  assert.ok(!normalized.startsWith("..") && !normalized.includes(".local"));
  inputs[normalized] = createHash("sha256").update(await readFile(absolute)).digest("hex");
}
const proof = { schema: 1, packages: pins, entry: "internal/executor/analytics_html_source.mjs", inputs, files, scope: "bounded UTF-8 explicit-head insertion; no compressed body rewrite or CSP changes" };
await writeFile(join(out, "source.json"), JSON.stringify(proof, null, 2) + "\n");
console.log(JSON.stringify({ bundle_sha256: files["analytics-html.js"], bytes: result.outputFiles[0].contents.length, inputs: Object.keys(inputs).length }));
