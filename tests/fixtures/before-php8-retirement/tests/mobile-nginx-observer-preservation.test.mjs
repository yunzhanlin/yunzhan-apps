import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { verifyOldNginxRuntimeRefusal } from "../tools/verify-nginx-runtime-handler-boundary.mjs";
const root = process.env.YUNZHAN_REGISTRY_FIXTURE_ROOT ?? fileURLToPath(new URL("../", import.meta.url));
const read = name => fs.readFileSync(path.join(root, name), "utf8");
test("Nginx-only refusal observer retains every original byte; only repository selection changes", () => {
  const old = read("tools/verify-nginx-runtime-handler-boundary.mjs");
  const current = fs.readFileSync(new URL("../tools/verify-nginx-runtime-handler-boundary.mjs", import.meta.url), "utf8");
  const body = text => text.slice(text.indexOf("export function verifyOldNginxRuntimeRefusal("), text.indexOf("\nif(process.argv[1]"));
  assert(body(old).startsWith("export function verifyOldNginxRuntimeRefusal("));
  assert(body(old).includes("assert(!events.some(e=>e.Action==='skip'))"));
  assert.equal(body(current), body(old));
});
test("unchanged Nginx observer still requires exactly its own failure and49 other original passing subtests", () => {
  const ids = JSON.parse(read("dist/catalog-v1.json")).apps.map(app => app.id);
  const prefix = "TestPublishedRepositoryCurrentSignedManifestABI";
  const events = [...ids.filter(id => id !== "nginx").map(id => ({Action:"pass",Test:prefix+"/"+id})),
    {Action:"output",Test:prefix+"/nginx",Output:"actual compiled handler rejects current signed manifest 应用面板处理器要求无效"},
    {Action:"fail",Test:prefix+"/nginx"},{Action:"fail",Test:prefix},{Action:"fail"}];
  const result = {status:1,stdout:events.map(event=>JSON.stringify(event)).join("\n")};
  assert.equal(verifyOldNginxRuntimeRefusal(result,ids).other49_passed,49);
  for(const bad of [{...result,status:0},{...result,error:new Error("spawn")},{...result,signal:"SIGTERM"},
    {...result,stdout:result.stdout.replace('"Action":"pass"','"Action":"skip"')},
    {...result,stdout:events.slice(1).map(event=>JSON.stringify(event)).join("\n")}])
      assert.throws(()=>verifyOldNginxRuntimeRefusal(bad,ids));
});
