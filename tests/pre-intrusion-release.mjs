// Historical readers preserve their exact signed catalog and CI prefix.
// Only the hardening ABI test's published root is scoped to that snapshot.
import fs from 'node:fs';import assert from 'node:assert/strict';import {createHash} from 'node:crypto';
export const beforeIntrusion='registry/reviewed-catalogs/before-intrusion1.1-24bhyz/';
const sha=x=>createHash('sha256').update(x).digest('hex'),read=n=>fs.readFileSync(new URL('../'+beforeIntrusion+n,import.meta.url));
const original=read('verify-pr61.yml');assert.equal(sha(original),'f2b177332b86eeacdd510f5fed8636f0384dc338d5e90ec73abe9624e683a9f6');
const oldLine="        run: sudo \"$(command -v go)\" test -json ./internal/appcatalog -run '^TestPublishedRepositoryCurrentSignedManifestABI$' -count=1 -args -published-app-registry-root \"$GITHUB_WORKSPACE\"",scopedLine="        run: sudo \"$(command -v go)\" test -json ./internal/appcatalog -run '^TestPublishedRepositoryCurrentSignedManifestABI$' -count=1 -args -published-app-registry-root \"$GITHUB_WORKSPACE/registry/reviewed-catalogs/before-intrusion1.1-24bhyz\"";
export function originalIntrusionWorkflow(bytes){
 const s=bytes.toString();if(s.startsWith(original.toString()))return bytes;
 assert.equal(s.split(scopedLine).length-1,1,'Only one hardening ABI predecessor root may be scoped');const restored=s.replace(scopedLine,()=>oldLine);assert(restored.startsWith(original.toString()),'Every other prior CI byte is immutable');return Buffer.from(restored);
}
export function preIntrusionRead(p,bytes){
 if(p==='.github/workflows/verify.yml')return originalIntrusionWorkflow(bytes);
 const names={'dist/catalog-v1.json':'catalog-v1.json','dist/catalog-v1.json.sha256':'catalog-v1.json.sha256','signatures/catalog-v1.sig':'catalog-v1.sig','signatures/catalog-v1.bundle.json':'catalog-v1.bundle.json','signatures/catalog-v1.pub.pem':'catalog-v1.pub.pem','registry/apps.json':'apps-registry.json'};
 if(Object.hasOwn(names,p)){const result=read(names[p]);if(p==='dist/catalog-v1.json')assert.equal(sha(result),'3ed78f60878a2a12cfad862a8d33901389cfcee5a96dbe14090eaf9a6179ad24');if(p==='registry/apps.json')assert.equal(sha(result),'896c753493c23990c49418cba927cdabeb1192696f33525b07bcd3dad59844db');return result;}return bytes;
}
