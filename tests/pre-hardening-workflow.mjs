// Restore only the one test-only ABI root moved to its exact signed predecessor.
// All original workflow hashes and native jobs still run unchanged.
import fs from 'node:fs';import assert from 'node:assert/strict';import {createHash}from'node:crypto';
export const beforeHardening='registry/reviewed-catalogs/before-hardening24bhhp/';
export const analyticsABIline='        run: sudo "$(command -v go)" test -json ./internal/appcatalog -run \'^TestPublishedRepositoryCurrentSignedManifestABI$\' -count=1 -args -published-app-registry-root "$GITHUB_WORKSPACE"';
export const scopedAnalyticsABIline=analyticsABIline.replace('$GITHUB_WORKSPACE"','$GITHUB_WORKSPACE/'+beforeHardening.slice(0,-1)+'"');
const original=fs.readFileSync(new URL('../'+beforeHardening+'verify-pr60.yml',import.meta.url));
assert.equal(createHash('sha256').update(original).digest('hex'),'62dc2b95b991ead4112f349252ae4ee2b5b0205c07427b04bf8a3549734e33ab');
export function originalHardeningWorkflow(bytes){
 const current=bytes.toString();assert.equal(current.split(scopedAnalyticsABIline).length-1,1,'Exactly one analytics predecessor root');
 const oldBlock='      - name: Complete current Root Linux Go contracts and vet\n        working-directory: panel-integration-hardening\n        run: |\n          sudo "$(command -v go)" test -p 1 ./... -count=1\n          go vet ./...';
 const fixedBlock=oldBlock.replace('sudo "$(command -v go)" test -p 1 ./... -count=1','sudo "$(command -v node)" ../tools/run-hardening-ci.mjs "$(command -v go)"');
 assert.equal(current.split(fixedBlock).length-1,1,'Exactly one declared test-only full-suite fixture overlay');
 const restored=current.replace(scopedAnalyticsABIline,()=>analyticsABIline).replace(fixedBlock,()=>oldBlock);assert(restored.startsWith(original.toString()),'No other original CI byte may change');return Buffer.from(restored);
}
export const preHardeningWorkflowRead=(p,bytes)=>p==='.github/workflows/verify.yml'?originalHardeningWorkflow(bytes):bytes;
export function preHardeningRead(p,bytes){
 if(p==='dist/catalog-v1.json'){const old=fs.readFileSync(new URL('../'+beforeHardening+'catalog-v1.json',import.meta.url));assert.equal(createHash('sha256').update(old).digest('hex'),'ac150c30f7d83cc0dc25218386831878d9b8deb45396e6e803fde88e6982dfd6');return old;}
 return preHardeningWorkflowRead(p,bytes);
}
