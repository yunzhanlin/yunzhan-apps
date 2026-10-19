// Historical tests retain their original assertions. Only seven old compiled
// handlers read the real signed predecessor; the new handler reads current50.
import fs from 'node:fs';import assert from 'node:assert/strict';import {createHash} from 'node:crypto';
import {originalHardeningWorkflow} from './pre-hardening-workflow.mjs';
const sha=b=>createHash('sha256').update(b).digest('hex');
export const beforeAnalytics='registry/reviewed-catalogs/before-analytics-session24bgnt/';
const original=fs.readFileSync(new URL('../'+beforeAnalytics+'verify-pr52.yml',import.meta.url));
assert.equal(sha(original),'fd925cd2e8aa81fb871077615778ee79decbae65942b9cec7412a79f3886eb63');
const old='-published-app-registry-root "$GITHUB_WORKSPACE"';
assert.equal(original.toString().split(old).length-1,7);
export const scopedPredecessorWorkflow=original.toString().replaceAll(old,'-published-app-registry-root "$GITHUB_WORKSPACE/'+beforeAnalytics.slice(0,-1)+'"');
export function originalAnalyticsWorkflow(bytes){
 const current=originalHardeningWorkflow(bytes).toString();assert(current.startsWith(scopedPredecessorWorkflow),'Historical CI changed beyond the seven exact signed predecessor paths');
 return Buffer.concat([original,Buffer.from(current.slice(scopedPredecessorWorkflow.length))]);
}
export function preAnalyticsWorkflowRead(p,bytes){return p==='.github/workflows/verify.yml'?originalAnalyticsWorkflow(bytes):bytes;}
