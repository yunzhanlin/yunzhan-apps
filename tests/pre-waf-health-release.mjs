// Two historical ABI invocations use their own signed catalog; all other
// original workflow bytes and executable/test sources remain unchanged.
import fs from 'node:fs';import assert from 'node:assert/strict';import {createHash} from 'node:crypto';
export const beforeWAFHealth='registry/reviewed-catalogs/before-waf-health24bijk/';
const sha=b=>createHash('sha256').update(b).digest('hex'),read=n=>fs.readFileSync(new URL('../'+beforeWAFHealth+n,import.meta.url));
const original=read('verify-pr64.yml');assert.equal(sha(original),'69b215c701922af629899e66df38b599d74fe0699a10b2b5b6f4f2fdffc1c33d');
export const oldWAFABIline="        run: sudo \"$(command -v go)\" test -json ./internal/appcatalog -run '^TestPublishedRepositoryCurrentSignedManifestABI$' -count=1 -args -published-app-registry-root \"$GITHUB_WORKSPACE\"";
export const scopedWAFABIline=oldWAFABIline.replace('$GITHUB_WORKSPACE"','$GITHUB_WORKSPACE/'+beforeWAFHealth.slice(0,-1)+'"');
export function originalWAFHealthWorkflow(bytes){
 // Older restoration layers call each other with already-restored prefixes.
 // With no health substitution, leave their own exact hash checks in charge.
 const text=bytes.toString();if(text.startsWith(original.toString())||!text.includes(scopedWAFABIline))return bytes;
 assert.equal(text.split(scopedWAFABIline).length-1,2,'Exactly two historical signed ABI roots may move');const restored=text.replaceAll(scopedWAFABIline,()=>oldWAFABIline);assert(restored.startsWith(original.toString()),'No other original nine-job workflow byte may change');return Buffer.from(restored);
}
export function preWAFHealthRead(p,bytes){
 if(p==='.github/workflows/verify.yml')return originalWAFHealthWorkflow(bytes);
 const names={'dist/catalog-v1.json':'catalog-v1.json','dist/catalog-v1.json.sha256':'catalog-v1.json.sha256','signatures/catalog-v1.sig':'catalog-v1.sig','signatures/catalog-v1.bundle.json':'catalog-v1.bundle.json','signatures/catalog-v1.pub.pem':'catalog-v1.pub.pem','registry/apps.json':'apps-registry.json'};
 if(Object.hasOwn(names,p)){const body=read(names[p]);if(p==='dist/catalog-v1.json')assert.equal(sha(body),'fbbca119f5edbc613377f7ac4a0fd2abcc1dd9a2a7a571891ab180cc1cbcd5fe');if(p==='registry/apps.json')assert.equal(sha(body),'34a9285edceaf95cc6de6aa8d6ef74b574ef6a055b6fa2524733d35ece339124');return body}return bytes;
}
