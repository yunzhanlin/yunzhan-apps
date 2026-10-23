// Historical assertions retain their genuine original signed catalog. Only
// the five compiled handlers predating runtime-package-version-v1 move to it;
// the two current handlers keep reading the current signed fifty-app catalog.
import fs from 'node:fs';
import {originalNativeMobileWorkflow} from './pre-native-mobile-release.mjs';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
export const beforeNginxRuntime='registry/reviewed-catalogs/before-nginx-runtime-package24bixw/';
const read=n=>fs.readFileSync(new URL('../'+n,import.meta.url));
const sha=b=>createHash('sha256').update(b).digest('hex');
const original=read('registry/reviewed-catalogs/before-nginx-runtime-workflow24bjbl/verify-pr70.yml');
assert.equal(sha(original),'b230a6bf4f6b990461ded7d0270d8fea1603807551dec6e205f1ec9dac47253f');
const oldABI='-published-app-registry-root "$GITHUB_WORKSPACE"';
const scopedABI='-published-app-registry-root "$GITHUB_WORKSPACE/'+beforeNginxRuntime.slice(0,-1)+'"';
const oldNegative='        run: node tools/verify-waf-health-handler-boundary.mjs';
const scopedNegative=oldNegative+' --repo-root '+beforeNginxRuntime.slice(0,-1);
export function originalNginxRuntimeWorkflow(bytes){
 bytes=originalNativeMobileWorkflow(bytes);
 let text=bytes.toString();
 const appended=text.indexOf('\n  nginx-runtime-signed-native-amd64:\n');
 const suffix=appended<0?'':text.slice(appended);
 if(appended>=0)text=text.slice(0,appended);
 if(!text.includes(scopedABI)&&!text.includes(scopedNegative))return bytes;
 assert.equal(text.split(scopedABI).length-1,5,'Exactly five historical signed ABI roots may move');
 for(const job of ['waf-health','waf-version','legacy-sync','runtime-failed','waf-descriptor']){
  const start=text.indexOf('\n  '+job+'-native-amd64:\n');assert(start>0);
  const next=text.slice(start+4).search(/\n  [a-z][a-z0-9-]+:\n/),end=next<0?text.length:start+4+next;
  const block=text.slice(start,end);assert.equal(block.split(scopedABI).length-1,1,job);
  text=text.slice(0,start)+block.replace(scopedABI,()=>oldABI)+text.slice(end);
 }
 assert.equal(text.split(scopedNegative).length-1,1,'Only the historical WAF-only negative gate uses its own signed catalog');
 text=text.replace(scopedNegative,()=>oldNegative);
 assert(text.startsWith(original.toString()),'No other original sixteen-job workflow byte may change');
 return Buffer.from(text+suffix);
}
export function preNginxRuntimeRead(name,bytes){
 if(name==='.github/workflows/verify.yml')return originalNginxRuntimeWorkflow(bytes);
 if(['dist/catalog-v1.json','dist/catalog-v1.json.sha256','signatures/catalog-v1.sig','signatures/catalog-v1.bundle.json','signatures/catalog-v1.pub.pem','registry/apps.json'].includes(name)){
  const raw=read(beforeNginxRuntime+name);
  if(name==='dist/catalog-v1.json')assert.equal(sha(raw),'18c83c0e2ef31d6cb81cb2230fffb30648bebe957adb4f3518dd9a39b11264cf');
  if(name==='registry/apps.json')assert.equal(sha(raw),'8940fe5819bddbc2a9333184ca1f02b1589b86a50ab778301975ae1f92cabe9e');
  return raw;
 }
 return bytes;
}
