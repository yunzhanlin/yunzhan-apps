// Bind the complete new schema predicates to the already published190
// candidate contract. Removing only these exact additions must reveal the
// unchanged pre-existing schema; this is never an arbitrary schema filter.
import assert from'node:assert/strict';import{canonical,sha256}from'../../tools/lib.mjs';
export function schemaBeforeLoadBalanceStream(value){
 const s=structuredClone(value),feature='load-balance-stream-controller-v1',flags=s.properties.required_panel_features.items.enum;
 assert.equal(flags.filter(f=>f===feature).length,1);assert.equal(flags.at(-1),feature);flags.pop();
 const branches=s.allOf[0].then.oneOf;assert.equal(branches.filter(b=>b.properties?.id?.const==='load-balance'&&b.properties.version?.const==='1.9.0').length,1);
 assert.equal(sha256(canonical(branches.at(-1))),'2e8f66578836d15d8f64dc5d0681dfccf621b82860cddb4a0ec94b8fa6c57ab7');branches.pop();
 assert.equal(s.allOf.filter(g=>g.if?.properties?.id?.const==='load-balance'&&g.if.properties.version?.const==='1.9.0').length,1);
 assert.equal(sha256(canonical(s.allOf.at(-1))),'90c7306ae1600f973a0eaa9cd87b53b7f48f54476ee662bcbe501a91e4ef749f');s.allOf.pop();
 return s;
}
