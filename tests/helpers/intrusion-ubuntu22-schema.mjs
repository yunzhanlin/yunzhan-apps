// Reverse only the exact reviewed111 schema extension before running old
// preservation assertions. Every pre-existing schema field and guard remains
// compared against the authentic pre111 Git bytes, not a synthesized baseline.
import assert from 'node:assert/strict';import fs from 'node:fs';import{createHash}from'node:crypto';
import{schemaBeforeLoadBalanceStream}from'./load-balance-stream-schema.mjs';
const feature='intrusion-upstream0112-v1',journal='intrusion-preserving-journal-v2';
export function schemaBeforeIntrusionUbuntu22(value){
 const current=schemaBeforeLoadBalanceStream(value),raw=fs.readFileSync(new URL('../../registry/reviewed-catalogs/before-intrusion111-20261030/schema/app.schema.json',import.meta.url));
 assert.equal(createHash('sha256').update(raw).digest('hex'),'6a7c50f5d9f4b21d13fa6c97c4eb754b4d605bb65cffb6783022fea5e98b056a');
 const previous=JSON.parse(raw),flags=current.properties.required_panel_features.items.enum;
 assert.equal(flags.filter(f=>f===feature).length,1);assert.equal(flags.at(-1),feature);flags.pop();
 const requirements={minItems:2,maxItems:2,prefixItems:[{const:journal},{const:feature}],items:false};
 const expected={properties:{id:{const:'anti-intrusion'},version:{const:'1.1.1'},delivery:{properties:{provider:{const:'panel-module'},target:{const:'intrusion-prevention'},manage_route:{const:'security'}}},required_panel_features:requirements}};
 const branches=current.allOf[0].then.oneOf;assert.equal(branches.filter(b=>b.properties?.id?.const==='anti-intrusion'&&b.properties.version?.const==='1.1.1').length,1);assert.deepEqual(branches.at(-1),expected);branches.pop();
 const guard={if:{required:['id','version'],properties:{id:{const:'anti-intrusion'},version:{const:'1.1.1'}}},then:{required:['required_panel_features'],properties:{required_panel_features:requirements}}};
 assert.equal(current.allOf.filter(g=>g.if?.properties?.id?.const==='anti-intrusion'&&g.if.properties.version?.const==='1.1.1').length,1);assert.deepEqual(current.allOf.at(-1),guard);current.allOf.pop();
 assert.deepEqual(current,previous,'Every pre111 schema field, branch, order and guard remains exact');
 return current;
}
