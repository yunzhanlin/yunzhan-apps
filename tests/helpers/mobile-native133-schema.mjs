// Reverse only the exact independent133 additions before older schema pins.
// Every original132 predicate and every unrelated current edit stays pinned.
import assert from 'node:assert/strict';
import {canonical,sha256}from '../../tools/lib.mjs';
const feature='mobile-native-delivery-v133';
export function schemaBeforeMobileNative133(value){
 const s=structuredClone(value),flags=s.properties.required_panel_features.items.enum,branches=s.allOf[0].then.oneOf,guard=s.allOf[1];
 if(!flags.includes(feature)&&!branches.some(v=>v.properties?.id?.const==='mobile'&&v.properties?.version?.const==='1.3.3')&&!JSON.stringify(guard).includes(feature))return s;
 assert.equal(flags.filter(v=>v===feature).length,1);assert.equal(flags.indexOf(feature),14);assert.equal(flags[13],'mobile-native-delivery-v132');flags.splice(14,1);
 assert.equal(branches.filter(v=>v.properties?.id?.const==='mobile'&&v.properties?.version?.const==='1.3.3').length,1);
 assert.equal(sha256(canonical(branches[11])),'28a9f84d68744b74f8f1fe6895a0304c075bb2eac46e2a842c131cd7dcaed941');branches.splice(11,1);
 assert.equal(sha256(canonical(guard)),'5135490b33d4e4bbdcf3d6e45d8c338849d9e7338a1b061f29461a1ce561c2ea');
 assert.equal(guard.if.anyOf.length,4);guard.if.anyOf.pop();assert.equal(guard.then.oneOf.length,3);guard.then.oneOf.pop();
 assert.equal(sha256(canonical(guard)),'20af45cc3b2775dbcb0e1cb85c01343e237e50fce8af71791e24a5ceef2f5b18');
 assert.equal(sha256(canonical(s)),'7fb8e8adaa01476e28b4a3bf76cb14747f73c81c4ac9daf1941d6c66b9d6e8f3','Every preMobile133 predicate remains exact');return s;
}
