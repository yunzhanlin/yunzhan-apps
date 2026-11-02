// Strip only the exact reviewed CC extension before historical schema checks.
// Hash the entire restored schema, so unrelated predicates cannot be normalized away.
import assert from 'node:assert/strict';
import {canonical,sha256} from '../../tools/lib.mjs';
export function schemaBeforeApacheCC(value){
 const s=structuredClone(value),feature='apache-native-cc-site-transactions-v1',flags=s.properties.required_panel_features.items.enum;
 if(!flags.includes(feature))return s;
 assert.equal(flags.filter(f=>f===feature).length,1);assert.equal(flags.at(-1),feature);flags.pop();
 const branches=s.allOf[0].then.oneOf;
 assert.equal(sha256(canonical(branches.at(-1))),'1547d6d027bce5ba5edc26ce8e5b1d4a81261ed5c1c51f27f570b795e2363898');branches.pop();
 const guards=s.allOf.filter(g=>g.if?.anyOf?.some(x=>x.properties?.required_panel_features?.contains?.const===feature));assert.equal(guards.length,1);
 const guard=guards[0];assert.equal(sha256(canonical(guard)),'94731883d3e0a5b86c8f575748af373d8b1d8886293e9b3478d2a183015fcf1d');
 assert.equal(guard.then.oneOf.length,3);guard.then.oneOf.pop();
 assert.deepEqual(guard.if.anyOf.pop(),{required:['required_panel_features'],properties:{required_panel_features:{contains:{const:feature}}}});
 assert.equal(sha256(canonical(s)),'4f0e6b862ec021eb3483f7b801ebf35328d635c07d8c3395a628e77349d30441','Every preCC schema predicate and array order must remain exact');return s;
}
