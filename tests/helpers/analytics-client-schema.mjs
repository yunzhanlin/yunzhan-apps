// Remove only the exact reviewed analytics232 ABI, retaining every older field and array order.
import assert from'node:assert/strict';import{canonical,sha256}from'../../tools/lib.mjs';
export function schemaBeforeAnalyticsClientAddress(value){
 const s=structuredClone(value),feature='analytics-managed-client-address-v1',flags=s.properties.required_panel_features.items.enum;
 if(!flags.includes(feature))return s;
 assert.equal(flags.filter(f=>f===feature).length,1);assert.equal(flags.at(-1),feature);flags.pop();
 const branches=s.allOf[0].then.oneOf;assert.equal(branches.filter(b=>b.properties?.id?.const==='website-analytics'&&b.properties.version?.const==='2.3.2').length,1);
 assert.equal(sha256(canonical(branches.at(-1))),'d1865339af2ef9948fbe82f5d9ae0b35a442a53626585c73809f40be9249b4fb');branches.pop();
 assert.equal(s.allOf.filter(g=>g.if?.properties?.id?.const==='website-analytics'&&g.if.properties.version?.const==='2.3.2').length,1);
 assert.equal(sha256(canonical(s.allOf.at(-1))),'7bc7a8cfebf68f410318f923e607654170eabfbe43f1dcb8cff19442a540e14f');s.allOf.pop();
 assert.equal(sha256(canonical(s)),'fbdd836846a4ffd14cc8d9b1d2e0e2698e86b747cb2084f3e05a8872c7a4fd93','Every pre232 schema predicate and array order must remain exact');return s;
}
