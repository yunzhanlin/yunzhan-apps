// Only the exact reviewed archive extension may be reversed for historical pins.
import assert from 'node:assert/strict';
import {canonical,sha256} from '../../tools/lib.mjs';
export function schemaBeforeApacheCCArchive(value){
 const s=structuredClone(value),feature='apache-cc-log-archive-v1',flags=s.properties.required_panel_features.items.enum;
 if(!flags.includes(feature))return s;
 assert.equal(flags.filter(f=>f===feature).length,1);assert.equal(flags.at(-1),feature);flags.pop();
 const branches=s.allOf[0].then.oneOf;assert.equal(sha256(canonical(branches.at(-1))),'335388840da486704360253935afc01f40f5c9c440a14a4f3088a51ae46a1956');branches.pop();
 const guards=s.allOf.filter(g=>g.if?.anyOf?.some(x=>x.properties?.required_panel_features?.contains?.const===feature));assert.equal(guards.length,1);const guard=guards[0];assert.equal(sha256(canonical(guard)),'7a6088a571e999ba85feff3a0ee2bb4e1abb77f3b8eff7607685e6f513489ced');
 assert.equal(guard.then.oneOf.length,4);guard.then.oneOf.pop();assert.deepEqual(guard.if.anyOf.pop(),{required:['required_panel_features'],properties:{required_panel_features:{contains:{const:feature}}}});
 assert.equal(sha256(canonical(s)),'530c9383fb67f45bea0aa435493fd24d9886729e9eab8a6066972dfd9f4d1fb2','Every preArchive schema predicate and order must stay exact');return s;
}
