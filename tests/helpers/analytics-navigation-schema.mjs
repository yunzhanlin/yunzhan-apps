// Reverse only the exact C59r4 ordering extension. Every original R3
// predicate and unrelated edit remains bound to its original whole digest.
import assert from 'node:assert/strict';
import {canonical,sha256} from '../../tools/lib.mjs';
import {schemaBeforeIntegrityKernel} from './integrity-kernel-schema.mjs';
export function schemaBeforeAnalyticsNavigation(value){
 const s=schemaBeforeIntegrityKernel(value),feature='analytics-navigation-order-v1',flags=s.properties.required_panel_features.items.enum,branches=s.allOf[0].then.oneOf;
 if(!flags.includes(feature)&&!branches.some(v=>v.properties?.version?.const==='2.4.1'&&v.properties?.id?.const==='website-analytics'))return s;
 assert.equal(flags.filter(v=>v===feature).length,1);assert.equal(flags.at(-1),feature);flags.pop();
 assert.equal(sha256(canonical(branches.at(-1))),'786542e69efe06ff9b57e15005d1a470ef285bc804250474e35be21295d3e089');branches.pop();
 assert.equal(sha256(canonical(s.allOf.at(-1))),'08ec695b57202ac4c0bfbf4157fdb20e59d2149a293f3b842d7a297b9965ec4d');s.allOf.pop();
 for(const [index,expected,before]of[[-2,'a7580b9780143ac6f06558c2e5a53776ce759358ad1d275ca7254ee21ddd7193','16e7b60ce46416d8fbb9a53e3e5f5e681cef20362fb14f5c806add95e49e23a8'],[-1,'f5ce36ec47a3902b9eeebe214e849935dce6108b07daa3fb6590114171ffc8df','d37acdb02eab99abb2b98cb61063d8d0a273b1cef8da23f13b5e0044df9cf02f']]){
  const node=s.allOf.at(index);assert.equal(sha256(canonical(node)),expected);assert.deepEqual(Object.keys(node.then),['anyOf']);assert.equal(node.then.anyOf.length,2);node.then=node.then.anyOf[0];assert.equal(sha256(canonical(node)),before);
 }
 assert.equal(sha256(canonical(s)),'a333d5262d9a9af9e46cd5a1ac78e44f3d47aef058efb0d9992d423df7afc440','Every preNavigation schema predicate must remain exact');return s;
}
