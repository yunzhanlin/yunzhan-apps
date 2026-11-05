import assert from 'node:assert/strict';
import {canonical,sha256}from '../../tools/lib.mjs';
const feature='files-sync-unpublished-retention-v1';
export function schemaBeforeFilesSyncUnpublished(value){
 const s=structuredClone(value),features=s.properties.required_panel_features.items.enum,branches=s.allOf[0].then.oneOf;
 if(!features.includes(feature)&&!branches.some(v=>v.properties?.id?.const==='files-sync'&&v.properties?.version?.const==='2.0.1'))return s;
 assert.equal(features.filter(v=>v===feature).length,1);assert.equal(features.at(-1),feature);features.pop();
 assert.equal(sha256(canonical(branches.pop())),'f96b067add2c998cce78c5dce1fe956b5e9dff1ed163f377500e86b17ee4c356');
 assert.equal(sha256(canonical(s.allOf.pop())),'920c94b6123afab4301bc955db00b42c35b259178462f301f0f4112cf327562c');
 assert.equal(s.allOf[32].then.anyOf.length,3);assert.equal(sha256(canonical(s.allOf[32].then.anyOf.pop())),'f96b067add2c998cce78c5dce1fe956b5e9dff1ed163f377500e86b17ee4c356');
 assert.deepEqual(Object.keys(s.allOf[33].then),['anyOf']);assert.equal(s.allOf[33].then.anyOf.length,2);
 assert.equal(sha256(canonical(s.allOf[33].then.anyOf[1])),'f96b067add2c998cce78c5dce1fe956b5e9dff1ed163f377500e86b17ee4c356');s.allOf[33].then=s.allOf[33].then.anyOf[0];
 assert.equal(sha256(canonical(s)),'70baea6205b2aa7243107b716c6007c9c8d5859a81b83d01e8f7c50ea08f38ef','Every preUnpublished C63 predicate must remain exact');
 return s;
}
