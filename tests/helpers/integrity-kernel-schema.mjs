// Reverse exactly the new closed kernel scope. All predecessor predicates
// remain bound to their original complete digest, including negative tests.
import assert from'node:assert/strict';
import {canonical,sha256}from'../../tools/lib.mjs';
export function schemaBeforeIntegrityKernel(value){
 const s=structuredClone(value),feature='integrity-kernel-inode-journal-v1',flags=s.properties.required_panel_features.items.enum,branches=s.allOf[0].then.oneOf;
 if(!flags.includes(feature)&&!branches.some(v=>v.properties?.id?.const==='website-tamper-proof'))return s;
 assert.equal(flags.filter(v=>v===feature).length,1);assert.equal(flags.at(-1),feature);flags.pop();
 assert.equal(sha256(canonical(branches.at(-1))),'163cd11d549e8bef25ba29e831d007c1d47d92abb45f31af5ddb6bc8ce861ffa');branches.pop();
 for(const expected of['05b6cd93488f777947873558afaeb6fdc459f9992275111bb9d0a50846288a1e','7099c956d89b686107e283abb02d05a5538a26ba9b2103c1e895dfcee66679b3']){assert.equal(sha256(canonical(s.allOf.at(-1))),expected);s.allOf.pop()}
 assert.equal(sha256(canonical(s)),'fa7371e96f4983a668ff413c6c273ee9aabe0527559f70d9dd0633ec55e4d096','Every preKernel schema predicate must remain exact');return s;
}
