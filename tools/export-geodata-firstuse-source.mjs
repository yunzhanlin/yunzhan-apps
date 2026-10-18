// New immutable original-key verified source; prior scopes are never rewritten.
import fs from'node:fs';import{fileURLToPath}from'node:url';import{createHash}from'node:crypto';import assert from'node:assert/strict';
const root=fileURLToPath(new URL('..',import.meta.url));
let code=fs.readFileSync(new URL('./export-geodata-identity-source.mjs',import.meta.url),'utf8');
const prior=JSON.parse(fs.readFileSync(new URL('../registry/geodata-identity-release.json',import.meta.url)));assert.equal(prior.source_inputs_sha256,'0e61edac147866bd64fc97c9c5dd515797d752d8337a58722a311853c33feebc');
assert.equal(createHash('sha256').update(code).digest('hex'),'ba61feee90071022d4304e50349dd367865f1cace50ef27f831d08b6b69b6489');
for(const[a,b]of [["const root=fileURLToPath(new URL('..',import.meta.url));",'const root='+JSON.stringify(root)+';'],['panel-integration-geodata-identity','panel-integration-geodata-firstuse'],['0.1.0-dev.proapps24geoidentitybggr','0.1.0-dev.proapps24geofirstbghg'],['0e61edac147866bd64fc97c9c5dd515797d752d8337a58722a311853c33feebc','cb807ed5c4e0b27ec3537850da252c0124a6dfb337ffa9ab1a22d26d20633732']]){assert(code.includes(a),a);code=code.replaceAll(a,b)}
await import('data:text/javascript;base64,'+Buffer.from(code).toString('base64'));
