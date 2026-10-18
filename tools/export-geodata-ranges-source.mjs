// New immutable source scope, verified with ORIGINAL public program trust.
import fs from'node:fs';import{fileURLToPath}from'node:url';import{createHash}from'node:crypto';import assert from'node:assert/strict';
const root=fileURLToPath(new URL('..',import.meta.url));let code=fs.readFileSync(new URL('./export-geodata-identity-source.mjs',import.meta.url),'utf8');
assert.equal(createHash('sha256').update(code).digest('hex'),'ba61feee90071022d4304e50349dd367865f1cace50ef27f831d08b6b69b6489');
for(const[a,b]of [["const root=fileURLToPath(new URL('..',import.meta.url));",'const root='+JSON.stringify(root)+';'],['geodata-identity','geodata-ranges'],['0.1.0-dev.proapps24geoidentitybggr','0.1.0-dev.proapps24georangebgia'],['0e61edac147866bd64fc97c9c5dd515797d752d8337a58722a311853c33feebc','bc5ac19fb87fae38e2f05af1fe71bca073fd89303a8d5e103246335a09c4ba02'],['length!==17105','length!==17108'],['selected.length!==1462','selected.length!==1465']]){assert(code.includes(a),a);code=code.replaceAll(a,b)}
await import('data:text/javascript;base64,'+Buffer.from(code).toString('base64'));
