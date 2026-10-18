// New immutable scope, verified against the original public program trust.
// Historical signed sources and all production admission guards remain intact.
import fs from 'node:fs';import {fileURLToPath} from 'node:url';import {createHash} from 'node:crypto';import assert from 'node:assert/strict';
const root=fileURLToPath(new URL('..',import.meta.url));let code=fs.readFileSync(new URL('./export-geodata-identity-source.mjs',import.meta.url),'utf8');
assert.equal(createHash('sha256').update(code).digest('hex'),'ba61feee90071022d4304e50349dd367865f1cace50ef27f831d08b6b69b6489');
for(const [a,b] of [["const root=fileURLToPath(new URL('..',import.meta.url));",'const root='+JSON.stringify(root)+';'],['geodata-identity','geodata-preflight'],['0.1.0-dev.proapps24geoidentitybggr','0.1.0-dev.proapps24geoflightbgjp'],['0e61edac147866bd64fc97c9c5dd515797d752d8337a58722a311853c33feebc','b183917a52ff1dedeb370e8b30eba1bc057fdade6d5543bfd0c69512326c6b07'],['length!==17105','length!==17113'],['selected.length!==1462','selected.length!==1470']]){assert(code.includes(a),a);code=code.replaceAll(a,b);}
await import('data:text/javascript;base64,'+Buffer.from(code).toString('base64'));
