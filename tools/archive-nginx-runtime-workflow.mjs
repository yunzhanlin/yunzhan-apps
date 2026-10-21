// Preserve the actual sixteen-job predecessor byte-for-byte before the Nginx
// application release changes only five historical positive ABI catalog roots.
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';
const root=fileURLToPath(new URL('..',import.meta.url));
const raw=fs.readFileSync(path.join(root,'.github/workflows/verify.yml'));
assert.equal(createHash('sha256').update(raw).digest('hex'),'b230a6bf4f6b990461ded7d0270d8fea1603807551dec6e205f1ec9dac47253f');
const output=path.join(root,'registry/reviewed-catalogs/before-nginx-runtime-workflow24bjbl');
assert(!fs.existsSync(output),'Immutable predecessor must never be overwritten');
fs.mkdirSync(output,{mode:0o755});
fs.writeFileSync(path.join(output,'verify-pr70.yml'),raw,{flag:'wx',mode:0o644});
console.log(JSON.stringify({ok:true,files:1,signing_operations:0,workflow_sha256:createHash('sha256').update(raw).digest('hex')}));
