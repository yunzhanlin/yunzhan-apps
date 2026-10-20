// One-time public release artifact archive. No keys are copied or generated.
import {readFile,lstat,realpath,mkdir,copyFile,constants} from 'node:fs/promises';
import {createHash,createPublicKey,verify} from 'node:crypto';
import {fileURLToPath} from 'node:url';import path from 'node:path';import assert from 'node:assert/strict';
const root=fileURLToPath(new URL('../',import.meta.url));
const sha=b=>createHash('sha256').update(b).digest('hex');
const items={'catalog-v1.json':'dist/catalog-v1.json','catalog-v1.json.sha256':'dist/catalog-v1.json.sha256','catalog-v1.sig':'signatures/catalog-v1.sig','catalog-v1.bundle.json':'signatures/catalog-v1.bundle.json','catalog-v1.pub.pem':'signatures/catalog-v1.pub.pem'};
const bodies={};for(const [name,relative]of Object.entries(items)){const file=path.join(root,relative),s=await lstat(file);assert(s.isFile()&&!s.isSymbolicLink()&&s.nlink===1);assert.equal(await realpath(file),file);bodies[name]=await readFile(file);}
assert.equal(sha(bodies['catalog-v1.json']),'3ed78f60878a2a12cfad862a8d33901389cfcee5a96dbe14090eaf9a6179ad24');assert.equal(sha(bodies['catalog-v1.pub.pem']),'659ea4edcecaf23a586e2ff371616fde5f6ee7c219fb70fa978816e2b10acf75');
const sig=bodies['catalog-v1.sig'].toString().trim(),bundle=JSON.parse(bodies['catalog-v1.bundle.json']);assert.equal(bundle.catalog,bodies['catalog-v1.json'].toString());assert.equal(bundle.signature,sig);assert(verify(null,bodies['catalog-v1.json'],createPublicKey(bodies['catalog-v1.pub.pem']),Buffer.from(sig,'base64')));
assert.equal(bodies['catalog-v1.json.sha256'].toString(),sha(bodies['catalog-v1.json'])+'  catalog-v1.json\n');
const dst=path.join(root,'registry/reviewed-catalogs/before-intrusion1.1-24bhyz');await mkdir(dst);
for(const [name,relative]of Object.entries(items)){await copyFile(path.join(root,relative),path.join(dst,name),constants.COPYFILE_EXCL);assert.equal(sha(await readFile(path.join(dst,name))),sha(bodies[name]));}
console.log('Preserved exact original-key signed catalog before intrusion1.1; historical handlers retain their actual prior catalog.');
