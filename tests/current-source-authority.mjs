import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
export const currentRelease='0.1.0-dev.proapps24statsguardv3beoq';
export const currentInputSHA='5411b3087db37b56677b8906865896802ec772390a7179f54af50415c5677457';
export const currentArchiveSHA='1b48dab44be6513c434203544ce5048aa1cab88031fed17cf4bd1c7216af1d0b';
export const sha=b=>createHash('sha256').update(b).digest('hex');
export async function verifyCurrentSource() {
 // systemd escaped mount-unit filenames contain literal backslashes.
 // They are filesystem names, not browser URLs.
 const root=fileURLToPath(new URL('../',import.meta.url));
 const read=p=>readFile(path.join(root,p),'utf8');
 const c=JSON.parse(await read('registry/functional-contracts.json')),i=JSON.parse(await read('panel-integration/source-sha256.json')),f=JSON.parse(await read('panel-integration/release-source-inputs.json'));
 assert.equal(c.current_reviewed_release,'reviewed_statistics_identity_release');
 const r=c[c.current_reviewed_release];assert.equal(r.release,currentRelease);assert.equal(r.frozen_inputs_sha256,currentInputSHA);
 assert.equal(f.archive,'panel-'+currentRelease+'-linux-amd64.tar.gz');assert.equal(f.archive_sha256,currentArchiveSHA);assert.equal(f.frozen_inputs_sha256,currentInputSHA);
 assert.deepEqual(i.release,{archive:f.archive,archive_sha256:currentArchiveSHA,frozen_inputs_sha256:currentInputSHA});
 assert.equal(Object.keys(i.files).length,1250);assert.equal(Object.keys(f.files).length,1209);assert.deepEqual(i.test_overrides??{},{});
 for(const [path,hash] of Object.entries(f.files)){assert.equal(i.files[path],hash,path);assert.equal(sha(await read('panel-integration/'+path)),hash,path);}
 assert.equal(r.source_overrides,0);assert.equal(r.signed_normal_release.amd64.archive,currentArchiveSHA);
 return {c,r,i,f};
}
