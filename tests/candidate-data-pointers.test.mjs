import test from 'node:test';
import assert from 'node:assert/strict';
import { cp, mkdir, mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { candidateAssets } from '../tools/candidate-assets.mjs';

const repository = fileURLToPath(new URL('..',import.meta.url));
const channel = 'data/geodata/dbip-city-lite-v1';
const pointer = 'catalog.signed.json';
const october = '2026-10-072848fd40e0a17eaf4fb95ba7f7370e9dcde9b2841ac58412ac11512461e1e7';
const november = '2026-11-3a54ed412fd91d7dc514a4d8cae37ee6b9541c160e41c38c3fd0c77cb3e62874';

async function fixture(t) {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(),'yunzhan-candidate-data-')));
  t.after(() => rm(root,{recursive:true,force:true}));
  await mkdir(path.join(root,'signatures'),{recursive:true});
  await mkdir(path.join(root,'dist/apps'),{recursive:true});
  await cp(path.join(repository,'signatures/catalog-v1.pub.pem'),path.join(root,'signatures/catalog-v1.pub.pem'));
  for (const scope of ['', 'candidate']) {
    const target = path.join(root,scope,channel);
    await mkdir(path.join(target,'releases'),{recursive:true});
    const selected = scope === 'candidate' ? november : october;
    for (const release of new Set([october,selected])) {
      await cp(path.join(repository,'candidate',channel,'releases',release),
        path.join(target,'releases',release),{recursive:true});
    }
    const release = path.join(target,'releases',selected);
    const manifest = await readFile(path.join(release,'manifest.json'),'utf8');
    const signature = (await readFile(path.join(release,'manifest.json.sig'),'utf8')).trim();
    await writeFile(path.join(target,pointer),JSON.stringify({manifest,signature}));
  }
  return root;
}

test('building a candidate preserves its newer original-key signed city pointer', async t => {
  const root = await fixture(t);
  const stable = await readFile(path.join(root,channel,pointer));
  const file = path.join(root,'candidate',channel,pointer);
  const candidate = await readFile(file);
  assert.notDeepEqual(candidate,stable);
  await candidateAssets(root);
  assert.deepEqual(await readFile(file),candidate);
  assert.deepEqual(await readFile(path.join(root,channel,pointer)),stable);
});

test('building a candidate refuses changed city pointer bytes without a valid signature', async t => {
  const root = await fixture(t);
  const file = path.join(root,'candidate',channel,pointer);
  const value = JSON.parse(await readFile(file));
  const raw = Buffer.from(value.signature,'base64');
  raw[0] ^= 1;
  value.signature = raw.toString('base64');
  const tampered = JSON.stringify(value);
  await writeFile(file,tampered);
  await assert.rejects(candidateAssets(root),/signed data pointer signature is invalid/);
  assert.equal(await readFile(file,'utf8'),tampered);
});
