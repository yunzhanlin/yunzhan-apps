import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import {candidateAssets} from '../tools/candidate-assets.mjs';
async function fixture(t){
  const root=await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(),'yunzhan-candidate-assets-')));
  t.after(()=>fs.rm(root,{recursive:true,force:true}));
  for(const dir of ['dist/apps/network-threat-detection/rule-data/fixture','data/geodata/fixture'])await fs.mkdir(path.join(root,dir),{recursive:true});
  await fs.writeFile(path.join(root,'dist/apps/network-threat-detection/rule-data/fixture/LICENSE'),'actual public licence\n');
  await fs.writeFile(path.join(root,'data/geodata/fixture/catalog.signed.json'),'public signed fixture bytes\n');
  return root;
}
test('candidate resources retain exact public bytes and repeat publication never rewrites changed assets',async t=>{
  const root=await fixture(t),result=await candidateAssets(root);assert.equal(result.files,2);
  const name='data/geodata/fixture/catalog.signed.json';
  assert((await fs.readFile(path.join(root,name))).equals(await fs.readFile(path.join(root,'candidate',name))));
  assert.deepEqual(await candidateAssets(root),result);
  await fs.writeFile(path.join(root,'candidate',name),'do not replace this changed output');
  await assert.rejects(candidateAssets(root),/changed immutable/);
  assert.equal(await fs.readFile(path.join(root,'candidate',name),'utf8'),'do not replace this changed output');
});
test('candidate public asset copy refuses source links output links and hardlinks without touching outside data',async t=>{
  const outside=await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(),'yunzhan-candidate-outside-')));
  t.after(()=>fs.rm(outside,{recursive:true,force:true}));await fs.writeFile(path.join(outside,'sentinel'),'original outside data');
  const linked=await fixture(t);await fs.symlink(outside,path.join(linked,'candidate'));
  await assert.rejects(candidateAssets(linked),/ordinary/);assert.deepEqual((await fs.readdir(outside)).sort(),['sentinel']);
  const source=await fixture(t);await fs.symlink(path.join(outside,'sentinel'),path.join(source,'data','linked'));
  await assert.rejects(candidateAssets(source),/link/);assert.equal(await fs.readFile(path.join(outside,'sentinel'),'utf8'),'original outside data');
  const hard=await fixture(t);await candidateAssets(hard);
  await fs.link(path.join(hard,'candidate/data/geodata/fixture/catalog.signed.json'),path.join(outside,'hardlink'));
  await assert.rejects(candidateAssets(hard),/ordinary/);assert.equal(await fs.readFile(path.join(outside,'sentinel'),'utf8'),'original outside data');
});
