import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, writeFile, copyFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { validateManifest } from '../tools/lib.mjs';

test('application versions cannot escape trusted package paths',async()=>{
 const source=JSON.parse(await readFile(new URL('../registry/apps.json',import.meta.url),'utf8'));
 for(const version of ['../1.0','1.0/../bad','1.0?x=1','v1.0','']) assert(validateManifest({...source.apps[0],version}).includes('invalid version'));
 for(const version of ['1.1.0','7.0.4-compat2','1.0']) assert(!validateManifest({...source.apps[0],version}).includes('invalid version'));
});

test('published app versions are immutable and historical endpoints retained',async()=>{
 const temporary=await mkdtemp(path.join(os.tmpdir(),'yunzhan-version-test-'));
 try{
  await mkdir(path.join(temporary,'tools'));await mkdir(path.join(temporary,'registry'));
  for(const name of ['build.mjs','lib.mjs','memcached-unix-contract.mjs','php-security-contract.mjs','php-bounded-contract.mjs'])await copyFile(new URL('../tools/'+name,import.meta.url),path.join(temporary,'tools',name));
  const source=JSON.parse(await readFile(new URL('../registry/apps.json',import.meta.url),'utf8'));
  // This exercises the generic immutable archive contract, not permission for
  // an unreviewed Nginx handler/version. Use an explicit unscoped runtime.
  const generic=source.apps.find(app=>app.id==='pure-ftpd');assert(generic&&!Object.hasOwn(generic,'required_panel_features'));source.apps=[generic];
  const save=()=>writeFile(path.join(temporary,'registry/apps.json'),JSON.stringify(source));
  await save();execFileSync(process.execPath,[path.join(temporary,'tools/build.mjs')],{stdio:'pipe'});
  source.apps[0].summary+=' changed';await save();
  assert.throws(()=>execFileSync(process.execPath,[path.join(temporary,'tools/build.mjs')],{stdio:'pipe'}),/publish a new version/);
  const old=source.apps[0].version;source.apps[0].version='99.0.0';await save();execFileSync(process.execPath,[path.join(temporary,'tools/build.mjs')],{stdio:'pipe'});
  assert((await readFile(path.join(temporary,'dist/apps',source.apps[0].id,old,'manifest.json'),'utf8')).includes(old));
 } finally {await rm(temporary,{recursive:true,force:true})}
});
