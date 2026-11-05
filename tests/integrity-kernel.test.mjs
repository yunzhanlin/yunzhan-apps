import test from'node:test';
import assert from'node:assert/strict';
import {fileURLToPath}from'node:url';
import {integrityKernelCases}from'../tools/integrity-kernel-fixtures.mjs';
import {validateManifest}from'../tools/lib.mjs';
const root=fileURLToPath(new URL('../',import.meta.url));
for(const fixture of integrityKernelCases(root))test('inode protection manifest: '+fixture.name,()=>{assert.equal(validateManifest(fixture.manifest).length===0,fixture.valid)});
