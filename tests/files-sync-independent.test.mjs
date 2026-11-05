import test from 'node:test';
import assert from 'node:assert/strict';
import {fileURLToPath}from 'node:url';
import {filesSyncIndependentCases}from '../tools/files-sync-independent-fixtures.mjs';
import {validateManifest}from '../tools/lib.mjs';
const root=fileURLToPath(new URL('../',import.meta.url));
for(const fixture of filesSyncIndependentCases(root))test('independent Root SFTP backup manifest: '+fixture.name,()=>{assert.equal(validateManifest(fixture.manifest).length===0,fixture.valid)});
