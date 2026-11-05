import test from'node:test';
import assert from'node:assert/strict';
import fs from'node:fs';
import {sha256}from'../tools/lib.mjs';
import{fileURLToPath}from'node:url';
const root=fileURLToPath(new URL('../',import.meta.url));
const read=p=>JSON.parse(fs.readFileSync(root+p,'utf8'));
test('every current native CI gate binds the actual exported source cohort before native compilation',()=>{
 const index=read('candidate/panel-integration-load-balance/source-sha256.json'),count=Object.keys(index.files).length,sha=index.release.frozen_inputs_sha256,workflow=fs.readFileSync(root+'.github/workflows/candidate-apps.yml','utf8');
 const gates=[['apache-cc-native-execution.json','source_file_count','check-apache-cc-native.mjs'],['analytics-route-execution.json','source_file_count','check-analytics-route-execution.mjs'],['enterprise-kernel-execution.json','source_sdk_files','check-enterprise-kernel-execution.mjs'],['backup-directory-native-execution.json',null,'check-backup-directory-native.mjs'],['retention-native-execution.json',null,'check-retention-native-execution.mjs'],['analytics-query-execution.json','source_sdk_files','check-analytics-query-execution.mjs'],['files-sync-unpublished-execution.json','source_sdk_files','check-files-sync-unpublished-execution.mjs']];
 for(const[name,field,command]of gates){const contract=read('tools/'+name);assert(workflow.includes(command),'Current execution gate must remain in the actual workflow: '+command);assert.equal(contract.source_inputs_sha256,sha,name);if(field)assert.equal(contract[field],count,name+' must describe the exported source, including all new regression files')}
 const negative=read('tools/kernel-publication-original-defect.json');assert.equal(negative.published_source_inputs_sha256,sha);assert.equal(negative.published_source_index_sha256,sha256(fs.readFileSync(root+'candidate/panel-integration-load-balance/source-sha256.json')),'Original negative stager must bind the exact current source index bytes');assert.equal(negative.published_source_sdk_files,count);assert.equal(negative.original_source_sdk_files,2413);assert.equal(read('tools/integrity-kernel-execution.json').source_sdk_files,2405,'The historical C60 source contract remains distinct');
});
