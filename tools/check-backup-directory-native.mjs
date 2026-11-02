import fs from 'node:fs';
import assert from 'node:assert/strict';
import {fileURLToPath} from 'node:url';
import {resolve} from 'node:path';

export const spec = JSON.parse(fs.readFileSync(new URL('./backup-directory-native-execution.json', import.meta.url)));

export function verifyBackupDirectoryExecution(record, architecture) {
  assert(record && typeof record === 'object' && !Array.isArray(record));
  assert.deepEqual(Object.keys(record).sort(), ['architecture','elapsed_seconds','errors','expected_failures','failures','format','passed','skipped','source_files','source_inputs_sha256','system','tests_run','uid','unexpected_successes'].sort());
  assert.equal(record.format, 1);
  assert.equal(record.system, 'Linux');
  assert(['x86_64','aarch64'].includes(architecture));
  assert.equal(record.architecture, architecture, 'execution must match the actual runner architecture');
  assert.equal(record.uid, 0, 'actual Root execution is required');
  assert.equal(record.source_inputs_sha256, spec.source_inputs_sha256);
  assert.deepEqual(record.source_files, spec.source_files, 'exact reviewed source inputs required');
  assert.equal(spec.expected_test_ids.length, 13);
  assert.equal(record.tests_run, 13, 'empty discovery or partial execution cannot pass');
  assert(Array.isArray(record.passed));
  assert.equal(new Set(record.passed).size, 13, 'duplicate tests cannot replace missing cases');
  assert.deepEqual([...record.passed].sort(), spec.expected_test_ids);
  assert.equal(record.passed.filter(name=>name.includes('.BackupDirectoryRootTests.')).length, 11);
  for(const field of ['failures','errors','skipped','expected_failures','unexpected_successes']) assert.deepEqual(record[field], [], field+' must be empty');
  assert(Number.isFinite(record.elapsed_seconds) && record.elapsed_seconds > 0 && record.elapsed_seconds <= 180);
  return {ok:true, architecture, actual_Root_test_methods:11, PASS:13, skips:0, source_inputs_sha256:spec.source_inputs_sha256, normal_installed_acceptance:false};
}

if(process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  assert.equal(process.argv.length, 4, 'one original JSON file and actual uname architecture are required');
  const path=process.argv[2], info=fs.lstatSync(path);
  assert(info.isFile() && !info.isSymbolicLink() && info.size > 0 && info.size <= 2*1024*1024);
  const index=JSON.parse(fs.readFileSync(new URL('../candidate/panel-integration-load-balance/source-sha256.json', import.meta.url)));
  assert.equal(index.release.frozen_inputs_sha256, spec.source_inputs_sha256);
  for(const [name,digest]of Object.entries(spec.source_files))assert.equal(index.files[name],digest);
  console.log(JSON.stringify(verifyBackupDirectoryExecution(JSON.parse(fs.readFileSync(path,'utf8')), process.argv[3])));
}
