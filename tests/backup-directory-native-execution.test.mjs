import test from 'node:test';
import assert from 'node:assert/strict';
import {spec,verifyBackupDirectoryExecution} from '../tools/check-backup-directory-native.mjs';

const original=()=>({format:1,system:'Linux',architecture:'x86_64',uid:0,source_inputs_sha256:spec.source_inputs_sha256,source_files:structuredClone(spec.source_files),tests_run:13,passed:[...spec.expected_test_ids],failures:[],errors:[],skipped:[],expected_failures:[],unexpected_successes:[],elapsed_seconds:1.5});

test('execution guard accepts exact thirteen methods on both real native architectures',()=>{
  for(const architecture of ['x86_64','aarch64']){
    const row=original();row.architecture=architecture;
    assert.deepEqual(verifyBackupDirectoryExecution(row,architecture),{ok:true,architecture,actual_Root_test_methods:11,PASS:13,skips:0,source_inputs_sha256:spec.source_inputs_sha256,normal_installed_acceptance:false});
  }
});

test('empty, partial, duplicate, skipped or foreign native execution is never acceptance',()=>{
  const changes=[
    row=>{row.tests_run=0;row.passed=[];},
    row=>{row.tests_run=12;row.passed.pop();},
    row=>{row.passed[12]=row.passed[0];},
    row=>{row.skipped=[['original','requires Root']];},
    row=>{row.failures=[['original','failed']];},
    row=>{row.errors=[['original','loader failure']];},
    row=>{row.expected_failures=[['original','expected but unexecuted']];},
    row=>{row.unexpected_successes=['original'];},
    row=>{row.uid=1001;},
    row=>{row.system='Darwin';},
    row=>{row.source_inputs_sha256='0'.repeat(64);},
    row=>{delete row.source_files['packaging/backup-directories.py'];},
    row=>{row.source_files['packaging/install.sh']='0'.repeat(64);},
    row=>{row.passed[0]='foreign.test';},
    row=>{row.elapsed_seconds=0;},
    row=>{row.elapsed_seconds=Infinity;},
    row=>{row.elapsed_seconds=181;},
    row=>{row.extra_asserted_success=true;},
  ];
  for(const change of changes){const row=original();change(row);assert.throws(()=>verifyBackupDirectoryExecution(row,'x86_64'));}
  assert.throws(()=>verifyBackupDirectoryExecution(original(),'aarch64'));
  assert.throws(()=>verifyBackupDirectoryExecution(original(),'unknown'));
});
