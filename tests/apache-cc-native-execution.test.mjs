import test from 'node:test';import assert from 'node:assert/strict';
import {spec,verifyApacheCCExecution} from '../tools/check-apache-cc-native.mjs';
const events=()=>[
 {Action:'start',Package:spec.package},
 ...spec.expected_pass_tests.flatMap(name=>[{Action:'run',Package:spec.package,Test:name},...(name==='TestApacheCCNativeAdmissionBudgetAndProcessRecovery'?spec.native_C_case_output.map(text=>({Action:'output',Package:spec.package,Test:name,Output:'    PASS '+text+'\n'})):[]),{Action:'pass',Package:spec.package,Test:name}]),
 {Action:'pass',Package:spec.package}
];
test('native source gate requires all actual thirty-five Root entry points, 147 outcomes and six C cases',()=>{
 for(const architecture of ['x86_64','aarch64'])assert.deepEqual(verifyApacheCCExecution(events(),architecture),{ok:true,architecture,actual_methods:35,PASS:147,native_C_cases:6,skips:0,source_inputs_sha256:spec.source_inputs_sha256,normal_installed_acceptance:false});
});
test('empty, partial, duplicate, skipped, foreign and missing native-process evidence cannot qualify',()=>{
 assert.throws(()=>verifyApacheCCExecution([],'x86_64'));
 for(const mutate of [
 e=>e.pop(),e=>e.splice(1,1),e=>e.push({...e[1]}),
 e=>e.push({Action:'skip',Package:spec.package,Test:spec.expected_pass_tests[0]}),
 e=>e.push({Action:'fail',Package:spec.package}),
 e=>e.push({Action:'pass',Package:spec.package,Test:'TestUnrelated'}),
 e=>{e[0].Package='foreign/package';},
 e=>{e.splice(e.findIndex(row=>row.Action==='output'),1);},
 e=>{e.push({...e.find(row=>row.Action==='output')});}
 ]){const e=events();mutate(e);assert.throws(()=>verifyApacheCCExecution(e,'aarch64'));}
 assert.throws(()=>verifyApacheCCExecution(events(),'unknown'));
});

