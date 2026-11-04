import fs from 'node:fs';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import path from 'node:path';

export const spec=JSON.parse(fs.readFileSync(new URL('./apache-cc-native-execution.json',import.meta.url)));
export function verifyApacheCCExecution(events,architecture){
 assert(['x86_64','aarch64'].includes(architecture));
 assert(Array.isArray(events)&&events.length>0&&events.length<=10000);
 assert.equal(spec.expected_root_tests.length,35);assert.equal(spec.expected_pass_tests.length,147);assert.equal(spec.native_C_case_output.length,6);
 const run=[],passed=[];let packagePassed=0,output='';
 for(const event of events){
  assert(event&&typeof event==='object'&&!Array.isArray(event));
  assert.equal(event.Package,spec.package);
  assert(!['fail','skip'].includes(event.Action),'failed/skipped execution cannot qualify');
  if(event.Test){
   assert(spec.expected_pass_tests.includes(event.Test),'foreign test cannot replace the intended case');
   if(event.Action==='run')run.push(event.Test);
   if(event.Action==='pass')passed.push(event.Test);
   if(event.Test==='TestApacheCCNativeAdmissionBudgetAndProcessRecovery'&&event.Action==='output')output+=event.Output||'';
  }else if(event.Action==='pass')packagePassed++;
 }
 assert.equal(packagePassed,1);
 assert.equal(new Set(run).size,run.length);assert.equal(new Set(passed).size,passed.length);
 assert.deepEqual(run.sort(),spec.expected_pass_tests);assert.deepEqual(passed.sort(),spec.expected_pass_tests);
 for(const text of spec.native_C_case_output)assert.equal(output.split('PASS '+text).length-1,1,'all six executed native C cases must appear once');
 return {ok:true,architecture,actual_methods:35,PASS:147,native_C_cases:6,skips:0,source_inputs_sha256:spec.source_inputs_sha256,normal_installed_acceptance:false};
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 assert.equal(process.argv.length,4);assert.equal(process.platform,'linux');
 const architecture=process.argv[3];assert.equal(architecture,process.arch==='arm64'?'aarch64':process.arch==='x64'?'x86_64':'unsupported');
 const file=process.argv[2],info=fs.lstatSync(file);assert(info.isFile()&&!info.isSymbolicLink()&&info.size>0&&info.size<=4<<20);
 const sdk=new URL('../candidate/panel-integration-load-balance/',import.meta.url),index=JSON.parse(fs.readFileSync(new URL('source-sha256.json',sdk)));
 assert.equal(index.release.frozen_inputs_sha256,spec.source_inputs_sha256);
 assert.equal(Object.keys(index.files).length,spec.source_file_count);
 const sdkPath=fs.realpathSync(fileURLToPath(sdk));
 for(const[name,digest]of Object.entries(index.files)){
  assert(!path.posix.isAbsolute(name)&&path.posix.normalize(name)===name&&!name.split('/').includes('..'));
  const f=path.join(sdkPath,name),s=fs.lstatSync(f);assert(f.startsWith(sdkPath+path.sep)&&fs.realpathSync(f)===f);
  assert(s.isFile()&&!s.isSymbolicLink()&&s.nlink===1&&s.size<=2<<20);
  assert.equal(createHash('sha256').update(fs.readFileSync(f)).digest('hex'),digest,name);
 }
 const events=fs.readFileSync(file,'utf8').trim().split('\n').map(line=>JSON.parse(line));
 console.log(JSON.stringify(verifyApacheCCExecution(events,architecture)));
}

