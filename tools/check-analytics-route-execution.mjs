import fs from 'node:fs';
import assert from 'node:assert/strict';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';
export const spec=JSON.parse(fs.readFileSync(new URL('./analytics-route-execution.json',import.meta.url)));
export function verifyAnalyticsRouteExecution(events,architecture){
 assert(['x86_64','aarch64'].includes(architecture));assert(Array.isArray(events)&&events.length>0&&events.length<=20000);
 const started=[],passed=[],packages=new Map();
 const wanted=spec.expected_tests.map(x=>x.package+':'+x.name).sort();assert.equal(wanted.length,16);assert.equal(new Set(wanted).size,16);
 for(const event of events){
  assert(event&&typeof event==='object'&&!Array.isArray(event));assert(spec.packages.includes(event.Package));assert(!['skip','fail'].includes(event.Action),'empty, skipped or failed execution cannot qualify');
  if(event.Test){const name=event.Package+':'+event.Test;assert(wanted.includes(name),'foreign test cannot replace the actual route contract');if(event.Action==='run')started.push(name);if(event.Action==='pass')passed.push(name);}
  else if(event.Action==='pass')packages.set(event.Package,(packages.get(event.Package)||0)+1);
 }
 assert.deepEqual(started.sort(),wanted);assert.deepEqual(passed.sort(),wanted);
 assert.deepEqual([...packages.keys()].sort(),[...spec.packages].sort());assert([...packages.values()].every(n=>n===1));
 return {ok:true,architecture,actual_PASS:passed.length,test_roots:4,skips:0,source_inputs_sha256:spec.source_inputs_sha256,source_only_not_installed:true};
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 assert.equal(process.argv.length,4);assert.equal(process.platform,'linux');assert.equal(process.argv[3],process.arch==='arm64'?'aarch64':process.arch==='x64'?'x86_64':'unsupported');
 const input=process.argv[2],st=fs.lstatSync(input);assert(st.isFile()&&!st.isSymbolicLink()&&st.nlink===1&&st.size>0&&st.size<=4<<20);
 const sdk=fs.realpathSync(fileURLToPath(new URL('../candidate/panel-integration-load-balance/',import.meta.url))),index=JSON.parse(fs.readFileSync(sdk+'/source-sha256.json'));
 assert.equal(index.release.frozen_inputs_sha256,spec.source_inputs_sha256);assert.equal(Object.keys(index.files).length,spec.source_file_count);
 for(const[name,digest]of Object.entries(index.files)){
  assert(!path.posix.isAbsolute(name)&&path.posix.normalize(name)===name&&!name.split('/').includes('..'));
  const file=path.join(sdk,name),s=fs.lstatSync(file);assert(file.startsWith(sdk+path.sep)&&fs.realpathSync(file)===file&&s.isFile()&&!s.isSymbolicLink()&&s.nlink===1&&s.size<=2<<20);
  assert.equal(createHash('sha256').update(fs.readFileSync(file)).digest('hex'),digest,name);
 }
 console.log(JSON.stringify(verifyAnalyticsRouteExecution(fs.readFileSync(input,'utf8').trim().split('\n').map(line=>JSON.parse(line)),process.argv[3])));
}
