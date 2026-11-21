import {test} from 'node:test';
import assert from 'node:assert/strict';
import {parseApacheRuntimeStatus} from '../web/src/apacheRuntime.ts';
import {apacheBodyBuildRow} from '../web/src/apacheBodyBuild.ts';
const baseline={selected_id:'apache-2.4.68',running_id:'apache-2.4.68',service_state:'active',recommended_id:'apache-2.4.71',target_installed:true,native_engine_required:true,waf_version:'2.5.1',activation_needed:true,checked_at:'2026-11-21T00:00:00Z'};
test('installing the fixed runtime does not claim existing sites are patched',()=>{
 assert.equal(parseApacheRuntimeStatus(baseline).activation_needed,true);
 const active={...baseline,selected_id:'apache-2.4.71',running_id:'apache-2.4.71',activation_needed:false};
 assert.equal(parseApacheRuntimeStatus(active).activation_needed,false);
 for(const patch of [{activation_needed:false},{target_installed:'true'},{running_id:''},{selected_id:'apache-2.4.70'},{running_id:'apache-2.4.70'},{checked_at:'unknown'}])assert.throws(()=>parseApacheRuntimeStatus({...baseline,...patch}));
 assert.throws(()=>parseApacheRuntimeStatus({...active,target_installed:false}));
 assert.equal(parseApacheRuntimeStatus({...active,target_installed:false,activation_needed:true}).activation_needed,true);
 assert.equal(parseApacheRuntimeStatus({...baseline,service_state:'inactive',running_id:''}).activation_needed,true);
});
test('current engine inventory admits the exact new runtime without expanding legacy retention',()=>{
 const row={job_id:'a'.repeat(32),state:'ready',build_only:true,architecture:'arm64',engine_version:'2.9.15-yz5',yajl_version:'2.1.0-debian5-yz1',crs_version:'4.30.0',apache_version:'2.4.71',integrity_verified:true,module_abi_validated:true,elf_hardening_validated:true,compiler_groups_collected:true,steps:[]};
 assert.equal(apacheBodyBuildRow(row),true);assert.equal(apacheBodyBuildRow({...row,apache_version:'2.4.70'}),false);
 assert.equal(apacheBodyBuildRow({...row,apache_version:'2.4.71',state:'retained_unsupported',engine_version:'2.9.15-yz4',error:'retained only',historical_integrity_verified:true,integrity_verified:false,module_abi_validated:false,elf_hardening_validated:false,compiler_groups_collected:false}),false);
});

// These are exact pre-C265 signed-source hashes, not refreshed expected output.
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {beforeApacheRuntimeBuild,beforeApacheRuntimeApp} from './release-build-baseline.mjs';
test('the new build gate preserves all previous commands and is mandatory exactly once',()=>{
 const text=readFileSync(new URL('../packaging/build-release.sh',import.meta.url),'utf8');
 const line='(cd "$BUILD_ROOT" && /opt/homebrew/bin/node --test scripts/test-apache-runtime.mjs) 2>&1 | tee -a "$STAGE/$NAME/BUILD_CHECKS.txt"\n';
 assert.equal(createHash('sha256').update(beforeApacheRuntimeBuild(text)).digest('hex'),'ab38501ddb91cb14e97344f136125150dfe2c7bcb6d67a1904d4a1bcd8fa6300');
 for(const changed of [text.replace(line,''),text.replace(line,line+line),text.replace(line,line.replace('--test','--check')),text.replace(line,'')+line])assert.throws(()=>beforeApacheRuntimeBuild(changed));
 assert.notEqual(beforeApacheRuntimeBuild(text.replace('go vet ./...','unreviewed-command ./...')),beforeApacheRuntimeBuild(text));
});
test('Apache manager changes preserve the complete previous App component outside their exact additions',()=>{
 const text=readFileSync(new URL('../web/src/App.vue',import.meta.url),'utf8');
 assert.equal(createHash('sha256').update(beforeApacheRuntimeApp(text)).digest('hex'),'98effed9cd3e2cc7ea9c54c31e435499a68b49bb9fb74ebc2957bd4d9e923700');
 const marker='  switch_apache: "切换 Apache 运行版本",\n';
 for(const changed of [text.replace(marker,''),text.replace(marker,marker+marker),text.replace(marker,marker.replace('switch_apache','unreviewed-action'))])assert.throws(()=>beforeApacheRuntimeApp(changed));
});

import {createRequire} from 'node:module';
import ts from '../web/node_modules/typescript/lib/typescript.js';
import {randomId} from '../web/src/randomId.ts';
import {apacheBodyBuildInventory} from '../web/src/apacheBodyBuild.ts';
const vue=createRequire(new URL('../web/package.json',import.meta.url))('vue');
test('actual Apache manager submits a Core-compatible nonce and retains it after an uncertain response',async()=>{
 const source=readFileSync(new URL('../web/src/ApacheRuntimeManager.vue',import.meta.url),'utf8');
 const start=source.indexOf('const visible='),end=source.indexOf('defineExpose({open});');assert(start>0&&end>start);
 const actual=ts.transpileModule(source.slice(start,end),{compilerOptions:{target:ts.ScriptTarget.ES2022}}).outputText;
 const posts=[],jobs=[];let reads=0,installations=0;
 const props={api:async(path,method,body,key)=>{
  if(method===undefined){assert.equal(path,'/runtimes/apache');reads++;return {...baseline,native_engine_required:false};}
  assert.equal(path,'/runtimes/apache/switch');assert.equal(method,'POST');posts.push({body,key});
  if(posts.length===1)throw Error('original HTTP response unavailable');
  return {job_id:'a'.repeat(32)};
 },onJob:id=>jobs.push(id),onInstall:()=>installations++};
 const manager=new Function('computed','ref','props','randomId','parseApacheRuntimeStatus','apacheBodyBuildInventory',actual+'\nreturn {open,refresh,activate,pending,error};')(vue.computed,vue.ref,props,randomId,parseApacheRuntimeStatus,apacheBodyBuildInventory);
 await manager.open();assert.equal(posts.length,0);await manager.activate();
 assert.equal(posts.length,1);assert.match(posts[0].key,/^[a-f0-9]{32}$/);assert.equal(manager.pending.value,posts[0].key);assert.deepEqual(posts[0].body,{release_id:'apache-2.4.71',engine_job_id:''});assert.match(manager.error.value,/original HTTP response unavailable/);
 await manager.refresh();assert.equal(posts.length,1);assert.equal(manager.pending.value,posts[0].key);
 await manager.activate();assert.equal(posts.length,2);assert.deepEqual(posts[1],posts[0]);assert.equal(manager.pending.value,'');assert.deepEqual(jobs,['a'.repeat(32)]);assert.equal(reads,2);assert.equal(installations,0);
});
