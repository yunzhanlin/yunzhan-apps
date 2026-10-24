import{originalReviewedHTTPSFixtureWorkflow}from'./reviewed-https-fixture-workflow.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';
const root=fileURLToPath(new URL('../',import.meta.url)),scope='panel-integration-runtime-memory/',read=n=>fs.readFileSync(root+n),json=n=>JSON.parse(read(n)),sha=b=>createHash('sha256').update(b).digest('hex');
const changed=['dev/panel-install@.service','internal/executor/build_resources.go','internal/executor/install_linux.go','internal/executor/program_upgrade_queues_linux.go','packaging/test_runtime_install_budget.py'];
const added=['internal/core/runtime_compile_oom_upgrade.go','internal/core/runtime_compile_oom_upgrade_test.go','internal/executor/build_cgroup_resources.go','internal/executor/build_cgroup_resources_linux.go','internal/executor/build_cgroup_resources_other.go','internal/executor/build_cgroup_resources_test.go','internal/executor/program_upgrade_runtime_compile_oom_linux.go','internal/executor/program_upgrade_runtime_compile_oom_linux_test.go','internal/executor/runtime_php_magic.go','internal/executor/runtime_php_magic_linux.go','internal/executor/runtime_php_magic_linux_test.go','internal/executor/runtime_php_magic_native_linux_test.go','internal/executor/runtime_php_magic_test.go'];
test('runtime memory source is the exact1777 normal files and1327 Go members without overlays',()=>{
 const index=json(scope+'source-sha256.json');assert.equal(sha(read(scope+'source-sha256.json')),'3a11544bc85edc7e815611da594706acac4c42b8dec7ff2fb22f33a4afb7a016');assert.equal(index.release.frozen_inputs_sha256,'286ecb49e1ae1abd566e40c065b044b4dd6d6ad9c3362733328eaa7beb5185e1');assert.equal(index.release.archive_sha256,'86061f90730d329f6555477cc62958e9ffc756afb4e8454872ae3338da02ddd5');assert.equal(Object.keys(index.files).length,1777);assert.equal(Object.keys(index.files).filter(n=>n.endsWith('.go')).length,1327);assert.deepEqual(index.test_overrides,{});assert.deepEqual(json(scope+'release-source-inputs.json').files,index.files);
 for(const[name,digest]of Object.entries(index.files)){assert(path.posix.normalize(name)===name&&!path.isAbsolute(name)&&!name.split('/').some(n=>['..','.git','.local','node_modules'].includes(n)));const info=fs.lstatSync(root+scope+name);assert(info.isFile()&&!info.isSymbolicLink()&&info.nlink===1);assert.equal(sha(read(scope+name)),digest,name);}
});
test('only the bounded build and separate OOM proof change; original collectors,status,retry and installer stay immutable',()=>{
 const current=json(scope+'source-sha256.json'),old=json('panel-integration-compiler-exit/source-sha256.json');assert(Object.keys(old.files).every(n=>Object.hasOwn(current.files,n)));assert.deepEqual(Object.keys(current.files).filter(n=>!Object.hasOwn(old.files,n)).sort(),[...added].sort());assert.deepEqual(Object.keys(current.files).filter(n=>Object.hasOwn(old.files,n)&&current.files[n]!==old.files[n]).sort(),[...changed].sort());
 for(const name of['internal/executor/runtime_compiler_scope_linux.go','internal/executor/runtime_compiler_collection_native_linux_test.go','internal/executor/runtime_compiler_php_configure_native_linux_test.go','internal/executor/program_upgrade_runtime_failed_linux.go','internal/executor/program_upgrade_runtime_failed_linux_test.go','internal/executor/runtime_install_status_linux.go','internal/executor/runtime_install_observation.go','internal/executor/runtime_install_retention_linux.go','internal/core/runtime_failed_upgrade.go','internal/core/runtime_native_retry.go','packaging/signed-release.py','packaging/upgrade-release.py','web/src/FileManager.vue'])assert.equal(current.files[name],old.files[name],name);
});
test('fileinfo changes only the reviewed exact2 generated representations, retaining original one-dimensional size and bytes',()=>{
 const common=read(scope+'internal/executor/runtime_php_magic.go').toString(),prepare=read(scope+'internal/executor/runtime_php_magic_linux.go').toString();
 for(const text of['php-8.2.35','php-8.3.36','bcd3eec44aa4e4eeb7deb4ee6b6cfb596dcc7baa','d2375f7306b94d7b35f42cd9afc83f54b3072936fc1dfb90eac2add22d60ef5a','9e18775970ba5aa3efab3912de48b7baaa90128c8ccb9880465d80422ff9537f','2aa3463ba3b5e4a1e729c5d288719a8b666510c51bd32e1083fbc6068f16f27e','e49c1e50fdfcb2c60d170559ff6bcb2417ff2a7c157e0c2d2602d1d554507031','rawBytes:   42528803','dataBytes:  7015032','dataBytes:  7955032','ZEND_NONSTRING','exactly three octal digits','original ONE-dimensional'])assert(common.includes(text),text);
 for(const text of['BEFORE chown/configure','spec.archiveSHA','runtimeMagicSourceSame','retained := runtimeMagicPath + ".upstream-"','renameNoReplace(root, runtimeMagicPath, retained)','target.Sync()'])assert(prepare.includes(text),text);
 for(const bad of['--disable-fileinfo','"-O0"','"-O1"','memory_limit=-1'])assert(!(common+prepare).includes(bad),bad);
});
test('normal runtime unit has finite memory,no swap,full cgroup kills and original five-hour supervisor budget',()=>{
 const settings=Object.fromEntries(read(scope+'dev/panel-install@.service').toString().split('\n').filter(n=>n.includes('=')).map(n=>n.split(/=(.*)/s).slice(0,2)));
 for(const[key,value]of Object.entries({MemoryAccounting:'true',MemoryHigh:'640M',MemoryMax:'768M',MemorySwapMax:'0',OOMPolicy:'stop',OOMScoreAdjust:'500',Environment:'GOMEMLIMIT=128MiB',NoNewPrivileges:'true',ProtectControlGroups:'true',KillMode:'control-group',TimeoutStartSec:'300min'}))assert.equal(settings[key],value,key);
 const code=read(scope+'internal/executor/build_cgroup_resources_linux.go').toString();for(const text of['/proc/self/cgroup','nativeCompilerCgroupUnit','memory.max','memory.current','/sys/fs/cgroup/system.slice','return minimum, true'])assert(code.includes(text),text);assert(!code.includes('WriteFile')&&!code.includes('O_WRONLY'));
});
test('OOM proof is SELECT-only,separate,dual-fenced,pre-publication and does not normalize the original running ledger',()=>{
 const core=read(scope+'internal/core/runtime_compile_oom_upgrade.go').toString(),native=read(scope+'internal/executor/program_upgrade_runtime_compile_oom_linux.go').toString();
 for(const text of['ReadOnly: true','state != "failed"','detail != RuntimeCompileOOMError','payload != "{}"','consumed_at IS NULL',"state NOT IN ('failed','succeeded')",'FROM runtime_installations','FROM runtime_instances','FROM sites','RuntimeCompileOOMSteps'])assert(core.includes(text),text);
 for(const text of['"Result": "oom-kill"','"ExecMainCode": "2"','"ExecMainStatus": "15"','status.State != "running"','status.Error != ""','runtimeCompileOOMReadLease(root, ".native-start.lock")','runtimeCompileOOMReadLease(root, "build.lock")','unix.LOCK_SH|unix.LOCK_NB','version + ".pending-" + id','finalBound != bound','finalPublication != publication','finalGeneration != generation'])assert(native.includes(text),text);
 for(const bad of['os.O_CREATE','WriteFile(','writeInstall(','syscall.Kill(','reset-failed','RetryRuntime(','NewService('])assert(!native.includes(bad),bad);
 const queues=read(scope+'internal/executor/program_upgrade_queues_linux.go').toString();assert(queues.includes('5*time.Second'));assert(queues.includes('closedRuntimeFailedInstall(ctx, name, run) || closedRuntimeCompileOOMInstall(ctx, name, run)'));
});
test('genuine constrained fixture validates actual ELF symbol size,bytes,O2,collection and retained official input',()=>{
 const code=read(scope+'internal/executor/runtime_php_magic_native_linux_test.go').toString();for(const text of['00000000000000e5','805306368','128MiB','spec.archiveSHA','prepareRuntimePHPBuildSource','"/usr/bin/make", "-j1", "ext/fileinfo/libmagic/apprentice.lo"','symbol.Size != uint64(spec.dataBytes)','hex.EncodeToString(sum[:]) != spec.dataSHA','compilerHasNoChildren()','"runtime_or_application_installed": false'])assert(code.includes(text),text);
});
test('new CI preserves the complete original24-job byte prefix and forbids overlays or softened failure handling',()=>{
 const workflow=originalReviewedHTTPSFixtureWorkflow(read('.github/workflows/verify.yml')),at=workflow.indexOf('\n  runtime-memory-native-amd64:\n');assert(at>0);assert.equal(sha(workflow.subarray(0,at)),'e2739695c90060d367ba0690b1448b802fef629d9f8e295dba7f40a27aec899a');const gate=workflow.subarray(at).toString();assert(gate.includes('panel-integration-runtime-memory')&&gate.includes('tools/run-runtime-memory-native-ci.mjs'));for(const bad of['continue-on-error','-overlay=','reset-failed','killall','pkill'])assert(!gate.includes(bad),bad);
});
test('the new exclusive exporter and actual native CI collector parse before dispatch',()=>{
 for(const file of ['tools/export-runtime-memory-source.mjs','tools/run-runtime-memory-native-ci.mjs']){
  const result=spawnSync(process.execPath,['--check',root+file],{encoding:'utf8',timeout:10000});assert.equal(result.status,0,result.stderr);assert(!result.error);
 }
});
