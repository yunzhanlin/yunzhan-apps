import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {createHash} from 'node:crypto';
import {privatePIDNamespaceTestExecutor} from '../tools/ci-pidns-test-executor.mjs';
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
test('private test executor uses real private procfs,PID1 supervisor and untouched binary arguments',()=>{
 const text=privatePIDNamespaceTestExecutor().toString();assert(text.startsWith('#!/usr/bin/python3 -I\n'));
 for(const value of["os.execv('/usr/bin/unshare'","'--mount'","'--pid'","'--fork'","'--mount-proc'","'--propagation', 'private'","'--kill-child=KILL'",'os.getpid() != 1','os.getppid() != 0',"os.readlink('/proc/self') != '1'",'subprocess.run(sys.argv[1:], check=False)','else 128 - result.returncode','*sys.argv[1:]'])assert(text.includes(value),value);
 for(const bad of['shell=True','continue-on-error','time.sleep','reset-failed','pkill','killall','returncode = 0','startupLeaseSnapshot'])assert(!text.includes(bad),bad);
});
test('historical lease parser and all its exact identity,orphan,deadline and size assertions remain immutable',()=>{
 const prefix=new URL('../panel-integration-hardening/',import.meta.url),index=JSON.parse(fs.readFileSync(new URL('source-sha256.json',prefix)));
 for(const name of['internal/upgradeguard/startup_linux.go','internal/upgradeguard/startup_lease_linux_test.go','internal/upgradeguard/service_startup_linux_test.go'])assert.equal(sha(fs.readFileSync(new URL(name,prefix))),index.files[name],name);
 const code=fs.readFileSync(new URL('internal/upgradeguard/startup_linux.go',prefix),'utf8');for(const value of['100 * time.Millisecond','attempt < 8','len(raw) > 4*1024*1024','ownsStartupLock(raw, record)'])assert(code.includes(value),value);
});
test('historical hardening runner isolates only execution of every original test binary,not compiler or source',()=>{
 const code=fs.readFileSync(new URL('../tools/run-hardening-ci.mjs',import.meta.url),'utf8');assert(code.includes("'-exec='+executor,'./...','-count=1'"));assert(code.includes('privatePIDNamespaceTestExecutor()'));assert(code.includes('production_source_overrides:0,original_assertions_unchanged:true'));assert(!code.includes("'-run'")&&!code.includes("'-skip'")&&!code.includes('continue-on-error'));
});
