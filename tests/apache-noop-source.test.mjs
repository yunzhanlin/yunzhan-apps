import test from'node:test';
import assert from'node:assert/strict';
import fs from'node:fs';
import path from'node:path';
import{fileURLToPath}from'node:url';
import{createHash}from'node:crypto';
const root=fileURLToPath(new URL('../',import.meta.url)),scope='panel-integration-apache-noop/',read=n=>fs.readFileSync(root+n),json=n=>JSON.parse(read(n)),sha=b=>createHash('sha256').update(b).digest('hex');
test('Apache no-op source is the exact normal1781-file1331-Go immutable export without overlays',()=>{
 const x=json(scope+'source-sha256.json');
 assert.equal(sha(read(scope+'source-sha256.json')),'a9b6fc26e8b9e8b7e025cccb792eb9168633441e1be2b197f9d80cb428c27e98');
 assert.equal(x.release.frozen_inputs_sha256,'641c9b007799536e5bed5fcc22c6c7a9229e1bfe9b8ec56d4a79fb984d702d00');
 assert.equal(x.release.archive_sha256,'6f7cba3d2b5e729ef46a5c733642d27c12d09aa6212de7bc2d500cb8bdfbd61b');
 assert.equal(Object.keys(x.files).length,1781);assert.equal(Object.keys(x.files).filter(n=>n.endsWith('.go')).length,1331);assert.deepEqual(x.test_overrides,{});assert.deepEqual(json(scope+'release-source-inputs.json').files,x.files);
 for(const[n,h]of Object.entries(x.files)){assert.equal(path.posix.normalize(n),n);assert(!path.isAbsolute(n)&&!n.split('/').some(c=>['..','.git','.local','node_modules'].includes(c)));const s=fs.lstatSync(root+scope+n);assert(s.isFile()&&!s.isSymbolicLink()&&s.nlink===1);assert.equal(sha(read(scope+n)),h,n);}
});
test('only metadata website no-op ordering and exact JSON whitespace optimization differ from admitted F33',()=>{
 const current=json(scope+'source-sha256.json'),old=json('panel-integration-php-bounded/source-sha256.json');
 assert(Object.keys(old.files).every(n=>Object.hasOwn(current.files,n)));
 assert.deepEqual(Object.keys(current.files).filter(n=>!(n in old.files)).sort(),['internal/executor/apache_waf_site_noop_native_linux_test.go','internal/executor/load_balance_json_whitespace.go','internal/executor/load_balance_json_whitespace_test.go']);
 const changed=['internal/executor/apache_waf_site_edit_linux.go','internal/executor/app_load_balance_history_linux.go'];
 assert.deepEqual(Object.keys(current.files).filter(n=>n in old.files&&current.files[n]!==old.files[n]).sort(),changed);
 for(const[n,h]of Object.entries(old.files))if(!changed.includes(n))assert.equal(current.files[n],h,n);
});
test('unchanged metadata triplet is validated before no-op; real Apache edits retain inactive-service and loaded-generation checks',()=>{
 const src=read(scope+'internal/executor/apache_waf_site_edit_linux.go').toString(),fixture=read(scope+'internal/executor/apache_waf_site_noop_native_linux_test.go').toString();
 const a=src.indexOf('apacheWAFConfigurationFilesMatchVersion(oldSource'),b=src.indexOf('apacheMetadataSitePolicy(content, cfg'),c=src.indexOf('apacheMetadataSiteBackupSame(before, after)'),d=src.indexOf('if apacheMetadataSiteSourceSame(prepared, oldSource'),e=src.indexOf('return func() error { return nil }, true, nil',d),f=src.indexOf('s.Config.Run(ctx, "/usr/bin/systemctl", "is-active", "panel-apache")'),g=src.indexOf('apacheWAFWaitLoadedVersion(ctx, cfg, domain, installed.Version)'),h=src.indexOf('next.Policy.Revision++');
 assert(0<a&&a<b&&b<c&&c<d&&d<e&&e<f&&f<g&&g<h);
 for(const s of ['txs.wafPendingPath()','Apache 防护存在','Apache 防护服务未运行'])if(s!=='Apache 防护存在')assert(src.includes(s),s);
 for(const s of ['identical','exact-module-relocation','changed-host-stopped','changed-alias-stopped','wrong-rules','duplicate-manifest','pending-transaction','reflect.DeepEqual(before[i], after)','wantCalls = 1'])assert(fixture.includes(s),s);
 assert(!src.slice(d,e).includes('实际加载指纹未变化'));
});
test('27th source gate preserves every byte of all26 earlier jobs and original limits',()=>{
 const bytes=read('.github/workflows/verify.yml'),at=bytes.indexOf('\n  apache-noop-native-amd64:\n');assert(at>0);assert.equal(sha(bytes.subarray(0,at)),"2e19460667e5b4c459b5ae117379d0c46ace55f8e602f3a7bd3e952420094957");
 const gate=bytes.subarray(at).toString();for(const s of ['panel-integration-apache-noop','go vet ./...','-race','TestLoadBalanceTrafficNativeMaximumRecordAndByteBudgetsMeasuredWithoutCommands'])assert(gate.includes(s),s);
 for(const s of ['continue-on-error','-overlay=','reset-failed','killall','pkill'])assert(!gate.includes(s),s);
 assert(read(scope+'internal/executor/program_upgrade_queues_linux.go').toString().includes('5*time.Second'));
 const cap=read(scope+'internal/executor/app_load_balance_traffic_alert_linux_test.go').toString();assert(cap.includes('2*time.Second')&&cap.includes('len(bounded.Records) != 2560'));
});
