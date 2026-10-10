import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
const read=p=>readFile(new URL('../'+p,import.meta.url),'utf8');
test('normal ABH exact source keeps a bounded slow official Apache archive and independent idle timeout',async()=>{
 const release=JSON.parse(await read('panel-integration/release-source-inputs.json'));
 assert.equal(release.frozen_inputs_sha256,'85c54234bfa58b6e25b8919f96bab560466ba197493e233b11cef206d75971fe');
 assert.equal(release.archive_sha256,'e08523947e4c913d470aa784e79c556796ca7df958de5f07cc75fc667f50b243');
 for(const file of ['internal/executor/install_linux.go','internal/executor/runtime_source_download_linux_test.go','internal/runtimecatalog/source_archive.go']){
  assert.equal(createHash('sha256').update(await read('panel-integration/'+file)).digest('hex'),release.files[file]);
 }
 const source=await read('panel-integration/internal/executor/install_linux.go');
 assert.match(source,/known != r/);assert.match(source,/status\.Status == 404 \|\| status\.Status == 410/);
 assert.match(source,/Total: 8 \* time\.Minute, BodyIdle: 45 \* time\.Second/);assert.match(source,/limits\.Total = 20 \* time\.Minute/);
 assert.match(source,/ResponseHeaderTimeout = 30 \* time\.Second/);assert.match(source,/time\.AfterFunc\(limits\.BodyIdle/);assert.match(source,/r\.Timer\.Reset\(r\.Idle\)/);
 assert.match(source,/context\.Cause\(transferContext\)/);assert.match(source,/64\*1024\*1024\+1/);assert.doesNotMatch(source,/InsecureSkipVerify\s*:/);
 const fixture=await read('panel-integration/internal/executor/runtime_source_download_linux_test.go');
 assert.equal((fixture.match(/^func TestRuntimeSourceDownload/gm)||[]).length,12);
 for(const name of ['SlowProgressStillVerifiesEveryByte','NoProgressAndPartialProgressFailClosed','TotalBudgetEvenWithContinuousProgress','StrictTLSBeforeCreatingSource','DigestMismatchHasNoSuccess','BodyCapacityStillBounded','CancelledBeforeOrBetweenRequests','NoUntrustedFallback'])assert(fixture.includes('TestRuntimeSourceDownload'+name));
});
test('source-transfer fixture success does not erase genuine failure or declare all 50 commercial',async()=>{
 const contracts=JSON.parse(await read('registry/functional-contracts.json'));
 assert.equal(contracts.apps.length,50);assert.equal(contracts.commercial_feature_parity_complete,false);
 const apache=contracts.apps.find(a=>a.id==='apache'),waf=contracts.apps.find(a=>a.id==='apache-waf');
 assert(apache.gaps.some(v=>v.includes('真实源码构建')&&v.includes('仍待完成')));
 assert(apache.boundaries.some(v=>v.includes('部分源码')));
 assert(waf.boundaries.some(v=>v.includes('6703942')&&v.includes('实际失败')&&v.includes('日志留存')));
 assert(waf.boundaries.some(v=>v.includes('45 秒')&&v.includes('不等于')));
 assert(waf.gaps.some(v=>v.includes('真实已安装签名应用更新')));
});
