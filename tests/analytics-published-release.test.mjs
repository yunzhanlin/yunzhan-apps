import{originalReviewedHTTPSFixtureWorkflow}from'./reviewed-https-fixture-workflow.mjs';
import test from 'node:test';import assert from 'node:assert/strict';import fs from 'node:fs';
import {catalogBeforeAnalyticsBytes,analyticsSignedCatalogBytes} from './previous-analytics-catalog.mjs';
import {originalAnalyticsWorkflow,scopedPredecessorWorkflow} from './pre-analytics-workflow.mjs';
import {verifyOldHandlerRefusal} from '../tools/verify-analytics-handler-boundary.mjs';
const read=p=>fs.readFileSync(new URL('../'+p,import.meta.url));
test('the actual new original-key signed package changes only analytics and pins the compiled session handler',()=>{
 const before=JSON.parse(catalogBeforeAnalyticsBytes()),now=JSON.parse(analyticsSignedCatalogBytes()),manifest=JSON.parse(read('dist/apps/website-analytics/2.3.1/manifest.json'));
 assert.equal(before.apps.find(a=>a.id==='website-analytics').version,'2.3.0');assert.equal(now.apps.find(a=>a.id==='website-analytics').version,'2.3.1');assert.deepEqual(manifest.required_panel_features,['analytics-session-lifecycle-v1']);
 assert(manifest.capabilities.some(s=>s.includes('30 分钟')));assert(manifest.capabilities.some(s=>s.includes('不刷新旅程')));assert(manifest.summary.includes('默认关闭'));assert.equal(manifest.delivery.provider,'panel-module');
});
test('all seven old positive cohorts retain exact predecessor scope; every other original CI byte stays intact',()=>{
 const raw=originalReviewedHTTPSFixtureWorkflow(read('.github/workflows/verify.yml'));assert.equal(raw.toString().split('registry/reviewed-catalogs/before-analytics-session24bgnt"').length-1,7);
 const restored=originalAnalyticsWorkflow(raw);assert(restored.includes('working-directory: panel-integration-analytics-session'));assert(raw.toString().startsWith(scopedPredecessorWorkflow));
 assert.throws(()=>originalAnalyticsWorkflow(Buffer.from(raw.toString().replace('go vet ./...','true'))));
});
test('old-handler negative gate accepts only one exact refusal while requiring all other49 success',()=>{
 const ids=['website-analytics',...Array.from({length:49},(_,i)=>'app-'+i)],p='TestPublishedRepositoryCurrentSignedManifestABI';
 const events=[...ids.slice(1).map(id=>({Action:'pass',Test:p+'/'+id})),{Action:'output',Test:p+'/website-analytics',Output:'面板处理器不支持 analytics-session-lifecycle-v1'},{Action:'fail',Test:p+'/website-analytics'},{Action:'fail',Test:p},{Action:'fail'}];
 const result={status:1,stdout:events.map(e=>JSON.stringify(e)).join('\n')};assert(verifyOldHandlerRefusal(result,ids).old_core_not_weakened);
 for(const mutate of [x=>x.status=0,x=>x.stdout=x.stdout.replace('analytics-session-lifecycle-v1','other-feature'),x=>x.stdout=x.stdout.split('\n').slice(1).join('\n'),x=>x.stdout+='\n'+JSON.stringify({Action:'skip',Test:p+'/other'}),x=>x.stdout+='\n'+JSON.stringify({Action:'fail',Test:p+'/other'})]){const bad=structuredClone(result);mutate(bad);assert.throws(()=>verifyOldHandlerRefusal(bad,ids));}
});
