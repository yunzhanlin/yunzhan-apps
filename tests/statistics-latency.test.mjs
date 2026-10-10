import {readFile} from 'node:fs/promises';
import assert from 'node:assert/strict';
import test from 'node:test';
const read=p=>readFile(new URL('../'+p,import.meta.url),'utf8');
test('statistics 2.4 advances the immutable manifest and publishes real bounded latency accumulation',async()=>{
 const registry=JSON.parse(await read('registry/apps.json')),app=registry.apps.find(a=>a.id==='website-statistics-v2');
 assert.equal(app.version,'2.4.0');assert(app.capabilities.some(c=>c.includes('P50/P90/P95/P99')));
 const source=await read('panel-integration/internal/executor/app_analytics_latency.go');
 assert.match(source,/analyticsLatencySampleLimit = 250000/);assert.match(source,/a.samples = nil/);assert.match(source,/len\(a.samples\)\*percent \+ 99/);
 assert.match(source,/Source: "nginx_request_time"/);assert.match(source,/Method: "nearest_rank"/);assert.match(source,/\*float64/);
 const aggregate=await read('panel-integration/internal/executor/app_analytics_report.go');
 assert(aggregate.indexOf('requests++')<aggregate.indexOf('latency.add(row.Seconds)'));assert.match(aggregate,/"latency": latencyReport/);
 const ui=await read('panel-integration/web/src/AnalyticsLatencyReport.vue');assert.match(ui,/没有有效请求/);assert.match(ui,/前段样本/);assert.match(ui,/<caption>/);assert.doesNotMatch(ui,/v-html|Math.random/);
});
test('native fixtures and server-side guidance do not conflate slow threshold or empty data with zeros',async()=>{
 const tests=await read('panel-integration/internal/executor/app_analytics_latency_test.go');
 for(const name of ['ExactLatencyRanksAndHistogramEdges','LatencyHasNoFakeEmptyOrBiasedQuantiles','LatencySharesTrafficFiltersAndSlowThreshold'])assert(tests.includes('TestAnalyticsReport'+name));
 assert.match(await read('panel-integration/internal/executor/app_statistics_history_linux_test.go'),/TestStatisticsHistoryLatencyUsesDurableRowsAndFilters/);
 const guidance=await read('panel-integration/internal/core/app_module_guidance.go');assert.match(guidance,/慢请求阈值只改变/);assert.match(guidance,/不是后端执行耗时/);
 const contracts=JSON.parse(await read('registry/functional-contracts.json'));assert.equal(contracts.commercial_feature_parity_complete,false);
});
