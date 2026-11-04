import test from 'node:test';import assert from 'node:assert/strict';
import {spec,verifyAnalyticsRouteExecution} from '../tools/check-analytics-route-execution.mjs';
// Closed fabricated parser fixtures only; never claim actual Linux execution.
const events=()=>[...spec.expected_tests.flatMap(x=>[{Package:x.package,Test:x.name,Action:'run'},{Package:x.package,Test:x.name,Action:'pass'}]),...spec.packages.map(Package=>({Package,Action:'pass'}))];
test('route CI parser admits only its exact closed forty-two test identities and two package completions',()=>{assert.equal(verifyAnalyticsRouteExecution(events(),'x86_64').actual_PASS,42);assert.equal(verifyAnalyticsRouteExecution(events(),'aarch64').source_only_not_installed,true)});
for(const scenario of['empty','missing','duplicate','foreign-test','foreign-package','skip','fail','missing-package','duplicate-package'])test('route CI parser refuses '+scenario,()=>{
 const v=events();
 if(scenario==='empty')v.length=0;if(scenario==='missing')v.splice(0,2);if(scenario==='duplicate')v.push(v[0]);if(scenario==='foreign-test')v[0].Test='TestDifferent';if(scenario==='foreign-package')v[0].Package='other';if(scenario==='skip')v.push({...v[0],Action:'skip'});if(scenario==='fail')v.push({...v[0],Action:'fail'});if(scenario==='missing-package')v.pop();if(scenario==='duplicate-package')v.push(v.at(-1));
 assert.throws(()=>verifyAnalyticsRouteExecution(v,'x86_64'));
});
