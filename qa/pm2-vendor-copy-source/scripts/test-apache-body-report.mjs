import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {apacheBodyReportURL,apacheBodyReportValid,apacheBodyCounting,apacheBodyScope} from '../web/src/apacheBodyReport.ts';
const id='a'.repeat(32);
const filter={site_id:'',rule:'',phase:'',from:'',to:''};
const fixture=()=>({events:[{time:'2026-10-11T00:00:00.123456Z',engine_version:'2.9.15-yz5',site_id:id,rule_id:941100,phase:2,severity:2,mode:'block',intercepted_mark:true}],available:true,partial:false,rejected_lines:0,log_bytes:2048,max_bytes:33554432,capacity_near_limit:false,metadata_best_effort:true,rule_matches:1,scanned:1,rules:[{name:'941100',count:1}],sites:[{name:id,count:1}],from:'2026-10-10T01:00:00Z',to:'2026-10-11T01:00:00Z',page:1,limit:50,counting_contract:apacheBodyCounting,scope:apacheBodyScope});
test('request is read-only closed numeric filters and exact pagination',()=>{
  assert.equal(apacheBodyReportURL(filter,1),'/software/apache-waf/body-report?page=1&limit=50');
  const url=apacheBodyReportURL({...filter,site_id:id,rule:'941100',phase:'2'},2);
  assert.match(url,/page=2&limit=50&site_id=a{32}&rule=941100&phase=2$/);
  for(const changed of [{rule:'01'},{rule:'100000000'},{phase:'6'},{site_id:'private.invalid'},{from:'not-a-date'},{from:'2026-10-11T00:00:00Z',to:'2026-10-10T00:00:00Z'},{cookie:'private'}])assert.throws(()=>apacheBodyReportURL({...filter,...changed},1));
  for(const n of [0,10001,1.5,NaN])assert.throws(()=>apacheBodyReportURL(filter,n));
  assert.throws(()=>apacheBodyReportURL(filter,1,1001));
});
test('numeric report has the same counting and scope as Core, never a request receipt',()=>{
  const source=readFileSync(new URL('../internal/core/apache_body_events.go',import.meta.url),'utf8');
  assert.ok(source.includes(`"${apacheBodyCounting}"`) && source.includes(`"${apacheBodyScope}"`));
  assert.equal(apacheBodyReportValid(fixture(),1),true);
  assert.equal(apacheBodyReportValid({...fixture(),available:false,events:[],rule_matches:0,scanned:0,log_bytes:0,rules:[],sites:[]},1),true);
});
test('unknown private fields, old engine and inconsistent action are refused',()=>{
  for(const change of [{request:'private'},{counting_contract:'http_requests'},{scope:'active'},{scanned:0},{rule_matches:5001},{partial:false,capacity_near_limit:true},{available:false},{page:2},{limit:100}])assert.equal(apacheBodyReportValid({...fixture(),...change},1),false);
  for(const change of [{engine_version:'2.9.15-yz4'},{site_id:'private.invalid'},{phase:9},{severity:-1},{rule_id:100000000},{cookie:'private'},{mode:'observe',intercepted_mark:true},{time:'2026-10-09T00:00:00Z'},{time:'bad'}])assert.equal(apacheBodyReportValid({...fixture(),events:[{...fixture().events[0],...change}]},1),false);
});
test('complete bounded dimensions are required rather than incomplete totals',()=>{
  for(const change of [{rules:[]},{sites:[]},{rules:[{name:'Cookie',count:1}]},{sites:[{name:id,count:2}]},{rules:[{name:'941100',count:1},{name:'941100',count:1}]}])assert.equal(apacheBodyReportValid({...fixture(),...change},1),false);
});
test('actual component clears stale report, discards late tab replies, and never writes or rotates',()=>{
  const source=readFileSync(new URL('../web/src/ApacheBodyEvents.vue',import.meta.url),'utf8');
  assert.match(source,/report\.value=undefined;error\.value=""/);
  assert.match(source,/if\(!current\(ticket\)\)return/);
  assert.match(source,/watch\(\[filter,range\]/);
  assert.match(source,/apacheBodyReportValid\(out,page\.value\)/);
  assert.match(source,/导出当前筛选页 JSON/);
  assert.doesNotMatch(source,/"POST"|"DELETE"|body-log\/rotate|onMounted|setInterval/);
  const workspace=readFileSync(new URL('../web/src/WafWorkspace.vue',import.meta.url),'utf8');
  assert.match(workspace,/<ApacheBodyEvents :api="api" :active="tab==='apache-body-events'" :sites="sites"\/>/);
});
