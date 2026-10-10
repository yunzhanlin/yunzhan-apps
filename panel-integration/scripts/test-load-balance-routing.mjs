import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import ts from '../web/node_modules/typescript/lib/typescript.js';
const read=p=>readFileSync(new URL('../'+p,import.meta.url),'utf8');
const compile=async p=>import('data:text/javascript;base64,'+Buffer.from(ts.transpileModule(read(p),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText).toString('base64'));
const {loadBalanceRoutingSaveBody}=await compile('web/src/loadBalanceRouting.ts');
const {loadBalanceEntryFields,loadBalanceEntryRow,loadBalanceTransitions}=await compile('web/src/loadBalanceReport.ts');
const domain='routing.example.test';
test('historical observation and explicit off never require or grant active authority',()=>{
  for(const health_check of [undefined,null,{}, {auto_traffic:false}]) {
    const body={domain,health_check};
    assert.equal(loadBalanceRoutingSaveBody(body),body);
  }
  for(const health_check of [[],1,'true', {auto_traffic:1},{auto_traffic:'true'},{auto_traffic:null}])assert.throws(()=>loadBalanceRoutingSaveBody({domain,health_check}));
});
test('active save requires exact current domain confirmation and no coercion',()=>{
  const body={domain,health_check:{auto_traffic:true},confirm:'ENABLE HEALTH ROUTING '+domain};
  assert.equal(loadBalanceRoutingSaveBody(body),body);
  for(const change of [{confirm:''},{confirm:body.confirm+' '},{confirm:'ENABLE HEALTH ROUTING other.example.test'},{domain:'ROUTING.example.test'},{domain:'../bad'},{domain:1}])assert.throws(()=>loadBalanceRoutingSaveBody({...body,...change}));
});
test('entry selection copies policy and nodes but never reuses confirmation or runtime authority',()=>{
  const row={nodes:[{address:'127.0.0.1:41001',weight:2}],health_check:{auto_traffic:true,path:'/ready'},backend_tls:{server_name:domain},routing:{sequence:7,down:['127.0.0.1:41001']},confirm:'already-confirmed',password:'secret'};
  const fields=loadBalanceEntryFields(row);
  assert.deepEqual(Object.keys(fields).sort(),['backend_tls','confirm','health_check','nodes']);
  assert.equal(fields.confirm,'');
  fields.nodes[0].weight=9;fields.health_check.path='/changed';fields.backend_tls.server_name='new.example.test';
  assert.equal(row.nodes[0].weight,2);assert.equal(row.health_check.path,'/ready');assert.equal(row.backend_tls.server_name,domain);
  const display=loadBalanceEntryRow(row);
  assert.equal(display.automatic_traffic_changes,true);assert.equal(display.routing_sequence,7);assert.equal(display.excluded_nodes,'127.0.0.1:41001');
  assert.equal(loadBalanceEntryRow({...row,health_check:{auto_traffic:'true'}}).automatic_traffic_changes,false);
});
test('history identity includes desired revision so a policy reset cannot hide earlier transitions',()=>{
  const at='2026-10-10T00:00:00Z';
  const events=loadBalanceTransitions([{domain,transitions:[{sequence:1,revision:1,at,to:'unhealthy'},{sequence:1,revision:2,at,to:'healthy'},{sequence:1,revision:2,at,to:'healthy'},{sequence:1,at,to:'invalid'}]}]);
  assert.equal(events.length,2);assert.deepEqual(events.map(e=>e.revision).sort(),[1,2]);
});
test('manager and packaging require dedicated explicit switch, closed save and native result columns',()=>{
  const manager=read('web/src/AppModuleManager.vue'),report=read('web/src/AppModuleReport.vue');
  assert.match(manager,/auto_traffic:false/);
  assert.match(manager,/typeof value!=='boolean'/);
  assert.match(manager,/aria-label="启用故障节点自动摘除与恢复"/);
  assert.match(manager,/action==='save' \? loadBalanceRoutingSaveBody\(body\)/);
  assert.match(manager,/auto_traffic=value;form.value.confirm=''/);
  assert.match(report,/traffic_excluded/);assert.match(report,/routing_sequence/);
  assert.match(read('packaging/build-release.sh'),/test-load-balance-routing\.mjs/);
});
