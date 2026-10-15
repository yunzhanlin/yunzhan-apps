import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {analyticsCollectorEnabled,analyticsHTMLActiveReady,analyticsHTMLActivationAcknowledged,analyticsHTMLBuildReady} from '../web/src/analyticsHTMLState.ts';
const id='a'.repeat(32);
test('only a complete verified ready build can be selected',()=>{
  const ready={job_id:id,state:'ready',integrity_verified:true,module_abi_validated:true,build_only:true,steps:[]};
  assert.equal(analyticsHTMLBuildReady(ready),true);
  for(const change of [{job_id:'nginx.service'},{state:'succeeded'},{state:'running'},{integrity_verified:false},{module_abi_validated:false},{build_only:false},{error:'failed'}, {job_id:'A'.repeat(32)}])assert.equal(analyticsHTMLBuildReady({...ready,...change}),false);
  assert.equal(analyticsHTMLBuildReady(),false);
});
test('worker acknowledgment is mandatory and absent state is unknown',()=>{
  const ready={job_id:id,state:'active',active:true,worker_acknowledged:true};
  assert.equal(analyticsHTMLActiveReady(ready),true);
  for(const change of [{active:false},{state:'ready'},{job_id:''},{worker_acknowledged:false},{worker_acknowledged:undefined},{error:'stale worker'}])assert.equal(analyticsHTMLActiveReady({...ready,...change}),false);
  assert.equal(analyticsHTMLActiveReady(),false);
});
test('a loading reply cannot imply automatic activation of all websites',()=>{
  const ready={job_id:id,active:true,worker_acknowledged:true,site_auto_injection:false};
  assert.equal(analyticsHTMLActivationAcknowledged(ready,id),true);
  for(const change of [{job_id:'b'.repeat(32)},{active:false},{worker_acknowledged:false},{site_auto_injection:true},{site_auto_injection:undefined}])assert.equal(analyticsHTMLActivationAcknowledged({...ready,...change},id),false);
  assert.equal(analyticsHTMLActivationAcknowledged(null,id),false);
});
test('immediate collector disable explicitly removes auto injection without mutating prior settings',()=>{
  const source={enabled:true,auto_inject_html:true,clicks:true,retention_days:30,key:'public'};
  const stopped=analyticsCollectorEnabled(source,false);
  assert.deepEqual(stopped,{...source,enabled:false,auto_inject_html:false});
  assert.equal(source.auto_inject_html,true);
  assert.deepEqual(analyticsCollectorEnabled(source,true),source);
  assert.equal(analyticsCollectorEnabled({enabled:true},false).auto_inject_html,false);
});
test('UI has no automatic create, activation, or retry and preserves opt-out when engine is unhealthy',()=>{
  const engine=readFileSync(new URL('../web/src/AnalyticsHTMLEngine.vue',import.meta.url),'utf8');
  const workspace=readFileSync(new URL('../web/src/AnalyticsWorkspace.vue',import.meta.url),'utf8');
  assert.match(engine,/watch\(enabled,[\s\S]*?if\(enabled\.value\)void refresh\(\)/);
  assert.doesNotMatch(engine,/watch\([^;]*?void (?:build|activate)\(/);
  assert.match(engine,/onBeforeUnmount\(\(\)=>\{disposed=true;\+\+sequence;stopTimer\(\)/);
  assert.match(engine,/active\.value=undefined;publishReady\(\);/);
  assert.match(workspace,/settings\.value=analyticsCollectorEnabled\(settings\.value,value===true\)/);
  assert.match(workspace,/!settings\.auto_inject_html && \(!settings\.enabled \|\| !htmlSupported \|\| !htmlEngineReady\)/);
  assert.match(workspace,/applied\.enabled!==payload\.enabled \|\| !!applied\.auto_inject_html!==!!payload\.auto_inject_html/);
  assert.doesNotMatch(engine,/crypto\.randomUUID/);
});
