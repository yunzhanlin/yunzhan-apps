import {test} from 'node:test';import assert from 'node:assert/strict';import {readFileSync} from 'node:fs';import ts from '../web/node_modules/typescript/lib/typescript.js';
import {outboundSourceInventory,outboundSourceReplyMatches} from '../web/src/outboundSourceView.ts';
const row={id:'a'.repeat(32),event_id:'b'.repeat(32),state:'source_blocked',attempts:0,http_status:0,error:'原日报来源待核对',created_at:1790000000,completed_at:0,day:'2026-10-11',source_sha:'c'.repeat(64),channel_revision:3};
const inventory={deliveries:[],blocked_sources:[row],blocked_source_total:1,blocked_source_limit:100};
const reply={id:row.id,event_id:row.event_id,state:'resolved',delivery_id:'d'.repeat(32),already_resolved:false};
test('only complete bounded inventories retain original non-secret source identity',()=>{
 assert.deepEqual(outboundSourceInventory(inventory),{rows:[row],total:1});
 assert(outboundSourceInventory({...inventory,blocked_sources:[{...row,state:'source_resolved',completed_at:1790000001}]}));
 for(const bad of [null,{},[],{...inventory,blocked_source_total:0},{...inventory,blocked_source_total:10001},{...inventory,blocked_source_limit:101},{...inventory,blocked_sources:[row,row],blocked_source_total:2},...['secret','invalid-day','bad-hash','completed','bad-revision'].map(mode=>({...inventory,blocked_sources:[{...row,...(mode==='secret'?{password:'owned-private-password'}:mode==='invalid-day'?{day:'2026-02-31'}:mode==='bad-hash'?{source_sha:'C'.repeat(64)}:mode==='completed'?{completed_at:1}:{channel_revision:0})}]}))])assert.equal(outboundSourceInventory(bad),undefined);
 const delivery={id:'d'.repeat(32),event_id:'e'.repeat(32),state:'pending',attempts:0,http_status:0,error:'',created_at:1790000000,completed_at:0};
 assert(outboundSourceInventory({...inventory,deliveries:[delivery]}));assert(!outboundSourceInventory({...inventory,deliveries:[delivery,delivery]}));assert(!outboundSourceInventory({...inventory,deliveries:[{...delivery,event_id:row.event_id}]}));
 assert(outboundSourceInventory({...inventory,blocked_sources:[{...row,state:'source_resolved',completed_at:1790000001}],deliveries:[{...delivery,event_id:row.event_id}]}));
});
test('acknowledgements must bind original block and event; never infer delivery',()=>{
 assert(outboundSourceReplyMatches(row,reply));assert(outboundSourceReplyMatches(row,{...reply,already_resolved:true}));
 for(const bad of [null,[],{},Object.create(reply),{...reply,id:'f'.repeat(32)},{...reply,event_id:'f'.repeat(32)},{...reply,state:'succeeded'},{...reply,token:'private'},{...reply,delivery_id:'bad'}])assert(!outboundSourceReplyMatches(row,bad));
});
test('closed delivery summaries remain readable; partial, unrelated and unbounded fields never render as valid history',()=>{
 const delivery={id:'d'.repeat(32),event_id:'e'.repeat(32),state:'succeeded',attempts:1,http_status:204,error:'',created_at:1790000000,completed_at:1790000001,kind:'load-balance-source',event_type:'source_ready',title:'负载均衡告警来源重新可核对',message:'不代表业务恢复',severity:'info',event_created_at:1790000000,test:false};
 assert(outboundSourceInventory({...inventory,deliveries:[delivery]}));
 for(const mutate of [{event_type:'arbitrary-private-source'},{kind:'load-balance',event_type:'source_ready'},{title:''},{message:'x'.repeat(257)},{test:1},{event_created_at:0},{secret:'private'}])assert(!outboundSourceInventory({...inventory,deliveries:[{...delivery,...mutate}]}));
 const incomplete={...delivery};delete incomplete.event_type;assert(!outboundSourceInventory({...inventory,deliveries:[incomplete]}));
 assert(source.includes('label="脱敏事件 / 摘要"'));assert(source.includes('{{ row.message }}'));assert(!source.includes('v-html='));
});
const source=readFileSync(new URL('../web/src/OutboundNotifications.vue',import.meta.url),'utf8');
const readStart=source.indexOf('async function focusHistoryError('),readEnd=source.indexOf('function showHistory(',readStart);
const writeStart=source.indexOf('async function reconcileSource('),writeEnd=source.indexOf('onMounted(',writeStart);
const actualHandlers=ts.transpileModule(source.slice(readStart,readEnd)+source.slice(writeStart,writeEnd),{compilerOptions:{target:ts.ScriptTarget.ES2022}}).outputText;
function setup(){
 const focus=[],calls=[],notices=[],channel={id:'e'.repeat(32),revision:3,enabled:true};
 const bindings={mounted:true,history:{value:true},selected:{value:channel},busyID:{value:''},historyLoading:{value:false},deliveries:{value:[]},sourceInventoryKnown:{value:true},sourceTotal:{value:1},sourceShown:{value:1},historyError:{value:''},sourceReconcileObservation:{value:null},historyErrorAnchor:{value:{isConnected:true,scrollIntoView:o=>focus.push(['scroll',o]),focus:o=>focus.push(['focus',o])}},nextTick:async()=>{},outboundSourceInventory,outboundSourceReplyMatches,ElMessage:{success:m=>notices.push(['success',m]),error:m=>notices.push(['error',m])},props:{api:async()=>{throw Error('Explicit test API not configured');}}};
 const handlers=new Function('bindings','with(bindings){'+actualHandlers+';return {reconcileSource,refreshHistory,focusHistoryError};}')(bindings);
 return {bindings,handlers,focus,calls,notices,channel};
}
test('actual reconcile handler never repeats writes and withholds lost or foreign success',async()=>{
 for(const mode of ['success','lost','foreign','refused','refresh-failed','access-changed']){
  const {bindings,handlers,focus,calls,notices,channel}=setup();
  bindings.props.api=async(path,method,body)=>{calls.push({path,method,body});if(method==='POST'){assert.deepEqual(body,{revision:3,expected_sha:row.source_sha});if(['lost','refused'].includes(mode))throw Error(mode);if(mode==='access-changed')bindings.selected.value={...channel,revision:4};return mode==='foreign'?{...reply,event_id:'f'.repeat(32)}:reply;}assert.equal(path,'/notification-channels/'+channel.id+'/deliveries');if(mode==='refresh-failed')throw Error('readonly refresh unavailable');return {...inventory,blocked_sources:[{...row,state:'source_resolved',completed_at:1790000001}]};};
  await handlers.reconcileSource(row);assert.equal(bindings.busyID.value,'');assert.equal(calls.filter(v=>v.method==='POST').length,1);
  if(mode==='access-changed'){assert.equal(notices.length,0);assert.equal(calls.length,1);continue;}
  const acknowledged=['success','refresh-failed'].includes(mode);assert.equal(notices.filter(v=>v[0]==='success').length,acknowledged?1:0);assert.equal(calls.some(v=>v.method===undefined),acknowledged);
  if(mode!=='success'){assert.equal(bindings.sourceInventoryKnown.value,false);const count=calls.length;await handlers.reconcileSource(row);assert.equal(calls.length,count,'blind reconcile replay');assert(focus.some(v=>v[0]==='focus'),'persistent actual error is focused');}
  else assert.equal(bindings.sourceReconcileObservation.value,null);
  if(mode==='refresh-failed')assert(bindings.historyError.value.includes('已收到原来源入队成功回执'));
 }
});
test('actual record loader drops stale rows and only current version can adopt full inventory',async()=>{
 for(const mode of ['valid','failed','malformed','revision-changed']){
  const {bindings,handlers,channel}=setup();bindings.deliveries.value=[{id:'stale'}];
  bindings.props.api=async()=>{assert.deepEqual(bindings.deliveries.value,[]);assert.equal(bindings.sourceInventoryKnown.value,false);if(mode==='failed')throw Error('read unavailable');if(mode==='revision-changed')bindings.selected.value={...channel,revision:4};return mode==='malformed'?{...inventory,blocked_sources:[{id:row.id}]}:inventory;};
  assert.equal(await handlers.refreshHistory(),mode==='valid');assert.equal(bindings.historyLoading.value,false);assert.equal(bindings.sourceInventoryKnown.value,mode==='valid');assert.equal(bindings.deliveries.value.length,mode==='valid'?1:0);
 }
 assert.match(source,/来源隔离共/);assert.match(source,/核对原报告并入队/);assert.match(source,/row.channel_revision!==selected\?\.revision/);
});
test('actual poll cannot clear unknown write; manual read must bind the same original tuple',async()=>{
 for(const mode of ['original','foreign-sha','foreign-id','foreign-event','missing-original']){
  const {bindings,handlers,channel,calls}=setup();
  bindings.sourceReconcileObservation.value={channel_id:channel.id,revision:3,id:row.id,event_id:row.event_id,source_sha:row.source_sha,state:'unverified'};bindings.historyError.value='original ambiguous outcome';
  bindings.props.api=async(path,method)=>{calls.push({path,method});assert.equal(method,undefined,'no mutation while reconciling');const changes=mode==='foreign-sha'?{source_sha:'f'.repeat(64)}:mode==='foreign-id'?{id:'f'.repeat(32)}:mode==='foreign-event'?{event_id:'f'.repeat(32)}:{};return {...inventory,blocked_sources:mode==='missing-original'?[]:[{...row,...changes}]};};
  assert(await handlers.refreshHistory());assert.equal(bindings.sourceReconcileObservation.value.state,'unverified');assert.equal(bindings.historyError.value,'original ambiguous outcome');assert(bindings.sourceInventoryKnown.value);
  const count=calls.length;await handlers.reconcileSource(row);assert.equal(calls.length,count,'automatic valid read cannot enable blind replay');
  assert.equal(await handlers.refreshHistory(true),mode==='original');
  assert.equal(bindings.sourceReconcileObservation.value===null,mode==='original');
  if(mode!=='original'){assert.equal(bindings.sourceInventoryKnown.value,false);assert.match(bindings.historyError.value,/同一原隔离身份/);}
 }
});
test('actual identity and persistent error are readonly, bounded and not empty-success',()=>{
 for(const text of ['原日报来源身份（只读）','row.day','row.event_id','row.source_sha','原通道 v','historyErrorAnchor','role="alert"','刷新记录','原来源操作或后续读取尚未完整核对'])assert(source.includes(text));
 assert.match(source,/empty-text="sourceInventoryKnown\?/);assert.match(source,/max-height: calc\(100vh - 32px\)/);assert.match(source,/refreshHistory\(true\)/);assert.match(source,/anchor\.focus\(\{preventScroll:true\}\)/);
});
