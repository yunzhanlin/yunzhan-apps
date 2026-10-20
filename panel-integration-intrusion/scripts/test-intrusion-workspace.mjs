import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {decodeIntrusionWorkspace,decodeIntrusionRequests} from '../web/src/intrusionWorkspace.ts';
const at='2026-10-20T00:00:00Z',id='1'.repeat(32),sha='a'.repeat(64);
const settings=()=>({max_retry:5,find_time_minutes:10,ban_time_minutes:60});
const current=()=>({format:1,checked_at:at,installed:true,version:'1.1.0',service_active:true,config_matches:true,healthy:false,kernel_scope_verified:false,kernel_scope_deferred:true,active_bans_known:true,active_bans:0,ssh_effective_ports:[2882],ssh_listening_ports:[2882],ssh_ports_match:true,actions:[{name:'nftables',ports:[2882],protocol:'tcp',scope_verified:true,kernel_scope_verified:false,kernel_scope_deferred:true,kernel_ipv4:false,kernel_ipv6:false,detail:'Synthetic deferred observation'}],settings:settings(),runtime_settings:{maxretry:5,findtime:600,bantime:3600},warnings:['等待首次实际封禁'],detail:'Synthetic read-only sample, no installed/native acceptance'});
const transaction=()=>({id,sha256:sha,action:'configure',started_at:at,finished_at:'',state:'pending',before_settings:settings(),target_settings:{...settings(),ban_time_minutes:120},before_ports:[22],target_ports:[2882],ssh_observed_ports:[2882],duration_changes_existing_bans:true,recovery_permitted:false,detail:'Synthetic original only'});
const workspace=()=>({format:1,checked_at:at,state_known:true,current:current(),pending:null,history:[],retained_temporaries:0,ban_duration_semantics:'当前及后续默认封禁到期时间受策略影响',detail:'Synthetic state'});
const pending=()=>({...workspace(),state_known:false,current:null,pending:transaction()});
const requests=()=>({actor_id:'2'.repeat(32),entries:[{id,action:'configure',state:'queued',created_at:at,request_sha256:sha}],next_cursor:'',read_only:true});
test('complete normal, deferred and original pending views do not invent installed health',()=>{
 assert.deepEqual(decodeIntrusionWorkspace(workspace()),workspace());assert.deepEqual(decodeIntrusionWorkspace(pending()),pending());
 const terminal=transaction();terminal.state='committed';terminal.finished_at=at;const w=workspace();w.history=[terminal];assert.deepEqual(decodeIntrusionWorkspace(w),w);
 for(const change of [{state_known:true},{current:current()},{pending:{...transaction(),duration_changes_existing_bans:false}},{pending:{...transaction(),sha256:'abc'}},{pending:{...transaction(),target_ports:[2882,22]}},{pending:{...transaction(),kernel_before:'private'}}])assert.throws(()=>decodeIntrusionWorkspace({...pending(),...change}));
});
test('unknown/truncated/oversized/contradictory server observations fail closed',()=>{
 for(const v of [null,[],{}, {...workspace(),state_known:false},{...workspace(),current:null},{...workspace(),checked_at:'2026-02-30T00:00:00Z'},{...workspace(),retained_temporaries:129},{...workspace(),history:Array(129).fill(transaction())},{...workspace(),extra:'private authority'}])assert.throws(()=>decodeIntrusionWorkspace(v));
 for(const change of [{version:'1.1.0-fake'},{healthy:true},{ssh_listening_ports:[22]},{active_bans:1.5},{settings:{max_retry:5}},{runtime_settings:{script:'root'}},{warnings:Array(65).fill('x')},{kernel_scope_verified:true},{actions:[{...current().actions[0],actionstart:'root script'}]},{detail:'汉'.repeat(6000)}])assert.throws(()=>decodeIntrusionWorkspace({...workspace(),current:{...current(),...change}}));
});
test('own original request pages are ordered, bounded, account-bound and key-free',()=>{
 assert.deepEqual(decodeIntrusionRequests(requests()),requests());
 for(const change of [{actor_id:'admin'},{entries:[...requests().entries,...requests().entries]},{entries:Array(21).fill(requests().entries[0])},{next_cursor:id},{read_only:false},{settings:settings()},{entries:[{...requests().entries[0],key:'private'}]},{entries:[{...requests().entries[0],state:'healthy'}]}])assert.throws(()=>decodeIntrusionRequests({...requests(),...change}));
 assert.throws(()=>decodeIntrusionRequests(requests(),id));
});
test('actual component keeps new lifecycle out of old generic modal and sends account-bound original once',()=>{
 const component=readFileSync(new URL('../web/src/IntrusionWorkspace.vue',import.meta.url),'utf8'),manager=readFileSync(new URL('../web/src/SecurityAppManager.vue',import.meta.url),'utf8');
 assert.match(manager,/<IntrusionWorkspace v-else-if="selected\?\.id === 'intrusion-prevention'"/);assert.match(component,/actor_id:own.actor_id,settings/);assert.match(component,/if\(disposed\|\|check.actor_id!==own.actor_id\)throw/);assert.match(component,/transaction_id:pending!\.id,plan_sha256:pending!\.sha256/);assert.match(component,/ticket\.value=original/);assert.match(component,/props\.onInstall\("intrusion-prevention",settings\)/);assert(!component.includes('localStorage'));assert(!component.includes('setInterval'));assert(!component.includes('systemctl'));
});
test('managed inspection policy sample is after kernel and before final ban sample',()=>{
 const code=readFileSync(new URL('../internal/executor/intrusion_inspection_linux.go',import.meta.url),'utf8'),policy=code.indexOf('actual, readErr := intrusionRuntimePolicy(read)'),kernel=code.indexOf('inspectIntrusionKernel(read,'),final=code.indexOf('finalRaw, finalReadErr := read(');
 assert(kernel>0&&policy>kernel&&policy<final,'source-order guard only; actual native two-phase acceptance remains separately required');assert.equal(code.split('intrusionRuntimePolicy(read)').length,2);
});
