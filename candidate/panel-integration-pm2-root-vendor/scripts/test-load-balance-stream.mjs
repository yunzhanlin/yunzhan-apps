import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {actor,other,requestID,access,policy,entry,mutation,row,workspace,model as m} from './load-balance-stream-fixture.mjs';
const sha=value=>createHash('sha256').update(value).digest('hex');
const copy=value=>structuredClone(value);
const reject=(value,fn)=>assert.throws(()=>fn(value));
test('canonical Go wire bytes, entry CAS fingerprint and operation digests match independent SHA256',()=>{
  const expected='{"format":1,"revision":7,"name":"fixture.lb.invalid","protocol":"tcp","port":42000,"probe_port":43000,"nodes":[{"address":"192.0.2.10:41001","weight":1,"backup":false},{"address":"[2001:db8::11]:41002","weight":3,"backup":false}],"method":"round-robin","connect_milliseconds":2000,"session_seconds":30,"max_sessions":64,"udp_requests":0,"udp_responses":0,"removed":false}';
  assert.equal(JSON.stringify(m.streamEntry(entry)),expected);
  const fp=sha(entry.name).slice(0,20)+':7:'+sha(expected).slice(0,24);
  assert.equal(m.streamEntryFingerprint(entry),fp);
  assert.equal(m.streamMutationHash(mutation),sha(JSON.stringify(mutation)));
  assert.deepEqual(m.streamTicket(actor,requestID,mutation),{format:1,actor_id:actor,request_id:requestID,mutation_sha256:sha(JSON.stringify(mutation))});
  const replace={...mutation,action:'replace',expected_revision:7,expected_fingerprint:fp};
  assert.equal(m.streamMutation(replace).expected_fingerprint,fp);
  assert.equal(m.streamMutation({...replace,action:'remove',policy:null}).policy,null);
  for(const change of [{name:'another.lb.invalid'},{expected_revision:8},{expected_fingerprint:fp+' '},{policy:null},{probe_port:43000},{actor_id:other},{permission_revision:99}])reject({...replace,...change},m.streamMutation);
  reject({...replace,action:'remove'},m.streamMutation);
  for(const name of ['foo','127.0.0.1','UPPER.lb.invalid','https://a.lb.invalid','a.lb.invalid/','-bad.lb.invalid','a..invalid'])reject({...mutation,name},m.streamMutation);
});
test('closed literal-IP node policies, actual types and bounded resources never normalize unsafe input',()=>{
  for(const address of ['server.internal:41001','127.0.0.1:42000','127.0.0.1:19100','127.0.0.1:19102','127.0.0.1:19080','169.254.169.254:80','100.100.100.200:80','0.0.0.0:80','255.255.255.255:80','224.0.0.1:41001','192.000.2.1:41001','192.0.2.1:041001','[fe80::1]:41001','[ff02::1]:41001','[fd00:ec2::254]:80','[::ffff:c000:201]:41001','[2001:0db8::1]:41001']){
    const p=copy(policy);p.nodes[0].address=address;reject(p,m.streamPolicy);
  }
  for(const change of [{port:'42000'},{max_sessions:513},{max_sessions:15},{session_seconds:601},{connect_milliseconds:499},{udp_requests:1},{udp_responses:1},{probe_port:43000},{nodes:[]},{nodes:Array.from({length:17},()=>policy.nodes[0])}])reject({...policy,...change},m.streamPolicy);
  for(const change of [{weight:0},{weight:101},{weight:'1'},{backup:1},{host:'secret'}]){const p=copy(policy);Object.assign(p.nodes[0],change);reject(p,m.streamPolicy);}
  reject({...policy,nodes:[policy.nodes[0],policy.nodes[0]]},m.streamPolicy);
  reject({...policy,nodes:policy.nodes.map(n=>({...n,backup:true}))},m.streamPolicy);
  reject({...policy,method:'source-ip',nodes:[policy.nodes[0],{...policy.nodes[1],backup:true}]},m.streamPolicy);
  assert.equal(m.streamPolicy({...policy,protocol:'udp',udp_requests:64,udp_responses:64}).protocol,'udp');
  reject({...policy,protocol:'udp',udp_requests:0},m.streamPolicy);
  const p=copy(entry);p.nodes[0].address='127.0.0.1:43000';reject(p,m.streamEntry);
  const normalized=m.streamPolicy(policy);normalized.nodes[0].weight=99;assert.equal(policy.nodes[0].weight,1);
});
test('original tickets are actor partitioned and contain no policy or credentials',()=>{
  const ticket=m.streamTicket(actor,requestID,mutation);
  assert.deepEqual(m.parseStreamTicket(ticket,actor),ticket);assert.notEqual(m.streamTicketKey(actor),m.streamTicketKey(other));
  for(const changed of [{...ticket,actor_id:other},{...ticket,request_id:'bad'},{...ticket,mutation_sha256:'0'.repeat(64)},{...ticket,password:'secret'},{...ticket,policy}])reject(changed,t=>m.parseStreamTicket(t,actor));
  reject(ticket,t=>m.parseStreamTicket(t,other));
});
test('rows require exact original actor, policy, result evidence and never turn unknown into success',()=>{
  const r=row(),ticket=m.streamTicket(actor,requestID,mutation);
  assert.equal(m.streamRow(r,actor,ticket).state,'reserved');
  for(const change of [{operation:{...r.operation,actor_id:other}},{operation:{...r.operation,request_id:'d'.repeat(32)}},{operation:{...r.operation,mutation:{...mutation,name:'different.lb.invalid'}}},{state:'completed'},{state:'success'},{created_at:'2026-02-30T00:00:00Z'},{result:{}},{manifest_sha256:'0'.repeat(64)}])reject({...r,...change},v=>m.streamRow(v,actor,ticket));
  const done={...r,state:'completed',result:{format:1,request_id:requestID,operation_sha256:sha(JSON.stringify(r.operation)),state:'committed',seed_sha256:'4'.repeat(64),final_event_sha256:'5'.repeat(64),configuration_sha256:'6'.repeat(64),service_observation_sha256:'7'.repeat(64)}};
  assert.equal(m.streamRow(done,actor,ticket).result.state,'committed');
  for(const key of ['seed_sha256','final_event_sha256','configuration_sha256','service_observation_sha256']){const changed=copy(done);delete changed.result[key];reject(changed,v=>m.streamRow(v,actor));}
  reject({...done,result:{...done.result,operation_sha256:'f'.repeat(64)}},v=>m.streamRow(v,actor));
  const refused={...done,result:{format:1,request_id:requestID,operation_sha256:sha(JSON.stringify(r.operation)),state:'refused-before-issue'}};
  assert.equal(m.streamRow(refused,actor).result.state,'refused-before-issue');
  reject({...refused,result:{...refused.result,seed_sha256:'4'.repeat(64)}},v=>m.streamRow(v,actor));
  assert.equal(m.streamRow({...r,state:'unknown'},actor).result,undefined);
});
test('pre-effect refusal is canonical original-request evidence, never a committed service result',()=>{
  const r=row(),operationHash=sha(JSON.stringify(r.operation));
  const receipt={format:1,request_id:requestID,version:'1.9.0',operation_sha256:operationHash,manifest_sha256:r.manifest_sha256,installed_sha256:'2'.repeat(64),programme_inputs_sha256:'3'.repeat(64),actor_observation_sha256:'4'.repeat(64),original_request_sha256:'5'.repeat(64),stage:'kernel-preflight'};
  const result={format:1,request_id:requestID,operation_sha256:operationHash,state:'refused-before-effects',preflight_refusal:JSON.stringify(receipt)};
  const refused={...r,state:'completed',result};
  assert.equal(m.streamRow(refused,actor).result.state,'refused-before-effects');
  assert.equal(m.streamRow({...refused,result:{...result,preflight_refusal:JSON.stringify({...receipt,stage:'control-preflight'})}},actor).result.state,'refused-before-effects');
  for(const [key,value] of Object.entries({format:2,request_id:'d'.repeat(32),version:'1.8.5',operation_sha256:'6'.repeat(64),manifest_sha256:'7'.repeat(64),stage:'service-started'})){
    reject({...refused,result:{...result,preflight_refusal:JSON.stringify({...receipt,[key]:value})}},v=>m.streamRow(v,actor));
  }
  for(const key of Object.keys(receipt)){
    const missing={...receipt};delete missing[key];
    reject({...refused,result:{...result,preflight_refusal:JSON.stringify(missing)}},v=>m.streamRow(v,actor));
    if(key.endsWith('_sha256'))for(const value of ['', '0'.repeat(64), 'z'.repeat(64), 123])reject({...refused,result:{...result,preflight_refusal:JSON.stringify({...receipt,[key]:value})}},v=>m.streamRow(v,actor));
  }
  const raw=JSON.stringify(receipt);
  for(const value of [undefined,null,receipt,raw+'\n',raw.replace('"format":1','"format":1,"format":1'),JSON.stringify({...receipt,dispatch:true}),JSON.stringify(Object.fromEntries(Object.entries(receipt).reverse()))]){
    reject({...refused,result:{...result,preflight_refusal:value}},v=>m.streamRow(v,actor));
  }
  for(const state of ['committed','refused-before-issue','unknown'])reject({...refused,result:{...result,state}},v=>m.streamRow(v,actor));
  for(const key of ['seed_sha256','final_event_sha256','configuration_sha256','service_observation_sha256'])reject({...refused,result:{...result,[key]:'8'.repeat(64)}},v=>m.streamRow(v,actor));
});
test('history is bounded own evidence with canonical pagination, not an execution or authority grant',()=>{
  const page={format:1,actor_id:actor,offset:0,total:1,next_offset:null,rows:[row()]};
  assert.equal(m.streamHistory(page,actor,0).rows.length,1);
  for(const change of [{actor_id:other},{total:2},{next_offset:32},{offset:32},{rows:[row(),row()]},{dispatch:true}])reject({...page,...change},v=>m.streamHistory(v,actor,0));
  reject({...page,rows:[row('reserved',other)]},v=>m.streamHistory(v,actor,0));
  assert.deepEqual(m.streamHistory({...page,rows:[],offset:4096},actor,4096).rows,[]);
});
test('workspace has exact bounded current facts, no public bind or invented health field',()=>{
  assert.equal(m.streamWorkspace(workspace()).state,'empty');
  const live=workspace([entry],1);assert.equal(m.streamWorkspace(live).configuration_verified,true);
  for(const change of [{bind_address:'0.0.0.0'},{state:'healthy'},{healthy:true},{version:'1.8.5'},{configuration_verified:false},{memory_max_bytes:2**31},{entries:[entry,entry]},{request_id:''},{generation:129}])reject({...live,...change},m.streamWorkspace);
  for(const change of [{state:'running'},{entries:[entry]},{request_id:requestID},{configuration_sha256:'1'.repeat(64)},{memory_high_bytes:1}])reject({...workspace(),...change},m.streamWorkspace);
  assert.equal(m.streamWorkspace(workspace([{...entry,removed:true}],2)).state,'stopped');
});
test('cold-boot eligibility is a distinct unverified full-lineage state, never generic degraded authority',()=>{
  const cold={...workspace([entry],1),state:'cold-boot-ready',configuration_verified:false};
  assert.equal(m.streamWorkspace(cold).state,'cold-boot-ready');
  assert.equal(m.streamWorkspace(cold).configuration_verified,false);
  for(const change of [{generation:0},{available:false},{configuration_verified:true},{retiring_workers:1},{request_id:''}])reject({...cold,...change},m.streamWorkspace);
  assert.equal(m.streamWorkspace({...cold,state:'degraded'}).state,'degraded');
});
test('host policy requires exact current full admin identity/revision; manager uses independent pane',()=>{
  assert(m.streamFullAdmin(access,actor));
  for(const change of [{user_id:other},{role:'viewer'},{permission_revision:0},{permission_revision:'1'},{menu_ids:['runtimes','system-tools']},{menu_ids:access.menu_ids.map(()=> 'runtimes')}])assert.equal(m.streamFullAdmin({...access,...change},actor),false);
  const read=p=>readFileSync(new URL('../'+p,import.meta.url),'utf8');
  const pane=read('web/src/LoadBalanceStreamWorkspace.vue'),manager=read('web/src/AppModuleManager.vue');
  assert.match(manager,/<LoadBalanceStreamWorkspace/);assert.match(manager,/label="TCP \/ UDP 入口" name="stream"/);
  assert.match(pane,/saveTicket\(streamTicket\(actor, id, mutation\)\)/);
  assert.match(pane,/workspaceReadFor.value === ticket.value.request_id/);
  assert.match(pane,/const completedBeforeRead = current.value\?\.state === "completed" \? current.value.operation.request_id : undefined/);
  assert.match(pane,/workspaceReadFor.value = completedBeforeRead/);
  assert.doesNotMatch(pane,/current.value.result.configuration_sha256 === workspace.value.configuration_sha256/);
  assert.doesNotMatch(pane,/structuredClone|\/install|\/upgrade|setInterval/);
  assert.match(read('packaging/build-release.sh'),/test-load-balance-stream\.mjs/);
});
