// Synthetic transport only. No credentials, VM, Fail2ban, SSH, or nft access.
import {createApp,ref} from '../web/node_modules/vue/dist/vue.esm-bundler.js';
import ElementPlus from '../web/node_modules/element-plus/es/index.mjs';
import '../web/node_modules/element-plus/dist/index.css';
import IntrusionWorkspace from '../web/src/IntrusionWorkspace.vue';
const at='2026-10-20T00:00:00Z',id='1'.repeat(32),actor='2'.repeat(32),digest='a'.repeat(64),clone=x=>JSON.parse(JSON.stringify(x));
const settings={max_retry:5,find_time_minutes:10,ban_time_minutes:60};
const current={format:1,checked_at:at,installed:true,version:'1.1.0',service_active:true,config_matches:true,healthy:false,kernel_scope_verified:false,kernel_scope_deferred:true,active_bans_known:true,active_bans:0,ssh_effective_ports:[2882],ssh_listening_ports:[2882],ssh_ports_match:true,actions:[{name:'nftables',ports:[2882],protocol:'tcp',scope_verified:true,kernel_scope_verified:false,kernel_scope_deferred:true,kernel_ipv4:false,kernel_ipv6:false,detail:'合成观察：等待首次实际封禁，不是实装验收'}],settings,runtime_settings:{maxretry:5,findtime:600,bantime:3600},warnings:['合成数据：无封禁，不宣称已验证攻击拦截'],detail:'合成数据：已核对实际监听，等待首次实际封禁'};
const transaction={id,sha256:digest,action:'configure',started_at:at,finished_at:'',state:'pending',before_settings:settings,target_settings:{...settings,ban_time_minutes:120},before_ports:[22],target_ports:[2882],ssh_observed_ports:[2882],duration_changes_existing_bans:true,recovery_permitted:true,detail:'合成只读预检通过；提交仍需重新核对'};
const base={format:1,checked_at:at,state_known:true,current,pending:null,history:[],retained_temporaries:0,ban_duration_semantics:'默认封禁时长适用于当前及后续使用默认时长的封禁，开始时间不重置，到期时间会随策略改变。',detail:'合成只读状态，非真实服务器验收'};
let mode='ready',pending=[],requests=[],actualActor=actor;
const calls=[],jobs=[];
window.intrusionFixture={calls,jobs,setMode(value){mode=value;if(value==='account-switch')actualActor='3'.repeat(32);},finishLate(){for(const fn of pending.splice(0))fn({...clone(base),detail:'旧组件迟到回包禁止显示'});}};
const api=async(path,method='GET',body,key)=>{
 calls.push({path,method,body,key});
 if(path==='/software/intrusion-prevention/workspace'){
  if(mode==='hold')return new Promise(resolve=>pending.push(resolve));
  if(mode==='corrupt')return {...clone(base),private_dump:'forbidden'};
  if(mode==='pending')return {...clone(base),state_known:false,current:null,pending:clone(transaction)};
  if(mode==='legacy')return {...clone(base),current:{...clone(current),version:'1.0'}};
  if(mode==='uninstalled')return {...clone(base),current:{...clone(current),installed:false,version:'',service_active:false,config_matches:false,healthy:false,kernel_scope_deferred:false,active_bans_known:false,ssh_ports_match:false,ssh_effective_ports:[],ssh_listening_ports:[],actions:[],settings:{},runtime_settings:{},warnings:[]}};
  return clone(base);
 }
 if(path==='/software/intrusion-prevention/requests'){if(mode==='requests-denied')throw Error('合成只读角色没有原请求管理权限');return {actor_id:actualActor,entries:clone(requests),next_cursor:'',read_only:true};}
 if(method==='POST'&&['configure','recover','uninstall'].some(a=>path===`/software/intrusion-prevention/${a}`)){
  if(body.actor_id!==actualActor||!/^[a-f0-9]{32}$/.test(key))throw Error('Synthetic stale actor or missing original');
  requests=[{id,action:path.split('/').at(-1),state:'queued',created_at:at,request_sha256:digest}];
  if(mode==='unknown')throw Error('合成：后端已入队但网络回复丢失；不可重发');
  return {job_id:id};
 }
 throw Error('Unexpected synthetic endpoint: '+path);
};
createApp({components:{IntrusionWorkspace},setup(){const mounted=ref(true);return {mounted,api,onJob:async id=>{jobs.push(id);},onInstall:async(id,settings)=>{calls.push({method:'STORE_INSTALL',id,settings});throw Error('合成应用商店回复未知，原身份由商店管理');}};},template:`<main style="max-width:1160px;margin:20px auto;font-family:system-ui"><p>隔离 UI 测试：合成数据，不是服务器或应用实装验收</p><button @click="mounted=false">销毁工作台</button><button @click="mounted=true">重新打开工作台</button><IntrusionWorkspace v-if="mounted" :api="api" :on-job="onJob" :on-install="onInstall" /></main>`}).use(ElementPlus).mount('#app');
