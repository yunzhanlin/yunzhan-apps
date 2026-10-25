// Isolated actual-Vue browser fixture. Mock transport ONLY; no server/VM writes.
import {createApp,ref} from 'vue';
import ElementPlus from 'element-plus';
import '../web/node_modules/element-plus/dist/index.css';
import MemcachedUnixManager from '../web/src/MemcachedUnixManager.vue';
const actor='a'.repeat(32),project='b'.repeat(32),mode=new URL(location.href).searchParams.get('case')||'normal';
const app={id:'memcached',name:'Memcached',version:'1.6.45-compat4',sha256:'e'.repeat(64),stage:'ready'};
const workspace={format:1,project_id:project,name:'隔离 UI 测试 · 非服务器实例',site_id:'',version:app.version,state:'running',state_known:true,healthy:true,socket_path:'/var/lib/panel-executor/memcached-sockets/'+project+'/cache.sock',cache_mb:128,memory_limit_mb:192,item_limit_mb:4,editor_limit_bytes:48*1024,network_mode:'none',runtime_sha256:'d'.repeat(64)};
if(mode.startsWith('retire')||mode==='review-retired')Object.assign(workspace,{name:'own-cache',state:mode==='retired'||mode==='review-retired'?'retired':'stopped',healthy:false,retirement_supported:mode!=='retired'&&mode!=='review-retired'});
if(workspace.state==='retired')workspace.retirement_request_id='1'.repeat(32);
let controls=[];
let savedReview;
if(mode.startsWith('review-'))controls=[{operation:{format:1,request_id:'1'.repeat(32),project_id:project,actor_id:mode==='review-other'?'c'.repeat(32):actor,input:{action:'stop',expected_runtime_sha256:workspace.runtime_sha256,acknowledge_cache_loss:true}},state:'unknown'}];
if(mode==='review-retired')controls[0].operation.input={action:'retire',expected_runtime_sha256:workspace.runtime_sha256,acknowledge_cache_loss:false,acknowledge_removal:true,confirm_name:workspace.name};
window.privateRequests=[];
const api=async(path,method='GET',body,key)=>{
 window.privateRequests.push({path,method,body:body===undefined?undefined:structuredClone(body),key});
 if(path==='/docker/projects')return{projects:[{id:project,name:workspace.name,template_id:'memcached-cache',template_profile:'memcached-unix-v1'},{id:'c'.repeat(32),name:'旧版 TCP 隔离示例',template_id:'memcached-cache'}]};
 if(path==='/app-registry/memcached/controls')return{records:structuredClone(controls.filter(row=>row.operation.actor_id===actor||row.state!=='completed')),truncated:false};
 if(path.endsWith('/workspace')){
  const out=structuredClone(workspace);
  if(body.action==='cache'){
   const action=body.cache.action;
   out.cache={action,found:true,changed:action!=='get'&&action!=='stats',value_base64:action==='get'?'/wANCoA=':undefined,value_bytes:action==='get'?5:0,cas:action==='get'?'18446744073709551615':undefined,flags:4294967295,ttl_remaining:42};
   if(action==='stats')out.cache.statistics={version:'1.6.45',curr_items:'1',bytes:'5',cmd_get:'1',get_hits:'1',limit_maxbytes:'134217728'};
  }
  return out;
 }
 if(path.endsWith('/controls')&&method==='POST'){
  const operation={format:1,request_id:key,project_id:project,actor_id:actor,input:structuredClone(body)};
  const result={format:1,request_id:key,project_id:project,operation_sha256:'f'.repeat(64),state:'completed',final_state:body.action==='retire'?'retired':body.action==='stop'?'stopped':'running',runtime_sha256:'9'.repeat(64)};
  const unknown=mode==='unknown'||mode==='retire-lost';
  const row=unknown?{operation,state:'unknown'}:{operation,state:'completed',result};
  controls=[row,...controls];if(mode!=='unknown'){workspace.state=result.final_state;workspace.healthy=workspace.state==='running';workspace.runtime_sha256=result.runtime_sha256;if(body.action==='retire'){workspace.retirement_supported=false;workspace.retirement_request_id=key;}}
  if(mode==='retire-lost')throw new Error('隔离模拟：卸载回复丢失');
  return structuredClone(row);
 }
 if(path.endsWith('/review')){
  const row=controls.find(v=>path.includes(v.operation.request_id));
  const value={format:1,request_id:row.operation.request_id,project_id:project,operation_sha256:'f'.repeat(64),original_outcome:'unknown'};
  if(method==='GET')return structuredClone(savedReview?{...value,observation:savedReview}:{...value,current_state:workspace.state,runtime_sha256:workspace.runtime_sha256});
  if(method==='POST'){
   const first=!savedReview;
   savedReview??={format:1,request_id:row.operation.request_id,project_id:project,operation_sha256:'f'.repeat(64),state:'observed',final_state:workspace.state,runtime_sha256:workspace.runtime_sha256,reviewer_id:actor,observed_at:'2026-10-24T12:00:00.123456789Z'};
   if(mode==='review-lost'&&first)throw new Error('隔离模拟：复核回复丢失');
   row.state='completed';row.result=structuredClone(savedReview);
   return{...value,observation:structuredClone(savedReview)};
  }
 }
 if(path.includes('/controls/')&&method==='GET')return structuredClone(controls.find(v=>path.endsWith(v.operation.request_id)));
 if(path.endsWith('/close')&&method==='POST'){
  const row=controls.find(v=>path.includes(v.operation.request_id));row.state='completed';row.result={format:1,request_id:row.operation.request_id,project_id:project,operation_sha256:'f'.repeat(64),state:'refused'};
  return structuredClone(row);
 }
 if(path==='/app-registry/memcached/install'&&method==='POST')return{job_id:'2'.repeat(32)};
 if(path==='/app-registry/memcached/installs/'+'2'.repeat(32)&&method==='GET')return{app_id:'memcached',job_id:'2'.repeat(32),provider:'compose',version:app.version,state_known:true,state:'succeeded'};
 throw new Error('Unexpected isolated UI mock route: '+path);
};
createApp({components:{MemcachedUnixManager},setup(){
 const manager=ref(),fullAdmin=ref(true);
 window.revokePrivateFixture=()=>{fullAdmin.value=false;};
 return{manager,api,actor,fullAdmin,open:()=>manager.value.open(app),install:()=>manager.value.open(app,'install')};
},template:'<main style="padding:16px;font:14px system-ui"><h1>隔离 UI 验收 · 仅模拟传输</h1><p>不连接 19100、不安装服务器软件，不作为真实 API 或商用验收。</p><button @click="open">打开隔离工作区</button> <button @click="install">打开隔离安装</button><MemcachedUnixManager ref="manager" :api="api" :actor="actor" :sites="[]" :full-admin="fullAdmin" /></main>'}).use(ElementPlus).mount('#app');
