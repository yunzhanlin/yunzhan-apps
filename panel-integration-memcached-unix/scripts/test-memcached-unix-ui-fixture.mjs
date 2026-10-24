// Isolated actual-Vue browser fixture. Mock transport ONLY; no server/VM writes.
import {createApp,ref} from 'vue';
import ElementPlus from 'element-plus';
import '../web/node_modules/element-plus/dist/index.css';
import MemcachedUnixManager from '../web/src/MemcachedUnixManager.vue';
const actor='a'.repeat(32),project='b'.repeat(32),mode=new URL(location.href).searchParams.get('case')||'normal';
const app={id:'memcached',name:'Memcached',version:'1.6.45-compat4',sha256:'e'.repeat(64),stage:'ready'};
const workspace={format:1,project_id:project,name:'隔离 UI 测试 · 非服务器实例',site_id:'',version:app.version,state:'running',state_known:true,healthy:true,socket_path:'/var/lib/panel-executor/memcached-sockets/'+project+'/cache.sock',cache_mb:128,memory_limit_mb:192,item_limit_mb:4,editor_limit_bytes:48*1024,network_mode:'none',runtime_sha256:'d'.repeat(64)};
let controls=[];
window.privateRequests=[];
const api=async(path,method='GET',body,key)=>{
 window.privateRequests.push({path,method,body:body===undefined?undefined:structuredClone(body),key});
 if(path==='/docker/projects')return{projects:[{id:project,name:workspace.name,template_id:'memcached-cache',template_profile:'memcached-unix-v1'},{id:'c'.repeat(32),name:'旧版 TCP 隔离示例',template_id:'memcached-cache'}]};
 if(path==='/app-registry/memcached/controls')return{records:structuredClone(controls),truncated:false};
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
  const result={format:1,request_id:key,project_id:project,operation_sha256:'f'.repeat(64),state:'completed',final_state:body.action==='stop'?'stopped':'running',runtime_sha256:'9'.repeat(64)};
  const row=mode==='unknown'?{operation,state:'unknown'}:{operation,state:'completed',result};
  controls=[row,...controls];if(mode!=='unknown'){workspace.state=result.final_state;workspace.healthy=workspace.state==='running';workspace.runtime_sha256=result.runtime_sha256;}
  return structuredClone(row);
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
