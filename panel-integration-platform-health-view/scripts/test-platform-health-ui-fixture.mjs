// Synthetic UI-only fixture. No VM, live agent, credentials or installations.
import {createApp,ref} from '../web/node_modules/vue/dist/vue.esm-bundler.js';
import ElementPlus from '../web/node_modules/element-plus/es/index.mjs';
import '../web/node_modules/element-plus/dist/index.css';
import AppModuleManager from '../web/src/AppModuleManager.vue';
const at=()=>new Date().toISOString().replace(/\.\d{3}Z$/,'Z');
function report(){
 const time=at(),health={cpu_cores:2,cpu_available:true,cpu_percent:0,memory_available:true,memory_percent:25,memory_total:4*1024**3,memory_used:1024**3,disk_percent_available:true,disk_percent:50,disk_total:32*1024**3,disk_used:16*1024**3,nginx_active:true,sampled_at:time,hostname:'synthetic-linux',os:'Debian GNU/Linux 13',arch:'amd64'};
 return {hosts:[
  {id:'ui-primary',url:'https://primary.example.invalid:8443/controlled/synthetic-health',expected_sha:'a'.repeat(64),healthy:true,telemetry_complete:true,status:200,report:{version:'app-modules-1',time,health:{...health}}},
  {id:'ui-missing-cpu',url:'https://unknown.example.invalid',expected_sha:'b'.repeat(64),healthy:true,telemetry_complete:false,status:200,report:{version:'app-modules-1',time,health:{...health,cpu_available:false,cpu_percent:null,os:'Ubuntu 24.04',arch:'arm64',nginx_active:false}}},
  {id:'ui-revoked',url:'https://revoked.example.invalid',expected_sha:'c'.repeat(64),healthy:false,telemetry_complete:false,status:401,error:'远端状态码或 JSON 媒体类型不符合健康协议'},
 ],checked_at:time,scope:'Synthetic UI-only snapshot, not a server acceptance'};
}
let mode='ready',pending=[];
const rows=[],calls=[];
window.platformHealthFixture={calls,rows,setMode:value=>{mode=value;},finishLate:()=>{for(const item of pending.splice(0))item.resolve({...report(),scope:'Synthetic late snapshot'});}};
const fields=[{key:'resource_id',label:'主机标识',kind:'text'},{key:'url',label:'HTTPS 地址',kind:'text'},{key:'token',label:'只读健康授权',kind:'password'},{key:'expected_sha',label:'主机配置摘要',kind:'identity'}];
const api=async(path,method='GET',body,key,signal)=>{
 const call={path,method,body,hasSignal:!!signal,aborted:signal?.aborted||false};calls.push(call);
 if(path==='/sites')return [];
 if(path==='/app-modules/platform-ops')return {definition:{id:'platform-ops',name:'多主机运维',actions:['run','add','remove'],fields},guidance:{description:'UI-only fixture',workflow:[],limitations:[]},status:{id:'platform-ops',installed:true,healthy:true,version:'1.3.0',installation_id:'d'.repeat(32)},report:report(),workspace:[{id:'hosts',label:'主机健康',fields:[],actions:['run'],help:'隔离 UI 验收：合成快照，不连接真实服务器。'},{id:'host',label:'登记主机',fields:fields.map(f=>f.key),actions:['add','remove'],help:'只填写表单，不自动提交。'}]};
 if(path==='/app-modules/platform-ops/run'){
  if(mode==='corrupt')return {...report(),partial:true};
  if(mode==='hold')return new Promise((resolve,reject)=>{pending.push({resolve,reject});signal?.addEventListener('abort',()=>{call.aborted=true;reject(new DOMException('Synthetic transport abort','AbortError'));},{once:true});});
  if(mode==='late')return new Promise((resolve,reject)=>{pending.push({resolve,reject});signal?.addEventListener('abort',()=>{call.aborted=true;},{once:true});});
  return report();
 }
 throw Error('Unexpected synthetic API operation: '+path);
};
createApp({components:{AppModuleManager},setup(){const manager=ref(),mounted=ref(true);return {manager,mounted,api,open:()=>manager.value.show('platform-ops'),onJob:()=>{throw Error('No jobs in UI fixture');},onInstall:()=>{throw Error('No installations in UI fixture');}};},template:`<main style="max-width:1100px;margin:12px auto;font-family:system-ui"><p>隔离界面测试 · 合成数据，非真实服务器验收</p><button @click="open">打开测试管理器</button><button @click="mounted=false">销毁测试组件</button><AppModuleManager v-if="mounted" ref="manager" :api="api" :on-job="onJob" :on-install="onInstall" /></main>`}).use(ElementPlus).mount('#app');
