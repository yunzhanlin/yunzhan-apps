// Isolated real-Vue UI fixture, not a live server or native acceptance proof.
import {createApp,ref} from '../web/node_modules/vue/dist/vue.esm-bundler.js';
import ElementPlus from '../web/node_modules/element-plus/es/index.mjs';
import '../web/node_modules/element-plus/dist/index.css';
import AnalyticsWorkspace from '../web/src/AnalyticsWorkspace.vue';
const site={id:'a'.repeat(32),name:'仅用于隔离界面验收',domain:'private.example.test'};
const engine='b'.repeat(32);
const empty={source:'private UI mock transport only',from:'QA',to:'QA',partial:false,sampled_events:0,overview:{pv:0,uv:0,sessions:0,active_visitors:0,clicks:0,bounce_rate:0,avg_engagement_seconds:0,unique_network_peers:0},pages:[],sources:[],browsers:[],devices:[],entry_pages:[],exit_pages:[],hours:[],campaigns:[],sessions:[],heatmap:[],performance:{},limitations:[]};
const mode=new URL(location.href).searchParams.get('case') || 'idle';
let settings={site_id:site.id,key:'c'.repeat(32),enabled:true,clicks:false,retention_days:30,revision:1,auto_inject_html:mode==='unhealthy',proxy_endpoint:'127.0.0.1:19100'};
let active=mode==='unhealthy' ? {active:false,state:'needs-attention',error:'private stale worker counterexample'} : {active:false,state:'not-activated'};
let entries=['ready','bad-ack','running'].includes(mode) ? [{job_id:engine,state:mode==='running'?'running':'ready',integrity_verified:mode!=='running',module_abi_validated:mode!=='running',build_only:true,architecture:'arm64',nginx_version:'1.24.0',steps:[]}] : [];
window.privateRequests=[];
const api=async(path,method='GET',body,key)=>{
  window.privateRequests.push({path,method,body:body?structuredClone(body):undefined,key});
  if(path===`/analytics/sites/${site.id}/config`){if(method==='POST'){settings={...body,revision:settings.revision+1};return {job_id:'d'.repeat(32)};}return structuredClone(settings);}
  if(path.startsWith('/analytics/sites/')&&path.includes('/report'))return structuredClone(empty);
  if(path.startsWith('/jobs/'))return {state:'succeeded'};
  if(path.endsWith('/html-engine/active'))return structuredClone(active);
  if(path.endsWith('/html-engines'))return {entries:structuredClone(entries),build_only:true};
  if(path.includes('/html-engine/jobs/')&&path.endsWith('/cancel')){entries[0]={...entries[0],state:'failed',error:'private administrator stopped',integrity_verified:false,module_abi_validated:false};return structuredClone(entries[0]);}
  if(path.includes('/html-engine/jobs/'))return structuredClone(entries[0]);
  if(path.endsWith('/html-engine/build')){entries=[{job_id:engine,state:'queued',integrity_verified:false,module_abi_validated:false,build_only:true,steps:[]}];return {job_id:engine};}
  if(path.endsWith('/html-engine/activate')){
    if(mode==='bad-ack')return {job_id:engine,active:true,worker_acknowledged:false,site_auto_injection:false};
    active={active:true,state:'active',job_id:engine,worker_acknowledged:true};
    return {job_id:engine,active:true,worker_acknowledged:true,site_auto_injection:false};
  }
  throw new Error('Unexpected private mock endpoint: '+path);
};
createApp({components:{AnalyticsWorkspace},setup(){const mounted=ref(true);return {mounted,api,site,version:mode==='legacy'?'2.2.0':'2.3.0'};},template:`<main style="padding:12px;max-width:960px;margin:auto"><p>隔离 UI 验收，仅模拟传输；不作为服务器功能验收。</p><button @click="mounted=false">销毁测试组件</button><AnalyticsWorkspace v-if="mounted" :api="api" :installed="true" :installed-version="version" :sites="[site]" /></main>`}).use(ElementPlus).mount('#app');
