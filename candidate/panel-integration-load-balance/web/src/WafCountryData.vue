<script setup lang="ts">
import {computed,onUnmounted,ref,watch} from 'vue';
import {CountryRequestIdentity,IndexedCountryStorage,readCountryDetail,readCountryDownloadCancelConditions,countryDownloadCancellationLabel,type CountryDownloadCancelConditions,type CountrySelection,type CountryTicket,type CountryLookup,type CountryDetail} from './wafCountryIdentity';
import {randomId} from './randomId';
import {formatPanelDateTime} from './panelTime';
type API=<T>(path:string,method?:string,body?:unknown,key?:string,signal?:AbortSignal)=>Promise<T>;
type Asset={code:string;bytes:number;networks:number;sha256:string};
type Page={actor_id:string;state:{installed:boolean;app_version:string;installation_sha256:string;supported:boolean;max_countries:number;max_bytes:number;max_networks:number;downloads_do_not_activate_policy:boolean};available:null|{app_version:'2.6.0';app_manifest_sha256:string;data_manifest_sha256:string;release:string;revision:number;license:string;attribution_url:string;files:Asset[]};source_error:string};
type JobPage={actor_id:string;entries:{id:string;state:string;created_at:string;payload_sha256:string}[];next_cursor:string;read_only:boolean};
const props=defineProps<{api:API;actor:string;active:boolean}>();
const emit=defineEmits<{'use-dataset':[CountryDetail]}>();
const endpoint='/software/nginx-waf/country-data',storage=new IndexedCountryStorage();
const page=ref<Page>(),jobs=ref<JobPage>(),pending=ref<CountryTicket>(),outcome=ref<CountryLookup>(),detail=ref<CountryDetail>();
const selected=ref<string[]>([]),error=ref(''),busy=ref(false),blocked=ref(true),detailBusy=ref(false);
let generation=0,abort=new AbortController(),timer:ReturnType<typeof setTimeout>|undefined;
const identity=()=>new CountryRequestIdentity(storage,props.actor,randomId);
const label=(s:string)=>({queued:'排队中',running:'下载及完整核对中',succeeded:'数据准备完成（任务不启用防护）',failed:'原任务失败',needs_attention:'原任务待核对',cancelled:'已取消（提交执行服务前）'}[s]||'状态无法核对');
const detailLabel=(v:CountryDetail|undefined)=>v?(countryDownloadCancellationLabel(v)||label(v.request.state)):'状态无法核对';
const canRequestDownloadCancellation=(v:CountryDetail|undefined)=>v?.request.state==='running'&&v.can_cancel_before_dispatch===false&&!v.download_cancellation&&!v.result;
function countryName(code:string){try{return new Intl.DisplayNames(['zh-CN'],{type:'region'}).of(code)||code;}catch{return code;}}
function stopTimer(){if(timer)clearTimeout(timer);timer=undefined;}
function reset(){generation++;stopTimer();abort.abort();abort=new AbortController();page.value=undefined;jobs.value=undefined;pending.value=undefined;outcome.value=undefined;detail.value=undefined;selected.value=[];busy.value=detailBusy.value=false;blocked.value=true;error.value='';}
function current(g:number,actor:string){return g===generation&&props.active&&props.actor===actor&&!abort.signal.aborted;}
const totals=computed(()=>{const files=page.value?.available?.files||[];return selected.value.reduce((n,code)=>{const f=files.find(x=>x.code===code);return{bytes:n.bytes+(f?.bytes||0),networks:n.networks+(f?.networks||0)};},{bytes:0,networks:0});});
const selectionValid=computed(()=>!!page.value?.available&&selected.value.length>0&&selected.value.length<=32&&totals.value.bytes>0&&totals.value.bytes<=64*1024*1024&&totals.value.networks>0&&totals.value.networks<=1048576);
function validatePage(v:Page,actor:string){
  const s=v?.state;if(v?.actor_id!==actor||!s||typeof s.installed!=='boolean'||typeof s.supported!=='boolean'||s.max_countries!==32||s.max_bytes!==64*1024*1024||s.max_networks!==1048576||s.downloads_do_not_activate_policy!==true||typeof v.source_error!=='string')throw Error('国家数据安装状态不能完整核对');
  if(s.supported&&(!s.installed||s.app_version!=='2.6.0'||!/^[a-f0-9]{64}$/.test(s.installation_sha256)))throw Error('国家数据安装实例不能核对');
  if(v.available){const a=v.available;if(!s.supported||a.app_version!=='2.6.0'||!/^[a-f0-9]{64}$/.test(a.app_manifest_sha256)||!/^[a-f0-9]{64}$/.test(a.data_manifest_sha256)||!/^20[2-9][0-9]-(0[1-9]|1[0-2])$/.test(a.release)||!Number.isSafeInteger(a.revision)||a.revision<1||a.revision>1000||!Array.isArray(a.files)||a.files.length<1||a.files.length>675)throw Error('签名国家目录无法核对');
    let previous='',bytes=0,networks=0;for(const f of a.files){if(typeof f.code!=='string'||!/^[A-Z]{2}$/.test(f.code)||f.code==='ZZ'||f.code<=previous||typeof f.sha256!=='string'||!/^[a-f0-9]{64}$/.test(f.sha256)||!Number.isSafeInteger(f.bytes)||f.bytes<1||f.bytes>64*1024*1024||!Number.isSafeInteger(f.networks)||f.networks<1||f.networks>1048576)throw Error('国家目录文件索引不完整');previous=f.code;bytes+=f.bytes;networks+=f.networks;}if(bytes>256*1024*1024||networks>4*1048576)throw Error('签名国家目录超出完整发布容量');
  }
}
async function readJobs(g:number,actor:string,cursor=''){
  const value=await props.api<JobPage>(endpoint+'/jobs'+(cursor?'?cursor='+encodeURIComponent(cursor):''),'GET',undefined,undefined,abort.signal);if(!current(g,actor))return;
  if(value?.actor_id!==actor||value.read_only!==true||!Array.isArray(value.entries)||value.entries.length>20||typeof value.next_cursor!=='string'||value.next_cursor!==''&&!/^[a-f0-9]{32}$/.test(value.next_cursor)||value.entries.some(x=>!/^[a-f0-9]{32}$/.test(x.id)||!['queued','running','succeeded','failed','needs_attention','cancelled'].includes(x.state)))throw Error('原国家数据任务目录无法完整核对');jobs.value=value;
}
async function readOriginal(g:number,actor:string){
  const original=pending.value;if(!original)return;
  const reply=await props.api<CountryLookup>(endpoint+'/requests/'+original.key,'GET',undefined,undefined,abort.signal);if(!current(g,actor))return;
  const next=await identity().observe(reply,original);if(!current(g,actor))return;pending.value=next;outcome.value=reply;
}
async function readDetail(g:number,actor:string,id:string){
  const value=await props.api<CountryDetail>(endpoint+'/jobs/'+id,'GET',undefined,undefined,abort.signal);
  if(current(g,actor))detail.value=readCountryDetail(value,actor,id);
}
function scheduleOriginal(){
  stopTimer();const state=outcome.value?.request?.request.state;
  if(!props.active||!(pending.value&&['queued','running'].includes(state||'')||['queued','running'].includes(detail.value?.request.state||'')))return;
  const g=generation,actor=props.actor;timer=setTimeout(async()=>{if(!current(g,actor)||busy.value||detailBusy.value)return;try{await readOriginal(g,actor);if(current(g,actor)&&detail.value&&['queued','running'].includes(detail.value.request.state))await readDetail(g,actor,detail.value.request.id);if(current(g,actor))await readJobs(g,actor);}catch(cause){if(current(g,actor))error.value=(cause as Error).message+'；保留原编号，未重发。';}finally{if(current(g,actor))scheduleOriginal();}},3000);
}
async function refresh(){
  if(!props.active||busy.value)return;stopTimer();const g=++generation,actor=props.actor;abort.abort();abort=new AbortController();busy.value=true;blocked.value=true;error.value='';
  try{const original=await identity().read();if(!current(g,actor))return;pending.value=original;await readOriginal(g,actor);if(!current(g,actor))return;
    const value=await props.api<Page>(endpoint,'GET',undefined,undefined,abort.signal);if(!current(g,actor))return;validatePage(value,actor);page.value=value;await readJobs(g,actor);if(!current(g,actor))return;blocked.value=false;
  }catch(cause){if(current(g,actor))error.value=(cause as Error).message+'；没有创建或重发任务，原浏览器记录保留。';}finally{if(current(g,actor)){busy.value=false;scheduleOriginal();}}
}
async function submit(restore=false){
  if(busy.value||blocked.value||!props.active)return;const p=page.value;if(!p?.available||!p.state.supported)return;
  if(!restore&&!selectionValid.value)return;const g=generation,actor=props.actor;busy.value=true;error.value='';stopTimer();
  try{const context=identity();let original=pending.value;
    if(restore){if(!original||outcome.value?.state_known!==false)throw Error('仅未确认的同一原请求可以手动恢复提交');}
    else{const a=p.available,selection:CountrySelection={action:'download',app_version:'2.6.0',app_manifest_sha256:a.app_manifest_sha256,installation_sha256:p.state.installation_sha256,release:a.release,revision:a.revision,data_manifest_sha256:a.data_manifest_sha256,countries:[...selected.value].sort()};const result=await context.begin(selection);if(!current(g,actor))return;original=result?.ticket;if(!original)throw Error('原请求没有持久保存，未提交');pending.value=original;if(result?.fresh!==true){await readOriginal(g,actor);return;}}
    if(!original)throw Error('原请求缺失，未生成替代编号');
    const reply=await props.api<{job_id:string;request_id:string;replayed:boolean;data_only:boolean}>(endpoint,'POST',{actor_id:actor,selection:original.selection},original.key,abort.signal);if(!current(g,actor))return;
    const next=await context.accepted(original,reply);if(!current(g,actor))return;pending.value=next;await readOriginal(g,actor);if(current(g,actor))await readJobs(g,actor);
  }catch(cause){if(current(g,actor))error.value=(cause as Error).message+'；保留同一请求编号和选项，只读核对，不自动重新 POST。';}finally{if(current(g,actor)){busy.value=false;scheduleOriginal();}}
}
async function showOriginal(id:string){
  if(busy.value||detailBusy.value||!props.active)return;const g=generation,actor=props.actor;detailBusy.value=true;error.value='';
  try{await readDetail(g,actor,id);}catch(cause){if(current(g,actor))error.value=(cause as Error).message;}finally{if(current(g,actor)){detailBusy.value=false;scheduleOriginal();}}
}
async function requestDownloadCancellation(value:CountryDetail|undefined){
  if(busy.value||detailBusy.value||!props.active||!canRequestDownloadCancellation(value))return;
  const g=generation,actor=props.actor;let original:CountryDetail;
  try{original=readCountryDetail(value!,actor,value!.request.id);}catch(cause){error.value=(cause as Error).message;return;}
  busy.value=true;stopTimer();error.value='';
  try{
    const observed=await props.api<CountryDownloadCancelConditions>(endpoint+'/jobs/'+original.request.id+'/download-cancellation','GET',undefined,undefined,abort.signal);
    if(!current(g,actor))return;
    const condition=readCountryDownloadCancelConditions(observed,original,actor);
    if(!condition.can_request){error.value='下载状态已改变；正在核对同一任务的实际结果。';return;}
    await props.api(endpoint+'/jobs/'+original.request.id+'/download-cancellation','POST',{actor_id:actor,payload_sha256:original.request.payload_sha256,request_sha256:condition.request_sha256,selection:original.selection},undefined,abort.signal);
  }catch(cause){if(current(g,actor))error.value=(cause as Error).message+'；取消是否生效尚未确认，保留原任务并继续核对。';}
  finally{
    if(current(g,actor))try{await readDetail(g,actor,original.request.id);if(current(g,actor)&&pending.value?.job===original.request.id)await readOriginal(g,actor);if(current(g,actor))await readJobs(g,actor);}catch(cause){if(current(g,actor))error.value=(cause as Error).message+'；停止结果待核对。';}
    if(current(g,actor)){busy.value=false;scheduleOriginal();}
  }
}
async function cancelOriginal(value:CountryDetail|undefined){
  if(busy.value||detailBusy.value||!props.active||value?.can_cancel_before_dispatch!==true)return;
  const g=generation,actor=props.actor;let original:CountryDetail;
  try{original=readCountryDetail(value,actor,value.request.id);}catch(cause){error.value=(cause as Error).message;return;}
  busy.value=true;stopTimer();error.value='';
  try{await props.api(endpoint+'/jobs/'+original.request.id+'/cancel-before-dispatch','POST',{actor_id:actor,payload_sha256:original.request.payload_sha256,selection:original.selection},undefined,abort.signal);}
  catch(cause){if(current(g,actor))error.value=(cause as Error).message+'；取消回执未确认，保留原编号，只读核对，不自动重发。';}
  finally{
    if(current(g,actor))try{
      const next=await props.api<CountryDetail>(endpoint+'/jobs/'+original.request.id,'GET',undefined,undefined,abort.signal);
      if(current(g,actor)){detail.value=readCountryDetail(next,actor,original.request.id);if(pending.value?.job===original.request.id)await readOriginal(g,actor);if(current(g,actor))await readJobs(g,actor);}
    }catch(cause){if(current(g,actor))error.value=(cause as Error).message+'；保留同一原任务，没有认定下载已停止。';}
    if(current(g,actor)){busy.value=false;scheduleOriginal();}
  }
}
function useDataset(){if(!props.active||busy.value||!detail.value||detail.value.request.state!=='succeeded')return;emit('use-dataset',readCountryDetail(detail.value,props.actor,detail.value.request.id));}
async function showPage(cursor=''){
  if(busy.value||!props.active)return;const g=generation,actor=props.actor;busy.value=true;error.value='';stopTimer();
  try{await readJobs(g,actor,cursor);}catch(cause){if(current(g,actor))error.value=(cause as Error).message+'；未改变原请求。';}finally{if(current(g,actor)){busy.value=false;scheduleOriginal();}}
}
watch(()=>[props.actor,props.active] as const,()=>{reset();if(props.active)void refresh();},{immediate:true});onUnmounted(reset);
</script>
<template>
  <section class="country-data" aria-label="国家与地区签名数据管理">
    <div class="country-head"><div><h3>国家 / 地区网段数据</h3><p>数据准备与网站策略分开操作。下载成功不表示防护已启用；本页不会修改网站配置、重载 Nginx 或安装其他软件。</p></div><el-button :loading="busy" @click="refresh">刷新原状态</el-button></div>
    <el-alert v-if="error" :title="error" type="error" :closable="false"/>
    <el-alert v-if="page&&!page.state.supported" title="需先正常签名安装或升级完整国家功能处理器；旧版防火墙不会因更新面板而自动获得此能力。" type="info" :closable="false"/>
    <p>来源：<a href="https://db-ip.com/" target="_blank" rel="noopener noreferrer">DB-IP Lite</a> · <a href="https://creativecommons.org/licenses/by/4.0/" target="_blank" rel="noopener noreferrer">CC BY 4.0</a>。IP 地域是网络地址的近似归属，并非设备实际位置，不保证所有地址均有定位。国家规则的“未匹配所选地区”不等于“未知国家”。</p>
    <section v-if="pending" class="country-pending" aria-live="polite"><h4>保留的原请求</h4><p>请求 <code>{{pending.key}}</code><span v-if="pending.job"> · 任务 <code>{{pending.job}}</code></span><br/>{{pending.selection.release}} r{{pending.selection.revision}} · {{pending.selection.countries.map(countryName).join('、')}}</p><p>{{outcome?.state_known?detailLabel(outcome.request):'是否已提交尚未确认，不能据此认定未提交。原编号不会自动更换。'}}</p><el-button :disabled="busy" @click="refresh">只读核对原请求</el-button><el-button v-if="outcome?.request?.can_cancel_before_dispatch" type="warning" :disabled="busy||detailBusy" @click="cancelOriginal(outcome.request)">取消尚未提交的原任务</el-button><el-button v-if="canRequestDownloadCancellation(outcome?.request)" type="warning" :disabled="busy||detailBusy" @click="requestDownloadCancellation(outcome?.request)">取消下载</el-button><el-button v-if="outcome?.state_known===false" type="warning" :disabled="busy||blocked||!page?.state.supported||!page.available" @click="submit(true)">手动恢复同一原提交</el-button><p>恢复只使用原账户、原编号和原选项；已存在时服务端只返回原任务。待核对任务不会被重新执行。</p></section>
    <el-alert v-if="page?.source_error" :title="'最新签名目录待核对：'+page.source_error" type="warning" :closable="false"/>
    <section v-if="page?.available" class="country-picker"><h4>已验签目录 · {{page.available.release}} r{{page.available.revision}}</h4><el-select v-model="selected" multiple filterable :multiple-limit="32" placeholder="选择国家或地区（最多32个）" :disabled="busy||!!pending||blocked" aria-label="选择国家或地区"><el-option v-for="file in page.available.files" :key="file.code" :label="countryName(file.code)+' · '+file.code" :value="file.code"/></el-select><p>当前选择 {{selected.length}} 个地区 · {{totals.networks.toLocaleString()}} 条网段 · {{(totals.bytes/1048576).toFixed(2)}} MiB。单次最多 1,048,576 条网段和 64 MiB；目录总量不是单次可启用量。</p><el-button type="primary" :disabled="busy||blocked||!!pending||!selectionValid" @click="submit(false)">准备并完整验证数据（不启用防护）</el-button></section>
    <p v-if="outcome?.state_known&&!pending">最近原请求：{{detailLabel(outcome.request)}}。浏览器待办已结束，原始任务和完整结果仍保留在面板。</p>
    <h4>当前账户的原始数据任务</h4><el-table :data="jobs?.entries||[]" empty-text="没有可完整核对的原数据任务"><el-table-column label="创建时间" min-width="155"><template #default="{row}">{{formatPanelDateTime(row.created_at)}}</template></el-table-column><el-table-column label="任务状态" min-width="190"><template #default="{row}">{{label(row.state)}}</template></el-table-column><el-table-column prop="id" label="原任务编号" min-width="210"/><el-table-column label="核对" width="100"><template #default="{row}"><el-button :disabled="busy||detailBusy" @click="showOriginal(row.id)">查看原结果</el-button></template></el-table-column></el-table>
    <el-button v-if="jobs?.next_cursor" :disabled="busy" @click="showPage(jobs.next_cursor)">下一页原任务</el-button><el-button v-if="jobs?.entries.length" :disabled="busy" @click="showPage()">返回第一页</el-button>
    <section v-if="detail" class="country-result"><h4>原任务 {{detail.request.id}}</h4><p>{{detailLabel(detail)}}<span v-if="detail.error"> · {{detail.error}}</span></p><p>{{detail.selection.release}} r{{detail.selection.revision}} · {{detail.selection.countries.join('、')}}</p><el-button v-if="detail.can_cancel_before_dispatch" type="warning" :disabled="busy||detailBusy" @click="cancelOriginal(detail)">取消尚未提交的原任务</el-button><el-button v-if="canRequestDownloadCancellation(detail)" type="warning" :disabled="busy||detailBusy" @click="requestDownloadCancellation(detail)">取消下载</el-button><p v-if="detail.download_cancellation">取消请求时间：{{formatPanelDateTime(detail.download_cancellation.requested_at)}}。页面会持续核对同一任务；若数据已经完成，将显示实际完成结果。</p><p v-else-if="detail.cancellation">取消时间：{{formatPanelDateTime(detail.cancellation.cancelled_at)}}。原任务在提交执行服务前结束，未下载或启用数据。原记录与审计保留。</p><p v-else-if="['queued','running','needs_attention'].includes(detail.request.state)">任务记录将保留；取消请求发出后，以原任务的实际停止或完成结果为准。</p><template v-if="detail.result?.cache"><p>已提交数据集：<code>{{detail.result.cache.dataset}}</code><br/>{{detail.result.cache.networks.toLocaleString()}} 条网段 · {{(detail.result.cache.bytes/1048576).toFixed(2)}} MiB · 原发布任务 {{detail.result.cache.original_job_id}}</p><el-alert title="这是原任务当时完整核对并提交的数据缓存回执，不是当前数据文件完整性或网站防护生效的证明。启用策略前还会独立复核原签名和全部文件。" type="info" :closable="false"/><el-button v-if="detail.request.state==='succeeded'" :disabled="busy||detailBusy" @click="useDataset">载入策略草稿（默认停用）</el-button></template></section>
  </section>
</template>
<style scoped>
.country-data{min-width:0}.country-data p{line-height:1.7;color:var(--el-text-color-secondary);overflow-wrap:anywhere}.country-head{display:flex;gap:16px;align-items:flex-start;justify-content:space-between}.country-data .el-alert{margin:12px 0}.country-data code{overflow-wrap:anywhere;word-break:break-all}.country-pending,.country-picker,.country-result{border:1px solid var(--el-border-color);border-radius:8px;padding:16px;margin:16px 0}.country-picker .el-select{width:min(100%,720px)}@media(max-width:640px){.country-head{flex-direction:column}.country-data :deep(.el-table .cell){overflow-wrap:anywhere}}
</style>
