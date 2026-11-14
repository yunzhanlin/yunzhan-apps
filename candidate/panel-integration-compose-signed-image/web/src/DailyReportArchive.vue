<script setup lang="ts">
import {onBeforeUnmount,ref,watch} from 'vue';
import DailyReportSummary from './DailyReportSummary.vue';
import {dailyArchivePage,dailyArchiveDetail,type DailyArchivePage,type DailyArchiveRow} from './dailyReportView';
const props=defineProps<{api:<T>(path:string,method?:string,body?:unknown,key?:string,signal?:AbortSignal)=>Promise<T>;active:boolean;enabled:boolean}>();
const limit=ref(20),page=ref<DailyArchivePage>(),pending=ref(''),error=ref('');
const selected=ref<DailyArchiveRow>(),detail=ref<Record<string,unknown>>();
let controller:AbortController|undefined;
function reset(){
 controller?.abort();
 controller=undefined;
 page.value=undefined;selected.value=undefined;detail.value=undefined;pending.value='';error.value='';
}
async function read<T>(action:'archive'|'report-detail',body:Record<string,unknown>,verify:(value:unknown)=>T|undefined,apply:(value:T)=>void){
 if(!props.active||!props.enabled||pending.value)return;
 const active=new AbortController();controller=active;pending.value=action;error.value='';
 try{
  const value=await props.api('/app-modules/daily-report/'+action,'POST',body,undefined,active.signal);
  if(controller!==active||active.signal.aborted||!props.active||!props.enabled)return;
  const checked=verify(value);
  if(checked===undefined)throw Error('服务器返回的日报身份或分页与本次选择不一致。');
  apply(checked);
 }catch(cause){
  if(controller===active&&!active.signal.aborted)error.value=cause instanceof Error?cause.message:'日报读取失败。';
 }finally{if(controller===active){controller=undefined;pending.value='';}}
}
function load(offset=0){
 if(pending.value||offset<0||offset>100000)return;
 const size=limit.value;
 page.value=undefined;selected.value=undefined;detail.value=undefined;
 void read('archive',{offset,limit:size},v=>dailyArchivePage(v,offset,size),v=>{page.value=v;});
}
function open(row:DailyArchiveRow){
 if(pending.value||!row.record_size_valid||!page.value?.reports.includes(row))return;
 selected.value=row;detail.value=undefined;
 void read('report-detail',{resource_id:row.day},v=>dailyArchiveDetail(v,row),v=>{detail.value=v;});
}
function download(){
 if(!selected.value||!detail.value||pending.value||!props.active||!props.enabled)return;
 const url=URL.createObjectURL(new Blob([JSON.stringify(detail.value,null,2)+'\n'],{type:'application/json;charset=utf-8'}));
 const a=document.createElement('a');a.href=url;a.download='daily-report-'+selected.value.day+'.json';a.click();
 window.setTimeout(()=>URL.revokeObjectURL(url),1000);
}
watch(()=>[props.active,props.enabled],()=>{reset();},{flush:'sync'});
onBeforeUnmount(reset);
</script>
<template>
 <section aria-label="已保存的日报目录" class="archive">
  <p>按日期查找已保存的日报。目录只核对日期、生成时间和大小；打开一条记录时才核对正文。</p>
  <p v-if="!enabled" role="status">应用的安装状态尚未核对，暂不能读取历史日报。</p>
  <template v-else>
   <div class="controls">
    <label>每页条数 <select v-model.number="limit" :disabled="!!pending" @change="load(0)"><option :value="10">10</option><option :value="20">20</option><option :value="50">50</option></select></label>
    <el-button :disabled="!!pending" @click="load(page?.offset??0)">刷新历史日报</el-button>
    <el-button :disabled="!page?.offset||!!pending" @click="load(Math.max(0,(page?.offset??0)-limit))">上一页</el-button>
    <el-button :disabled="!page||!!pending||page.offset+limit>=page.total||page.offset+limit>100000" @click="load((page?.offset??0)+limit)">下一页</el-button>
   </div>
   <p v-if="pending" role="status">{{pending==='archive'?'正在读取已保存目录…':'正在核对所选日报正文…'}}</p>
   <p v-if="error" role="alert">{{error}}</p>
   <template v-if="page">
    <p role="status">{{page.total ? `共有 ${page.total} 份日报；当前列出 ${page.reports.length} 份。` : '还没有已保存的日报。'}}</p>
    <ul v-if="page.reports.length" class="days">
     <li v-for="row in page.reports" :key="row.day">
      <div><strong>{{row.day}}</strong><p>{{row.created_at}} · {{row.bytes}} B</p></div>
      <el-button :disabled="!!pending||!row.record_size_valid" :aria-label="'打开 '+row.day+' 的日报'" @click="open(row)">{{row.record_size_valid?'打开日报':'大小异常'}}</el-button>
     </li>
    </ul>
   </template>
   <section v-if="selected && detail" aria-label="已核验的日报正文">
    <h4>{{selected.day}} 日报</h4>
    <DailyReportSummary :report="detail" />
    <el-button @click="download">下载这份日报 JSON</el-button>
   </section>
  </template>
 </section>
</template>
<style scoped>
.archive{display:grid;gap:12px;overflow-wrap:anywhere}
.archive p{margin:0}
.controls,.days li{display:flex;align-items:center;justify-content:flex-start;flex-wrap:wrap;gap:8px}
.controls label{display:flex;align-items:center;gap:6px}
.controls :deep(.el-button+.el-button){margin-left:0}
.days{list-style:none;padding:0;margin:0}
.days li{justify-content:space-between;padding:10px 0;border-bottom:1px solid var(--panel-border,#dce5ed)}
.days p{font-size:12px;color:var(--panel-muted,#61738d)}
[aria-label="已核验的日报正文"]{border-top:1px solid var(--panel-border,#dce5ed);padding-top:14px}
[aria-label="已核验的日报正文"]>.el-button{margin-top:12px}
</style>
