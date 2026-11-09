<script setup lang="ts">
import {computed,onBeforeUnmount,ref,watch} from "vue";
import {ElMessageBox} from "element-plus";
import {apacheLogActionReceipt,apacheLogExport,apacheLogInventory,type ApacheLogArchive,type ApacheLogInventory,type ApacheLogRecovery,type ApacheLogStage} from "./apacheNumericLogs";
import {formatPanelDateTime} from "./panelTime";
import ApacheLogAutomation from "./ApacheLogAutomation.vue";
type API=<T>(path:string,method?:string,body?:unknown,key?:string)=>Promise<T>;
const props=defineProps<{api:API;active:boolean;installed:boolean;version?:string;parentBusy:boolean}>();
const inventory=ref<ApacheLogInventory>(),reading=ref(false),writing=ref(false),confirming=ref(false),known=ref(false),unknown=ref(false),error=ref(""),receipt=ref("");
const automaticBlocked=ref(true);
let epoch=0,disposed=false;
const current=(ticket:number)=>!disposed && props.active && ticket===epoch;
const supported=computed(()=>props.installed && ["2.4.0","2.5.0","2.5.1"].includes(props.version||""));
const blocked=computed(()=>!supported.value || props.parentBusy || reading.value || writing.value || confirming.value || !known.value || unknown.value);
const label=(s:string)=>({completed:"快照已完成",copying:"复制结果待核对",prepared:"截断结果待核对",removing:"删除结果待核对",retained:"已保留未知结果","retained-incomplete":"已保留不完整快照","retained-missing":"原快照缺失，保留意图"}[s] || "状态不可核实");
async function refresh(){
 if(!props.active || reading.value || writing.value || !supported.value)return;
 const ticket=epoch;reading.value=true;known.value=false;error.value="";
 try{
  const out=await props.api<unknown>("/software/apache-waf/body-log/archives");
  if(!current(ticket))return;
  if(!apacheLogInventory(out))throw Error("库存身份、摘要、容量或恢复状态无法完整核实");
  inventory.value=out;known.value=true;unknown.value=false;
 }catch(e){if(current(ticket))error.value="库存读取未完成，未显示为空："+(e as Error).message;}
 finally{if(current(ticket))reading.value=false;}
}
async function confirm(text:string,exact?:string):Promise<boolean>{
 try{
  if(exact){const result=await ElMessageBox.prompt(text+"\n请逐字输入："+exact,"核对原日志记录",{inputPlaceholder:exact,confirmButtonText:"核对并执行",cancelButtonText:"取消",inputValidator:(v:string)=>v===exact || "确认文本与当前所选记录不符",closeOnClickModal:false});return result.value===exact;}
  await ElMessageBox.confirm(text,"Apache 数值日志维护",{confirmButtonText:"保存快照并轮转",cancelButtonText:"取消",type:"warning",closeOnClickModal:false});return true;
 }catch{return false;}
}
async function action(kind:"rotate"|"remove"|"retain"|"retain-stage",item?:ApacheLogArchive|ApacheLogRecovery|ApacheLogStage){
 if(blocked.value || kind==="rotate" && automaticBlocked.value)return;
 const ticket=epoch;
 let path="/software/apache-waf/body-log/rotate",payload:unknown={},id="",digest="",text="将完整核验并保存当前数字日志快照，再清空同一个日志文件；Apache 不重载。最多保留 8 份，写入锁忙或结果未知时会保留证据并拒绝重复截断。",exact:string|undefined;
 if(kind==="remove"){
  const row=item as ApacheLogArchive;id=row.id;digest=row.sha256;path="/software/apache-waf/body-log/archives/"+id+"/remove";payload={sha256:digest,confirm_delete:true};text="将永久移除所选快照，不改变当前日志。原 SHA-256："+digest+"。若原记录是“删除结果待核对”，本次只核对并继续这个原标识和摘要的删除。";exact="DELETE APACHE BODY SNAPSHOT "+id;
 }else if(kind==="retain"){
  const row=item as ApacheLogRecovery;id=row.archive.id;path="/software/apache-waf/body-log/archives/"+id+"/retain";payload={index_sha256:row.index_sha256,snapshot_sha256:row.snapshot_sha256,snapshot_missing:row.snapshot_missing,confirm_unknown:true};text="保留所选未完成轮转的原意图与实际快照；不会再截断当前日志，也不会把未知结果标成成功。索引摘要："+row.index_sha256+"。";exact="RETAIN APACHE BODY "+id;
 }else if(kind==="retain-stage"){
  const row=item as ApacheLogStage;id=row.id;path="/software/apache-waf/body-log/index-stages/"+id+"/retain";payload={sha256:row.sha256,confirm_unknown:true};text="将原索引残件按摘要保留，保持 inode 与字节，不采用为正式快照索引。SHA-256："+row.sha256+"。";exact="RETAIN APACHE INDEX "+id;
 }
 confirming.value=true;const accepted=await confirm(text,exact);if(current(ticket))confirming.value=false;
 if(!accepted || !current(ticket) || blocked.value)return;
 writing.value=true;known.value=false;error.value="";receipt.value="";
 try{
  const out=await props.api<unknown>(path,"POST",payload);
  if(!current(ticket))return;
  if(!apacheLogActionReceipt(out,kind,id,digest))throw Error("原操作回执身份或状态不完整");
  receipt.value=kind==="rotate"?"原数字日志快照已核验并持久保存，同 inode 轮转完成；未重载 Apache。":kind==="remove"?"所选摘要快照已移除，当前日志未改变。":"未知结果原证据已保留；没有重做原轮转或宣称成功。";
 }catch(e){if(current(ticket)){unknown.value=true;error.value="提交结果需核对："+(e as Error).message+"。本页不会自动重试，请先刷新原库存。";}}
 finally{if(current(ticket))writing.value=false;}
 if(current(ticket) && !unknown.value)await refresh();
}
async function exportSnapshot(row:ApacheLogArchive){
 if(blocked.value)return;
 const ticket=epoch;reading.value=true;error.value="";
 try{
  const out=await props.api<unknown>("/software/apache-waf/body-log/archives/"+row.id);
  if(!current(ticket))return;
  if(!apacheLogExport(out,row))throw Error("所选快照摘要、隐私字段或导出范围不符");
  const object=URL.createObjectURL(new Blob([JSON.stringify(out,null,2)],{type:"application/json;charset=utf-8"}));
  const link=document.createElement("a");link.href=object;link.download="apache-body-numeric-"+row.id+".json";link.click();URL.revokeObjectURL(object);
  receipt.value="已导出所选快照的数字记录尾部；最多 4 MiB / 5000 条，不是完整原始文件或独立流量统计。";
 }catch(e){if(current(ticket))error.value=(e as Error).message;}
 finally{if(current(ticket))reading.value=false;}
}
watch(()=>[props.active,props.installed,props.version],()=>{epoch++;known.value=false;reading.value=false;writing.value=false;confirming.value=false;inventory.value=undefined;error.value="";receipt.value="";if(props.active && supported.value)void refresh();},{immediate:true});
onBeforeUnmount(()=>{disposed=true;epoch++;});
</script>
<template>
 <section class="apache-logs">
  <el-alert type="info" :closable="false" title="保存数字日志快照后轮转，不重载 Apache。仅管理员可维护，不包含 IP、URI、Cookie、请求体或文件原文。"/>
  <p v-if="!supported">需要先完成 Apache 原生防护应用的签名安装。当前读取不会创建日志、安装软件或启用网站防护。</p>
  <ApacheLogAutomation :api="api" :active="active" :installed="installed" :version="version" :parent-busy="parentBusy||writing||confirming" @blocked="automaticBlocked=$event" @inventory-change="refresh"/>
  <div class="apache-log-actions"><el-button :loading="reading" :disabled="!supported || writing" @click="refresh">核对完整库存</el-button><el-button type="primary" :loading="writing" :disabled="blocked || automaticBlocked || !inventory || inventory.archives.length>=8 || inventory.recovery.length>0 || inventory.index_stages.length>0" @click="action('rotate')">保存快照并轮转</el-button></div>
  <el-alert v-if="error" type="error" :closable="false" :title="error"/>
  <el-alert v-if="receipt && known" type="success" :closable="false" :title="receipt"/>
  <p v-if="!known && supported" role="status">{{reading?'正在核对固定目录、全部快照与摘要':'库存尚不可核实，不能当成零个快照。'}}</p>
  <template v-if="known && inventory">
   <el-descriptions :column="3" border><el-descriptions-item label="快照名额">{{inventory.archives.length}} / 8</el-descriptions-item><el-descriptions-item label="每份最大容量">32 MiB</el-descriptions-item><el-descriptions-item label="维护状态">{{inventory.maintenance_healthy?'本次库存已核实':'存在未知结果或保留证据'}}</el-descriptions-item></el-descriptions>
   <p>“库存已核实”只表示本次日志库存核对，不代表网站已启用防护。达到名额时拒绝新轮转，不自动覆盖旧证据。</p>
   <el-table :data="inventory.archives" max-height="420" empty-text="已核实：当前没有数字日志快照">
    <el-table-column prop="id" label="原快照标识" min-width="220" show-overflow-tooltip/>
    <el-table-column label="创建时间" min-width="170"><template #default="{row}">{{formatPanelDateTime(row.captured_at)}}</template></el-table-column>
    <el-table-column prop="bytes" label="字节" width="110"/>
    <el-table-column label="状态" min-width="180"><template #default="{row}">{{label(row.state)}}</template></el-table-column>
    <el-table-column prop="sha256" label="SHA-256" min-width="210" show-overflow-tooltip/>
    <el-table-column label="操作" min-width="190"><template #default="{row}"><el-button link :disabled="blocked || row.state==='copying'" @click="exportSnapshot(row)">导出数字记录</el-button><el-button link type="danger" :disabled="blocked || row.state==='copying' || row.state==='prepared'" @click="action('remove',row)">{{row.state==='removing'?'核对原删除':'移除快照'}}</el-button></template></el-table-column>
   </el-table>
   <template v-if="inventory.recovery.length"><h4>未确认完成的原轮转或删除</h4><p>保留不会重做原轮转、恢复原流量或宣称成功。删除结果待核对的记录须按原标识及摘要明确处理。</p><div v-for="row in inventory.recovery" :key="row.archive.id" class="apache-log-recovery"><code>{{row.archive.id}}</code><span>{{label(row.archive.state)}} · {{row.snapshot_missing?'原快照缺失':row.snapshot_bytes+' 字节'}}</span><el-button :disabled="blocked || row.archive.state==='removing'" @click="action('retain',row)">核对并保留未知结果</el-button></div></template>
   <template v-if="inventory.index_stages.length"><h4>未提交的原索引残件</h4><div v-for="row in inventory.index_stages" :key="row.id" class="apache-log-recovery"><code>{{row.id}}</code><span>{{row.bytes}} 字节 · {{row.sha256}}</span><el-button :disabled="blocked" @click="action('retain-stage',row)">按原摘要保留残件</el-button></div></template>
  </template>
  <p>快照可能重叠，不合计为独立流量或已确认拦截数。导出只读取所选快照尾部最多 4 MiB / 5000 条数字记录；未确认复制、损坏摘要或异常路径不会作为完整导出。自动轮转须明确保存策略，快照删除始终需要逐份按摘要确认。</p>
 </section>
</template>
<style scoped>
.apache-logs{display:grid;gap:14px}.apache-logs p{margin:0;line-height:1.7;color:#64748b}.apache-log-actions{display:flex;gap:10px;flex-wrap:wrap}.apache-log-actions .el-button{margin:0}.apache-log-recovery{display:flex;gap:12px;align-items:center;flex-wrap:wrap;border:1px solid #e2e8f0;padding:12px;border-radius:8px}.apache-log-recovery span,.apache-log-recovery code{overflow-wrap:anywhere;min-width:0}.apache-log-recovery span{flex:1}.apache-logs h4{margin:10px 0 0}@media(max-width:760px){.apache-log-recovery{align-items:flex-start;flex-direction:column}.apache-log-actions .el-button{max-width:100%}}
</style>
