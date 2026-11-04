<script setup lang="ts">
import {computed,onBeforeUnmount,ref,watch} from "vue";
import {ElMessageBox} from "element-plus";
import {ccArchiveRequest,ccArchiveEntry,ccArchiveInventory,ccRequestObservation,ccArchiveChunk,ccArchiveData,ccRecovery,ccRetentionTicket,ccHistoryObservation,ccHistoryReceipt,sameCCArchiveRequest,type CCArchiveRequest,type CCArchiveEntry,type CCArchiveInventory,type CCRequestObservation,type CCRecovery,type CCRetentionTicket} from "./apacheCCArchives";
import {browserSHA256} from "./browserSHA256";
import {randomId} from "./randomId";
import {formatPanelDateTime} from "./panelTime";
type API=<T>(path:string,method?:string,body?:unknown,key?:string)=>Promise<T>;
const props=defineProps<{api:API;actor?:string;active:boolean;installed:boolean;version?:string;implementation:string;revision:number;parentBusy:boolean}>();
const inventory=ref<CCArchiveInventory>(),known=ref(false),reading=ref(false),writing=ref(false),confirming=ref(false),storageReady=ref(false),error=ref(""),receipt=ref(""),progress=ref("");
const storageError=ref(""),operationError=ref("");
const pending=ref<CCArchiveRequest>(),observation=ref<CCRequestObservation>(),allowIncomplete=ref(false);
const recovery=ref<CCRecovery>(),pendingRetention=ref<CCRetentionTicket>();
const priorRetentions=ref<CCRetentionTicket[]>([]);
const pendingHistory=ref<CCRetentionTicket>();
let epoch=0,disposed=false;
const actorValid=computed(()=>typeof props.actor==="string"&&/^[a-f0-9]{32}$/.test(props.actor));
const supported=computed(()=>actorValid.value&&props.installed&&props.version==="2.5.1"&&props.implementation===props.version);
const current=(ticket:number)=>!disposed&&props.active&&ticket===epoch;
const busy=computed(()=>reading.value||writing.value||confirming.value||props.parentBusy);
const canArchive=computed(()=>supported.value&&storageReady.value&&known.value&&!busy.value&&!pending.value&&!pendingRetention.value&&!pendingHistory.value&&!!inventory.value?.maintenance_healthy&&inventory.value.archives.length<8&&inventory.value.current.available&&inventory.value.current.bytes>0&&(!inventory.value.current.tail_incomplete||allowIncomplete.value)&&Number.isSafeInteger(props.revision)&&props.revision>=1&&props.revision<=1000000000);
const archiveRows=computed(()=>inventory.value?[...inventory.value.archives,...inventory.value.history]:[]);
const isHistory=(row:CCArchiveEntry)=>!!inventory.value?.history.some(value=>value.id===row.id);
const canClose=computed(()=>supported.value&&known.value&&!busy.value&&!!pending.value&&["not-recorded","closed"].includes(observation.value?.kind||""));
const key=()=>"yunzhan.apache-cc-archive.v1."+props.actor;
const retentionKey=()=>key()+".retain";
const priorRetentionKey=()=>key()+".retain.prior";
const historyKey=()=>key()+".history";
function loadPending(){
 storageReady.value=false;storageError.value="";pending.value=undefined;observation.value=undefined;pendingRetention.value=undefined;pendingHistory.value=undefined;recovery.value=undefined;priorRetentions.value=[];
 if(!actorValid.value)return;
 try{
  const raw=sessionStorage.getItem(key());
  if(raw!==null){const value:unknown=JSON.parse(raw);if(!ccArchiveRequest(value))throw Error("原请求记录格式不完整，未删除或覆盖");pending.value=value;}
  const retained=sessionStorage.getItem(retentionKey());
  if(retained!==null){const value:unknown=JSON.parse(retained);if(!ccRetentionTicket(value))throw Error("原证据保留请求记录不完整，未删除或覆盖");pendingRetention.value=value;}
  const prior=sessionStorage.getItem(priorRetentionKey());if(prior!==null){const value:unknown=JSON.parse(prior);if(!Array.isArray(value)||value.length>8||!value.every(ccRetentionTicket))throw Error("以前保留请求的原标识不完整，未覆盖");priorRetentions.value=value;}
  const history=sessionStorage.getItem(historyKey());if(history!==null){const value:unknown=JSON.parse(history);if(!ccRetentionTicket(value))throw Error("原历史转存请求记录不完整，未删除或覆盖");pendingHistory.value=value;}
  storageReady.value=true;
 }catch(e){storageError.value="浏览器原请求标识尚不可核实，未提交新归档："+(e as Error).message;}
}
function rememberRetention(value:CCRetentionTicket){
 if(priorRetentions.value.some(x=>x.id===value.id&&x.sha256===value.sha256))return;
 if(priorRetentions.value.length>=8)throw Error("本浏览器保留的旧请求已达 8 份，未覆盖原标识");
 const values=[...priorRetentions.value,value],raw=JSON.stringify(values);sessionStorage.setItem(priorRetentionKey(),raw);if(sessionStorage.getItem(priorRetentionKey())!==raw)throw Error("旧保留请求标识未完整保存");priorRetentions.value=values;
}
function clearHistory(value:CCRetentionTicket){
 if(!pendingHistory.value||pendingHistory.value.id!==value.id||pendingHistory.value.sha256!==value.sha256)throw Error("原历史转存标识已变化");
 sessionStorage.removeItem(historyKey());if(sessionStorage.getItem(historyKey())!==null)throw Error("原历史转存标识未清除");pendingHistory.value=undefined;
}
async function observeHistory(ticket:number){
 const original=pendingHistory.value;if(!original)return;
 const out=await props.api<unknown>("/software/apache-waf/cc-log/archives/"+original.id+"/history");if(!current(ticket))return;
 if(!ccHistoryObservation(out,original.id)||out.snapshot_sha256!==original.sha256)throw Error("原历史转存的文件清单或摘要不同，保留原等待标识");
 if(out.history){clearHistory(original);receipt.value="已核对原历史转存；所有原始文件继续保存，未再次移动。";operationError.value="";}
}
function clearRetention(value:CCRetentionTicket){
 if(!pendingRetention.value||pendingRetention.value.id!==value.id||pendingRetention.value.sha256!==value.sha256)throw Error("原保留请求已变化，保留浏览器记录");
 sessionStorage.removeItem(retentionKey());if(sessionStorage.getItem(retentionKey())!==null)throw Error("原保留标识未清除，继续核对");pendingRetention.value=undefined;
}
async function observeRetention(ticket:number){
 const original=pendingRetention.value;if(!original)return;
 const out=await props.api<unknown>("/software/apache-waf/cc-log/archives/"+original.id+"/recovery");if(!current(ticket))return;
 if(!ccRecovery(out,original.id))throw Error("原保留证据回执不完整");recovery.value=out;
 if(out.record.state==="retained-unknown"){
  if(out.snapshot_sha256!==original.sha256){operationError.value="已核实另一份完整保留证据；原保留请求的结果仍未知，原浏览器标识继续保留。";return;}
  clearRetention(original);operationError.value="";receipt.value="已核对原证据保留回执；原归档结果仍未知，未重复名称交换。";
 }
}
function persistPending(value:CCArchiveRequest){
 const raw=JSON.stringify(value);sessionStorage.setItem(key(),raw);
 if(sessionStorage.getItem(key())!==raw)throw Error("浏览器未完整保存原请求标识，未提交");
 pending.value=value;observation.value=undefined;
}
function clearPending(value:CCArchiveRequest){
 if(!pending.value||!sameCCArchiveRequest(pending.value,value))throw Error("浏览器当前原请求已变化，保留记录");
 sessionStorage.removeItem(key());if(sessionStorage.getItem(key())!==null)throw Error("浏览器原请求标识未清除，保留核对状态");
 pending.value=undefined;observation.value=undefined;
}
async function observeOriginal(ticket:number){
 const original=pending.value;if(!original)return;
 const out=await props.api<unknown>("/software/apache-waf/cc-log/requests/"+original.request_id);
 if(!current(ticket))return;
 if(!ccRequestObservation(out,original))throw Error("原请求标识或完整回执未通过核对");
 observation.value=out;
 if(out.kind==="archive"&&out.record.state==="completed"){
  clearPending(original);operationError.value="";receipt.value="原归档已完整核对，旧日志已封存，新日志继续记录；未重做原操作。";
 }
}
async function refresh(){
 if(!props.active||!supported.value||reading.value||writing.value)return;
 const ticket=epoch;reading.value=true;known.value=false;error.value="";recovery.value=undefined;
 try{
  const out=await props.api<unknown>("/software/apache-waf/cc-log/archives");if(!current(ticket))return;
  if(!ccArchiveInventory(out))throw Error("完整库存、原始身份或封存摘要无法核实");
  inventory.value=out;known.value=true;await observeOriginal(ticket);await observeRetention(ticket);await observeHistory(ticket);
 }catch(e){if(current(ticket)){known.value=false;error.value="读取尚未完成，不能当成空库存："+(e as Error).message;}}
 finally{if(current(ticket))reading.value=false;}
}
async function preserveHistory(row:CCArchiveEntry){
 if(!known.value||!supported.value||!storageReady.value||busy.value||row.state==="unknown"||isHistory(row)||!inventory.value||inventory.value.history.length>=32||pendingRetention.value||pendingHistory.value&&pendingHistory.value.id!==row.id)return;
 const ticket=epoch;reading.value=true;error.value="";let original;
 try{const out=await props.api<unknown>("/software/apache-waf/cc-log/archives/"+row.id+"/history");if(!current(ticket))return;if(!ccHistoryObservation(out,row.id)||pendingHistory.value&&pendingHistory.value.sha256!==out.snapshot_sha256)throw Error("原文件清单已变化，未转存");original=out;}
 catch(e){if(current(ticket))error.value=(e as Error).message;return;}
 finally{if(current(ticket))reading.value=false;}
 if(!original||!current(ticket))return;
 if(original.history){if(pendingHistory.value)clearHistory(pendingHistory.value);await refresh();return;}
 confirming.value=true;
 try{await ElMessageBox.confirm("将这一份已封存的原归档及所有阶段记录整体转入私有历史目录，释放一个待归档名额。所有文件继续保留并可下载；当前日志不改变，不删除旧文件。","保留原文件并转入历史",{confirmButtonText:"转存并保留全部原文件",cancelButtonText:"取消",closeOnClickModal:false});}
 catch{return;}finally{if(current(ticket))confirming.value=false;}
 if(!current(ticket)||busy.value||!known.value||!supported.value||!storageReady.value)return;
 const saved={id:row.id,sha256:original.snapshot_sha256},raw=JSON.stringify(saved);
 try{sessionStorage.setItem(historyKey(),raw);if(sessionStorage.getItem(historyKey())!==raw)throw Error("原转存标识未完整保存");pendingHistory.value=saved;}
 catch(e){storageReady.value=false;storageError.value=(e as Error).message;return;}
 writing.value=true;receipt.value="";operationError.value="";
 try{const out=await props.api<unknown>("/software/apache-waf/cc-log/archives/"+saved.id+"/history","POST",{sha256:saved.sha256,confirm_preserve:true});if(!current(ticket))return;if(!ccHistoryReceipt(out,saved.id,saved.sha256))throw Error("原文件转存回执不一致");clearHistory(saved);receipt.value="原归档和全部阶段证据已转入历史，待归档名额已释放；原文件没有删除。";}
 catch(e){if(current(ticket))operationError.value="原历史转存结果须核对："+(e as Error).message+"。不会自动重发；以原标识核对文件位置与摘要。";}
 finally{if(current(ticket))writing.value=false;}
 if(current(ticket))await refresh();
}
async function inspectRecovery(row:CCArchiveEntry){
 if(!known.value||!supported.value||busy.value||row.state==="completed")return;
 const ticket=epoch;reading.value=true;error.value="";
 try{const out=await props.api<unknown>("/software/apache-waf/cc-log/archives/"+row.id+"/recovery");if(!current(ticket))return;if(!ccRecovery(out,row.id))throw Error("原始证据清单或完整摘要不符");recovery.value=out;}
 catch(e){if(current(ticket)){recovery.value=undefined;error.value=(e as Error).message;}}
 finally{if(current(ticket))reading.value=false;}
}
async function retainUnknown(){
 const original=recovery.value;
 if(!original||original.record.state!=="unknown"||!supported.value||!known.value||!storageReady.value||busy.value||pendingRetention.value&&pendingRetention.value.id!==original.record.id)return;
 const ticket=epoch;confirming.value=true;
 try{await ElMessageBox.confirm((pendingRetention.value?"以前的保留请求结果仍未知，旧标识将另行保留。本次采用刚核实的新快照，完整保留所有旧残件。":"")+"原归档结果仍未知。按当前摘要保留所有原始证据并封存原数据；不重复归档，不更换当前日志，不重载 Apache。","保留未知结果的原证据",{confirmButtonText:"保留证据，原结果仍未知",cancelButtonText:"取消",closeOnClickModal:false});}
 catch{return;}finally{if(current(ticket))confirming.value=false;}
 if(!current(ticket)||!supported.value||!known.value||!storageReady.value||busy.value||recovery.value!==original||pendingRetention.value&&pendingRetention.value.id!==original.record.id)return;
 const saved={id:original.record.id,sha256:original.snapshot_sha256},raw=JSON.stringify(saved);
 try{if(pendingRetention.value)rememberRetention(pendingRetention.value);sessionStorage.setItem(retentionKey(),raw);if(sessionStorage.getItem(retentionKey())!==raw)throw Error("原保留请求未完整保存");pendingRetention.value=saved;}
 catch(e){storageReady.value=false;storageError.value=(e as Error).message;return;}
 writing.value=true;operationError.value="";receipt.value="";
 try{
  const out=await props.api<unknown>("/software/apache-waf/cc-log/archives/"+saved.id+"/retain","POST",{sha256:saved.sha256,confirm_unknown:true});if(!current(ticket))return;
  if(!ccArchiveEntry(out,saved.id)||out.state!=="retained-unknown"||out.retained?.snapshot_sha256!==saved.sha256)throw Error("原保留完成回执不一致");
  clearRetention(saved);receipt.value="全部原始证据已保留；原归档结果仍未知，当前日志继续使用原文件。";
 }catch(e){if(current(ticket))operationError.value="原证据保留结果须核对："+(e as Error).message+"。不会自动重发保留或归档。";}
 finally{if(current(ticket))writing.value=false;}
 if(current(ticket))await refresh();
}
async function acknowledgeObservedRetention(){
 const original=pendingRetention.value,observed=recovery.value;
 if(!original||!observed||observed.record.id!==original.id||observed.record.state!=="retained-unknown"||!known.value||!supported.value||!storageReady.value||busy.value)return;
 const ticket=epoch;confirming.value=true;
 try{await ElMessageBox.confirm("当前完整保留证据已核实，但它与原保留请求的摘要不同。原请求标识将另行保存并继续视为结果未知；确认后解除本浏览器等待，服务端原文件继续保留。","确认现有保留证据",{confirmButtonText:"保留旧标识并确认",cancelButtonText:"取消",closeOnClickModal:false});}
 catch{return;}finally{if(current(ticket))confirming.value=false;}
 if(!current(ticket)||busy.value||pendingRetention.value?.sha256!==original.sha256)return;
 try{rememberRetention(original);clearRetention(original);operationError.value="";receipt.value="已明确采用当前保留证据，旧请求标识另行保存且结果仍未知；没有重新执行原操作。";}catch(e){storageReady.value=false;storageError.value=(e as Error).message;}
}
async function acknowledgeRetainedOriginal(){
 const original=pending.value,observed=observation.value;
 if(!original||!observed||observed.kind!=="archive"||observed.record.state!=="retained-unknown"||!known.value||!supported.value||!storageReady.value||busy.value||pendingRetention.value)return;
 const ticket=epoch;confirming.value=true;
 try{await ElMessageBox.confirm("服务端已保留原请求的全部证据，但原归档结果仍未知。确认后仅解除本浏览器对该原请求的等待，服务端证据继续保存；不重做原操作。","确认原结果未知",{confirmButtonText:"确认并保留服务端证据",cancelButtonText:"取消",closeOnClickModal:false});}
 catch{return;}finally{if(current(ticket))confirming.value=false;}
 if(!current(ticket)||busy.value||!pending.value||!sameCCArchiveRequest(pending.value,original))return;
 try{clearPending(original);operationError.value="";receipt.value="已确认原结果未知，服务端证据继续保留；可以另建新的归档请求。";}catch(e){storageReady.value=false;storageError.value=(e as Error).message;}
}
async function archive(){
 if(!canArchive.value)return;
 const ticket=epoch;confirming.value=true;
 try{await ElMessageBox.confirm("完整保留当前 CC 原始日志，并开始新的私有日志；Apache 不重载，限流额度不重置。"+(allowIncomplete.value?"原残缺末行将按原始字节封存，不作为完整事件。":"末行不完整时暂停，原文件保留。"),"归档 CC 日志",{confirmButtonText:"归档并继续记录",cancelButtonText:"取消",closeOnClickModal:false});}
 catch{return;}finally{if(current(ticket))confirming.value=false;}
 if(!current(ticket)||!canArchive.value)return;
 const original:CCArchiveRequest={request_id:randomId().replaceAll("-",""),expected_revision:props.revision,allow_incomplete:allowIncomplete.value};
 try{persistPending(original);}catch(e){storageReady.value=false;storageError.value=(e as Error).message;return;}
 writing.value=true;error.value="";operationError.value="";receipt.value="";
 try{
  const out=await props.api<unknown>("/software/apache-waf/cc-log/archive","POST",original,original.request_id);
  if(!current(ticket))return;
  if(!ccArchiveEntry(out,original.request_id)||out.state!=="completed"||!out.intent||!sameCCArchiveRequest(out.intent.request,original))throw Error("原归档完成回执不完整");
  clearPending(original);receipt.value="原始 CC 日志已按完整摘要封存，新日志继续记录；Apache 与限流额度保持原状态。";
 }catch(e){if(current(ticket)){operationError.value="归档结果须按原标识核对："+(e as Error).message+"。本页不会自动重发请求。";}}
 finally{if(current(ticket))writing.value=false;}
 if(current(ticket))await refresh();
}
async function closeUnstarted(){
 const original=pending.value;if(!original||!canClose.value)return;
 const ticket=epoch;writing.value=true;error.value="";receipt.value="";
 try{
  const out=await props.api<unknown>("/software/apache-waf/cc-log/requests/"+original.request_id+"/close","POST",original);
  if(!current(ticket))return;
  if(!ccRequestObservation(out,original,true)||out.kind!=="closed")throw Error("未收到拒绝迟到提交的原关闭回执");
  clearPending(original);operationError.value="";receipt.value="已核实原归档未开始并关闭原请求；迟到提交会被拒绝，原日志未改变。";
 }catch(e){if(current(ticket))operationError.value="原关闭结果须核对："+(e as Error).message+"。原标识保留，不重发归档。";}
 finally{if(current(ticket))writing.value=false;}
 if(current(ticket))await refresh();
}
async function download(row:CCArchiveEntry){
 if(!known.value||!supported.value||busy.value||!ccArchiveData(row))return;
 const ticket=epoch;reading.value=true;error.value="";progress.value="";
 try{
  const out=await props.api<unknown>("/software/apache-waf/cc-log/archives/"+row.id);
  if(!current(ticket))return;
  if(!ccArchiveEntry(out,row.id)||!ccArchiveData(out)||ccArchiveData(out)?.sha256!==ccArchiveData(row)?.sha256||out.state!==row.state)throw Error("原归档已变化，未下载文件");
  const original=ccArchiveData(out)!,data=new Uint8Array(original.bytes),parts=Math.ceil(data.length/262144);
  for(let part=0;part<parts;part++){
   const chunk=await props.api<unknown>("/software/apache-waf/cc-log/archives/"+row.id+"/chunks/"+part);
   if(!current(ticket))return;
   data.set(ccArchiveChunk(chunk,out,part),part*262144);progress.value=`已核对 ${part+1} / ${parts} 段`;
  }
  if(browserSHA256(data)!==original.sha256)throw Error("完整原始文件摘要不符，未生成下载文件");
  const url=URL.createObjectURL(new Blob([data],{type:"application/octet-stream"}));
  const link=document.createElement("a");link.href=url;link.download="apache-cc-original-"+row.id+".log";link.click();URL.revokeObjectURL(url);
  receipt.value="完整原始日志已核对 SHA-256 并生成下载文件；请妥善保存其中的客户端 IP 和路径信息。"+(out.state==="retained-unknown"?"该文件为未知结果留下的数据，不能代表原归档已成功。":"");
 }catch(e){if(current(ticket))error.value=(e as Error).message;}
 finally{if(current(ticket)){reading.value=false;progress.value="";}}
}
watch(()=>[props.active,props.installed,props.version,props.implementation,props.actor],()=>{
 epoch++;known.value=false;inventory.value=undefined;reading.value=false;writing.value=false;confirming.value=false;error.value="";operationError.value="";receipt.value="";progress.value="";loadPending();
 if(props.active&&supported.value)void refresh();
},{immediate:true});
onBeforeUnmount(()=>{disposed=true;epoch++;});
</script>
<template>
 <section class="cc-archives">
  <el-alert type="info" :closable="false" title="保留 CC 原始日志后继续记录，不重载 Apache，不重置限流额度。原日志可能包含客户端 IP 和请求路径，仅管理员可下载。"/>
  <p v-if="!supported">CC 原始日志归档需要已安装的 Apache WAF 2.5.1 及对应面板版本；当前读取不会升级软件或启用防护。</p>
  <div class="cc-archive-actions"><el-button :loading="reading" :disabled="!supported||writing" @click="refresh">核对库存与原请求</el-button><el-checkbox v-model="allowIncomplete" :disabled="busy||!!pending" aria-label="保留残缺末行的原始字节">同时保留残缺末行</el-checkbox><el-button type="primary" :loading="writing" :disabled="!canArchive" @click="archive">归档原日志并继续记录</el-button></div>
  <el-alert v-if="error" type="error" :closable="false" :title="error"/>
  <el-alert v-if="storageError" type="error" :closable="false" :title="storageError"/>
  <el-alert v-if="operationError" type="error" :closable="false" :title="operationError"/>
  <el-alert v-if="receipt" type="success" :closable="false" :title="receipt"/>
  <p v-if="progress" role="status">{{progress}}</p>
  <div v-if="pending" class="cc-original-request"><strong>原请求待核对</strong><code>{{pending.request_id}}</code><p>读取不会重新执行归档。已开始或结果未知的原操作保持原证据；只有证明未开始的请求才可关闭，并拒绝后续迟到提交。</p><el-button v-if="observation?.kind==='archive'&&observation.record.state==='retained-unknown'" :disabled="busy||!!pendingRetention||!storageReady" @click="acknowledgeRetainedOriginal">确认原结果未知并保留证据</el-button><el-button v-else :disabled="!canClose" @click="closeUnstarted">{{observation?.kind==='closed'?'核对原关闭回执':'关闭已核实未开始的原请求'}}</el-button></div>
  <el-alert v-if="pendingRetention" type="warning" :closable="false" :title="'原证据保留请求待核对：'+pendingRetention.id+'。只读核对不会重新提交。'"/>
  <details v-if="priorRetentions.length"><summary>保留的旧请求标识（原结果仍未知）</summary><p v-for="item in priorRetentions" :key="item.id+item.sha256"><code>{{item.id}} · {{item.sha256}}</code></p></details>
  <el-alert v-if="pendingHistory" type="warning" :closable="false" :title="'原历史转存待核对：'+pendingHistory.id+'。不会自动重新提交；若核实仍在原处，可再次明确选择转存。'"/>
  <div v-if="recovery" class="cc-original-request"><strong>{{recovery.record.state==='retained-unknown'?'原证据已保留，原结果仍未知':'未知结果的原始证据'}}</strong><code>{{recovery.record.id}}</code><p>原始文件 {{Object.keys(recovery.snapshot.files).length}} 份 · 快照 SHA-256：{{recovery.snapshot_sha256}}</p><p>保留会核对 Root 独立副本并保留全部残件，当前日志不换名、不清空。副本可能来自中断写入，原归档结果仍未知；没有副本时不会声称已备份。来源文件只绑定身份，其内容不作为副本完整性的依据。</p><el-button v-if="recovery.record.state==='unknown'" :disabled="busy||!known||!storageReady||!!pendingRetention&&pendingRetention.id!==recovery.record.id" @click="retainUnknown">{{pendingRetention?'保留旧请求并按当前快照保留证据':'按该摘要保留原证据'}}</el-button><el-button v-else-if="pendingRetention?.id===recovery.record.id" :disabled="busy||!known||!storageReady" @click="acknowledgeObservedRetention">保留旧标识并确认现有证据</el-button></div>
  <p v-if="!known&&supported" role="status">{{reading?'正在读取全部归档和摘要':'尚未取得完整库存，不能显示为零份归档。'}}</p>
  <template v-if="known&&inventory">
   <p>当前 CC 日志：{{inventory.current.available?inventory.current.bytes+' 字节':'已核实尚未创建'}} / 32 MiB{{inventory.current.tail_incomplete?' · 末行不完整，需明确保留原字节后才能归档':''}}。空日志不生成归档。</p>
   <p>待归档 {{inventory.archives.length}} / 8 份 · 历史 {{inventory.history.length}} / 32 份 · 每份独立副本最多 32 MiB，原文件另行保留并占用额外空间 · {{inventory.maintenance_healthy?'本次库存已核实':'有未知结果，暂停新归档'}}。转存历史会保留全部原文件，历史已满时暂停，不自动删除数据。</p>
   <el-table :data="archiveRows" max-height="440" empty-text="已核实：当前没有 CC 原始日志归档">
    <el-table-column prop="id" label="原请求标识" min-width="240" show-overflow-tooltip/>
    <el-table-column label="存放位置" width="100"><template #default="{row}">{{isHistory(row)?'历史保留':'待归档'}}</template></el-table-column>
    <el-table-column label="归档时间" min-width="175"><template #default="{row}">{{formatPanelDateTime(row.intent?.at)}}</template></el-table-column>
    <el-table-column label="原始字节" width="115"><template #default="{row}">{{ccArchiveData(row)?.bytes??row.intent?.source.bytes??'未知'}}</template></el-table-column>
    <el-table-column label="状态" min-width="160"><template #default="{row}">{{row.state==='completed'?'独立副本已校验':row.state==='retained-unknown'?'证据已保留 · 原结果未知':'结果未知'}}{{row.intent?.tail_incomplete?' · 含残缺末行':''}}<small v-if="row.problem">{{row.problem}}</small><small v-if="row.source_status==='changed-after-copy'">原来源文件已变化，独立副本完整</small><small v-else-if="row.source_status==='not-authoritative'">原来源文件另行保留，内容不作为副本依据</small></template></el-table-column>
    <el-table-column label="SHA-256" min-width="210" show-overflow-tooltip><template #default="{row}">{{row.completed?.archive.sha256||row.intent?.source.sha256||'尚未核实'}}</template></el-table-column>
    <el-table-column label="操作" min-width="260"><template #default="{row}"><el-button link :disabled="busy||!ccArchiveData(row)" @click="download(row)">下载已校验副本</el-button><el-button v-if="row.state!=='completed'" link :disabled="busy" @click="inspectRecovery(row)">核对原始证据</el-button><el-button v-if="!isHistory(row)&&row.state!=='unknown'" link :disabled="busy||!storageReady||inventory.history.length>=32||!!pendingRetention||!!pendingHistory&&pendingHistory.id!==row.id" @click="preserveHistory(row)">保留并转存历史</el-button></template></el-table-column>
   </el-table>
  </template>
  <p>归档建立仅 Root 可访问的独立副本，并保留原 inode 与独立阶段记录，不把残缺末行解释为完整事件，不将未知结果追认为成功。下载按段核对身份，完整文件摘要一致后才生成文件。</p>
 </section>
</template>
<style scoped>
.cc-archives{display:grid;gap:14px}.cc-archives p{margin:0;color:#64748b;line-height:1.7}.cc-archive-actions{display:flex;align-items:center;gap:12px;flex-wrap:wrap}.cc-archive-actions .el-button{margin:0}.cc-original-request{display:grid;gap:10px;padding:14px;border:1px solid #e2e8f0;border-radius:8px}.cc-original-request code{overflow-wrap:anywhere}.cc-archives small{display:block;line-height:1.5;color:#b45309}@media(max-width:760px){.cc-archive-actions{align-items:flex-start;flex-direction:column}.cc-original-request .el-button{white-space:normal;height:auto;min-height:32px;max-width:100%}}
</style>
