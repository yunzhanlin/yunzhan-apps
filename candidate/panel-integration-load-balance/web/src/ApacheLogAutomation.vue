<script setup lang="ts">
import {computed,onBeforeUnmount,ref,watch} from "vue";
import {ElMessageBox} from "element-plus";
import {apacheAutomationDefaults,apacheAutomationStatus,sameApacheAutomationPolicy,type ApacheAutomationStatus} from "./apacheLogAutomation";
import {formatPanelDateTime} from "./panelTime";
type API=<T>(path:string,method?:string,body?:unknown,key?:string)=>Promise<T>;
const props=defineProps<{api:API;active:boolean;installed:boolean;version?:string;parentBusy:boolean}>();
const emit=defineEmits<{(event:"inventory-change"):void;(event:"blocked",value:boolean):void}>();
const applied=ref<ApacheAutomationStatus>(),draft=ref(apacheAutomationDefaults()),draftRevision=ref(0);
const reading=ref(false),writing=ref(false),confirming=ref(false),known=ref(false),uncertain=ref(false),error=ref(""),receipt=ref("");
let epoch=0,disposed=false,initialized=false,inventoryIdentity="";
const supported=computed(()=>props.installed&&props.version==="2.4.0");
const current=(ticket:number)=>!disposed&&props.active&&ticket===epoch;
const dirty=computed(()=>!!applied.value&&!sameApacheAutomationPolicy(draft.value,applied.value.policy));
const staleDraft=computed(()=>dirty.value&&applied.value?.policy_revision!==draftRevision.value);
const busy=computed(()=>reading.value||writing.value||confirming.value||props.parentBusy);
const unknownRotation=computed(()=>["rotating","unknown"].includes(applied.value?.record?.state||""));
const stateLabels:Record<string,string>={idle:"等待触发",rotating:"轮转结果待核对",completed:"已确认完成",blocked:"达到上限，已暂停",unknown:"结果未知，已暂停",retained_unknown:"已保留未知结果"};
const stateName=(value:string)=>stateLabels[value]||"状态未核实";
const errorLabels:Record<string,string>={archive_capacity:"8 个快照名额已满，请先导出并按摘要管理快照。",history_capacity:"未知结果历史达到上限，原证据已保留。",rotation_failed:"原轮转没有确认完成，禁止自动和手动重复截断。",verification_failed:"轮转后的完整摘要或完成索引未通过核对。"};
const errorName=(value?:string)=>errorLabels[value||""]||"";
function resetDraft(){if(!applied.value)return;draft.value={...applied.value.policy};draftRevision.value=applied.value.policy_revision;initialized=true;}
async function readStatus(explicit=false){
 if(!props.active||!supported.value||busy.value||uncertain.value&&!explicit)return;
 const ticket=epoch;reading.value=true;
 try{
  const result=await props.api<unknown>("/software/apache-waf/body-log/automatic");
  if(!current(ticket))return;
  if(!apacheAutomationStatus(result))throw Error("自动轮转配置、记录摘要或历史无法完整核实");
  applied.value=result;known.value=true;error.value="";if(explicit)uncertain.value=false;
  if(!initialized)resetDraft();
  const identity=JSON.stringify([result.record?.id,result.record?.state,result.record?.archive_count,result.record?.archive?.id]);
  if(inventoryIdentity&&inventoryIdentity!==identity)emit("inventory-change");
  inventoryIdentity=identity;
  emit("blocked",["rotating","unknown"].includes(result.record?.state||""));
 }catch(e){if(current(ticket)){known.value=false;emit("blocked",true);error.value=(e as Error).message;}}
 finally{if(current(ticket))reading.value=false;}
}
async function save(){
 if(busy.value||!known.value||uncertain.value||!dirty.value||staleDraft.value)return;
 const ticket=epoch,submitted={...draft.value},revision=draftRevision.value;
 writing.value=true;receipt.value="";error.value="";
 try{
  const result=await props.api<unknown>("/software/apache-waf/body-log/automatic/configure","POST",{expected_revision:revision,...submitted});
  if(!current(ticket))return;
  if(!apacheAutomationStatus(result)||!sameApacheAutomationPolicy(result.policy,submitted)||result.policy_revision!==revision+1)throw Error("保存回执与所选策略或修订不一致");
  applied.value=result;known.value=true;resetDraft();
  emit("blocked",["rotating","unknown"].includes(result.record?.state||""));
  receipt.value=submitted.enabled?"自动轮转策略已保存，执行器每分钟核查固定数值日志。":"自动轮转已停用，原快照、窗口和未知记录已保留。";
 }catch(e){if(current(ticket)){uncertain.value=true;known.value=false;emit("blocked",true);error.value="提交结果需核对："+(e as Error).message+"。请先读取原状态；本页不会自动重试。";}}
 finally{if(current(ticket))writing.value=false;}
}
async function retain(){
 const status=applied.value;
 if(!status?.record||!unknownRotation.value||busy.value||!known.value||uncertain.value)return;
 const ticket=epoch,id=status.record.id,digest=status.record_sha256,exact="RETAIN APACHE AUTO "+id;
 confirming.value=true;
 try{
  const answer=await ElMessageBox.prompt("保留原未知自动轮转证据，不重新截断，不将原结果改成成功。须先处理下方具体快照或索引的未完成记录。原记录 SHA-256："+digest+"。请输入："+exact,"保留自动轮转未知结果",{inputPlaceholder:exact,confirmButtonText:"按原摘要保留",cancelButtonText:"取消",closeOnClickModal:false,inputValidator:(value:string)=>value===exact||"请输入当前原记录的完整确认文本"});
  if(!current(ticket)||answer.value!==exact)return;
 }catch{return;}
 finally{if(current(ticket))confirming.value=false;}
 if(!current(ticket))return;
 writing.value=true;receipt.value="";error.value="";
 try{
  const result=await props.api<unknown>("/software/apache-waf/body-log/automatic/retain","POST",{sha256:digest,confirm_unknown:true});
  if(!current(ticket))return;
  if(!apacheAutomationStatus(result)||result.record?.id!==id||result.record.state!=="retained_unknown"||!result.record.history.some(h=>h.id===id&&h.outcome==="unknown_retained"))throw Error("原未知结果保留回执无法核实");
  applied.value=result;known.value=true;emit("blocked",false);emit("inventory-change");receipt.value="原未知结果已按摘要保留，未重做轮转或追认成功。";
 }catch(e){if(current(ticket)){known.value=false;uncertain.value=true;emit("blocked",true);error.value="保留结果需核对："+(e as Error).message+"。请读取原状态，不要重复提交。";}}
 finally{if(current(ticket))writing.value=false;}
}
watch(()=>[props.active,props.installed,props.version],()=>{epoch++;initialized=false;inventoryIdentity="";known.value=false;uncertain.value=false;reading.value=false;writing.value=false;confirming.value=false;applied.value=undefined;error.value="";receipt.value="";emit("blocked",true);if(props.active&&supported.value)void readStatus(true);},{immediate:true});
const timer=setInterval(()=>{void readStatus();},15000);
onBeforeUnmount(()=>{disposed=true;epoch++;clearInterval(timer);});
</script>
<template>
 <section class="apache-automation">
  <div class="automation-heading"><h4>自动轮转</h4><el-button :loading="reading" :disabled="!supported||writing||confirming||parentBusy" @click="readStatus(true)">读取原状态</el-button></div>
  <p>由面板执行器每分钟检查固定数值日志，默认关闭。大小或时间达到任一阈值且日志非空时保存快照；原 Apache 防护应用、站点策略和服务配置保持原值。</p>
  <el-alert v-if="error" type="error" :closable="false" :title="error"/>
  <el-alert v-if="receipt&&known" type="success" :closable="false" :title="receipt"/>
  <el-alert v-if="staleDraft" type="warning" :closable="false" title="服务器策略修订已变化，当前草稿已保留。请放弃草稿并读取实际配置后再编辑。"/>
  <template v-if="supported">
   <el-form label-position="top" class="automation-form" @submit.prevent="save">
    <el-form-item label="启用自动轮转"><el-switch v-model="draft.enabled" :disabled="busy||!known||uncertain" aria-label="Apache 数值日志自动轮转开关"/></el-form-item>
    <el-form-item label="文件大小触发（MiB）"><el-input-number v-model="draft.rotate_mib" :min="1" :max="28" :disabled="busy||!known||uncertain" aria-label="Apache 自动轮转大小阈值"/></el-form-item>
    <el-form-item label="非空日志轮转窗口（分钟）"><el-input-number v-model="draft.max_age_minutes" :min="10" :max="1440" :disabled="busy||!known||uncertain" aria-label="Apache 自动轮转时间阈值"/></el-form-item>
   </el-form>
   <div class="automation-actions"><el-button type="primary" :loading="writing" :disabled="busy||!known||uncertain||!dirty||staleDraft" @click="save">保存自动轮转策略</el-button><el-button :disabled="busy||!dirty||!known" @click="resetDraft">放弃草稿</el-button><span v-if="dirty">有未保存修改</span></div>
  </template>
  <template v-if="known&&applied">
   <p>已保存策略：{{applied.policy.enabled?'开启':'关闭'}} · {{applied.policy.rotate_mib}} MiB / {{applied.policy.max_age_minutes}} 分钟 · 修订 {{applied.policy_revision}}</p>
   <div v-if="applied.record" class="automation-status" role="status">
    <strong>{{stateName(applied.record.state)}}</strong>
    <span>最后检查：{{formatPanelDateTime(applied.record.checked_at)}}</span><span>轮转窗口起点：{{formatPanelDateTime(applied.record.window_started_at)}}</span>
    <span>上次核对日志：{{applied.record.log_bytes}} 字节 · 快照 {{applied.record.archive_count}} / 8</span>
    <span v-if="applied.record.last_rotation_at">最后完成：{{formatPanelDateTime(applied.record.last_rotation_at)}}</span>
    <p v-if="errorName(applied.record.error_code)">{{errorName(applied.record.error_code)}}</p>
    <p v-if="Date.now()-Date.parse(applied.record.checked_at)>180000&&applied.policy.enabled">超过三分钟没有新的检查记录，请核对执行器和原日志；未显示为正在正常调度。</p>
    <template v-if="unknownRotation"><code>{{applied.record.id}}</code><code>{{applied.record_sha256}}</code><el-button :disabled="busy||uncertain" @click="retain">按摘要保留未知自动轮转</el-button></template>
    <div v-if="applied.record.history.length" class="automation-history"><h5>最近轮转摘要</h5><article v-for="row in [...applied.record.history].reverse()" :key="row.id"><span>{{formatPanelDateTime(row.at)}} · {{row.outcome==='completed'?'已确认完成':'原未知结果已保留'}}</span><code>{{row.archive?.id||row.id}}</code><span v-if="row.archive">{{row.archive.bytes}} 字节</span></article></div>
   </div>
   <p v-else>尚未创建自动轮转记录。默认关闭状态的读取不创建调度文件。</p>
  </template>
  <p>最多 8 份快照，每份 32 MiB；历史摘要最多 16 条，未知证据不自动丢弃。满额、路径异常或结果未知时暂停，不自动删除历史。修改阈值、停用或重启执行器均保留原窗口和证据；定时刷新保留未保存草稿。</p>
 </section>
</template>
<style scoped>
.apache-automation{display:grid;gap:12px;border:1px solid #dce7e2;border-radius:10px;padding:16px;min-width:0}.apache-automation h4,.apache-automation h5,.apache-automation p{margin:0}.apache-automation p{line-height:1.7;color:#64748b}.automation-heading,.automation-actions{display:flex;align-items:center;gap:10px;flex-wrap:wrap;min-width:0}.automation-heading h4{margin-right:auto}.automation-form{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px}.automation-form .el-form-item{margin:0;min-width:0}.automation-status,.automation-history{display:grid;gap:8px;min-width:0}.automation-status code,.automation-history code{overflow-wrap:anywhere;white-space:normal;min-width:0}.automation-history article{display:grid;gap:4px;padding:8px 0;border-top:1px solid #e2e8f0}.automation-actions .el-button{margin:0}.automation-actions span,.automation-status span{color:#64748b;font-size:13px}@media(max-width:760px){.apache-automation{padding:12px}.automation-form{grid-template-columns:1fr}.automation-actions .el-button,.automation-status>.el-button{max-width:100%;height:auto;min-height:32px;white-space:normal}}
</style>
