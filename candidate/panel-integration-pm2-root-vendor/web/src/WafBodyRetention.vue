<script setup lang="ts">
import { onUnmounted, ref, watch } from "vue";
import { formatPanelDateTime } from "./panelTime";
type API = <T>(path:string,method?:string,body?:unknown,key?:string)=>Promise<T>;
interface Policy {enabled:boolean;days:number;keep_latest:number;confirm_delete_completed_snapshots:boolean}
interface Operation {plan:{id:string;at:string;days:number;keep_latest:number;selected:string[]};plan_sha256:string;state:string;verified_deleted:string[]}
interface Status {available:boolean;enabled:boolean;stale:boolean;sha256?:string;blocked_unknown?:boolean;blocked_retained_unknown?:boolean;retained_unknown_archive_ids?:string[];record?:{checked_at:string;policy_revision:number;operation?:Operation;history:Operation[]}}
const props=defineProps<{api:API;settings:{body_log_retention?:Policy;body?:{engine_job_id:string}};supported:boolean;active:boolean;parentBusy:boolean}>();
const emit=defineEmits<{"inventory-changed":[];"safety-state":[{blocked:boolean;unverified:boolean;busy:boolean}]}>();
const status=ref<Status>(),error=ref(""),saved=ref(""),loading=ref(false),reviewBusy=ref(false),acknowledge=ref(false);
let timer:ReturnType<typeof setTimeout>|undefined,disposed=false,generation=0,lastFingerprint="";
function safety(){emit("safety-state",{blocked:!!(status.value?.blocked_unknown||status.value?.blocked_retained_unknown),unverified:props.supported&&(!status.value||!!error.value),busy:reviewBusy.value});}
const label=(state?:string)=>({deleting:"清理中，结果尚未确认",completed:"所选快照删除已核对",unknown:"结果未知，自动清理已暂停",retained_unknown:"未知计划已保留，未宣称成功"}[state||""]||"尚无清理操作");
function toggle(value:string|number|boolean){
  if(!props.supported||props.parentBusy)return;
  props.settings.body_log_retention ||= {enabled:false,days:30,keep_latest:2,confirm_delete_completed_snapshots:false};
  props.settings.body_log_retention.enabled=value===true;
  props.settings.body_log_retention.confirm_delete_completed_snapshots=false;
}
function changePolicy(){if(props.settings.body_log_retention)props.settings.body_log_retention.confirm_delete_completed_snapshots=false;}
async function refresh(){
  if(disposed||!props.supported||!props.active||loading.value)return;
  loading.value=true;const current=generation;
  try{
    const result=await props.api<Status>("/software/nginx-waf/body-log/retention");
    if(disposed||current!==generation)return;
    // The record digest changes on minute checks even without a deletion. Only
    // operation/progress changes require another bounded inventory scan.
    const evidence=JSON.stringify([result.available,result.record?.operation,result.record?.history,result.retained_unknown_archive_ids]);
    if(evidence!==lastFingerprint){lastFingerprint=evidence;emit("inventory-changed");}
    if(status.value?.sha256!==result.sha256)acknowledge.value=false;
    status.value=result;error.value="";safety();
  }catch(e){if(!disposed&&current===generation){error.value=(e as Error).message;safety();}}
  finally{loading.value=false;}
}
function schedule(){
  if(timer)clearTimeout(timer);timer=undefined;
  if(disposed||!props.active||!props.supported)return;
  timer=setTimeout(async()=>{await refresh();schedule();},30000);
}
async function review(){
  if(!acknowledge.value||!status.value?.sha256||!status.value.blocked_unknown||reviewBusy.value||props.parentBusy||error.value)return;
  reviewBusy.value=true;error.value="";saved.value="";safety();
  try{
    await props.api("/software/nginx-waf/body-log/retention/retain","POST",{sha256:status.value.sha256,acknowledge_unknown_deletion_not_repeated:true},crypto.randomUUID().replaceAll("-",""));
    acknowledge.value=false;await refresh();emit("inventory-changed");
    saved.value="已保留原未知计划与部分进度；未重试删除、未改成成功，也没有改动当前日志。原计划仍有快照或索引时，后续自动清理继续暂停，需逐份导出并按摘要处理。";
  }catch(e){error.value=(e as Error).message;}finally{reviewBusy.value=false;safety();}
}
watch(()=>[props.active,props.supported],async()=>{generation++;safety();if(props.active&&props.supported)await refresh();schedule();},{immediate:true});
onUnmounted(()=>{disposed=true;generation++;if(timer)clearTimeout(timer);});
</script>

<template>
  <section aria-label="已完成请求体快照保留期">
    <h4>已完成快照保留期清理</h4>
    <el-alert v-if="!supported" title="升级到 Nginx WAF 2.5.1 后才能配置；默认关闭，升级不自动删除任何快照。" type="info" :closable="false"/>
    <el-form label-position="top" class="waf-three">
      <el-form-item label="启用保留期清理（默认关闭）"><el-switch :model-value="settings.body_log_retention?.enabled || false" :disabled="!supported || parentBusy || !settings.body?.engine_job_id" aria-label="启用已完成快照保留期清理" @change="toggle"/></el-form-item>
      <el-form-item v-if="settings.body_log_retention" label="保留期（天）"><el-input-number v-model="settings.body_log_retention.days" :min="1" :max="365" :disabled="!supported || parentBusy" aria-label="已完成快照保留天数" @change="changePolicy"/></el-form-item>
      <el-form-item v-if="settings.body_log_retention" label="始终保留最近几份"><el-input-number v-model="settings.body_log_retention.keep_latest" :min="1" :max="7" :disabled="!supported || parentBusy" aria-label="始终保留的最近快照份数" @change="changePolicy"/></el-form-item>
    </el-form>
    <el-checkbox v-if="settings.body_log_retention?.enabled" v-model="settings.body_log_retention.confirm_delete_completed_snapshots" :disabled="!supported || parentBusy">确认保存后自动永久删除超过保留期、未受保护且摘要核对通过的已完成快照</el-checkbox>
    <p>设置仅为草稿，需使用工作区“保存并应用”才生效。每分钟检查；至少保留最近一份，未知、缺失、不完整或损坏的快照不会自动删除。当前日志、Nginx 普通访问/错误日志不在清理范围，不发送信号或重载 Nginx。</p>
    <div v-if="supported" class="waf-actions"><span>服务器实际策略：{{error ? '尚未核验' : status ? status.enabled ? '已启用' : '未启用' : '尚未读取'}} · {{label(status?.record?.operation?.state)}}</span><el-button :loading="loading" :disabled="reviewBusy" @click="refresh">刷新快照清理状态</el-button></div>
    <el-alert v-if="error" :title="error+'；状态未核验，不能当成清理成功。'" type="error" :closable="false"/>
    <el-alert v-if="saved" :title="saved" type="info" :closable="false"/>
    <el-alert v-if="status?.stale" title="检查记录过期或策略修订变化，不能宣称自动清理正在正常运行。" type="warning" :closable="false"/>
    <el-alert v-if="status?.blocked_retained_unknown" title="已保留的未知计划仍有原快照或索引：后续自动清理继续暂停，绝不通过新计划重复删除。请逐份导出并按摘要处理残件；原未知结果仍不会标成成功。" type="warning" :closable="false"/>
    <p v-if="status?.blocked_retained_unknown">保留中的原快照：{{status.retained_unknown_archive_ids?.join('、')}}</p>
    <el-descriptions v-if="status?.record" :column="2" border><el-descriptions-item label="最近检查">{{formatPanelDateTime(status.record.checked_at)}}</el-descriptions-item><el-descriptions-item label="实际策略修订">{{status.record.policy_revision}}</el-descriptions-item></el-descriptions>
    <template v-if="status?.record?.operation">
      <p>原操作 {{status.record.operation.plan.id}} · 已核对删除 {{status.record.operation.verified_deleted.length}} / 原计划 {{status.record.operation.plan.selected.length}} 份 · {{label(status.record.operation.state)}}</p>
      <p>计划 SHA-256：<code>{{status.record.operation.plan_sha256}}</code></p>
    </template>
    <template v-if="status?.blocked_unknown">
      <el-alert title="原删除计划结果仍未知。核对只保留原计划与部分进度，不重试删除或变成成功；未完成的具体快照事务需另行按摘要处理。" type="warning" :closable="false"/>
      <el-checkbox v-model="acknowledge" :disabled="reviewBusy || parentBusy">确认原删除结果仍未知，仅保留原计划，绝不自动重试原删除操作</el-checkbox>
      <el-button :loading="reviewBusy" :disabled="!acknowledge || parentBusy || !!error || !status.sha256" @click="review">按摘要保留未知清理计划</el-button>
    </template>
    <el-table v-if="status?.record?.history.length" :data="status.record.history" max-height="200"><el-table-column label="计划时间" min-width="160"><template #default="{row}">{{formatPanelDateTime(row.plan.at)}}</template></el-table-column><el-table-column label="原操作" min-width="220"><template #default="{row}">{{row.plan.id}}</template></el-table-column><el-table-column label="结果" min-width="180"><template #default="{row}">{{label(row.state)}}</template></el-table-column><el-table-column label="已核对删除 / 原计划" min-width="150"><template #default="{row}">{{row.verified_deleted.length}} / {{row.plan.selected.length}}</template></el-table-column></el-table>
    <p>最多保留 16 条历史计划；旧的已完成摘要可滚动替换，未知计划不会自动丢弃。未知记录满额时停止新删除，保留原证据。</p>
  </section>
</template>

<style scoped>
section{margin-block:24px;padding:16px;border:1px solid var(--el-border-color);border-radius:8px}
.waf-three{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:16px}
.waf-actions{display:flex;flex-wrap:wrap;align-items:center;gap:12px;margin-block:12px}
p{line-height:1.6;overflow-wrap:anywhere}code{word-break:break-all}
:deep(.el-alert){margin-block:10px}:deep(.el-checkbox){height:auto;white-space:normal;line-height:1.6;margin-block:10px}
:deep(.el-checkbox__label){white-space:normal}
@media(max-width:720px){.waf-three{grid-template-columns:1fr}section{padding:12px}}
</style>
