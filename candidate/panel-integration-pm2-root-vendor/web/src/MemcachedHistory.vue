<script setup lang="ts">
import { onUnmounted, ref, watch } from "vue";
type API = <T>(path: string, method?: string, body?: unknown, key?: string, signal?: AbortSignal) => Promise<T>;
interface RecordStatus { app_id: string; project_id: string; request_id: string; job_id: string; state: string; state_known: boolean; expected_version: string; expected_sha256: string; detail: string; version_recorded?: boolean }
interface Preview { project_id: string; project_sha256: string; current_image: string; target_image: string; already_pinned: boolean; host_port: number }
const props = defineProps<{ api: API; actor: string }>();
const visible = ref(false), loading = ref(false), checking = ref(false), error = ref("");
const projects = ref<string[]>([]), project = ref(""), records = ref<RecordStatus[]>([]), preview = ref<Preview>(), observed = ref<RecordStatus>();
let generation = 0, abort = new AbortController();
const labels: Record<string,string> = {reserved:"已保留",unknown:"待核对",prepared:"原配置已保存",pull_started:"已开始拉取",image_verified:"镜像已核对",apply_started:"已开始替换",applied:"新服务已健康",committed:"事务已完成",rollback_started:"已开始恢复",rolled_back:"已恢复原镜像",failed_safe:"未替换原服务",needs_attention:"原事务需要处理"};
function validRecord(value: RecordStatus) {
  return !!value && value.app_id === "memcached" && [value.project_id,value.request_id,value.job_id,value.expected_sha256,value.expected_version,value.state].every(item => typeof item === "string") && /^[a-f0-9]{32}$/.test(value.project_id) && /^[a-f0-9]{32}$/.test(value.request_id) && /^[a-f0-9]{32}$/.test(value.job_id) && /^[a-f0-9]{64}$/.test(value.expected_sha256) && /^\d+\.\d+\.\d+(?:[.-][a-z0-9]+)*$/.test(value.expected_version) && Object.hasOwn(labels,value.state) && typeof value.state_known === "boolean";
}
function reset() {
  generation++; abort.abort(); abort = new AbortController(); visible.value = false; loading.value = checking.value = false; error.value = ""; projects.value = []; project.value = ""; records.value = []; preview.value = undefined; observed.value = undefined;
}
watch(() => props.actor, reset); onUnmounted(reset);
async function inspect() {
  const g = generation, selected = project.value; preview.value = undefined;
  if (!projects.value.includes(selected) || !/^[a-f0-9]{32}$/.test(selected)) return;
  const value = await props.api<Preview>(`/app-registry/memcached/instances/${selected}/update-plan`, "GET", undefined, undefined, abort.signal);
  if (g !== generation) return;
  if (value.project_id !== selected || !/^[a-f0-9]{64}$/.test(value.project_sha256) || typeof value.already_pinned !== "boolean") throw new Error("原实例只读预检身份不能核对");
  preview.value = value;
}
async function load() {
  if (loading.value || checking.value) return;
  const g = ++generation; abort.abort(); abort = new AbortController(); loading.value = true; error.value = ""; observed.value = undefined; preview.value = undefined;
  try {
    const values = await props.api<RecordStatus[]>("/app-registry/memcached/updates", "GET", undefined, undefined, abort.signal);
    if (g !== generation) return;
    if (!Array.isArray(values) || values.length > 128 || values.some(value => !validRecord(value)) || new Set(values.map(value => value.request_id)).size !== values.length) throw new Error("原更新清单不完整或身份冲突，未采纳回复");
    records.value = values;
    await inspect();
  } catch (e) { if (g === generation) error.value = e instanceof Error ? e.message : String(e); }
  finally { if (g === generation) loading.value = false; }
}
async function open(rows: { id: string }[]) {
  reset(); projects.value = [...new Set(rows.filter(row => /^[a-f0-9]{32}$/.test(row.id)).map(row => row.id))]; project.value = projects.value[0] || ""; visible.value = true; await load();
}
async function observeRecord(original: RecordStatus) {
  if (loading.value || checking.value || !validRecord(original) || !records.value.some(row => row.request_id === original.request_id && row.project_id === original.project_id && row.job_id === original.job_id)) return;
  const g = generation; checking.value = true; observed.value = undefined; error.value = "";
  try {
    const value = await props.api<RecordStatus>(`/app-registry/memcached/instances/${original.project_id}/updates/${original.request_id}`, "GET", undefined, undefined, abort.signal);
    if (g !== generation) return;
    if (!validRecord(value) || value.project_id !== original.project_id || value.request_id !== original.request_id || value.job_id !== original.job_id || value.expected_version !== original.expected_version || value.expected_sha256 !== original.expected_sha256) throw new Error("回复不属于该原更新记录，未采纳回复");
    observed.value = value;
  } catch (e) { if (g === generation) error.value = `${e instanceof Error ? e.message : String(e)}。只核对该原记录，不提交或重发更新。`; }
  finally { if (g === generation) checking.value = false; }
}
defineExpose({open});
</script>
<template>
  <el-dialog v-model="visible" title="Memcached · 实例与原更新记录" width="min(960px, 96vw)" :close-on-click-modal="false">
    <el-alert title="此页只读：不安装、拉取或重建容器，不创建请求编号或版本回执。记录状态不是本次实时核对结果。" type="info" :closable="false" show-icon />
    <el-alert v-if="error" :title="error" type="error" :closable="false" show-icon />
    <div class="history-toolbar"><label for="mc-history-instance">当前已安装实例</label><el-select id="mc-history-instance" v-model="project" :disabled="loading || checking" @change="load"><el-option v-for="id in projects" :key="id" :label="id" :value="id" /></el-select><el-button :loading="loading" :disabled="checking" @click="load">只读刷新</el-button></div>
    <el-descriptions v-if="preview" :column="1" border><el-descriptions-item label="当前监听">127.0.0.1:{{preview.host_port}}</el-descriptions-item><el-descriptions-item label="实际镜像"><code>{{preview.current_image}}</code></el-descriptions-item><el-descriptions-item label="固定镜像核对">{{preview.already_pinned?'已使用目标固定镜像，无需重建':'尚未使用目标固定镜像；此页不会提交更新'}}</el-descriptions-item></el-descriptions>
    <h3>当前账户的原更新记录（非实时，不按时间排序）</h3>
    <el-table :data="records" empty-text="没有可核对的原更新记录；不会据此重发更新"><el-table-column prop="project_id" label="原实例" min-width="160"/><el-table-column prop="request_id" label="原请求编号" min-width="180"/><el-table-column label="记录状态" min-width="135"><template #default="{row}">{{labels[row.state] || '待核对'}}</template></el-table-column><el-table-column label="操作" width="135"><template #default="{row}"><el-button :disabled="loading || checking" @click="observeRecord(row)">只核对原任务</el-button></template></el-table-column></el-table>
    <section v-if="observed" aria-live="polite"><h3>本次原任务核对</h3><p>原请求：<code>{{observed.request_id}}</code> · 原任务：<code>{{observed.job_id}}</code></p><p>{{observed.detail}}</p><p>{{observed.state_known?labels[observed.state]:'本次原生状态无法确认；保留原记录，不重发'}}</p><p v-if="observed.state === 'committed'">{{observed.version_recorded?'对应版本回执已核对':'对应版本回执仍待核对'}}</p></section>
    <template #footer><el-button @click="visible=false">关闭</el-button></template>
  </el-dialog>
</template>
<style scoped>
.history-toolbar{display:flex;align-items:center;gap:12px;margin:18px 0}.history-toolbar .el-select{flex:1;min-width:0}.el-alert{margin:12px 0}code,p,:deep(.el-table .cell){overflow-wrap:anywhere}p{line-height:1.7}@media(max-width:640px){.history-toolbar{flex-direction:column;align-items:stretch}}
</style>
