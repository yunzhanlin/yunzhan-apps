<script setup lang="ts">
import { computed, onUnmounted, ref, watch } from "vue";
import { randomId } from "./randomId";
import { MemcachedUpdateIdentity, type MemcachedUpdateTicket } from "./memcachedUpdateIdentity";
type API = <T>(path: string, method?: string, body?: unknown, key?: string, signal?: AbortSignal) => Promise<T>;
interface Plan { project_id: string; project_sha256: string; current_image: string; runtime_image_id: string; target_image: string; host_port: number; container_id: string }
interface Status { project_id: string; request_id: string; job_id: string; state: string; state_known: boolean; expected_version: string; expected_sha256: string; version_recorded: boolean; detail: string }
const props = defineProps<{ api: API; actor: string }>();
const emit = defineEmits<{ changed: [] }>();
const visible = ref(false), busy = ref(false), checking = ref(false), accepted = ref(false), error = ref("");
const project = ref(""), version = ref(""), digest = ref("");
const instances = ref<{ id: string; version?: string }[]>([]), plan = ref<Plan>(), ticket = ref<MemcachedUpdateTicket>(), status = ref<Status>();
let generation = 0, abort = new AbortController(), timer: ReturnType<typeof setTimeout> | undefined;
const labels: Record<string, string> = { reserved: "已保留原请求", unknown: "结果尚不能确认", prepared: "已保存原配置", pull_started: "正在拉取固定镜像", image_verified: "镜像身份已核对", apply_started: "正在替换服务", applied: "新服务已健康", committed: "原事务已完成", rollback_started: "正在恢复原镜像", rolled_back: "已恢复原镜像", failed_safe: "未替换原服务", needs_attention: "需要处理原事务，禁止重发" };
const safeTerminal = computed(() => !!status.value?.state_known && ["committed", "rolled_back", "failed_safe"].includes(status.value.state));
const identity = () => new MemcachedUpdateIdentity(localStorage, props.actor, randomId);
function stopPoll() { if (timer) clearTimeout(timer); timer = undefined; }
function schedule(g: number) {
  stopPoll(); if (!visible.value || g !== generation || (!ticket.value && !status.value)) return;
  if (status.value?.state_known && (["rolled_back", "failed_safe", "needs_attention"].includes(status.value.state) || status.value.state === "committed" && status.value.version_recorded)) return;
  timer = setTimeout(() => { if (g === generation && visible.value && !busy.value && !checking.value) void observe(g); }, 5000);
}
function reset() { generation++; stopPoll(); abort.abort(); abort = new AbortController(); visible.value = false; busy.value = checking.value = false; plan.value = undefined; ticket.value = undefined; status.value = undefined; instances.value = []; project.value = version.value = digest.value = ""; error.value = ""; accepted.value = false; }
watch(() => props.actor, reset); watch(visible, value => { if (!value) stopPoll(); }); onUnmounted(() => { generation++; stopPoll(); abort.abort(); });
async function inspect() {
  const g = ++generation; abort.abort(); abort = new AbortController(); plan.value = undefined; status.value = undefined; ticket.value = undefined; accepted.value = false; error.value = ""; checking.value = true;
  try {
    ticket.value = identity().read(project.value);
    if (ticket.value) { await observe(g); return; }
    const prior = await props.api<Status[]>("/app-registry/memcached/updates", "GET", undefined, undefined, abort.signal);
    if (g !== generation) return;
    const active = prior.filter(s => s.project_id === project.value && !["committed", "rolled_back", "failed_safe"].includes(s.state));
    if (active.length > 1) throw new Error("原项目存在冲突记录，未创建新请求");
    if (active[0]) { status.value = active[0]; await observe(g); return; }
    const p = await props.api<Plan>(`/app-registry/memcached/instances/${project.value}/update-plan`, "GET", undefined, undefined, abort.signal);
    if (g !== generation) return;
    if (p.project_id !== project.value || !/^[a-f0-9]{64}$/.test(p.project_sha256)) throw new Error("原项目预检身份不一致");
    plan.value = p;
  } catch (e) { if (g === generation) error.value = e instanceof Error ? e.message : String(e); }
  finally { if (g === generation) { checking.value = false; schedule(g); } }
}
async function open(app: { version: string; sha256: string }, rows: { id: string; version?: string }[]) {
  reset(); version.value = app.version; digest.value = app.sha256; instances.value = rows.filter(s => /^[a-f0-9]{32}$/.test(s.id)); project.value = instances.value[0]?.id || ""; visible.value = true;
  if (project.value) await inspect(); else error.value = "没有可核对的已安装实例；不会自动安装新实例";
}
async function observe(g = generation) {
  const key = ticket.value?.key || status.value?.request_id, selected = project.value;
  if (!key) return;
  checking.value = true;
  try {
    const next = await props.api<Status>(`/app-registry/memcached/instances/${selected}/updates/${key}`, "GET", undefined, undefined, abort.signal);
    if (g !== generation) return;
    const original = ticket.value?.input;
    if (next.project_id !== selected || next.request_id !== key || original && (next.expected_version !== original.expected_version || next.expected_sha256 !== original.expected_sha256)) throw new Error("回复不属于原更新请求，保留原记录");
    status.value = next; error.value = ""; if (safeTerminal.value) emit("changed");
  } catch (e) { if (g === generation) error.value = `${e instanceof Error ? e.message : String(e)}。只保留并核对原请求，不重新提交。`; }
  finally { if (g === generation) { checking.value = false; schedule(g); } }
}
async function submit() {
  if (!plan.value || !accepted.value || ticket.value || status.value || busy.value) return;
  const g = generation; busy.value = true; error.value = "";
  try {
    const original = identity().begin(project.value, { expected_version: version.value, expected_sha256: digest.value, expected_project_sha256: plan.value.project_sha256, acknowledge_cache_loss: true });
    ticket.value = original;
    const next = await props.api<Status>(`/app-registry/memcached/instances/${project.value}/updates`, "POST", original.input, original.key, abort.signal);
    if (g !== generation) return;
    if (next.request_id !== original.key || next.project_id !== project.value || next.expected_version !== original.input.expected_version || next.expected_sha256 !== original.input.expected_sha256) throw new Error("提交回复身份不一致，保留原请求");
    status.value = next; await observe(g);
  } catch (e) { if (g === generation) error.value = `${e instanceof Error ? e.message : String(e)}。若已保留请求，只能核对原任务，不能重复提交。`; }
  finally { if (g === generation) { busy.value = false; schedule(g); } }
}
async function newInspection() {
  if (!safeTerminal.value || !status.value) return;
  try { if (ticket.value) identity().finish(project.value, ticket.value.key, status.value.state_known, status.value.state); await inspect(); }
  catch (e) { error.value = e instanceof Error ? e.message : String(e); }
}
defineExpose({ open });
</script>

<template>
  <el-dialog v-model="visible" title="Memcached · 逐实例安全更新" width="min(820px, 95vw)" :close-on-click-modal="false">
    <el-alert title="重建容器会中断缓存连接，缓存可能全部清空。原镜像保留不等于恢复原缓存。" type="warning" :closable="false" show-icon />
    <div class="mc-toolbar"><label for="mc-instance">已安装实例</label><el-select id="mc-instance" v-model="project" :disabled="busy || checking" @change="inspect"><el-option v-for="row in instances" :key="row.id" :value="row.id" :label="`${row.id.slice(0, 12)} · ${row.version || '版本待核对'}`" /></el-select></div>
    <el-alert v-if="error" :title="error" type="error" :closable="false" show-icon />
    <el-descriptions v-if="plan && !ticket && !status" :column="1" border>
      <el-descriptions-item label="目标版本">{{ version }}</el-descriptions-item>
      <el-descriptions-item label="原监听地址">127.0.0.1:{{ plan.host_port }}</el-descriptions-item>
      <el-descriptions-item label="当前镜像"><code>{{ plan.current_image }}</code></el-descriptions-item>
      <el-descriptions-item label="原镜像身份"><code>{{ plan.runtime_image_id }}</code></el-descriptions-item>
      <el-descriptions-item label="目标固定镜像"><code>{{ plan.target_image }}</code></el-descriptions-item>
    </el-descriptions>
    <section v-if="ticket || status" aria-live="polite" class="mc-status">
      <h3>{{ labels[status?.state || 'unknown'] || '状态待核对' }}</h3>
      <p>原请求：<code>{{ ticket?.key || status?.request_id }}</code></p>
      <p v-if="status?.job_id">原任务：<code>{{ status.job_id }}</code></p>
      <p>{{ status?.detail || '尚未取得可靠回复。关闭或刷新页面不会重新提交更新。' }}</p>
      <el-alert v-if="status?.state === 'committed'" :title="status.version_recorded ? '实际服务及新版本回执均已核对' : '原服务事务完成，面板版本回执仍待核对'" :type="status.version_recorded ? 'success' : 'warning'" :closable="false" />
      <p v-if="status && !status.state_known">本次状态未知，不代表原更新没有提交，也不代表已成功。</p>
    </section>
    <el-checkbox v-if="plan && !ticket && !status" v-model="accepted" class="mc-ack">我已安排维护窗口，明确接受连接中断和缓存可能全部清空，仅更新这个实例。</el-checkbox>
    <template #footer>
      <el-button @click="visible = false">关闭</el-button>
      <el-button v-if="ticket || status" :loading="checking" :disabled="busy" @click="observe()">只核对原任务</el-button>
      <el-button v-if="safeTerminal" :disabled="busy || checking" @click="newInspection">核对最新配置</el-button>
      <el-button v-if="!ticket && !status" type="primary" :loading="busy" :disabled="!plan || !accepted || checking" @click="submit">按本次预检更新</el-button>
    </template>
  </el-dialog>
</template>

<style scoped>
.mc-toolbar{display:flex;align-items:center;gap:16px;margin:20px 0}.mc-toolbar .el-select{flex:1}.mc-status{padding:12px 0}.mc-ack{margin:20px 0;white-space:normal;height:auto}code{word-break:break-all;white-space:normal}.el-descriptions{margin-top:18px}@media(max-width:600px){.mc-toolbar{align-items:stretch;flex-direction:column}.mc-toolbar .el-select{width:100%}}
</style>
