<script setup lang="ts">
import { computed, onBeforeUnmount, ref, shallowRef, watch } from "vue";
import { randomId } from "./randomId";
import {
  parseStreamTicket, streamBasePath, streamEntry, streamEntryFingerprint, streamFullAdmin,
  streamHistory, streamMutation, streamRow, streamTicket, streamTicketKey,
  streamVersion, streamWorkspace, type StreamEntry, type StreamHistory,
  type StreamMutation, type StreamPolicy, type StreamRow, type StreamTicket, type StreamWorkspace,
} from "./loadBalanceStream";

type API = <T>(path: string, method?: string, body?: unknown, idempotencyKey?: string, signal?: AbortSignal) => Promise<T>;
const props = defineProps<{ api: API; actor: string; access?: unknown; active: boolean; installed: boolean; installedVersion: string }>();
const workspace = shallowRef<StreamWorkspace>();
// A prior completed transaction is historical evidence, not a live snapshot.
// Require a successful explicit read after learning that original terminal ID;
// another administrator may legitimately have advanced the live generation.
const workspaceReadFor = ref<string>();
const history = shallowRef<StreamHistory>();
const current = shallowRef<StreamRow>(), selected = shallowRef<StreamRow>(), ticket = shallowRef<StreamTicket>();
const error = ref(""), notice = ref(""), storageError = ref(""), reading = ref(false), writing = ref(false);
const editorAction = ref<StreamMutation["action"]>("create"), name = ref("");
const originalEntry = shallowRef<StreamEntry>();
function emptyPolicy(): StreamPolicy {
  return { protocol: "tcp", port: 42000, nodes: [{ address: "", weight: 1, backup: false }, { address: "", weight: 1, backup: false }], method: "round-robin", connect_milliseconds: 2000, session_seconds: 30, max_sessions: 64, udp_requests: 0, udp_responses: 0 };
}
const policy = ref<StreamPolicy>(emptyPolicy());
let epoch = 0, pollCount = 0, timer: ReturnType<typeof setTimeout> | undefined;
const controllers = new Set<AbortController>();
const allowed = computed(() => props.active && streamFullAdmin(props.access, props.actor));
const pending = computed(() => !!ticket.value && (!current.value || current.value.state !== "completed"));
const writable = computed(() => allowed.value && props.installed && props.installedVersion === streamVersion && workspace.value?.available === true
  && ["empty", "running", "stopped", "cold-boot-ready"].includes(workspace.value.state) && workspace.value.generation < 128 && !!history.value
  && !history.value.rows.some(row => row.state !== "completed") && !pending.value && !storageError.value && !writing.value && !reading.value
  && (!ticket.value || (current.value?.state === "completed" && workspaceReadFor.value === ticket.value.request_id)));
const stateNames: Record<string, string> = { unavailable: "尚不可用", empty: "尚无原生配置", "busy-or-unknown": "有事务占用或状态未确定", unknown: "无法核对", degraded: "配置或资源核对异常", "cold-boot-ready": "重启后待恢复", running: "运行配置核验通过", stopped: "已停止且配置核验通过" };
const rowNames: Record<string, string> = { reserved: "原请求已保留，尚未派发", issued: "原请求已派发，等待持久结果", unknown: "结果不确定，禁止重新派发", completed: "原请求已结束" };
const actionNames = { create: "新建入口", replace: "替换入口配置", remove: "移除入口" };
function amount(value: number): string { return `${(value / 1024 / 1024).toFixed(1)} MiB`; }
function message(cause: unknown): string { return cause instanceof Error ? cause.message : "查询失败，没有执行新操作"; }
function live(e: number, actor: string): boolean { return epoch === e && props.actor === actor && allowed.value; }
function cancel() {
  epoch++;
  if (timer) clearTimeout(timer);
  timer = undefined;
  for (const c of controllers) c.abort();
  controllers.clear();
  reading.value = writing.value = false;
}
function resetEditor() { editorAction.value = "create"; name.value = ""; originalEntry.value = undefined; policy.value = emptyPolicy(); }
function saveTicket(value: StreamTicket) {
  const raw = JSON.stringify(value), key = streamTicketKey(value.actor_id);
  localStorage.setItem(key, raw);
  if (localStorage.getItem(key) !== raw) throw new Error("无法持久保存原请求编号；未提交新操作");
  ticket.value = value;
  storageError.value = "";
}
function loadTicket() {
  try {
    const raw = localStorage.getItem(streamTicketKey(props.actor));
    ticket.value = raw === null ? undefined : parseStreamTicket(JSON.parse(raw), props.actor);
  } catch {
    storageError.value = "本地原请求索引无法核对或存储不可用。仍可查询本人历史，不会覆盖索引或重新提交操作。";
  }
}
async function readAPI(path: string, e: number, actor: string): Promise<unknown> {
  const c = new AbortController(); controllers.add(c);
  try {
    const raw = await props.api<unknown>(path, "GET", undefined, undefined, c.signal);
    if (!live(e, actor) || c.signal.aborted) throw new Error("查询身份已改变");
    return raw;
  } finally { controllers.delete(c); }
}
function schedule(e: number, actor: string) {
  if (timer) clearTimeout(timer);
  timer = undefined;
  // Only bounded GET observations of an already saved original identity.
  if (live(e, actor) && ticket.value && current.value && ["reserved", "issued"].includes(current.value.state) && pollCount++ < 320) {
    timer = setTimeout(() => { void observeOriginal(); }, 2500);
  }
}
async function observeOriginal() {
  if (!allowed.value || !ticket.value || writing.value || reading.value) return;
  const e = epoch, actor = props.actor, saved = ticket.value;
  reading.value = true;
  try {
    const row = streamRow(await readAPI(`${streamBasePath}/controls/${saved.request_id}`, e, actor), actor, saved);
    if (!live(e, actor)) return;
    current.value = row; selected.value = row; error.value = "";
    if (history.value) history.value = { ...history.value, rows: history.value.rows.map(old => old.operation.request_id === row.operation.request_id ? row : old) };
    if (row.state === "completed") {
      notice.value = row.result?.state === "committed" ? "原事务的持久结果已核对；这不代表业务上游健康。请刷新当前配置观察。" : "原请求在派发前已关闭，没有执行该变更。";
      resetEditor();
    }
  } catch (cause) {
    if (live(e, actor)) error.value = `原编号已保留：${message(cause)}。只读核对失败不会建立新编号或重发操作。`;
  } finally {
    if (live(e, actor)) { reading.value = false; schedule(e, actor); }
  }
}
async function refresh(offset = 0) {
  if (!allowed.value || reading.value || writing.value) return;
  const e = epoch, actor = props.actor;
  const completedBeforeRead = current.value?.state === "completed" ? current.value.operation.request_id : undefined;
  if (timer) clearTimeout(timer);
  reading.value = true; error.value = "";
  try {
    // Never keep a previous successful live configuration after a failed read.
    workspace.value = undefined; workspaceReadFor.value = undefined;
    try {
      workspace.value = streamWorkspace(await readAPI(`${streamBasePath}/workspace`, e, actor));
      workspaceReadFor.value = completedBeforeRead;
    }
    catch (cause) { if (live(e, actor)) error.value = message(cause); }
    if (!live(e, actor)) return;
    history.value = undefined;
    const page = streamHistory(await readAPI(`${streamBasePath}/controls${offset ? `?offset=${offset}` : ""}`, e, actor), actor, offset);
    if (!live(e, actor)) return;
    history.value = page;
    const active = page.rows.find(row => row.state !== "completed");
    if (!ticket.value && active && !storageError.value) {
      try { saveTicket(streamTicket(actor, active.operation.request_id, active.operation.mutation)); }
      catch { storageError.value = "无法保存从本人历史恢复的原编号；没有提交新操作。"; }
    }
    if (!ticket.value) selected.value = page.rows[0];
  } catch (cause) { if (live(e, actor)) error.value = message(cause); }
  finally { if (live(e, actor)) reading.value = false; }
  if (live(e, actor) && ticket.value) await observeOriginal();
}
function edit(entry?: StreamEntry, remove = false) {
  if (!writable.value) return;
  resetEditor(); notice.value = "";
  if (!entry) return;
  originalEntry.value = streamEntry(entry);
  editorAction.value = remove ? "remove" : "replace"; name.value = entry.name;
  policy.value = { protocol: entry.protocol, port: entry.port, nodes: entry.nodes.map(n => ({ ...n })), method: entry.method, connect_milliseconds: entry.connect_milliseconds, session_seconds: entry.session_seconds, max_sessions: entry.max_sessions, udp_requests: entry.udp_requests, udp_responses: entry.udp_responses };
}
function changeProtocol() { policy.value.udp_requests = policy.value.protocol === "udp" ? 1 : 0; policy.value.udp_responses = 0; }
async function submit() {
  if (!writable.value) return;
  const e = epoch, actor = props.actor;
  let mutation: StreamMutation;
  try {
    const old = originalEntry.value;
    mutation = streamMutation({ format: 1, action: editorAction.value, name: name.value, expected_revision: old?.revision ?? 0, expected_fingerprint: old ? streamEntryFingerprint(old) : "", policy: editorAction.value === "remove" ? null : policy.value });
    const id = randomId().replaceAll("-", "");
    saveTicket(streamTicket(actor, id, mutation)); // Required BEFORE the one POST.
  } catch (cause) { error.value = message(cause); return; }
  const saved = ticket.value!;
  writing.value = true; current.value = selected.value = undefined; notice.value = ""; error.value = ""; pollCount = 0;
  const c = new AbortController(); controllers.add(c);
  try {
    const row = streamRow(await props.api<unknown>(`${streamBasePath}/controls/${saved.request_id}`, "POST", mutation, saved.request_id, c.signal), actor, saved);
    if (!live(e, actor) || c.signal.aborted) return;
    current.value = selected.value = row;
  } catch (cause) {
    if (live(e, actor)) notice.value = `提交响应未能核对：${message(cause)}。已保存原编号；接下来只查询该编号，不重发。`;
  } finally { controllers.delete(c); if (live(e, actor)) writing.value = false; }
  if (live(e, actor)) await observeOriginal();
}
async function closeReserved() {
  if (!allowed.value || reading.value || writing.value || !ticket.value || current.value?.state !== "reserved") return;
  const e = epoch, actor = props.actor, saved = ticket.value;
  writing.value = true;
  const c = new AbortController(); controllers.add(c);
  try {
    const row = streamRow(await props.api<unknown>(`${streamBasePath}/controls/${saved.request_id}/close`, "POST", {}, saved.request_id, c.signal), actor, saved);
    if (!live(e, actor) || c.signal.aborted) return;
    current.value = selected.value = row;
  } catch (cause) { if (live(e, actor)) notice.value = `关闭响应未核对：${message(cause)}。不会重复关闭或声称已撤销。`; }
  finally { controllers.delete(c); if (live(e, actor)) writing.value = false; }
  if (live(e, actor)) await observeOriginal();
}
function recoverIndex() {
  if (!allowed.value || reading.value || writing.value || !history.value) return;
  const row = history.value.rows.find(r => r.state !== "completed") ?? history.value.rows[0];
  if (!row) { error.value = "本人历史中没有可核对的原请求，不能用空历史抹去未知索引。"; return; }
  try { saveTicket(streamTicket(props.actor, row.operation.request_id, row.operation.mutation)); current.value = selected.value = row; void observeOriginal(); }
  catch (cause) { error.value = message(cause); }
}
watch(() => [props.active, props.actor, props.installed, props.installedVersion, JSON.stringify(props.access)], () => {
  cancel(); workspace.value = history.value = undefined; workspaceReadFor.value = undefined; current.value = selected.value = undefined; ticket.value = undefined;
  error.value = notice.value = storageError.value = ""; pollCount = 0; resetEditor();
  if (allowed.value) { loadTicket(); void refresh(); }
}, { immediate: true, flush: "sync" });
onBeforeUnmount(cancel);
</script>

<template>
  <section class="lb-stream" aria-label="原生 TCP UDP 负载均衡">
    <el-alert v-if="!allowed" title="TCP/UDP 配置包含主机策略，仅当前完整主机管理员可以查看；账号或权限变化后已清除本页私有数据。" type="warning" :closable="false" />
    <template v-else>
      <div class="stream-heading"><div><h3>TCP / UDP 入口</h3><p>独立原生控制器 · 配置核验、原请求结果与业务健康分别显示</p></div><el-button :loading="reading" :disabled="writing" @click="refresh()">只读刷新配置与历史</el-button></div>
      <el-alert title="当前原生入口只绑定 127.0.0.1，不是公网入口；运行配置核验通过不等于后端连通、流量均衡或业务健康。公网接入仍需独立隔离与实流验收。" type="warning" :closable="false" />
      <el-alert v-if="!installed || installedVersion !== streamVersion" :title="`TCP/UDP 变更需要明确安装并验收独立签名版本 ${streamVersion}；当前为 ${installed ? installedVersion || '版本未知' : '未安装'}。此页面不会自动安装、升级或启用。`" type="info" :closable="false" />
      <el-alert v-if="error" :title="error" type="error" :closable="false" role="alert" />
      <el-alert v-if="notice" :title="notice" type="info" :closable="false" />
      <el-alert v-if="workspace?.state === 'cold-boot-ready'" title="服务器已重启。选择入口并确认配置后提交，将恢复原有未移除入口并应用本次变更。已移除入口仅在你明确选择恢复并提交后重新启用。" type="warning" :closable="false" />
      <el-alert v-if="storageError" :title="storageError" type="error" :closable="false" />
      <el-button v-if="storageError && history" :disabled="reading || writing" @click="recoverIndex">从本人历史恢复本地索引（只读）</el-button>
      <div v-if="workspace" class="stream-summary" aria-label="当前原生配置观察">
        <dl><dt>配置观察</dt><dd>{{ stateNames[workspace.state] }}</dd><dt>当前代次</dt><dd>{{ workspace.generation }}</dd><dt>可用主机内存（查询时）</dt><dd>{{ amount(workspace.available_memory_bytes) }}</dd><dt>服务内存 High / Max</dt><dd>{{ amount(workspace.memory_high_bytes) }} / {{ amount(workspace.memory_max_bytes) }}</dd><dt>排空中的旧工作进程</dt><dd>{{ workspace.retiring_workers }} / 1</dd></dl>
        <p>{{ workspace.detail }}</p><p v-if="workspace.configuration_sha256" class="stream-digest">配置 SHA-256：{{ workspace.configuration_sha256 }}</p>
      </div>
      <p v-else>尚无可核对的当前配置；不会沿用上一次成功查询作为当前状态。</p>
      <h4>当前入口与保留记录</h4>
      <div v-if="workspace?.entries.length" class="stream-table"><table aria-label="当前入口与保留记录">
        <thead><tr><th scope="col">入口标识</th><th scope="col">监听</th><th scope="col">修订</th><th scope="col">记录状态</th><th scope="col">操作</th></tr></thead>
        <tbody><tr v-for="row in workspace.entries" :key="row.name">
          <td data-label="入口标识">{{ row.name }}</td><td data-label="监听">127.0.0.1:{{ row.port }} / {{ row.protocol.toUpperCase() }}</td><td data-label="修订">{{ row.revision }}</td><td data-label="记录状态">{{ row.removed ? '已移除 · 保留指纹' : '配置中' }}</td>
          <td data-label="操作"><div class="stream-actions"><el-button :disabled="!writable" @click="edit(row)">{{ row.removed || workspace.state === 'cold-boot-ready' ? '选择恢复' : '选择编辑' }}</el-button><el-button v-if="!row.removed" type="danger" plain :disabled="!writable" @click="edit(row, true)">选择移除</el-button></div></td>
        </tr></tbody>
      </table></div><p v-else>没有当前入口记录。</p>
      <el-button :disabled="!writable" @click="edit()">填写新入口</el-button>
      <el-form label-position="top" class="stream-editor" @submit.prevent="submit">
        <h4>{{ actionNames[editorAction] }}</h4><p v-if="originalEntry">依据原修订 {{ originalEntry.revision }} 和完整配置指纹提交；若服务端已变更，将拒绝覆盖。</p>
        <el-form-item label="入口名称（小写域名式标识）"><el-input v-model="name" aria-label="TCP UDP 入口名称" :disabled="!writable || editorAction !== 'create'" placeholder="service.example.test" maxlength="253" /></el-form-item>
        <el-alert v-if="editorAction === 'remove'" :title="`将移除 ${name} 的监听配置。原记录保留；已有连接按原排空期限处理，不会强制杀死进程。`" type="warning" :closable="false" />
        <template v-else>
          <div class="stream-fields">
            <el-form-item label="传输协议"><select v-model="policy.protocol" class="stream-select" aria-label="传输协议" :disabled="!writable" @change="changeProtocol"><option value="tcp">TCP</option><option value="udp">UDP</option></select></el-form-item>
            <el-form-item label="回环监听端口（20000–60000）"><el-input-number v-model="policy.port" aria-label="回环监听端口" :min="20000" :max="60000" :disabled="!writable" /></el-form-item>
            <el-form-item label="均衡方式"><select v-model="policy.method" class="stream-select" aria-label="均衡方式" :disabled="!writable"><option value="round-robin">加权轮询</option><option value="least-connections">最少连接</option><option value="source-ip" :disabled="policy.nodes.some(node => node.backup)">来源 IP（不支持备用节点）</option></select></el-form-item>
          </div>
          <h4>后端节点（2–16 个，至少一个主节点）</h4><p>只接受明确 IP 和端口；节点 IP 仅用于受限出站，不代表探活成功。</p>
          <div v-for="(node, index) in policy.nodes" :key="index" class="stream-node">
            <el-form-item :label="`节点 ${index + 1} IP:端口`"><el-input v-model="node.address" :aria-label="`后端节点 ${index + 1}`" :disabled="!writable" placeholder="192.0.2.10:41001 或 [2001:db8::10]:41001" maxlength="80" /></el-form-item>
            <el-form-item label="权重"><el-input-number v-model="node.weight" :aria-label="`节点 ${index + 1} 权重`" :min="1" :max="100" :disabled="!writable" /></el-form-item>
            <el-form-item label="备用节点"><el-switch v-model="node.backup" :aria-label="`节点 ${index + 1} 备用`" :disabled="!writable || policy.method === 'source-ip'" /></el-form-item>
            <el-button type="danger" plain :aria-label="`删除节点 ${index + 1}`" :disabled="!writable || policy.nodes.length <= 2" @click="policy.nodes.splice(index, 1)">删除</el-button>
          </div>
          <el-button :disabled="!writable || policy.nodes.length >= 16" @click="policy.nodes.push({ address: '', weight: 1, backup: false })">添加后端节点</el-button>
          <div class="stream-fields"><el-form-item label="连接超时（毫秒）"><el-input-number v-model="policy.connect_milliseconds" aria-label="连接超时" :min="500" :max="5000" :disabled="!writable" /></el-form-item><el-form-item label="会话超时（秒）"><el-input-number v-model="policy.session_seconds" aria-label="会话超时" :min="2" :max="600" :disabled="!writable" /></el-form-item><el-form-item label="最大并发会话"><el-input-number v-model="policy.max_sessions" aria-label="最大并发会话" :min="16" :max="512" :disabled="!writable" /></el-form-item></div>
          <div v-if="policy.protocol === 'udp'" class="stream-fields"><el-form-item label="每会话请求数"><el-input-number v-model="policy.udp_requests" aria-label="UDP 请求数" :min="1" :max="64" :disabled="!writable" /></el-form-item><el-form-item label="预期响应数（0 表示不等待响应）"><el-input-number v-model="policy.udp_responses" aria-label="UDP 响应数" :min="0" :max="64" :disabled="!writable" /></el-form-item></div>
          <p>探针端口、系统账号、进程和渲染路径均由受限服务端分配，浏览器不提交。会话缓冲、完整配置端口冲突与内存余量由服务端重新检查。</p>
        </template>
        <el-button type="primary" native-type="submit" :loading="writing" :disabled="!writable">{{ workspace?.state === 'cold-boot-ready' ? (editorAction === 'remove' ? '恢复其余入口并移除此入口' : '恢复并应用配置') : (editorAction === 'remove' ? '提交移除原入口' : '提交配置变更') }}</el-button>
      </el-form>
      <section class="stream-original" aria-label="原始控制请求">
        <h4>原请求结果</h4><template v-if="ticket"><p class="stream-digest">原编号：{{ ticket.request_id }}</p><p>{{ current ? rowNames[current.state] : '尚未核对原持久记录；禁止重新提交或建立新编号' }}</p><el-button :disabled="reading || writing" @click="pollCount = 0; observeOriginal()">只读核对原请求</el-button><el-button v-if="current?.state === 'reserved'" :disabled="reading || writing" @click="closeReserved">关闭未派发的原请求</el-button></template><p v-else>没有本地原请求索引。刷新时仅查询本人服务器历史，不自动提交。</p>
        <p>已派发或不确定的请求不能由浏览器伪装为撤销；请求结束也不是当前服务健康证明。</p>
      </section>
      <h4>本人历史（只读，不恢复授权或执行）</h4>
      <div v-if="history?.rows.length" class="stream-table"><table aria-label="本人只读请求历史">
        <thead><tr><th scope="col">建立时间（UTC）</th><th scope="col">入口</th><th scope="col">动作</th><th scope="col">记录状态</th><th scope="col">详情</th></tr></thead>
        <tbody><tr v-for="row in history.rows" :key="row.operation.request_id"><td data-label="建立时间（UTC）">{{ row.created_at }}</td><td data-label="入口">{{ row.operation.mutation.name }}</td><td data-label="动作">{{ actionNames[row.operation.mutation.action] }}</td><td data-label="记录状态">{{ rowNames[row.state] }}</td><td data-label="详情"><el-button @click="selected = row">查看记录</el-button></td></tr></tbody>
      </table></div>
      <p v-else>{{ history ? '本人尚无历史记录。' : '本人历史尚未核对；变更提交保持禁用。' }}</p>
      <div v-if="history" class="stream-pagination"><span>本次观察共 {{ history.total }} 条，每页最多 32 条；翻页不是跨页快照。</span><el-button :disabled="reading || writing || history.offset === 0" @click="refresh(Math.max(0, history.offset - 32))">上一页</el-button><el-button :disabled="reading || writing || history.next_offset === null" @click="refresh(history.next_offset ?? 0)">下一页</el-button></div>
      <div v-if="selected" class="stream-record"><p class="stream-digest">历史原编号：{{ selected.operation.request_id }}</p><p>{{ rowNames[selected.state] }} · {{ selected.result?.state === 'committed' ? '原配置事务已提交（历史结果）' : selected.result?.state === 'refused-before-issue' ? '派发前关闭，无变更' : selected.result?.state === 'refused-before-effects' ? '执行器预检拒绝，未修改配置或服务' : '暂无完整终态结果' }}</p><p class="stream-digest">签名应用清单摘要：{{ selected.manifest_sha256 }}</p><pre>{{ JSON.stringify(selected.operation.mutation, null, 2) }}</pre><p v-if="selected.result" class="stream-digest">原操作摘要：{{ selected.result.operation_sha256 }}</p></div>
    </template>
  </section>
</template>

<style scoped>
.lb-stream { min-width: 0; color: var(--el-text-color-primary); }
.lb-stream :deep(.el-alert) { margin: 12px 0; }
.stream-heading { display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 12px; }
.stream-heading h3 { margin-bottom: 6px; }.stream-heading p,.stream-digest { color: var(--el-text-color-secondary); }
.stream-summary,.stream-editor,.stream-original,.stream-record { margin: 16px 0; padding: 16px; border: 1px solid var(--el-border-color); border-radius: 8px; min-width: 0; }
.stream-summary dl { display: grid; grid-template-columns: minmax(130px, 1fr) minmax(140px, 2fr); gap: 10px; }.stream-summary dd { margin: 0; }
.stream-fields { display: grid; grid-template-columns: repeat(3,minmax(0,1fr)); gap: 16px; margin-top: 16px; }.stream-fields :deep(.el-input-number) { width: 100%; }
/* Fixed native controls avoid resize-observer/popover feedback on narrow panes. */
.stream-select { width: 100%; min-width: 0; height: 32px; padding: 0 10px; border: 1px solid var(--el-border-color); border-radius: var(--el-border-radius-base); background: var(--el-fill-color-blank); color: var(--el-text-color-regular); font: inherit; box-sizing: border-box; }
.stream-select:focus-visible { outline: 2px solid var(--el-color-primary); outline-offset: 2px; }.stream-select:disabled { background: var(--el-disabled-bg-color); color: var(--el-disabled-text-color); cursor: not-allowed; }
.stream-node { display: grid; grid-template-columns: minmax(200px,1fr) 145px 90px auto; gap: 12px; align-items: center; }
.stream-pagination { display: flex; align-items: center; flex-wrap: wrap; gap: 10px; margin: 12px 0; }
.stream-table { margin: 12px 0; }.stream-table table { width: 100%; border-collapse: collapse; table-layout: fixed; }.stream-table th,.stream-table td { padding: 12px; text-align: left; border-bottom: 1px solid var(--el-border-color-lighter); overflow-wrap: anywhere; }.stream-table th { color: var(--el-text-color-secondary); font-weight: 500; }.stream-actions { display: flex; flex-wrap: wrap; gap: 8px; }.stream-actions :deep(.el-button + .el-button) { margin-left: 0; }
.stream-digest { overflow-wrap: anywhere; font-size: 13px; }.stream-record pre { white-space: pre-wrap; overflow-wrap: anywhere; font-size: 12px; }
@media(max-width:700px) { .stream-fields { grid-template-columns: 1fr; }.stream-node { grid-template-columns: minmax(0,1fr) 120px; }.stream-node :deep(.el-input-number) { width: 100%; }.stream-summary dl { grid-template-columns: 1fr; }.stream-summary dd { margin-bottom: 8px; }.stream-editor { padding: 12px; } }
@media(max-width:700px) { .stream-table thead { position: absolute; width: 1px; height: 1px; overflow: hidden; clip-path: inset(50%); }.stream-table table,.stream-table tbody { display: block; }.stream-table tbody tr { display: grid; grid-template-columns: minmax(0,1fr); padding: 8px; margin-bottom: 12px; border: 1px solid var(--el-border-color); border-radius: 8px; }.stream-table td { display: grid; grid-template-columns: 105px minmax(0,1fr); gap: 8px; padding: 8px 4px; border: 0; align-items: start; }.stream-table td::before { content: attr(data-label); color: var(--el-text-color-secondary); } }
</style>
