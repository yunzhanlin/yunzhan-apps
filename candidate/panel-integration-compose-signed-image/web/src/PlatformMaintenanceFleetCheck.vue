<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue';

type API = <T>(path: string, method?: string, body?: unknown) => Promise<T>;
type Plan = { plan: { format: number; sha256: string }; grant_id: string; actor_id: string; allowed_commands: string[]; expires_at: number };
type Operation = { request_id: string; command: 'nginx-check'; expected_plan_sha256: string; confirm: '' };
type Ticket = { url: string; token: string; actor_id: string; operation: Operation };
type Outcome = 'ready' | 'completed' | 'failed' | 'needs_attention' | 'not_dispatched';
type Row = { id: number; url: string; token: string; plan?: Plan; ticket?: Ticket; state: Outcome; message: string };
const props = defineProps<{ api: API; enabled: boolean; installationId: string; actorId?: string }>();
const base = '/app-modules/platform-ops/maintenance/remote';
const rows = ref<Row[]>([]);
const busy = ref(false);
const notice = ref('');
let next = 0;
let epoch = 0;
const hex = (v: unknown, n: number): v is string => typeof v === 'string' && v.length === n && /^[a-f0-9]+$/.test(v);
function add() {
  if (rows.value.length < 8 && !busy.value) rows.value.push({ id: ++next, url: '', token: '', state: 'ready', message: '' });
}
function reset() {
  epoch++;
  rows.value = [];
  busy.value = false;
  notice.value = '';
  add();
  add();
}
reset();
watch(() => [props.enabled, props.installationId, props.actorId], reset);
onBeforeUnmount(() => { epoch++; rows.value = []; });

async function digest(value: string) {
  if (!globalThis.crypto?.subtle) throw Error('需要 HTTPS 或本机安全连接');
  const bytes = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
  return [...new Uint8Array(bytes)].map(x => x.toString(16).padStart(2, '0')).join('');
}
function origin(address: string) {
  const u = new URL(address);
  if (u.protocol !== 'https:' || u.username || u.password || u.search || u.hash) throw Error('请输入明确的 HTTPS 面板地址');
  return u.hostname.replace(/\.$/, '') + ':' + (u.port || '443');
}
function invalidate(row: Row) {
  row.plan = undefined;
  row.message = '';
}
async function checkPlan(row: Row) {
  if (busy.value || row.ticket || !props.enabled) return;
  const current = epoch;
  const url = row.url.trim();
  const token = row.token;
  busy.value = true;
  invalidate(row);
  try {
    origin(url);
    if (!hex(token, 64)) throw Error('请输入该目标面板的独立维护秘密');
    const p = await props.api<Plan>(base + '/plan', 'POST', { url, token });
    const expected = await digest(token);
    if (current !== epoch) return;
    if (p.plan?.format !== 1 || !hex(p.plan.sha256, 64) || p.grant_id !== expected ||
        !hex(p.actor_id, 32) || !p.allowed_commands?.includes('nginx-check') ||
        !Number.isSafeInteger(p.expires_at) || p.expires_at * 1000 <= Date.now()) {
      throw Error('远端配置检查授权或计划无法核对');
    }
    row.plan = p;
    row.message = '已核对配置检查授权及计划';
  } catch (error) {
    if (current === epoch) row.message = (error as Error).message;
  } finally {
    if (current === epoch) busy.value = false;
  }
}
const canSubmit = computed(() => props.enabled && !busy.value && rows.value.length >= 2 &&
  rows.value.every(row => !row.ticket && !!row.plan));
const outcomes: Record<Outcome, string> = {
  ready: '待检查', completed: '配置检查通过', failed: '原检查失败',
  needs_attention: '原结果未确认', not_dispatched: '未派发',
};
function finish(row: Row, state: Outcome, outcome?: string) {
  row.state = state;
  row.message = state === 'completed' ? 'Nginx 配置有效' : state === 'failed' ?
    outcome === 'plan_changed_before_command' ? '执行前计划已变化' : 'Nginx 配置检查未通过' :
    state === 'not_dispatched' ? '没有向该目标发送检查命令' : '只读核对原请求；不会自动重发';
  if (state !== 'needs_attention') row.token = '';
  if (state !== 'needs_attention' && row.ticket) row.ticket = { ...row.ticket, token: '' };
}
async function submit() {
  if (!canSubmit.value) return;
  const current = epoch;
  const active = [...rows.value];
  let targets: Ticket[];
  try {
    const origins = new Set(active.map(row => origin(row.url.trim())));
    if (origins.size !== active.length || new Set(active.map(row => row.token)).size !== active.length) throw Error('每行必须是不同面板，并使用各自的维护秘密');
    targets = active.map(row => {
      const p = row.plan!;
      if (p.expires_at * 1000 <= Date.now()) throw Error('维护授权已到期，先重新核对原计划');
      const request_id = [...crypto.getRandomValues(new Uint8Array(16))].map(n => n.toString(16).padStart(2, '0')).join('');
      return { url: row.url.trim(), token: row.token, actor_id: p.actor_id, operation: { request_id, command: 'nginx-check', expected_plan_sha256: p.plan.sha256, confirm: '' } };
    });
  } catch (error) {
    notice.value = (error as Error).message;
    return;
  }
  busy.value = true;
  notice.value = '';
  active.forEach((row, i) => { row.ticket = targets[i]; row.state = 'needs_attention'; });
  try {
    const result = await props.api<{ all_succeeded: boolean; results: Array<{ request_id: string; state: Outcome; outcome?: string }> }>(base + '/fleet/checks', 'POST', { targets });
    if (current !== epoch) return;
    if (!Array.isArray(result.results) || result.results.length !== targets.length ||
        result.all_succeeded !== result.results.every(item => item.state === 'completed') ||
        result.results.some((item, i) => item.request_id !== targets[i].operation.request_id ||
          !['completed', 'failed', 'needs_attention', 'not_dispatched'].includes(item.state) ||
          (item.state === 'completed' ? item.outcome !== 'config_valid' :
            item.state === 'failed' ? !['command_failed', 'plan_changed_before_command'].includes(item.outcome || '') :
            item.outcome !== undefined))) throw Error('批量回执无法核对');
    result.results.forEach((item, i) => finish(active[i], item.state, item.outcome));
    notice.value = result.all_succeeded ? '所有目标的 Nginx 配置均通过检查。' : '批量检查已返回；请逐台查看原结果。';
  } catch {
    if (current === epoch) {
      active.forEach(row => finish(row, 'needs_attention'));
      notice.value = '未收到完整回执。请使用每台的原请求 ID 核对，勿重复派发。';
    }
  } finally {
    if (current === epoch) busy.value = false;
  }
}
async function inspect(row: Row) {
  const ticket = row.ticket;
  if (busy.value || !ticket?.token || row.state !== 'needs_attention') return;
  const current = epoch;
  busy.value = true;
  try {
    const result = await props.api<{
      request_id?: string; retry_allowed?: boolean; request_sha256?: string; state: string; outcome?: string;
      request?: { format: number; grant_id: string; actor_id: string; input: Operation };
    }>(base + '/commands/status', 'POST', ticket);
    if (current !== epoch) return;
    if (result.state === 'needs_attention' && result.request_id === ticket.operation.request_id && result.retry_allowed === false) return;
    const grant_id = await digest(ticket.token);
    const identity = { format: 1, grant_id, actor_id: ticket.actor_id, input: ticket.operation };
    const pin = await digest(JSON.stringify(identity));
    if (current !== epoch) return;
    if (JSON.stringify(result.request) !== JSON.stringify(identity) || result.request_sha256 !== pin ||
        (result.state !== 'completed' || result.outcome !== 'config_valid') &&
        (result.state !== 'failed' || !['command_failed', 'plan_changed_before_command'].includes(result.outcome || ''))) {
      throw Error('远端回执与原操作不同');
    }
    finish(row, result.state as Outcome, result.outcome);
  } catch {
    if (current === epoch) row.message = '暂无法核对；保留原请求 ID，不重发命令';
  } finally {
    if (current === epoch) busy.value = false;
  }
}
</script>

<template>
  <section aria-label="批量 Nginx 配置检查" class="fleet-check">
    <h4>批量 Nginx 配置检查</h4>
    <p>选择 2–8 台面板，逐台核对独立授权和配置计划后运行检查。检查不会重载 Nginx。</p>
    <fieldset v-for="(row, index) in rows" :key="row.id">
      <legend>目标 {{ index + 1 }}</legend>
      <el-input v-model="row.url" :aria-label="'目标 '+(index+1)+' HTTPS 地址'" :disabled="busy || !!row.ticket" placeholder="https://" @input="invalidate(row)" />
      <el-input v-model="row.token" :aria-label="'目标 '+(index+1)+' 维护秘密'" type="password" autocomplete="off" :disabled="busy || !!row.ticket" @input="invalidate(row)" />
      <div class="actions">
        <el-button :disabled="busy || !enabled || !!row.ticket || !row.url || !row.token" @click="checkPlan(row)">核对计划</el-button>
        <el-button v-if="!row.ticket && rows.length > 2" :disabled="busy" @click="rows.splice(index,1)">移除此目标</el-button>
        <el-button v-if="row.state==='needs_attention'" :disabled="busy || !row.ticket?.token" @click="inspect(row)">只读核对原结果</el-button>
      </div>
      <p v-if="row.plan && !row.ticket">计划 SHA-256：{{ row.plan.plan.sha256 }}</p>
      <p v-if="row.ticket">{{ outcomes[row.state] }} · 原请求 {{ row.ticket.operation.request_id }}</p>
      <p v-if="row.message" role="status">{{ row.message }}</p>
    </fieldset>
    <div class="actions">
      <el-button :disabled="busy || rows.length >= 8 || rows.some(row => !!row.ticket)" @click="add">添加目标</el-button>
      <el-button type="primary" :disabled="!canSubmit" @click="submit">执行已核对的配置检查</el-button>
      <el-button v-if="rows.every(row=>!!row.ticket && row.state!=='needs_attention')" :disabled="busy" @click="reset">准备新批次</el-button>
    </div>
    <p v-if="notice" role="status">{{ notice }}</p>
  </section>
</template>
<style scoped>
.fleet-check { min-width: 0; overflow-wrap: anywhere; }
fieldset { min-width: 0; margin: 10px 0; border: 1px solid var(--el-border-color); border-radius: 6px; }
.actions { display: flex; flex-wrap: wrap; gap: 8px; margin-block: 8px; }
.actions :deep(.el-button) { margin-left: 0; }
p { margin-block: 6px; }
</style>
