<script setup lang="ts">
import { computed, ref } from "vue";
import { ElMessage, ElMessageBox } from "element-plus";
import { Plus, Refresh, Tickets } from "@element-plus/icons-vue";

type API = <T>(path: string, method?: string, body?: unknown) => Promise<T>;
interface Runtime {
  id: string;
  family: string;
  version: string;
  status: string;
}
interface Instance {
  id: string;
  name: string;
  release_id: string;
  port: number;
  max_memory_mb: number;
  created_at: string;
  status: string;
  clients: number;
  used_memory: number;
  logical_dbs?: { index: number; keys: number }[];
}
interface KeysPage { db: number; cursor: string; keys: string[]; omitted: number }
interface KeyInfo { db: number; name: string; kind: string; ttl_seconds: number; size: number }
interface KeyPreview { db: number; name: string; kind: string; total: number; sampled: boolean; truncated: boolean; items: { name: string; value: string }[] }
const props = defineProps<{ api: API; installed: Runtime[] }>();
const emit = defineEmits<{ changed: [] }>();
const drawer = ref(false),
  loading = ref(false),
  createOpen = ref(false),
  logsOpen = ref(false),
  logs = ref(""),
  keysOpen = ref(false),
  keysLoading = ref(false),
  keysInstance = ref<Instance | null>(null),
  keysDB = ref(0),
  keysPattern = ref("*"),
  keysCursor = ref("0"),
  keysList = ref<string[]>([]),
  keysOmitted = ref(0),
  keyInfo = ref<KeyInfo | null>(null),
  keyValue = ref<string | null>(null),
  keyValueLoading = ref(false),
  keyEditing = ref(false),
  keyDraft = ref(""),
  keyValueSaving = ref(false);
const keyPreview = ref<KeyPreview | null>(null), keyPreviewLoading = ref(false);
const keyHashField = ref<string | null>(null), keyHashValue = ref<string | null>(null), keyHashDraft = ref(""), keyHashLoading = ref(false), keyHashSaving = ref(false), keyHashDeleting = ref(false);
const keyHashAdding = ref(false), keyHashNewField = ref(""), keyHashNewValue = ref(""), keyHashAddSaving = ref(false);
let hashFieldReadSequence = 0;
let keyInfoReadSequence = 0;
let keysLoadSequence = 0;
const instances = ref<Instance[]>([]);
const form = ref({ name: "", release_id: "", port: 16379, max_memory_mb: 128 });
const releases = computed(() =>
  props.installed.filter(
    (r) => r.family === "redis" && r.status === "installed",
  ),
);
const running = computed(
  () => instances.value.filter((item) => item.status === "running").length,
);
const memory = (bytes: number) =>
  bytes < 1024 * 1024
    ? `${Math.round(bytes / 1024)} KB`
    : `${(bytes / 1024 / 1024).toFixed(1)} MB`;

async function refresh() {
  loading.value = true;
  try {
    instances.value = (
      await props.api<{ instances: Instance[] }>("/redis/instances")
    ).instances;
  } catch (e) {
    ElMessage.error(e instanceof Error ? e.message : "读取 Redis 实例失败");
  } finally {
    loading.value = false;
  }
}
async function open(instanceID?: string, db = 0) {
  drawer.value = true;
  await refresh();
  if (instanceID) {
    const item = instances.value.find((value) => value.id === instanceID);
    if (item) await showKeys(item, db);
  }
}
async function showKeys(item: Instance, db = 0) {
  if (item.status !== "running") { ElMessage.warning("请先启动 Redis 实例"); return; }
  keysInstance.value = item;
  keysDB.value = db;
  keysPattern.value = "*";
  keysCursor.value = "0";
  keysList.value = [];
  keyInfo.value = null;
  keyValue.value = null;
  keyPreview.value = null;
  keyHashField.value = null;
  keyHashValue.value = null;
  keyHashAdding.value = false;
  hashFieldReadSequence++;
  keyInfoReadSequence++;
  keysLoadSequence++;
  keysLoading.value = false;
  keyHashLoading.value = false;
  keyEditing.value = false;
  keysOpen.value = true;
  await loadKeys(false);
}
async function loadKeys(next: boolean) {
  const item = keysInstance.value, db = keysDB.value;
  if (!item) return;
  const sequence = ++keysLoadSequence;
  const cursor = next ? keysCursor.value : "0";
  const pattern = keysPattern.value.trim() || "*";
  keysLoading.value = true;
  if (!next) {
    keysList.value = [];
    keysCursor.value = "0";
    keysOmitted.value = 0;
    keyInfo.value = null;
    keyValue.value = null;
    keyPreview.value = null;
    keyEditing.value = false;
    keyHashField.value = null;
    keyHashValue.value = null;
    keyHashAdding.value = false;
    hashFieldReadSequence++;
    keyInfoReadSequence++;
    keyHashLoading.value = false;
  }
  try {
    const page = await props.api<KeysPage>(`/redis/instances/${item.id}/keys?db=${db}&cursor=${encodeURIComponent(cursor)}&pattern=${encodeURIComponent(pattern)}`);
    if (sequence !== keysLoadSequence || keysInstance.value?.id !== item.id || keysDB.value !== db) return;
    keysCursor.value = page.cursor;
    keysOmitted.value = page.omitted;
    keysList.value = next ? [...new Set([...keysList.value, ...page.keys])].slice(0, 500) : page.keys;
  } catch (e) { if (sequence === keysLoadSequence) ElMessage.error(e instanceof Error ? e.message : "读取 Redis 键失败"); }
  finally { if (sequence === keysLoadSequence) keysLoading.value = false; }
}
async function showKeyInfo(name: string) {
  const item = keysInstance.value, db = keysDB.value;
  if (!item) return;
  const sequence = ++keyInfoReadSequence;
  keyInfo.value = null;
  keyValue.value = null;
  keyPreview.value = null;
  keyHashField.value = null;
  keyHashValue.value = null;
  keyHashAdding.value = false;
  hashFieldReadSequence++;
  keyHashLoading.value = false;
  keyEditing.value = false;
  try {
    const info = await props.api<KeyInfo>(`/redis/instances/${item.id}/keys/info?db=${db}&name=${encodeURIComponent(name)}`);
    if (sequence === keyInfoReadSequence && keysInstance.value?.id === item.id && keysDB.value === db && info.name === name) keyInfo.value = info;
  } catch (e) { if (sequence === keyInfoReadSequence) ElMessage.error(e instanceof Error ? e.message : "读取 Redis 键详情失败"); }
}
async function saveKeyValue() {
  const item = keysInstance.value, selected = keyInfo.value, oldValue = keyValue.value;
  if (!item || !selected || oldValue === null) return;
  const draft = keyDraft.value;
  if (new TextEncoder().encode(draft).length > 4096) { ElMessage.error("文本内容不能超过 4 KiB"); return; }
  keyValueSaving.value = true;
  try {
    await props.api(`/redis/instances/${item.id}/keys/value`, "PUT", { db: selected.db, name: selected.name, old_value: oldValue, value: draft });
    if (keysInstance.value?.id === item.id && keysDB.value === selected.db && keyInfo.value === selected) {
      keyValue.value = draft;
      keyEditing.value = false;
      keyInfo.value = { ...selected, size: new TextEncoder().encode(draft).length };
    }
    ElMessage.success("Redis 文本键已更新，原有效期已保留");
  } catch (e) { ElMessage.error(e instanceof Error ? e.message : "更新 Redis 键失败"); }
  finally { keyValueSaving.value = false; }
}
async function setKeyTTL() {
  const item = keysInstance.value, selected = keyInfo.value;
  if (!item || !selected) return;
  try {
    const prompt = await ElMessageBox.prompt(
      `为 ${selected.name} 设置有效期（秒）。输入 0 表示永久保留，最长 365 天。`,
      "设置 Redis 键有效期",
      { inputValue: String(Math.max(0, selected.ttl_seconds)), inputValidator: (value: string) => /^(0|[1-9]\d*)$/.test(value) && Number(value) <= 31536000 || "请输入 0–31536000 秒", confirmButtonText: "保存有效期", cancelButtonText: "取消" },
    );
    const seconds = Number(prompt.value);
    await props.api(`/redis/instances/${item.id}/keys/ttl`, "PUT", { db: selected.db, name: selected.name, ttl_seconds: seconds === 0 ? -1 : seconds });
    if (keysInstance.value?.id === item.id && keysDB.value === selected.db && keyInfo.value === selected) await showKeyInfo(selected.name);
    ElMessage.success("Redis 键有效期已更新");
  } catch (e) { if (e instanceof Error) ElMessage.error(e.message); }
}
async function loadKeyValue() {
  const item = keysInstance.value, selected = keyInfo.value;
  if (!item || !selected || selected.kind !== "string") return;
  keyValueLoading.value = true;
  try {
    const out = await props.api<{ value: string }>(`/redis/instances/${item.id}/keys/value?db=${selected.db}&name=${encodeURIComponent(selected.name)}`);
    if (keysInstance.value?.id === item.id && keyInfo.value === selected && keysDB.value === selected.db) keyValue.value = out.value;
  } catch (e) { ElMessage.error(e instanceof Error ? e.message : "读取键内容失败"); }
  finally { keyValueLoading.value = false; }
}
async function loadKeyPreview() {
  const item = keysInstance.value, selected = keyInfo.value;
  if (!item || !selected || !["hash", "list", "set", "zset"].includes(selected.kind)) return;
  keyPreviewLoading.value = true;
  try {
    const out = await props.api<KeyPreview>(`/redis/instances/${item.id}/keys/preview?db=${selected.db}&name=${encodeURIComponent(selected.name)}`);
    if (keysInstance.value?.id === item.id && keyInfo.value === selected && keysDB.value === selected.db) keyPreview.value = out;
  } catch (e) { ElMessage.error(e instanceof Error ? e.message : "读取键预览失败"); }
  finally { keyPreviewLoading.value = false; }
}
function canEditHashField(field: string) {
  return field !== "[二进制内容]" && new TextEncoder().encode(field).length > 0 && new TextEncoder().encode(field).length < 512;
}
async function editHashField(field: string) {
  const item = keysInstance.value, selected = keyInfo.value;
  if (!item || !selected || selected.kind !== "hash" || !canEditHashField(field)) return;
  keyHashField.value = null;
  keyHashValue.value = null;
  const sequence = ++hashFieldReadSequence;
  keyHashLoading.value = true;
  try {
    const out = await props.api<{ value: string }>(`/redis/instances/${item.id}/keys/hash-field?db=${selected.db}&name=${encodeURIComponent(selected.name)}&field=${encodeURIComponent(field)}`);
    if (sequence !== hashFieldReadSequence || keysInstance.value?.id !== item.id || keyInfo.value !== selected || keysDB.value !== selected.db) return;
    keyHashField.value = field;
    keyHashValue.value = out.value;
    keyHashDraft.value = out.value;
  } catch (e) { if (sequence === hashFieldReadSequence) ElMessage.error(e instanceof Error ? e.message : "读取哈希字段失败"); }
  finally { if (sequence === hashFieldReadSequence) keyHashLoading.value = false; }
}
async function saveHashField() {
  const item = keysInstance.value, selected = keyInfo.value, field = keyHashField.value, oldValue = keyHashValue.value;
  if (!item || !selected || !field || oldValue === null) return;
  const draft = keyHashDraft.value;
  if (new TextEncoder().encode(draft).length > 4096) { ElMessage.error("字段内容不能超过 4 KiB"); return; }
  keyHashSaving.value = true;
  try {
    await props.api(`/redis/instances/${item.id}/keys/hash-field`, "PUT", { db: selected.db, name: selected.name, field, old_value: oldValue, value: draft });
    if (keysInstance.value?.id === item.id && keyInfo.value === selected && keysDB.value === selected.db && keyHashField.value === field) {
      keyHashValue.value = draft;
      await loadKeyPreview();
    }
    ElMessage.success("哈希字段已更新，键有效期保持不变");
  } catch (e) { ElMessage.error(e instanceof Error ? e.message : "更新哈希字段失败"); }
  finally { keyHashSaving.value = false; }
}
async function removeHashField() {
  const item = keysInstance.value, selected = keyInfo.value, field = keyHashField.value, oldValue = keyHashValue.value;
  if (!item || !selected || !field || oldValue === null) return;
  try {
    const confirmation = await ElMessageBox.prompt(`从 ${selected.name} 删除字段 ${field}。请输入完整字段名确认。`, "删除 Redis 哈希字段", { type: "warning", inputPlaceholder: field, confirmButtonText: "删除字段", cancelButtonText: "取消" });
    if (confirmation.value !== field) { ElMessage.error("字段名不匹配，未执行删除"); return; }
    keyHashDeleting.value = true;
    const result = await props.api<{ key_exists: boolean }>(`/redis/instances/${item.id}/keys/hash-field`, "DELETE", { db: selected.db, name: selected.name, field, old_value: oldValue, confirm_field: confirmation.value });
    if (keysInstance.value?.id === item.id && keyInfo.value === selected && keysDB.value === selected.db) {
      keyHashField.value = null;
      keyHashValue.value = null;
      if (result.key_exists) { await showKeyInfo(selected.name); await loadKeyPreview(); }
      else { keysList.value = keysList.value.filter(name => name !== selected.name); keyInfo.value = null; keyPreview.value = null; }
    }
    await refresh();
    emit("changed");
    ElMessage.success("Redis 哈希字段已删除");
  } catch (e) { if (e instanceof Error) ElMessage.error(e.message); }
  finally { keyHashDeleting.value = false; }
}
async function addHashField() {
  const item = keysInstance.value, selected = keyInfo.value;
  const field = keyHashNewField.value, value = keyHashNewValue.value;
  if (!item || !selected || selected.kind !== "hash") return;
  if (!field.trim() || !canEditHashField(field) || new TextEncoder().encode(value).length > 4096) { ElMessage.error("字段名需小于 512 字节，内容最多 4 KiB"); return; }
  keyHashAddSaving.value = true;
  try {
    await props.api(`/redis/instances/${item.id}/keys/hash-field`, "POST", { db: selected.db, name: selected.name, field, value });
    if (keysInstance.value?.id === item.id && keyInfo.value === selected && keysDB.value === selected.db) {
      keyHashAdding.value = false;
      keyHashNewField.value = "";
      keyHashNewValue.value = "";
      await showKeyInfo(selected.name);
      await loadKeyPreview();
    }
    await refresh();
    emit("changed");
    ElMessage.success("Redis 哈希字段已添加");
  } catch (e) { ElMessage.error(e instanceof Error ? e.message : "添加哈希字段失败"); }
  finally { keyHashAddSaving.value = false; }
}
async function removeKey() {
  const item = keysInstance.value, selected = keyInfo.value;
  if (!item || !selected) return;
  try {
    const confirmation = await ElMessageBox.prompt(
      `将从 ${item.name} 的 db${selected.db} 永久删除此键。请输入完整键名 ${selected.name}`,
      "删除 Redis 键",
      { type: "warning", confirmButtonText: "删除此键", cancelButtonText: "取消", inputPlaceholder: selected.name },
    );
    if (confirmation.value !== selected.name) { ElMessage.error("键名不匹配，未执行删除"); return; }
    await props.api(`/redis/instances/${item.id}/keys`, "DELETE", { db: selected.db, name: selected.name, confirm_name: confirmation.value });
    keysList.value = keysList.value.filter(name => name !== selected.name);
    keyInfo.value = null;
    keyValue.value = null;
    keyEditing.value = false;
    ElMessage.success("Redis 键已删除");
    await refresh();
    emit("changed");
  } catch (e) {
    if (e instanceof Error) ElMessage.error(e.message);
  }
}
function create() {
  if (!releases.value.length) {
    ElMessage.warning("请先安装 Redis 运行环境");
    return;
  }
  const used = new Set(instances.value.map((item) => item.port));
  let port = 16379;
  while (used.has(port) && port <= 16999) port++;
  form.value = {
    name: "",
    release_id: releases.value.at(-1)?.id || releases.value[0].id,
    port,
    max_memory_mb: 128,
  };
  createOpen.value = true;
}
async function submit() {
  if (!form.value.name.trim()) {
    ElMessage.warning("请输入实例名称");
    return;
  }
  loading.value = true;
  try {
    await props.api("/redis/instances", "POST", {
      ...form.value,
      name: form.value.name.trim(),
    });
    createOpen.value = false;
    ElMessage.success("Redis 实例已创建并通过 PING");
    await refresh();
    emit("changed");
  } catch (e) {
    ElMessage.error(e instanceof Error ? e.message : "创建失败");
  } finally {
    loading.value = false;
  }
}
async function action(item: Instance, value: "start" | "stop" | "restart") {
  try {
    await props.api(`/redis/instances/${item.id}/${value}`, "POST", {});
    ElMessage.success("实例状态已更新");
    await refresh();
    emit("changed");
  } catch (e) {
    ElMessage.error(e instanceof Error ? e.message : "操作失败");
  }
}
async function showLogs(item: Instance) {
  try {
    logs.value = (
      await props.api<{ content: string }>(`/redis/instances/${item.id}/logs`)
    ).content;
    logsOpen.value = true;
  } catch (e) {
    ElMessage.error(e instanceof Error ? e.message : "读取日志失败");
  }
}
async function remove(item: Instance) {
  try {
    const name = await ElMessageBox.prompt(
      `将停止实例并永久删除数据目录。请输入实例名称 ${item.name}`,
      "删除 Redis 实例",
      {
        confirmButtonText: "永久删除",
        cancelButtonText: "取消",
        inputPlaceholder: item.name,
        type: "warning",
      },
    );
    await props.api(`/redis/instances/${item.id}`, "DELETE", {
      confirm_name: name.value,
    });
    ElMessage.success("Redis 实例与数据已删除");
    await refresh();
    emit("changed");
  } catch (e) {
    if (e instanceof Error) ElMessage.error(e.message);
  }
}
defineExpose({ open, refresh });
</script>

<template>
  <el-drawer
    v-model="drawer"
    title="Redis 实例管理"
    size="900px"
    class="redis-drawer"
    @open="refresh"
  >
    <div class="redis-summary">
      <div>
        <small>实例总数</small><strong>{{ instances.length }}</strong>
      </div>
      <div>
        <small>运行中</small><strong class="green">{{ running }}</strong>
      </div>
      <div>
        <small>版本数量</small><strong>{{ releases.length }}</strong>
      </div>
      <div class="redis-actions">
        <el-button :icon="Refresh" @click="refresh">刷新</el-button
        ><el-button
          type="primary"
          :icon="Plus"
          :disabled="!releases.length"
          @click="create"
          >创建实例</el-button
        >
      </div>
    </div>
    <el-table
      v-loading="loading"
      :data="instances"
      empty-text="尚未创建 Redis 实例"
      class="redis-table"
    >
      <el-table-column label="实例" min-width="150"
        ><template #default="{ row }"
          ><strong>{{ row.name }}</strong
          ><small>{{ row.id.slice(0, 8) }}</small></template
        ></el-table-column
      >
      <el-table-column label="版本" min-width="110"
        ><template #default="{ row }"
          >Redis {{ row.release_id.replace("redis-", "") }}</template
        ></el-table-column
      >
      <el-table-column label="本机地址" min-width="145"
        ><template #default="{ row }"
          >127.0.0.1:{{ row.port }}</template
        ></el-table-column
      >
      <el-table-column label="内存" min-width="115"
        ><template #default="{ row }"
          >{{ memory(row.used_memory || 0) }} /
          {{ row.max_memory_mb }} MB</template
        ></el-table-column
      >
      <el-table-column label="连接" width="75" prop="clients" />
      <el-table-column label="状态" width="95"
        ><template #default="{ row }"
          ><el-tag
            :type="
              row.status === 'running'
                ? 'success'
                : row.status === 'stopped'
                  ? 'info'
                  : 'danger'
            "
            >{{
              row.status === "running"
                ? "运行中"
                : row.status === "stopped"
                  ? "已停止"
                  : "需核对"
            }}</el-tag
          ></template
        ></el-table-column
      >
      <el-table-column label="操作" min-width="245" fixed="right"
        ><template #default="{ row }"
          ><el-button
            link
            type="primary"
            @click="action(row, row.status === 'running' ? 'stop' : 'start')"
            >{{ row.status === "running" ? "停止" : "启动" }}</el-button
          ><el-button
            link
            type="primary"
            :disabled="row.status !== 'running'"
            @click="action(row, 'restart')"
            >重启</el-button
          ><el-button link type="primary" @click="showLogs(row)">日志</el-button
          ><el-button link type="primary" :disabled="row.status !== 'running'" @click="showKeys(row)">查看键</el-button
          ><el-button link type="danger" @click="remove(row)"
            >删除</el-button
          ></template
        ></el-table-column
      >
    </el-table>
    <div class="redis-security">
      <strong>访问边界</strong
      ><span
        >所有实例只监听 127.0.0.1，启用 protected-mode，并由独立 panel-redis
        系统账户运行。</span
      >
    </div>
  </el-drawer>
  <el-dialog v-model="keysOpen" :title="`${keysInstance?.name || 'Redis'} · db${keysDB} 键浏览`" width="740px" class="redis-keys-dialog">
    <p class="redis-key-note">SCAN 每批最多请求 50 个键。文本字符串和哈希字段可按需读取、编辑（最多 4 KiB）；列表、有序集合、哈希和集合可查看最多 20 项。删除单键需要输入完整键名确认。</p>
    <div class="redis-key-toolbar">
      <el-select v-model="keysDB" aria-label="Redis 逻辑库" @change="loadKeys(false)"><el-option v-for="index in 16" :key="index - 1" :value="index - 1" :label="`db${index - 1}`" /></el-select>
      <el-input v-model="keysPattern" aria-label="Redis 键搜索模式" maxlength="128" placeholder="键名模式，例如 user:*" @keyup.enter="loadKeys(false)" />
      <el-button :loading="keysLoading" @click="loadKeys(false)">搜索</el-button>
    </div>
    <div class="redis-key-layout" v-loading="keysLoading">
      <div class="redis-key-list">
        <button v-for="name in keysList" :key="name" type="button" :class="{ active: keyInfo?.name === name }" @click="showKeyInfo(name)">{{ name }}</button>
        <el-empty v-if="!keysList.length" description="本批没有匹配的文本键" :image-size="55" />
      </div>
      <dl v-if="keyInfo" class="redis-key-info">
        <dt>键名</dt><dd>{{ keyInfo.name }}</dd>
        <dt>类型</dt><dd>{{ keyInfo.kind }}</dd>
        <dt>大小</dt><dd>{{ keyInfo.size < 0 ? '—' : keyInfo.kind === 'string' ? `${keyInfo.size} 字节` : `${keyInfo.size} 项` }}</dd>
        <dt>剩余有效期</dt><dd>{{ keyInfo.ttl_seconds === -1 ? '永久' : keyInfo.ttl_seconds < 0 ? '已过期' : `${keyInfo.ttl_seconds} 秒` }}</dd>
        <dt v-if="keyInfo.kind === 'string'">内容</dt>
        <dd v-if="keyInfo.kind === 'string'"><el-button v-if="keyValue === null" link type="primary" :loading="keyValueLoading" @click="loadKeyValue">查看文本</el-button><template v-else-if="keyEditing"><el-input v-model="keyDraft" type="textarea" :rows="5" aria-label="Redis 文本内容" /><div class="redis-key-edit-actions"><el-button size="small" @click="keyEditing = false">取消</el-button><el-button size="small" type="primary" :loading="keyValueSaving" @click="saveKeyValue">保存内容</el-button></div></template><template v-else><pre class="redis-key-value">{{ keyValue }}</pre><el-button link type="primary" @click="keyDraft = keyValue; keyEditing = true">编辑文本</el-button></template></dd>
        <dt v-if="['hash', 'list', 'set', 'zset'].includes(keyInfo.kind)">内容</dt>
        <dd v-if="['hash', 'list', 'set', 'zset'].includes(keyInfo.kind)">
          <el-button v-if="!keyPreview" link type="primary" :loading="keyPreviewLoading" @click="loadKeyPreview">查看前 20 项</el-button>
          <template v-else><small>{{ keyPreview.sampled ? '抽样' : '从首项开始' }}显示 {{ keyPreview.items.length }} / {{ keyPreview.total }} 项；每项最多 512 字节</small><div class="redis-preview-list"><div v-for="(entry, index) in keyPreview.items" :key="index"><strong v-if="entry.name">{{ entry.name }}</strong><span>{{ entry.value }}</span><el-button v-if="keyPreview.kind === 'hash' && canEditHashField(entry.name)" link type="primary" size="small" :loading="keyHashLoading" @click="editHashField(entry.name)">编辑字段</el-button></div></div><div v-if="keyHashField !== null && keyHashValue !== null" class="redis-hash-editor"><strong>编辑字段：{{ keyHashField }}</strong><el-input v-model="keyHashDraft" type="textarea" :rows="3" aria-label="Redis 哈希字段内容" /><div><el-button size="small" @click="keyHashField = null; keyHashValue = null">取消</el-button><el-button size="small" type="danger" plain :loading="keyHashDeleting" @click="removeHashField">删除字段</el-button><el-button size="small" type="primary" :loading="keyHashSaving" @click="saveHashField">保存字段</el-button></div></div><template v-if="keyPreview.kind === 'hash'"><div v-if="keyHashAdding" class="redis-hash-editor"><strong>添加哈希字段</strong><el-input v-model="keyHashNewField" aria-label="新哈希字段名" maxlength="511" placeholder="字段名" /><el-input v-model="keyHashNewValue" type="textarea" :rows="3" aria-label="新哈希字段内容" /><div><el-button size="small" @click="keyHashAdding = false">取消</el-button><el-button size="small" type="primary" :loading="keyHashAddSaving" @click="addHashField">保存新字段</el-button></div></div><el-button v-else link type="primary" @click="keyHashAdding = true">添加字段</el-button></template><el-button link type="primary" :loading="keyPreviewLoading" @click="loadKeyPreview">刷新预览</el-button></template>
        </dd>
        <dt>操作</dt><dd><el-button link type="primary" @click="setKeyTTL">设置有效期</el-button><el-button link type="danger" @click="removeKey">删除此键</el-button></dd>
      </dl>
      <p v-else class="redis-key-placeholder">选择键名查看类型、大小和有效期。</p>
    </div>
    <div class="redis-key-footer"><small v-if="keysOmitted">{{ keysOmitted }} 个二进制或超长键名未显示</small><el-button :disabled="keysCursor === '0' || keysList.length >= 500" :loading="keysLoading" @click="loadKeys(true)">下一批</el-button></div>
  </el-dialog>
  <el-dialog v-model="createOpen" title="创建 Redis 实例" width="520px">
    <el-form label-position="top">
      <el-form-item label="实例名称"
        ><el-input
          v-model="form.name"
          maxlength="40"
          placeholder="例如：会话缓存"
      /></el-form-item>
      <el-form-item label="Redis 版本"
        ><el-select v-model="form.release_id" style="width: 100%"
          ><el-option
            v-for="item in releases"
            :key="item.id"
            :label="`Redis ${item.version}`"
            :value="item.id" /></el-select
      ></el-form-item>
      <div class="redis-form-grid">
        <el-form-item label="本机端口"
          ><el-input-number
            v-model="form.port"
            :min="16379"
            :max="16999"
            controls-position="right" /></el-form-item
        ><el-form-item label="最大内存（MB）"
          ><el-input-number
            v-model="form.max_memory_mb"
            :min="32"
            :max="16384"
            :step="32"
            controls-position="right"
        /></el-form-item>
      </div>
      <el-alert
        :closable="false"
        type="info"
        title="默认开启 AOF 持久化，内存达到上限后按 allkeys-lru 淘汰；端口不向公网暴露。"
      />
    </el-form>
    <template #footer
      ><el-button @click="createOpen = false">取消</el-button
      ><el-button type="primary" :loading="loading" @click="submit"
        >创建并启动</el-button
      ></template
    >
  </el-dialog>
  <el-dialog v-model="logsOpen" title="Redis 服务日志" width="760px">
    <pre class="redis-logs">{{ logs || "暂无日志" }}</pre>
    <template #footer
      ><el-button :icon="Tickets" @click="logsOpen = false"
        >关闭</el-button
      ></template
    ></el-dialog
  >
</template>

<style scoped>
.redis-summary {
  display: grid;
  grid-template-columns: repeat(3, minmax(100px, 1fr)) auto;
  gap: 12px;
  margin-bottom: 18px;
}
.redis-summary > div {
  border: 1px solid #e8edf3;
  border-radius: 8px;
  padding: 14px 16px;
  background: #fff;
}
.redis-summary small {
  display: block;
  color: #718096;
  margin-bottom: 8px;
}
.redis-summary strong {
  font-size: 24px;
  color: #172033;
}
.redis-summary .green {
  color: #08a858;
}
.redis-summary .redis-actions {
  display: flex;
  align-items: center;
  gap: 8px;
  border: 0;
  padding: 0;
}
.redis-table {
  border: 1px solid #e8edf3;
  border-radius: 8px;
}
.redis-table strong,
.redis-table small {
  display: block;
}
.redis-table small {
  color: #94a3b8;
  margin-top: 4px;
}
.redis-security {
  display: flex;
  gap: 12px;
  margin-top: 16px;
  padding: 14px 16px;
  border-radius: 8px;
  background: #f0fbf5;
  color: #4b6474;
  font-size: 13px;
}
.redis-security strong {
  color: #08a858;
  white-space: nowrap;
}
.redis-form-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 16px;
}
.redis-form-grid :deep(.el-input-number) {
  width: 100%;
}
.redis-logs {
  max-height: 480px;
  overflow: auto;
  margin: 0;
  padding: 16px;
  background: #111820;
  color: #d9e7df;
  border-radius: 7px;
  font:
    12px/1.6 ui-monospace,
    monospace;
  white-space: pre-wrap;
}
.redis-key-note { margin: 0 0 14px; color: #718096; font-size: 12px; line-height: 1.5; }
.redis-key-toolbar { display: grid; grid-template-columns: 95px minmax(0,1fr) auto; gap: 8px; margin-bottom: 12px; }
.redis-key-layout { display: grid; grid-template-columns: minmax(0,1.2fr) minmax(0,1fr); gap: 12px; min-height: 260px; }
.redis-key-list { max-height: 340px; overflow: auto; border: 1px solid #e4ebf2; border-radius: 6px; }
.redis-key-list button { display: block; width: 100%; padding: 9px 12px; border-bottom: 1px solid #edf1f5; color: #344966; font-size: 12px; text-align: left; overflow-wrap: anywhere; }
.redis-key-list button:hover,.redis-key-list button.active { background: #eaf9f1; color: #078e4a; }
.redis-key-info { display: grid; grid-template-columns: 74px minmax(0,1fr); align-content: start; gap: 13px 8px; margin: 0; padding: 15px; border: 1px solid #e4ebf2; border-radius: 6px; font-size: 12px; }
.redis-key-info dt { color: #73849b; }.redis-key-info dd { margin: 0; color: #243954; overflow-wrap: anywhere; }
.redis-key-value { max-height: 160px; overflow: auto; white-space: pre-wrap; overflow-wrap: anywhere; margin: 0; padding: 8px; background: #f5f8fa; border: 1px solid #e4ebf2; border-radius: 4px; font: 12px/1.5 ui-monospace, monospace; }
.redis-preview-list { max-height: 180px; overflow: auto; margin: 7px 0; border: 1px solid #e4ebf2; border-radius: 4px; }
.redis-preview-list > div { display: grid; gap: 3px; padding: 7px 9px; border-bottom: 1px solid #edf1f5; }
.redis-preview-list > div:last-child { border-bottom: 0; }
.redis-preview-list strong { color: #52647d; font-weight: 600; }
.redis-preview-list span { white-space: pre-wrap; overflow-wrap: anywhere; font: 12px/1.4 ui-monospace, monospace; }
.redis-hash-editor { display: grid; gap: 7px; margin: 8px 0; }
.redis-hash-editor strong { font-size: 12px; overflow-wrap: anywhere; }
.redis-hash-editor > div:last-child { display: flex; justify-content: flex-end; gap: 6px; }
.redis-key-edit-actions { display: flex; justify-content: flex-end; gap: 8px; margin-top: 8px; }
.redis-key-placeholder { display: grid; place-items: center; margin: 0; border: 1px solid #e4ebf2; border-radius: 6px; color: #8796aa; font-size: 12px; }
.redis-key-footer { display: flex; justify-content: space-between; align-items: center; margin-top: 12px; color: #8594a7; }
@media (max-width: 760px) {
  .redis-key-layout { grid-template-columns: 1fr; }
  .redis-key-toolbar { grid-template-columns: 95px minmax(0,1fr); }
  .redis-key-toolbar > .el-button { grid-column: 1/-1; }
  .redis-summary {
    grid-template-columns: 1fr 1fr;
  }
  .redis-summary .redis-actions {
    grid-column: 1/-1;
  }
  .redis-form-grid {
    grid-template-columns: 1fr;
  }
  .redis-security {
    flex-direction: column;
  }
}
</style>
