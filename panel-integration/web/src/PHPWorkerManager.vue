<script setup lang="ts">
import { onMounted, ref } from "vue";
import { ElMessage, ElMessageBox } from "element-plus";

interface Worker {
  id: string; name: string; entry: string; arguments: string[];
  enabled: boolean; status: string; observed_release_id: string;
  pid?: number; invocation_id?: string; last_error?: string;
}
const props = defineProps<{
  siteId: string;
  phpVersion: string;
  siteStatus: string;
  api: <T>(path: string, method?: string, body?: unknown) => Promise<T>;
}>();
const workers = ref<Worker[]>([]), loading = ref(false), busy = ref(false), error = ref("");
const creating = ref(false), name = ref(""), entry = ref("artisan"), argumentsText = ref("queue:work");
const restart = ref("always"), memory = ref(256), tasks = ref(64), stop = ref(30);
const logVisible = ref(false), logText = ref(""), logName = ref("");
const base = `/sites/${props.siteId}/php-workers`;
async function load() {
  loading.value = true; error.value = "";
  try { workers.value = (await props.api<{ workers: Worker[] }>(base)).workers; }
  catch (e) { error.value = (e as Error).message; }
  finally { loading.value = false; }
}
async function create() {
  busy.value = true; error.value = "";
  try {
    await props.api(base, "POST", {
      name: name.value, entry: entry.value,
      arguments: argumentsText.value === "" ? [] : argumentsText.value.split("\n"),
      restart_policy: restart.value, memory_mb: memory.value,
      tasks_max: tasks.value, stop_seconds: stop.value,
    });
    creating.value = false; name.value = ""; ElMessage.success("PHP 进程已启动"); await load();
  } catch (e) { error.value = (e as Error).message; }
  finally { busy.value = false; }
}
async function action(v: Worker, command: string) {
  busy.value = true; error.value = "";
  try { await props.api(`${base}/${v.id}/${command}`, "POST", {}); await load(); }
  catch (e) { const message = (e as Error).message; await load(); error.value = message; }
  finally { busy.value = false; }
}
async function remove(v: Worker) {
  try {
    const { value } = await ElMessageBox.prompt(`输入进程名称「${v.name}」确认删除。网站文件会保留。`, "删除 PHP 进程", {
      inputValidator: (value: string) => value === v.name || "名称不匹配", confirmButtonText: "删除", cancelButtonText: "取消",
    });
    busy.value = true; error.value = "";
    await props.api(`${base}/${v.id}`, "DELETE", { confirm_name: value }); await load();
  } catch (e) { if (e !== "cancel" && e !== "close") error.value = (e as Error).message; }
  finally { busy.value = false; }
}
async function logs(v: Worker) {
  busy.value = true; error.value = "";
  try {
    logText.value = (await props.api<{ content: string }>(`${base}/${v.id}/logs`)).content;
    logName.value = v.name; logVisible.value = true;
  } catch (e) { error.value = (e as Error).message; }
  finally { busy.value = false; }
}
const statusLabel: Record<string, string> = { running: "运行中", stopped: "已停止", failed: "失败", activating: "启动中", deactivating: "停止中", unknown: "未知" };
onMounted(load);
</script>

<template>
  <div class="php-workers" v-loading="loading">
    <el-alert title="常驻进程使用该网站的 PHP 版本、参数与独立运行用户。进程启动检查不代表业务队列健康。" type="info" :closable="false" />
    <el-alert v-if="workers.length" title="自动重绑与回退仍在开发：变更 PHP 版本、PHP 参数或停用网站前，需要先删除这些进程配置。停止进程仍会保留版本引用。" type="warning" :closable="false" />
    <el-alert v-if="error" :title="error" type="error" :closable="false" />
    <div class="worker-toolbar">
      <span>网站 PHP：{{ phpVersion ? phpVersion.replace("php-", "") : "未绑定" }}</span>
      <el-button :disabled="busy" @click="load">刷新</el-button>
      <el-button type="primary" :disabled="busy || !phpVersion || siteStatus !== 'running'" @click="creating = !creating">添加进程</el-button>
    </div>
    <el-form v-if="creating" label-position="top" @submit.prevent="create" class="worker-form">
      <el-form-item label="进程名称"><el-input v-model="name" maxlength="40" placeholder="例如：邮件队列" /></el-form-item>
      <el-form-item label="入口文件"><el-input v-model="entry" maxlength="256" placeholder="artisan、bin/console 或 worker.php" /></el-form-item>
      <el-form-item label="应用参数（每行一个，不需要引号）" class="worker-arguments"><el-input v-model="argumentsText" type="textarea" :rows="3" placeholder="queue:work&#10;--sleep=3&#10;--tries=3" /><small>参数直接传给 PHP 脚本，支持空格；不会当作 Shell 命令执行。</small></el-form-item>
      <el-form-item label="重启策略"><el-select v-model="restart"><el-option label="退出后重启" value="always" /><el-option label="异常退出时重启" value="on-failure" /></el-select></el-form-item>
      <el-form-item label="内存上限（MB）"><el-input-number v-model="memory" :min="64" :max="2048" /></el-form-item>
      <el-form-item label="进程/线程上限"><el-input-number v-model="tasks" :min="16" :max="256" /></el-form-item>
      <el-form-item label="停止等待（秒）"><el-input-number v-model="stop" :min="5" :max="120" /></el-form-item>
      <div class="worker-form-actions"><el-button @click="creating = false" :disabled="busy">取消</el-button><el-button type="primary" native-type="submit" :loading="busy" :disabled="!name || !entry">创建并启动</el-button></div>
    </el-form>
    <el-table :data="workers" empty-text="暂无 PHP 常驻进程">
      <el-table-column label="进程名称" min-width="135"><template #default="{ row }"><strong>{{ row.name }}</strong><div class="worker-note">{{ row.entry }}</div></template></el-table-column>
      <el-table-column label="PHP / PID" min-width="125"><template #default="{ row }">{{ row.observed_release_id.replace('php-', '') }}<div class="worker-note">PID {{ row.pid || '—' }}</div></template></el-table-column>
      <el-table-column label="状态" min-width="110"><template #default="{ row }"><el-tag :type="row.status === 'running' ? 'success' : row.status === 'failed' ? 'danger' : 'info'">{{ statusLabel[row.status] || row.status }}</el-tag><div v-if="row.last_error" class="worker-note">{{ row.last_error }}</div></template></el-table-column>
      <el-table-column label="操作" min-width="230"><template #default="{ row }"><el-button link type="primary" :disabled="busy" @click="action(row, row.status === 'running' ? 'stop' : 'start')">{{ row.status === 'running' ? '停止' : '启动' }}</el-button><el-button link type="primary" :disabled="busy" @click="action(row, 'restart')">重启</el-button><el-button link type="primary" :disabled="busy" @click="logs(row)">日志</el-button><el-button link type="danger" :disabled="busy" @click="remove(row)">删除</el-button></template></el-table-column>
    </el-table>
    <el-dialog v-model="logVisible" :title="'PHP 进程日志 · ' + logName" width="min(850px, 95vw)" append-to-body><pre class="worker-log">{{ logText || '暂无日志' }}</pre></el-dialog>
  </div>
</template>

<style scoped>
.php-workers { display: grid; gap: 14px; min-width: 0; }
.worker-toolbar { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.worker-toolbar span { margin-right: auto; color: #60718e; }
.worker-form { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 0 20px; padding: 18px; border: 1px solid #e4eaf2; border-radius: 6px; }
.worker-arguments, .worker-form-actions { grid-column: 1 / -1; }
.worker-arguments small, .worker-note { color: #78869b; font-size: 12px; margin-top: 5px; overflow-wrap: anywhere; }
.worker-form-actions { display: flex; justify-content: flex-end; }
.worker-form :deep(.el-select), .worker-form :deep(.el-input-number) { width: 100%; }
.worker-log { max-height: 60vh; overflow: auto; white-space: pre-wrap; overflow-wrap: anywhere; padding: 16px; background: #151b22; color: #d4e2ef; border-radius: 5px; }
@media (max-width: 600px) { .worker-form { grid-template-columns: minmax(0, 1fr); padding: 12px; } }
</style>
