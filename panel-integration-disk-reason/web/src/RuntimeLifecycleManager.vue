<script setup lang="ts">
import { formatPanelDateTime } from "./panelTime";
import { ref } from "vue";
import { ElMessage, ElMessageBox } from "element-plus";
interface Reference {
  kind: string;
  id: string;
  name: string;
  state: string;
}
interface Inventory {
  release_id: string;
  recorded: Reference[];
  actual: Reference[];
  referenced: boolean;
  checked_at: string;
}
const props = defineProps<{
  api: <T>(path: string, method?: string, body?: unknown) => Promise<T>;
  onJob: (id: string) => Promise<void>;
  retired: { id: string; retired_at: string; architecture: string }[];
  busy: (id: string) => boolean;
}>();
const open = ref(false),
  loading = ref(false),
  reference = ref<Inventory | null>(null),
  error = ref("");
const kindNames: Record<string, string> = {
  site: "网站绑定",
  mysql_instance: "数据库实例",
  nginx_ingress: "全局入口",
  site_job: "网站任务",
  runtime_job: "环境任务",
  nginx_selection: "实际入口",
  rollback_guard: "切换恢复保护",
  php_binding: "FPM / CLI 绑定",
  mysql_manifest: "数据库绑定",
  redis_manifest: "Redis 实例绑定",
  node_manifest: "Node.js 项目绑定",
  mariadb_manifest: "MariaDB 实例绑定",
  mysql_job: "数据库任务",
  install_job: "安装任务",
  process: "实际进程",
};
const stateNames: Record<string, string> = {
  running: "运行中",
  stopped: "已停用",
  bound: "已绑定",
  selected: "当前选择",
  pending: "待核对",
  queued: "排队中",
  needs_attention: "需核对",
};
async function inspect(id: string) {
  open.value = true;
  loading.value = true;
  error.value = "";
  reference.value = null;
  try {
    reference.value = await props.api<Inventory>(`/runtimes/${id}/references`);
  } catch (e) {
    error.value = (e as Error).message;
  } finally {
    loading.value = false;
  }
}
async function act(id: string, action: "retire" | "restore" | "purge") {
  const labels = {
    retire: "卸载并保留恢复副本",
    restore: "恢复运行环境",
    purge: "永久清理恢复副本",
  };
  try {
    if (action === "retire") {
      await inspect(id);
      if (!reference.value || reference.value.referenced) return;
    }
    const message =
      action === "retire"
        ? `将 ${id} 的独立程序目录移入私有恢复副本，保留网站、数据库及配置。执行时会再次检查所有引用。`
        : action === "restore"
          ? `核对 ${id} 恢复副本的完整性，并恢复到原安装目录。`
          : `永久删除 ${id} 的恢复副本。此后无法从该副本恢复；该版本新安装的程序目录保持不动。`;
    const { value } = await ElMessageBox.prompt(
      message + ` 请输入 ${id} 确认。`,
      labels[action],
      {
        confirmButtonText: action === "purge" ? "永久清理" : "确认执行",
        cancelButtonText: "取消",
        inputPlaceholder: id,
        inputValidator: (v: string) => v === id || "请输入完全一致的版本标识",
        type: action === "purge" ? "warning" : "info",
      },
    );
    const result = await props.api<{ job_id: string }>(
      `/runtimes/${id}/lifecycle/${action}`,
      "POST",
      { confirm_version: value },
    );
    open.value = false;
    await props.onJob(result.job_id);
  } catch (e) {
    if (e instanceof Error) ElMessage.error(e.message);
  }
}
defineExpose({ inspect, retire: (id: string) => act(id, "retire") });
</script>
<template>
  <section v-if="retired.length" class="panel-card runtime-retired">
    <div class="card-heading">
      <div>
        <h2>运行环境恢复副本</h2>
        <p>已卸载版本保留在这里，可恢复或永久清理。</p>
      </div>
    </div>
    <div
      v-for="item in retired"
      :key="item.id"
      class="retired-item"
      :data-release="item.id"
    >
      <div>
        <strong>{{ item.id }}</strong
        ><small
          >{{ item.architecture }} ·
          {{ formatPanelDateTime(item.retired_at) }}</small
        >
      </div>
      <div class="retired-actions">
        <el-button :disabled="busy(item.id)" @click="act(item.id, 'restore')"
          >恢复</el-button
        ><el-button
          type="danger"
          plain
          :disabled="busy(item.id)"
          @click="act(item.id, 'purge')"
          >永久清理</el-button
        >
      </div>
    </div>
  </section>
  <el-dialog
    v-model="open"
    title="运行环境引用检查"
    width="760px"
    class="runtime-reference-dialog"
    :close-on-click-modal="false"
  >
    <div v-loading="loading" style="min-height: 100px">
      <el-alert v-if="error" :title="error" type="error" :closable="false" />
      <template v-if="reference">
        <p class="reference-version">{{ reference.release_id }}</p>
        <el-alert
          :type="reference.referenced ? 'warning' : 'success'"
          :title="
            reference.referenced
              ? '此版本仍有引用，不能卸载'
              : '未发现版本引用，可以卸载并保留恢复副本'
          "
          :closable="false"
        />
        <p class="reference-help">
          停用的网站和数据库仍保留版本绑定。执行卸载时会再次核对当前状态。
        </p>
        <div
          v-for="group in [
            { title: '面板记录', items: reference.recorded },
            { title: '执行器实际状态', items: reference.actual },
          ]"
          :key="group.title"
          class="reference-group"
        >
          <h3>
            {{ group.title }} <span>{{ group.items.length }}</span>
          </h3>
          <p v-if="!group.items.length" class="reference-empty">无引用</p>
          <div
            v-for="item in group.items"
            :key="item.kind + item.id"
            class="reference-item"
          >
            <strong>{{ item.name }}</strong
            ><small
              >{{ kindNames[item.kind] || item.kind }} ·
              {{ stateNames[item.state] || item.state }}</small
            ><code>{{ item.id }}</code>
          </div>
        </div>
      </template>
    </div>
    <template #footer
      ><el-button @click="open = false">关闭</el-button
      ><el-button
        v-if="
          reference &&
          !reference.referenced &&
          reference.release_id !== 'nginx-system'
        "
        type="warning"
        :disabled="busy(reference.release_id)"
        @click="act(reference.release_id, 'retire')"
        >卸载并保留副本</el-button
      ></template
    >
  </el-dialog>
</template>
<style scoped>
.runtime-retired {
  margin-top: 20px;
}
.retired-item {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  padding: 18px 24px;
  border-top: 1px solid #edf0ef;
}
.retired-item small {
  display: block;
  color: #73867c;
  font-size: 12px;
  margin-top: 6px;
}
.reference-version {
  font-size: 18px;
  font-weight: 650;
  word-break: break-all;
}
.reference-help,
.reference-empty {
  font-size: 13px;
  color: #6e7f75;
  line-height: 1.7;
}
.reference-group {
  margin-top: 22px;
}
.reference-group h3 {
  font-size: 14px;
}
.reference-group h3 span {
  font-weight: 400;
  margin-left: 8px;
  color: #73867c;
}
.reference-item {
  padding: 12px 0;
  border-top: 1px solid #edf0ef;
  display: flex;
  flex-direction: column;
  gap: 5px;
  word-break: break-all;
}
.reference-item small {
  color: #73867c;
}
.reference-item code {
  font-size: 11px;
  color: #596c60;
}
.retired-actions {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}
.retired-actions .el-button {
  margin: 0;
}
@media (max-width: 640px) {
  .retired-item {
    align-items: flex-start;
    flex-direction: column;
    padding: 16px;
  }
  .reference-item {
    font-size: 13px;
  }
}
</style>
<style>
.runtime-reference-dialog {
  max-width: calc(100vw - 24px);
}
.runtime-reference-dialog .el-dialog__body {
  max-height: 65vh;
  overflow: auto;
}
</style>
