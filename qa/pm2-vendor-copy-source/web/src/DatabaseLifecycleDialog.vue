<script setup lang="ts">
import { computed, ref } from "vue";
import { ElMessage } from "element-plus";
interface Database {
  id: string;
  server_id: string;
  name: string;
  username: string;
  status: string;
  revision: number;
}
interface Plan {
  database_id: string;
  revision: number;
  status: string;
  connections: number;
  backup_count: number;
  accounts: { id: string; name: string; status: string }[];
  references: { kind: string; database: string; name: string }[];
  blocked_reasons: string[];
}
const props = defineProps<{
  api: <T>(path: string, method?: string, body?: unknown) => Promise<T>;
  servers: { id: string; name: string; release_id: string }[];
  onJob: (id: string) => Promise<void>;
}>();
const emit = defineEmits<{ changed: [scope: string] }>();
const open = ref(false),
  busy = ref(false),
  target = ref<Database>(),
  plan = ref<Plan>(),
  confirm = ref(""),
  error = ref("");
const selectedServer = computed(() =>
  props.servers.find((s) => s.id === target.value?.server_id),
);
const kinds: Record<string, string> = {
  account: "使用中的账号",
  recycled_account: "回收账号依赖",
  grant: "额外授权",
  view: "跨库视图",
  routine: "跨库存储程序",
  trigger: "跨库触发器",
  event: "跨库事件",
};
async function begin(db: Database) {
  try {
    const p = await props.api<Plan>(`/databases/items/${db.id}/removal-plan`);
    if (p.revision !== db.revision || p.database_id !== db.id)
      throw new Error("数据库状态已变化，请刷新后重新查看");
    target.value = db;
    plan.value = p;
    confirm.value = "";
    error.value = "";
    open.value = true;
  } catch (e) {
    ElMessage.error((e as Error).message);
  }
}
async function submit() {
  const db = target.value,
    p = plan.value;
  if (
    !db ||
    !p ||
    busy.value ||
    p.blocked_reasons.length ||
    confirm.value !== db.name
  )
    return;
  busy.value = true;
  try {
    const recover = db.status === "quarantined";
    const j = await props.api<{ job_id: string }>(
      `/databases/items/${db.id}/${recover ? "recover" : "quarantine"}`,
      "POST",
      { revision: p.revision, confirm_name: confirm.value },
    );
    open.value = false;
    emit("changed", recover ? "active" : "trash");
    await props.onJob(j.job_id);
  } catch (e) {
    error.value = (e as Error).message;
  } finally {
    busy.value = false;
  }
}
defineExpose({ begin });
</script>
<template>
  <el-dialog
    v-model="open"
    :title="target?.status === 'quarantined' ? '恢复数据库' : '数据库回收确认'"
    width="640px"
    class="database-lifecycle-dialog"
    :close-on-click-modal="!busy"
    :close-on-press-escape="!busy"
    :show-close="!busy"
    destroy-on-close
  >
    <template v-if="target && plan">
      <el-alert v-if="error" :title="error" type="error" :closable="false" />
      <el-alert
        v-for="reason in plan.blocked_reasons"
        :key="reason"
        :title="reason"
        type="warning"
        :closable="false"
      />
      <div class="lifecycle-summary">
        <strong>{{ target.name }}</strong>
        <p>
          {{ selectedServer?.name }} ·
          {{ selectedServer?.release_id }}
        </p>
        <p>
          每库应用账号：<code>{{ target.username }}</code>
        </p>
        <p>
          当前直接连接：{{ plan.connections }} · 已有备份：{{
            plan.backup_count
          }}
          份
        </p>
      </div>
      <p v-if="target.status === 'quarantined'">
        将恢复原数据库和每库应用账号的访问权限，继续使用原密码。依赖此库的回收账号需要在数据库恢复后单独恢复。
      </p>
      <p v-else>
        将锁定每库应用账号、结束其直接连接并撤销权限。数据库内容、原密码、库名和备份保留，可从数据库回收站恢复。
      </p>
      <p class="muted">
        数据仍占用磁盘，库名不能复用。MySQL
        全局管理员仍保留访问权；此操作不会删除实际数据。
      </p>
      <ul v-if="plan.references.length" class="lifecycle-references">
        <li v-for="(r, i) in plan.references" :key="i">
          {{ kinds[r.kind] || r.kind }}：{{ r.database }} / {{ r.name }}
        </li>
      </ul>
      <p
        v-if="plan.accounts.some((a) => a.status === 'quarantined')"
        class="muted"
      >
        回收账号的依赖记录保留。恢复顺序：先数据库，后账号。
      </p>
      <el-form label-position="top" @submit.prevent="submit"
        ><el-form-item label="输入数据库名称确认"
          ><el-input
            v-model="confirm"
            aria-label="确认回收或恢复数据库名称"
            :disabled="busy" /></el-form-item
      ></el-form>
    </template>
    <template #footer
      ><el-button :disabled="busy" @click="open = false">取消</el-button
      ><el-button
        :type="target?.status === 'quarantined' ? 'primary' : 'danger'"
        :loading="busy"
        :disabled="
          !target ||
          !plan ||
          plan.blocked_reasons.length > 0 ||
          confirm !== target.name
        "
        @click="submit"
        >{{
          target?.status === "quarantined" ? "恢复数据库" : "移入回收站"
        }}</el-button
      ></template
    >
  </el-dialog>
</template>
<style scoped>
.lifecycle-summary {
  padding: 16px;
  background: #f2f8f5;
  border: 1px solid #dfebe3;
  border-radius: 6px;
  margin: 18px 0;
  overflow-wrap: anywhere;
}
.lifecycle-summary p {
  margin: 10px 0 0;
  font-size: 13px;
}
.lifecycle-references {
  max-height: 180px;
  overflow: auto;
  overflow-wrap: anywhere;
  padding-left: 20px;
}
</style>
<style>
@media (max-width: 700px) {
  .database-lifecycle-dialog {
    width: calc(100vw - 28px) !important;
    margin-top: 5vh !important;
  }
  .database-lifecycle-dialog .el-dialog__body {
    max-height: 65vh;
    overflow: auto;
  }
}
</style>
