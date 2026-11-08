<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from "vue";
import { ElMessage, ElMessageBox } from "element-plus";
interface Account {
  id: string;
  server_id: string;
  name: string;
  username: string;
  role: string;
  database_ids: string[];
  enabled: boolean;
  status: string;
  revision: number;
}
interface Credential {
  username: string;
  password: string;
  host: string;
  port: number;
  databases: string[];
  enabled: boolean;
}
interface RemovalPlan {
  account_id: string;
  revision: number;
  status: string;
  connections: number;
  references: { kind: string; database: string; name: string }[];
  blocked_reasons: string[];
}
const props = defineProps<{
  api: <T>(path: string, method?: string, body?: unknown) => Promise<T>;
  servers: { id: string; name: string; release_id: string; status: string }[];
  databases: { id: string; server_id: string; name: string; status: string }[];
  onJob: (id: string) => Promise<void>;
}>();
const emit = defineEmits<{ changed: [] }>();
const accounts = ref<Account[]>([]),
  error = ref(""),
  dialogError = ref(""),
  busy = ref(false),
  open = ref(false),
  credentialsOpen = ref(false),
  credential = ref<Credential>(),
  editing = ref<Account>(),
  page = ref(1),
  name = ref(""),
  serverID = ref(""),
  role = ref("readonly"),
  databaseIDs = ref<string[]>([]),
  confirm = ref("");
const scope = ref("active"),
  recycleOpen = ref(false),
  recycleTarget = ref<Account>(),
  recyclePlan = ref<RemovalPlan>(),
  recycleConfirm = ref("");
const referenceKinds: Record<string, string> = {
  view: "视图",
  routine: "存储程序",
  trigger: "触发器",
  event: "事件",
};
const roles = [
  {
    id: "readonly",
    label: "只读",
    description: "查询数据与查看视图，不可修改数据。",
  },
  {
    id: "readwrite",
    label: "读写",
    description: "直接增删改查、执行存储过程，不直接授予表结构权限。",
  },
  {
    id: "manager",
    label: "库管理",
    description: "管理所选库的数据、表、视图及存储过程。",
  },
];
const roleLabel = (value: string) =>
  roles.find((r) => r.id === value)?.label || value;
const serverName = (id: string) =>
  props.servers.find((s) => s.id === id)?.name || id;
const dbName = (id: string) =>
  props.databases.find((d) => d.id === id)?.name || id;
const available = computed(() =>
  props.databases.filter(
    (d) => d.server_id === serverID.value && d.status === "ready",
  ),
);
const filtered = computed(() =>
  accounts.value.filter((a) =>
    scope.value === "trash"
      ? a.status === "quarantined"
      : a.status !== "quarantined",
  ),
);
const visible = computed(() =>
  filtered.value.slice((page.value - 1) * 5, page.value * 5),
);
watch(scope, () => {
  page.value = 1;
});
let timer: ReturnType<typeof setInterval>;
watch(serverID, () => {
  if (!editing.value) databaseIDs.value = [];
});
async function refresh() {
  try {
    accounts.value = await props.api<Account[]>("/databases/accounts");
    error.value = "";
  } catch (e) {
    error.value = (e as Error).message;
  }
}
function begin(a?: Account) {
  if (!a) {
    scope.value = "active";
    page.value = 1;
  }
  editing.value = a;
  serverID.value =
    a?.server_id || props.servers.find((s) => s.status === "running")?.id || "";
  name.value = a?.name || "";
  role.value = a?.role || "readonly";
  databaseIDs.value = a ? [...a.database_ids] : [];
  confirm.value = "";
  dialogError.value = "";
  open.value = true;
}
async function submit() {
  if (busy.value) return;
  busy.value = true;
  dialogError.value = "";
  try {
    const a = editing.value;
    const endpoint = a
      ? `/databases/accounts/${a.id}/permissions`
      : "/databases/accounts";
    const body = a
      ? {
          revision: a.revision,
          confirm_name: confirm.value,
          role: role.value,
          database_ids: databaseIDs.value,
        }
      : {
          server_id: serverID.value,
          name: name.value,
          role: role.value,
          database_ids: databaseIDs.value,
        };
    const j = await props.api<{ job_id: string }>(endpoint, "POST", body);
    open.value = false;
    await refresh();
    emit("changed");
    await props.onJob(j.job_id);
  } catch (e) {
    dialogError.value = (e as Error).message;
  } finally {
    busy.value = false;
  }
}
async function operate(a: Account, action: string) {
  const rotate = action === "rotate-password";
  const title = rotate
    ? "更新数据库账号密码"
    : action === "disable"
      ? "停用数据库账号"
      : "启用数据库账号";
  const text = rotate
    ? `将生成“${a.name}”的新密码并结束其直接连接，完成后需要更新应用连接配置。`
    : action === "disable"
      ? `将阻止“${a.name}”直接登录并结束现有连接。以该账号为 DEFINER 的既有视图和存储程序保持原语义。`
      : `将恢复“${a.name}”在已授权数据库内的登录能力。`;
  try {
    await ElMessageBox.prompt(text + " 请输入账号名称确认。", title, {
      confirmButtonText: rotate
        ? "生成新密码"
        : action === "disable"
          ? "停用账号"
          : "启用账号",
      cancelButtonText: "取消",
      inputValidator: (v) => v === a.name || "请输入完全一致的账号名称",
    });
    busy.value = true;
    const j = await props.api<{ job_id: string }>(
      `/databases/accounts/${a.id}/${action}`,
      "POST",
      { revision: a.revision, confirm_name: a.name },
    );
    await refresh();
    await props.onJob(j.job_id);
  } catch (e) {
    if (e !== "cancel" && e !== "close") ElMessage.error((e as Error).message);
  } finally {
    busy.value = false;
  }
}
async function showCredential(a: Account) {
  try {
    credential.value = await props.api<Credential>(
      `/databases/accounts/${a.id}/credentials`,
      "POST",
      {},
    );
    credentialsOpen.value = true;
  } catch (e) {
    ElMessage.error((e as Error).message);
  }
}
async function showJob(a: Account) {
  try {
    const j = await props.api<{ job_id: string }>(
      `/databases/accounts/${a.id}/latest-job`,
    );
    await props.onJob(j.job_id);
  } catch (e) {
    ElMessage.error((e as Error).message);
  }
}
async function beginRecycle(a: Account) {
  try {
    const plan = await props.api<RemovalPlan>(
      `/databases/accounts/${a.id}/removal-plan`,
    );
    if (plan.revision !== a.revision || plan.account_id !== a.id)
      throw new Error("账号状态已变化，请刷新后重新查看影响范围");
    recycleTarget.value = a;
    recyclePlan.value = plan;
    recycleConfirm.value = "";
    dialogError.value = "";
    recycleOpen.value = true;
  } catch (e) {
    ElMessage.error((e as Error).message);
    await refresh();
  }
}
async function submitRecycle() {
  const a = recycleTarget.value,
    plan = recyclePlan.value;
  if (
    !a ||
    !plan ||
    busy.value ||
    plan.blocked_reasons.length ||
    recycleConfirm.value !== a.name
  )
    return;
  busy.value = true;
  try {
    const restore = a.status === "quarantined";
    const j = await props.api<{ job_id: string }>(
      `/databases/accounts/${a.id}/${restore ? "restore" : "quarantine"}`,
      "POST",
      { revision: plan.revision, confirm_name: recycleConfirm.value },
    );
    recycleOpen.value = false;
    scope.value = restore ? "active" : "trash";
    page.value = 1;
    await refresh();
    await props.onJob(j.job_id);
  } catch (e) {
    dialogError.value = (e as Error).message;
  } finally {
    busy.value = false;
  }
}
onMounted(() => {
  refresh();
  timer = setInterval(refresh, 4000);
});
onUnmounted(() => {
  clearInterval(timer);
  credential.value = undefined;
});
</script>
<template>
  <section class="panel-card list-card database-account-section">
    <div class="table-toolbar">
      <div>
        <h2>数据库账号</h2>
        <small class="muted"
          >为应用或报表设置独立账号，精确选择数据库和权限。</small
        >
      </div>
      <el-button type="primary" @click="begin()">创建账号</el-button>
    </div>
    <el-alert v-if="error" :title="error" type="error" :closable="false" />
    <el-radio-group
      v-model="scope"
      aria-label="数据库账号列表范围"
      class="account-scope"
    >
      <el-radio-button value="active">使用中</el-radio-button>
      <el-radio-button value="trash">账号回收站</el-radio-button>
    </el-radio-group>
    <p v-if="scope === 'trash'" class="account-empty">
      回收账号已锁定且撤销授权。原身份、名称和凭据仍保留，恢复后使用原密码与原启停状态。
    </p>
    <div v-if="!filtered.length" class="account-empty">
      {{
        scope === "trash"
          ? "暂无回收账号。"
          : "可在这里增加只读、读写或库管理账号；现有每库应用账号继续使用。"
      }}
    </div>
    <article
      v-for="a in visible"
      :key="a.id"
      class="account-row"
      :data-account-id="a.id"
    >
      <div class="account-title">
        <strong>{{ a.name }}</strong
        ><el-tag
          size="small"
          :type="
            a.status === 'ready' ? (a.enabled ? 'success' : 'info') : 'warning'
          "
          >{{
            a.status === "ready"
              ? a.enabled
                ? "已启用"
                : "已停用"
              : a.status === "quarantined"
                ? "已回收"
                : a.status === "needs_attention"
                  ? "待核对"
                  : "操作中"
          }}</el-tag
        ><el-tag size="small" type="info"
          >{{ a.status === "quarantined" ? "原权限：" : ""
          }}{{ roleLabel(a.role) }}</el-tag
        >
      </div>
      <div class="account-details">
        <code>{{ a.username }}</code
        ><small>{{ serverName(a.server_id) }}</small
        ><small>授权数据库：{{ a.database_ids.map(dbName).join("、") }}</small>
      </div>
      <div class="account-actions">
        <template v-if="a.status !== 'quarantined'">
          <el-button
            size="small"
            :disabled="busy || a.status !== 'ready'"
            @click="showCredential(a)"
            >连接信息</el-button
          ><el-button
            size="small"
            :disabled="busy || a.status !== 'ready'"
            @click="begin(a)"
            >权限</el-button
          ><el-button
            size="small"
            :disabled="busy || a.status !== 'ready'"
            @click="operate(a, 'rotate-password')"
            >更新密码</el-button
          ><el-button
            size="small"
            :disabled="busy || a.status !== 'ready'"
            @click="operate(a, a.enabled ? 'disable' : 'enable')"
            >{{ a.enabled ? "停用" : "启用" }}</el-button
          >
          <el-button
            size="small"
            type="danger"
            plain
            :disabled="busy || a.status !== 'ready'"
            @click="beginRecycle(a)"
            >移入回收站</el-button
          >
        </template>
        <el-button
          v-else
          size="small"
          type="primary"
          :disabled="busy"
          @click="beginRecycle(a)"
          >恢复账号</el-button
        >
        <el-button size="small" text @click="showJob(a)">查看任务</el-button>
      </div>
    </article>
    <el-pagination
      v-if="filtered.length > 5"
      v-model:current-page="page"
      :page-size="5"
      :total="filtered.length"
      layout="prev, pager, next"
    />
  </section>
  <el-dialog
    v-model="open"
    :title="editing ? '修改数据库权限' : '创建数据库账号'"
    width="640px"
    class="database-account-dialog"
    :close-on-click-modal="!busy"
    :close-on-press-escape="!busy"
    :show-close="!busy"
    destroy-on-close
  >
    <el-alert
      v-if="dialogError"
      :title="dialogError"
      type="error"
      :closable="false"
    /><el-form label-position="top" @submit.prevent="submit">
      <el-form-item label="所属 MySQL 实例"
        ><el-select
          v-model="serverID"
          aria-label="账号所属实例"
          :disabled="!!editing || busy"
          style="width: 100%"
          ><el-option
            v-for="s in servers"
            :key="s.id"
            :value="s.id"
            :label="s.name + ' · ' + s.release_id"
            :disabled="s.status !== 'running'" /></el-select
      ></el-form-item>
      <el-form-item label="账号名称"
        ><el-input
          v-model="name"
          aria-label="数据库账号名称"
          :disabled="!!editing || busy"
          maxlength="40"
          placeholder="例如 报表只读账号"
        /><small class="muted"
          >填写用途名称，系统分配独立的 MySQL 用户名和随机密码。</small
        ></el-form-item
      >
      <el-form-item label="授权数据库"
        ><el-select
          v-model="databaseIDs"
          multiple
          collapse-tags
          :max-collapse-tags="3"
          collapse-tags-tooltip
          aria-label="账号授权数据库"
          :disabled="busy"
          placeholder="选择同一实例中的数据库"
          style="width: 100%"
          ><el-option
            v-for="d in available"
            :key="d.id"
            :value="d.id"
            :label="d.name" /></el-select
        ><small class="muted"
          >仅列出已完成创建或导入的数据库，最多选择 32 个。</small
        ></el-form-item
      >
      <el-form-item label="账号权限"
        ><el-radio-group
          v-model="role"
          aria-label="账号权限档位"
          :disabled="busy"
          class="account-role-options"
          ><el-radio v-for="r in roles" :key="r.id" :value="r.id" border
            ><strong>{{ r.label }}</strong
            ><small>{{ r.description }}</small></el-radio
          ></el-radio-group
        ></el-form-item
      >
      <div class="account-review">
        {{ editing ? "将调整" : "将授予" }}
        <strong>{{ name || "新账号" }}</strong> 对
        <strong>{{
          databaseIDs.map(dbName).join("、") || "所选数据库"
        }}</strong>
        的{{ roleLabel(role) }}权限。{{
          editing
            ? "权限更新会结束该账号的现有直接连接。"
            : "账号仅允许从服务器本机连接。"
        }}
      </div>
      <p class="muted">
        权限按 MySQL 授权生效；已有 DEFINER 视图和存储程序使用其定义者权限。
      </p>
      <el-form-item v-if="editing" label="确认账号名称"
        ><el-input
          v-model="confirm"
          aria-label="确认权限账号名称"
          :disabled="busy"
      /></el-form-item> </el-form
    ><template #footer
      ><el-button :disabled="busy" @click="open = false">取消</el-button
      ><el-button
        type="primary"
        :loading="busy"
        :disabled="
          !serverID ||
          !name ||
          !databaseIDs.length ||
          databaseIDs.length > 32 ||
          (!!editing && confirm !== name)
        "
        @click="submit"
        >{{ editing ? "应用权限" : "创建账号" }}</el-button
      ></template
    >
  </el-dialog>
  <el-dialog
    v-model="credentialsOpen"
    title="数据库账号连接信息"
    width="540px"
    class="database-account-dialog"
    @closed="credential = undefined"
  >
    <template v-if="credential"
      ><el-alert
        v-if="!credential.enabled"
        title="账号已停用，重新启用后才可直接连接。"
        type="info"
        :closable="false"
      /><el-form label-position="top"
        ><el-form-item label="MySQL 用户名"
          ><el-input
            :model-value="credential.username"
            aria-label="MySQL 账号用户名"
            readonly /></el-form-item
        ><el-form-item label="密码"
          ><el-input
            :model-value="credential.password"
            type="password"
            show-password
            aria-label="MySQL 账号密码"
            readonly /></el-form-item
        ><el-form-item label="本机地址"
          ><el-input
            :model-value="credential.host + ':' + credential.port"
            readonly /></el-form-item
        ><el-form-item label="授权数据库"
          ><span>{{ credential.databases.join("、") }}</span></el-form-item
        ></el-form
      ></template
    >
  </el-dialog>
  <el-dialog
    v-model="recycleOpen"
    :title="
      recycleTarget?.status === 'quarantined'
        ? '恢复数据库账号'
        : '数据库账号回收确认'
    "
    width="640px"
    class="database-account-dialog"
    :close-on-click-modal="!busy"
    :close-on-press-escape="!busy"
    :show-close="!busy"
    destroy-on-close
  >
    <template v-if="recycleTarget && recyclePlan">
      <el-alert
        v-if="dialogError"
        :title="dialogError"
        type="error"
        :closable="false"
      />
      <el-alert
        v-for="reason in recyclePlan.blocked_reasons"
        :key="reason"
        :title="reason"
        type="warning"
        :closable="false"
      />
      <div class="account-review">
        <strong>{{ recycleTarget.name }}</strong>
        <p>
          <code>{{ recycleTarget.username }}</code>
        </p>
        <p>所属实例：{{ serverName(recycleTarget.server_id) }}</p>
        <p>
          原权限：{{ roleLabel(recycleTarget.role) }} · 原状态：{{
            recycleTarget.enabled ? "启用" : "停用"
          }}
        </p>
        <p>数据库：{{ recycleTarget.database_ids.map(dbName).join("、") }}</p>
        <p>当前直接连接：{{ recyclePlan.connections }}</p>
      </div>
      <p v-if="recycleTarget.status === 'quarantined'">
        将恢复原数据库权限和原密码。{{
          recycleTarget.enabled
            ? "账号恢复后可登录。"
            : "账号原来已停用，恢复后仍保持停用。"
        }}
      </p>
      <p v-else>
        将锁定登录、结束直接连接并撤销授权。原身份、名称和密码保留，可从账号回收站恢复；应用中的连接配置需要由使用者处理。
      </p>
      <ul v-if="recyclePlan.references.length" class="account-reference-list">
        <li v-for="(r, i) in recyclePlan.references" :key="i">
          {{ referenceKinds[r.kind] || r.kind }}：{{ r.database }}.{{ r.name }}
        </li>
      </ul>
      <el-form label-position="top" @submit.prevent="submitRecycle"
        ><el-form-item label="输入账号名称确认"
          ><el-input
            v-model="recycleConfirm"
            aria-label="确认回收或恢复账号名称"
            :disabled="busy" /></el-form-item
      ></el-form>
    </template>
    <template #footer
      ><el-button :disabled="busy" @click="recycleOpen = false">取消</el-button
      ><el-button
        :type="recycleTarget?.status === 'quarantined' ? 'primary' : 'danger'"
        :loading="busy"
        :disabled="
          !recycleTarget ||
          !recyclePlan ||
          recyclePlan.blocked_reasons.length > 0 ||
          recycleConfirm !== recycleTarget.name
        "
        @click="submitRecycle"
        >{{
          recycleTarget?.status === "quarantined" ? "恢复账号" : "移入回收站"
        }}</el-button
      ></template
    >
  </el-dialog>
</template>
<style scoped>
.account-scope {
  margin: 0 22px 18px;
}
.account-reference-list {
  padding-left: 20px;
  overflow-wrap: anywhere;
}
.account-empty {
  padding: 24px;
  color: #718078;
  font-size: 13px;
}
.account-row {
  padding: 20px 22px;
  border-top: 1px solid #e9efeb;
  display: grid;
  gap: 10px;
}
.account-title {
  display: flex;
  align-items: center;
  gap: 10px;
  flex-wrap: wrap;
}
.account-title strong {
  overflow-wrap: anywhere;
}
.account-details {
  display: flex;
  flex-wrap: wrap;
  gap: 8px 18px;
  align-items: center;
  font-size: 12px;
  color: #708278;
}
.account-details code {
  font-size: 12px;
}
.account-details small {
  overflow-wrap: anywhere;
}
.account-actions {
  display: flex;
  gap: 7px;
  flex-wrap: wrap;
  margin-top: 4px;
}
.account-actions .el-button {
  margin: 0;
}
.database-account-section .el-pagination {
  margin: 16px;
}
.account-role-options {
  display: grid;
  gap: 9px;
  width: 100%;
}
.account-role-options .el-radio {
  margin: 0;
  height: auto;
  min-height: 62px;
  padding: 14px;
  white-space: normal;
}
.account-role-options small {
  display: block;
  font-size: 12px;
  color: #72867b;
  line-height: 1.7;
  font-weight: 400;
  margin-top: 4px;
}
.account-review {
  padding: 14px;
  background: #f2f8f5;
  border: 1px solid #dfe9e2;
  border-radius: 8px;
  font-size: 13px;
  line-height: 1.9;
  margin: 0 0 20px;
  overflow-wrap: anywhere;
}
.el-form-item small {
  margin-top: 5px;
  line-height: 1.6;
}
@media (max-width: 680px) {
  .account-row {
    padding: 16px;
  }
  .database-account-section .table-toolbar {
    align-items: flex-start;
  }
  .account-actions {
    gap: 8px 6px;
  }
}
</style>
<style>
.database-account-dialog {
  max-height: 90vh;
  max-width: calc(100vw - 24px);
  margin-top: 5vh;
  display: flex;
  flex-direction: column;
}
.database-account-dialog .el-dialog__body {
  overflow: auto;
}
.database-account-dialog .el-dialog__footer {
  flex-shrink: 0;
}
.database-account-dialog .el-alert {
  margin-bottom: 16px;
}
</style>
