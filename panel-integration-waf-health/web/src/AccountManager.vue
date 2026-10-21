<script setup lang="ts">
import { onMounted, onBeforeUnmount, ref } from "vue";
import { ElMessage } from "element-plus";
const props = defineProps<{
  api: <T>(path: string, method?: string, body?: unknown) => Promise<T>;
  onSession: (value: { username: string; csrf: string }) => void;
  onBusy: (busy: boolean) => void;
}>();
interface State {
  username: string;
  totp_enabled: boolean;
  recovery_remaining: number;
  server_time: string;
}
interface Result {
  username: string;
  csrf: string;
  secret?: string;
  uri?: string;
  expires_at?: number;
  recovery_codes?: string[];
}
const state = ref<State | null>(null),
  loading = ref(false),
  busy = ref(false),
  error = ref(""),
  open = ref(false),
  action = ref(""),
  step = ref("verify");
const password = ref(""),
  code = ref(""),
  newPassword = ref(""),
  repeatPassword = ref(""),
  secret = ref(""),
  uri = ref(""),
  expiresAt = ref(0),
  codes = ref<string[]>([]),
  saved = ref(false);
const titles: Record<string, string> = {
  setup: "开启双重验证",
  disable: "关闭双重验证",
  recovery: "重新生成恢复码",
  password: "修改管理员密码",
};
function clear() {
  password.value = "";
  code.value = "";
  newPassword.value = "";
  repeatPassword.value = "";
  secret.value = "";
  uri.value = "";
  codes.value = [];
  saved.value = false;
  expiresAt.value = 0;
}
async function refresh() {
  loading.value = true;
  error.value = "";
  try {
    state.value = await props.api<State>("/account");
  } catch (e) {
    error.value = (e as Error).message;
  } finally {
    loading.value = false;
  }
}
function begin(value: string) {
  clear();
  error.value = "";
  action.value = value;
  step.value = "verify";
  open.value = true;
}
function close(done: () => void) {
  if (busy.value) return;
  if (step.value === "codes" && !saved.value) {
    ElMessage.warning("请先保存恢复码，并勾选已保存");
    return;
  }
  clear();
  done();
}
async function submit() {
  if (!password.value) {
    error.value = "请输入当前密码";
    return;
  }
  if (
    action.value === "password" &&
    (newPassword.value !== repeatPassword.value ||
      newPassword.value.length < 12)
  ) {
    error.value = "新密码至少 12 字符，且两次输入一致";
    return;
  }
  busy.value = true;
  props.onBusy(true);
  error.value = "";
  try {
    const operation =
      action.value === "setup" && step.value === "secret"
        ? "confirm"
        : action.value;
    const result = await props.api<Result>("/account/" + operation, "POST", {
      password: password.value,
      code: code.value,
      new_password: action.value === "password" ? newPassword.value : "",
    });
    if (result.csrf)
      props.onSession({ username: result.username, csrf: result.csrf });
    if (result.secret) {
      secret.value = result.secret;
      uri.value = result.uri || "";
      expiresAt.value = result.expires_at || 0;
      step.value = "secret";
      code.value = "";
    } else if (result.recovery_codes) {
      codes.value = result.recovery_codes;
      secret.value = "";
      uri.value = "";
      password.value = "";
      code.value = "";
      step.value = "codes";
      await refresh();
    } else {
      clear();
      open.value = false;
      ElMessage.success("账户设置已更新，旧会话已撤销");
      await refresh();
    }
  } catch (e) {
    error.value = (e as Error).message;
  } finally {
    busy.value = false;
    props.onBusy(false);
  }
}
async function copy(value: string) {
  try {
    await navigator.clipboard.writeText(value);
    ElMessage.success("已复制");
  } catch {
    ElMessage.warning("无法自动复制，请选择文本手动复制");
  }
}
function download() {
  const blob = new Blob(
    [
      "自有面板 · " +
        (state.value?.username || "") +
        "\n一次性恢复码，每个只能使用一次，请离线保管。\n\n" +
        codes.value.join("\n") +
        "\n",
    ],
    { type: "text/plain;charset=utf-8" },
  );
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = "panel-recovery-codes.txt";
  link.click();
  URL.revokeObjectURL(url);
}
defineExpose({ refresh });
onMounted(refresh);
onBeforeUnmount(() => {
  clear();
  props.onBusy(false);
});
</script>
<template>
  <div v-loading="loading" class="account-page">
    <el-alert
      v-if="error && !open"
      :title="error"
      type="error"
      :closable="false"
    />
    <section v-if="state" class="panel-card account-card">
      <div class="account-card-heading">
        <div>
          <span class="account-eyebrow">管理员账户</span>
          <h2>{{ state.username }}</h2>
        </div>
        <el-button @click="refresh">重新读取</el-button>
      </div>
      <div class="account-row">
        <div>
          <h3>登录密码</h3>
          <p>
            使用至少 12 字符的独立密码。修改后，其他已登录设备需要重新登录。
          </p>
        </div>
        <el-button @click="begin('password')">修改密码</el-button>
      </div>
      <div class="account-row">
        <div>
          <h3>
            验证器双重验证
            <el-tag :type="state.totp_enabled ? 'success' : 'info'">{{
              state.totp_enabled ? "已开启" : "未开启"
            }}</el-tag>
          </h3>
          <p>
            使用兼容 TOTP 的验证器生成 6 位动态码，每 30
            秒更新。登录时同时验证密码与动态码。
          </p>
        </div>
        <el-button
          :type="state.totp_enabled ? 'warning' : 'primary'"
          plain
          @click="begin(state.totp_enabled ? 'disable' : 'setup')"
          >{{ state.totp_enabled ? "关闭双重验证" : "开启双重验证" }}</el-button
        >
      </div>
      <div v-if="state.totp_enabled" class="account-row">
        <div>
          <h3>
            一次性恢复码
            <el-tag type="info">剩余 {{ state.recovery_remaining }} 个</el-tag>
          </h3>
          <p>
            验证器不可用时，使用密码和一个未使用的恢复码登录。生成新码会作废所有旧码。
          </p>
        </div>
        <el-button @click="begin('recovery')">重新生成恢复码</el-button>
      </div>
    </section>
    <p class="account-help">
      忘记密码或丢失验证器及恢复码时，可在服务器本机使用管理员救援命令。服务器时间：{{
        state?.server_time
      }}
    </p>
    <el-dialog
      v-model="open"
      :title="step === 'codes' ? '保存一次性恢复码' : titles[action]"
      width="min(600px,95vw)"
      class="account-dialog"
      :close-on-click-modal="false"
      :close-on-press-escape="false"
      :before-close="close"
      @closed="clear"
    >
      <el-alert v-if="error" :title="error" type="error" :closable="false" />
      <template v-if="step === 'codes'"
        ><el-alert
          title="恢复码只显示这一次，请保存在面板之外。"
          type="warning"
          :closable="false"
        />
        <pre aria-label="一次性恢复码" class="recovery-codes">{{
          codes.join("\n")
        }}</pre>
        <div class="account-code-actions">
          <el-button @click="download">下载恢复码</el-button
          ><el-button @click="copy(codes.join('\n'))">复制恢复码</el-button>
        </div>
        <el-checkbox v-model="saved"
          >我已将恢复码保存在安全位置</el-checkbox
        ></template
      >
      <el-form v-else label-position="top" @submit.prevent="submit">
        <template v-if="step === 'secret'"
          ><p class="account-help">
            在验证器中手动添加账户，选择“基于时间”，输入下面的密钥。输入生成的 6
            位验证码后，才会正式启用。
          </p>
          <div class="account-secret" aria-label="验证器设置密钥">
            {{ secret }}
          </div>
          <div class="account-code-actions">
            <el-button @click="copy(secret)">复制设置密钥</el-button
            ><el-button @click="copy(uri)">复制验证器链接</el-button>
          </div>
          <p class="account-help">
            本次设置有效至
            {{ new Date(expiresAt * 1000).toLocaleTimeString("zh-CN") }}。
          </p></template
        >
        <el-form-item v-show="step !== 'secret'" label="当前密码"
          ><el-input
            v-model="password"
            aria-label="当前密码"
            type="password"
            autocomplete="current-password"
            show-password
        /></el-form-item>
        <template v-if="action === 'password'"
          ><el-form-item label="新密码"
            ><el-input
              v-model="newPassword"
              aria-label="新密码"
              type="password"
              autocomplete="new-password"
              show-password /></el-form-item
          ><el-form-item label="再次输入新密码"
            ><el-input
              v-model="repeatPassword"
              aria-label="再次输入新密码"
              type="password"
              autocomplete="new-password" /></el-form-item
        ></template>
        <el-form-item
          v-if="step === 'secret' || state?.totp_enabled"
          :label="step === 'secret' ? '验证器动态码' : '动态码或恢复码'"
          ><el-input
            v-model="code"
            :aria-label="step === 'secret' ? '验证器动态码' : '动态码或恢复码'"
            autocomplete="one-time-code"
            :maxlength="40"
            :placeholder="
              step === 'secret' ? '6 位验证码' : '6 位动态码或一次性恢复码'
            "
        /></el-form-item>
        <p v-if="step === 'verify'" class="account-help">
          验证当前身份后执行。完成修改后，所有旧会话会失效，当前设备将重新签发会话。
        </p>
      </el-form>
      <template #footer
        ><el-button
          v-if="step !== 'codes'"
          :disabled="busy"
          @click="close(() => (open = false))"
          >取消</el-button
        ><el-button
          v-if="step === 'codes'"
          type="primary"
          :disabled="!saved"
          @click="close(() => (open = false))"
          >完成</el-button
        ><el-button v-else type="primary" :loading="busy" @click="submit">{{
          step === "secret"
            ? "验证并启用"
            : action === "setup"
              ? "生成设置密钥"
              : "确认修改"
        }}</el-button></template
      >
    </el-dialog>
  </div>
</template>
<style scoped>
.account-card {
  max-width: 1060px;
}
.account-card-heading {
  padding: 26px;
  display: flex;
  justify-content: space-between;
  align-items: center;
}
.account-eyebrow {
  font-size: 12px;
  color: #7a8e82;
}
.account-card-heading h2 {
  margin: 10px 0 0;
  font-size: 24px;
}
.account-row {
  padding: 26px;
  border-top: 1px solid #eaf0ec;
  display: flex;
  gap: 24px;
  justify-content: space-between;
  align-items: center;
}
.account-row h3 {
  font-size: 16px;
  margin: 0 0 12px;
}
.account-row h3 .el-tag {
  margin-left: 10px;
}
.account-row p,
.account-help {
  font-size: 13px;
  color: #6b8074;
  line-height: 1.8;
  margin: 10px 0;
}
.account-row p {
  max-width: 650px;
}
.account-help {
  max-width: 1060px;
  margin-top: 18px;
}
.account-secret {
  padding: 18px;
  background: #f1f7f3;
  border: 1px solid #dce9e0;
  border-radius: 8px;
  font: 18px/1.7 monospace;
  word-break: break-all;
  user-select: all;
}
.account-code-actions {
  display: flex;
  gap: 12px;
  flex-wrap: wrap;
  margin: 16px 0;
}
.recovery-codes {
  background: #f4f8f5;
  padding: 18px;
  border-radius: 8px;
  font-size: 13px;
  line-height: 1.9;
  overflow-wrap: anywhere;
  white-space: pre-wrap;
}
.account-dialog .el-form {
  margin-top: 18px;
}
@media (max-width: 600px) {
  .account-row {
    align-items: flex-start;
    flex-direction: column;
    padding: 20px;
    gap: 10px;
  }
  .account-card-heading {
    padding: 20px;
  }
  .recovery-codes {
    font-size: 11px;
    padding: 12px;
  }
}
</style>
<style>
.account-dialog.el-dialog {
  display: flex;
  flex-direction: column;
  margin: 16px auto;
  max-height: calc(100dvh - 32px);
}
.account-dialog .el-dialog__body {
  overflow-y: auto;
  min-height: 0;
}
.account-dialog .el-dialog__footer {
  flex-shrink: 0;
}
</style>
