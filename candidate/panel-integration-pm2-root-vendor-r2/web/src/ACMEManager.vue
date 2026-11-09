<script setup lang="ts">
import { formatPanelDateTime } from "./panelTime";
import { computed, onMounted, onUnmounted, ref, watch } from "vue";
import { ElMessage } from "element-plus";
interface Site {
  id: string;
  name: string;
  domain: string;
  status: string;
  settings: { domains: string[] };
}
interface Provider {
  id: string;
  name: string;
  directory: string;
  test: boolean;
  terms?: string;
}
interface Account {
  provider: string;
  email: string;
  terms_url: string;
  terms_accepted_at: string;
}
interface Renewal {
  site_id: string;
  site_name: string;
  domain: string;
  provider: string;
  certificate_id: string;
  enabled: boolean;
  next_attempt_at: number;
  last_error: string;
}
const props = defineProps<{
  api: <T>(path: string, method?: string, body?: unknown) => Promise<T>;
  sites: Site[];
  onJob: (id: string) => Promise<void>;
}>();
const providers = ref<Provider[]>([]),
  accounts = ref<Account[]>([]),
  renewals = ref<Renewal[]>([]),
  error = ref(""),
  visible = ref(false),
  busy = ref(false),
  termsBusy = ref(false),
  formError = ref("");
const siteID = ref(""),
  providerID = ref(""),
  email = ref(""),
  accepted = ref(false),
  autoRenew = ref(true),
  redirect = ref(true),
  info = ref<Provider | null>(null);
const selectedSite = computed(() =>
  props.sites.find((s) => s.id === siteID.value),
);
const existingAccount = computed(() =>
  accounts.value.find((a) => a.provider === providerID.value),
);
const alreadyAccepted = computed(
  () =>
    !!info.value?.terms &&
    existingAccount.value?.terms_url === info.value.terms &&
    !!existingAccount.value.terms_accepted_at,
);
let generation = 0,
  timer: ReturnType<typeof setInterval> | undefined;
async function refresh() {
  try {
    const [p, a, r] = await Promise.all([
      props.api<Provider[]>("/acme/providers"),
      props.api<Account[]>("/acme/accounts"),
      props.api<Renewal[]>("/acme/renewals"),
    ]);
    providers.value = p;
    accounts.value = a;
    renewals.value = r;
    error.value = "";
  } catch (e) {
    error.value = (e as Error).message;
  }
}
async function terms() {
  const current = ++generation;
  info.value = null;
  accepted.value = false;
  termsBusy.value = true;
  formError.value = "";
  email.value = existingAccount.value?.email || "";
  try {
    const data = await props.api<Provider>(
      "/acme/providers/" + providerID.value,
    );
    if (current === generation) info.value = data;
  } catch (e) {
    if (current === generation) formError.value = (e as Error).message;
  } finally {
    if (current === generation) termsBusy.value = false;
  }
}
async function open(id = "", provider = "") {
  await refresh();
  if (error.value) return;
  siteID.value = id;
  providerID.value =
    provider ||
    (providers.value.some((p) => p.id === "pebble")
      ? "pebble"
      : "letsencrypt-staging");
  autoRenew.value = true;
  redirect.value = true;
  formError.value = "";
  visible.value = true;
  await terms();
}
watch(providerID, () => {
  if (visible.value) void terms();
});
async function submit() {
  if (
    !siteID.value ||
    !info.value ||
    (!alreadyAccepted.value && !accepted.value)
  ) {
    formError.value = "请选择网站并确认当前 CA 服务条款";
    return;
  }
  busy.value = true;
  formError.value = "";
  try {
    const result = await props.api<{ job_id: string }>("/acme/orders", "POST", {
      site_id: siteID.value,
      provider: providerID.value,
      email: email.value,
      terms_url: info.value.terms,
      accept_terms: alreadyAccepted.value || accepted.value,
      auto_renew: autoRenew.value,
      redirect: redirect.value,
    });
    visible.value = false;
    ElMessage.success("证书订单已提交，执行进度可在任务中心查看");
    await props.onJob(result.job_id);
  } catch (e) {
    formError.value = (e as Error).message;
  } finally {
    busy.value = false;
  }
}
async function toggle(row: Renewal, value: unknown) {
  busy.value = true;
  try {
    await props.api("/acme/renewals/" + row.site_id, "POST", {
      enabled: !!value,
    });
    await refresh();
  } catch (e) {
    row.enabled = !value;
    ElMessage.error((e as Error).message);
  } finally {
    busy.value = false;
  }
}
function clear() {
  generation++;
  info.value = null;
  email.value = "";
  accepted.value = false;
  formError.value = "";
  termsBusy.value = false;
}
onMounted(async () => {
  await refresh();
  timer = setInterval(() => {
    if (!visible.value && !busy.value) void refresh();
  }, 10000);
});
onUnmounted(() => {
  generation++;
  if (timer) clearInterval(timer);
});
defineExpose({ refresh });
</script>
<template>
  <section class="panel-card acme-manager">
    <div class="table-toolbar">
      <div>
        <strong>自动证书与续期</strong>
        <p class="acme-help">
          申请、部署和续期持续执行，失败原因留在任务中心。
        </p>
      </div>
      <el-button type="primary" @click="open()">申请自动证书</el-button>
    </div>
    <el-alert v-if="error" :title="error" type="error" :closable="false" />
    <el-table
      :data="renewals"
      empty-text="申请证书后，可在这里管理该网站的自动续期"
    >
      <el-table-column label="网站" min-width="220"
        ><template #default="{ row }"
          ><strong>{{ row.site_name }}</strong
          ><span class="table-secondary">{{ row.domain }}</span></template
        ></el-table-column
      >
      <el-table-column label="CA / 状态" min-width="200"
        ><template #default="{ row }"
          >{{
            providers.find((p) => p.id === row.provider)?.name || row.provider
          }}<span class="table-secondary">{{
            row.last_error ||
            (row.enabled ? "每天检查，到期前 30 天自动续期" : "自动续期已暂停")
          }}</span></template
        ></el-table-column
      >
      <el-table-column label="下次检查" min-width="165"
        ><template #default="{ row }">{{
          row.enabled
            ? formatPanelDateTime(row.next_attempt_at * 1000)
            : "—"
        }}</template></el-table-column
      >
      <el-table-column label="自动续期" width="100"
        ><template #default="{ row }"
          ><el-switch
            v-model="row.enabled"
            :disabled="busy"
            :aria-label="row.domain + ' 自动续期'"
            @change="toggle(row, $event)" /></template
      ></el-table-column>
      <el-table-column label="操作" width="100"
        ><template #default="{ row }"
          ><el-button
            link
            type="primary"
            :disabled="busy"
            @click="open(row.site_id, row.provider)"
            >立即续期</el-button
          ></template
        ></el-table-column
      >
    </el-table>
  </section>
  <el-dialog
    v-model="visible"
    title="申请 / 续期自动证书"
    width="min(740px, 95vw)"
    :close-on-click-modal="false"
    :close-on-press-escape="!busy"
    :show-close="!busy"
    @closed="clear"
    class="acme-order-dialog"
    destroy-on-close
  >
    <el-form label-position="top" :disabled="busy">
      <el-alert
        v-if="formError"
        :title="formError"
        type="error"
        show-icon
        :closable="false"
      />
      <el-form-item label="选择网站"
        ><el-select
          v-model="siteID"
          aria-label="申请证书的网站"
          placeholder="选择运行中的网站"
          style="width: 100%"
          ><el-option
            v-for="site in sites.filter((s) => s.status === 'running')"
            :key="site.id"
            :value="site.id"
            :label="site.name + ' · ' + site.domain"
        /></el-select>
        <div v-if="selectedSite" class="acme-domains">
          验证域名：{{
            [selectedSite.domain, ...selectedSite.settings.domains].join("、")
          }}
        </div></el-form-item
      >
      <el-form-item label="证书颁发机构"
        ><el-select
          v-model="providerID"
          aria-label="证书颁发机构"
          style="width: 100%"
          ><el-option
            v-for="provider in providers"
            :key="provider.id"
            :value="provider.id"
            :label="provider.name" /></el-select
      ></el-form-item>
      <el-form-item label="CA 联系邮箱"
        ><el-input
          v-model="email"
          :readonly="!!existingAccount"
          aria-label="CA 联系邮箱"
          placeholder="用于 CA 账户联系的邮箱"
        />
        <div v-if="existingAccount" class="acme-help">
          使用此 CA 已登记的账户。
        </div></el-form-item
      >
      <div v-loading="termsBusy" class="acme-terms">
        <template v-if="info">
          <el-alert
            v-if="info.test"
            :title="
              info.id === 'pebble'
                ? '本机验收 CA：证书不受浏览器公共信任，仅用于开发验证。'
                : 'CA 测试环境：签发证书不受浏览器公共信任。'
            "
            type="info"
            show-icon
            :closable="false"
          />
          <p v-if="info.id !== 'pebble'">
            <a :href="info.terms" target="_blank" rel="noopener noreferrer"
              >查看 CA 服务条款</a
            >
          </p>
          <el-tag v-if="alreadyAccepted" type="success"
            >已确认当前 CA 服务条款</el-tag
          >
          <el-checkbox v-else v-model="accepted">{{
            info.id === "pebble"
              ? "确认使用本地测试 CA"
              : "我已阅读并同意当前 CA 服务条款"
          }}</el-checkbox>
        </template>
      </div>
      <div class="acme-options">
        <el-checkbox v-model="autoRenew">自动续期</el-checkbox
        ><el-checkbox v-model="redirect">强制 HTTPS</el-checkbox>
      </div>
      <p class="acme-help">
        申请会启用该网站的 HTTP-01 验证入口。CA 需要从公网访问正式域名的 80
        端口；本地验收使用开发入口。新证书验证并部署成功后才替换原证书。
      </p>
    </el-form>
    <template #footer
      ><el-button :disabled="busy" @click="visible = false">取消</el-button
      ><el-button
        type="primary"
        :loading="busy"
        :disabled="termsBusy || !info"
        @click="submit"
        >提交证书订单</el-button
      ></template
    >
  </el-dialog>
</template>
<style>
.acme-manager {
  overflow: hidden;
  margin-bottom: 20px;
}
.acme-help {
  font-size: 13px;
  line-height: 1.8;
  color: var(--el-text-color-secondary);
  margin: 6px 0;
}
.acme-domains {
  font-size: 13px;
  line-height: 1.8;
  overflow-wrap: anywhere;
  margin-top: 8px;
  color: var(--el-text-color-secondary);
}
.acme-order-dialog {
  display: flex;
  flex-direction: column;
  max-height: 90vh;
}
.acme-order-dialog .el-dialog__body {
  overflow: auto;
}
.acme-order-dialog .el-dialog__footer {
  flex-shrink: 0;
}
.acme-terms {
  min-height: 40px;
  margin-bottom: 12px;
}
.acme-terms .el-alert {
  margin-bottom: 12px;
}
.acme-options {
  display: flex;
  gap: 20px;
  flex-wrap: wrap;
}
.acme-terms .el-checkbox {
  height: auto;
  white-space: normal;
}
.acme-terms .el-checkbox__label {
  white-space: normal;
  line-height: 1.8;
}
.acme-order-dialog .el-alert {
  margin-bottom: 12px;
}
</style>
