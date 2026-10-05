<script setup lang="ts">
import { formatPanelDateTime } from "./panelTime";
import ACMEManager from "./ACMEManager.vue";
import { onMounted, ref } from "vue";
import { ElMessage } from "element-plus";
interface Certificate {
  id: string;
  name: string;
  domains: string[];
  issuer: string;
  fingerprint: string;
  not_after: string;
  algorithm: string;
  trusted: boolean;
  status: string;
  references: number;
}
const props = defineProps<{
  sites: {
    id: string;
    name: string;
    domain: string;
    status: string;
    settings: { domains: string[] };
  }[];
  onJob: (id: string) => Promise<void>;
  api: <T>(path: string, method?: string, body?: unknown) => Promise<T>;
}>();
const acmeManager = ref<InstanceType<typeof ACMEManager> | null>(null);
const certificates = ref<Certificate[]>([]),
  loading = ref(false),
  busy = ref(false),
  error = ref("");
const visible = ref(false),
  name = ref(""),
  certificatePEM = ref(""),
  privateKeyPEM = ref(""),
  formError = ref("");
const statuses: Record<string, string> = {
  valid: "有效",
  expiring: "即将到期",
  expired: "已过期",
  not_yet_valid: "尚未生效",
};
async function refresh() {
  loading.value = true;
  error.value = "";
  try {
    certificates.value = await props.api<Certificate[]>("/certificates");
  } catch (e) {
    error.value = (e as Error).message;
  } finally {
    loading.value = false;
  }
}
function clear() {
  name.value = "";
  certificatePEM.value = "";
  privateKeyPEM.value = "";
  formError.value = "";
}
async function readFile(event: Event, key: boolean) {
  const input = event.target as HTMLInputElement,
    file = input.files?.[0];
  try {
    if (!file) return;
    if (file.size > (key ? 16384 : 32768))
      throw new Error(
        key ? "私钥文件不能超过 16 KiB" : "证书链文件不能超过 32 KiB",
      );
    const value = await file.text();
    if (key) privateKeyPEM.value = value;
    else certificatePEM.value = value;
    formError.value = "";
  } catch (e) {
    formError.value = (e as Error).message;
  } finally {
    input.value = "";
  }
}
async function upload() {
  if (!name.value.trim() || !certificatePEM.value || !privateKeyPEM.value) {
    formError.value = "请填写名称、证书链与私钥";
    return;
  }
  busy.value = true;
  formError.value = "";
  try {
    await props.api<Certificate>("/certificates", "POST", {
      name: name.value,
      certificate_pem: certificatePEM.value,
      private_key_pem: privateKeyPEM.value,
    });
    clear();
    visible.value = false;
    ElMessage.success("证书已保存，可在网站设置中绑定");
    await refresh();
  } catch (e) {
    formError.value = (e as Error).message;
  } finally {
    busy.value = false;
  }
}
onMounted(refresh);
defineExpose({
  refresh: async () => {
    await refresh();
    await acmeManager.value?.refresh();
  },
});
</script>
<template>
  <ACMEManager ref="acmeManager" :api="api" :sites="sites" :on-job="onJob" />
  <section class="panel-card certificate-manager" v-loading="loading">
    <div class="table-toolbar">
      <div class="tabs-label">
        证书列表 <span class="count-badge">{{ certificates.length }}</span>
      </div>
      <el-button
        type="primary"
        @click="
          clear();
          visible = true;
        "
        >上传证书</el-button
      >
    </div>
    <el-alert v-if="error" :title="error" type="error" :closable="false" />
    <el-table
      :data="certificates"
      empty-text="尚无证书，上传后可为网站开启 HTTPS"
    >
      <el-table-column label="名称 / 域名" min-width="230"
        ><template #default="{ row }"
          ><strong>{{ row.name }}</strong
          ><span class="table-secondary">{{
            row.domains.join(" · ")
          }}</span></template
        ></el-table-column
      >
      <el-table-column label="状态" width="115"
        ><template #default="{ row }"
          ><el-tag
            :type="
              row.status === 'valid'
                ? 'success'
                : row.status === 'expiring'
                  ? 'warning'
                  : 'danger'
            "
            >{{ statuses[row.status] || row.status }}</el-tag
          ></template
        ></el-table-column
      >
      <el-table-column label="到期时间" min-width="170"
        ><template #default="{ row }">{{
          formatPanelDateTime(row.not_after)
        }}</template></el-table-column
      >
      <el-table-column label="颁发者 / 信任" min-width="200"
        ><template #default="{ row }"
          >{{ row.issuer
          }}<span class="table-secondary">{{
            row.trusted ? "服务器系统 CA 信任" : "私有 CA 或系统未信任"
          }}</span></template
        ></el-table-column
      >
      <el-table-column label="绑定网站" width="95"
        ><template #default="{ row }">{{
          row.references
        }}</template></el-table-column
      >
      <el-table-column label="算法 / 指纹" min-width="220"
        ><template #default="{ row }"
          >{{ row.algorithm
          }}<code class="certificate-fingerprint" :title="row.fingerprint"
            >SHA-256 {{ row.fingerprint }}</code
          ></template
        ></el-table-column
      >
    </el-table>
    <p class="certificate-note">
      新证书通过检查后保存，进入“网站 → 设置 → SSL /
      HTTPS”绑定。更换证书时，上传新证书并重新绑定即可。
    </p>
  </section>
  <el-dialog
    v-model="visible"
    title="上传 SSL 证书"
    width="min(760px, 95vw)"
    :close-on-click-modal="false"
    :close-on-press-escape="!busy"
    :show-close="!busy"
    @closed="clear"
    destroy-on-close
    class="certificate-upload-dialog"
  >
    <el-form label-position="top" :disabled="busy">
      <el-alert
        v-if="formError"
        :title="formError"
        type="error"
        :closable="false"
        show-icon
      />
      <el-form-item label="证书名称"
        ><el-input
          v-model="name"
          aria-label="证书名称"
          maxlength="80"
          placeholder="例如：主站证书 2026"
      /></el-form-item>
      <el-form-item label="证书链（PEM）"
        ><input
          type="file"
          accept=".pem,.crt,.cer"
          aria-label="选择证书文件"
          @change="readFile($event, false)" /><el-input
          v-model="certificatePEM"
          type="textarea"
          :rows="5"
          aria-label="证书链 PEM"
          placeholder="先放服务器证书，再放中间证书"
      /></el-form-item>
      <el-form-item label="私钥（PEM）"
        ><input
          type="file"
          accept=".pem,.key"
          aria-label="选择私钥文件"
          @change="readFile($event, true)" /><el-input
          v-model="privateKeyPEM"
          type="textarea"
          :rows="4"
          aria-label="证书私钥 PEM"
          placeholder="与证书匹配的未加密 PEM 私钥"
      /></el-form-item>
      <p class="certificate-note">
        私钥提交后加密保存，不提供回显。当前本机开发入口使用环回连接；远程管理应先启用面板
        HTTPS。
      </p>
    </el-form>
    <template #footer
      ><el-button :disabled="busy" @click="visible = false">取消</el-button
      ><el-button type="primary" :loading="busy" @click="upload"
        >检查并保存</el-button
      ></template
    >
  </el-dialog>
</template>
<style>
.certificate-manager {
  overflow: hidden;
}
.certificate-note {
  color: var(--el-text-color-secondary);
  font-size: 13px;
  line-height: 1.8;
  margin: 18px 22px;
}
.certificate-fingerprint {
  display: block;
  font-size: 11px;
  color: var(--el-text-color-secondary);
  overflow-wrap: anywhere;
  line-height: 1.5;
  margin-top: 6px;
}
.certificate-upload-dialog {
  display: flex;
  flex-direction: column;
  max-height: 90vh;
}
.certificate-upload-dialog .el-dialog__body {
  overflow: auto;
}
.certificate-upload-dialog .el-dialog__footer {
  flex-shrink: 0;
}
.certificate-upload-dialog input[type="file"] {
  max-width: 100%;
  margin-bottom: 8px;
}
.certificate-upload-dialog .certificate-note {
  margin: 0;
}
.certificate-upload-dialog .el-alert {
  margin-bottom: 16px;
}
</style>
