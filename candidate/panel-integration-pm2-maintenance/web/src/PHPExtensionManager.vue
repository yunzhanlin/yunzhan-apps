<script setup lang="ts">
import { ref } from "vue";
import { ElMessage } from "element-plus";
interface Extension {
  extension: { id: string; name: string; version: string; sha256: string };
  release_id: string;
  status: string;
  error?: string;
  manifest?: {
    abi: { architecture: string; extension_build: string };
    module_sha256: string;
  };
}
const props = defineProps<{
  api: <T>(path: string, method?: string, body?: unknown) => Promise<T>;
  onJob: (id: string) => Promise<void>;
  busy: (id: string) => boolean;
}>();
const visible = ref(false),
  release = ref(""),
  loading = ref(false),
  submitting = ref(false),
  error = ref(""),
  rows = ref<Extension[]>([]);
async function refresh() {
  loading.value = true;
  error.value = "";
  try {
    rows.value = await props.api<Extension[]>(
      `/php/extensions/${release.value}`,
    );
  } catch (e) {
    error.value = (e as Error).message;
  } finally {
    loading.value = false;
  }
}
async function inspect(id: string) {
  release.value = id;
  rows.value = [];
  visible.value = true;
  await refresh();
}
async function install(extension: string) {
  submitting.value = true;
  error.value = "";
  try {
    const job = await props.api<{ job_id: string }>(
      `/php/extensions/${release.value}/install`,
      "POST",
      { extension_id: extension },
    );
    visible.value = false;
    ElMessage.success("扩展安装任务已提交");
    await props.onJob(job.job_id);
  } catch (e) {
    error.value = (e as Error).message;
  } finally {
    submitting.value = false;
  }
}
defineExpose({ inspect });
</script>
<template>
  <el-dialog
    v-model="visible"
    :title="'PHP 独立扩展 · ' + release.replace('php-', '')"
    width="min(760px, 95vw)"
    class="php-extension-dialog"
    :close-on-click-modal="false"
  >
    <p class="extension-intro">
      扩展为当前 PHP 精确版本单独编译。安装后，在「网站设置 → PHP
      参数」为需要的网站启用，CLI 同步生效。
    </p>
    <el-alert v-if="error" :title="error" type="error" :closable="false" />
    <div v-loading="loading" class="extension-list">
      <article
        v-for="row in rows"
        :key="row.extension.id"
        class="extension-card"
        :data-extension="row.extension.id"
      >
        <div class="extension-heading">
          <div>
            <strong>{{ row.extension.name }}</strong
            ><span>{{ row.extension.version }}</span>
          </div>
          <el-tag
            :type="
              row.status === 'installed'
                ? 'success'
                : row.status === 'needs_attention'
                  ? 'danger'
                  : 'info'
            "
            >{{
              row.status === "installed"
                ? "已安装并核对"
                : row.status === "needs_attention"
                  ? "需核对"
                  : "未安装"
            }}</el-tag
          >
        </div>
        <p>用于 PHP 应用连接 Redis 服务。</p>
        <el-alert
          v-if="row.error"
          :title="row.error"
          type="error"
          :closable="false"
        />
        <dl v-if="row.manifest">
          <dt>PHP ABI</dt>
          <dd>{{ row.manifest.abi.extension_build }}</dd>
          <dt>架构</dt>
          <dd>{{ row.manifest.abi.architecture }}</dd>
          <dt>模块 SHA-256</dt>
          <dd class="extension-hash">{{ row.manifest.module_sha256 }}</dd>
        </dl>
        <el-button
          v-if="row.status === 'not_installed'"
          type="primary"
          :loading="submitting"
          :disabled="busy(release)"
          @click="install(row.extension.id)"
          >安装到 PHP {{ release.replace("php-", "") }}</el-button
        >
        <small v-if="row.status === 'installed'"
          >已安装的扩展可供本站 PHP 版本的网站选择。</small
        >
      </article>
    </div>
    <template #footer
      ><el-button :loading="loading" :disabled="submitting" @click="refresh"
        >重新核对</el-button
      ><el-button @click="visible = false">关闭</el-button></template
    >
  </el-dialog>
</template>
<style scoped>
.extension-intro {
  color: #60756a;
  line-height: 1.8;
  margin: 0 0 20px;
}
.extension-list {
  min-height: 100px;
}
.extension-card {
  border: 1px solid #e4ece7;
  padding: 20px;
  border-radius: 12px;
  background: #fbfdfb;
}
.extension-heading {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 12px;
}
.extension-heading strong {
  font-size: 22px;
  text-transform: capitalize;
}
.extension-heading span {
  margin-left: 10px;
  color: #73867c;
}
.extension-card p,
.extension-card small {
  color: #6b7c72;
  line-height: 1.7;
}
.extension-card dl {
  display: grid;
  grid-template-columns: 100px 1fr;
  gap: 12px;
  font-size: 13px;
}
.extension-card dt {
  color: #73867c;
}
.extension-card dd {
  margin: 0;
  overflow-wrap: anywhere;
}
.extension-hash {
  font-family: monospace;
  font-size: 11px;
}
@media (max-width: 600px) {
  .extension-card {
    padding: 14px;
  }
  .extension-card dl {
    grid-template-columns: 80px 1fr;
  }
  .extension-heading strong {
    font-size: 20px;
  }
}
</style>
