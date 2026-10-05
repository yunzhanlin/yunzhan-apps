<script setup lang="ts">
import { computed, ref, watch } from "vue";
import { ElMessage } from "element-plus";
import { randomId } from "./randomId";

interface Site { id: string; name: string; domain: string; status: string; settings: { domains?: string[] } }
interface Certificate { id: string; name: string; domains: string[]; status: string; not_after: string }
interface SiteState { id: string; domain: string; settings_revision: number; settings: Record<string, unknown> }
interface Preview { config_sha: string; current: string; candidate: string }
interface Row { id: string; domain: string; settings: Record<string, unknown>; revision: number; sha: string; candidate: string; error: string; jobID: string; key: string }

const props = defineProps<{
  sites: Site[];
  api: <T>(path: string, method?: string, body?: unknown, idempotencyKey?: string) => Promise<T>;
  onSubmitted: () => Promise<void>;
}>();
const selectedSiteIDs = defineModel<string[]>({ default: () => [] });
const visible = defineModel<boolean>("visible", { default: false });
const certificates = ref<Certificate[]>([]);
const certificateID = ref("");
const redirect = ref(false);
const busy = ref(false);
const rows = ref<Row[]>([]);
const certificate = computed(() => certificates.value.find((item) => item.id === certificateID.value));
const eligibleSites = computed(() => props.sites.filter((site) => site.status === "running"));
const selectedSites = computed(() => eligibleSites.value.filter((site) => selectedSiteIDs.value.includes(site.id)));
const readyRows = computed(() => rows.value.filter((row) => !!row.sha && !row.error));
const covers = (pattern: string, name: string) => {
  const domain = pattern.toLowerCase(), host = name.toLowerCase();
  if (domain === host) return true;
  if (!domain.startsWith("*.")) return false;
  const suffix = domain.slice(2);
  return host.endsWith("." + suffix) && host.slice(0, -(suffix.length + 1)).length > 0 && !host.slice(0, -(suffix.length + 1)).includes(".");
};
function certificateCovers(site: Site) {
  if (!certificate.value || certificate.value.status !== "valid") return false;
  return [site.domain, ...(site.settings?.domains || [])].every((host) => certificate.value!.domains.some((pattern) => covers(pattern, host)));
}
function resetPreview() { rows.value = []; }
watch(visible, async (open) => {
  if (!open) return;
  certificateID.value = "";
  redirect.value = false;
  resetPreview();
  try { certificates.value = await props.api<Certificate[]>("/certificates"); }
  catch (error) { ElMessage.error((error as Error).message); }
});
watch([selectedSiteIDs, certificateID, redirect], resetPreview, { deep: true });
async function preview() {
  if (busy.value || !certificate.value || !selectedSites.value.length) return;
  if (selectedSites.value.length > 20) { ElMessage.error("一次最多预览 20 个网站"); return; }
  busy.value = true;
  rows.value = [];
  for (const site of selectedSites.value) {
    if (!certificateCovers(site)) {
      rows.value.push({ id: site.id, domain: site.domain, settings: {}, revision: 0, sha: "", candidate: "", error: "证书未覆盖站点全部域名", jobID: "", key: "" });
      continue;
    }
    try {
      const current = await props.api<SiteState>(`/sites/${site.id}/settings`);
      const settings = structuredClone(current.settings);
      settings.tls = { certificate_id: certificateID.value, redirect: redirect.value };
      const result = await props.api<Preview>(`/sites/${site.id}/settings/preview`, "POST", { settings, expected_revision: current.settings_revision });
      rows.value.push({ id: site.id, domain: site.domain, settings, revision: current.settings_revision, sha: result.config_sha, candidate: result.candidate, error: "", jobID: "", key: randomId() });
    } catch (error) {
      rows.value.push({ id: site.id, domain: site.domain, settings: {}, revision: 0, sha: "", candidate: "", error: (error as Error).message, jobID: "", key: "" });
    }
  }
  busy.value = false;
}
async function submit() {
  if (busy.value || !readyRows.value.length) return;
  busy.value = true;
  for (const row of rows.value) {
    if (!row.sha || row.error || row.jobID) continue;
    try {
      const result = await props.api<{ job_id: string }>(`/sites/${row.id}/settings`, "POST", {
        settings: row.settings, expected_revision: row.revision, expected_config_sha: row.sha,
      }, row.key);
      row.jobID = result.job_id;
    } catch (error) { row.error = (error as Error).message; }
  }
  busy.value = false;
  const count = rows.value.filter((row) => !!row.jobID).length;
  if (count) { ElMessage.success(`已提交 ${count} 个网站配置任务`); await props.onSubmitted(); }
}
</script>

<template>
  <el-dialog v-model="visible" title="批量部署 SSL" width="min(850px, 94vw)" destroy-on-close>
    <div class="batch-ssl-intro">选择证书和运行中的网站；先逐站验证证书覆盖范围与 Nginx 候选配置，再提交配置任务。</div>
    <div class="batch-ssl-controls">
      <el-select v-model="certificateID" placeholder="选择已上传证书" aria-label="批量 SSL 证书" :disabled="busy">
        <el-option v-for="cert in certificates" :key="cert.id" :label="`${cert.name} · ${cert.domains.join(', ')}`" :value="cert.id" :disabled="cert.status !== 'valid'" />
      </el-select>
      <el-checkbox v-model="redirect" :disabled="busy">HTTP 自动跳转 HTTPS</el-checkbox>
    </div>
    <div class="batch-ssl-list">
      <label v-for="site in eligibleSites" :key="site.id" class="batch-ssl-site">
        <el-checkbox v-model="selectedSiteIDs" :value="site.id" :disabled="busy" @change="resetPreview" />
        <span>{{ site.domain }}</span>
        <small v-if="certificateID" :class="certificateCovers(site) ? 'ok' : 'bad'">{{ certificateCovers(site) ? '证书覆盖' : '证书不覆盖' }}</small>
      </label>
      <p v-if="!eligibleSites.length" class="batch-ssl-empty">暂无运行中的网站</p>
    </div>
    <div v-if="rows.length" class="batch-ssl-results">
      <h3>逐站预览结果</h3>
      <div v-for="row in rows" :key="row.id"><strong>{{ row.domain }}</strong><span :class="row.error ? 'bad' : 'ok'">{{ row.error || (row.jobID ? `任务 ${row.jobID.slice(0, 8)} 已提交` : '验证通过') }}</span><details v-if="row.candidate"><summary>查看 Nginx 候选配置</summary><pre>{{ row.candidate }}</pre></details></div>
    </div>
    <template #footer>
      <el-button @click="visible = false">关闭</el-button>
      <el-button :disabled="!certificateID || !selectedSites.length || busy" :loading="busy && !rows.length" @click="preview">预览配置</el-button>
      <el-button type="primary" :disabled="!readyRows.length || busy || readyRows.every(row => !!row.jobID)" :loading="busy && !!rows.length" @click="submit">提交 {{ readyRows.filter(row => !row.jobID).length }} 个任务</el-button>
    </template>
  </el-dialog>
</template>

<style scoped>
.batch-ssl-intro { color: #63758c; font-size: 12px; line-height: 1.5; margin-bottom: 14px; }
.batch-ssl-controls { display: flex; align-items: center; gap: 18px; margin-bottom: 12px; }
.batch-ssl-controls .el-select { flex: 1; min-width: 0; }
.batch-ssl-list { max-height: 245px; overflow: auto; border: 1px solid #e4ebf2; border-radius: 6px; }
.batch-ssl-site { min-height: 37px; padding: 5px 12px; display: flex; align-items: center; gap: 10px; border-bottom: 1px solid #edf1f5; font-size: 12px; }
.batch-ssl-site:last-child { border: 0; }
.batch-ssl-site span { flex: 1; }
.batch-ssl-site small { font-size: 11px; }
.batch-ssl-empty { text-align: center; color: #8291a4; font-size: 12px; }
.batch-ssl-results { margin-top: 14px; border: 1px solid #e4ebf2; border-radius: 6px; }
.batch-ssl-results h3 { margin: 0; padding: 8px 12px; font-size: 13px; border-bottom: 1px solid #edf1f5; }
.batch-ssl-results > div { padding: 8px 12px; border-bottom: 1px solid #edf1f5; font-size: 12px; display: flex; flex-wrap: wrap; justify-content: space-between; gap: 4px 12px; }
.batch-ssl-results > div:last-child { border: 0; }
.batch-ssl-results details { width: 100%; color: #65758b; }
.batch-ssl-results pre { max-height: 170px; overflow: auto; background: #101a25; color: #e3ebf2; padding: 9px; font-size: 10px; }
.ok { color: #08a858; }.bad { color: #f04438; }
@media (max-width: 680px) { .batch-ssl-controls { align-items: stretch; flex-direction: column; } }
</style>
