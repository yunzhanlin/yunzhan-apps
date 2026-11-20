<script setup lang="ts">
import {computed, onBeforeUnmount, ref, watch} from 'vue';

type Policy = {site_id: string; enabled: boolean; sample_percent: number; revision: number};
type API = <T>(path: string, method?: string, body?: unknown) => Promise<T>;
const props = defineProps<{api: API; site: string; collecting: boolean}>();
const policy = ref<Policy>();
const busy = ref(false), error = ref(''), saved = ref(false);
let generation = 0;
const path = computed(() => '/analytics/sites/' + encodeURIComponent(props.site) + '/replay-policy');

async function load() {
 const current = ++generation;
 const site = props.site;
 policy.value = undefined;
 error.value = '';
 saved.value = false;
 busy.value = Boolean(site);
 if (!site) return;
 try {
  const value = await props.api<Policy>(path.value);
  if (current !== generation) return;
  if (value.site_id !== site) throw new Error('回看设置的网站不匹配');
  policy.value = value;
 } catch (e) {
  if (current === generation) error.value = (e as Error).message;
 } finally {
  if (current === generation) busy.value = false;
 }
}

async function save() {
 const draft = policy.value;
 if (!draft || busy.value || draft.enabled && !props.collecting) return;
 const current = generation;
 const submitted = {...draft};
 busy.value = true;
 error.value = '';
 saved.value = false;
 try {
  const value = await props.api<Policy>(path.value, 'POST', submitted);
  if (current !== generation) return;
  if (value.site_id !== submitted.site_id || value.revision !== submitted.revision + 1 ||
      value.enabled !== submitted.enabled || value.sample_percent !== submitted.sample_percent) throw new Error('回看设置结果无法核对');
  policy.value = value;
  saved.value = true;
 } catch (e) {
  if (current === generation) error.value = (e as Error).message;
 } finally {
  if (current === generation) busy.value = false;
 }
}
watch(() => props.site, load, {immediate: true, flush: 'sync'});
onBeforeUnmount(() => { generation++; });
</script>

<template>
  <section class="replay-settings" aria-label="会话画面采集设置">
    <h4>会话画面</h4>
    <p>访客同意后，以遮挡后的页面布局、滚动和点击位置重建画面。最长保存 7 天，且遵循网站的事件保留期限。</p>
    <el-alert v-if="error" type="error" :title="error" :closable="false" />
    <p v-if="saved" role="status">会话画面设置已保存。</p>
    <div v-if="policy" class="replay-settings-controls">
      <label>启用会话画面 <el-switch v-model="policy.enabled" aria-label="启用会话画面" :disabled="busy || (!policy.enabled && !collecting)" /></label>
      <label>会话抽样比例（%） <el-input-number v-model="policy.sample_percent" :min="1" :max="100" :disabled="busy" aria-label="会话画面抽样比例" /></label>
      <el-button :loading="busy" :disabled="policy.enabled && !collecting" @click="save">保存会话画面设置</el-button>
    </div>
    <el-button v-else-if="error" :disabled="busy" @click="load">重新读取设置</el-button>
    <details>
      <summary>接入访客同意</summary>
      <p>在网站的隐私选项中保存访客的选择。加载采集脚本前，可以设置 <code>window.yunzhanAnalyticsReplayConsent</code>。访客更改选择时，用下面的方式通知当前页面。</p>
      <pre>window.dispatchEvent(new CustomEvent("yunzhan:analytics-replay-consent", {detail: true}));</pre>
      <pre>window.dispatchEvent(new CustomEvent("yunzhan:analytics-replay-consent", {detail: false}));</pre>
      <p>给需要遮挡的区域加上 <code>data-yunzhan-private</code> 属性。表单、嵌入内容、隐藏区域和 Web Components 自动排除。画面使用色块呈现文字与图片的位置。</p>
    </details>
  </section>
</template>

<style scoped>
.replay-settings{padding:12px 14px;border:1px solid var(--el-border-color);border-radius:8px;margin:14px 0}
.replay-settings h4{margin:0 0 6px}
.replay-settings-controls{display:flex;align-items:center;flex-wrap:wrap;gap:12px}
details{margin:12px 0 0}
summary{cursor:pointer}
pre{white-space:pre-wrap;overflow-wrap:anywhere;font-size:12px}
</style>
