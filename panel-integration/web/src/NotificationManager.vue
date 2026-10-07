<script setup lang="ts">
import { formatPanelDateTime } from "./panelTime";
import { onMounted, ref } from "vue";
import { ElMessage } from "element-plus";
import OutboundNotifications from "./OutboundNotifications.vue";

interface Settings {
  schedule_failures: boolean;
  remote_failures: boolean;
  monitor_alerts: boolean;
  retention_days: number;
  revision: number;
  updated_at: string;
}
interface Notice {
  id: string;
  kind: string;
  title: string;
  message: string;
  created_at: number;
  read_at?: number;
}
interface NoticeResponse {
  notifications: Notice[];
  unread: number;
}
const props = defineProps<{ api: <T>(path: string, method?: string, body?: unknown) => Promise<T> }>();
const emit = defineEmits<{ updated: [] }>();
const saved = ref<Settings | null>(null);
const draft = ref<Settings | null>(null);
const list = ref<Notice[]>([]);
const unread = ref(0);
const loading = ref(false);
const saving = ref(false);
const error = ref("");

async function refresh() {
  if (loading.value) return;
  loading.value = true;
  error.value = "";
  try {
    const [settings, notices] = await Promise.all([
      props.api<Settings>("/notification-settings"),
      props.api<NoticeResponse>("/notifications?limit=30"),
    ]);
    saved.value = settings;
    draft.value = { ...settings };
    list.value = notices.notifications;
    unread.value = notices.unread;
  } catch (e) {
    error.value = (e as Error).message;
  } finally {
    loading.value = false;
  }
}
async function save() {
  if (!draft.value || saving.value) return;
  saving.value = true;
  try {
    const updated = await props.api<Settings>("/notification-settings", "PUT", draft.value);
    saved.value = updated;
    draft.value = { ...updated };
    emit("updated");
    ElMessage.success("通知策略已保存");
  } catch (e) {
    ElMessage.error((e as Error).message);
  } finally {
    saving.value = false;
  }
}
async function readAll() {
  try {
    await props.api("/notifications/read-all", "POST", {});
    await refresh();
    emit("updated");
    ElMessage.success("全部站内通知已标为已读");
  } catch (e) {
    ElMessage.error((e as Error).message);
  }
}
const formatTime = (value: number) => formatPanelDateTime(value * 1000);
defineExpose({ refresh });
onMounted(refresh);
</script>

<template>
  <div class="notification-settings-page" v-loading="loading">
    <OutboundNotifications :api="api" />
    <el-alert v-if="error" :title="error" type="error" :closable="false" />
    <section class="panel-card notification-settings-card">
      <div class="notification-settings-heading"><div><h2>站内通知</h2><p>选择要记录的运维事件；设置会在当前服务器上保存。</p></div><el-tag type="success">{{ unread }} 条未读</el-tag></div>
      <div v-if="draft" class="notification-settings-fields">
        <label><span><strong>计划任务失败</strong><small>脚本、备份或维护任务执行失败</small></span><el-switch v-model="draft.schedule_failures" aria-label="记录计划任务失败" /></label>
        <label><span><strong>远端备份失败</strong><small>WebDAV 副本重试耗尽</small></span><el-switch v-model="draft.remote_failures" aria-label="记录远端备份失败" /></label>
        <label><span><strong>资源告警</strong><small>CPU、内存、磁盘或服务进入告警</small></span><el-switch v-model="draft.monitor_alerts" aria-label="记录资源告警" /></label>
        <label><span><strong>已读通知保留天数</strong><small>范围 7–365 天，未读通知继续保留</small></span><el-input-number v-model="draft.retention_days" :min="7" :max="365" aria-label="已读通知保留天数" /></label>
      </div>
      <div class="notification-settings-actions"><el-button type="primary" :loading="saving" :disabled="!draft" @click="save">保存设置</el-button><el-button :disabled="!saved" @click="draft = saved ? { ...saved } : null">取消修改</el-button><small v-if="saved">配置版本 {{ saved.revision }}</small></div>
    </section>
    <section class="panel-card notification-recent-card">
      <div class="notification-settings-heading"><div><h2>最近通知</h2><p>按发生时间显示最近 30 条事件。</p></div><el-button :disabled="!unread" @click="readAll">全部已读</el-button></div>
      <div class="notification-recent-list">
        <div v-for="item in list" :key="item.id" :class="['notification-recent-item', { unread: !item.read_at }]">
          <span class="notification-recent-dot"></span><div><strong>{{ item.title }}</strong><p>{{ item.message }}</p></div><time>{{ formatTime(item.created_at) }}</time>
        </div>
        <el-empty v-if="!list.length" description="暂无通知" :image-size="64" />
      </div>
    </section>
  </div>
</template>

<style scoped>
.notification-settings-page { display: grid; gap: 14px; }
.notification-settings-card,.notification-recent-card { padding: 0; }
.notification-settings-heading { display: flex; justify-content: space-between; align-items: center; gap: 16px; padding: 16px 18px; border-bottom: 1px solid #e6ecf2; }
.notification-settings-heading h2 { color: #13243b; font-size: 16px; }
.notification-settings-heading p { margin-top: 4px; color: #78879c; font-size: 12px; }
.notification-settings-fields { padding: 4px 18px; }
.notification-settings-fields label { display: flex; justify-content: space-between; align-items: center; gap: 18px; min-height: 65px; border-bottom: 1px solid #edf1f5; }
.notification-settings-fields label:last-child { border-bottom: 0; }
.notification-settings-fields strong,.notification-settings-fields small { display: block; }
.notification-settings-fields strong { color: #20324a; font-size: 13px; }
.notification-settings-fields small { margin-top: 4px; color: #8795a7; font-size: 11px; }
.notification-settings-actions { display: flex; align-items: center; gap: 8px; padding: 14px 18px 18px; }
.notification-settings-actions small { margin-left: auto; color: #8795a7; }
.notification-recent-list { max-height: 370px; overflow-y: auto; }
.notification-recent-item { display: flex; align-items: start; gap: 10px; padding: 12px 18px; border-bottom: 1px solid #edf1f5; }
.notification-recent-item.unread { background: #f4fbf7; }
.notification-recent-dot { flex: none; width: 7px; height: 7px; margin-top: 7px; border-radius: 50%; background: #b5c0cc; }
.notification-recent-item.unread .notification-recent-dot { background: #08a75b; }
.notification-recent-item > div { flex: 1; min-width: 0; }
.notification-recent-item strong { color: #20324a; font-size: 12px; }
.notification-recent-item p { margin-top: 3px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: #6f7f95; font-size: 12px; }
.notification-recent-item time { flex: none; color: #8a98a9; font-size: 11px; }
@media (max-width: 600px) { .notification-settings-heading { align-items: start; } .notification-recent-item time { display: none; } .notification-settings-fields label { gap: 8px; } }
</style>
