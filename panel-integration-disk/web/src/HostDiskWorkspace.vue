<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue';
import { hostDiskAllowed, hostDiskBase as base, hostDiskVersion, hostSelection, validHostState, validHostJob, validHostReply,
  sameHostSelection, hostTerminal, hostReport, hostBytes, hostCount, hostCapacityValue, hostDrillDirectory, hostStateLabel, hostReasonLabel, hostID,
  type HostDiskAPI, type HostDiskState, type HostJob, type HostReply, type HostRecovery, type HostSelection, type HostUsageRow } from './hostDisk';
import type { AccessPlan } from './menuPermissions';
const props = defineProps<{ api: HostDiskAPI; access?: AccessPlan | null; active: boolean; installed: boolean; installationId: string; installedVersion: string }>();
const allowed = computed(() => props.active && hostDiskAllowed(props.access));
const state = ref<HostDiskState>(), jobs = ref<HostJob[]>([]), recovery = ref<HostRecovery[]>([]), reply = ref<HostReply>();
const mountID = ref(''), directory = ref(''), selectedID = ref(''), tab = ref('scan'), filter = ref(''), mountFilter = ref('');
const busy = ref(false), error = ref(''), message = ref(''), readKnown = ref(false), checkedAt = ref(''), recoverID = ref(''), confirm = ref('');
const pending = ref<{ key: string; selection: HostSelection }>();
let epoch = 0, timer: ReturnType<typeof setTimeout> | undefined;
const mounts = computed(() => state.value?.inventory?.inventory.mounts ?? []);
const visibleMounts = computed(() => mounts.value.filter(m => `${m.mount_point} ${m.filesystem} ${m.mount_id}`.toLocaleLowerCase().includes(mountFilter.value.toLocaleLowerCase())));
const mount = computed(() => mounts.value.find(m => m.mount_id === mountID.value));
const selection = computed(() => hostSelection(state.value, mountID.value, directory.value));
const enabled = computed(() => allowed.value && props.installed && props.installedVersion === hostDiskVersion && !!state.value?.inventory
  && state.value.installation_id === props.installationId && state.value.app_version === props.installedVersion);
const selected = computed(() => jobs.value.find(j => j.id === selectedID.value));
const report = computed(() => hostReport(reply.value));
const result = computed(() => reply.value?.result ?? reply.value?.observation?.result ?? undefined);
const capacity = computed(() => result.value?.capacity);
const canSubmit = computed(() => enabled.value && readKnown.value && !busy.value && !!selection.value && !pending.value && recovery.value.length === 0 && !jobs.value.some(j => !hostTerminal(j.state)));
const originalMount = computed(() => {
  const s = reply.value?.job.request.selection;
  if (!s || !state.value?.inventory || s.boot_id !== state.value.inventory.host.boot_id || s.mount_namespace_id !== state.value.inventory.host.mount_namespace_id
    || s.installation_id !== state.value.installation_id || s.app_manifest_sha256 !== state.value.app_manifest_sha256) return;
  return mounts.value.find(m => m.mount_id === s.mount_id && m.binding_sha256 === s.mount_binding_sha256 && m.filesystem_class === 'local' && m.path_actionable);
});
const directoryRows = computed(() => (report.value?.top_directories ?? []).filter(r => r.path.toLocaleLowerCase().includes(filter.value.toLocaleLowerCase())));
const fileRows = computed(() => (report.value?.top_files ?? []).filter(r => r.path.toLocaleLowerCase().includes(filter.value.toLocaleLowerCase())));
function stopPolling() { if (timer !== undefined) clearTimeout(timer); timer = undefined; }
function clear() {
  epoch++; stopPolling(); state.value = undefined; jobs.value = []; recovery.value = []; reply.value = undefined;
  mountID.value = ''; directory.value = ''; selectedID.value = ''; pending.value = undefined; readKnown.value = false;
  checkedAt.value = ''; error.value = ''; message.value = ''; recoverID.value = ''; confirm.value = ''; busy.value = false;
}
function schedule() {
  stopPolling();
  if (allowed.value && selected.value && !hostTerminal(selected.value.state) && !error.value)
    timer = setTimeout(() => { void observe(selectedID.value); }, 3000);
}
function merge(j: HostJob) { const i = jobs.value.findIndex(x => x.id === j.id); if (i < 0) jobs.value.unshift(j); else jobs.value[i] = j; }
function fail(e: unknown) { error.value = e instanceof Error ? e.message : '状态暂不能核对'; stopPolling(); }
async function refresh() {
  if (!allowed.value || busy.value) return;
  const e = epoch; busy.value = true; error.value = ''; readKnown.value = false; stopPolling();
  try {
    const [s, own, active] = await Promise.all([
      props.api<HostDiskState>(base), props.api<{ jobs: HostJob[] }>(base + '/jobs'), props.api<{ jobs: HostRecovery[]; metadata_only: boolean }>(base + '/recovery'),
    ]);
    if (e !== epoch || !allowed.value) return;
    if (!validHostState(s) || !Array.isArray(own.jobs) || own.jobs.length > 128 || own.jobs.some(j => !validHostJob(j)) || new Set(own.jobs.map(j => j.id)).size !== own.jobs.length
      || active.metadata_only !== true || !Array.isArray(active.jobs) || active.jobs.length > 128 || active.jobs.some(j => !hostID(j.id) || !['queued','dispatching','running','cancel_requested','uncertain'].includes(j.state) || typeof j.created_at !== 'string' || typeof j.updated_at !== 'string')) throw Error('挂载清单或原任务清单无法完整核对；没有使用部分数据');
    state.value = s; jobs.value = own.jobs; recovery.value = active.jobs; readKnown.value = true; checkedAt.value = new Date().toLocaleString();
    if (!mounts.value.some(m => m.mount_id === mountID.value)) { mountID.value = ''; directory.value = ''; }
    if (reply.value && !own.jobs.some(j => j.id === reply.value?.job.id && sameHostSelection(j.request.selection,reply.value.job.request.selection))) reply.value = undefined;
    if (!selectedID.value || !own.jobs.some(j => j.id === selectedID.value)) selectedID.value = own.jobs.find(j => !hostTerminal(j.state))?.id ?? own.jobs[0]?.id ?? '';
  } catch (x) { if (e === epoch) { state.value = undefined; jobs.value = []; recovery.value = []; reply.value = undefined; fail(x); } }
  finally { if (e === epoch) busy.value = false; }
  if (e === epoch && readKnown.value && selectedID.value) await observe(selectedID.value);
}
async function observe(id: string) {
  if (!allowed.value || busy.value || !hostID(id)) return;
  const original = jobs.value.find(j => j.id === id); if (!original) return;
  stopPolling(); const e = epoch; busy.value = true; error.value = ''; selectedID.value = id;
  if (reply.value?.job.id !== id) reply.value = undefined;
  try {
    const out = await props.api<HostReply>(base + '/jobs/' + id);
    if (e !== epoch || !allowed.value || selectedID.value !== id) return;
    if (!validHostReply(out, original)) throw Error('原任务、结果或退出凭证不能核对；未显示为完成');
    merge(out.job); reply.value = out;
    if (out.terminal_verified) recovery.value = recovery.value.filter(j => j.id !== id);
    checkedAt.value = new Date().toLocaleString();
  } catch (x) { if (e === epoch) { reply.value = undefined; fail(x); } }
  finally { if (e === epoch) { busy.value = false; schedule(); } }
}
async function submit() {
  if (!canSubmit.value || !selection.value) return;
  if (!globalThis.crypto?.getRandomValues) { error.value = '需要安全随机源生成原请求标识'; return; }
  const key = [...crypto.getRandomValues(new Uint8Array(16))].map(x => x.toString(16).padStart(2,'0')).join('');
  pending.value = { key, selection: { ...selection.value } };
  await submitOriginal();
}
async function submitOriginal() {
  if (!allowed.value || !enabled.value || busy.value || !pending.value) return;
  const e = epoch, original = pending.value; busy.value = true; error.value = ''; stopPolling();
  message.value = '正在提交原请求；收到接收回执不代表扫描已完成。';
  let id = '';
  try {
    const out = await props.api<{ job: HostJob; dispatch_uncertain: boolean; terminal_verified: boolean }>(base + '/jobs', 'POST', original.selection, original.key);
    if (e !== epoch || !allowed.value) return;
    if (!validHostJob(out.job) || !sameHostSelection(out.job.request.selection,original.selection) || out.terminal_verified !== false || typeof out.dispatch_uncertain !== 'boolean') throw Error('原提交回执无法核对；保留标识，未换标识重发');
    merge(out.job); selectedID.value = out.job.id; pending.value = undefined; reply.value = undefined; id = out.job.id;
    recovery.value = [...recovery.value.filter(j => j.id !== id), {id,state:out.job.state,created_at:out.job.created_at,updated_at:out.job.updated_at}];
    message.value = out.dispatch_uncertain ? '派发回执未知；只读取原任务，不会自动重新派发。' : '原任务已接收，正在只读核对进度。';
  } catch (x) { if (e === epoch) { fail(x); message.value = '请求可能已接收。保留原提交标识；先只读查询原请求，禁止换标识重发。'; } }
  finally { if (e === epoch) busy.value = false; }
  if (e === epoch && id) await observe(id);
}
async function reconcileSubmission() {
  if (!allowed.value || busy.value || !pending.value) return;
  const e = epoch, original = pending.value; busy.value = true; error.value = ''; let id = '';
  try {
    const out = await props.api<{ found: boolean; job?: HostJob }>(base + '/requests/' + original.key);
    if (e !== epoch || !allowed.value) return;
    if (out.found === false && out.job === undefined) { message.value = '当前尚未查到原请求，不代表之前的在途请求必然失败。可继续只读核对；显式继续提交也只使用相同标识和原选择。'; return; }
    if (out.found !== true || !validHostJob(out.job) || !sameHostSelection(out.job.request.selection,original.selection)) throw Error('原标识与原扫描选择不匹配；未采用或覆盖');
    merge(out.job); selectedID.value = out.job.id; pending.value = undefined; id = out.job.id;
    message.value = '已找回原任务；查询没有派发扫描。';
  } catch (x) { if (e === epoch) fail(x); }
  finally { if (e === epoch) busy.value = false; }
  if (e === epoch && id) await observe(id);
}
async function cancelJob() {
  const original = selected.value;
  if (!allowed.value || busy.value || !original || hostTerminal(original.state)) return;
  const e = epoch; busy.value = true; error.value = ''; stopPolling();
  try {
    const out = await props.api<{ job: HostJob; cancel_uncertain?: boolean }>(base + '/jobs/' + original.id + '/cancel', 'POST', {});
    if (e !== epoch || !allowed.value) return;
    if (!validHostJob(out.job) || out.job.id !== original.id || out.job.request.actor_id !== original.request.actor_id || out.job.request.access_revision !== original.request.access_revision || !sameHostSelection(out.job.request.selection,original.request.selection)) throw Error('取消回执与原任务不匹配；请只读核对');
    merge(out.job); message.value = '已请求取消。只有核对实际退出和原凭证后才标记结束；不会自动重发取消或扫描。';
  } catch (x) { if (e === epoch) fail(x); }
  finally { if (e === epoch) busy.value = false; }
  if (e === epoch) await observe(original.id);
}
async function recover() {
  const id = recoverID.value;
  if (!allowed.value || busy.value || !hostID(id) || confirm.value !== 'CLOSE ' + id || !recovery.value.some(j => j.id === id)) return;
  const e = epoch; busy.value = true; error.value = ''; stopPolling();
  try {
    const out = await props.api<{ id: string; state: string; terminal_verified: boolean; metadata_only: boolean }>(base + '/jobs/' + id + '/recover', 'POST', {});
    if (e !== epoch || !allowed.value) return;
    if (out.id !== id || out.metadata_only !== true || typeof out.terminal_verified !== 'boolean' || !['cancel_requested','complete','partial','failed','canceled'].includes(out.state) || out.terminal_verified !== hostTerminal(out.state)) throw Error('原任务收尾回执无法核对；保留原任务，未假定已停止');
    message.value = out.terminal_verified ? '原任务已核对退出并封闭，不会以原标识重新扫描。维护操作不授予原账户的私有报告访问权。' : '已请求停止原进程，尚未封闭。请只读刷新后核对，可显式继续收尾。';
    if (out.terminal_verified) { recovery.value = recovery.value.filter(j => j.id !== id); recoverID.value = ''; confirm.value = ''; }
    reply.value = undefined;
  } catch (x) { if (e === epoch) fail(x); }
  finally { if (e === epoch) busy.value = false; }
  if (e === epoch && !error.value) await refresh();
}
function chooseDirectory(row: HostUsageRow, isDirectory: boolean) {
  const path = hostDrillDirectory(originalMount.value,row,isDirectory);
  if (path === undefined || !originalMount.value) return;
  mountID.value = originalMount.value.mount_id; directory.value = path; tab.value = 'scan';
  message.value = '已选择目录，尚未开始新扫描。确认范围后点击“开始扫描”。';
}
function exportResult() {
  if (!allowed.value || !reply.value?.terminal_verified || !result.value || !report.value) return;
  const blob = new Blob([JSON.stringify({format:1,job:reply.value.job,result:result.value,terminal_verified:true},null,2)], {type:'application/json;charset=utf-8'});
  const url = URL.createObjectURL(blob), link = document.createElement('a'); link.href = url; link.download = 'disk-analysis-' + reply.value.job.id + '.json'; link.click(); setTimeout(() => URL.revokeObjectURL(url),1000);
}
watch(() => [props.active,props.installed,props.installedVersion,props.installationId,props.access] as const, () => { clear(); if (allowed.value) void refresh(); }, {deep:true,immediate:true});
onBeforeUnmount(clear);
</script>

<template>
  <section v-if="active" class="host-disk" aria-label="全盘磁盘分析">
    <el-alert v-if="!allowed" title="全盘信息包含主机私有路径，仅完整权限管理员可读取；网站目录分析权限不因此扩大。" type="warning" :closable="false" />
    <template v-else>
      <header class="disk-heading"><div><h3>主机磁盘分析</h3><p>挂载点独立扫描 · 文件与目录排行 · 可核对的后台任务</p></div><el-button :disabled="busy" @click="refresh">只读刷新清单与原任务</el-button></header>
      <el-alert v-if="error" :title="error" type="error" :closable="false" role="alert" />
      <p v-if="message" role="status" class="disk-notice">{{ message }}</p>
      <el-alert v-if="!installed || installedVersion!==hostDiskVersion" title="全盘后台任务需要明确更新并核对磁盘分析 1.4.0 与对应面板能力。此页不自动安装或更新；现有网站目录分析继续独立使用。" type="warning" :closable="false" />
      <el-alert v-else-if="state && !enabled" title="应用安装实例或签名清单与当前页面不一致，请重新打开并核对。已暂停新扫描，原任务仅只读查询。" type="warning" :closable="false" />
      <div v-if="pending" class="disk-pending" role="status"><strong>原提交回执待核对</strong><p>原提交标识：{{ pending.key }}。没有自动重试。关闭页面不会取消服务器任务；重开后先读取历史和维护清单。</p><el-button :disabled="busy" @click="reconcileSubmission">只读查询原提交</el-button><el-button :disabled="busy || !enabled" @click="submitOriginal">显式继续提交同一原请求</el-button></div>
      <el-tabs v-model="tab">
        <el-tab-pane label="扫描范围" name="scan">
          <p class="disk-notice">仅扫描选定的本地挂载子树；不跨子挂载、不读取文件内容。最多 1000 万条元数据、512 层目录、30 分钟，单任务 CPU 20%、内存 512 MiB。不是实时一致快照；绑定挂载、子卷或存储池不可相加。</p>
          <div class="disk-controls"><label>本地挂载点<select v-model="mountID" :disabled="busy || !!pending" aria-label="选择本地挂载点" @change="directory='' "><option value="">请选择挂载点</option><option v-for="m in mounts" :key="m.mount_id" :value="m.mount_id" :disabled="m.filesystem_class!=='local' || !m.path_actionable">{{ m.mount_point }} · {{ m.filesystem }} · #{{ m.mount_id }}{{ m.filesystem_class!=='local'?'（不支持扫描）':'' }}</option></select></label><label>挂载点内的相对目录<el-input v-model="directory" :disabled="busy || !!pending" aria-label="扫描相对目录" placeholder="留空扫描所选挂载点；例如 www/example" maxlength="4096" /></label></div>
          <p v-if="mount" class="disk-path">扫描范围：{{ mount.mount_point }}{{ directory ? (mount.mount_point==='/'?'':'/')+directory : '' }} <span v-if="mount.mount_read_only">· 只读挂载</span></p>
          <p v-if="directory && !selection" class="disk-warning">目录必须是普通相对路径，不接受 ..、绝对路径、控制字符、空路径段或超过 4096 字节的范围。</p>
          <el-button type="primary" :disabled="!canSubmit" @click="submit">开始扫描</el-button><span v-if="recovery.length" class="disk-warning">存在尚未结束的原任务；先核对任务或到“中断恢复”收尾。</span>
          <div class="disk-table-title"><h4>宿主挂载清单（{{ mounts.length }}）</h4><el-input v-model="mountFilter" aria-label="筛选挂载清单" placeholder="筛选路径或文件系统" clearable /></div>
          <div class="disk-table" role="region" aria-label="宿主挂载清单，可横向滚动" tabindex="0"><table><thead><tr><th>挂载点 / ID</th><th>文件系统 / 根</th><th>可扫描性</th></tr></thead><tbody><tr v-for="m in visibleMounts.slice(0,200)" :key="m.mount_id"><td>{{ m.mount_point }}<small>#{{ m.mount_id }}{{m.stacked_mount_point?' · 同路径叠加挂载':''}}</small></td><td>{{ m.filesystem }}<small>{{ m.filesystem_root }}</small></td><td>{{ m.filesystem_class==='local' && m.path_actionable ? '本地 · 可选择' : m.filesystem_class==='remote_or_userspace' ? '远端或用户态 · 不扫描' : m.filesystem_class==='kernel_virtual' ? '内核虚拟 · 不扫描' : '未知或路径仅展示 · 不扫描' }}</td></tr></tbody></table></div><p v-if="visibleMounts.length>200">当前筛选显示前 200 条，请缩小筛选范围；扫描选择仍来自完整清单。</p><p v-if="readKnown && !mounts.length">当前应用未提供全盘清单，不表示主机没有磁盘。</p>
        </el-tab-pane>
        <el-tab-pane label="我的任务与报告" name="jobs">
          <div class="disk-table" role="region" aria-label="我的扫描历史，可横向滚动" tabindex="0"><table><thead><tr><th>原任务 / 时间</th><th>扫描选择</th><th>状态</th><th>操作</th></tr></thead><tbody><tr v-for="j in jobs" :key="j.id"><td>{{j.id}}<small>{{j.created_at}}</small></td><td>挂载 #{{j.request.selection.mount_id}}<small>{{j.request.selection.relative_directory || '挂载根目录'}}</small></td><td>{{hostStateLabel(j.state)}}</td><td><el-button text :disabled="busy" @click="observe(j.id)">只读核对</el-button></td></tr></tbody></table></div><p v-if="readKnown && !jobs.length">本账户尚无全盘任务记录。</p>
        </el-tab-pane>
        <el-tab-pane label="中断恢复" name="recovery">
          <p>维护清单只显示活动任务标识、状态和时间，不显示其他账户的路径与报告。收尾会请求停止原任务，并核对原进程退出、扫描锁释放和执行范围为空；不能核对时继续保留未知状态，绝不重新扫描。</p>
          <div class="disk-table" role="region" aria-label="活动任务维护清单，可横向滚动" tabindex="0"><table><thead><tr><th>任务标识</th><th>状态 / 更新时间</th><th>操作</th></tr></thead><tbody><tr v-for="j in recovery" :key="j.id"><td>{{j.id}}</td><td>{{hostStateLabel(j.state)}}<small>{{j.updated_at}}</small></td><td><el-button text :disabled="busy" @click="recoverID=j.id;confirm=''">选择收尾</el-button></td></tr></tbody></table></div><p v-if="readKnown && !recovery.length">没有尚未结束的全盘任务。</p>
          <template v-if="recoverID"><p class="disk-warning">停止并收尾原任务：{{recoverID}}。不会删除用户文件，也不授予私有报告访问权。</p><el-input v-model="confirm" aria-label="确认停止并收尾原任务" :placeholder="'CLOSE '+recoverID" :disabled="busy"/><el-button type="warning" :disabled="busy || confirm!=='CLOSE '+recoverID" @click="recover">停止并核对收尾</el-button></template>
        </el-tab-pane>
      </el-tabs>
      <article v-if="selected" class="disk-result" aria-label="原任务进度与分析结果">
        <div class="disk-heading"><div><h3>{{hostStateLabel(reply?.observation?.state || selected.state)}}</h3><p class="disk-path">原任务：{{selected.id}}</p></div><div><el-button :disabled="busy" @click="observe(selected.id)">只读核对原任务</el-button><el-button v-if="!hostTerminal(selected.state)" type="warning" :disabled="busy || selected.state==='cancel_requested'" @click="cancelJob">{{selected.state==='cancel_requested'?'正在核对取消':'取消原扫描'}}</el-button></div></div>
        <p v-if="!reply">尚未核对当前进度或原报告；不是零占用，也不表示任务已经结束。</p>
        <template v-else>
          <el-alert v-if="!reply.terminal_verified" title="当前是进行中或待核对数据，不是最终结果。只读轮询不会重新扫描；关闭页面不取消后台任务。" type="info" :closable="false" />
          <el-alert v-else-if="reply.report_unavailable" title="原任务已核对收尾，但没有可验证的完整报告。未补造扫描统计、零占用或成功结果。" type="warning" :closable="false" />
          <p v-if="reply.observation">原进程：{{reply.observation.original_process==='alive'?'仍在运行':reply.observation.original_process==='gone'?'已退出':'未知'}}；执行范围：{{reply.observation.original_scope==='busy'?'仍有进程':reply.observation.original_scope==='empty'?'已空':'未知'}}；扫描锁：{{reply.observation.run_lease_free?'已释放':'仍被持有或未知'}}</p>
          <template v-if="report">
            <p class="disk-path">本次范围：{{report.selected_path}}；开始：{{report.started_at}}<span v-if="report.finished_at">；结束：{{report.finished_at}}</span></p>
            <div class="disk-metrics"><div><small>已读取元数据</small><strong>{{hostCount(report.metadata_entries_read)}}</strong></div><div><small>已分配块（inode 去重）</small><strong>{{hostBytes(report.inode_allocated_bytes)}}</strong></div><div><small>逻辑大小（按文件路径累计）</small><strong>{{hostBytes(report.regular_logical_entry_bytes)}}</strong></div><div><small>唯一普通文件</small><strong>{{hostCount(report.unique_regular_files)}}</strong></div></div>
            <p class="disk-notice">已分配块不等于独占物理空间；硬链接按本次范围内首次观察的 inode 归属，目录排行不能相加。稀疏或压缩候选 {{hostCount(report.allocation_below_logical_files)}}，不证明实际稀疏区或可回收空间。扫描期间文件变化可能影响结果。</p>
            <el-alert v-if="report.state!=='complete' || !report.index_flushed" :title="`结果未完整：${report.partial_reasons.map(hostReasonLabel).join('、') || '仍在扫描'}${report.index_flushed?'':'；索引未确认写入'}`" type="warning" :closable="false" />
            <div class="disk-metrics"><div><small>所在文件系统总容量</small><strong>{{hostCapacityValue(capacity,'total_bytes')}}</strong></div><div><small>已用容量</small><strong>{{hostCapacityValue(capacity,'used_bytes')}}</strong></div><div><small>普通账户可用</small><strong>{{hostCapacityValue(capacity,'available_bytes')}}</strong></div><div><small>可用 inode</small><strong>{{hostCapacityValue(capacity,'free_inodes')}}</strong></div></div>
            <p class="disk-notice">容量来自结果时的挂载视图，不是当前实时值，不代表选定目录独占；无可靠容量时显示“未知”。</p>
            <div class="disk-table-title"><h4>目录与大文件排行（各最多 100 项）</h4><el-input v-model="filter" aria-label="筛选扫描排行" placeholder="筛选完整路径" clearable/></div>
            <div v-for="group in [{name:'目录排行',rows:directoryRows,directory:true},{name:'大文件排行',rows:fileRows,directory:false}]" :key="group.name"><h4>{{group.name}}</h4><div class="disk-table" role="region" :aria-label="group.name+'，可横向滚动'" tabindex="0"><table><thead><tr><th>路径</th><th>逻辑大小</th><th>已分配块</th><th>操作</th></tr></thead><tbody><tr v-for="(row,i) in group.rows" :key="i"><td>{{row.path}}<small v-if="!row.path_actionable">转义或截断路径，仅展示</small></td><td>{{hostBytes(row.logical_bytes)}}</td><td>{{hostBytes(row.allocated_bytes)}}</td><td><button v-if="hostDrillDirectory(originalMount,row,group.directory)!==undefined" class="disk-link" :disabled="busy || !!pending" @click="chooseDirectory(row,group.directory)">{{group.directory?'选择此目录':'选择所在目录'}}</button><span v-else>仅统计</span></td></tr></tbody></table></div></div>
            <el-button :disabled="!reply.terminal_verified || !result" @click="exportResult">导出已核对结果 JSON</el-button>
          </template>
        </template>
      </article>
      <p v-if="checkedAt" class="disk-notice">最近只读核对：{{checkedAt}}。历史只属于原账户；全盘页面不提供删除文件功能。</p>
    </template>
  </section>
</template>

<style scoped>
.host-disk{min-width:0;color:var(--el-text-color-primary)}.disk-heading,.disk-table-title{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap}.disk-heading h3{margin:8px 0}.disk-heading p{margin:6px 0;color:var(--el-text-color-secondary)}.disk-heading>.el-button{margin-left:0}.host-disk .el-alert{margin:12px 0}.host-disk p{line-height:1.65;overflow-wrap:anywhere}.disk-notice{color:var(--el-text-color-secondary);font-size:13px}.disk-warning{color:var(--el-color-warning-dark-2);margin:8px}.disk-path{overflow-wrap:anywhere;font-family:ui-monospace,monospace;font-size:13px}.disk-controls{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:16px;margin:18px 0}.disk-controls label{display:flex;flex-direction:column;gap:8px;min-width:0}.disk-controls select{padding:10px;border:1px solid var(--el-border-color);border-radius:5px;background:var(--el-bg-color);color:var(--el-text-color-regular);width:100%;min-width:0}.disk-pending{border:1px solid var(--el-color-warning-light-5);background:var(--el-color-warning-light-9);padding:14px;border-radius:8px;margin:12px 0;overflow-wrap:anywhere}.disk-table-title .el-input{max-width:280px}.disk-table{overflow:auto;max-height:380px;border:1px solid var(--el-border-color-lighter);border-radius:6px;margin:12px 0;max-width:100%}.disk-table table{width:100%;min-width:620px;border-collapse:collapse;table-layout:fixed;font-size:13px}.disk-table td,.disk-table th{text-align:left;padding:11px;border-bottom:1px solid var(--el-border-color-lighter);overflow-wrap:anywhere;vertical-align:top}.disk-table th{background:var(--el-fill-color-light);position:sticky;top:0}.disk-table small{display:block;color:var(--el-text-color-secondary);margin-top:5px}.disk-table th:first-child{width:42%}.disk-result{border-top:1px solid var(--el-border-color);margin-top:20px;padding-top:12px}.disk-metrics{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px;margin:15px 0}.disk-metrics>div{border:1px solid var(--el-border-color-lighter);border-radius:8px;padding:14px;overflow-wrap:anywhere;background:var(--el-fill-color-extra-light)}.disk-metrics small{display:block;color:var(--el-text-color-secondary);line-height:1.5}.disk-metrics strong{display:block;font-size:20px;margin-top:8px}.disk-link{border:0;background:none;color:var(--el-color-primary);padding:3px;cursor:pointer;text-align:left}.disk-link:disabled{opacity:.5;cursor:not-allowed}.disk-link:focus-visible,.disk-table:focus-visible{outline:2px solid var(--el-color-primary);outline-offset:2px}@media(max-width:620px){.disk-controls{grid-template-columns:1fr}.disk-metrics{grid-template-columns:repeat(2,minmax(0,1fr))}.disk-heading>div{min-width:0}.disk-heading .el-button{margin:4px 4px 4px 0}.disk-table-title .el-input{max-width:none}.disk-metrics strong{font-size:17px}}
</style>
