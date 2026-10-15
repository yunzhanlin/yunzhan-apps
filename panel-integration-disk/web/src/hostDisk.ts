import { menuPermissionIDs, validAccessPlan, type AccessPlan } from './menuPermissions.ts';

export const hostDiskVersion = '1.4.0';
export const hostDiskBase = '/software/disk-analysis/host';
export type HostDiskAPI = <T>(path: string, method?: string, body?: unknown, key?: string, signal?: AbortSignal) => Promise<T>;
export interface HostMount {
  mount_id: string; parent_id: string; mount_point: string; filesystem_root: string;
  filesystem: string; filesystem_class: string; binding_sha256: string;
  path_actionable: boolean; mount_read_only: boolean; stacked_mount_point: boolean;
}
export interface HostDiskState {
  format: number; installed: boolean; app_version: string; installation_id: string; app_manifest_sha256: string;
  inventory: null | { host: { boot_id: string; mount_namespace_id: string }; inventory: { format: number; mounts: HostMount[]; mount_list_complete: boolean; snapshot_consistent: boolean; binding_sha256: string } };
}
export interface HostSelection {
  boot_id: string; mount_namespace_id: string; mount_id: string; mount_binding_sha256: string;
  relative_directory: string; app_version: string; installation_id: string; app_manifest_sha256: string;
}
export interface HostJob {
  id: string; request: { format: number; job_id: string; actor_id: string; access_revision: string; selection: HostSelection };
  state: string; cancel_state: string; created_at: string; updated_at: string;
}
export interface HostUsageRow { path: string; logical_bytes: string; allocated_bytes: string; path_actionable: boolean; link_count: number }
export interface HostReport {
  format: number; mount_id: string; mount_binding_sha256: string; selected_path: string; state: string;
  started_at: string; finished_at: string; enumeration_complete: boolean; snapshot_consistent: boolean;
  exclusive_physical_bytes: boolean; index_flushed: boolean; accounting: string; directory_attribution: string;
  metadata_entries_read: string; regular_file_entries: string; unique_regular_files: string; duplicate_regular_inodes: string;
  directory_entries: string; symbolic_links: string; special_nodes: string; regular_logical_entry_bytes: string;
  regular_unique_logical_bytes: string; regular_allocated_bytes: string; directory_allocated_bytes: string;
  symlink_allocated_bytes: string; special_allocated_bytes: string; inode_allocated_bytes: string;
  allocation_below_logical_files: string; excluded_child_mounts: string; excluded_own_worker_directories: string;
  unavailable_metadata_entries: string; skipped_directories: string; duplicate_directory_inodes: string;
  partial_reasons: string[]; top_files: HostUsageRow[]; top_directories: HostUsageRow[];
}
export interface HostCapacity {
  state: string; total_bytes: string | null; free_bytes: string | null; available_bytes: string | null;
  used_bytes: string | null; reserved_free_bytes: string | null; total_inodes: string | null;
  free_inodes: string | null; used_inodes: string | null; inode_state: string;
  capacity_view_sha256: string; capacity_may_overlap: boolean; snapshot_consistent: boolean;
}
export interface HostResult { format: number; request: HostJob['request']; state: string; report: HostReport | null; capacity: HostCapacity; error_code: string; at: string }
export interface HostObservation {
  format: number; request: HostJob['request']; state: string; terminal_verified: boolean;
  original_process: string; original_scope: string; run_lease_free: boolean;
  progress: null | { report: HostReport; at: string }; result: HostResult | null;
}
export interface HostReply { job: HostJob; result?: HostResult; observation?: HostObservation; terminal_verified: boolean; report_unavailable?: boolean }
export interface HostRecovery { id: string; state: string; created_at: string; updated_at: string }
const object = (v: unknown): v is Record<string, any> => !!v && typeof v === 'object' && !Array.isArray(v);
export const hostID = (v: unknown): v is string => typeof v === 'string' && /^[a-f0-9]{32}$/.test(v);
const sha = (v: unknown): v is string => typeof v === 'string' && /^[a-f0-9]{64}$/.test(v);
const boot = (v: unknown): v is string => typeof v === 'string' && /^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(v);
export const hostInteger = (v: unknown): v is string => typeof v === 'string' && /^(0|[1-9][0-9]{0,19})$/.test(v) && BigInt(v) <= 18446744073709551615n;
const positive = (v: unknown): v is string => hostInteger(v) && v !== '0';
const timestamp = (v: unknown) => typeof v === 'string' && /^20[2-9][0-9]-/.test(v) && Number.isFinite(Date.parse(v));
const namespace = (v: unknown) => typeof v === 'string' && v.split(':').length === 2 && hostInteger(v.split(':')[0]) && positive(v.split(':')[1]);
export function hostDiskAllowed(v: AccessPlan | null | undefined): boolean {
  return validAccessPlan(v) && v.role === 'admin' && menuPermissionIDs.every(id => v.menu_ids.includes(id));
}
export function hostPath(v: unknown): v is string {
  if (typeof v !== 'string' || !v.startsWith('/') || new TextEncoder().encode(v).length > 4096 || /[\u0000-\u001f\u007f\ud800-\udfff]/u.test(v)) return false;
  return v === '/' || !v.endsWith('/') && v.slice(1).split('/').every(p => p !== '' && p !== '.' && p !== '..');
}
export function hostRelative(v: unknown): v is string { return v === '' || typeof v === 'string' && !v.startsWith('/') && hostPath('/' + v); }
export function validHostSelection(v: unknown): v is HostSelection {
  return object(v) && boot(v.boot_id) && namespace(v.mount_namespace_id) && positive(v.mount_id) && sha(v.mount_binding_sha256)
    && hostRelative(v.relative_directory) && v.app_version === hostDiskVersion && hostID(v.installation_id) && sha(v.app_manifest_sha256);
}
const selectionKeys = ['boot_id','mount_namespace_id','mount_id','mount_binding_sha256','relative_directory','app_version','installation_id','app_manifest_sha256'] as const;
export function sameHostSelection(a: HostSelection, b: HostSelection): boolean { return selectionKeys.every(k => a[k] === b[k]); }
export function validHostState(v: unknown): v is HostDiskState {
  if (!object(v) || v.format !== 1 || typeof v.installed !== 'boolean' || typeof v.app_version !== 'string') return false;
  if (!v.installed) return v.app_version === '' && v.installation_id === '' && v.app_manifest_sha256 === '' && v.inventory === null;
  if (v.app_version !== hostDiskVersion) return v.installation_id === '' && v.app_manifest_sha256 === '' && v.inventory === null;
  const i = v.inventory?.inventory, h = v.inventory?.host;
  return hostID(v.installation_id) && sha(v.app_manifest_sha256) && object(h) && boot(h.boot_id) && namespace(h.mount_namespace_id)
    && object(i) && i.format === 1 && i.mount_list_complete === true && i.snapshot_consistent === false && sha(i.binding_sha256)
    && Array.isArray(i.mounts) && i.mounts.length > 0 && i.mounts.length <= 16384
    && new Set(i.mounts.map((m: any) => m?.mount_id)).size === i.mounts.length && i.mounts.every((m: unknown) => object(m) && positive(m.mount_id) && positive(m.parent_id)
      && typeof m.mount_point === 'string' && m.mount_point.startsWith('/') && m.mount_point.length <= 12288
      && typeof m.filesystem_root === 'string' && m.filesystem_root.startsWith('/') && m.filesystem_root.length <= 12288
      && typeof m.filesystem === 'string' && m.filesystem.length > 0 && m.filesystem.length <= 64
      && ['local','kernel_virtual','remote_or_userspace','unknown'].includes(m.filesystem_class) && sha(m.binding_sha256)
      && typeof m.path_actionable === 'boolean' && typeof m.mount_read_only === 'boolean' && typeof m.stacked_mount_point === 'boolean'
      && (!m.path_actionable || hostPath(m.mount_point) && hostPath(m.filesystem_root)));
}
export function hostSelection(state: HostDiskState | undefined, id: string, directory: string): HostSelection | undefined {
  if (!validHostState(state) || state.app_version !== hostDiskVersion || !state.inventory || !hostRelative(directory)) return;
  const m = state.inventory.inventory.mounts.find(m => m.mount_id === id);
  if (!m || m.filesystem_class !== 'local' || !m.path_actionable) return;
  return { boot_id: state.inventory.host.boot_id, mount_namespace_id: state.inventory.host.mount_namespace_id, mount_id: m.mount_id, mount_binding_sha256: m.binding_sha256, relative_directory: directory,
    app_version: state.app_version, installation_id: state.installation_id, app_manifest_sha256: state.app_manifest_sha256 };
}
export const hostTerminal = (s: string) => ['complete','partial','failed','canceled'].includes(s);
export function validHostJob(v: unknown): v is HostJob {
  return object(v) && hostID(v.id) && object(v.request) && v.request.format === 1 && v.request.job_id === v.id
    && hostID(v.request.actor_id) && positive(v.request.access_revision) && validHostSelection(v.request.selection)
    && ['queued','dispatching','running','uncertain','cancel_requested','complete','partial','failed','canceled'].includes(v.state)
    && ['','requested','not_dispatched'].includes(v.cancel_state) && timestamp(v.created_at) && timestamp(v.updated_at);
}
const counters = ['metadata_entries_read','regular_file_entries','unique_regular_files','duplicate_regular_inodes','directory_entries','symbolic_links','special_nodes','regular_logical_entry_bytes','regular_unique_logical_bytes','regular_allocated_bytes','directory_allocated_bytes','symlink_allocated_bytes','special_allocated_bytes','inode_allocated_bytes','allocation_below_logical_files','excluded_child_mounts','excluded_own_worker_directories','unavailable_metadata_entries','skipped_directories','duplicate_directory_inodes'];
function validReport(v: unknown, s: HostSelection): v is HostReport {
  const rows = (v: unknown) => Array.isArray(v) && v.length <= 100 && v.every(r => object(r) && typeof r.path === 'string' && r.path.startsWith('/') && new TextEncoder().encode(r.path).length <= 515 && hostInteger(r.logical_bytes) && hostInteger(r.allocated_bytes) && typeof r.path_actionable === 'boolean' && Number.isSafeInteger(r.link_count) && r.link_count >= 0 && r.link_count <= 4294967295);
  return object(v) && v.format === 1 && v.mount_id === s.mount_id && v.mount_binding_sha256 === s.mount_binding_sha256
    && typeof v.selected_path === 'string' && v.selected_path.startsWith('/') && new TextEncoder().encode(v.selected_path).length <= 515
    && ['running','complete','partial','failed','canceled'].includes(v.state) && typeof v.enumeration_complete === 'boolean'
    && v.enumeration_complete === (v.state === 'complete') && v.snapshot_consistent === false && v.exclusive_physical_bytes === false && typeof v.index_flushed === 'boolean'
    && (['failed','canceled'].includes(v.state) || v.index_flushed === true)
    && v.accounting === 'st_blocks_512_per_inode_not_exclusive_extents' && v.directory_attribution === 'first_observed_inode_within_this_scan'
    && counters.every(k => hostInteger(v[k])) && Array.isArray(v.partial_reasons) && v.partial_reasons.length <= 64 && v.partial_reasons.every((r: unknown) => typeof r === 'string' && r.length < 128)
    && rows(v.top_files) && rows(v.top_directories) && timestamp(v.started_at) && (v.state === 'running' ? v.finished_at === '' : timestamp(v.finished_at));
}
function validResult(v: unknown, j: HostJob, terminal = true): v is HostResult {
  return object(v) && v.format === 1 && hostTerminal(v.state) && (!terminal || v.state === j.state) && typeof v.error_code === 'string'
    && object(v.request) && v.request.job_id === j.id && v.request.actor_id === j.request.actor_id && v.request.access_revision === j.request.access_revision
    && validHostSelection(v.request.selection) && sameHostSelection(v.request.selection,j.request.selection)
    && timestamp(v.at) && object(v.capacity) && typeof v.capacity.state === 'string'
    && (v.report === null ? !['complete','partial'].includes(v.state) : validReport(v.report,j.request.selection) && v.report.state === v.state);
}
export function validHostReply(v: unknown, expected: HostJob): v is HostReply {
  if (!object(v) || !validHostJob(v.job) || v.job.id !== expected.id || v.job.request.actor_id !== expected.request.actor_id || v.job.request.access_revision !== expected.request.access_revision || !sameHostSelection(v.job.request.selection,expected.request.selection) || typeof v.terminal_verified !== 'boolean') return false;
  if (v.terminal_verified !== hostTerminal(v.job.state)) return false;
  if (v.result !== undefined && !validResult(v.result,v.job)) return false;
  if (v.observation !== undefined) {
    const o = v.observation;
    if (!object(o) || o.format !== 1 || o.request?.job_id !== expected.id || o.request?.actor_id !== expected.request.actor_id || !validHostSelection(o.request?.selection) || !sameHostSelection(o.request.selection,expected.request.selection)
      || !['alive','gone','unknown'].includes(o.original_process) || !['busy','empty','unknown'].includes(o.original_scope) || typeof o.run_lease_free !== 'boolean' || o.terminal_verified !== v.terminal_verified) return false;
    if (o.result !== null && !validResult(o.result,v.job,v.terminal_verified) || o.progress !== null && (!object(o.progress) || !validReport(o.progress.report,expected.request.selection))) return false;
    if (v.terminal_verified && (o.original_process !== 'gone' || o.original_scope !== 'empty' || o.run_lease_free !== true)) return false;
  }
  if (v.terminal_verified && ['complete','partial'].includes(v.job.state) && !v.result && !v.observation?.result) return false;
  return true;
}
export function hostReport(reply: HostReply | undefined): HostReport | undefined {
  return reply?.result?.report ?? reply?.observation?.result?.report ?? reply?.observation?.progress?.report ?? undefined;
}
export function hostBytes(v: unknown): string {
  if (!hostInteger(v)) return '未知';
  const n = BigInt(v), units = ['B','KiB','MiB','GiB','TiB','PiB','EiB'];
  let unit = 0, scale = 1n;
  while (unit < units.length - 1 && n >= scale * 1024n) { scale *= 1024n; unit++; }
  return unit === 0 ? `${n} B` : `${n / scale}.${(n % scale) * 10n / scale} ${units[unit]}`;
}
export function hostCount(v: unknown): string { return hostInteger(v) ? v : '未知'; }
export function hostCapacityValue(c: HostCapacity | undefined, key: keyof HostCapacity): string {
  if (!c || c.state !== 'available' || c.capacity_may_overlap !== true || c.snapshot_consistent !== false) return '未知';
  if (['total_inodes','free_inodes','used_inodes'].includes(key)) return c.inode_state === 'available' ? hostCount(c[key]) : '未知';
  return hostBytes(c[key]);
}
export function hostDrillDirectory(m: HostMount | undefined, r: HostUsageRow, directory: boolean): string | undefined {
  if (!m || !r.path_actionable || !hostPath(r.path) || !hostPath(m.mount_point)) return;
  let p = directory ? r.path : r.path.slice(0,r.path.lastIndexOf('/')) || '/';
  if (p === m.mount_point) return '';
  const prefix = m.mount_point === '/' ? '/' : m.mount_point + '/';
  if (!p.startsWith(prefix)) return;
  p = p.slice(prefix.length);
  return hostRelative(p) ? p : undefined;
}
export const hostStateLabel = (s: string) => ({queued:'等待派发',dispatching:'已提交派发，待核对',starting:'正在核对启动',running:'扫描中',settling:'正在核对退出',uncertain:'状态待核对',cancel_requested:'已请求取消，待核对退出',complete:'完整枚举',partial:'部分结果',failed:'失败',canceled:'已取消'}[s] ?? '未知状态');
export const hostReasonLabel = (s: string) => ({child_mount_excluded:'已排除子挂载',inode_or_mount_changed:'文件身份或挂载发生变化',kernel_boundary_unavailable:'无法核对内核隔离边界',metadata_unavailable:'部分元数据无法读取',directory_inode_repeated:'遇到重复目录 inode',entry_budget_reached:'达到元数据数量上限',own_worker_state_excluded:'已排除扫描程序自身状态目录',depth_budget_reached:'达到目录深度上限',canceled:'已取消',deadline_reached:'达到扫描时限',index_unavailable_or_capacity_reached:'索引不可用或达到容量上限',usage_overflow:'统计值超过精确范围',original_index_already_used:'原索引不可重复使用',progress_or_authority_rejected:'进度写入或当前权限无法核对',scope_unavailable:'扫描范围不可用',index_unavailable_or_full:'索引不可用或空间不足',mount_changed_or_boundary:'挂载变化或跨越隔离边界',scan_or_authority_unavailable:'扫描条件或当前权限不可用'}[s] ?? `其他原因（${s}）`);
