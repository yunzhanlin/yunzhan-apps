<script setup lang="ts">
import { computed, ref } from "vue";
import {remoteConnectionRow} from "./remoteSync";
import ThreatIDSReport from "./ThreatIDSReport.vue";
import AnalyticsLatencyReport from "./AnalyticsLatencyReport.vue";
import AnalyticsGeographyReport from "./AnalyticsGeographyReport.vue";
import DailyReportSummary from "./DailyReportSummary.vue";
import PlatformHealthReport from "./PlatformHealthReport.vue";
import {dailySnapshot} from "./dailyReportView";
import { loadBalanceEntryRow, loadBalanceNodeSummary, loadBalanceTransitions } from "./loadBalanceReport";
import {taskProcessColumns,taskProcessRows} from './taskManager';
import {statisticsHistoryNotice} from './statisticsHistory';
import {diskDirectorySelection,diskFileSelection,diskValueNotice} from './diskUsage';
import {mobileArtifactURL} from './mobileDelivery';
const props = defineProps<{ id: string; report: Record<string, any> }>();
const taskQuery=ref(''),taskManagedOnly=ref(false);
const emit = defineEmits<{ select: [row: Record<string, any>] }>();
const names: Record<string, string> = {
  pm2_version: "PM2 版本",
  signal_accepted:"信号发送已接受",
  exit_verified:"退出已核对",
  connections:"连接明细",
  connections_available:"连接数据可核对",
  cpu_available:"CPU 速率可核对",
  io_available:"I/O 速率可核对",
  sample_limit:"进程采样上限",
  display_limit:"进程展示上限",
  sampled_processes:"已采样进程数",
  displayed_processes:"本次展示进程数",
  display_limited:"展示限制已触发",
  load_transactions:"实际配置事务",
  transaction_state:"事务状态",
  transaction_format:"事务格式",
  transaction_files:"完整恢复文件数",
  transaction_sha256:"完整事务文件 SHA-256",
  transaction_bytes:"事务文件大小",
  transaction_archived:"已保留归档",
  transaction_archivable:"当前允许归档",
  transaction_active_count:"活动事务记录数",
  transaction_archive_count:"归档事务记录数",
  transaction_active_bytes:"活动事务逻辑字节",
  transaction_archive_bytes:"归档事务逻辑字节",
  transaction_archive_ready:"归档维护前提已满足",
  transaction_archive_blocked:"归档暂停原因",
  configuration_changed:"修改入口配置",
  requests: "请求数",
  history_persistent: "已持久化保存",
  history_retention_days: "历史保留天数",
  history_row_limit: "全站历史行数上限",
  history_backlog_bytes: "尚未读取的日志",
  history_blocked_sources: "进度冲突或缺失来源",
  history_compressed_sources: "尚未完成或无法导入的压缩归档",
  history_unsupported_rotation_sources: "尚不能核对的轮转来源",
  history_verified_compressed_sources: "完整校验过的压缩来源",
  history_deferred_compressed_sources: "校验超时后延后重试的压缩来源",
  history_gzip_read_timeout_seconds: "每个压缩来源校验时间上限（秒）",
  history_gzip_scheduler_site_limit: "压缩轮询网站身份上限",
  history_request_ids_enabled: "请求标识去重已启用",
  history_duplicate_requests: "本次识别并跳过的重复请求",
  history_request_receipt_limit: "全站去重身份记录上限",
  history_gzip_import_enabled: "压缩归档导入已启用",
  history_gzip_scan_limit_per_pass: "每次完整校验的压缩归档上限",
  history_gzip_legacy_missing_id_policy: "旧压缩行标识策略",
  history_compressed_source_limit_bytes: "单个压缩来源校验字节上限",
  history_compressed_expansion_limit_bytes: "单个归档解压字节上限",
  history_missing_log: "当前无可读访问日志",
  history_invalid_lines: "历史采集无效行",
  history_evicted_rows: "因行数上限退役的历史",
  history_expired_streams: "本次退役的过期已读文件进度",
  history_before_retention: "查询开始早于保留窗口",
  history_checked_at: "本次增量核对（UTC）",
  history_first_request: "最早保留请求（UTC）",
  history_last_request: "最近保留请求（UTC）",
  history_raw_user_agents_stored: "保存原始 User-Agent",
  history_query_strings_stored: "保存查询参数",
  history_worker_checked_at: "后台采集最近核对（UTC）",
  history_worker_error: "后台采集告警",
  history_worker_fresh: "后台采集状态新鲜",
  unique_ips: "独立 IP",
  bytes: "流量 / 大小",
  errors: "错误请求",
  bots: "爬虫请求",
  slow_count: "慢请求",
  slow_threshold_seconds: "慢请求阈值（秒）",
  cardinality_limited: "统计维度已达上限",
  average_seconds: "平均响应（秒）",
  max_seconds: "最大响应（秒）",
  qps_last_minute: "最近一分钟 QPS",
  total_bytes: "总占用",
  unique_logical_bytes: "去重后的逻辑大小",
  allocated_bytes: "已分配块大小（范围内 inode 去重）",
  allocated_file_bytes: "该 inode 已分配块大小",
  unique_files: "唯一普通文件数",
  hardlink_entries: "重复硬链接路径数",
  sparse_candidates: "稀疏或压缩候选数（inode 去重）",
  ignored_links: "跳过的符号链接",
  ignored_special: "跳过的特殊文件",
  foreign_filesystems_skipped: "跳过的其他文件系统入口",
  directory_cycles_skipped: "跳过的重复目录身份",
  entries_scanned: "已检查目录项",
  entry_limited: "目录项达到上限",
  depth_limited: "目录深度达到上限",
  classification_limited: "分类或路径展示已达上限",
  scan_complete: "扫描范围已遍历完整",
  read_batch_size: "每批读取目录项数",
  allocation_basis: "分配块计算方式",
  snapshot_consistent: "原子一致性快照",
  filesystem_available: "文件系统容量可核对",
  filesystem_inodes_available: "文件系统 inode 容量可核对",
  filesystem_error: "文件系统容量读取错误",
  filesystem_capacity_bytes: "所在文件系统总容量（非本站占用）",
  filesystem_used_bytes: "所在文件系统已使用",
  filesystem_available_bytes: "所在文件系统普通用户可用",
  filesystem_reserved_bytes: "文件系统保留空间",
  filesystem_total_inodes: "所在文件系统 inode 总数",
  filesystem_free_inodes: "所在文件系统可用 inode",
  filesystem_used_inodes: "所在文件系统已用 inode",
  link_count: "inode 硬链接总数",
  allocation_below_logical: "分配块少于逻辑大小（不单独证明稀疏区）",
  files: "文件数",
  scanned_php: "扫描 PHP 文件",
  pid: "PID",
  name: "名称",
  cpu_percent: "CPU %",
  memory: "内存",
  read_rate: "读取 / 秒",
  write_rate: "写入 / 秒",
  state: "状态",
  managed: "受管",
  can_terminate: "允许终止",
  start_time: "进程身份",
  path: "路径",
  line: "行号",
  rule: "风险规则",
  severity: "风险等级",
  evidence: "代码命中",
  time: "时间",
  ip: "IP",
  method: "方法",
  status: "状态码",
  seconds: "耗时（秒）",
  browser: "浏览器",
  device: "设备",
  domain: "域名",
  port: "端口",
  entry: "程序入口",
  environment_keys: "已设置变量名称",
  bind_address: "监听 IP",
  passive_address: "NAT / 被动通告地址",
  passive_start: "被动起始端口",
  passive_end: "被动结束端口",
  certificate_id: "证书标识",
  max_clients: "最大并发连接",
  max_per_ip: "每 IP 连接上限",
  idle_minutes: "空闲超时（分钟）",
  service_active: "服务正在运行",
  boot_enabled: "开机启动",
	state_known: "运行状态已核对",
	runtime_validated: "本次已验证入口运行",
	preserved_stopped: "已保留停止状态",
  data_tls_required: "数据通道强制加密",
  tls_required: "控制通道强制加密",
  tls_verified: "实际 TLS 探测通过",
  certificate: "域名证书",
  certificate_error: "证书告警",
  recovery_pending: "存在待恢复配置",
  runtime_binary: "实际独立运行时",
  runtime_error: "运行时完整性告警",
  account_limits_ready: "受管账户限制已就绪",
  restart_verified: "切换后 TLS 已验证",
  firewall_changed: "自动修改防火墙",
  credentials_sent: "健康探测发送凭据",
  config: "实际服务配置",
  exposure_approved: "已确认非回环暴露",
  fingerprint: "证书摘要",
  trusted: "系统信任链有效",
  backup_id: "私有恢复备份标识",
  package_sha256: "清单摘要",
  lock_sha256: "锁定文件摘要",
  service_state: "部署进程状态",
  backup_path: "原依赖保留位置",
  allow_install_scripts: "网站用户安装脚本",
  archived: "已归档记录数",
  records_retained: "记录可恢复",
  dependency_directories_retained: "依赖备份未删除",
  id: "标识",
  site_id: "网站 ID",
  username: "用户名",
	quota_mb: "容量限制 MiB（0 不限）",
	quota_files: "数量限制（0 不限）",
	upload_kb: "上传 KiB/s（0 不限）",
	download_kb: "下载 KiB/s（0 不限）",
	max_sessions: "会话数（0 不限）",
	client_allow: "允许客户端 IP",
	client_deny: "拒绝客户端 IP",
	quota_usage_files: "已统计文件与目录",
	quota_usage_bytes: "已统计容量（字节）",
	quota_usage_known: "容量计数已知",
	soft_quota: "FTP 软配额（非磁盘硬配额）",
	shared_home_counter: "同目录账户共享容量计数",
	new_connections_only: "变更用于后续新连接",
  role: "角色",
  site_ids: "网站范围",
  menu_ids: "菜单授权",
  full_admin: "完整权限管理员",
  sessions: "有效会话",
  totp_enabled: "两步验证",
  source: "源 / 导出路径",
  read_only: "只读",
  address: "节点地址",
  sticky: "IP 会话粘滞",
  stale: "结果已过期或未产生",
  reason: "检查原因",
  scheme: "检查协议",
  tls_verification: "TLS 验证方式",
  check_address: "实际检查地址",
  pending: "存在待恢复事务",
  count: "实际记录数",
  healthy: "健康",
  weight: "权重",
  backup: "备用节点",
  kind: "变更类型",
  before: "基线摘要",
  after: "当前摘要",
  created_at: "创建时间",
  ok: "成功",
  url: "HTTPS 地址",
  total_seconds: "总响应时间",
  not_after: "到期时间",
  issuer: "签发者",
  checked_at: "检查时间（UTC）",
  invalid_lines: "跳过无效日志",
  partial: "结果不完整",
  copied: "已复制",
  skipped: "未变化",
  conflicts: "目标冲突",
  preview: "仅预览（未写入目标）",
  deletes: "删除目标文件",
  checkpoint: "同步检查点",
  restored: "已恢复",
  findings: "风险命中",
  quarantine: "PHP 隔离记录",
  sha256: "文件 SHA-256",
  backup_verified: "独立备份摘要验证",
  backup_error: "备份或目录告警",
  source_present: "原位置存在文件",
  quarantined_count: "已隔离记录",
  pending_transactions: "待修复事务",
  backup_bytes: "原始备份容量",
  backup_budget_bytes: "备份容量预算",
  interpretation: "结果说明",
  updated_at: "最近状态变化",
  mode: "原文件权限",
  independent_backup_retained: "独立备份保留",
  runtime_processes_changed: "自动改变运行进程",
  processes: "真实进程",
  users: "账户",
  apps: "PM2 项目",
  mounts: "NFS 挂载",
  actual_mounted: "真实挂载已验证",
  mount_error: "挂载状态告警",
  exports: "NFS 网站目录导出",
  clients: "允许客户端 IP/CIDR",
  export_id: "NFS 原生导出编号",
  uid: "网站用户 UID",
  gid: "网站用户组 GID",
  encrypted: "传输加密",
  client_identity: "客户端文件身份",
  runtime_ready: "独立运行时就绪",
  runtime_format: "运行时格式",
  private_client_ready: "独立挂载工具就绪",
  actual_nfs_v4_rpc: "真实 NFSv4 RPC 检查通过",
  export_error: "导出目录告警",
  hosts: "主机",
  tokens: "本机只读授权",
  token_id: "授权标识（非访问令牌）",
  telemetry_complete: "CPU / 内存 / 磁盘指标均可用",
  nodes: "上游节点",
  entries: "负载均衡入口",
  http_health: "持续 HTTP 检查",
  http_health_enabled: "持续 HTTP 检查已启用",
  backend_protocol: "后端转发协议",
  http_transitions: "最近 HTTP 状态转换（界面最多 200 条）",
  health_check: "HTTP 检查策略",
  automatic_traffic_changes: "自动修改流量",
  traffic_excluded: "已从新请求流量摘除",
  routing_sequence: "实际流量运行序号",
  excluded_nodes: "实际摘除节点",
  completed_at: "完成时间（UTC）",
  recovered: "本次为显式恢复",
  last_success: "最近一次检查通过",
  http_status: "HTTP 响应状态",
  latency_ms: "耗时（毫秒）",
  failures: "连续失败次数",
  successes: "连续成功次数",
  worker_error: "后台检查错误",
  transitions: "最近状态转换",
  sequence: "转换序号",
  from: "原状态",
  to: "当前状态",
  at: "发生时间（UTC）",
  transport: "转发范围",
  active_health_checks: "主动应用健康检查",
  active_application_health_checks: "主动应用健康检查",
  entry_fingerprint_verified: "入口配置生效指纹已验证",
  transaction_id: "持久事务标识",
  website_files_deleted: "删除网站文件",
  changes: "文件变化",
  largest_files: "最大文件",
  directories: "目录占用",
  children: "一级目录 / 文件占用",
  extensions: "扩展名占用",
  paths: "访问页面",
  status_codes: "状态码",
  hours: "小时趋势（UTC）",
  referers: "访问来源",
  browsers: "浏览器",
  devices: "设备",
  methods: "HTTP 方法",
  spiders: "爬虫",
  visitors: "访客 IP",
  error_requests: "错误请求明细",
  slow_requests: "慢请求明细",
  alerts: "网络变化",
  dns: "DNS 解析",
  http: "HTTP 入口",
  nginx: "Nginx 配置",
  tls_certificate: "TLS 证书",
  enabled: "启用",
  valid: "有效",
  output: "检查输出",
  error: "错误",
  signal: "信号",
  sites: "网站数",
  running_sites: "运行网站",
  plans: "同步计划",
  remote_targets: "跨服务器 SFTP 连接",
  remote_jobs: "远端持久任务",
  remote_backups: "远端实际事务备份",
  remote_backup_archive:"远端保留备份归档",
  backup_snapshot_sha256:"完整备份内容摘要",
  backup_archive_state:"备份归档阶段",
  content_verified:"此次已核对完整文件内容",
  backup_transaction_id: "原事务标识",
  backup_files: "保留文件与容量",
  transaction_limit: "事务数量上限",
  byte_limit: "备份容量上限（字节）",
  transaction_slots_available: "剩余活动事务名额",
  bytes_available: "剩余备份容量",
  next_transaction_capacity_available: "容量可容纳下次交接（不代表可执行）",
  pending_recovery: "存在待恢复交接",
  pending_archive_recovery: "存在待恢复备份归档（阻止新传输）",
  remote_plans: "远端实时与定时计划",
  change_sequence: "已持久接受的变化序号",
  consumed_sequence: "原任务已核对的变化序号",
  pending_sequence: "原预留任务捕获的变化序号",
  plan_revision: "计划修订号",
  excludes: "排除路径前缀",
  remote_target_revision: "绑定连接修订号",
  remote_plan_id: "定时计划标识",
  remote_plan_revision: "提交时计划修订号",
  pending_job_id: "原预留任务标识",
  last_job_id: "最近核对的原任务",
  remote_target_id: "远端连接标识",
  remote_request_id: "远端任务标识",
  job_archived: "任务已归档",
  job_sha256: "完整任务记录摘要",
  archive_bytes: "私有归档占用",
  remote_files_changed: "改变远端文件",
  remote_target: "连接与目录策略",
  root: "远端目标目录",
  backup_root: "公开目录之外的私有备份",
  auth_kind: "认证方式（不回显材料）",
  host_key_fingerprint: "固定 SSH 主机公钥指纹",
  ssh_host_key_verified: "主机公钥已核对",
  sftp_subsystem: "真实 SFTP 子系统已连接",
  job: "远端任务",
  queued: "已接受后台排队（尚未完成）",
  replayed: "读取原任务，未重复创建",
  cancel_requested: "已请求停止后续交接",
  skipped_count: "内容相同的文件数",
  started_at: "开始时间（UTC）",
  finished_at: "完成或停止时间（UTC）",
  policies: "监控策略",
  history: "执行历史",
  plan_errors: "计划记录错误",
  revision: "配置版本",
  realtime: "实时模式",
  watcher_state: "内核监听状态",
  watch_directories: "监听目录数",
  watch_overflows: "事件溢出次数",
  watch_error: "监听降级原因",
  last_trigger: "最近触发方式",
  last_check_at: "最近检查（UTC）",
  interval: "间隔（秒）",
  last_state: "最近执行状态",
  last_error: "最近错误",
  next_run_at: "下次执行（UTC）",
  last_started_at: "最近开始（UTC）",
  last_finished_at: "最近完成（UTC）",
  action: "操作",
  outcome: "结果",
  copied_count: "复制数",
  conflicts_count: "冲突数",
  changes_count: "变更数",
  restored_count: "恢复数",
  history_limited: "有界历史记录",
  total: "匹配记录数",
  retained_count: "已保留记录数",
  retention_days: "保留天数",
  record_limit: "记录安全上限",
  limit: "每页条数",
  offset: "分页起点",
  signature_verified: "签名通过",
  failure_count: "连续失败次数",
  target_site_id: "目标网站 ID",
  report_limited: "展示记录有上限",
  certificates_due_14_days: "14 天内到期证书",
  failed_site_jobs: "失败网站任务",
  failed_runtime_jobs: "失败运行时任务",
  audit_events_24h: "24 小时审计事件",
  score: "健康检查得分",
  passed_checks: "通过检查",
  total_checks: "检查总数",
  recommendations: "处置建议",
  advice: "建议",
  check: "检查项",
  findings_count: "风险命中数",
  severity_counts: "风险级别分布",
  rule_counts: "扫描规则分布",
  reports: "历史日报目录",
  day: "报告日期",
  actor: "操作人",
  trigger: "触发方式",
  listener_details: "监听服务明细",
  listener_count: "监听服务数",
  public_listener_count: "公网监听数",
  new_public_listeners: "新增公网监听",
  connection_count: "TCP 连接数",
  protocol: "协议",
  endpoint: "监听地址",
  public: "非回环监听",
  process: "进程",
  baseline_present: "可信基线已保存",
  baseline_at: "基线时间",
};
const analytics = computed(() =>
  ["website-analytics", "website-statistics-v2"].includes(props.id),
);
function reportLabel(key:string):string {
  if(props.id==='disk-analysis'&&key==='total_bytes')return '逻辑大小（按路径累计）';
  if(props.id==='disk-analysis'&&key==='directories')return '目录逻辑大小（含硬链接路径）';
  if(props.id==='disk-analysis'&&key==='extensions')return '扩展名逻辑大小（含硬链接路径）';
  if(props.id==='platform-ops'&&key==='healthy')return 'HTTPS 与健康协议通过';
  if(props.id==='platform-ops'&&key==='expected_sha')return '主机配置摘要（只读）';
  if(props.id==="files-sync" && props.report.preview===true) {
    const previewLabels:Record<string,string>={copied:"拟复制（尚未写入）",copied_count:"拟复制数",deletes:"拟删除（本模式不删除目标文件）"};
    if(previewLabels[key])return previewLabels[key];
  }
  return names[key] || key;
}
const metrics = computed(() =>
  Object.entries(props.report).filter(
    ([key, value]) =>
      typeof value === "number" &&
      [
        "requests",
        "unique_ips",
        "bytes",
        "errors",
        "bots",
        "slow_count",
        "average_seconds",
        "qps_last_minute",
        "total_bytes",
        "unique_logical_bytes",
        "allocated_bytes",
        "unique_files",
        "hardlink_entries",
        "sparse_candidates",
        "files",
        "scanned_php",
        "findings_count",
        "score",
        "passed_checks",
        "total_checks",
        "listener_count",
        "public_listener_count",
        "new_public_listeners",
        "connection_count",
        "sites",
        "running_sites",
        "certificates_due_14_days",
        "failed_site_jobs",
        "failed_runtime_jobs",
        "audit_events_24h",
      ].includes(key),
  ),
);
const groups = computed(() =>
  Object.entries({...props.report, ...(props.id==="files-sync" && props.report.job ? {remote_jobs:[props.report.job]} : {}), ...(props.id==="files-sync" && props.report.remote_plan ? {remote_plans:[props.report.remote_plan]} : {}), ...(props.id==="load-balance" && Array.isArray(props.report.http_health) ? {http_transitions:loadBalanceTransitions(props.report.http_health)} : {}), ...(props.id==='nfs-manager' && props.report.config ? {exports:props.report.config.exports} : {}), ...(props.report.deployment ? {deployments: [props.report.deployment]} : {})}).filter(
    ([key, value]) => Array.isArray(value) && !["site_ids", "mobile_downloads", "menu_catalog"].includes(key),
  ),
);
const distributions = computed(() =>
  Object.entries(props.report).filter(
    ([key, value]) =>
      value &&
      typeof value === "object" &&
      !Array.isArray(value) &&
      Object.keys(value).length &&
      Object.values(value).every((v) => typeof v === "number") &&
      key !== "filters",
  ),
);
const info = computed(() =>
  Object.entries({...props.report, ...(props.id === 'nfs-manager' && props.report.config ? {bind_address:props.report.config.bind_address, port:props.report.config.port, revision:props.report.config.revision, exposure_approved:props.report.config.exposure_approved} : {})}).filter(
    ([key, value]) =>
      value !== null &&
      value !== undefined &&
      !["scope", "site_id", "filters", "token"].includes(key) &&
      typeof value !== "object" &&
      !metrics.value.some(([k]) => k === key),
  ),
);
function format(key: string, value: unknown, row?:Record<string,unknown>): string {
	if(props.id==='pm2-manager'&&key==='state')return ({active:'运行中',inactive:'已停止',failed:'运行失败',unknown:'无法核对'} as Record<string,string>)[String(value)]||'未知状态';
  if(props.id==='disk-analysis'){const notice=diskValueNotice(props.report,key,value);if(notice)return notice;}
  if(props.id==='disk-analysis'&&key==='allocation_basis')return value==='st_blocks_512_inode_deduplicated'?'Linux 已分配块，按本次扫描范围内 inode 去重':'未知计算方式';
  if(props.id==='website-statistics-v2' && key==='history_request_receipt_limit' && props.report.history_request_ids_enabled!==true)return '未启用（旧版历史模式）';
  if(props.id==='website-statistics-v2' && key==='history_gzip_scan_limit_per_pass' && props.report.history_gzip_import_enabled!==true)return '未启用';
  if(props.id==='task-manager') {
    if(key==='state')return ({R:'运行中',S:'睡眠',D:'不可中断等待',I:'内核空闲',T:'已停止',t:'跟踪停止',Z:'僵尸',X:'已退出',x:'已退出'} as Record<string,string>)[String(value)]||'未知';
    if(key==='connections' && props.report.connections_available!==true)return '未取得，当前状态未知';
    if(['cpu_percent','read_rate','write_rate'].includes(key) && (typeof value!=='number' || !Number.isFinite(value) || value<0 || !row || row[key==='cpu_percent'?'cpu_available':'io_available']!==true))return '未知';
  }
  if(props.id==="load-balance" && key==="transaction_state")return ({committed:"变更已提交",recovered:"恢复已确认",applying:"变更未完成（不可归档）",restored:"原文件已恢复但原生确认未完成（不可归档）"} as Record<string,string>)[String(value)]||String(value??"—");
  if(props.id==="files-sync" && key==="backup_archive_state")return ({reviewed:"内容已核对（未归档）",prepared:"原归档已持久预留（须显式恢复）",reserved:"原迁移已接受或回执待核对（须显式恢复）",committed:"归档已提交，证据保留"} as Record<string,string>)[String(value)]||String(value??"—");
  if(props.id==="files-sync" && key==="backup_files" && Array.isArray(value))return value.map(file=>`${file.name==='previous'?'原文件备份':file.name==='staged'?'保留暂存':file.name} · ${format('bytes',file.bytes)} · ${Number(file.mode).toString(8).padStart(3,'0')}`).join("；")||"空事务目录（仍保留身份）";
  if(props.id==="files-sync" && key==="last_state")return ({pending:"等待下次定时补查",queueing:"已预留原任务，接受结果待核对",queued:"原任务已排队（未完成）",succeeded:"原任务已完整成功",paused:"已暂停",'paused-error':"异常暂停，需核对原任务",removed:"已移除（证据保留）"} as Record<string,string>)[String(value)]||String(value??"—");
  if(props.id==="files-sync" && key==="state")return ({queued:"已排队（未完成）",running:"后台执行中",succeeded:"本次同步已完成",conflicts:"已处理可同步文件，存在保留冲突",failed:"未全部完成或已取消",interrupted:"中断或无法确认，需核对恢复",recovered:"交接已恢复，剩余文件未重传"} as Record<string,string>)[String(value)]||String(value??"—");
  if(props.id==="files-sync" && key==="remote_target" && value && typeof value==="object") {const v=value as Record<string,any>;return `${v.address}:${v.port} · ${v.username} · ${v.root} · 私有备份 ${v.backup_root}`;}
  if (props.id==="load-balance" && ["state","from","to"].includes(key)) return ({unknown:"未达到判定阈值",healthy:"检查正常",unhealthy:"检查失败",stale:"结果已过期",inactive:"后台检查未运行"} as Record<string,string>)[String(value)] || String(value ?? "—");
  if (props.id==="load-balance" && key==="nodes" && Array.isArray(value)) return loadBalanceNodeSummary(value);
  if (props.id==="load-balance" && key==="reason") return ({ok:"状态与内容匹配",request_failed:"请求失败",timeout:"请求超时",status_mismatch:"状态码不匹配（不跟随跳转）",body_incomplete:"响应不完整",body_too_large:"响应超过 16 KiB",content_missing:"响应缺少指定内容",tls_validation_failed:"TLS 证书链、域名或有效期验证失败"} as Record<string,string>)[String(value)] || String(value ?? "—");
  if (props.id === "php-code-security" && key === "state") return ({prepared:"隔离准备中（待核对）",quarantined:"已隔离",conflict:"并发冲突（未覆盖）",restoring:"恢复中断（待核对）",restored:"已恢复",cancelled:"已取消（备份保留）"} as Record<string,string>)[String(value)] || String(value || "—");
  if (key === "watcher_state") return ({ active: "运行中", pending: "准备中", disabled: "未启用", stopped: "已停止", degraded: "已降级（保留补查）", unavailable: "不可用（保留补查）" } as Record<string, string>)[String(value)] || String(value || "—");
  if (typeof value === "boolean") return value ? "是" : "否";
  if (typeof value === "number") {
    if (/bytes|memory|rate/.test(key)) {
      const units = ["B", "KiB", "MiB", "GiB", "TiB"];
      let n = value,
        i = 0;
      while (n >= 1024 && i < 4) {
        n /= 1024;
        i++;
      }
      return `${n.toFixed(i ? 2 : 0)} ${units[i]}${key.endsWith("_rate") ? "/s" : ""}`;
    }
    return Number.isInteger(value) ? String(value) : value.toFixed(3);
  }
  if (Array.isArray(value)) return value.join(", ");
  return String(value ?? "—");
}
function rows(values: any[],key=''): Record<string, any>[] {
  const selected=props.id==='task-manager'&&key==='processes'?taskProcessRows(values,taskQuery.value,taskManagedOnly.value):values;
  return selected.slice(0, props.id==='task-manager' ? 500 : 200).map((v) => {
    if (v === null || typeof v !== "object") return { path: String(v) };
    return {
      ...(v.app || v.mount || {}),
      ...Object.fromEntries(
        Object.entries(v).filter(
          ([, value]) =>
            !value || typeof value !== "object" || Array.isArray(value),
        ),
      ),
      ...(props.id==="load-balance" && Array.isArray(v.nodes) ? loadBalanceEntryRow(v) : {}),
      ...(props.id==="files-sync" ? remoteConnectionRow(v) : {}),
      ...(props.id==="files-sync" && v.remote_target_revision ? {plan_revision:v.revision} : {}),
    };
  });
}
function columns(values: any[]) {
	if(props.id==='pm2-manager'&&values.some(value=>value&&typeof value==='object'&&(value.app||'instances' in value)))return ['id','site_id','state','boot_enabled','state_known','entry','port','instances','memory_mb','revision','environment_keys','error'];
  if(props.id==='task-manager'&&values.some(value=>value&&typeof value==='object'&&'pid' in value))return taskProcessColumns(values);
  if(props.id==="files-sync" && values.some(value=>value && value.backup_archive_state))return ["backup_transaction_id","remote_target_id","revision","backup_bytes","backup_archive_state","backup_snapshot_sha256","pending_recovery","content_verified"];
  if(props.id==="files-sync" && values.some(value=>value && value.backup_transaction_id))return ["backup_transaction_id","remote_target_id","revision","backup_bytes","backup_files","pending_recovery"];
  if(props.id==="files-sync" && values.some(value=>value && value.remote_target_revision))return ["id","remote_target_id","site_id","enabled","realtime","watcher_state","watch_directories","watch_overflows","watch_error","plan_revision","remote_target_revision","interval","next_run_at","last_trigger","change_sequence","consumed_sequence","pending_sequence","last_state","pending_job_id","last_job_id","last_finished_at","last_error","excludes"];
  if(props.id==="files-sync" && values.some(value=>value && value.remote_target))return ["remote_target_id","remote_target","auth_kind","enabled","revision","host_key_fingerprint"];
  if(props.id==="files-sync" && values.some(value=>value && value.remote_request_id))return ["remote_request_id","remote_target_id","remote_plan_id","remote_plan_revision","site_id","state","job_archived","copied_count","skipped_count","conflicts_count","created_at","started_at","finished_at","error"];
  if (props.id==="load-balance" && values.some(value=>value && Array.isArray(value.nodes)))
    return ["domain","port","revision","nodes","backend_protocol","sticky","http_health_enabled","automatic_traffic_changes","routing_sequence","excluded_nodes"];
  if (props.id==="load-balance" && values.some(value=>value && typeof value==="object" && "checked_at" in value && "last_success" in value))
    return ["domain","revision","address","scheme","check_address","state","stale","traffic_excluded","routing_sequence","last_success","http_status","reason","latency_ms","failures","successes","checked_at","tls_verification","worker_error"];
	if (props.id === "php-code-security" && values.some(value=>value && typeof value==='object' && 'state' in value)) return ["id","site_id","path","state","sha256","bytes","mode","source_present","backup_verified","backup_error","revision","created_at","updated_at"];
	if (props.id === "nfs-manager" && values.some(value=>value && typeof value==='object' && 'clients' in value)) return ["id","site_id","path","clients","read_only","export_id","uid","gid"];
	if (props.id === "pure-ftpd" && values.some(value => value && typeof value === "object" && "username" in value)) return ["username","site_id","quota_mb","quota_files","quota_usage_files","quota_usage_bytes","upload_kb","download_kb","max_sessions","client_allow","client_deny"];
  if (props.id === "files-sync" && values.some(value => value && typeof value === "object" && "watcher_state" in value))
    return ["id", "site_id", "target_site_id", "enabled", "realtime", "watcher_state", "watch_directories", "watch_overflows", "watch_error", "revision", "interval", "last_trigger", "last_state", "copied_count", "conflicts_count", "last_error", "excludes"];
  if (values.some(value => value && typeof value === "object" && "watcher_state" in value))
    return ["site_id", "enabled", "realtime", "watcher_state", "watch_directories", "watch_overflows", "watch_error", "revision", "interval", "last_check_at", "last_trigger", "last_state", "last_error", "auto_restore", "signature_verified", "files", "excludes"];
  return [...new Set(rows(values).flatMap((v) => Object.keys(v)))]
    .filter(
      (k) =>
        ![
          "password",
          "token",
          "start_time",
          "site_ids",
          "before",
          "after",
          "can_drill",
          "directory",
        ].includes(k),
    )
    .slice(0, 14);
}
function choose(row: Record<string, any>) {
  if(!row||typeof row!=='object'||Array.isArray(row))return;
  if ("can_terminate" in row && !row.can_terminate) return;
  if (props.id === "disk-analysis") {
    const selected=diskFileSelection(row);if(selected)emit("select",selected);
    return;
  }
  emit("select", { ...row, resource_id: row.resource_id || row.id, site_ids: row.site_ids });
}
function chartRows(values: any, key: string) {
  return Object.entries(values)
    .map(([name, value]) => ({ name, value }))
    .sort((a, b) =>
      key === "hours"
        ? a.name.localeCompare(b.name)
        : Number(b.value) - Number(a.value),
    )
    .slice(0, 100);
}
function directory(name: string) {
  if(props.id!=='disk-analysis')return;
  const selected=diskDirectorySelection(props.report.path,name);if(selected)emit("select",selected);
}
function mobileDownloadURL(item: unknown): string | undefined {
  return mobileArtifactURL(props.report.version, item);
}
</script>
<template>
  <ThreatIDSReport v-if="id === 'network-threat-detection' && report.capture_state" :report="report" />
  <DailyReportSummary v-else-if="id==='daily-report' && dailySnapshot(report)" :report="report" />
  <PlatformHealthReport v-else-if="id==='platform-ops' && report.hosts !== undefined" :report="report" @select="choose" />
  <div v-else class="functional-report">
    <el-alert v-if="id==='daily-report' && report.report_contents_verified===false" type="info" :closable="false" title="目录只核对日期、记录时间和字节数；未据此宣称报告内容完整。选择日期后再严格读取原报告。" />
    <el-alert
      v-if="report.partial"
      type="warning"
      :title="id==='task-manager' ? '进程列表达到采样或展示上限，属于部分结果，不能据此判断全部进程状态。' : '这是有界采样或扫描的部分结果，不能据此认定全部数据已核对。'"
      :closable="false"
    />
    <el-alert
      v-if="report.report_limited"
      type="info"
      title="明细展示有上限；完整复制、冲突、变更或恢复数量见计数，不代表扫描失败。"
      :closable="false"
    />
    <p v-if="report.scope" class="report-scope">{{ report.scope }}</p>
    <section v-if="id === 'files-sync' && report.backup_maintenance" class="diagnosis-check" aria-label="原备份归档与摘要核对">
      <h4>原备份归档与摘要核对</h4>
      <dl><template v-for="(value,key) in report.backup_maintenance" :key="key"><dt>{{ names[String(key)] || key }}</dt><dd>{{ format(String(key),value) }}</dd></template></dl>
    </section>
    <el-alert v-if="id === 'website-statistics-v2' && statisticsHistoryNotice(report)"
      type="warning" :title="statisticsHistoryNotice(report)" :closable="false" />
    <el-alert v-if="id === 'website-statistics-v2' && (!report.history_worker_fresh || report.history_worker_error)"
      type="warning" :title="report.history_worker_error || '后台采集尚未核对或状态已过期；本次手动读取成功不代表后台正在持续采集。'" :closable="false" />
    <section v-if="id === 'mobile-pwa' && Array.isArray(report.mobile_downloads)" class="mobile-downloads">
      <article v-for="item in report.mobile_downloads" :key="item.filename" class="diagnosis-check">
        <h4>{{ item.name }} <el-tag>{{ item.platform }}</el-tag></h4>
        <p>{{ item.state }}</p>
        <p><code>SHA-256: {{ item.sha256 }}</code></p>
        <a v-if="mobileDownloadURL(item)" :href="mobileDownloadURL(item)" target="_blank" rel="noopener noreferrer" class="el-button el-button--primary" :aria-label="`下载${item.name}`">下载交付包</a>
        <p v-else role="status" class="report-scope">交付物与报告版本或内置发布清单不一致，下载入口已停用；请刷新报告或升级签名面板。</p>
      </article>
    </section>
    <div v-if="metrics.length" class="report-metrics">
      <div v-for="[key, value] in metrics" :key="key">
        <span>{{ reportLabel(key) }}</span
        ><strong>{{ format(key, value) }}</strong>
      </div>
    </div>
    <AnalyticsLatencyReport v-if="analytics && report.latency !== undefined" :report="report.latency" />
    <AnalyticsGeographyReport v-if="analytics && report.geography !== undefined" :report="report.geography" />
    <el-alert v-if="analytics && report.geography_error" type="warning" :closable="false" :title="String(report.geography_error)" />
    <template v-if="report.checks">
      <section
        v-for="(value, key) in report.checks"
        :key="key"
        class="diagnosis-check"
      >
        <h4>
          {{ names[String(key)] || key }}
          <el-tag
            v-if="
              typeof value.ok === 'boolean' || typeof value.valid === 'boolean'
            "
            :type="(value.ok ?? value.valid) ? 'success' : 'danger'"
            >{{ (value.ok ?? value.valid) ? "通过" : "需处理" }}</el-tag
          >
        </h4>
        <dl>
          <template v-for="(v, k) in value" :key="k"
            ><dt>{{ names[String(k)] || k }}</dt>
            <dd>{{ format(String(k), v) }}</dd></template
          >
        </dl>
      </section>
    </template>
    <el-tabs
      v-if="analytics || distributions.length"
      class="report-distributions"
    >
      <el-tab-pane
        v-for="[key, values] in distributions"
        :key="key"
        :label="reportLabel(key)"
      >
        <div v-if="id === 'disk-analysis'" class="disk-table-scroll" role="region" :aria-label="reportLabel(key)" tabindex="0">
          <table class="disk-report-table">
            <caption class="disk-table-caption">{{ reportLabel(key) }}（逻辑大小，按路径累计）</caption>
            <thead><tr><th scope="col">{{ key === 'directories' ? '目录（点击下钻）' : '项目' }}</th><th scope="col">逻辑大小</th></tr></thead>
            <tbody><tr v-for="row in chartRows(values, key)" :key="row.name">
              <td>
                <button v-if="key === 'directories' && diskDirectorySelection(report.path, row.name)" type="button" class="disk-path-button" @click="directory(row.name)">{{ row.name }}</button>
                <span v-else>{{ row.name }}</span>
                <el-tag v-if="key === 'directories' && !diskDirectorySelection(report.path, row.name)" type="info" size="small">仅统计，不能下钻</el-tag>
              </td>
              <td>{{ format('bytes', row.value) }}</td>
            </tr></tbody>
          </table>
        </div>
        <el-table
          v-else
          :data="chartRows(values, key)"
          max-height="340"
          stripe
          @row-click="
            (row: any) =>
              id === 'disk-analysis' && key === 'directories'
                ? directory(row.name)
                : undefined
          "
          ><el-table-column
            prop="name"
            :label="key === 'directories' ? '目录（点击下钻）' : '项目'"
            min-width="230"
          ><template #default="{row}"><span>{{row.name}}</span><el-tag v-if="id==='disk-analysis'&&key==='directories'&&!diskDirectorySelection(report.path,row.name)" type="info" size="small">仅统计，不能下钻</el-tag></template></el-table-column><el-table-column label="数量 / 大小" width="150"
            ><template #default="{ row }">{{
              format(id === "disk-analysis" ? "bytes" : "count", row.value)
            }}</template></el-table-column
          ></el-table
        >
      </el-tab-pane>
    </el-tabs>
    <section v-for="[key, values] in groups" :key="key" class="report-group">
      <h4>
        {{ reportLabel(key) }}
        <small
          >{{ values.length }} 项{{
            values.length > (id==='task-manager'?500:200) ? `，只展示前 ${id==='task-manager'?500:200} 项` : ""
          }}</small
        >
      </h4>
      <div v-if="id==='task-manager'&&key==='processes'" class="task-snapshot-filter" role="region" aria-label="筛选当前进程快照">
        <el-input v-model="taskQuery" aria-label="筛选当前快照的进程名称或 PID" placeholder="进程名称或 PID（当前快照）" maxlength="128" clearable />
        <el-checkbox v-model="taskManagedOnly">仅云栈受管进程（包括不可终止项）</el-checkbox>
        <p role="status">当前筛选 {{taskProcessRows(values,taskQuery,taskManagedOnly).length}} / {{Math.min(values.length,500)}} 条；仅筛选已返回快照，不重新采样，不代表全部进程。点击“刷新报告”核对最新状态。</p>
      </div>
      <p v-if="!values.length">暂无记录。</p>
      <template
        v-else-if="
          key === 'sites' && typeof values[0] === 'object' && values[0].changes
        "
        ><section v-for="site in values" :key="site.site_id">
          <p>网站 {{ site.site_id }}</p>
          <AppModuleReport
            :id="id"
            :report="{
              changes: site.changes,
              restored: site.restored || [],
              changes_count: site.changes_count,
              restored_count: site.restored_count,
              report_limited: site.report_limited,
            }"
            @select="(row) => emit('select', { ...row, site_id: site.site_id })"
          /></section
      ></template>
      <div v-else-if="id === 'disk-analysis' && key === 'largest_files'" class="disk-table-scroll" role="region" aria-label="大文件分析结果，可横向滚动" tabindex="0">
        <table class="disk-report-table disk-files-table">
          <caption class="disk-table-caption">大文件分析结果（仅扫描范围内）</caption>
          <thead><tr><th scope="col">文件路径 / 查看目录</th><th scope="col">逻辑大小</th><th scope="col">该文件已分配块</th><th scope="col">硬链接数</th></tr></thead>
          <tbody><tr v-for="(row, rowIndex) in rows(values, key)" :key="rowIndex" @click="choose(row)">
            <td><button v-if="diskFileSelection(row)" type="button" class="disk-path-button" @click.stop="choose(row)">{{ row.path }}</button><span v-else>{{ row.path }}</span><el-tag v-if="!diskFileSelection(row)" type="info" size="small">仅统计，不能下钻</el-tag></td>
            <td>{{ format('bytes', row.bytes, row) }}</td>
            <td>{{ format('allocated_file_bytes', row.allocated_file_bytes, row) }}</td>
            <td>{{ format('link_count', row.link_count, row) }}</td>
          </tr></tbody>
        </table>
      </div>
      <el-table
        v-else
        :data="rows(values,key)"
        stripe
        max-height="370"
        @row-click="choose"
      >
        <el-table-column
          v-for="column in columns(values)"
          :key="column"
          :prop="column"
          :label="reportLabel(column)"
          :sortable="
            [
              'cpu_percent',
              'memory',
              'read_rate',
              'write_rate',
              'bytes',
              'requests',
              'seconds',
            ].includes(column)
          "
          :min-width="
            id==='task-manager'&&column==='name' ? 160 : ['path', 'evidence', 'url', 'source'].includes(column) ? 220 : 100
          "
          show-overflow-tooltip
          ><template #default="{ row }">{{
            format(column, row[column], row)
          }}</template></el-table-column
        >
        <el-table-column
          v-if="
            [
              'processes',
              'users',
              'apps',
              'mounts',
              'exports',
              'hosts',
              'tokens',
              'changes',
              'largest_files',
              'nodes',
              'plans',
              'remote_plans',
              'policies',
            ].includes(key)
          "
          label="选择操作"
          fixed="right"
          width="110"
          ><template #default="{ row }"
            ><el-button
              size="small"
              :disabled="
                (key === 'processes' && !row.can_terminate) ||
                row.can_drill === false
              "
              @click.stop="choose(row)"
              >{{
                key === "processes"
                  ? "选择终止"
                  : id === "disk-analysis"
                    ? "查看目录"
                    : "填入表单"
              }}</el-button
            ></template
          ></el-table-column
        >
      </el-table>
    </section>
    <dl v-if="info.length" class="report-info">
      <template v-for="[key, value] in info" :key="key"
        ><dt>{{ reportLabel(key) }}</dt>
        <dd>{{ format(key, value) }}</dd></template
      >
    </dl>
    <el-alert
      v-if="report.token"
      type="warning"
      title="只读令牌仅在生成时显示。请妥善保存，不要分享截图或报告。"
      :closable="false"
    />
    <el-input
      v-if="report.token"
      :model-value="report.token"
      type="password"
      show-password
      readonly
      aria-label="新生成的只读令牌"
    />
    <details v-if="!report.token">
      <summary>查看原始诊断数据</summary>
      <pre>{{ JSON.stringify(report, null, 2) }}</pre>
    </details>
  </div>
</template>
<style scoped>
.disk-table-scroll {
  max-width: 100%;
  max-height: 370px;
  overflow: auto;
  border: 1px solid #e2e8f0;
  border-radius: 8px;
}
.disk-report-table {
  width: 100%;
  border-collapse: collapse;
  text-align: left;
  font-size: 13px;
  color: #243247;
}
.disk-files-table { min-width: 700px; }
.disk-table-caption { padding: 10px; text-align: left; color: #657181; font-size: 12px; }
.disk-report-table th, .disk-report-table td { padding: 10px; border-bottom: 1px solid #e2e8f0; vertical-align: top; }
.disk-report-table th { background: #f8fafc; }
.disk-report-table tbody tr:nth-child(even) { background: #f8fafc; }
.disk-report-table td:first-child { min-width: 180px; overflow-wrap: anywhere; }
.disk-report-table td:not(:first-child) { white-space: nowrap; }
.disk-report-table .el-tag { margin: 4px; }
.disk-path-button { border: 0; background: none; padding: 0; color: #087f5b; text-align: left; overflow-wrap: anywhere; cursor: pointer; font: inherit; }
.disk-path-button:hover { text-decoration: underline; }
.disk-path-button:focus-visible, .disk-table-scroll:focus-visible { outline: 2px solid #087f5b; outline-offset: 2px; }
.report-metrics {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
  gap: 10px;
  margin: 14px 0;
}
.report-metrics > div {
  padding: 14px;
  border: 1px solid #e2e8f0;
  border-radius: 8px;
  background: #f8fafc;
}
.report-metrics span {
  display: block;
  color: #657181;
  font-size: 12px;
}
.report-metrics strong {
  display: block;
  margin-top: 6px;
  font-size: 20px;
  color: #243247;
}
.report-scope {
  font-size: 12px;
  color: #657181;
}
.report-group,
.diagnosis-check {
  margin-top: 18px;
}
.report-group small {
  font-weight: normal;
  color: #758094;
}
h4 {
  font-size: 14px;
  margin: 12px 0;
}
.report-info,
dl {
  display: grid;
  grid-template-columns: 140px 1fr;
  gap: 6px;
  font-size: 12px;
}
dt {
  color: #657181;
}
dd {
  margin: 0;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
  max-height: 220px;
  overflow: auto;
}
details {
  margin-top: 20px;
  color: #657181;
  font-size: 12px;
}
pre {
  max-height: 300px;
  overflow: auto;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
  background: #f5f7fa;
  padding: 12px;
}
.functional-report {
  min-width: 0;
}
.task-snapshot-filter {
  display: grid;
  gap: 8px;
  margin: 12px 0;
  max-width: 100%;
}
.task-snapshot-filter .el-input { max-width: 360px; }
.task-snapshot-filter .el-checkbox { height: auto; white-space: normal; }
.task-snapshot-filter p { margin: 0; font-size: 12px; color: #657181; overflow-wrap: anywhere; }
.report-distributions {
  max-width: 100%;
}
@media (max-width: 600px) {
  .report-info,
  dl {
    grid-template-columns: 1fr;
  }
  .report-metrics {
    grid-template-columns: 1fr 1fr;
  }
}
</style>
