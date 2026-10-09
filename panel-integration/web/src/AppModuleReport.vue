<script setup lang="ts">
import { computed } from "vue";
import {remoteConnectionRow} from "./remoteSync";
import ThreatIDSReport from "./ThreatIDSReport.vue";
import { loadBalanceEntryRow, loadBalanceNodeSummary, loadBalanceTransitions } from "./loadBalanceReport";
const props = defineProps<{ id: string; report: Record<string, any> }>();
const emit = defineEmits<{ select: [row: Record<string, any>] }>();
const names: Record<string, string> = {
  requests: "请求数",
  history_persistent: "已持久化保存",
  history_retention_days: "历史保留天数",
  history_row_limit: "全站历史行数上限",
  history_backlog_bytes: "尚未读取的日志",
  history_blocked_sources: "进度冲突或缺失来源",
  history_compressed_sources: "未自动导入的压缩归档",
  history_missing_log: "当前无可读访问日志",
  history_invalid_lines: "历史采集无效行",
  history_evicted_rows: "因行数上限退役的历史",
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
  average_seconds: "平均响应（秒）",
  max_seconds: "最大响应（秒）",
  qps_last_minute: "最近一分钟 QPS",
  total_bytes: "总占用",
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
  actual_nfs_v4_rpc: "真实 NFSv4 RPC 检查通过",
  export_error: "导出目录告警",
  hosts: "主机",
  nodes: "上游节点",
  entries: "负载均衡入口",
  http_health: "持续 HTTP 检查",
  http_health_enabled: "持续 HTTP 检查已启用",
  backend_protocol: "后端转发协议",
  http_transitions: "最近 HTTP 状态转换（界面最多 200 条）",
  health_check: "HTTP 检查策略",
  automatic_traffic_changes: "自动修改流量",
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
  Object.entries({...props.report, ...(props.id==="files-sync" && props.report.job ? {remote_jobs:[props.report.job]} : {}), ...(props.id==="load-balance" && Array.isArray(props.report.http_health) ? {http_transitions:loadBalanceTransitions(props.report.http_health)} : {}), ...(props.id==='nfs-manager' && props.report.config ? {exports:props.report.config.exports} : {}), ...(props.report.deployment ? {deployments: [props.report.deployment]} : {})}).filter(
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
function format(key: string, value: unknown) {
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
function rows(values: any[]): Record<string, any>[] {
  return values.slice(0, 200).map((v) => {
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
    };
  });
}
function columns(values: any[]) {
  if(props.id==="files-sync" && values.some(value=>value && value.remote_target))return ["remote_target_id","remote_target","auth_kind","enabled","revision","host_key_fingerprint"];
  if(props.id==="files-sync" && values.some(value=>value && value.remote_request_id))return ["remote_request_id","remote_target_id","site_id","state","job_archived","copied_count","skipped_count","conflicts_count","created_at","started_at","finished_at","error"];
  if (props.id==="load-balance" && values.some(value=>value && Array.isArray(value.nodes)))
    return ["domain","port","revision","nodes","backend_protocol","sticky","http_health_enabled"];
  if (props.id==="load-balance" && values.some(value=>value && typeof value==="object" && "checked_at" in value && "last_success" in value))
    return ["domain","revision","address","scheme","check_address","state","stale","last_success","http_status","reason","latency_ms","failures","successes","checked_at","tls_verification","worker_error"];
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
  if ("can_terminate" in row && !row.can_terminate) return;
  if (props.id === "disk-analysis") {
    if (row.can_drill === false) return;
    const path = row.directory === "." ? "" : row.directory;
    emit("select", { path, drill: true });
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
  if (name === ".") name = "";
  const base = props.report.path;
  emit("select", { path: [base, name].filter(Boolean).join("/"), drill: true });
}
function mobileDownloadURL(value: unknown): string | undefined {
  if (typeof value !== "string") return;
  const prefix = "https://github.com/yunzhanlin/yunzhan-apps/releases/download/v0.1.0-dev.proapps11/";
  const allowed = ["yunzhan-mobile-1.3.0-android.apk", "yunzhan-mobile-1.3.0-ios-unsigned.tar.gz", "yunzhan-mobile-1.3.0-source.tar.gz"];
  return allowed.some(name => value === prefix + name) ? value : undefined;
}
</script>
<template>
  <ThreatIDSReport v-if="id === 'network-threat-detection' && report.capture_state" :report="report" />
  <div v-else class="functional-report">
    <el-alert
      v-if="report.partial"
      type="warning"
      title="这是有界扫描的部分结果，不能据此认定全量数据已统计或网站没有风险。"
      :closable="false"
    />
    <el-alert
      v-if="report.report_limited"
      type="info"
      title="明细展示有上限；完整复制、冲突、变更或恢复数量见计数，不代表扫描失败。"
      :closable="false"
    />
    <p v-if="report.scope" class="report-scope">{{ report.scope }}</p>
    <el-alert v-if="id === 'website-statistics-v2' && (report.history_blocked_sources || report.history_compressed_sources || report.history_missing_log)"
      type="warning" title="部分日志无法自动续读：压缩归档不会重复导入，检查点冲突不会从头重置。已有历史保留；请核对日志轮转方式与历史范围。" :closable="false" />
    <el-alert v-if="id === 'website-statistics-v2' && (!report.history_worker_fresh || report.history_worker_error)"
      type="warning" :title="report.history_worker_error || '后台采集尚未核对或状态已过期；本次手动读取成功不代表后台正在持续采集。'" :closable="false" />
    <section v-if="id === 'mobile-pwa' && Array.isArray(report.mobile_downloads)" class="mobile-downloads">
      <article v-for="item in report.mobile_downloads" :key="item.filename" class="diagnosis-check">
        <h4>{{ item.name }} <el-tag>{{ item.platform }}</el-tag></h4>
        <p>{{ item.state }}</p>
        <p><code>SHA-256: {{ item.sha256 }}</code></p>
        <a v-if="mobileDownloadURL(item.url)" :href="mobileDownloadURL(item.url)" target="_blank" rel="noopener noreferrer" class="el-button el-button--primary">下载交付包</a>
      </article>
    </section>
    <div v-if="metrics.length" class="report-metrics">
      <div v-for="[key, value] in metrics" :key="key">
        <span>{{ names[key] || key }}</span
        ><strong>{{ format(key, value) }}</strong>
      </div>
    </div>
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
        :label="names[key] || key"
      >
        <el-table
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
          /><el-table-column label="数量 / 大小" width="150"
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
            values.length > 200 ? "，只展示前 200 项" : ""
          }}</small
        >
      </h4>
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
      <el-table
        v-else
        :data="rows(values)"
        stripe
        max-height="370"
        @row-click="choose"
      >
        <el-table-column
          v-for="column in columns(values)"
          :key="column"
          :prop="column"
          :label="names[column] || column"
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
            ['path', 'evidence', 'url', 'source'].includes(column) ? 220 : 100
          "
          show-overflow-tooltip
          ><template #default="{ row }">{{
            format(column, row[column])
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
              'changes',
              'largest_files',
              'nodes',
              'plans',
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
