<script setup lang="ts">
import { formatPanelDate, formatPanelDateTime } from "./panelTime";
import { randomId } from "./randomId";
import { apiURL } from "./panelBase";
import { canOpenView, canReadPath, validAccessPlan, type AccessPlan } from "./menuPermissions";
import SoftwareLogo from "./SoftwareLogo.vue";
import AppModuleManager from "./AppModuleManager.vue";
import { isSecuritySoftware, softwareManagerKind } from "./softwareRouting";
import { normalizeStoreSearch } from "./storeSearch";
import type { SecurityAppCatalogItem, SecurityAppStatus } from "./SecurityAppManager.vue";
import PanelIcon from "./PanelIcon.vue";
import { computed, defineAsyncComponent, nextTick, onMounted, onUnmounted, ref } from "vue";
import { ElMessage, ElMessageBox } from "element-plus";
import {
  Odometer,
  Monitor,
  Box,
  Clock,
  Document,
  Refresh,
  Plus,
  SwitchButton,
  ArrowRight,
  View,
  Connection,
  Folder,
  Lock,
  DataLine,
  Calendar,
  DataBoard,
  Fold,
  Search,
  Bell,
  Brush,
  UserFilled,
  Setting,
  Tickets,
  Grid,
  Platform,
  Tools,
  User,
  ArrowDown,
  VideoPlay,
  VideoPause,
  Timer,
} from "@element-plus/icons-vue";
const AccountManager = defineAsyncComponent(() => import("./AccountManager.vue")) as typeof import("./AccountManager.vue")["default"];
const CertificateManager = defineAsyncComponent(() => import("./CertificateManager.vue")) as typeof import("./CertificateManager.vue")["default"];
const DatabaseManager = defineAsyncComponent(() => import("./DatabaseManager.vue")) as typeof import("./DatabaseManager.vue")["default"];
const FileManager = defineAsyncComponent(() => import("./FileManager.vue")) as typeof import("./FileManager.vue")["default"];
const SiteSettingsManager = defineAsyncComponent(() => import("./SiteSettingsManager.vue")) as typeof import("./SiteSettingsManager.vue")["default"];
const BatchSSLManager = defineAsyncComponent(() => import("./BatchSSLManager.vue")) as typeof import("./BatchSSLManager.vue")["default"];
const RuntimeLifecycleManager = defineAsyncComponent(() => import("./RuntimeLifecycleManager.vue")) as typeof import("./RuntimeLifecycleManager.vue")["default"];
const PHPExtensionManager = defineAsyncComponent(() => import("./PHPExtensionManager.vue")) as typeof import("./PHPExtensionManager.vue")["default"];
const MonitoringManager = defineAsyncComponent(() => import("./MonitoringManager.vue")) as typeof import("./MonitoringManager.vue")["default"];
const ScheduleManager = defineAsyncComponent(() => import("./ScheduleManager.vue")) as typeof import("./ScheduleManager.vue")["default"];
const BackupManager = defineAsyncComponent(() => import("./BackupManager.vue")) as typeof import("./BackupManager.vue")["default"];
const PanelAccessManager = defineAsyncComponent(() => import("./PanelAccessManager.vue")) as typeof import("./PanelAccessManager.vue")["default"];
const NotificationManager = defineAsyncComponent(() => import("./NotificationManager.vue")) as typeof import("./NotificationManager.vue")["default"];
const SecurityManager = defineAsyncComponent(() => import("./SecurityManager.vue")) as typeof import("./SecurityManager.vue")["default"];
const TerminalManager = defineAsyncComponent(() => import("./TerminalManager.vue")) as typeof import("./TerminalManager.vue")["default"];
const SystemToolsManager = defineAsyncComponent(() => import("./SystemToolsManager.vue")) as typeof import("./SystemToolsManager.vue")["default"];
const DockerManager = defineAsyncComponent(() => import("./DockerManager.vue")) as typeof import("./DockerManager.vue")["default"];
const RedisManager = defineAsyncComponent(() => import("./RedisManager.vue")) as typeof import("./RedisManager.vue")["default"];
const MariaDBManager = defineAsyncComponent(() => import("./MariaDBManager.vue")) as typeof import("./MariaDBManager.vue")["default"];
const NodeManager = defineAsyncComponent(() => import("./NodeManager.vue")) as typeof import("./NodeManager.vue")["default"];
const SecurityAppManager = defineAsyncComponent(() => import("./SecurityAppManager.vue")) as typeof import("./SecurityAppManager.vue")["default"];
interface Site {
  settings: { domains: string[]; public_ingress?: boolean; tls?: { certificate_id?: string } };
  id: string;
  name: string;
  domain: string;
  slug: string;
  status: string;
  created_at: string;
  runtime_instance_id: string;
  php_version_id: string;
}
interface Job {
  id: string;
  site_id: string;
  target_id: string;
  site_name: string;
  kind: string;
  database_name?: string;
  state: string;
  error: string;
  created_at: string;
  updated_at: string;
  steps: { time: string; message: string }[];
}
interface SiteCertificate {
  id: string;
  not_after: string;
  status: string;
}
interface SiteTraffic {
  days: { date: string; bytes: number; requests: number }[];
  sites: { id: string; today_bytes: number }[];
  partial: boolean;
  updated_at: string;
}
interface Audit {
  id: number;
  actor: string;
  action: string;
  target: string;
  result: string;
  created_at: string;
}
interface PanelNotification {
  id: string;
  kind: string;
  title: string;
  message: string;
  severity: "info" | "warning" | "critical";
  created_at: number;
  read_at?: number;
}
interface Overview {
  hostname: string;
  os: string;
  kernel?: string;
  arch: string;
  cpu_cores: number;
  cpu_percent: number;
  memory_percent: number;
  memory_used: number;
  memory_total: number;
  disk_percent: number;
  disk_used: number;
  disk_total: number;
  disk_available?: number;
  network_rx: number;
  network_tx: number;
  uptime_seconds: number;
  load: string;
  nginx_active: boolean;
  sampled_at: string;
  counts: {
    sites: number;
    running_sites: number;
    pending_jobs: number;
    attention_jobs: number;
  };
}
interface Runtimes {
  retired?: { id: string; retired_at: string; architecture: string }[];
  active_nginx?: string;
  installed: {
    id: string;
    extensions?: string[];
    source_url?: string;
    sha256?: string;
    family: string;
    version: string;
    source: string;
    binary: string;
    status: string;
  }[];
  catalog: {
    family: string;
    name: string;
    versions: string[];
    description: string;
    state: string;
    releases?: {
      id: string;
      version: string;
      series: string;
      channel: string;
      source_url: string;
      sha256: string;
    }[];
  }[];
}
interface SoftwareApps { catalog: SecurityAppCatalogItem[]; status: SecurityAppStatus[] }
interface RegistryApp {
  id: string;
  name: string;
  category: "deployment" | "professional";
  version: string;
  summary: string;
  stage: "ready" | "integration" | "design";
  risk: "maintained" | "maintenance" | "eol" | "privileged";
  provider: "runtime" | "compose" | "panel-module";
  target: string;
  manage_route: string;
  capabilities: string[];
  package_url: string;
  sha256: string;
}
interface RegistryStatus { id: string; state_known?: boolean; installed: boolean; healthy: boolean; detail: string; supported?: boolean; compatibility_detail?: string; installed_version?: string; latest_version?: string; version_known?: boolean; update_available?: boolean; update_supported?: boolean; update_kind?: string; update_detail?: string }
interface AppRegistry {
  catalog: { schema_version: number; generated_at: string; repository: string; apps: RegistryApp[] };
  status: RegistryStatus[];
  source: { source: string; stale: boolean; fetched_at?: string; checked_at?: string; error?: string };
  host?: { platform: string; architecture: string };
}
const user = ref(""),
  csrf = ref(""),
  initialized = ref(true),
  ready = ref(false),
  busy = ref(false),
  error = ref(""),
  authError = ref("");
const accessPlan = ref<AccessPlan | null>(null);
let accessEpoch = 0;
const canManageSites = computed(() => accessPlan.value?.role === "admin" && canOpenView(accessPlan.value, "sites"));
const accountRoleLabel = computed(() => accessPlan.value?.role === "admin" ? "管理员" : accessPlan.value?.role === "operator" ? "指定网站操作员" : "只读账户");
function clearAccessData() {
  accessEpoch++;
  sites.value = []; jobs.value = []; audits.value = []; siteCertificates.value = [];
  siteTraffic.value = null; overview.value = null; samples.value = [];
  notifications.value = []; notificationUnread.value = 0;
  runtimes.value = { installed: [], catalog: [] }; softwareApps.value = { catalog: [], status: [] };
  appRegistry.value = { catalog: { schema_version: 1, generated_at: "", repository: "", apps: [] }, status: [], source: { source: "", stale: false } };
  selectedJob.value = null; jobOpen.value = false; createOpen.value = false;
  siteTrafficLoadedAt = 0;
}
function applyAccess(value: unknown) {
  if (!validAccessPlan(value)) throw new Error("账户授权未正确加载，请重新登录");
  accessPlan.value = value; clearAccessData();
  if (!canOpenView(value, view.value)) view.value = value.menu_ids[0] || "account";
}
async function permittedRead<T>(path: string): Promise<T | undefined> {
  if (!canReadPath(accessPlan.value, path)) return undefined;
  const epoch = accessEpoch, session = csrf.value;
  const result = await api<T>(path);
  return epoch === accessEpoch && session === csrf.value ? result : undefined;
}
const accountManager = ref<InstanceType<typeof AccountManager> | null>(null);
const databaseManager = ref<InstanceType<typeof DatabaseManager> | null>(null);
const certificateManager = ref<InstanceType<typeof CertificateManager> | null>(
  null,
);
const monitoringManager = ref<InstanceType<typeof MonitoringManager> | null>(
  null,
);
const scheduleManager = ref<InstanceType<typeof ScheduleManager> | null>(null);
const backupManager = ref<InstanceType<typeof BackupManager> | null>(null);
const panelAccessManager = ref<InstanceType<typeof PanelAccessManager> | null>(
  null,
);
const notificationManager = ref<InstanceType<typeof NotificationManager> | null>(null);
const fileManager = ref<InstanceType<typeof FileManager> | null>(null);
const securityManager = ref<InstanceType<typeof SecurityManager> | null>(null);
const terminalManager = ref<InstanceType<typeof TerminalManager> | null>(null);
const dockerManager = ref<InstanceType<typeof DockerManager> | null>(null);
const redisManager = ref<InstanceType<typeof RedisManager> | null>(null);
const mariadbManager = ref<InstanceType<typeof MariaDBManager> | null>(null);
const nodeManager = ref<InstanceType<typeof NodeManager> | null>(null);
async function manualRefresh() {
  if (view.value === "account") await accountManager.value?.refresh();
  else if (view.value === "monitor") await monitoringManager.value?.refresh();
  else if (view.value === "schedules") await scheduleManager.value?.refresh();
  else if (view.value === "backups") await backupManager.value?.refresh();
  else if (view.value === "panel-access") {
    if (settingsTab.value === "notice") await notificationManager.value?.refresh();
    else await panelAccessManager.value?.refresh();
  }
  else if (view.value === "security") await securityManager.value?.refresh();
  else if (view.value === "certificates")
    await certificateManager.value?.refresh();
  else {
    if (view.value === "sites") await loadSiteTraffic(true);
    await refresh(view.value === "runtimes");
  }
}
const otpCode = ref(""),
  accountChanging = ref(false);
const username = ref("admin"),
  password = ref(""),
  bootstrap = ref(""),
  view = ref("overview"),
  sidebar = ref(false);
const settingsTab = ref("basic");
const theme = ref<"light" | "dark">("light");
const sidebarStyle = ref<"default" | "compact">("default");
const displayDensity = ref<"comfortable" | "compact">("comfortable");
const searchOpen = ref(false),
  searchText = ref(""),
  searchInput = ref<HTMLInputElement | null>(null);
const overview = ref<Overview | null>(null),
  sites = ref<Site[]>([]),
  siteCertificates = ref<SiteCertificate[]>([]),
  siteTraffic = ref<SiteTraffic | null>(null),
  jobs = ref<Job[]>([]),
  audits = ref<Audit[]>([]),
  notifications = ref<PanelNotification[]>([]),
  notificationUnread = ref(0),
  runtimes = ref<Runtimes>({ installed: [], catalog: [] }),
  softwareApps = ref<SoftwareApps>({ catalog: [], status: [] }),
  appRegistry = ref<AppRegistry>({ catalog: { schema_version: 1, generated_at: "", repository: "", apps: [] }, status: [], source: { source: "", stale: false } }),
  registryInstalling = ref<string[]>([]);
const samples = ref<{ cpu: number; memory: number; time: number }[]>([]),
  query = ref(""),
  siteStatusFilter = ref("all"),
  sitePHPFilter = ref("all"),
  sitePage = ref(1),
  sitePageSize = ref(8),
  creating = ref(false),
  createOpen = ref(false),
  siteName = ref(""),
  slug = ref(""),
  primaryDomain = ref("");
const selectedJob = ref<Job | null>(null),
  jobOpen = ref(false),
  configOpen = ref(false),
  siteConfig = ref({ path: "", content: "" }),
  loadingConfig = ref(false);
const versions = ref<Record<string, string>>({
  nginx: "nginx-1.30.4",
  apache: "apache-2.4.68",
  php: "php-8.4.25",
  mysql: "mysql-8.4.11",
  mariadb: "mariadb-11.8.9",
  redis: "redis-8.2.10",
  node: "node-24.21.0",
  docker: "docker-debian-26.1.5",
});
const storeCategories = [
  { id: "recommended", label: "推荐" },
  { id: "web", label: "Web 环境" },
  { id: "database", label: "数据库" },
  { id: "cache", label: "缓存" },
  { id: "monitoring", label: "监控" },
  { id: "security", label: "安全防护" },
  { id: "tools", label: "运维工具" },
  { id: "deployment", label: "部署软件" },
  { id: "professional", label: "专业功能" },
  { id: "all", label: "全部软件" },
] as const;
const storeTabCategories = storeCategories.filter((category) =>
  ["recommended", "web", "database", "cache", "monitoring", "tools", "all"].includes(category.id),
);
const storeCategory = ref<string>("recommended"),
  storeSearch = ref(""),
  storeStatus = ref("all"),
  storeSort = ref("recommended");
const showReferenceRuntimeCards = computed(() =>
  storeCategory.value === "recommended" && !storeSearch.value.trim(),
);
const storeFamilies: Record<string, string[]> = {
  web: ["nginx", "apache", "php"],
  database: ["mysql", "mariadb"],
  cache: ["redis"],
  monitoring: [],
  tools: ["docker", "node"],
};
type BuiltInStoreApp = { id: string; family: string; name: string; category: string; page: string; description: string; tags: readonly string[]; templateId?: string };
const builtInStoreApps: readonly BuiltInStoreApp[] = [
  { id: "database-admin", family: "mysql", name: "数据库管理中心", category: "database", page: "databases", description: "管理 MySQL 与 MariaDB 实例、数据库、账号权限、SQL 导入、备份和恢复。", tags: ["数据库", "权限", "备份恢复"] },
  { id: "server-monitor", family: "monitoring", name: "服务器监控", category: "monitoring", page: "monitor", description: "读取真实 CPU、内存、磁盘、网络、进程、数据库和站点指标。", tags: ["资源趋势", "进程", "阈值告警"] },
  { id: "memcached-template", family: "memcached", name: "Memcached 缓存", category: "cache", page: "runtimes", templateId: "memcached-cache", description: "使用官方固定版本镜像创建受管实例，只监听主机回环端口。", tags: ["1.6.45", "128 MB", "Docker 模板"] },
  { id: "sftp-manager", family: "sftp", name: "站点 SFTP 管理", category: "tools", page: "files", description: "为受管站点创建隔离的 OpenSSH SFTP 账号，支持改密、停启和删除。", tags: ["目录隔离", "一次性密码", "无 Shell"] },
  { id: "backup-center", family: "backup", name: "备份与恢复", category: "tools", page: "backups", description: "集中备份站点和数据库，支持校验、下载、恢复及失败回滚。", tags: ["站点备份", "数据库备份", "恢复校验"] },
  { id: "task-scheduler", family: "scheduler", name: "计划任务", category: "tools", page: "schedules", description: "按固定周期执行受控备份和维护任务，保留每次执行结果。", tags: ["定时执行", "结果记录", "保留策略"] },
];
function openBuiltInStoreApp(app: BuiltInStoreApp) {
  if (app.templateId) void dockerManager.value?.openTemplate(app.templateId);
  else go(app.page);
}
const filteredBuiltInApps = computed(() => {
  const term = normalizeStoreSearch(storeSearch.value);
  if (storeCategory.value === "recommended" && !term) return [];
  if (["unavailable", "updates"].includes(storeStatus.value)) return [];
  const items = builtInStoreApps.filter((app) => {
    if (appRegistry.value.catalog.apps.length && app.id === "memcached-template") return false;
    if (!["recommended", "all", app.category].includes(storeCategory.value)) return false;
    if (storeStatus.value === "installed" && app.templateId) return false;
    if (storeStatus.value === "installable" && !app.templateId) return false;
    return !term || normalizeStoreSearch(`${app.name} ${app.description} ${app.tags.join(" ")}`).includes(term);
  });
  return storeSort.value === "name" ? [...items].sort((a, b) => a.name.localeCompare(b.name, "zh-CN")) : items;
});
const filteredCatalog = computed(() => {
  if (appRegistry.value.catalog.apps.length && !showReferenceRuntimeCards.value) return [];
  const term = normalizeStoreSearch(storeSearch.value);
  const items = runtimes.value.catalog.filter((rt) => {
    if (storeCategory.value !== "recommended" && storeCategory.value !== "all" && !storeFamilies[storeCategory.value]?.includes(rt.family)) return false;
    if (term && !normalizeStoreSearch(`${rt.name} ${rt.family} ${rt.description} ${(rt.versions || []).join(" ")}`).includes(term)) return false;
    const installed = runtimeInstalled(versions.value[rt.family] || "");
    if (storeStatus.value === "installed" && !installed) return false;
    if (storeStatus.value === "installable" && (installed || rt.state !== "available")) return false;
    if (storeStatus.value === "unavailable" && rt.state === "available") return false;
    return true;
  });
  if (storeSort.value === "name") items.sort((a, b) => a.name.localeCompare(b.name, "zh-CN"));
  if (storeSort.value === "installed") items.sort((a, b) => Number(runtimeInstalled(versions.value[b.family] || "")) - Number(runtimeInstalled(versions.value[a.family] || "")));
  return items;
});
const softwareStatus = (id: string) => softwareApps.value.status.find((item) => item.id === id);
const softwareManager = ref<InstanceType<typeof SecurityAppManager> | null>(null);
const appModuleManager = ref<InstanceType<typeof AppModuleManager> | null>(null);
function openSoftwareApp(app: SecurityAppCatalogItem) {
  const manager = softwareManagerKind(app);
  if (manager === "security") softwareManager.value?.show(app, softwareStatus(app.id));
  else if (manager === "module") void appModuleManager.value?.show(app.id);
  else ElMessage.error("当前面板没有该应用的管理界面，请升级面板后重试");
}
function installSoftwareApp(app: SecurityAppCatalogItem) {
  if (softwareManagerKind(app) === "security") void softwareManager.value?.install(app, softwareStatus(app.id));
  else openSoftwareApp(app);
}
async function queueSoftwareInstall(id: string, settings: Record<string, unknown> = {}): Promise<string> {
  const software = softwareApps.value.catalog.find(item => item.id === id);
  if (!software || !softwareManagerKind(software)) throw new Error("当前面板没有该应用的已审核处理器");
  const app = appRegistry.value.catalog.apps.find(item => item.provider === "panel-module" && item.target === id);
  let result: { job_id: string };
  if (app) {
    const status = registryStatus(app.id);
    if (appRegistry.value.source.stale) throw new Error("仓库目录尚未核对，请检查更新后重试");
    if (app.stage !== "ready" || status?.supported === false || status?.state_known === false) throw new Error(status?.compatibility_detail || "当前应用尚不满足安装条件，请刷新状态");
    result = await api<{ job_id: string }>(`/app-registry/${app.id}/install`, "POST", { settings, expected_version: app.version, expected_sha256: app.sha256 });
  } else {
    // Offline fallback may use only handlers already compiled into this panel.
    result = await api<{ job_id: string }>(`/software/${id}/install`, "POST", { settings });
  }
  return result.job_id;
}
const filteredSoftwareApps = computed(() => {
  if (appRegistry.value.catalog.apps.length) return [];
  const term = normalizeStoreSearch(storeSearch.value);
  if (storeCategory.value === "recommended" && !term) return [];
  if (["updates", "unavailable"].includes(storeStatus.value)) return [];
  const items = softwareApps.value.catalog.filter((app) => {
    const catalogID = app.id === "intrusion-prevention" ? "anti-intrusion" : app.id === "mobile-pwa" ? "mobile" : app.id;
    if (["deployment", "professional"].includes(storeCategory.value) && app.category !== storeCategory.value) return false;
    if (!["recommended", "all", "deployment", "professional"].includes(storeCategory.value) && !registryCategoryMap[storeCategory.value]?.includes(catalogID)) return false;
    const status = softwareStatus(app.id);
    if (term && !normalizeStoreSearch(`${app.name} ${app.family} ${app.description} ${app.capabilities.join(" ")}`).includes(term)) return false;
    if (storeStatus.value === "installed" && !status?.installed) return false;
    if (storeStatus.value === "installable" && status?.installed) return false;
    if (storeStatus.value === "unavailable") return false;
    return true;
  });
  if (storeSort.value === "name") items.sort((a, b) => a.name.localeCompare(b.name, "zh-CN"));
  if (storeSort.value === "installed") items.sort((a, b) => Number(Boolean(softwareStatus(b.id)?.installed)) - Number(Boolean(softwareStatus(a.id)?.installed)));
  return items;
});
const registryStatus = (id: string) => appRegistry.value.status.find((item) => item.id === id);
const registryChecking = ref(false);
const registryUpdates = computed(() => appRegistry.value.status.filter(item => item.update_available).length);
async function checkRegistryUpdates() {
  if (registryChecking.value) return;
  registryChecking.value = true;
  try {
    appRegistry.value = await api<AppRegistry>("/app-registry?refresh=1");
    if (appRegistry.value.source.stale) ElMessage.warning("仓库检查失败，当前显示已验签缓存；尚未确认最新版本");
    else ElMessage.success(`已检查 GitHub 应用目录，${registryUpdates.value} 个应用有新版`);
  } catch (e) {
    appRegistry.value.source = { ...appRegistry.value.source, stale: true, error: (e as Error).message };
    ElMessage.error((e as Error).message);
  } finally { registryChecking.value = false; }
}
async function updateRegistryApp(app: RegistryApp) {
  const status = registryStatus(app.id);
  if (!status?.update_supported) { ElMessage.warning(status?.update_detail || "请先核对应用版本"); return; }
  registryInstalling.value = [...registryInstalling.value, app.id];
  try {
    const result = await api<{ job_id: string }>(`/app-registry/${app.id}/update`, "POST", { expected_version: app.version, expected_sha256: app.sha256 });
    await refresh();
    await revealJob(result.job_id);
    ElMessage.success(`${app.name} 更新任务已提交；成功完成后才记录新版本`);
  } catch (e) { ElMessage.error((e as Error).message); }
  finally { registryInstalling.value = registryInstalling.value.filter(id => id !== app.id); }
}
const registryCategoryMap: Record<string, string[]> = {
  web: ["nginx", "apache", "openlitespeed", "php-85", "php-84", "php-83", "php-82", "php-81", "php-80", "php-74", "php-73", "php-72", "php-71", "php-70", "php-56", "php-55", "php-54", "php-53", "php-52"],
  database: ["mysql", "mongodb", "phpmyadmin"],
  cache: ["redis", "memcached"],
  monitoring: ["site-diagnosis", "network-threat-detection", "website-analytics", "daily-report", "website-statistics-v2", "task-manager", "disk-analysis", "file-monitor"],
  security: ["nginx-waf", "apache-waf", "enterprise-tamper-proof", "website-tamper-proof", "php-code-security", "system-hardening", "anti-intrusion"],
  tools: ["pure-ftpd", "elasticsearch", "rabbitmq", "pm2-manager", "docker-manager", "files-sync", "load-balance", "mobile", "user-manager", "platform-ops", "nfs-manager"],
};
const filteredRegistryApps = computed(() => {
  if (showReferenceRuntimeCards.value) return [];
  const term = normalizeStoreSearch(storeSearch.value);
  const items = appRegistry.value.catalog.apps.filter((app) => {
    if (storeCategory.value === "recommended" && (app.stage !== "ready" || app.risk === "eol") && !term) return false;
    if (["deployment", "professional"].includes(storeCategory.value) && app.category !== storeCategory.value) return false;
    if (!["recommended", "all", "deployment", "professional"].includes(storeCategory.value) && !registryCategoryMap[storeCategory.value]?.includes(app.id)) return false;
    const localName = softwareApps.value.catalog.find(item => item.id === app.target)?.name || "";
    if (term && !normalizeStoreSearch(`${app.name} ${localName} ${app.id} ${app.summary} ${app.capabilities.join(" ")}`).includes(term)) return false;
    const status = registryStatus(app.id);
    if (storeStatus.value === "installed" && !status?.installed) return false;
    if (storeStatus.value === "updates" && !status?.update_available) return false;
    if (storeStatus.value === "installable" && (status?.installed || app.stage !== "ready" || status?.supported === false)) return false;
    if (storeStatus.value === "unavailable" && app.stage === "ready" && status?.supported !== false) return false;
    return true;
  });
  if (storeSort.value === "name") items.sort((a, b) => a.name.localeCompare(b.name, "zh-CN"));
  if (storeSort.value === "installed") items.sort((a, b) => Number(Boolean(registryStatus(b.id)?.installed)) - Number(Boolean(registryStatus(a.id)?.installed)));
  return items;
});
function openRegistryApp(app: RegistryApp) {
  if (app.provider === "panel-module") {
    const software = softwareApps.value.catalog.find(item => item.id === app.target);
    if (software) openSoftwareApp(software);
    else if (!isSecuritySoftware(app.target)) void appModuleManager.value?.show(app.target);
    else ElMessage.warning("安全软件目录尚未加载，请刷新后重试");
  }
  else if (app.manage_route === "docker") void dockerManager.value?.open();
  else go(app.manage_route || "runtimes");
}
async function installRegistryApp(app: RegistryApp) {
  const status = registryStatus(app.id);
  if (status?.state_known === false) { ElMessage.warning("当前安装状态尚未确认，请刷新后再试"); return; }
  if (status?.installed) {
    openRegistryApp(app);
    return;
  }
  if (status?.supported === false) { ElMessage.warning(status.compatibility_detail || "该应用不支持当前系统或 CPU 架构"); return; }
  if (app.stage !== "ready") {
    ElMessage.warning(app.stage === "integration" ? "该应用正在接入安装器" : "该功能正在实现中");
    return;
  }
  if (app.provider === "panel-module") {
    openRegistryApp(app);
    return;
  }
  const body: Record<string, unknown> = { expected_version: app.version, expected_sha256: app.sha256 };
  try {
	if (app.provider === "compose") {
	  const defaultPort = ({ "memcached-cache": 21211, mongodb: 27017, elasticsearch: 19200 } as Record<string, number>)[app.target] || 18080;
      const answer = await ElMessageBox.prompt("应用只会绑定到主机回环地址，请输入 1024–65535 之间的本机端口。", `安装 ${app.name}`, {
		inputValue: String(defaultPort),
        inputValidator: (value: string) => Number.isInteger(Number(value)) && Number(value) >= 1024 && Number(value) <= 65535 || "端口必须在 1024–65535 之间",
        confirmButtonText: "验签并安装",
        cancelButtonText: "取消",
      });
      body.host_port = Number(answer.value);
    } else {
      await ElMessageBox.confirm(`面板将从云栈官方 GitHub 仓库拉取 ${app.name} ${app.version} 清单，验证 Ed25519 目录签名和应用包 SHA-256 后再执行受限安装。`, `安装 ${app.name}`, {
        confirmButtonText: "验签并安装",
        cancelButtonText: "取消",
        type: app.risk === "privileged" ? "warning" : "info",
      });
    }
    registryInstalling.value = [...registryInstalling.value, app.id];
    const result = await api<{ job_id?: string }>(`/app-registry/${app.id}/install`, "POST", body);
    await refresh();
    if (result.job_id && app.provider !== "compose") await revealJob(result.job_id);
    else if (app.provider === "compose") void dockerManager.value?.open();
    ElMessage.success(`${app.name} 安装任务已提交`);
  } catch (e) {
    if (e instanceof Error && e.message !== "cancel") ElMessage.error(e.message);
  } finally {
    registryInstalling.value = registryInstalling.value.filter((id) => id !== app.id);
  }
}
const showPanelRuntime = computed(() =>
  ["recommended", "all", "tools"].includes(storeCategory.value) &&
  ["all", "installed"].includes(storeStatus.value) &&
  (!normalizeStoreSearch(storeSearch.value) || normalizeStoreSearch("云栈面板 panel 运维").includes(normalizeStoreSearch(storeSearch.value))),
);
const fileSiteID = ref("");
const settingsOpen = ref(false),
  settingsSiteID = ref(""),
  settingsInitialTab = ref("basic");
function openSiteSettings(id: string, tab = "basic") {
  settingsSiteID.value = id;
  settingsInitialTab.value = tab;
  settingsOpen.value = true;
}
const batchSSLOpen = ref(false),
  selectedSiteIDs = ref<string[]>([]);
function selectVisibleSites(checked: boolean) {
  const ids = new Set(selectedSiteIDs.value);
  for (const site of pagedSites.value) checked ? ids.add(site.id) : ids.delete(site.id);
  selectedSiteIDs.value = [...ids];
}
const createPHP = ref("");
const phpOpen = ref(false),
  phpTarget = ref<Site | null>(null),
  phpSelection = ref(""),
  submittingPHP = ref(false);
const installedPHP = computed(() =>
  runtimes.value.installed.filter(
    (r) => r.family === "php" && r.status === "installed",
  ),
);
const lifecycleManager = ref<InstanceType<
  typeof RuntimeLifecycleManager
> | null>(null);
async function lifecycleJob(id: string) {
  await refresh();
  await revealJob(id);
}
const extensionManager = ref<InstanceType<typeof PHPExtensionManager> | null>(
  null,
);
const runtimeBusy = (id: string) =>
  jobs.value.some(
    (j) =>
      j.target_id === id &&
      ["queued", "running", "needs_attention"].includes(j.state),
  );
const runtimeInstalled = (id: string) =>
  runtimes.value.installed.some((r) => r.id === id && r.status === "installed");
const versionManagerOpen = ref(false), versionManagerFamily = ref(""), versionManagerSelection = ref("");
const versionManagerRuntime = computed(() => runtimes.value.catalog.find(item => item.family === versionManagerFamily.value));
const versionManagerAvailable = computed(() => versionManagerRuntime.value?.releases?.filter(item => !runtimeInstalled(item.id)) || []);
function openVersionManager(family: string) {
  versionManagerFamily.value = family;
  versionManagerSelection.value = versionManagerAvailable.value[0]?.id || "";
  versionManagerOpen.value = true;
}
function openRuntimeSettings(family: string, id: string) {
  if (family === "mysql") go("databases");
  else if (family === "nginx" || family === "apache") go("sites");
  else if (family === "php") extensionManager.value?.inspect(id);
  else lifecycleManager.value?.inspect(id);
}
async function installSelectedVersion() {
  const family = versionManagerFamily.value, id = versionManagerSelection.value;
  if (!versionManagerAvailable.value.some(item => item.id === id)) return;
  versions.value[family] = id;
  versionManagerOpen.value = false;
  await installRuntime(family);
}
async function installRuntime(family: string) {
  const id = versions.value[family];
  const release = runtimes.value.catalog
    .find((r) => r.family === family)
    ?.releases?.find((r) => r.id === id);
  if (!release) return;
  try {
    await ElMessageBox.confirm(
      `安装 ${{ php: "PHP", mysql: "MySQL", mariadb: "MariaDB", docker: "Docker", redis: "Redis", node: "Node.js", nginx: "Nginx", apache: "Apache" }[family] || family} ${release.version}。${family === "docker" ? "使用 Debian 签名仓库中的固定 Engine 与 Compose 软件包。" : ["node", "mariadb"].includes(family) ? "使用官方架构二进制并校验 SHA-256。" : "使用固定官方源码并校验 SHA-256。安装后可以单独选择生效范围。"}`,
      "安装运行环境",
      { confirmButtonText: "开始安装", cancelButtonText: "取消" },
    );
    const result = await api<{ job_id: string }>("/runtimes/install", "POST", {
      release_id: id,
    });
    await refresh();
    await revealJob(result.job_id);
  } catch (e) {
    if (e instanceof Error) ElMessage.error(e.message);
  }
}
async function installBundle(name: string, families: string[]) {
  const selected = families
    .map((family) => {
      const id = versions.value[family];
      const catalog = runtimes.value.catalog.find(
        (item) => item.family === family,
      );
      const release = catalog?.releases?.find((item) => item.id === id);
      return release
        ? {
            family,
            id,
            version: release.version,
            name: catalog?.name || family,
          }
        : null;
    })
    .filter((item): item is NonNullable<typeof item> => Boolean(item));
  if (selected.length !== families.length) {
    ElMessage.error("组合中有版本尚未进入可安装目录，请重新选择");
    return;
  }
  const releases = selected.filter((item) => !runtimeInstalled(item.id));
  if (!releases.length) {
    ElMessage.success(`${name} 所需运行环境均已安装`);
    return;
  }
  try {
    await ElMessageBox.confirm(
      `将按当前选择安装：${releases.map((item) => `${item.name} ${item.version}`).join("、")}。任务会进入安全安装队列并逐项校验。`,
      `一键安装 ${name}`,
      { confirmButtonText: "开始安装", cancelButtonText: "取消" },
    );
    const signature = selected.map((item) => item.id).join("|");
    let pending: { signature: string; key: string } | null = null;
    try { pending = JSON.parse(sessionStorage.getItem("panel-pending-bundle") || "null"); } catch { /* Ignore stale browser state. */ }
    const key = pending?.signature === signature ? pending.key : randomId();
    sessionStorage.setItem("panel-pending-bundle", JSON.stringify({ signature, key }));
    const result = await api<{ job_ids: string[]; installed: string[] }>("/runtimes/install-bundle", "POST", {
      release_ids: selected.map((item) => item.id),
    }, key);
    sessionStorage.removeItem("panel-pending-bundle");
    await refresh();
    go("jobs");
    ElMessage.success(result.job_ids.length ? `${name} 的 ${result.job_ids.length} 个安装任务已完整入队` : `${name} 所需运行环境均已安装`);
  } catch (e) {
    if (e instanceof Error) ElMessage.error(e.message);
  }
}
async function activateNginx(id: string) {
  try {
    await ElMessageBox.confirm(
      "这会切换全机网站入口。先核对全部网站和模块，再重启 Nginx 并逐站验证；失败将恢复原版本。切换期间新连接可能短暂重试。",
      "切换 Nginx 入口",
      {
        confirmButtonText: "预检并切换",
        cancelButtonText: "取消",
        type: "warning",
      },
    );
    const result = await api<{ job_id: string }>(
      "/runtimes/nginx/switch",
      "POST",
      { release_id: id },
    );
    await refresh();
    await revealJob(result.job_id);
  } catch (e) {
    if (e instanceof Error) ElMessage.error(e.message);
  }
}
function choosePHP(site: Site) {
  phpTarget.value = site;
  phpSelection.value = site.php_version_id;
  phpOpen.value = true;
}
async function switchPHP() {
  if (!phpTarget.value) return;
  submittingPHP.value = true;
  try {
    const result = await api<{ job_id: string }>(
      `/sites/${phpTarget.value.id}/php`,
      "POST",
      { release_id: phpSelection.value },
    );
    phpOpen.value = false;
    await refresh();
    await revealJob(result.job_id);
  } catch (e) {
    ElMessage.error((e as Error).message);
  } finally {
    submittingPHP.value = false;
  }
}
const allNav = [
  { key: "overview", label: "概览", icon: Odometer },
  { key: "sites", label: "网站", icon: Monitor },
  { key: "databases", label: "数据库", icon: Connection },
  { key: "files", label: "文件", icon: Folder },
  { key: "security", label: "安全", icon: Lock },
  { key: "runtimes", label: "软件商店", icon: Grid },
  { key: "schedules", label: "计划任务", icon: Calendar },
  { key: "monitor", label: "监控", icon: DataLine },
  { key: "terminal", label: "终端", icon: Platform },
  { key: "panel-access", label: "面板设置", icon: Setting },
  { key: "audit", label: "日志", icon: Tickets },
  { key: "system-tools", label: "系统工具", icon: Tools },
];
const nav = computed(() => allNav.filter(item => canOpenView(accessPlan.value, item.key)));
const panelVersion = import.meta.env.VITE_PANEL_VERSION || "0.1.0-dev";
const runtimeCardTags: Record<string, string[]> = {
  nginx: ["Web 服务", "反向代理", "高性能"],
  apache: ["Web 服务", "开源", "跨平台"],
  mysql: ["数据库", "关系型", "开源"],
  mariadb: ["数据库", "开源", "高性能"],
  redis: ["缓存", "键值存储", "高性能"],
  docker: ["容器", "虚拟化", "DevOps"],
  php: ["开发语言", "Web 开发"],
  node: ["开发环境", "前端工具", "高性能"],
  waf: ["WAF", "Nginx", "请求防护"],
  hardening: ["系统安全", "sysctl", "偏差检测"],
  intrusion: ["Fail2ban", "SSH", "自动封禁"],
};
const pageTitles: Record<string, string> = {
  overview: "服务器总览",
  sites: "网站管理",
  runtimes: "软件商店",
  databases: "数据库管理",
  files: "文件管理",
  monitor: "系统监控",
  certificates: "SSL 证书",
  "panel-access": "面板设置",
  security: "安全中心",
  schedules: "计划任务",
  backups: "备份管理",
  jobs: "任务中心",
  audit: "操作日志",
  account: "账户安全",
  terminal: "在线终端",
  "system-tools": "系统工具",
};
const title = computed(() => pageTitles[view.value] || "服务器总览");
const filteredSites = computed(() =>
  sites.value.filter((s) => {
    const matchesText = (s.name + " " + s.domain + " " + (s.settings?.domains || []).join(" "))
      .toLowerCase().includes(query.value.trim().toLowerCase());
    const matchesStatus = siteStatusFilter.value === "all" ||
      (siteStatusFilter.value === "running" ? s.status === "running" : s.status !== "running");
    return matchesText && matchesStatus &&
      (sitePHPFilter.value === "all" ||
        (sitePHPFilter.value === "static" ? !s.php_version_id : s.php_version_id === sitePHPFilter.value));
  }),
);
const pagedSites = computed(() => filteredSites.value.slice((sitePage.value - 1) * sitePageSize.value, sitePage.value * sitePageSize.value));
const sitePHPOptions = computed(() => [...new Set(sites.value.map((s) => s.php_version_id).filter(Boolean))].sort());
const siteCertificate = (site: Site) => siteCertificates.value.find((cert) => cert.id === site.settings?.tls?.certificate_id);
const siteExpiry = (site: Site) => siteCertificate(site)?.not_after || "";
const siteTLSState = (site: Site) => {
  if (!site.settings.tls?.certificate_id) return { label: "未部署", kind: "site-alert" };
  const cert = siteCertificate(site);
  if (!cert) return { label: "需核对", kind: "site-alert" };
  if (cert.status === "expired") return { label: "已过期", kind: "site-alert" };
  if (cert.status === "not_yet_valid") return { label: "未生效", kind: "site-alert" };
  if (cert.status === "expiring") return { label: "即将到期", kind: "site-warn" };
  if (cert.status === "valid") return { label: "已部署", kind: "site-ok" };
  return { label: "需核对", kind: "site-alert" };
};
const siteURL = (site: Site) => site.settings.public_ingress
  ? `${site.settings.tls?.certificate_id ? "https" : "http"}://${site.domain}`
  : `http://${site.domain}:19101`;
const expiringSites = computed(() => sites.value.filter((site) => {
  const expiry = siteExpiry(site);
  return expiry && new Date(expiry).getTime() - Date.now() <= 30 * 86400000;
}));
const siteDate = (value: string) => value ? formatPanelDate(value, { year: "numeric", month: "2-digit", day: "2-digit" }).replaceAll("/", "-") : "—";
const siteTodayBytes = (site: Site) => {
  const record = siteTraffic.value?.sites.find((item) => item.id === site.id);
  return record ? bytes(record.today_bytes) : "—";
};
const siteTrafficDays = computed(() => siteTraffic.value?.days || []);
const siteTrafficFocus = ref<number | null>(null);
const focusedTrafficDay = computed(() => siteTrafficFocus.value === null ? null : siteTrafficDays.value[siteTrafficFocus.value] || null);
const siteTrafficAmount = (value: number) => value < 1024 ? `${value} B` : value < 1048576 ? `${(value / 1024).toFixed(2)} KB` : value < 1073741824 ? `${(value / 1048576).toFixed(2)} MB` : `${(value / 1073741824).toFixed(2)} GB`;
const siteTrafficMaxBytes = computed(() => Math.max(0, ...siteTrafficDays.value.map(day => day.bytes)));
const siteTrafficUnit = computed(() => siteTrafficMaxBytes.value >= 1073741824 ? { label: "GB", divisor: 1073741824 } : siteTrafficMaxBytes.value >= 1048576 ? { label: "MB", divisor: 1048576 } : siteTrafficMaxBytes.value >= 1024 ? { label: "KB", divisor: 1024 } : { label: "B", divisor: 1 });
const siteTrafficTick = (fraction: number) => {
  const value = siteTrafficMaxBytes.value * fraction / siteTrafficUnit.value.divisor;
  return siteTrafficUnit.value.label === "B" ? Math.round(value).toString() : value.toFixed(value >= 10 ? 1 : 2);
};
const siteTrafficY = (field: "bytes" | "requests", index: number) => {
  const days = siteTrafficDays.value;
  const max = Math.max(1, ...days.map((day) => day[field]));
  return 133 - ((days[index]?.[field] || 0) / max) * 100;
};
const siteTrafficLine = (field: "bytes" | "requests") => {
  const days = siteTrafficDays.value;
  return days.map((_, index) => `${42 + index * 91},${siteTrafficY(field, index)}`).join(" ");
};
const siteReminders = computed(() => {
  const reminders: { title: string; detail: string; severity: string; date: string }[] = [];
  for (const site of sites.value) {
    const cert = siteCertificate(site);
    const expiry = siteExpiry(site);
    if (site.settings.tls?.certificate_id && !cert) reminders.push({ title: site.domain, detail: "SSL 证书记录无法读取", severity: "danger", date: "—" });
    else if (cert?.status === "not_yet_valid") reminders.push({ title: site.domain, detail: "SSL 证书尚未生效", severity: "warning", date: "—" });
    else if (expiry) {
      const days = Math.ceil((new Date(expiry).getTime() - Date.now()) / 86400000);
      if (days <= 30) reminders.push({ title: site.domain, detail: days < 0 ? "SSL 证书已过期" : `SSL 证书将在 ${days} 天后到期`, severity: days < 0 ? "danger" : "warning", date: siteDate(expiry) });
    } else reminders.push({ title: site.domain, detail: "尚未部署 SSL 证书", severity: "info", date: "—" });
  }
  return reminders.sort((a, b) => (a.severity === "danger" ? -1 : a.severity === "warning" ? 0 : 1) - (b.severity === "danger" ? -1 : b.severity === "warning" ? 0 : 1)).slice(0, 5);
});
const pending = computed(
  () =>
    jobs.value.filter((j) => ["queued", "running"].includes(j.state)).length,
);
const jobNames: Record<string, string> = {
  acme_certificate: "申请 / 续期证书",
  create_site: "创建网站",
  configure_site: "更新网站配置",
  enable_site: "启用网站",
  disable_site: "停用网站",
  install_runtime: "安装运行环境",
  software_install: "安装安全软件",
  software_configure: "更新安全软件配置",
  software_uninstall: "卸载安全软件",
  software_update: "更新应用版本 · 保留配置",
  install_php_extension: "安装 PHP 独立扩展",
  switch_php: "切换 PHP 版本",
  switch_nginx: "切换 Nginx 入口",
  retire_runtime: "卸载运行环境",
  restore_runtime: "恢复运行环境",
  purge_runtime_copy: "清理恢复副本",
  create_instance: "创建 MySQL 实例",
  start_instance: "启动 MySQL 实例",
  stop_instance: "停止 MySQL 实例",
  restart_instance: "重启 MySQL 实例",
  create_database: "创建数据库",
  import_database: "导入 SQL",
  overwrite_database: "覆盖导入 SQL",
  create_account: "创建数据库账号",
  update_account: "修改数据库权限",
  rotate_account: "更新数据库账号密码",
  enable_account: "启用数据库账号",
  disable_account: "停用数据库账号",
  quarantine_account: "回收数据库账号",
  restore_account: "恢复数据库账号",
  quarantine_database: "回收数据库",
  recover_database: "恢复回收数据库",
  backup_database: "备份数据库",
  restore_database: "恢复数据库",
  backup_site: "备份网站文件",
  restore_site: "恢复网站文件",
  migrate_database: "迁移 MySQL 数据库",
};
const isStoreInstallJob = (job: Job) =>
  job.kind === "install_runtime" || job.kind.startsWith("software_");
const jobTarget = (job: Job) => {
  if (job.database_name) return `${job.database_name} · ${job.site_name}`;
  if (job.kind.startsWith("software_")) {
    return softwareApps.value.catalog.find((item) => item.id === job.target_id)?.name || job.target_id;
  }
  return job.site_name || job.target_id;
};
type GlobalSearchResult = {
  key: string;
  category: string;
  label: string;
  detail: string;
  target: string;
  value?: string;
};
const searchResults = computed<GlobalSearchResult[]>(() => {
  const term = searchText.value.trim().toLowerCase();
  const pages = [
    ...nav.value.map((item) => ({ key: item.key, label: item.label })),
    ...["backups", "jobs", "certificates", "account"].map((key) => ({ key, label: pageTitles[key] })),
  ].filter(item => canOpenView(accessPlan.value, item.key));
  if (!term) {
    return ["sites", "databases", "files", "runtimes", "schedules", "monitor"].filter(key => canOpenView(accessPlan.value, key)).map((key) => ({
      key: `page:${key}`, category: "常用功能", label: pageTitles[key], detail: "打开管理页面", target: "page", value: key,
    }));
  }
  const results: GlobalSearchResult[] = pages
    .filter((item) => `${item.label} ${item.key}`.toLowerCase().includes(term))
    .map((item) => ({ key: `page:${item.key}`, category: "功能", label: item.label, detail: "打开管理页面", target: "page", value: item.key }));
  for (const site of canOpenView(accessPlan.value, "sites") ? sites.value : []) {
    if (`${site.name} ${site.domain} ${(site.settings?.domains || []).join(" ")}`.toLowerCase().includes(term)) {
      results.push({ key: `site:${site.id}`, category: "网站", label: site.name, detail: site.domain, target: "site", value: site.id });
    }
  }
  for (const runtime of runtimes.value.catalog) {
    if (`${runtime.name} ${runtime.family} ${(runtime.versions || []).join(" ")}`.toLowerCase().includes(term)) {
      results.push({ key: `runtime:${runtime.family}`, category: "软件", label: runtime.name, detail: runtime.versions?.join(" / ") || "查看可用版本", target: "runtime", value: runtime.family });
    }
  }
  for (const app of softwareApps.value.catalog) {
    if (`${app.name} ${app.family} ${app.capabilities.join(" ")}`.toLowerCase().includes(term)) results.push({ key: `software:${app.id}`, category: "安全软件", label: app.name, detail: app.description, target: "software", value: app.id });
  }
  for (const job of jobs.value.slice(0, 40)) {
    if (`${jobNames[job.kind] || job.kind} ${jobTarget(job)} ${job.state} ${job.id}`.toLowerCase().includes(term)) {
      results.push({ key: `job:${job.id}`, category: "任务", label: jobNames[job.kind] || job.kind, detail: `${jobTarget(job) || "系统任务"} · ${states[job.state] || job.state}`, target: "job", value: job.id });
    }
  }
  if ("刷新当前页面".includes(term) || "refresh".includes(term)) {
    results.push({ key: "command:refresh", category: "命令", label: "刷新当前页面", detail: pageTitles[view.value] || "当前页面", target: "refresh" });
  }
  if (canManageSites.value && ("创建网站".includes(term) || "新建站点".includes(term))) {
    results.push({ key: "command:create-site", category: "命令", label: "创建网站", detail: "打开新建网站表单", target: "create-site" });
  }
  if (canOpenView(accessPlan.value, "files")) results.push({ key: "file:search", category: "文件", label: `在网站文件中搜索“${searchText.value.trim()}”`, detail: "搜索所选站点的根目录", target: "file", value: searchText.value.trim() });
  return results.slice(0, 14);
});
const states: Record<string, string> = {
  running: "运行中",
  stopped: "已停用",
  provisioning: "创建中",
  needs_attention: "待核对",
  queued: "排队中",
  succeeded: "已完成",
  failed: "失败",
  canceled: "已取消",
  success: "成功",
  denied: "拒绝",
};
const label = (s: string) => states[s] || s;
const statusType = (s: string): "success" | "warning" | "danger" | "info" =>
  ["running", "succeeded", "success"].includes(s)
    ? "success"
    : ["failed", "denied"].includes(s)
      ? "danger"
      : ["queued", "provisioning", "needs_attention"].includes(s)
        ? "warning"
        : "info";
const date = (s: string) =>
  formatPanelDateTime(s, {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  });
const bytes = (v = 0) =>
  v >= 1073741824
    ? (v / 1073741824).toFixed(1) + " GB"
    : v >= 1048576
      ? (v / 1048576).toFixed(0) + " MB"
      : (v / 1024).toFixed(0) + " KB";
const percent = (v = 0) => Math.max(0, Math.min(100, v)).toFixed(1);
const uptime = computed(() => {
  const s = overview.value?.uptime_seconds || 0;
  return s >= 86400
    ? Math.floor(s / 86400) + " 天 " + Math.floor((s % 86400) / 3600) + " 小时"
    : Math.floor(s / 3600) + " 小时 " + Math.floor((s % 3600) / 60) + " 分钟";
});
const serverSampleTime = computed(() => overview.value?.sampled_at ? formatPanelDateTime(overview.value.sampled_at) : "—");
const healthState = computed(() => {
  if (error.value) return { label: "连接异常", kind: "error" };
  if (!overview.value) return { label: "正在获取状态", kind: "warning" };
  if (!overview.value.nginx_active) return { label: "网站入口待检查", kind: "warning" };
  return { label: "服务器运行正常", kind: "ok" };
});
const series = (field: "cpu" | "memory") =>
  samples.value
    .map(
      (s, i) =>
        `${samples.value.length > 1 ? (i / (samples.value.length - 1)) * 720 : 0},${180 - Math.min(100, Math.max(0, s[field])) * 1.6}`,
    )
    .join(" ");
const go = (key: string) => {
  if (!canOpenView(accessPlan.value, key)) { ElMessage.warning("当前账户未获该菜单授权"); return; }
  view.value = key;
  query.value = "";
  sidebar.value = false;
  if (key === "sites") void loadSiteTraffic(true);
};
async function openSiteBackup(siteID = "") {
  go("backups");
  await nextTick();
  backupManager.value?.openSiteBackup(siteID);
}
let siteTrafficLoadedAt = 0;
async function loadSiteTraffic(force = false) {
  if (!canReadPath(accessPlan.value, "/sites/traffic")) { siteTraffic.value = null; return; }
  if (!force && Date.now() - siteTrafficLoadedAt < 60000) return;
  siteTrafficLoadedAt = Date.now();
  try { const result = await permittedRead<SiteTraffic>("/sites/traffic"); if (result) siteTraffic.value = result; }
  catch { siteTraffic.value = null; }
}
function openSearch() {
  searchOpen.value = true;
  void nextTick(() => searchInput.value?.focus());
}
function onGlobalShortcut(event: KeyboardEvent) {
  if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k" && user.value) {
    event.preventDefault();
    openSearch();
  }
}
function setTheme(value: "light" | "dark") {
  theme.value = value;
  document.documentElement.classList.toggle("dark", value === "dark");
  localStorage.setItem("panel-theme", value);
}
function setSidebarStyle(value: "default" | "compact") {
  sidebarStyle.value = value;
  localStorage.setItem("panel-sidebar-style", value);
}
function setDisplayDensity(value: "comfortable" | "compact") {
  displayDensity.value = value;
  localStorage.setItem("panel-display-density", value);
}
async function chooseSearchResult(result: GlobalSearchResult) {
  searchOpen.value = false;
  searchText.value = "";
  if (result.target === "page" && result.value) go(result.value);
  else if (result.target === "site" && result.value) {
    const site = sites.value.find((item) => item.id === result.value);
    go("sites");
    query.value = site?.domain || site?.name || "";
  } else if (result.target === "runtime") {
    storeCategory.value = "all";
    storeStatus.value = "all";
    storeSearch.value = runtimes.value.catalog.find((item) => item.family === result.value)?.name || result.value || "";
    go("runtimes");
  } else if (result.target === "software") {
    storeCategory.value = "all";
    storeStatus.value = "all";
    const registryApp = appRegistry.value.catalog.apps.find(item => item.provider === "panel-module" && item.target === result.value);
    storeSearch.value = registryApp?.name || softwareApps.value.catalog.find((item) => item.id === result.value)?.name || result.value || "";
    go("runtimes");
  }
  else if (result.target === "job" && result.value) {
    const job = jobs.value.find((item) => item.id === result.value);
    go("jobs");
    if (job) openJob(job);
  } else if (result.target === "file" && result.value) {
    go("files");
    await nextTick();
    fileManager.value?.searchFor(result.value);
  } else if (result.target === "refresh") await manualRefresh();
  else if (result.target === "create-site") createOpen.value = true;
}
function submitSearch() {
  const first = searchResults.value[0];
  if (first) void chooseSearchResult(first);
}
const notificationTime = (value: number) =>
  formatPanelDateTime(value * 1000);
async function readNotification(item: PanelNotification) {
  try {
    if (!item.read_at) {
      await api(`/notifications/${item.id}/read`, "POST", {});
      item.read_at = Math.floor(Date.now() / 1000);
      notificationUnread.value = Math.max(0, notificationUnread.value - 1);
    }
    if (item.kind === "schedule") go("schedules");
    else if (item.kind === "remote") go("backups");
    else if (item.kind === "monitor") go("monitor");
  } catch (e) {
    ElMessage.error((e as Error).message);
  }
}
async function readAllNotifications() {
  try {
    await api("/notifications/read-all", "POST", {});
    const now = Math.floor(Date.now() / 1000);
    notifications.value.forEach((item) => (item.read_at ||= now));
    notificationUnread.value = 0;
  } catch (e) {
    ElMessage.error((e as Error).message);
  }
}
async function api<T>(
  path: string,
  method = "GET",
  body?: unknown,
  idempotencyKey?: string,
): Promise<T> {
  const requestCSRF = csrf.value;
  const r = await fetch(apiURL(path), {
    method,
    credentials: "same-origin",
    headers: {
      "Content-Type": "application/json",
      "X-CSRF-Token": csrf.value,
      ...(method === "POST" ? { "Idempotency-Key": idempotencyKey || randomId() } : {}),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const data = await r.json();
  if (!r.ok) {
    if (
      r.status === 401 &&
      path !== "/login" &&
      requestCSRF === csrf.value &&
      !accountChanging.value
    ) {
      user.value = ""; accessPlan.value = null; clearAccessData();
    }
    throw new Error(data.error || "请求失败");
  }
  return data;
}
let refreshing = false;
async function refresh(forceRegistry = false) {
  if (
    !user.value ||
    refreshing ||
    accountChanging.value ||
    view.value === "account"
  )
    return;
  refreshing = true;
  const epoch = accessEpoch;
  const errors: string[] = [];
  await Promise.allSettled([
    permittedRead<Overview>("/overview")
      .then((d) => {
        if (!d) return;
        overview.value = d;
        samples.value = [
          ...samples.value,
          { cpu: d.cpu_percent, memory: d.memory_percent, time: Date.now() },
        ].slice(-36);
      })
      .catch((e) => errors.push(e.message)),
    permittedRead<Site[]>("/sites")
      .then((d) => { if (d) sites.value = d; })
      .catch((e) => errors.push(e.message)),
    permittedRead<SiteCertificate[]>("/certificates")
      .then((d) => { if (d) siteCertificates.value = d; })
      .catch((e) => errors.push(e.message)),
    ...(view.value === "sites" ? [loadSiteTraffic()] : []),
    permittedRead<Job[]>("/jobs")
      .then(async (d) => {
        if (!d) return;
        jobs.value = d;
        if (selectedJob.value) {
          const id = selectedJob.value.id;
          const found = d.find((x) => x.id === id);
          if (found) selectedJob.value = found;
          else if (jobOpen.value) {
            const latest = await permittedRead<Job>("/jobs/" + id);
            if (latest && selectedJob.value?.id === id) selectedJob.value = latest;
          }
        }
      })
      .catch((e) => errors.push(e.message)),
    permittedRead<Audit[]>("/audit")
      .then((d) => { if (d) audits.value = d; })
      .catch((e) => errors.push(e.message)),
    permittedRead<{ notifications: PanelNotification[]; unread: number }>(
      "/notifications?limit=30",
    )
      .then((d) => {
        if (!d) return;
        notifications.value = d.notifications;
        notificationUnread.value = d.unread;
      })
      .catch((e) => errors.push(e.message)),
    permittedRead<Runtimes>("/runtimes")
      .then((d) => {
        if (!d) return;
        runtimes.value = d;
        for (const item of d.catalog) {
          if (item.releases?.length && !item.releases.some(release => release.id === versions.value[item.family])) {
            versions.value[item.family] = item.releases[0].id;
          }
        }
      })
      .catch((e) => errors.push(e.message)),
    permittedRead<SoftwareApps>("/software")
      .then((d) => { if (d) softwareApps.value = d; })
      .catch((e) => errors.push(e.message)),
    permittedRead<AppRegistry>(forceRegistry === true ? "/app-registry?refresh=1" : "/app-registry")
      .then((d) => { if (d) appRegistry.value = d; })
      .catch((e) => {
        if (epoch !== accessEpoch) return;
        appRegistry.value.source = { ...appRegistry.value.source, stale: true, error: e.message };
        if (!appRegistry.value.catalog.apps.length) errors.push(e.message);
      }),
  ]);
  if (epoch === accessEpoch) error.value = errors[0] || "";
  refreshing = false;
}
async function login() {
  busy.value = true;
  authError.value = "";
  try {
    if (!initialized.value) {
      await api("/bootstrap", "POST", {
        username: username.value,
        password: password.value,
        token: bootstrap.value,
      });
      initialized.value = true;
    }
    const me = await api<{ username: string; csrf: string }>("/login", "POST", {
      username: username.value,
      password: password.value,
      code: otpCode.value,
    });
    csrf.value = me.csrf;
    const access = await api<AccessPlan>("/me");
    applyAccess(access);
    user.value = me.username;
    lastSessionActivitySentAt = Date.now();
    password.value = "";
    otpCode.value = "";
    bootstrap.value = "";
    await refresh();
  } catch (e) {
    authError.value = (e as Error).message;
  } finally {
    busy.value = false;
  }
}
async function logout() {
  try {
    await api("/logout", "POST", {});
    user.value = "";
    csrf.value = "";
    accessPlan.value = null; clearAccessData();
    lastSessionActivitySentAt = 0;
    sites.value = [];
    jobs.value = [];
    audits.value = [];
    overview.value = null;
    samples.value = [];
  } catch (e) {
    ElMessage.error((e as Error).message);
  }
}
async function create() {
  creating.value = true;
  try {
    const j = await api<{ job_id: string }>("/sites", "POST", {
      name: siteName.value,
      slug: slug.value,
      domain: primaryDomain.value.trim(),
      php_version_id: createPHP.value,
    });
    createOpen.value = false;
    siteName.value = "";
    slug.value = "";
    primaryDomain.value = "";
    await refresh();
    await revealJob(j.job_id);
    ElMessage.success("创建任务已提交");
  } catch (e) {
    ElMessage.error((e as Error).message);
  } finally {
    creating.value = false;
  }
}
async function action(s: Site) {
  const act = s.status === "running" ? "disable" : "enable";
  try {
    if (act === "disable")
      await ElMessageBox.confirm(
        `停用后 ${s.domain} 将停止提供页面，网站文件会保留。`,
        "停用网站",
        {
          confirmButtonText: "停用",
          cancelButtonText: "取消",
          type: "warning",
        },
      );
    await api(`/sites/${s.id}/${act}`, "POST", {});
    await refresh();
    ElMessage.success("操作已加入任务队列");
  } catch (e) {
    if (e instanceof Error) ElMessage.error(e.message);
  }
}
async function archiveSite(s: Site) {
  try {
    const confirmation = await ElMessageBox.prompt(
      `归档后将停止 ${s.domain} 的服务并释放域名，网站目录会保存在服务器归档区。请输入完整主域名确认。`,
      "归档网站",
      {
        inputPlaceholder: s.domain,
        inputValidator: (value: string) => value === s.domain || "主域名不匹配",
        confirmButtonText: "归档网站",
        cancelButtonText: "取消",
        type: "warning",
      },
    );
    const result = await api<{ job_id: string }>(`/sites/${s.id}`, "DELETE", { confirm_domain: confirmation.value });
    await refresh();
    await revealJob(result.job_id);
    ElMessage.success("网站归档任务已提交");
  } catch (e) {
    if (e instanceof Error && e.message !== "cancel") ElMessage.error(e.message);
  }
}
function siteCommand(site: Site, command: string) {
  if (command === "files") {
    fileSiteID.value = site.id;
    go("files");
  } else if (command === "config") void config(site);
  else if (command === "waf") openSiteSettings(site.id, "waf");
  else if (command === "php") choosePHP(site);
  else if (command === "toggle") void action(site);
  else if (command === "archive") void archiveSite(site);
}
async function config(s: Site) {
  loadingConfig.value = true;
  try {
    siteConfig.value = await api(`/sites/${s.id}/config`);
    configOpen.value = true;
  } catch (e) {
    ElMessage.error((e as Error).message);
  } finally {
    loadingConfig.value = false;
  }
}
const buildLog = ref(""),
  buildLogOpen = ref(false);
async function showBuildLog(j: Job) {
  try {
    const log = await api<{ content: string }>(`/jobs/${j.id}/log`);
    buildLog.value = log.content;
    buildLogOpen.value = true;
  } catch (e) {
    ElMessage.error((e as Error).message);
  }
}
async function retry(j: Job) {
  try {
    await api(`/jobs/${j.id}/retry`, "POST", {});
    await refresh();
    ElMessage.success("将核对已有资源并重试");
  } catch (e) {
    ElMessage.error((e as Error).message);
  }
}
const siteBusy = (s: Site) =>
  jobs.value.some(
    (j) => j.site_id === s.id && ["queued", "running"].includes(j.state),
  );
async function revealJob(id: string) {
  const list = await api<Job[]>("/jobs");
  jobs.value = list;
  const found =
    list.find((j) => j.id === id) || (await api<Job>("/jobs/" + id));
  openJob(found);
}
function openJob(j: Job) {
  selectedJob.value = j;
  jobOpen.value = true;
}
let timer: ReturnType<typeof setInterval>;
let lastSessionActivitySentAt = 0;
function onSessionActivity() {
  if (!user.value || document.visibilityState !== "visible") return;
  const now = Date.now();
  if (now - lastSessionActivitySentAt < 60_000) return;
  lastSessionActivitySentAt = now;
  void api("/session/activity", "POST", {}).catch(() => {
    // A failed ping is retried on the next real user interaction.
    lastSessionActivitySentAt = 0;
  });
}
onMounted(async () => {
  setTheme(localStorage.getItem("panel-theme") === "dark" ? "dark" : "light");
  setSidebarStyle(localStorage.getItem("panel-sidebar-style") === "compact" ? "compact" : "default");
  setDisplayDensity(localStorage.getItem("panel-display-density") === "compact" ? "compact" : "comfortable");
  window.addEventListener("keydown", onGlobalShortcut);
  window.addEventListener("pointerdown", onSessionActivity);
  window.addEventListener("keydown", onSessionActivity);
  window.addEventListener("scroll", onSessionActivity, true);
  try {
    const b = await api<{ initialized: boolean }>("/bootstrap");
    initialized.value = b.initialized;
    if (b.initialized) {
      try {
        const me = await api<AccessPlan & { username: string; csrf: string }>("/me");
        applyAccess(me);
        user.value = me.username;
        csrf.value = me.csrf;
        await refresh();
      } catch {}
    }
  } catch (e) {
    authError.value = (e as Error).message;
  } finally {
    ready.value = true;
  }
  timer = setInterval(refresh, 5000);
});
onUnmounted(() => {
  clearInterval(timer);
  window.removeEventListener("keydown", onGlobalShortcut);
  window.removeEventListener("pointerdown", onSessionActivity);
  window.removeEventListener("keydown", onSessionActivity);
  window.removeEventListener("scroll", onSessionActivity, true);
});
</script>

<template>
  <div v-if="!ready" class="boot">
    <span class="brand-mark"
      ><el-icon><DataBoard /></el-icon
    ></span>
    <p>正在连接开发环境…</p>
  </div>
  <div v-else-if="!user" class="auth-page">
    <div class="auth-intro">
      <div class="wordmark">
        <span class="brand-mark"
          ><PanelIcon name="brand" /></span
        ><span class="brand-copy"
          ><strong>云栈面板</strong><small>服务器运维面板</small></span
        >
      </div>
      <div>
        <span class="eyebrow">A SPACE FOR YOUR SERVER</span>
        <h1>服务器管理，<br />从这里开始。</h1>
        <p>
          用自己的面板，管理自己的环境。<br />站点、服务与每一次变更，都清晰可见。
        </p>
        <div class="auth-lines"><span></span><span></span><span></span></div>
      </div>
      <small>服务器运维面板</small>
    </div>
    <div class="auth-box">
      <div class="small-kicker">WORKSPACE ACCESS</div>
      <h2>{{ initialized ? "登录工作台" : "初始化工作台" }}</h2>
      <p class="muted">
        {{
          initialized
            ? "输入管理员账户，继续管理服务器。"
            : "使用本机初始化令牌创建第一个管理员。"
        }}
      </p>
      <form @submit.prevent="login">
        <label v-if="!initialized" for="bootstrap">初始化令牌</label
        ><input
          v-if="!initialized"
          id="bootstrap"
          v-model="bootstrap"
          required
          autocomplete="off"
          type="password"
        />
        <label for="username">用户名</label
        ><input
          id="username"
          v-model="username"
          required
          autocomplete="username"
          placeholder="管理员用户名"
        />
        <label for="password">密码</label
        ><input
          id="password"
          v-model="password"
          required
          :autocomplete="initialized ? 'current-password' : 'new-password'"
          type="password"
          placeholder="输入管理员密码"
          :minlength="initialized ? undefined : 12"
        />
        <template v-if="initialized"
          ><label for="otp-code">动态码或恢复码（已开启双重验证时填写）</label
          ><input
            id="otp-code"
            v-model="otpCode"
            autocomplete="one-time-code"
            maxlength="40"
            placeholder="未开启双重验证可留空"
        /></template>
        <el-alert
          v-if="authError"
          :title="authError"
          type="error"
          :closable="false"
          show-icon
        />
        <el-button
          type="primary"
          native-type="submit"
          size="large"
          :loading="busy"
          class="auth-submit"
          >{{ initialized ? "进入工作台" : "创建管理员并登录" }}
          <el-icon><ArrowRight /></el-icon
        ></el-button>
      </form>
      <div class="auth-foot">
        <span class="live-dot"></span>独立 Linux 服务器环境
      </div>
    </div>
  </div>
  <div v-else class="app-shell" :class="{ 'sidebar-compact': sidebarStyle === 'compact', 'density-compact': displayDensity === 'compact' }">
    <div v-if="sidebar" class="sidebar-scrim" @click="sidebar = false"></div>
    <aside :class="['sidebar', { open: sidebar }]">
      <div class="wordmark">
        <span class="brand-mark"
          ><PanelIcon name="brand" /></span
        ><span class="brand-copy"
          ><strong>云栈面板</strong><small>服务器运维面板</small></span
        >
      </div>
      <div class="server-switch">
        <span class="server-avatar"
          ><el-icon><Monitor /></el-icon
        ></span>
        <div>
          <strong>Panel Dev</strong
          ><small
            ><span class="live-dot"></span
            >{{ error ? "连接异常" : "本地开发环境" }}</small
          >
        </div>
        <span class="mini-tag">01</span>
      </div>
      <div class="nav-caption">服务器管理</div>
      <nav>
        <button
          v-for="n in nav"
          :key="n.key"
          :class="{ active: view === n.key }"
          :aria-label="n.label"
          :title="sidebarStyle === 'compact' ? n.label : undefined"
          @click="go(n.key)"
        >
          <PanelIcon :name="n.key" /><span>{{ n.label }}</span
          ><span v-if="n.key === 'jobs' && pending" class="nav-count">{{
            pending
          }}</span
          ><span v-if="view === n.key" class="nav-dot"></span>
        </button>
      </nav>
      <div class="sidebar-bottom">
        <div class="dev-note">
          <span class="lab-label">开发版 0.1</span>
          <p>每一个可用状态，<br />都来自实际执行结果。</p>
        </div>
        <button
          class="account"
          aria-label="退出登录"
          title="退出登录"
          @click="logout"
        >
          <span class="avatar"><el-icon><UserFilled /></el-icon></span
          ><span
            ><strong>{{ user }}</strong
            ><small>{{ accountRoleLabel }}</small></span
          ><el-icon><SwitchButton /></el-icon>
        </button>
      </div>
    </aside>
    <main class="main">
      <header class="topbar">
        <div class="topbar-left">
          <button
            class="mobile-menu"
            aria-label="展开导航"
            @click="sidebar = true"
          >
            <el-icon><Fold /></el-icon>
          </button>
          <div class="breadcrumb">
            <span>首页</span><span class="slash">/</span
            ><strong>{{ title }}</strong>
          </div>
          <span :class="['health-badge', healthState.kind]"
            ><span class="live-dot"></span>{{ healthState.label }}</span
          ><span class="uptime-text">运行时间：{{ uptime }}</span>
        </div>
        <div class="topbar-right">
          <button class="global-search" type="button" aria-label="全局搜索" @click="openSearch">
            <span>搜索功能、站点、文件或命令...</span
            ><el-icon><Search /></el-icon>
          </button>
          <el-popover placement="bottom-end" :width="390" trigger="click">
            <template #reference>
              <button class="icon-button notification-button" aria-label="通知">
                <el-icon><Bell /></el-icon
                ><span v-if="notificationUnread" class="notification-count">{{
                  notificationUnread > 99 ? "99+" : notificationUnread
                }}</span>
              </button>
            </template>
            <div class="notification-panel">
              <div class="notification-panel-head">
                <div><strong>站内通知</strong><small>{{ notificationUnread }} 条未读</small></div>
                <el-button v-if="notificationUnread" link type="primary" @click="readAllNotifications">全部已读</el-button>
              </div>
              <div class="notification-list">
                <button
                  v-for="item in notifications"
                  :key="item.id"
                  :class="['notification-item', { unread: !item.read_at }]"
                  @click="readNotification(item)"
                >
                  <i :class="item.severity"></i>
                  <span><strong>{{ item.title }}</strong><small>{{ item.message }}</small><time>{{ notificationTime(item.created_at) }}</time></span>
                </button>
                <el-empty v-if="!notifications.length" description="暂无通知" :image-size="48" />
              </div>
            </div>
          </el-popover>
          <button class="icon-button" aria-label="主题与显示" @click="go('panel-access'); settingsTab = 'theme'">
            <PanelIcon name="theme" />
          </button>
          <el-dropdown trigger="click" @command="(command: string) => command === 'logout' ? logout() : (go('panel-access'), settingsTab = 'account')">
            <button class="topbar-account" type="button" aria-label="账户菜单"><span class="avatar small"><el-icon><UserFilled /></el-icon></span><strong class="topbar-user">{{ user }}</strong><el-icon><ArrowDown /></el-icon></button>
            <template #dropdown><el-dropdown-menu><el-dropdown-item command="account">账户设置</el-dropdown-item><el-dropdown-item command="logout" divided>退出登录</el-dropdown-item></el-dropdown-menu></template>
          </el-dropdown>
        </div>
      </header>
      <el-dialog v-model="searchOpen" title="全局搜索" width="620px" class="global-search-dialog" @opened="searchInput?.focus()">
        <div class="global-search-panel">
          <div class="global-search-entry">
            <el-icon><Search /></el-icon>
            <input ref="searchInput" v-model="searchText" aria-label="搜索功能、站点、文件或命令" placeholder="搜索功能、站点、文件或命令..." autocomplete="off" @keydown.enter.prevent="submitSearch" />
            <kbd>⌘ K</kbd>
          </div>
          <div class="global-search-results">
            <button v-for="result in searchResults" :key="result.key" type="button" @click="chooseSearchResult(result)">
              <span class="global-search-result-type">{{ result.category }}</span>
              <span><strong>{{ result.label }}</strong><small>{{ result.detail }}</small></span>
              <el-icon><ArrowRight /></el-icon>
            </button>
            <p v-if="!searchResults.length" class="global-search-empty">没有匹配的功能或资源</p>
          </div>
          <p class="global-search-hint">按 Enter 打开首项 · 文件搜索作用于所选站点根目录</p>
        </div>
      </el-dialog>
      <div class="page-content">
        <div
          :class="[
            'page-heading',
            {
              'runtime-heading': view === 'runtimes',
              'monitor-heading': view === 'monitor',
              'security-heading': view === 'security',
              'plain-heading': [
                'sites',
                'databases',
                'monitor',
                'security',
              'panel-access',
              ].includes(view),
              'settings-heading': view === 'panel-access',
            },
          ]"
        >
          <div>
            <div class="small-kicker">
              {{ view === "overview" ? "SERVER OVERVIEW" : "SERVER WORKSPACE" }}
            </div>
            <h1>{{ title === "总览" ? "服务器总览" : title }}</h1>
            <p>
              {{
                view === "overview"
                  ? "查看运行状态，掌握每一次变化。"
                  : view === "sites"
                    ? "管理服务器上的网站站点，支持站点创建、SSL 证书、备份、伪静态、PHP 版本等功能。"
                    : view === "runtimes"
                      ? "安装和管理精确运行环境与可验证的安全防护软件。"
                      : view === "databases"
                        ? "集中管理服务器上的数据库，支持多种数据库类型，提供备份、监控、权限管理等功能。"
                        : view === "files"
                          ? "在线管理服务器文件，支持上传、下载、编辑、压缩解压等功能。"
                          : view === "monitor"
                            ? "后台持续采样，查看资源趋势、缺口和阈值告警。"
                            : view === "certificates"
                              ? "管理证书、有效期与站点绑定。"
                              : view === "panel-access"
                                ? "配置面板的基本信息、安全选项、通知设置和外观显示等参数。"
                                : view === "security"
                                  ? "检查主机防火墙、SSH、登录记录和受管网站安全线索。"
                                  : view === "schedules"
                                    ? "按计划执行备份、日志维护与运维任务，核对每次实际结果。"
                                    : view === "backups"
                                      ? "集中核对、下载并恢复网站与数据库备份。"
                                      : view === "account"
                                        ? "保护管理员登录，并准备账户恢复方式。"
                                        : view === "jobs"
                                          ? "长任务持续执行，刷新页面也不会丢失记录。"
                                          : view === "terminal"
                                            ? "通过 Web 终端连接服务器，进行实时命令操作和系统管理。"
                                            : view === "system-tools"
                                              ? "集中进入证书、备份、任务、账户与系统维护工具。"
                                              : "记录身份、操作对象和执行结果。"
              }}
            </p>
            <div
              v-if="view === 'runtimes'"
              class="store-categories"
              aria-label="软件分类"
            >
              <button v-for="category in storeTabCategories" :key="category.id" type="button" :class="{ active: storeCategory === category.id }" @click="storeCategory = category.id">{{ category.label }}</button>
            </div>
          </div>
          <div v-if="view === 'databases'" class="site-heading-actions">
            <el-button type="primary" :icon="Plus" @click="databaseManager?.newDatabase()">创建数据库</el-button>
            <el-button @click="databaseManager?.openImport()">导入</el-button>
            <el-button @click="go('backups')">备份</el-button>
            <el-button @click="databaseManager?.openPermissions()">权限管理</el-button>
          </div>
          <div v-else-if="view === 'sites' && canManageSites" class="site-heading-actions">
            <el-button type="primary" :icon="Plus" @click="createOpen = true">添加站点</el-button>
            <el-button @click="batchSSLOpen = true">批量部署 SSL</el-button>
            <el-button v-if="canOpenView(accessPlan, 'backups')" @click="openSiteBackup()">备份站点</el-button>
            <el-dropdown trigger="click" @command="(command: string) => go(command)">
              <el-button>更多操作⌄</el-button>
              <template #dropdown><el-dropdown-menu>
                <el-dropdown-item v-if="canOpenView(accessPlan, 'jobs')" command="jobs">站点任务</el-dropdown-item>
                <el-dropdown-item v-if="canOpenView(accessPlan, 'audit')" command="audit">操作日志</el-dropdown-item>
              </el-dropdown-menu></template>
            </el-dropdown>
          </div>
          <el-button v-else-if="view === 'security'" type="primary" @click="securityManager?.scanNow()">立即扫描</el-button>
          <el-button
            v-else-if="view === 'overview' && canManageSites"
            type="primary"
            :icon="Plus"
            @click="createOpen = true"
            >创建网站</el-button
          ><el-button
            v-else-if="view === 'runtimes'"
            :icon="Tickets"
            @click="go('jobs')"
            >软件安装日志</el-button
          ><div v-else-if="view === 'schedules'" class="site-heading-actions">
            <el-button type="primary" :icon="Plus" @click="scheduleManager?.createSchedule()">添加任务</el-button>
            <el-button @click="scheduleManager?.openRunPicker()">立即执行</el-button>
            <el-button @click="scheduleManager?.openTaskSettings()">任务设置</el-button>
          </div><el-button
            v-else-if="view === 'terminal'"
            type="primary"
            :icon="Plus"
            @click="terminalManager?.start()"
            >新建会话</el-button
          ><el-button
            v-else-if="!['system-tools', 'panel-access', 'files'].includes(view)"
            :icon="Refresh"
            @click="manualRefresh"
            >刷新</el-button
          >
        </div>
        <el-alert
          v-if="error"
          class="page-alert"
          :title="error"
          description="当前显示最近一次读取的数据，请检查虚拟机和执行服务。"
          type="error"
          :closable="false"
          show-icon
        />
        <template v-if="view === 'overview'">
          <div class="summary-strip">
            <div>
              <span class="server-status"
                ><span class="live-dot"></span
                >{{
                  overview?.nginx_active ? "服务器在线" : "正在读取状态"
                }}</span
              ><span class="strip-separator"></span
              ><span>{{ overview?.hostname || "panel-dev" }}</span
              ><span class="subtle">{{ overview?.os || "正在读取系统信息" }}</span>
            </div>
            <small>已运行 {{ uptime }}</small>
          </div>
          <div class="metric-grid">
            <article class="metric">
              <div class="metric-title">
                <span>CPU 使用率</span><el-icon><Odometer /></el-icon>
              </div>
              <div class="metric-number">
                {{ percent(overview?.cpu_percent) }}<span>%</span>
              </div>
              <el-progress
                :percentage="Number(percent(overview?.cpu_percent))"
                :show-text="false"
                :stroke-width="5"
                color="#0f766e"
              />
              <div class="metric-footer">
                {{ overview?.cpu_cores || "—" }} 核处理器 <span>实时采样</span>
              </div>
            </article>
            <article class="metric">
              <div class="metric-title">
                <span>内存使用</span><el-icon><Box /></el-icon>
              </div>
              <div class="metric-number">
                {{ percent(overview?.memory_percent) }}<span>%</span>
              </div>
              <el-progress
                :percentage="Number(percent(overview?.memory_percent))"
                :show-text="false"
                :stroke-width="5"
                color="#7e9b78"
              />
              <div class="metric-footer">
                {{ bytes(overview?.memory_used) }}
                <span>/ {{ bytes(overview?.memory_total) }}</span>
              </div>
            </article>
            <article class="metric">
              <div class="metric-title">
                <span>磁盘使用</span><el-icon><Document /></el-icon>
              </div>
              <div class="metric-number">
                {{ percent(overview?.disk_percent) }}<span>%</span>
              </div>
              <el-progress
                :percentage="Number(percent(overview?.disk_percent))"
                :show-text="false"
                :stroke-width="5"
                color="#c49a61"
              />
              <div class="metric-footer">
                {{ bytes(overview?.disk_used) }}
                <span>/ {{ bytes(overview?.disk_total) }}</span>
              </div>
            </article>
            <article class="metric website-metric">
              <div class="metric-title">
                <span>托管网站</span><el-icon><Monitor /></el-icon>
              </div>
              <div class="metric-number">
                {{ overview?.counts?.sites || 0 }}<span>个</span>
              </div>
              <div class="site-count-detail">
                <span class="live-dot"></span
                >{{ overview?.counts?.running_sites || 0 }} 个运行中
              </div>
              <button class="text-link metric-footer" @click="go('sites')">
                查看全部网站 <el-icon><ArrowRight /></el-icon>
              </button>
            </article>
          </div>
          <div class="dashboard-grid">
            <section class="panel-card resource-chart">
              <div class="card-heading">
                <div>
                  <h2>资源趋势</h2>
                  <p>当前会话 · 每 5 秒采样</p>
                </div>
                <div class="legend">
                  <span><i class="cpu-line"></i>CPU</span
                  ><span><i class="memory-line"></i>内存</span>
                </div>
              </div>
              <div class="chart-wrap">
                <div class="chart-axis">
                  <span>100%</span><span>50%</span><span>0%</span>
                </div>
                <svg
                  viewBox="0 0 720 210"
                  role="img"
                  aria-label="本次会话 CPU 和内存使用趋势"
                  preserveAspectRatio="none"
                >
                  <line
                    v-for="y in [20, 100, 180]"
                    :key="y"
                    x1="0"
                    :y1="y"
                    x2="720"
                    :y2="y"
                    stroke="#e8eeeb"
                    stroke-dasharray="4 4"
                  />
                  <polyline
                    v-if="samples.length > 1"
                    :points="series('memory')"
                    fill="none"
                    stroke="#8ca681"
                    stroke-width="2"
                  />
                  <polyline
                    v-if="samples.length > 1"
                    :points="series('cpu')"
                    fill="none"
                    stroke="#0f766e"
                    stroke-width="2.5"
                  />
                  <text
                    v-if="samples.length < 2"
                    x="360"
                    y="105"
                    text-anchor="middle"
                    fill="#8c9993"
                    font-size="13"
                  >
                    正在收集采样数据
                  </text>
                </svg>
              </div>
              <div class="chart-bottom">
                <span>本次会话开始</span
                ><span>{{
                  overview?.sampled_at ? date(overview.sampled_at) : "等待数据"
                }}</span>
              </div>
            </section>
            <section class="panel-card services">
              <div class="card-heading">
                <div>
                  <h2>服务状态</h2>
                  <p>正在运行的基础环境</p>
                </div>
                <el-icon><Connection /></el-icon>
              </div>
              <div class="service-row">
                <div class="software-icon nginx">N</div>
                <div><strong>Nginx</strong><small>网站入口</small></div>
                <el-tag
                  disable-transitions
                  :type="overview?.nginx_active ? 'success' : 'danger'"
                  effect="light"
                  round
                  >{{ overview?.nginx_active ? "运行中" : "待检查" }}</el-tag
                >
              </div>
              <div class="service-row">
                <div class="software-icon panel-icon">P</div>
                <div>
                  <strong>Panel API</strong><small>管理服务与任务队列</small>
                </div>
                <el-tag disable-transitions type="success" effect="light" round
                  >已连接</el-tag
                >
              </div>
              <div class="network-box">
                <span
                  >累计接收
                  <strong>{{ bytes(overview?.network_rx) }}</strong></span
                ><span
                  >累计发送
                  <strong>{{ bytes(overview?.network_tx) }}</strong></span
                >
              </div>
              <button class="text-link" @click="go('runtimes')">
                管理运行环境 <el-icon><ArrowRight /></el-icon>
              </button>
            </section>
          </div>
          <section class="panel-card recent-jobs">
            <div class="card-heading">
              <div>
                <h2>
                  最近任务 <span class="count-badge">{{ jobs.length }}</span>
                </h2>
                <p>配置校验、执行与访问验证</p>
              </div>
              <button class="text-link" @click="go('jobs')">
                全部任务 <el-icon><ArrowRight /></el-icon>
              </button>
            </div>
            <el-table
              :data="jobs.slice(0, 5)"
              empty-text="还没有任务。创建第一个网站，开始验证完整流程。"
              @row-click="openJob"
              ><el-table-column label="任务" min-width="160"
                ><template #default="{ row }"
                  ><strong>{{ jobNames[row.kind] }}</strong
                  ><span class="table-secondary">{{
                    jobTarget(row)
                  }}</span></template
                ></el-table-column
              ><el-table-column label="状态" width="110"
                ><template #default="{ row }"
                  ><el-tag
                    disable-transitions
                    :type="statusType(row.state)"
                    size="small"
                    >{{ label(row.state) }}</el-tag
                  ></template
                ></el-table-column
              ><el-table-column label="提交时间" min-width="160"
                ><template #default="{ row }">{{
                  date(row.created_at)
                }}</template></el-table-column
              ><el-table-column width="80"
                ><template #default>详情 →</template></el-table-column
              ></el-table
            >
          </section>
        </template>
        <template v-if="view === 'sites'">
          <div class="site-summary-grid">
            <article class="panel-card site-summary-card">
              <span class="summary-icon green"><PanelIcon name="sites" /></span>
              <div>
                <small>网站总数</small><strong>{{ sites.length }}</strong
                ><span>当前已创建的站点</span>
              </div>
            </article>
            <article class="panel-card site-summary-card">
              <span class="summary-icon green"
                ><el-icon><VideoPlay /></el-icon
              ></span>
              <div>
                <small>运行中</small
                ><strong>{{
                  sites.filter((s) => s.status === "running").length
                }}</strong
                ><span>{{ sites.length ? `运行正常 ${(sites.filter((s) => s.status === 'running').length / sites.length * 100).toFixed(1)}%` : '暂无站点' }}</span>
              </div>
            </article>
            <article class="panel-card site-summary-card">
              <span class="summary-icon orange"
                ><el-icon><VideoPause /></el-icon
              ></span>
              <div>
                <small>已暂停</small
                ><strong>{{
                  sites.filter((s) => s.status !== "running").length
                }}</strong
                ><span>{{ sites.length ? `占比 ${(sites.filter((s) => s.status !== 'running').length / sites.length * 100).toFixed(1)}%` : '暂无站点' }}</span>
              </div>
            </article>
            <article class="panel-card site-summary-card">
              <span class="summary-icon red"
                ><el-icon><Timer /></el-icon
              ></span>
              <div>
                <small>即将到期</small
                ><strong>{{ expiringSites.length }}</strong
                ><span>证书 30 天内到期或已过期</span>
              </div>
            </article>
          </div>
          <section class="panel-card site-list-card">
            <div class="site-list-toolbar">
              <h2>站点列表</h2>
              <div class="site-list-filters">
                <el-input v-model="query" placeholder="输入域名或者备注搜索..." aria-label="搜索网站" clearable :prefix-icon="Search" />
                <el-select v-model="siteStatusFilter" aria-label="网站状态筛选" @change="sitePage = 1"><el-option label="全部状态" value="all"/><el-option label="运行中" value="running"/><el-option label="未运行" value="stopped"/></el-select>
                <el-select v-model="sitePHPFilter" aria-label="PHP 版本筛选" @change="sitePage = 1"><el-option label="全部 PHP 版本" value="all"/><el-option label="静态站点" value="static"/><el-option v-for="id in sitePHPOptions" :key="id" :label="id.replace('php-', 'PHP ')" :value="id"/></el-select>
                <el-button type="primary" @click="sitePage = 1">搜索</el-button>
                <el-button @click="query = ''; siteStatusFilter = 'all'; sitePHPFilter = 'all'; sitePage = 1">重置</el-button>
              </div>
            </div>
            <div class="site-table-scroll"><table class="site-table">
              <thead><tr><th class="site-check"><input type="checkbox" :checked="!!pagedSites.length && pagedSites.every(site => selectedSiteIDs.includes(site.id))" aria-label="选择当前页网站" @change="selectVisibleSites(($event.target as HTMLInputElement).checked)" /></th><th>#</th><th>域名</th><th>根目录</th><th>PHP 版本</th><th>SSL 证书</th><th>状态</th><th>到期时间</th><th>流量（今日）</th><th>备注</th><th>操作</th></tr></thead>
              <tbody>
                <tr v-for="(row, index) in pagedSites" :key="row.id">
                  <td class="site-check"><input v-model="selectedSiteIDs" type="checkbox" :value="row.id" :aria-label="`选择 ${row.domain}`" /></td>
                  <td>{{ (sitePage - 1) * sitePageSize + index + 1 }}</td>
                  <td><a class="site-domain" :href="siteURL(row)" :title="`打开 ${siteURL(row)}`" target="_blank" rel="noopener noreferrer">{{ row.domain }}</a></td>
                  <td><span class="site-path" :title="`/srv/panel/sites/${row.id}/public`">/srv/panel/sites/{{ row.id }}/public</span></td>
                  <td>{{ row.php_version_id ? row.php_version_id.replace('php-', '') : '静态' }}</td>
                  <td><span :class="siteTLSState(row).kind">● {{ siteTLSState(row).label }}</span></td>
                  <td><span :class="row.status === 'running' ? 'site-ok' : 'site-warn'">● {{ label(row.status) }}</span></td>
                  <td>{{ siteDate(siteExpiry(row)) }}</td>
                  <td>{{ siteTodayBytes(row) }}</td><td>{{ row.name }}</td>
                  <td class="site-row-actions"><button @click="openSiteSettings(row.id)" :disabled="row.status === 'provisioning' || siteBusy(row)">管理</button><i></i><button @click="openSiteBackup(row.id)" :disabled="row.status === 'provisioning' || row.status === 'needs_attention' || siteBusy(row)">备份</button><i></i>
                    <el-dropdown trigger="click" :disabled="siteBusy(row) || ['provisioning', 'needs_attention'].includes(row.status)" @command="(command: string) => siteCommand(row, command)"><button class="site-more">更多⌄</button><template #dropdown><el-dropdown-menu><el-dropdown-item command="waf">网站防护 WAF</el-dropdown-item><el-dropdown-item command="files">文件</el-dropdown-item><el-dropdown-item command="config">查看配置</el-dropdown-item><el-dropdown-item command="php">PHP 版本</el-dropdown-item><el-dropdown-item command="toggle">{{ row.status === 'running' ? '停用' : '启用' }}</el-dropdown-item><el-dropdown-item command="archive">归档网站</el-dropdown-item></el-dropdown-menu></template></el-dropdown>
                  </td>
                </tr>
                <tr v-if="!pagedSites.length"><td colspan="11" class="site-table-empty">{{ sites.length ? '没有符合筛选条件的站点' : '还没有网站，点击右上角“添加站点”开始。' }}</td></tr>
              </tbody>
            </table></div>
            <div class="site-list-footer"><span>共 {{ filteredSites.length }} 条记录，每页 {{ sitePageSize }} 条</span><el-pagination v-model:current-page="sitePage" v-model:page-size="sitePageSize" :total="filteredSites.length" :page-sizes="[8, 10, 20]" layout="prev, pager, next, sizes" background /></div>
          </section>
          <div class="site-bottom-grid">
            <section class="panel-card site-traffic-chart">
              <div class="site-bottom-heading"><h2>近7日网站流量趋势</h2><div v-if="sites.length" class="site-chart-legend"><span><i class="green-dot"></i>总流量</span><span><i class="blue-dot"></i>请求次数（万次）</span></div></div>
              <div class="site-chart-shell" @mouseleave="siteTrafficFocus = null">
                <div v-if="!sites.length" class="site-chart-empty">添加站点后，这里会显示最近七天的真实访问流量。</div>
                <div v-else class="site-chart-unit">流量（{{ siteTrafficUnit.label }}）{{ siteTraffic?.partial ? ' · 部分日志' : '' }}</div>
                <div v-if="focusedTrafficDay" class="site-chart-tooltip" :style="{ left: `${Math.min(79, Math.max(12, (42 + siteTrafficFocus! * 91) / 620 * 100))}%` }" role="status">
                  <strong>{{ focusedTrafficDay.date }}</strong>
                  <span><i class="green-dot"></i>流量：{{ siteTrafficAmount(focusedTrafficDay.bytes) }}</span>
                  <span><i class="blue-dot"></i>请求：{{ focusedTrafficDay.requests.toLocaleString('zh-CN') }} 次</span>
                </div>
                <svg v-if="sites.length" viewBox="0 0 620 164" role="img" aria-label="最近七天的流量与请求趋势" preserveAspectRatio="none">
                  <defs><linearGradient id="siteTrafficFill" x1="0" x2="0" y1="0" y2="1"><stop offset="0%" stop-color="#0ca956" stop-opacity=".18"/><stop offset="100%" stop-color="#0ca956" stop-opacity=".01"/></linearGradient><linearGradient id="siteRequestsFill" x1="0" x2="0" y1="0" y2="1"><stop offset="0%" stop-color="#1674e8" stop-opacity=".13"/><stop offset="100%" stop-color="#1674e8" stop-opacity=".01"/></linearGradient></defs>
                  <path v-for="y in [33, 58, 83, 108, 133]" :key="y" :d="`M42 ${y} H590`" stroke="#e5edf6" stroke-width="1"/>
                  <path v-for="x in [42, 133, 224, 315, 406, 497, 588]" :key="x" :d="`M${x} 33 V133`" stroke="#eaf0f7" stroke-width="1"/>
                  <text v-for="(fraction, index) in [1, 0.75, 0.5, 0.25, 0]" :key="`axis-${index}`" x="36" :y="36 + index * 25" text-anchor="end">{{ siteTrafficTick(fraction) }}</text>
                  <polygon v-if="siteTrafficDays.length" :points="`42,133 ${siteTrafficLine('bytes')} 588,133`" fill="url(#siteTrafficFill)"/>
                  <polygon v-if="siteTrafficDays.length" :points="`42,133 ${siteTrafficLine('requests')} 588,133`" fill="url(#siteRequestsFill)"/>
                  <polyline v-if="siteTrafficDays.length" :points="siteTrafficLine('bytes')" fill="none" stroke="#08a856" stroke-width="3"/>
                  <polyline v-if="siteTrafficDays.length" :points="siteTrafficLine('requests')" fill="none" stroke="#1975e8" stroke-width="1.5" stroke-dasharray="5 3"/>
                  <line v-if="siteTrafficFocus !== null && focusedTrafficDay" :x1="42 + siteTrafficFocus * 91" y1="25" :x2="42 + siteTrafficFocus * 91" y2="133" stroke="#8fa7bd" stroke-dasharray="3 3" />
                  <circle v-if="siteTrafficFocus !== null && focusedTrafficDay" :cx="42 + siteTrafficFocus * 91" :cy="siteTrafficY('bytes', siteTrafficFocus)" r="4" fill="#08a856" stroke="white" stroke-width="2" />
                  <circle v-if="siteTrafficFocus !== null && focusedTrafficDay" :cx="42 + siteTrafficFocus * 91" :cy="siteTrafficY('requests', siteTrafficFocus)" r="4" fill="#1975e8" stroke="white" stroke-width="2" />
                  <text v-for="(day, index) in siteTrafficDays" :key="day.date" :x="42 + index * 91" y="157" text-anchor="middle">{{ day.date.slice(5) }}</text>
                  <rect v-for="(day, index) in siteTrafficDays" :key="`hit-${day.date}`" :x="index === 0 ? 24 : 42 + index * 91 - 45" y="22" :width="index === 0 || index === siteTrafficDays.length - 1 ? 63 : 91" height="114" fill="transparent" tabindex="0" role="button" :aria-label="`${day.date} 流量 ${siteTrafficAmount(day.bytes)}，请求 ${day.requests} 次`" @mouseenter="siteTrafficFocus = index" @focus="siteTrafficFocus = index" @click="siteTrafficFocus = index" @blur="siteTrafficFocus = null" />
                </svg>
              </div>
            </section>
            <section class="panel-card site-expiry-card">
              <div class="site-bottom-heading"><h2>近期到期提醒</h2><button class="text-link" @click="go('certificates')">查看更多 <el-icon><ArrowRight /></el-icon></button></div>
              <div v-if="siteReminders.length" class="site-expiry-list"><div v-for="(reminder, index) in siteReminders" :key="`${reminder.title}-${index}`"><span :class="['site-reminder-mark', reminder.severity]">!</span><span>域名 {{ reminder.title }} 的 {{ reminder.detail }}</span><time>{{ reminder.date }}</time></div></div>
              <div v-else class="site-expiry-empty">暂无证书到期或未部署提醒</div>
            </section>
          </div>
        </template>
        <template v-if="view === 'runtimes'">
          <PHPExtensionManager
            ref="extensionManager"
            :api="api"
            :on-job="lifecycleJob"
            :busy="runtimeBusy"
          />
          <RuntimeLifecycleManager
            ref="lifecycleManager"
            :api="api"
            :on-job="lifecycleJob"
            :retired="runtimes.retired || []"
            :busy="runtimeBusy"
          />
          <div class="store-layout">
            <div class="store-main panel-card">
              <div class="store-toolbar">
                <div class="store-search">
                  <el-icon><Search /></el-icon
                  ><input v-model="storeSearch" aria-label="搜索软件" placeholder="搜索软件名称、描述或关键字..." />
                </div>
                <select v-model="storeCategory" aria-label="软件分类筛选"><option v-for="category in storeCategories" :key="category.id" :value="category.id">{{ category.label }}</option></select>
                <select v-model="storeStatus" aria-label="软件状态筛选"><option value="all">所有状态</option><option value="installed">已安装</option><option value="updates">可更新 ({{ registryUpdates }})</option><option value="installable">可安装</option><option value="unavailable">待适配</option></select>
                <select v-model="storeSort" aria-label="软件排序"><option value="recommended">综合排序</option><option value="name">名称排序</option><option value="installed">已安装优先</option></select>
              </div>
              <div v-if="appRegistry.catalog.apps.length" class="app-registry-source">
                <span>云栈官方 GitHub 应用仓库</span>
                <el-tag size="small" :type="appRegistry.source.stale ? 'warning' : 'success'">{{ appRegistry.source.stale ? '已验签缓存' : 'Ed25519 已验签' }}</el-tag>
                <small>{{ appRegistry.catalog.apps.length }} 个应用 · {{ registryUpdates }} 个有新版 · 仅安装或更新时拉取应用包</small>
                <small v-if="appRegistry.host">{{ appRegistry.host.platform || '未支持的系统' }} / {{ appRegistry.host.architecture }}</small>
                <small v-if="appRegistry.source.fetched_at">目录检查：{{ formatPanelDateTime(appRegistry.source.fetched_at) }}</small>
                <el-button size="small" :loading="registryChecking" @click="checkRegistryUpdates">检查更新</el-button>
              </div>
              <el-alert v-if="appRegistry.source.stale" type="warning" :closable="false" :title="appRegistry.catalog.apps.length ? '未能确认仓库最新版本，当前显示已验签缓存' : '无法连接应用仓库，尚未加载签名目录'" :description="appRegistry.source.error" />
              <div v-if="!appRegistry.catalog.apps.length && softwareApps.catalog.length" class="software-fallback-notice">
                <el-alert type="warning" :closable="false" title="仓库目录尚未加载：当前仅提供本机已审核的应用管理与安装，尚未确认在线版本。" />
                <el-button size="small" :loading="registryChecking" @click="checkRegistryUpdates">重新加载仓库</el-button>
              </div>
              <div class="runtime-grid">
                <article v-for="app in filteredRegistryApps" :key="'registry-' + app.id" class="panel-card runtime-card registry-runtime-card">
                  <div class="runtime-card-head">
                    <SoftwareLogo :family="app.id.startsWith('php-') ? 'php' : app.id" />
                    <div class="runtime-product"><h2>{{ app.name }}</h2><span>v{{ app.version }} · {{ app.category === 'deployment' ? '部署软件' : '专业功能' }}</span></div>
                    <el-tag
                      disable-transitions
                      :type="registryStatus(app.id)?.installed ? (registryStatus(app.id)?.healthy ? 'success' : 'warning') : app.stage === 'ready' ? 'info' : app.stage === 'integration' ? 'warning' : 'info'"
                      size="small"
                    >{{ registryStatus(app.id)?.state_known === false ? '状态待核对' : registryStatus(app.id)?.installed ? (registryStatus(app.id)?.healthy ? '已安装' : '待核对') : registryStatus(app.id)?.supported === false && app.stage === 'ready' ? '当前机器不支持' : app.stage === 'ready' ? '可安装' : app.stage === 'integration' ? '接入中' : '实现中' }}</el-tag>
                  </div>
                  <div v-if="registryStatus(app.id)?.installed" class="registry-version-line"><span>已安装 {{ registryStatus(app.id)?.installed_version || '版本待核对' }} → 仓库 {{ app.version }}</span><el-tag v-if="registryStatus(app.id)?.update_available" size="small" type="warning">有新版</el-tag></div>
                  <p>{{ app.summary }}</p>
                  <div class="runtime-card-tags"><span v-for="tag in app.capabilities.slice(0, 3)" :key="tag">{{ tag }}</span></div>
                  <div class="registry-card-actions">
                  <el-button
                    class="runtime-install-button"
                    :type="app.stage === 'ready' ? 'primary' : 'default'"
                    :disabled="app.stage !== 'ready' || registryStatus(app.id)?.state_known === false || (!registryStatus(app.id)?.installed && registryStatus(app.id)?.supported === false) || registryInstalling.includes(app.id)"
                    @click="installRegistryApp(app)"
                  >{{ registryStatus(app.id)?.state_known === false ? '状态待核对' : registryInstalling.includes(app.id) ? '验签与提交中' : registryStatus(app.id)?.installed ? '打开管理' : registryStatus(app.id)?.supported === false && app.stage === 'ready' ? '当前机器不支持' : app.stage === 'ready' ? '安装' : app.stage === 'integration' ? '接入中' : '实现中' }}</el-button>
                  <el-button v-if="registryStatus(app.id)?.update_available" class="registry-update-button" type="warning" :disabled="registryInstalling.includes(app.id) || appRegistry.source.stale" @click="registryStatus(app.id)?.update_supported ? updateRegistryApp(app) : (registryStatus(app.id)?.update_kind === 'compose-review' ? openRegistryApp(app) : ElMessage.warning(registryStatus(app.id)?.update_detail || '请先升级面板'))">{{ registryStatus(app.id)?.update_supported ? '更新应用' : registryStatus(app.id)?.update_kind === 'compose-review' ? '核对容器更新' : '需升级面板' }}</el-button>
                  </div>
                  <div class="runtime-note">
                    {{ app.provider === 'runtime' ? '受审核运行时' : app.provider === 'compose' ? '受限 Compose 应用' : '面板功能模块' }} · {{ app.risk === 'eol' ? '已停止维护，仅限隔离兼容迁移' : app.risk === 'privileged' ? '涉及系统权限' : 'SHA-256 固定包' }}<br />
                    {{ registryStatus(app.id)?.detail || '等待状态检查' }}
                    <template v-if="registryStatus(app.id)?.update_detail"><br />{{ registryStatus(app.id)?.update_detail }}</template>
                    <template v-if="registryStatus(app.id)?.compatibility_detail"><br />{{ registryStatus(app.id)?.compatibility_detail }}</template>
                  </div>
                </article>
                <article
                  v-for="rt in filteredCatalog"
                  :key="rt.family"
                  class="panel-card runtime-card"
                >
                  <div class="runtime-card-head">
                    <SoftwareLogo :family="rt.family" />
                    <div class="runtime-product">
                      <h2>{{ rt.name }}</h2>
                      <el-select
                        v-model="versions[rt.family]"
                        class="runtime-version-select"
                        :id="'version-' + rt.family"
                        :aria-label="rt.name + ' 版本'"
                      >
                        <template v-if="rt.releases"><el-option v-for="v in rt.releases" :key="v.id" :value="v.id" :label="v.version + ' · ' + ({ security: '安全维护', active: '常规维护', stable: 'Stable', mainline: 'Mainline', eol: '维护已结束 · 兼容迁移', lts: 'LTS', maintenance: '维护版本' }[v.channel] || v.channel)" /></template>
                        <template v-else><el-option v-for="v in rt.versions" :key="v" :value="v" :label="v" /></template>
                      </el-select>
                    </div>
                    <el-tag disable-transitions :type="runtimeInstalled(versions[rt.family] || '') ? 'success' : 'info'" size="small">{{
                      runtimeInstalled(versions[rt.family] || '') ? '已安装' : rt.state === "available" ? "可安装" : "待适配"
                    }}</el-tag>
                  </div>
                  <p>{{ rt.description }}</p>
                  <div class="runtime-card-tags"><span v-for="tag in runtimeCardTags[rt.family] || []" :key="tag">{{ tag }}</span></div>
                  <template v-if="rt.state === 'available'">
                    <el-button
                      v-if="
                        rt.family === 'docker' &&
                        runtimeInstalled(versions[rt.family] || '')
                      "
                      class="runtime-install-button"
                      type="primary"
                      @click="dockerManager?.open()"
                      >打开管理</el-button
                    >
                    <el-button
                      v-else-if="
                        rt.family === 'redis' &&
                        runtimeInstalled(versions[rt.family] || '')
                      "
                      class="runtime-install-button"
                      type="primary"
                      @click="redisManager?.open()"
                      >实例管理</el-button
                    >
                    <el-button
                      v-else-if="
                        rt.family === 'node' &&
                        runtimeInstalled(versions[rt.family] || '')
                      "
                      class="runtime-install-button"
                      type="primary"
                      @click="nodeManager?.open()"
                      >项目管理</el-button
                    >
                    <el-button
                      v-else-if="
                        rt.family === 'mariadb' &&
                        runtimeInstalled(versions[rt.family] || '')
                      "
                      class="runtime-install-button"
                      type="primary"
                      @click="mariadbManager?.open()"
                      >实例管理</el-button
                    >
                    <div v-else class="runtime-card-actions">
                      <el-button v-if="runtimeInstalled(versions[rt.family] || '')" @click="openRuntimeSettings(rt.family, versions[rt.family])">设置</el-button>
                      <el-button
                        type="primary"
                        :disabled="runtimeBusy(versions[rt.family] || '')"
                        @click="runtimeInstalled(versions[rt.family] || '') ? openVersionManager(rt.family) : installRuntime(rt.family)"
                      >{{ runtimeBusy(versions[rt.family] || '') ? '安装中' : runtimeInstalled(versions[rt.family] || '') ? '版本管理' : '安装' }}</el-button>
                    </div>
                    <div class="runtime-note">
                      {{
                        rt.family === "docker"
                          ? "Debian 签名仓库 · 固定 Engine 与 Compose 版本"
                          : rt.family === "mysql"
                            ? "官方二进制 · PGP 与 SHA-256 校验"
                            : rt.family === "mariadb"
                              ? "MariaDB Foundation 官方 x86_64 二进制 · SHA-256 校验"
                              : rt.family === "node"
                                ? "官方二进制 · 官方 SHA-256 清单"
                                : rt.family === "apache"
                                  ? "Apache 官方源码 · 官方 SHA-256 清单"
                                  : "官方源码 · SHA-256 校验"
                      }}<br />{{
                        rt.family === "php"
                          ? "CLI、FPM 与常用扩展一并构建"
                          : rt.family === "mysql"
                            ? "安装程序后，在数据库页面创建独立实例"
                            : rt.family === "mariadb"
                              ? "11.4 与 11.8 LTS 可在独立目录中并存"
                              : rt.family === "docker"
                                ? "安装后在此页管理容器、镜像和 Compose 项目"
                                : rt.family === "redis"
                                  ? "服务端与客户端共存，下一步创建独立实例"
                                  : rt.family === "node"
                                    ? "node 与 npm 随精确版本独立共存"
                                    : rt.family === "apache"
                                      ? "独立安装，不替换当前 Nginx 全局入口"
                                      : "独立安装，入口切换将单独验证"
                      }}
                    </div>
                  </template>
                  <div v-else class="runtime-note">
                    实际安装与兼容性验证将按版本逐项接入。
                  </div>
                </article>
                <article v-if="showPanelRuntime" class="panel-card runtime-card panel-runtime-card">
                  <div class="runtime-card-head">
                    <span class="software-icon panel-icon"
                      ><el-icon><DataBoard /></el-icon
                    ></span>
                    <div class="runtime-product">
                      <h2>云栈面板</h2>
                      <span>{{ panelVersion }}</span>
                    </div>
                    <el-tag disable-transitions type="success" size="small"
                      >已安装</el-tag
                    >
                  </div>
                  <p>服务器运维控制面板，统一管理网站、数据库与系统服务。</p>
                  <label>当前版本</label>
                  <div class="panel-version">{{ panelVersion }} · 当前版本</div>
                  <el-button
                    class="runtime-install-button"
                    type="primary"
                    @click="go('overview')"
                    >打开面板</el-button
                  >
                  <div class="runtime-note">
                    运维工具 · 服务器管理<br />当前控制台已连接实际 Linux
                    执行服务
                  </div>
                </article>
                <article v-for="app in filteredSoftwareApps" :key="app.id" class="panel-card runtime-card security-runtime-card">
                  <div class="runtime-card-head">
                    <SoftwareLogo :family="app.family" />
                    <div class="runtime-product"><h2>{{ app.name }}</h2><span>v{{ app.version }} · {{ app.source }}</span></div>
                    <el-tag disable-transitions :type="softwareStatus(app.id)?.installed ? (softwareStatus(app.id)?.healthy ? 'success' : 'warning') : 'info'" size="small">{{ softwareStatus(app.id)?.installed ? (softwareStatus(app.id)?.healthy ? '已安装' : '待核对') : '可安装' }}</el-tag>
                  </div>
                  <p>{{ app.description }}</p>
                  <div class="runtime-card-tags"><span v-for="tag in runtimeCardTags[app.family] || app.capabilities.slice(0, 3)" :key="tag">{{ tag }}</span></div>
                  <div class="runtime-card-actions">
                    <el-button v-if="softwareStatus(app.id)?.installed" @click="openSoftwareApp(app)">设置</el-button>
                    <el-button type="primary" :disabled="runtimeBusy(app.id)" @click="softwareStatus(app.id)?.installed ? openSoftwareApp(app) : installSoftwareApp(app)">{{ runtimeBusy(app.id) ? '执行中' : softwareStatus(app.id)?.installed ? '打开管理' : '安装' }}</el-button>
                  </div>
                </article>
                <article v-for="app in filteredBuiltInApps" :key="app.id" class="panel-card runtime-card built-in-runtime-card">
                  <div class="runtime-card-head">
                    <SoftwareLogo :family="app.family" />
                    <div class="runtime-product"><h2>{{ app.name }}</h2><span>{{ app.templateId ? 'Docker 应用模板' : '面板原生模块' }}</span></div>
                    <el-tag disable-transitions :type="app.templateId ? 'info' : 'success'" size="small">{{ app.templateId ? '可创建实例' : '已内置' }}</el-tag>
                  </div>
                  <p>{{ app.description }}</p>
                  <div class="runtime-card-tags"><span v-for="tag in app.tags" :key="tag">{{ tag }}</span></div>
                  <el-button class="runtime-install-button" type="primary" @click="openBuiltInStoreApp(app)">{{ app.templateId ? '创建 Docker 实例' : '打开管理' }}</el-button>
                  <div class="runtime-note">{{ app.templateId ? '固定镜像版本 · 回环端口 · 受管 Compose 生命周期' : '不重复安装同类 Web 工具；直接使用面板已验证的原生功能' }}</div>
                </article>
                <el-empty v-if="!filteredRegistryApps.length && !filteredCatalog.length && !filteredBuiltInApps.length && !filteredSoftwareApps.length && !showPanelRuntime" class="store-filter-empty" description="当前筛选条件下没有软件" :image-size="56" />
              </div>
            </div>
            <aside class="store-side">
              <section class="panel-card store-queue">
                <div class="store-side-title">
                  <h3>
                    安装队列（{{
                      jobs.filter(
                        (j) =>
                          isStoreInstallJob(j) &&
                          ["queued", "running"].includes(j.state),
                      ).length
                    }}）
                  </h3>
                  <button @click="go('jobs')">全部任务 ›</button>
                </div>
                <div
                  v-for="job in jobs
                    .filter(
                      (j) =>
                        isStoreInstallJob(j) &&
                        ['queued', 'running'].includes(j.state),
                    )
                    .slice(0, 2)"
                  :key="job.id"
                  class="queue-item"
                >
                  <SoftwareLogo :family="job.target_id" />
                  <div>
                    <strong>{{ jobTarget(job) }}</strong
                    ><small
                      >{{ label(job.state) }} ·
                      {{ job.steps?.at(-1)?.message || "等待执行" }}</small
                    >
                  </div>
                </div>
                <div
                  v-if="
                    !jobs.some(
                      (j) =>
                        isStoreInstallJob(j) &&
                        ['queued', 'running'].includes(j.state),
                    )
                  "
                  class="store-empty"
                >
                  当前没有安装任务
                </div>
              </section>
              <section class="panel-card store-bundles">
                <div class="store-side-title">
                  <h3>常用组合推荐</h3>
                  <span>查看更多 ›</span>
                </div>
                <div class="bundle-item">
                  <SoftwareLogo family="nginx" />
                  <div>
                    <strong>LNMP</strong><small>Nginx + PHP + MySQL</small>
                  </div>
                  <button
                    @click="installBundle('LNMP', ['nginx', 'php', 'mysql'])"
                  >
                    一键安装
                  </button>
                </div>
                <div class="bundle-item">
                  <SoftwareLogo family="apache" />
                  <div>
                    <strong>LAMP</strong><small>Apache + PHP + MySQL</small>
                  </div>
                  <button
                    @click="installBundle('LAMP', ['apache', 'php', 'mysql'])"
                  >
                    一键安装
                  </button>
                </div>
                <div class="bundle-item">
                  <SoftwareLogo family="docker" />
                  <div>
                    <strong>Docker 环境</strong><small>Docker + Compose</small>
                  </div>
                  <button
                    @click="
                      runtimeInstalled(versions.docker)
                        ? dockerManager?.open()
                        : installBundle('Docker 环境', ['docker'])
                    "
                  >
                    {{
                      runtimeInstalled(versions.docker)
                        ? "打开管理"
                        : "一键安装"
                    }}
                  </button>
                </div>
                <div class="bundle-item">
                  <SoftwareLogo family="wordpress" />
                  <div>
                    <strong>博客系统</strong
                    ><small>WordPress + 独立 MariaDB 容器</small>
                  </div>
                  <button
                    @click="
                      runtimeInstalled(versions.docker)
                        ? dockerManager?.openTemplate('wordpress-blog')
                        : installBundle('Docker 环境', ['docker'])
                    "
                  >
                    {{ runtimeInstalled(versions.docker) ? '部署应用' : '安装 Docker' }}
                  </button>
                </div>
                <div class="bundle-item">
                  <SoftwareLogo family="node" />
                  <div>
                    <strong>Node.js 开发环境</strong
                    ><small>Node.js + Nginx</small>
                  </div>
                  <button
                    @click="
                      runtimeInstalled(versions.node)
                        ? nodeManager?.open()
                        : installBundle('Node.js 开发环境', ['node', 'nginx'])
                    "
                  >
                    {{
                      runtimeInstalled(versions.node) ? "打开管理" : "一键安装"
                    }}
                  </button>
                </div>
              </section>
            </aside>
          </div>
          <DockerManager ref="dockerManager" :api="api" />
          <SecurityAppManager ref="softwareManager" :api="api" :on-job="lifecycleJob" :on-install="queueSoftwareInstall" />
          <el-dialog v-model="versionManagerOpen" :title="`${versionManagerRuntime?.name || '软件'} · 版本管理`" width="500px">
            <p class="runtime-version-help">精确版本独立安装并存；安装后可在对应网站或数据库设置中切换，现有绑定保持不变。</p>
            <el-select v-model="versionManagerSelection" style="width: 100%" aria-label="选择另一软件版本" placeholder="当前目录中没有待安装版本">
              <el-option v-for="item in versionManagerRuntime?.releases || []" :key="item.id" :value="item.id" :label="`${item.version} · ${runtimeInstalled(item.id) ? '已安装' : item.channel}`" :disabled="runtimeInstalled(item.id)" />
            </el-select>
            <template #footer><el-button @click="versionManagerOpen = false">关闭</el-button><el-button type="primary" :disabled="!versionManagerSelection" @click="installSelectedVersion">安装所选版本</el-button></template>
          </el-dialog>
          <RedisManager
            ref="redisManager"
            :api="api"
            :installed="runtimes.installed"
          />
          <MariaDBManager
            ref="mariadbManager"
            :api="api"
            :csrf="csrf"
            :installed="runtimes.installed"
          />
          <NodeManager
            ref="nodeManager"
            :api="api"
            :installed="runtimes.installed"
            :sites="sites"
          />
          <section class="panel-card store-ranking">
            <h3>热门软件排行</h3>
            <div>
              <span><b>1</b>Nginx</span><span><b>2</b>MySQL</span
              ><span><b>3</b>Redis</span><span><b>4</b>PHP</span
              ><span><b>5</b>Docker</span>
            </div>
          </section>
          <details class="panel-card installed-section">
            <summary>
              <span
                ><strong>已安装软件</strong
                ><small>核对真实程序、版本和构建模块</small></span
              ><span>{{ runtimes.installed.length }} 个精确版本 ›</span>
            </summary>
            <section class="installed-runtime-list">
              <div class="card-heading">
                <div>
                  <h2>已安装环境</h2>
                  <p>从虚拟机中读取的实际版本</p>
                </div>
                <el-tag disable-transitions type="success"
                  >已连接执行服务</el-tag
                >
              </div>
              <div
                v-for="rt in runtimes.installed"
                :key="rt.id"
                class="installed-runtime"
                :data-release="rt.id"
              >
                <SoftwareLogo :family="rt.family" />
                <div class="installed-main">
                  <strong
                    >{{
                      rt.family === "php"
                        ? "PHP "
                        : rt.family === "mysql"
                          ? "MySQL "
                          : rt.family === "mariadb"
                            ? "MariaDB "
                            : rt.family === "redis"
                              ? "Redis "
                              : rt.family === "node"
                                ? "Node.js "
                                : rt.family === "apache"
                                  ? "Apache "
                                  : ""
                    }}{{ rt.version }}</strong
                  ><small>{{ rt.source }} · {{ rt.binary }}</small>
                  <details
                    v-if="rt.extensions?.length"
                    class="runtime-extensions"
                  >
                    <summary>
                      {{ rt.extensions.length }} 个已编译扩展 / 模块
                    </summary>
                    <small>{{ rt.extensions.join(" · ") }}</small>
                  </details>
                </div>
                <el-tag
                  disable-transitions
                  :type="rt.status === 'needs_attention' ? 'danger' : 'success'"
                  >{{
                    rt.status === "needs_attention"
                      ? "需核对"
                      : rt.id === runtimes.active_nginx
                        ? "当前入口"
                        : "已安装并核对"
                  }}</el-tag
                >
                <el-button
                  v-if="
                    rt.family === 'nginx' && rt.id !== runtimes.active_nginx
                  "
                  size="small"
                  :disabled="
                    jobs.some(
                      (j) =>
                        j.kind === 'switch_nginx' &&
                        ['queued', 'running'].includes(j.state),
                    )
                  "
                  @click="activateNginx(rt.id)"
                  >设为入口</el-button
                >
                <el-button
                  v-if="rt.family === 'php'"
                  size="small"
                  :disabled="rt.status !== 'installed'"
                  @click="extensionManager?.inspect(rt.id)"
                  >独立扩展</el-button
                >
                <el-button
                  v-if="rt.family === 'redis'"
                  size="small"
                  @click="redisManager?.open()"
                  >实例管理</el-button
                >
                <el-button
                  v-if="rt.family === 'node'"
                  size="small"
                  @click="nodeManager?.open()"
                  >项目管理</el-button
                >
                <el-button
                  v-if="rt.family === 'mariadb'"
                  size="small"
                  @click="mariadbManager?.open()"
                  >实例管理</el-button
                >
                <div class="lifecycle-actions">
                  <el-button
                    size="small"
                    @click="lifecycleManager?.inspect(rt.id)"
                    >引用</el-button
                  ><el-button
                    v-if="rt.id !== 'nginx-system' && rt.family !== 'docker'"
                    size="small"
                    type="warning"
                    plain
                    :disabled="runtimeBusy(rt.id)"
                    @click="lifecycleManager?.retire(rt.id)"
                    >卸载</el-button
                  >
                </div>
              </div>
            </section>
          </details>
        </template>
        <SiteSettingsManager
          v-model="settingsOpen"
          :site-id="settingsSiteID"
          :initial-tab="settingsInitialTab"
          :api="api"
          :on-job="revealJob"
        />
        <BatchSSLManager
          v-model:visible="batchSSLOpen"
          v-model="selectedSiteIDs"
          :sites="sites"
          :api="api"
          :on-submitted="refresh"
        />
        <FileManager
          v-if="view === 'files'"
          ref="fileManager"
          :api="api"
          :sites="sites"
          :csrf="csrf"
          :initialSiteID="fileSiteID"
          :access="accessPlan"
        />
        <DatabaseManager
          v-if="view === 'databases'"
          ref="databaseManager"
          :api="api"
          :csrf="csrf"
          :installed="runtimes.installed"
          :on-job="revealJob"
          :open-redis="(id?: string, db?: number) => redisManager?.open(id, db)"
        />
        <RedisManager
          v-if="view === 'databases'"
          ref="redisManager"
          :api="api"
          :installed="runtimes.installed"
          @changed="databaseManager?.refresh()"
        />
        <MonitoringManager
          v-if="view === 'monitor'"
          ref="monitoringManager"
          :api="api"
        />
        <ScheduleManager
          v-if="view === 'schedules'"
          ref="scheduleManager"
          :api="api"
        />
        <BackupManager
          v-if="view === 'backups'"
          ref="backupManager"
          :api="api"
          :on-job="revealJob"
          :sites="sites"
        />
        <CertificateManager
          v-if="view === 'certificates'"
          ref="certificateManager"
          :api="api"
          :sites="sites"
          :on-job="revealJob"
        />
        <div v-if="view === 'panel-access'" class="settings-page" :class="{ 'basic-layout': settingsTab === 'basic' }">
          <nav class="panel-card settings-tabs" aria-label="面板设置分类">
            <button
              :class="{ active: settingsTab === 'basic' }"
              @click="settingsTab = 'basic'"
            >
              <el-icon><Setting /></el-icon>基本设置
            </button>
            <button
              :class="{ active: settingsTab === 'account' }"
              @click="settingsTab = 'account'"
            >
              <el-icon><User /></el-icon>管理员账户
            </button>
            <button v-if="canOpenView(accessPlan, 'security')"
              :class="{ active: settingsTab === 'security' }"
              @click="settingsTab = 'security'"
            >
              <el-icon><Lock /></el-icon>安全设置
            </button>
            <button
              :class="{ active: settingsTab === 'notice' }"
              @click="settingsTab = 'notice'"
            >
              <el-icon><Bell /></el-icon>通知设置
            </button>
            <button
              :class="{ active: settingsTab === 'theme' }"
              @click="settingsTab = 'theme'"
            >
              <el-icon><Brush /></el-icon>主题与显示
            </button>
          </nav>
          <template v-if="settingsTab === 'basic'">
            <div class="settings-main-grid">
              <PanelAccessManager
                ref="panelAccessManager"
                :api="api"
                :theme="theme"
                :sidebar-style="sidebarStyle"
                :display-density="displayDensity"
                :on-session="(value) => { user = value.username; csrf = value.csrf; }"
                :on-busy="(value) => (accountChanging = value)"
                @tab="(value) => (settingsTab = value)"
                @theme="setTheme"
                @sidebar-style="setSidebarStyle"
                @display-density="setDisplayDensity"
              />
              <aside class="settings-side-column">
                <section class="panel-card system-info-card">
                  <div class="settings-card-title">
                    <el-icon><DataBoard /></el-icon>
                    <h2>系统信息</h2>
                  </div>
                  <dl>
                    <dt>面板版本</dt>
                    <dd>v{{ panelVersion }}</dd>
                    <dt>操作系统</dt>
                    <dd>{{ overview?.os || "—" }}</dd>
                    <dt>内核版本</dt>
                    <dd>{{ overview?.kernel || "—" }}</dd>
                    <dt>服务器时间</dt>
                    <dd title="来自服务器采样时间，按面板界面时区显示">{{ serverSampleTime }}</dd>
                    <dt>运行时间</dt>
                    <dd>{{ uptime }}</dd>
                    <dt>面板目录</dt>
                    <dd>/opt/panel</dd>
                    <dt>日志查看</dt>
                    <dd>journalctl -u panel</dd>
                  </dl>
                </section>
                <section class="panel-card settings-help-card">
                  <div class="settings-card-title">
                    <el-icon><Connection /></el-icon>
                    <h2>帮助说明</h2>
                  </div>
                  <ol>
                    <li>
                      <b>如何修改面板入口？</b
                      ><span>在基本设置中查看或修改公网 HTTP 安全入口，也可配置 HTTPS 域名和访问网段。</span>
                    </li>
                    <li>
                      <b>忘记管理员密码怎么办？</b
                      ><span>可在本机使用 root 救援命令重置账户密码。</span>
                    </li>
                    <li>
                      <b>如何提高面板安全性？</b
                      ><span>启用双重验证，并定期核对防火墙与 SSH。</span>
                    </li>
                    <li>
                      <b>如何自定义面板域名？</b
                      ><span>上传覆盖域名的证书，在基本设置中预览并保存。</span>
                    </li>
                    <li>
                      <b>如何恢复面板？</b
                      ><span>在系统工具中创建并下载加密整包备份。</span>
                    </li>
                  </ol>
                </section>
              </aside>
            </div>
          </template>
          <div v-else-if="settingsTab === 'account'">
            <section class="panel-card"><el-button type="primary" @click="appModuleManager?.show('user-manager')">面板用户与菜单授权</el-button><p class="muted">管理角色、独立菜单、网站范围与会话撤销。账户授权变更后需要重新登录。</p></section>
          <AccountManager
            ref="accountManager"
            :api="api"
            :on-session="
              (value) => {
                user = value.username;
                csrf = value.csrf;
              }
            "
            :on-busy="(value) => (accountChanging = value)"
          />
          </div>
          <SecurityManager
            v-else-if="settingsTab === 'security'"
            ref="securityManager"
            :api="api"
            @navigate="go"
          />
          <NotificationManager
            v-else-if="settingsTab === 'notice'"
            ref="notificationManager"
            :api="api"
            @updated="refresh"
          />
          <section v-else class="panel-card settings-placeholder theme-settings-card">
            <div class="settings-card-title">
              <el-icon><Brush /></el-icon>
              <h2>主题与显示</h2>
            </div>
            <p>选择浅色或深色主题；当前服务器面板的布局与操作位置保持一致。</p>
            <div class="theme-preview" role="group" aria-label="界面主题">
              <button type="button" :class="{ active: theme === 'light' }" aria-label="浅色主题" :aria-pressed="theme === 'light'" @click="setTheme('light')"><span class="theme-thumb light"></span><strong>浅色主题</strong></button>
              <button type="button" :class="{ active: theme === 'dark' }" aria-label="深色主题" :aria-pressed="theme === 'dark'" @click="setTheme('dark')"><span class="theme-thumb dark"></span><strong>深色主题</strong></button>
            </div>
            <div class="display-options">
              <label>侧边栏样式 <el-select :model-value="sidebarStyle" aria-label="侧边栏样式" @change="setSidebarStyle"><el-option value="default" label="默认样式"/><el-option value="compact" label="紧凑图标栏"/></el-select></label>
              <label>显示密度 <el-select :model-value="displayDensity" aria-label="显示密度" @change="setDisplayDensity"><el-option value="comfortable" label="舒适（推荐）"/><el-option value="compact" label="紧凑"/></el-select></label>
            </div>
            <p class="theme-settings-note">主题保存在当前浏览器中，重新登录后仍会保持。</p>
          </section>
        </div>
        <SecurityManager
          v-if="view === 'security'"
          ref="securityManager"
          :api="api"
          @navigate="go"
        />
        <TerminalManager
          v-if="view === 'terminal'"
          ref="terminalManager"
          :overview="overview"
          :csrf="csrf"
          @open="go"
        />
        <SystemToolsManager v-if="view === 'system-tools'" @open="go" />
        <AccountManager
          ref="accountManager"
          v-if="view === 'account'"
          :api="api"
          :on-session="
            (value) => {
              user = value.username;
              csrf = value.csrf;
            }
          "
          :on-busy="(value) => (accountChanging = value)"
        />
        <section v-if="view === 'jobs'" class="panel-card list-card">
          <div class="table-toolbar">
            <div class="tabs-label">
              执行记录 <span class="count-badge">{{ jobs.length }}</span>
            </div>
            <small class="muted">{{ pending }} 个任务执行中</small>
          </div>
          <el-table :data="jobs" empty-text="暂无任务"
            ><el-table-column label="任务 / 对象" min-width="190"
              ><template #default="{ row }"
                ><strong>{{ jobNames[row.kind] }}</strong
                ><span class="table-secondary">{{
                  jobTarget(row)
                }}</span></template
              ></el-table-column
            ><el-table-column label="状态" width="110"
              ><template #default="{ row }"
                ><el-tag
                  disable-transitions
                  :type="statusType(row.state)"
                  size="small"
                  >{{ label(row.state) }}</el-tag
                ></template
              ></el-table-column
            ><el-table-column label="最近结果" min-width="260"
              ><template #default="{ row }"
                ><span :class="{ 'error-text': row.error }">{{
                  row.error || row.steps?.at(-1)?.message || "等待执行服务处理"
                }}</span></template
              ></el-table-column
            ><el-table-column label="更新时间" min-width="160"
              ><template #default="{ row }">{{
                date(row.updated_at)
              }}</template></el-table-column
            ><el-table-column label="操作" width="155" fixed="right"
              ><template #default="{ row }"
                ><el-button link type="primary" @click="openJob(row)"
                  >详情</el-button
                ><el-button
                  v-if="['failed', 'needs_attention'].includes(row.state)"
                  link
                  type="warning"
                  @click="retry(row)"
                  >核对并重试</el-button
                ></template
              ></el-table-column
            ></el-table
          >
        </section>
        <section v-if="view === 'audit'" class="panel-card list-card">
          <div class="table-toolbar">
            <div class="tabs-label">
              操作审计 <span class="count-badge">{{ audits.length }}</span>
            </div>
            <small class="muted">最近 200 条</small>
          </div>
          <el-table :data="audits" empty-text="暂无记录"
            ><el-table-column
              prop="actor"
              label="操作者"
              width="115"
            /><el-table-column
              prop="action"
              label="操作"
              min-width="150"
            /><el-table-column
              prop="target"
              label="对象"
              min-width="230"
              show-overflow-tooltip
            /><el-table-column label="结果" width="110"
              ><template #default="{ row }"
                ><el-tag
                  disable-transitions
                  :type="statusType(row.result)"
                  size="small"
                  >{{ label(row.result) }}</el-tag
                ></template
              ></el-table-column
            ><el-table-column label="时间" min-width="165"
              ><template #default="{ row }">{{
                date(row.created_at)
              }}</template></el-table-column
            ></el-table
          >
        </section>
        <AppModuleManager ref="appModuleManager" :api="api" :on-job="lifecycleJob" :on-install="queueSoftwareInstall" :registry="appRegistry" :access="accessPlan" />
        <footer class="page-footer">
          <span>自有面板 · 本地开发版</span
          ><span>数据来自实际 Linux 服务 <span class="live-dot"></span></span>
        </footer>
      </div>
    </main>
    <el-dialog
      v-model="createOpen"
      title="创建网站"
      width="480px"
      class="create-dialog"
      :close-on-click-modal="false"
      ><p class="dialog-intro">选择静态站点，或绑定一个已安装的 PHP 版本。</p>
      <form @submit.prevent="create" class="site-form">
        <label for="site-name">网站名称</label
        ><input
          id="site-name"
          v-model="siteName"
          required
          maxlength="60"
          placeholder="例如：我的第一个网站"
        /><label for="site-slug">站点标识</label
        ><input
          id="site-slug"
          v-model="slug"
          required
          pattern="[a-z][a-z0-9-]{2,31}"
          placeholder="例如：my-first-site"
          maxlength="32"
        /><small>3–32 位小写字母、数字或连字符，以字母开头。</small>
        <label for="site-domain">主域名</label>
        <input
          id="site-domain"
          v-model="primaryDomain"
          maxlength="253"
          placeholder="例如：www.example.com；留空使用开发域名"
        />
        <small
          >填写小写完整域名，不含协议、端口和路径。国际域名请使用
          Punycode。</small
        >
        <label>运行环境</label
        ><el-select
          v-model="createPHP"
          :empty-values="[null, undefined]"
          aria-label="网站运行环境"
          ><el-option value="" label="静态站点" /><el-option
            v-for="rt in installedPHP"
            :key="rt.id"
            :value="rt.id"
            :label="'PHP ' + rt.version"
        /></el-select>
        <div class="domain-preview">
          <span>开发访问地址</span
          ><strong
            >http://{{
              primaryDomain.trim() || (slug || "my-first-site") + ".localhost"
            }}:19101</strong
          >
        </div>
        <div class="form-flow">
          <span>生成配置</span><b>→</b><span>语法校验</span><b>→</b
          ><span>访问验证</span>
        </div>
        <div class="dialog-actions">
          <el-button @click="createOpen = false">取消</el-button
          ><el-button type="primary" native-type="submit" :loading="creating"
            >创建网站</el-button
          >
        </div>
      </form></el-dialog
    >
    <el-dialog
      v-model="phpOpen"
      title="网站 PHP 版本"
      width="500px"
      class="create-dialog"
      :close-on-click-modal="false"
    >
      <template v-if="phpTarget"
        ><p class="dialog-intro">
          {{ phpTarget.name }} · {{ phpTarget.domain }}
        </p>
        <p>
          当前环境：{{
            phpTarget.php_version_id?.replace("php-", "PHP ") || "静态站点"
          }}
        </p>
        <el-select
          v-model="phpSelection"
          aria-label="目标 PHP 版本"
          style="width: 100%"
          ><el-option value="" label="静态站点（禁止执行 PHP）" /><el-option
            v-for="rt in installedPHP"
            :key="rt.id"
            :value="rt.id"
            :label="'PHP ' + rt.version"
        /></el-select>
        <p class="muted">
          先验证候选 PHP 进程，再检查 Nginx 配置与实际访问。成功后同步该站点的
          CLI 绑定；失败保留原版本。
        </p>
        <div class="dialog-actions">
          <el-button @click="phpOpen = false">取消</el-button
          ><el-button type="primary" :loading="submittingPHP" @click="switchPHP"
            >验证并切换</el-button
          >
        </div></template
      >
    </el-dialog>
    <el-drawer v-model="jobOpen" title="任务详情" size="520px"
      ><template v-if="selectedJob"
        ><div class="job-detail-heading">
          <h2>{{ jobNames[selectedJob.kind] }}</h2>
          <el-tag disable-transitions :type="statusType(selectedJob.state)">{{
            label(selectedJob.state)
          }}</el-tag>
        </div>
        <p class="muted">{{ jobTarget(selectedJob) }}</p>
        <div class="detail-meta">
          <span>任务 ID</span><code>{{ selectedJob.id }}</code
          ><span>创建时间</span
          ><strong>{{ date(selectedJob.created_at) }}</strong>
        </div>
        <el-alert
          v-if="selectedJob.error"
          :title="selectedJob.error"
          type="error"
          :closable="false"
        />
        <el-button
          v-if="
            ['install_runtime', 'install_php_extension'].includes(
              selectedJob.kind,
            )
          "
          @click="showBuildLog(selectedJob)"
          >查看构建日志</el-button
        >
        <h3 class="step-title">执行步骤</h3>
        <el-timeline
          ><el-timeline-item
            v-for="(step, i) in selectedJob.steps"
            :key="i"
            :timestamp="date(step.time)"
            color="#0f766e"
            >{{ step.message }}</el-timeline-item
          ><el-timeline-item v-if="!selectedJob.steps.length" type="info">{{
            selectedJob.state === "running"
              ? "执行服务正在处理，结果会自动更新。"
              : "任务已持久化，等待执行。"
          }}</el-timeline-item></el-timeline
        ><el-button
          v-if="['failed', 'needs_attention'].includes(selectedJob.state)"
          type="primary"
          @click="retry(selectedJob)"
          >核对已有资源并重试</el-button
        ></template
      ></el-drawer
    >
    <el-drawer
      v-model="buildLogOpen"
      title="构建日志 · 最近 48 KB"
      size="760px"
    >
      <pre class="code-block">{{ buildLog }}</pre>
    </el-drawer>
    <el-drawer v-model="configOpen" title="Nginx 站点配置" size="620px"
      ><p class="code-path">{{ siteConfig.path }}</p>
      <pre class="code-block">{{ siteConfig.content }}</pre>
      <p class="muted">这是执行服务读取的实际配置文件。</p></el-drawer
    >
  </div>
</template>

<style>
.store-main .runtime-grid .runtime-card.registry-runtime-card {
  height: auto;
  min-height: 260px;
  padding: 12px 16px;
  display: flex;
  flex-direction: column;
}
.registry-runtime-card .runtime-product { flex: 1; overflow-wrap: anywhere; }
.registry-version-line { display: flex; flex-wrap: wrap; gap: 6px; align-items: center; margin-top: 8px; font-size: 12px; color: var(--muted, #64799a); }
.registry-card-actions { display: flex; flex-wrap: wrap; justify-content: flex-end; gap: 6px; margin-top: 8px; }
.store-main .registry-runtime-card .registry-card-actions .el-button { margin: 0; float: none; }
.store-main .runtime-grid .registry-runtime-card .runtime-note { display: block; margin-top: 10px; font-size: 12px; line-height: 1.5; overflow-wrap: anywhere; }
.lifecycle-actions {
  display: flex;
  gap: 6px;
}
.lifecycle-actions .el-button {
  margin: 0;
}
.installed-runtime {
  flex-wrap: wrap;
}
.installed-main {
  min-width: 0;
  flex-basis: 35%;
}
@media (max-width: 640px) {
  .installed-main {
    flex-basis: calc(100% - 70px);
  }
  .lifecycle-actions {
    margin-left: auto;
  }
}
</style>
