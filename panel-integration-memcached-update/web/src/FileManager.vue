<script setup lang="ts">
import { formatPanelDateTime } from "./panelTime";
import { apiURL } from "./panelBase";
import { canReadPath, type AccessPlan } from "./menuPermissions";
import { computed, onBeforeUnmount, ref, watch } from "vue";
import { ElMessage, ElMessageBox } from "element-plus";
import {
  Folder,
  Document,
  Picture,
  Upload,
  Refresh,
  Plus,
  Delete,
  MoreFilled,
  Connection,
  Key,
} from "@element-plus/icons-vue";
interface Site {
  id: string;
  name: string;
  domain: string;
  status: string;
}
interface Entry {
  name: string;
  path: string;
  kind: string;
  size: number;
  mode: string;
  modified_at: string;
}
interface Listing {
  entries: Entry[];
  directory?: Entry;
  total: number;
  page: number;
  truncated: boolean;
}
interface Revision {
  id: string;
  path: string;
  kind: string;
  reason: string;
  deleted_at: string;
  mode: string;
}
interface SFTPAccount {
  id: string;
  site_id: string;
  site_name: string;
  domain: string;
  username: string;
  status: "enabled" | "disabled";
  created_at: string;
  updated_at: string;
}
const props = defineProps<{
  api: <T>(path: string, method?: string, body?: unknown) => Promise<T>;
  sites: Site[];
  csrf: string;
  initialSiteID: string;
  access?: AccessPlan | null;
}>();
const canReadSystem = computed(() => props.access === undefined || props.access?.role === "admin" && props.access.menu_ids.includes("files"));
const canWriteSite = computed(() => props.access === undefined || !!props.access && props.access.role !== "viewer" && props.access.menu_ids.includes("files"));
const canReadDisk = computed(() => props.access === undefined || canReadPath(props.access, "/overview"));
const available = computed(() =>
  props.sites.filter(
    (s) => !["provisioning", "needs_attention"].includes(s.status),
  ),
);
const recentSiteKey = "panel-files-recent-site";
function recentSiteID() {
  try { return localStorage.getItem(recentSiteKey) || ""; } catch { return ""; }
}
function rememberSite(id: string) {
  try { localStorage.setItem(recentSiteKey, id); } catch { /* Browser storage may be unavailable. */ }
}
const initialSite = available.value.find((site) => site.id === props.initialSiteID)
  || available.value.find((site) => site.id === recentSiteID())
  || available.value[0];
const siteID = ref(initialSite?.id || "");
const systemMode = ref<boolean>(canReadSystem.value && !initialSite);
const systemDirectory = ref("/");
const treeRoot = ref<Entry[]>([]);
const treeChildren = ref<Record<string, Entry[]>>({});
const expandedPaths = ref<string[]>(["/"]);
const diskUsed = ref(0), diskTotal = ref(0), diskAvailable = ref<number | null>(null);
const diskReady = ref(false), diskLoading = ref(false), diskDetailsOpen = ref(false), diskReadAt = ref(0), diskError = ref("");
const directory = ref(""),
  search = ref(""),
  page = ref(1),
  total = ref(0);
const entries = ref<Entry[]>([]),
  directoryInfo = ref<Entry | null>(null),
  truncated = ref(false),
  loading = ref(false),
  busy = ref(false),
  error = ref("");
const selectedPaths = ref<string[]>([]);
const inspectedPath = ref("");
const inspectedEntry = computed(() => entries.value.find((item) => item.path === inspectedPath.value));
const selectedEntries = computed(() => entries.value.filter((item) => selectedPaths.value.includes(item.path)));
const singleSelected = computed(() => selectedEntries.value.length === 1 ? selectedEntries.value[0] : undefined);
const dialog = ref(false),
  operation = ref("create"),
  source = ref(""),
  destination = ref(""),
  content = ref(""),
  digest = ref(""),
  mode = ref("0644");
const formError = ref(""),
  savedContent = ref("");
const previewOpen = ref(false), previewBusy = ref(false), previewURL = ref(""), previewName = ref(""), previewError = ref("");
let previewRequest: AbortController | undefined;
const maxImagePreview = 8 * 1024 * 1024;
function imageType(entry: Entry) {
  const extension = entry.name.toLowerCase().split(".").pop();
  return ({ png: "image/png", jpg: "image/jpeg", jpeg: "image/jpeg", gif: "image/gif", webp: "image/webp", ico: "image/x-icon" } as Record<string, string>)[extension || ""] || "";
}
function canPreviewImage(entry: Entry) {
  return entry.kind === "file" && !systemMode.value && entry.size > 0 && entry.size <= maxImagePreview && !!imageType(entry);
}
function fileTypeLabel(entry: Entry) {
  if (entry.kind === "directory") return "文件夹";
  if (entry.kind === "link") return "链接";
  if (entry.kind !== "file") return "特殊文件";
  const name = entry.name.toLowerCase();
  if (name === ".htaccess" || name.endsWith(".conf") || name.endsWith(".ini")) return "配置文件";
  if (imageType(entry)) return "图片文件";
  const extension = name.split(".").pop();
  return ({ php: "PHP 文件", md: "Markdown", xml: "XML 文件", txt: "文本文件", html: "HTML 文件", htm: "HTML 文件", css: "CSS 文件", js: "JavaScript 文件", json: "JSON 文件", zip: "ZIP 压缩包" } as Record<string, string>)[extension || ""] || "文件";
}
function fileIconClass(entry: Entry) {
  if (entry.kind === "directory") return "folder";
  if (imageType(entry) && entry.kind === "file") return "image";
  const type = fileTypeLabel(entry);
  if (type === "PHP 文件" || type === "XML 文件" || type === "JavaScript 文件") return "code";
  if (type === "Markdown") return "markdown";
  return "document";
}
function clearPreview() {
  previewRequest?.abort();
  previewRequest = undefined;
  if (previewURL.value) URL.revokeObjectURL(previewURL.value);
  previewURL.value = "";
  previewError.value = "";
  previewBusy.value = false;
}
async function previewImage(entry: Entry) {
  if (!canPreviewImage(entry)) return;
  clearPreview();
  const controller = new AbortController();
  previewRequest = controller;
  previewName.value = entry.name;
  previewOpen.value = true;
  previewBusy.value = true;
  try {
    const response = await fetch(apiURL(`${endpoint("/download")}?path=${encodeURIComponent(entry.path)}`), { credentials: "same-origin", cache: "no-store", signal: controller.signal });
    if (!response.ok) throw new Error(`读取图片失败（HTTP ${response.status}）`);
    const length = Number(response.headers.get("content-length"));
    if (!Number.isSafeInteger(length) || length < 1 || length > maxImagePreview) throw new Error("图片大小超出 8 MiB 预览限制");
    const bytes = await response.arrayBuffer();
    if (bytes.byteLength !== length) throw new Error("图片传输不完整");
    if (controller.signal.aborted) return;
    previewURL.value = URL.createObjectURL(new Blob([bytes], { type: imageType(entry) }));
  } catch (error) {
    if (!controller.signal.aborted) { previewOpen.value = false; ElMessage.error((error as Error).message); }
  } finally {
    if (previewRequest === controller) { previewRequest = undefined; previewBusy.value = false; }
  }
}
const trashOpen = ref(false),
  trash = ref<Revision[]>([]),
  trashPage = ref(1),
  trashTotal = ref(0),
  trashLoading = ref(false);
const sftpOpen = ref(false),
  sftpLoading = ref(false),
  sftpBusy = ref(false),
  sftpAccounts = ref<SFTPAccount[]>([]),
  sftpSiteID = ref(""),
  oneTimeUsername = ref(""),
  oneTimePassword = ref("");
const uploadInput = ref<HTMLInputElement>(),
  uploadProgress = ref(0),
  uploadName = ref("");
let transfer: XMLHttpRequest | undefined;
let requestSequence = 0;
const selected = computed(() =>
  available.value.find((s) => s.id === siteID.value),
);
const visiblePath = computed(() => systemMode.value ? systemDirectory.value : `/srv/panel/sites/${siteID.value}/public${directory.value ? "/" + directory.value : ""}`);
const pathDraft = ref(visiblePath.value);
watch(visiblePath, value => { pathDraft.value = value; });
interface FileLocation { system: boolean; systemPath: string; site: string; relative: string }
const history = ref<FileLocation[]>([{ system: systemMode.value, systemPath: systemDirectory.value, site: siteID.value, relative: directory.value }]);
const historyIndex = ref(0);
function rememberLocation() {
  const next = { system: systemMode.value, systemPath: systemDirectory.value, site: siteID.value, relative: directory.value };
  const previous = history.value[historyIndex.value];
  if (previous && JSON.stringify(previous) === JSON.stringify(next)) return;
  history.value = [...history.value.slice(0, historyIndex.value + 1), next].slice(-50);
  historyIndex.value = history.value.length - 1;
}
function moveHistory(step: number) {
  const index = historyIndex.value + step;
  if (index < 0 || index >= history.value.length) return;
  historyIndex.value = index;
  const target = history.value[index];
  systemMode.value = target.system;
  systemDirectory.value = target.systemPath;
  siteID.value = target.site;
  directory.value = target.relative;
  search.value = "";
  page.value = 1;
  void load();
}
function goParent() {
  if (systemMode.value) {
    if (systemDirectory.value === "/") return;
    navigateSystem(systemDirectory.value.split("/").slice(0, -1).join("/") || "/");
  } else if (directory.value) {
    navigate(directory.value.split("/").slice(0, -1).join("/"));
  } else {
    navigateSystem(`/srv/panel/sites/${siteID.value}`);
  }
}
function jumpPath() {
  const path = pathDraft.value.trim();
  if (!path.startsWith("/") || path.length > 4096 || path.includes("\\") || path.split("/").some(part => part === "." || part === "..") || /[\x00-\x1f]/.test(path)) {
    ElMessage.warning("请输入有效的服务器绝对路径");
    pathDraft.value = visiblePath.value;
    return;
  }
  navigateSystem(path.replace(/\/+$/, "") || "/");
}
async function copyPath() {
  try { await navigator.clipboard.writeText(visiblePath.value); ElMessage.success("路径已复制"); }
  catch { ElMessage.error("复制路径失败"); }
}
const diskPercent = computed(() => diskTotal.value > 0 ? Math.min(100, Math.round(diskUsed.value / diskTotal.value * 100)) : 0);
const treeNodes = computed(() => {
  const nodes: { entry: Entry; depth: number }[] = [];
  function add(items: Entry[], depth: number) {
    const visible = items.filter((item) => item.kind === "directory" || (depth === 0 && item.kind === "link" && ["bin", "lib", "lib64", "sbin"].includes(item.name)));
    if (depth === 0) visible.sort((a, b) => a.name.localeCompare(b.name, "en"));
    for (const entry of visible) {
      nodes.push({ entry, depth });
      if (entry.kind === "directory" && expandedPaths.value.includes(entry.path) && depth < 6) add(treeChildren.value[entry.path] || [], depth + 1);
    }
  }
  add(treeRoot.value, 0);
  return nodes;
});
const dialogTitles: Record<string, string> = {
  create: "新建文件",
  mkdir: "新建文件夹",
  save: "编辑文本",
  rename: "重命名",
  chmod: "修改权限",
  compress: "压缩为 ZIP",
  extract: "解压到新目录",
};
const editing = computed(() => ["create", "save"].includes(operation.value));
const textBytes = computed(
  () => new TextEncoder().encode(content.value).byteLength,
);
const join = (name: string) =>
  directory.value ? directory.value + "/" + name : name;
const endpoint = (suffix = "") => `/sites/${siteID.value}/files${suffix}`;
function size(n: number) {
  if (n < 1024) return n + " B";
  if (n < 1048576) return (n / 1024).toFixed(1) + " KiB";
  return (n / 1048576).toFixed(1) + " MiB";
}
function diskSize(n: number) {
  return n >= 1073741824 ? (n / 1073741824).toFixed(1) + " GB" : (n / 1048576).toFixed(1) + " MB";
}
async function loadDisk() {
  if (!canReadDisk.value) { diskReady.value = false; diskError.value = "当前账户未授权磁盘概览"; return; }
  diskLoading.value = true;
  try {
    const data = await props.api<{ disk_used: number; disk_total: number; disk_available?: number }>("/overview");
    if (!Number.isFinite(data.disk_total) || data.disk_total <= 0 || !Number.isFinite(data.disk_used) || data.disk_used < 0 || data.disk_used > data.disk_total) throw new Error("磁盘容量读数无效");
    diskUsed.value = data.disk_used;
    diskTotal.value = data.disk_total;
    diskAvailable.value = Number.isFinite(data.disk_available) && data.disk_available! >= 0 && data.disk_available! <= data.disk_total ? data.disk_available! : null;
    diskReady.value = true;
    diskReadAt.value = Date.now();
    diskError.value = "";
  } catch (error) {
    diskReady.value = false;
    diskError.value = (error as Error).message || "磁盘读数暂不可用";
  } finally { diskLoading.value = false; }
}
async function showDiskDetails() {
  diskDetailsOpen.value = true;
  await loadDisk();
}
void loadDisk();
const date = (value: string) =>
  formatPanelDateTime(value);
async function load() {
  if (!systemMode.value && !siteID.value) return;
  const seq = ++requestSequence;
  loading.value = true;
  error.value = "";
  try {
    const result = await props.api<Listing>(
      (systemMode.value ? "/filesystem" : endpoint()) +
        "?" +
        new URLSearchParams({
          path: systemMode.value ? systemDirectory.value : directory.value,
          search: search.value,
          page: String(page.value),
          limit: "14",
        }),
    );
    if (seq !== requestSequence) return;
    entries.value = result.entries;
    inspectedPath.value = "";
    directoryInfo.value = result.directory || null;
    selectedPaths.value = [];
    total.value = result.total;
    page.value = result.page;
    truncated.value = result.truncated;
  } catch (e) {
    if (seq === requestSequence) {
      error.value = (e as Error).message;
      entries.value = [];
      directoryInfo.value = null;
      total.value = 0;
    }
  } finally {
    if (seq === requestSequence) loading.value = false;
  }
}
void load();
async function loadTree(path: string) {
  if (!canReadSystem.value) return;
  try {
    const result = await props.api<Listing>("/filesystem?" + new URLSearchParams({ path, limit: "100" }));
    if (path === "/") treeRoot.value = result.entries;
    else treeChildren.value = { ...treeChildren.value, [path]: result.entries };
  } catch (e) {
    ElMessage.error((e as Error).message);
  }
}
void loadTree("/");
async function toggleTree(entry: Entry) {
  if (expandedPaths.value.includes(entry.path)) expandedPaths.value = expandedPaths.value.filter((p) => p !== entry.path);
  else {
    expandedPaths.value = [...expandedPaths.value, entry.path];
    if (!treeChildren.value[entry.path]) await loadTree(entry.path);
  }
}
function navigateSystem(path: string) {
  for (const site of available.value) {
    const root = `/srv/panel/sites/${site.id}/public`;
    if (path === root || path.startsWith(root + "/")) {
      siteID.value = site.id;
      systemMode.value = false;
      rememberSite(site.id);
      directory.value = path === root ? "" : path.slice(root.length + 1);
      search.value = "";
      page.value = 1;
      rememberLocation();
      void load();
      return;
    }
  }
  if (!canReadSystem.value) { ElMessage.info("当前账户仅可浏览已授权网站的 public 目录"); return; }
  systemMode.value = true;
  systemDirectory.value = path;
  search.value = "";
  page.value = 1;
  rememberLocation();
  void load();
}
function selectSite(id: string) {
  if (!available.value.some((site) => site.id === id)) return;
  siteID.value = id;
  systemMode.value = false;
  rememberSite(id);
  directory.value = "";
  search.value = "";
  page.value = 1;
  rememberLocation();
  void load();
}
watch(available, (items) => {
  if (!items.length || items.some((site) => site.id === siteID.value)) return;
  const next = items.find((site) => site.id === props.initialSiteID) || items.find((site) => site.id === recentSiteID()) || items[0];
  selectSite(next.id);
});
function navigate(path: string) {
  if (systemMode.value) { navigateSystem(path); return; }
  directory.value = path;
  rememberLocation();
  search.value = "";
  page.value = 1;
  void load();
}
function find() {
  page.value = 1;
  void load();
}
function searchFor(term: string) {
  if (systemMode.value) systemDirectory.value = "/";
  else directory.value = "";
  search.value = term;
  page.value = 1;
  void load();
}
defineExpose({ searchFor });
async function open(kind: string, entry?: Entry) {
  if (!canWriteSite.value && kind !== "save") { ElMessage.info("当前账户仅可查看文件"); return; }
  operation.value = kind;
  source.value = entry?.path || "";
  content.value = "";
  savedContent.value = "";
  digest.value = "";
  mode.value = entry?.mode || "0644";
  formError.value = "";
  destination.value =
    kind === "compress"
      ? join("." + (entry?.name || "archive") + ".zip")
      : kind === "extract"
        ? join((entry?.name || "archive").replace(/\.zip$/i, "") + "-unpacked")
        : entry?.path || join(kind === "mkdir" ? "new-folder" : "new-file.txt");
  if (kind === "save" && entry) {
    loading.value = true;
    try {
      const text = await props.api<{ content: string; sha256: string }>(
        endpoint("/text") + "?path=" + encodeURIComponent(entry.path),
      );
      content.value = text.content;
      savedContent.value = text.content;
      digest.value = text.sha256;
    } catch (e) {
      ElMessage.error((e as Error).message);
      return;
    } finally {
      loading.value = false;
    }
  }
  dialog.value = true;
}
async function closeDialog(done: () => void) {
  if (busy.value) return;
  if (editing.value && content.value !== savedContent.value) {
    try {
      await ElMessageBox.confirm(
        "关闭后将丢弃尚未保存的文本。",
        "放弃本次编辑",
        { confirmButtonText: "放弃编辑", cancelButtonText: "继续编辑" },
      );
    } catch {
      return;
    }
  }
  done();
}
async function submit() {
  if (!canWriteSite.value) { formError.value = "当前账户仅可查看文件"; return; }
  if (busy.value) return;
  formError.value = "";
  if (editing.value && textBytes.value > 32768) {
    formError.value = "文本编辑最大 32 KiB。";
    return;
  }
  busy.value = true;
  const kind = operation.value;
  const payload: Record<string, string> = { action: kind, path: source.value };
  if (["mkdir", "create"].includes(kind)) payload.path = destination.value;
  if (["rename", "compress", "extract"].includes(kind))
    payload.destination = destination.value;
  if (editing.value) payload.content = content.value;
  if (kind === "save") payload.expected_sha256 = digest.value;
  if (kind === "chmod") payload.mode = mode.value;
  try {
    await props.api(endpoint("/action"), "POST", payload);
    savedContent.value = content.value;
    dialog.value = false;
    ElMessage.success("操作已完成");
    await load();
  } catch (e) {
    formError.value = (e as Error).message;
  } finally {
    busy.value = false;
  }
}
async function recycle(entry: Entry) {
  try {
    await ElMessageBox.confirm(
      `将“${entry.name}”移入当前站点的回收站，可以稍后恢复。`,
      "移入回收站",
      {
        confirmButtonText: "移入回收站",
        cancelButtonText: "取消",
        type: "warning",
      },
    );
  } catch {
    return;
  }
  busy.value = true;
  try {
    await props.api(endpoint("/action"), "POST", {
      action: "trash",
      path: entry.path,
    });
    await load();
    ElMessage.success("已移入回收站");
  } catch (e) {
    ElMessage.error((e as Error).message);
  } finally {
    busy.value = false;
  }
}
async function loadTrash() {
  trashLoading.value = true;
  try {
    const data = await props.api<{
      entries: Revision[];
      total: number;
      page: number;
    }>(endpoint("/trash") + `?page=${trashPage.value}&limit=20`);
    trash.value = data.entries;
    trashTotal.value = data.total;
    trashPage.value = data.page;
  } catch (e) {
    ElMessage.error((e as Error).message);
  } finally {
    trashLoading.value = false;
  }
}
function showTrash() {
  trashOpen.value = true;
  trashPage.value = 1;
  void loadTrash();
}
async function loadSFTP() {
  sftpLoading.value = true;
  try {
    const data = await props.api<{ accounts: SFTPAccount[] }>("/sftp");
    sftpAccounts.value = data.accounts;
  } catch (e) {
    ElMessage.error((e as Error).message);
  } finally {
    sftpLoading.value = false;
  }
}
function showSFTP() {
  sftpSiteID.value = siteID.value || available.value[0]?.id || "";
  oneTimeUsername.value = "";
  oneTimePassword.value = "";
  sftpOpen.value = true;
  void loadSFTP();
}
async function createSFTP() {
  if (!sftpSiteID.value || sftpBusy.value) return;
  sftpBusy.value = true;
  try {
    const data = await props.api<{
      account: SFTPAccount;
      password: string;
    }>("/sftp", "POST", { site_id: sftpSiteID.value });
    oneTimeUsername.value = data.account.username;
    oneTimePassword.value = data.password;
    await loadSFTP();
    ElMessage.success("SFTP 账户已创建，请立即保存一次性密码");
  } catch (e) {
    ElMessage.error((e as Error).message);
  } finally {
    sftpBusy.value = false;
  }
}
async function rotateSFTP(account: SFTPAccount) {
  try {
    await ElMessageBox.confirm(
      `将重置 ${account.username} 的密码，并立即断开该账户的现有连接。`,
      "重置 SFTP 密码",
      {
        confirmButtonText: "重置密码",
        cancelButtonText: "取消",
        type: "warning",
      },
    );
  } catch {
    return;
  }
  sftpBusy.value = true;
  try {
    const data = await props.api<{ password: string }>(
      `/sftp/${account.id}/password`,
      "POST",
      {},
    );
    oneTimeUsername.value = account.username;
    oneTimePassword.value = data.password;
    ElMessage.success("密码已重置，请立即保存");
  } catch (e) {
    ElMessage.error((e as Error).message);
  } finally {
    sftpBusy.value = false;
  }
}
async function setSFTPStatus(account: SFTPAccount, enabled: boolean) {
  sftpBusy.value = true;
  try {
    await props.api(`/sftp/${account.id}/status`, "PUT", { enabled });
    await loadSFTP();
    ElMessage.success(enabled ? "SFTP 账户已启用" : "SFTP 账户已停用");
  } catch (e) {
    ElMessage.error((e as Error).message);
  } finally {
    sftpBusy.value = false;
  }
}
async function removeSFTP(account: SFTPAccount) {
  let confirmUsername = "";
  try {
    const result = await ElMessageBox.prompt(
      `删除后该账户将不能再登录。请输入完整用户名 ${account.username} 确认。`,
      "删除 SFTP 账户",
      {
        confirmButtonText: "永久删除",
        cancelButtonText: "取消",
        inputPlaceholder: account.username,
        inputValidator: (value: string) =>
          value === account.username || "用户名不匹配",
        type: "warning",
      },
    );
    confirmUsername = result.value;
  } catch {
    return;
  }
  sftpBusy.value = true;
  try {
    await props.api(`/sftp/${account.id}`, "DELETE", {
      confirm_username: confirmUsername,
    });
    if (oneTimeUsername.value === account.username) {
      oneTimeUsername.value = "";
      oneTimePassword.value = "";
    }
    await loadSFTP();
    ElMessage.success("SFTP 账户已删除");
  } catch (e) {
    ElMessage.error((e as Error).message);
  } finally {
    sftpBusy.value = false;
  }
}
async function copyCredential(value: string, label: string) {
  try {
    await navigator.clipboard.writeText(value);
    ElMessage.success(`${label}已复制`);
  } catch {
    ElMessage.error("浏览器未允许复制，请手动选择文本");
  }
}
async function restore(item: Revision) {
  let target = item.path;
  try {
    const result = await ElMessageBox.prompt(
      "填写相对于网站根目录的恢复路径。目标必须不存在。",
      "恢复文件",
      {
        inputValue:
          item.reason === "edit"
            ? item.path + ".restored-" + Date.now()
            : item.path,
        confirmButtonText: "恢复",
        cancelButtonText: "取消",
        inputValidator: (value: string) => !!value || "请输入恢复路径",
      },
    );
    target = result.value;
  } catch {
    return;
  }
  busy.value = true;
  try {
    await props.api(endpoint("/action"), "POST", {
      action: "restore",
      trash_id: item.id,
      destination: target,
    });
    await loadTrash();
    await load();
    ElMessage.success("已恢复到 " + target);
  } catch (e) {
    ElMessage.error((e as Error).message);
  } finally {
    busy.value = false;
  }
}
async function purge(item: Revision) {
  try {
    await ElMessageBox.confirm(
      `永久删除“${item.path}”的这份${item.reason === "edit" ? "编辑前副本" : "回收文件"}，删除后无法恢复。`,
      "永久删除回收项",
      {
        confirmButtonText: "永久删除",
        cancelButtonText: "取消",
        type: "warning",
      },
    );
  } catch {
    return;
  }
  busy.value = true;
  try {
    await props.api(endpoint("/action"), "POST", {
      action: "purge",
      trash_id: item.id,
    });
    await loadTrash();
    ElMessage.success("已永久删除所选回收项");
  } catch (e) {
    ElMessage.error((e as Error).message);
  } finally {
    busy.value = false;
  }
}
function uploadFile(file: File): Promise<void> {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    transfer = xhr;
    xhr.open(
      "POST",
      apiURL(
        endpoint("/upload") +
        "?path=" +
        encodeURIComponent(join(file.name))),
    );
    xhr.setRequestHeader("Content-Type", "application/octet-stream");
    xhr.setRequestHeader("X-CSRF-Token", props.csrf);
    xhr.timeout = 300000;
    xhr.upload.onprogress = (e) => {
      if (e.lengthComputable)
        uploadProgress.value = Math.round((e.loaded / e.total) * 100);
    };
    xhr.onload = () => {
      transfer = undefined;
      let result: { error?: string } = {};
      try {
        result = JSON.parse(xhr.responseText);
      } catch {}
      if (xhr.status >= 200 && xhr.status < 300) resolve();
      else reject(new Error(result.error || "上传失败"));
    };
    xhr.onerror = () => reject(new Error("上传连接中断"));
    xhr.ontimeout = () => reject(new Error("上传超时"));
    xhr.onabort = () => reject(new Error("上传已取消"));
    xhr.send(file);
  });
}
async function uploadChanged(event: Event) {
  const input = event.target as HTMLInputElement;
  const files = Array.from(input.files || []);
  input.value = "";
  if (!files.length) return;
  if (files.some((f) => f.size > 512 * 1024 * 1024)) {
    ElMessage.error("单个文件不能超过 512 MiB");
    return;
  }
  busy.value = true;
  try {
    for (const file of files) {
      uploadName.value = file.name;
      uploadProgress.value = 0;
      await uploadFile(file);
    }
    ElMessage.success(`已上传 ${files.length} 个文件`);
  } catch (e) {
    ElMessage.error((e as Error).message);
  } finally {
    transfer = undefined;
    uploadName.value = "";
    busy.value = false;
    await load();
  }
}
function command(kind: string, entry: Entry) {
  if (kind === "trash") void recycle(entry);
  else void open(kind, entry);
}
function toggleAllFiles(event: Event) {
  const checked = (event.target as HTMLInputElement).checked;
  selectedPaths.value = checked && !systemMode.value ? entries.value.map((item) => item.path) : [];
}
function operateSelected(kind: string) {
  if (!singleSelected.value || systemMode.value) return;
  if (kind === "trash") void recycle(singleSelected.value);
  else void open(kind, singleSelected.value);
}
onBeforeUnmount(() => {
  requestSequence++;
  transfer?.abort();
  clearPreview();
});
</script>

<template>
  <div class="file-management-layout">
    <aside class="panel-card file-tree-panel">
      <div class="file-side-title">目录结构</div>
      <button v-if="canReadSystem" class="file-tree-root" :class="{ active: systemMode && systemDirectory === '/' }" @click="navigateSystem('/')">
        <el-icon><Folder /></el-icon><strong>/</strong>
      </button>
      <div class="file-system-tree">
        <div v-for="node in treeNodes" :key="node.entry.path" class="file-tree-node" :style="{ paddingLeft: `${8 + node.depth * 17}px` }">
          <span v-if="node.entry.kind === 'link'" class="file-tree-expand file-tree-link-marker" aria-hidden="true">↗</span>
          <button v-else class="file-tree-expand" :aria-label="'展开 ' + node.entry.path" @click="toggleTree(node.entry)">{{ expandedPaths.includes(node.entry.path) ? '⌄' : '›' }}</button>
          <button class="file-tree-directory" :class="{ active: (systemMode && systemDirectory === node.entry.path) || (!systemMode && visiblePath === node.entry.path) }" :disabled="node.entry.kind === 'link'" :title="node.entry.kind === 'link' ? '符号链接仅展示，不能进入' : node.entry.path" @click="navigateSystem(node.entry.path)"><el-icon><Folder /></el-icon><span>{{ node.entry.name }}</span></button>
        </div>
      </div>
      <div class="file-site-group-title">托管网站目录</div>
      <button
        v-for="site in available"
        :key="site.id"
        :class="['file-tree-site', { active: !systemMode && site.id === siteID }]"
        @click="selectSite(site.id)"
      >
        <el-icon><Folder /></el-icon><span>{{ site.name }}</span>
      </button>
      <div v-if="selected && !systemMode" class="file-tree-children">
        <button
          v-for="entry in entries
            .filter((item) => item.kind === 'directory')
            .slice(0, 12)"
          :key="entry.path"
          @click="navigate(entry.path)"
        >
          <el-icon><Folder /></el-icon><span>{{ entry.name }}</span>
        </button>
      </div>
      <button class="file-tree-recycle" :disabled="systemMode" @click="showTrash">
        <el-icon><Delete /></el-icon>回收站
      </button>
    </aside>
    <section class="panel-card file-manager">
      <el-empty v-if="!selected && !systemMode" description="当前账户暂无已授权的可管理网站。" />
      <template v-else>
        <div class="file-path">
          <div class="file-path-controls">
            <button type="button" aria-label="后退目录" title="后退" :disabled="busy || historyIndex === 0" @click="moveHistory(-1)">‹</button>
            <button type="button" aria-label="前进目录" title="前进" :disabled="busy || historyIndex >= history.length - 1" @click="moveHistory(1)">›</button>
            <button type="button" aria-label="上级目录" title="上级目录" :disabled="busy || (systemMode && systemDirectory === '/') || (!canReadSystem && !directory)" @click="goParent">↑</button>
            <form @submit.prevent="jumpPath"><input v-model="pathDraft" aria-label="文件路径" title="输入服务器绝对路径后回车" spellcheck="false" :disabled="busy" /></form>
            <button type="button" aria-label="复制文件路径" title="复制文件路径" @click="copyPath">⧉</button>
          </div>
          <label class="site-picker"><span>托管站点</span><select
            v-model="siteID"
            @change="selectSite(siteID)"
            aria-label="文件管理站点"
            :disabled="busy || dialog || trashOpen"
          ><option v-if="!available.length" value="">暂无可管理的网站</option><option v-for="site in available" :key="site.id" :value="site.id">{{ site.name }} · {{ site.domain }}</option></select></label><span class="file-total">{{ total }} 项</span>
        </div>
        <div class="file-toolbar">
          <div class="file-buttons">
            <el-button
              type="primary"
              :icon="Upload"
              :disabled="busy || systemMode || !canWriteSite"
              title="服务器目录只读；选择托管网站后可上传"
              @click="uploadInput?.click()"
              >上传文件</el-button
            ><el-button :icon="Plus" :disabled="busy || systemMode || !canWriteSite" @click="open('create')">新建文件</el-button>
            <el-button :icon="Folder" :disabled="busy || systemMode || !canWriteSite" @click="open('mkdir')">新建文件夹</el-button>
            <el-button :disabled="busy || systemMode || !canWriteSite || !singleSelected || !['file', 'directory'].includes(singleSelected.kind)" @click="operateSelected('compress')">压缩</el-button>
            <el-button :disabled="busy || systemMode || !canWriteSite || !singleSelected || singleSelected.kind !== 'file' || !singleSelected.name.toLowerCase().endsWith('.zip')" @click="operateSelected('extract')">解压</el-button>
            <el-button :disabled="busy || systemMode || !canWriteSite || !singleSelected || !['file', 'directory'].includes(singleSelected.kind)" @click="operateSelected('chmod')">权限</el-button>
            <el-button :icon="Delete" :disabled="busy || systemMode || !canWriteSite || !singleSelected" @click="operateSelected('trash')">删除</el-button>
            <span v-if="systemMode || !canWriteSite" class="file-readonly-label">只读</span>
          </div>
          <form class="file-search" @submit.prevent="find">
            <el-input
              v-model="search"
              aria-label="搜索当前目录"
              placeholder="搜索当前目录文件..."
              clearable
              :disabled="busy"
              @clear="find"
            /><el-button native-type="submit" :disabled="busy">搜索</el-button
            ><el-button
              :icon="Refresh"
              circle
              aria-label="刷新文件列表"
              :disabled="busy"
              @click="load"
            />
          </form>
          <input
            ref="uploadInput"
            class="hidden-file-input"
            type="file"
            multiple
            aria-label="选择上传文件"
            @change="uploadChanged"
          />
        </div>
        <div v-if="uploadName" class="upload-status">
          <span
            >正在上传 {{ uploadName }} ·
            {{
              uploadProgress === 100 ? "正在保存" : uploadProgress + "%"
            }}</span
          ><el-progress :percentage="uploadProgress" :show-text="false" />
        </div>
        <el-alert
          v-if="error"
          :title="error"
          type="error"
          :closable="false"
          show-icon
        />
        <el-alert
          v-if="truncated"
          title="当前目录超过 10,000 项，仅展示本次扫描的前 10,000 项。可进入子目录继续管理。"
          type="warning"
          :closable="false"
        />
        <div
          v-loading="loading"
          class="file-list"
          aria-label="文件列表"
          :aria-busy="loading"
        >
          <div class="file-row file-columns">
            <input type="checkbox" aria-label="全选当前页" :disabled="systemMode || busy || !entries.length" :checked="!systemMode && entries.length > 0 && selectedPaths.length === entries.length" @change="toggleAllFiles" /><span>名称</span><span>大小</span><span>修改时间</span><span>权限</span><span>类型</span><span>操作</span>
          </div>
          <div
            v-for="entry in entries"
            :key="entry.path"
            class="file-row"
            :class="{ inspected: inspectedPath === entry.path }"
            :data-file="entry.name"
            tabindex="0"
            :aria-label="'查看 ' + entry.name + ' 的文件信息'"
            @click="inspectedPath = entry.path"
            @keydown.enter="inspectedPath = entry.path"
            @keydown.space.prevent="inspectedPath = entry.path"
          >
            <input type="checkbox" :aria-label="'选择 ' + entry.name" :disabled="systemMode || busy" :checked="selectedPaths.includes(entry.path)" @change="(event: Event) => selectedPaths = (event.target as HTMLInputElement).checked ? [...selectedPaths, entry.path] : selectedPaths.filter((path) => path !== entry.path)" />
            <div class="file-name">
              <el-icon :class="fileIconClass(entry)"
                ><Folder v-if="entry.kind === 'directory'" /><Picture v-else-if="entry.kind === 'file' && imageType(entry)" /><Document
                  v-else /></el-icon
              ><button
                :disabled="busy || entry.kind !== 'directory' && (systemMode || entry.kind !== 'file')"
                :title="entry.name"
                @click="
                  entry.kind === 'directory'
                    ? systemMode ? navigateSystem(entry.path) : navigate(entry.path)
                    : canPreviewImage(entry) ? previewImage(entry) : open('save', entry)
                "
              >
                {{ entry.name }}</button
              ><span v-if="entry.kind === 'link'" class="kind-label">链接</span
              ><span v-if="entry.kind === 'special'" class="kind-label"
                >特殊文件</span
              >
            </div>
            <span class="file-size">{{
              entry.kind === "directory" ? "—" : size(entry.size)
            }}</span
            ><time class="file-date">{{ date(entry.modified_at) }}</time><span class="file-mode">{{ entry.mode }}</span><span class="file-kind">{{ fileTypeLabel(entry) }}</span>
            <div class="file-operations">
              <el-button
                v-if="entry.kind === 'directory'"
                link
                type="primary"
                :disabled="busy"
                @click="systemMode ? navigateSystem(entry.path) : navigate(entry.path)"
                >打开</el-button
              ><el-button
                v-else-if="entry.kind === 'file' && !systemMode"
                link
                type="primary"
                :disabled="busy"
                @click="canPreviewImage(entry) ? previewImage(entry) : open('save', entry)"
                >{{ canPreviewImage(entry) ? '预览' : canWriteSite ? '编辑' : '查看' }}</el-button
              ><a
                v-if="entry.kind === 'file' && !systemMode"
                :href="
                  apiURL(
                  endpoint('/download') +
                  '?path=' +
                  encodeURIComponent(entry.path))
                "
                download
                >下载</a
              ><el-dropdown
                v-if="!systemMode && canWriteSite"
                :disabled="busy"
                trigger="click"
                @command="(kind: string) => command(kind, entry)"
                ><el-button
                  link
                  :icon="MoreFilled"
                  :disabled="busy"
                  :aria-label="'更多操作 ' + entry.name"
                /><template #dropdown
                  ><el-dropdown-menu
                    ><el-dropdown-item command="rename">重命名</el-dropdown-item
                    ><el-dropdown-item
                      v-if="['file', 'directory'].includes(entry.kind)"
                      command="chmod"
                      >修改权限</el-dropdown-item
                    ><el-dropdown-item
                      v-if="['file', 'directory'].includes(entry.kind)"
                      command="compress"
                      >压缩为 ZIP</el-dropdown-item
                    ><el-dropdown-item
                      v-if="
                        entry.kind === 'file' &&
                        entry.name.toLowerCase().endsWith('.zip')
                      "
                      command="extract"
                      >解压到新目录</el-dropdown-item
                    ><el-dropdown-item divided command="trash"
                      >移入回收站</el-dropdown-item
                    ></el-dropdown-menu
                  ></template
                ></el-dropdown
              >
            </div>
          </div>
          <el-empty
            v-if="!loading && !entries.length && !error"
            :description="search ? '没有匹配的文件' : '当前目录为空'"
            :image-size="80"
          />
        </div>
        <div class="file-footer">
          <span>{{ systemMode ? `共 ${total} 项 · 服务器目录只读` : '文本编辑 ≤ 32 KiB · 单文件上传 ≤ 512 MiB' }}</span
          ><el-pagination
            v-if="total > 14"
            v-model:current-page="page"
            :page-size="14"
            :total="total"
            layout="prev, pager, next"
            :pager-count="5"
            :disabled="busy"
            @current-change="load"
          />
        </div>
      </template>
    </section>
    <aside class="file-info-column">
      <section class="panel-card file-info-card">
        <div class="file-side-title">文件信息</div>
        <div class="file-info-folder">
          <el-icon><Folder v-if="!inspectedEntry || inspectedEntry.kind === 'directory'" /><Document v-else /></el-icon
          ><strong>{{ inspectedEntry?.name || (systemMode ? (systemDirectory.split('/').filter(Boolean).at(-1) || '/') : (selected?.name || '未选择站点')) }}</strong>
        </div>
        <dl>
          <dt>类型</dt>
          <dd>{{ inspectedEntry ? inspectedEntry.kind === 'directory' ? '文件夹' : inspectedEntry.kind === 'file' ? '文件' : inspectedEntry.kind === 'link' ? '符号链接' : '特殊文件' : systemMode ? '服务器目录（只读）' : '网站目录' }}</dd>
          <template v-if="!systemMode && !inspectedEntry"><dt>域名</dt><dd>{{ selected?.domain || "—" }}</dd></template>
          <dt>路径</dt>
          <dd>{{ inspectedEntry ? (systemMode ? inspectedEntry.path : `${visiblePath}/${inspectedEntry.name}`) : visiblePath }}</dd>
          <dt>当前目录</dt>
          <dd>{{ visiblePath }}</dd>
          <template v-if="inspectedEntry && inspectedEntry.kind !== 'directory'"><dt>大小</dt><dd>{{ size(inspectedEntry.size) }}</dd></template>
          <dt>修改时间</dt>
          <dd>{{ inspectedEntry ? date(inspectedEntry.modified_at) : directoryInfo ? date(directoryInfo.modified_at) : '—' }}</dd>
          <dt>权限</dt>
          <dd>{{ inspectedEntry?.mode || directoryInfo?.mode || '—' }}</dd>
          <dt v-if="!inspectedEntry">包含</dt>
          <dd v-if="!inspectedEntry">
            {{ entries.filter((item) => item.kind === "directory").length }}
            个文件夹，{{
              entries.filter((item) => item.kind === "file").length
            }}
            个文件
          </dd>
        </dl>
      </section>
      <section v-if="canReadDisk" class="panel-card file-info-card file-storage-card">
        <div class="file-side-title">存储使用<button type="button" @click="showDiskDetails">查看详情 ›</button></div>
        <div class="file-storage-summary"><div class="file-storage-donut" :style="{ background: diskReady ? `conic-gradient(#08ad5b ${diskPercent}%, #e4eaf0 0)` : '#e4eaf0' }"><div><strong>{{ diskReady ? `${diskPercent}%` : '—' }}</strong><small>已使用</small></div></div><div><strong>{{ diskReady ? diskSize(diskUsed) : '—' }}</strong><span>/ {{ diskReady ? diskSize(diskTotal) : '—' }}</span><small>{{ diskReady ? '面板数据分区' : '读数暂不可用' }}</small></div></div>
      </section>
      <section v-if="canWriteSite" class="panel-card file-quick-actions">
        <div class="file-side-title">快捷操作</div>
        <button :disabled="systemMode" @click="open('create')">
          <el-icon><Document /></el-icon>新建文件
        </button>
        <button :disabled="systemMode" @click="open('mkdir')">
          <el-icon><Folder /></el-icon>新建文件夹
        </button>
        <button :disabled="systemMode" @click="uploadInput?.click()">
          <el-icon><Upload /></el-icon>上传文件
        </button>
        <button v-if="canReadSystem" :disabled="systemMode" @click="showSFTP">
          <el-icon><Connection /></el-icon>SFTP 账户
        </button>
      </section>
    </aside>
  </div>
  <el-dialog v-model="diskDetailsOpen" title="存储使用详情" width="min(460px, 94vw)">
    <p class="file-disk-note">包含 /srv/panel 的文件系统容量，不包含其他独立挂载的磁盘；可用量取文件系统实际可用块。</p>
    <div v-if="diskReady" class="file-disk-details">
      <div><span>总容量</span><strong>{{ diskSize(diskTotal) }}</strong></div>
      <div><span>已使用</span><strong>{{ diskSize(diskUsed) }}（{{ diskPercent }}%）</strong></div>
      <div><span>可用</span><strong>{{ diskAvailable === null ? '—' : diskSize(diskAvailable) }}</strong></div>
      <small>读取时间：{{ formatPanelDateTime(diskReadAt) }}</small>
    </div>
    <p v-else class="file-disk-error">{{ diskLoading ? '正在读取磁盘容量…' : diskError }}</p>
    <template #footer><el-button :loading="diskLoading" @click="loadDisk">刷新读数</el-button><el-button type="primary" @click="diskDetailsOpen = false">完成</el-button></template>
  </el-dialog>
  <el-dialog
    v-model="dialog"
    :title="operation === 'save' && !canWriteSite ? '查看文本（只读）' : dialogTitles[operation]"
    :width="editing ? 'min(920px, 94vw)' : 'min(540px, 94vw)'"
    :close-on-click-modal="false"
    :before-close="closeDialog"
    destroy-on-close
    class="file-dialog"
  >
    <el-form label-position="top" @submit.prevent="submit">
      <el-form-item
        v-if="
          ['create', 'mkdir', 'rename', 'compress', 'extract'].includes(
            operation,
          )
        "
        :label="
          ['compress', 'extract', 'rename'].includes(operation)
            ? '目标路径'
            : '文件路径'
        "
        ><el-input
          v-model="destination"
          :disabled="busy"
          aria-label="文件目标路径"
        />
        <div class="form-help">
          相对于网站根目录，目标路径必须不存在。
        </div></el-form-item
      >
      <div v-if="source" class="source-path">{{ source }}</div>
      <el-form-item v-if="operation === 'chmod'" label="八进制权限"
        ><el-input
          v-model="mode"
          maxlength="4"
          aria-label="八进制权限"
          :disabled="busy"
        />
        <div class="form-help">
          例如：0644 普通文件、0600 私有文件、0755 文件夹。
        </div></el-form-item
      >
      <template v-if="editing"
        ><el-input
          v-model="content"
          type="textarea"
          :rows="18"
          resize="vertical"
          aria-label="文件文本内容"
          :readonly="!canWriteSite"
          :disabled="busy"
          spellcheck="false"
          class="file-editor"
        />
        <div class="editor-foot">
          <span>{{
            operation === "save"
              ? "保存前保留副本；文件被外部修改时将提示冲突。"
              : "使用 UTF-8 编码保存。"
          }}</span
          ><span :class="{ 'over-limit': textBytes > 32768 }"
            >{{ size(textBytes) }} / 32 KiB</span
          >
        </div></template
      >
      <el-alert
        v-if="operation === 'compress'"
        title="默认生成隐藏 ZIP，可从文件列表下载。压缩总大小上限 512 MiB，最多 10,000 项。"
        type="info"
        :closable="false"
      />
      <el-alert
        v-if="operation === 'extract'"
        title="完整检查 ZIP 后才创建目标目录。解压总大小上限 512 MiB，链接与越界路径会被拒绝。"
        type="info"
        :closable="false"
      />
      <el-alert
        v-if="formError"
        :title="formError"
        type="error"
        :closable="false"
        show-icon
        class="file-form-error"
      />
    </el-form>
    <template #footer
      ><el-button :disabled="busy" @click="closeDialog(() => (dialog = false))"
        >取消</el-button
      ><el-button
        type="primary"
        :loading="busy"
        v-if="canWriteSite"
        :disabled="editing && textBytes > 32768"
        @click="submit"
        >{{ operation === "save" ? "保存文件" : "确认操作" }}</el-button
      ></template
    >
  </el-dialog>
  <el-dialog
    v-model="previewOpen"
    :title="'图片预览 · ' + previewName"
    width="min(940px, 94vw)"
    class="file-image-dialog"
    @closed="() => { if (!previewOpen) clearPreview(); }"
  >
    <div v-loading="previewBusy" class="file-image-preview">
      <img v-if="previewURL && !previewError" :src="previewURL" :alt="previewName" @error="previewError = '无法预览该图片，请下载检查文件格式。'" />
      <p v-if="previewError" class="file-image-error">{{ previewError }}</p>
    </div>
  </el-dialog>
  <el-dialog
    v-model="trashOpen"
    title="回收站与编辑副本"
    width="min(900px, 94vw)"
    :close-on-click-modal="false"
    :show-close="!busy"
    :close-on-press-escape="!busy"
    class="file-trash-dialog"
  >
    <p class="trash-note">
      每个站点独立保存删除文件与编辑前副本，最多 2,000
      条。恢复时选择一个不存在的路径。
    </p>
    <div v-loading="trashLoading" class="trash-list">
      <article v-for="item in trash" :key="item.id" class="trash-row">
        <div>
          <strong>{{ item.path }}</strong>
          <p>
            {{ item.reason === "edit" ? "编辑前副本" : "已删除" }} ·
            {{ date(item.deleted_at) }} · {{ item.mode }}
          </p>
        </div>
        <div>
          <el-button v-if="canWriteSite" link type="primary" :disabled="busy" @click="restore(item)"
            >恢复</el-button
          ><el-button v-if="canWriteSite" link type="danger" :disabled="busy" @click="purge(item)"
            >永久删除</el-button
          >
        </div>
      </article>
      <el-empty
        v-if="!trashLoading && !trash.length"
        description="暂无回收文件或编辑副本"
        :image-size="70"
      />
    </div>
    <el-pagination
      v-if="trashTotal > 20"
      v-model:current-page="trashPage"
      :page-size="20"
      :total="trashTotal"
      layout="prev, pager, next"
      :pager-count="5"
      :disabled="busy"
      @current-change="loadTrash"
    />
  </el-dialog>
  <el-dialog
    v-model="sftpOpen"
    title="SFTP 账户"
    width="min(940px, 96vw)"
    :close-on-click-modal="false"
    :show-close="!sftpBusy"
    :close-on-press-escape="!sftpBusy"
    class="sftp-dialog"
  >
    <div class="sftp-create-bar">
      <div>
        <strong>按网站创建隔离账户</strong>
        <p>登录后固定进入该网站目录，只能通过 SFTP 传输文件。</p>
      </div>
      <el-select
        v-model="sftpSiteID"
        aria-label="SFTP 账户网站"
        :disabled="sftpBusy"
        placeholder="选择网站"
      >
        <el-option
          v-for="site in available"
          :key="site.id"
          :label="site.name + ' · ' + site.domain"
          :value="site.id"
        />
      </el-select>
      <el-button
        type="primary"
        :icon="Plus"
        :loading="sftpBusy"
        :disabled="!sftpSiteID"
        data-sftp-create
        @click="createSFTP"
        >创建账户</el-button
      >
    </div>
    <el-alert
      v-if="oneTimePassword"
      title="密码只显示这一次，请立即保存"
      type="warning"
      :closable="false"
      show-icon
      class="sftp-credential"
    >
      <dl>
        <dt>用户名</dt>
        <dd>
          <code>{{ oneTimeUsername }}</code
          ><el-button
            link
            type="primary"
            @click="copyCredential(oneTimeUsername, '用户名')"
            >复制</el-button
          >
        </dd>
        <dt>密码</dt>
        <dd>
          <code data-sftp-password>{{ oneTimePassword }}</code
          ><el-button
            link
            type="primary"
            @click="copyCredential(oneTimePassword, '密码')"
            >复制</el-button
          >
        </dd>
        <dt>连接</dt>
        <dd>服务器 22 端口 · 协议 SFTP · 目录 /site</dd>
      </dl>
    </el-alert>
    <div v-loading="sftpLoading" class="sftp-table" aria-label="SFTP 账户列表">
      <div class="sftp-row sftp-columns">
        <span>网站</span><span>用户名</span><span>状态</span
        ><span>创建时间</span><span>操作</span>
      </div>
      <div
        v-for="account in sftpAccounts"
        :key="account.id"
        class="sftp-row"
        :data-sftp-user="account.username"
      >
        <div class="sftp-site">
          <strong>{{ account.site_name }}</strong
          ><small>{{ account.domain }}</small>
        </div>
        <code>{{ account.username }}</code>
        <span :class="['sftp-status', account.status]">{{
          account.status === "enabled" ? "已启用" : "已停用"
        }}</span>
        <time>{{ date(account.created_at) }}</time>
        <div class="sftp-actions">
          <el-button
            link
            type="primary"
            :icon="Key"
            :disabled="sftpBusy"
            @click="rotateSFTP(account)"
            >重置密码</el-button
          >
          <el-button
            link
            :type="account.status === 'enabled' ? 'warning' : 'success'"
            :disabled="sftpBusy"
            @click="setSFTPStatus(account, account.status !== 'enabled')"
            >{{ account.status === "enabled" ? "停用" : "启用" }}</el-button
          >
          <el-button
            link
            type="danger"
            :disabled="sftpBusy"
            @click="removeSFTP(account)"
            >删除</el-button
          >
        </div>
      </div>
      <el-empty
        v-if="!sftpLoading && !sftpAccounts.length"
        description="尚未创建 SFTP 账户"
        :image-size="72"
      />
    </div>
    <template #footer>
      <el-button :disabled="sftpBusy" @click="sftpOpen = false">关闭</el-button>
    </template>
  </el-dialog>
</template>

<style scoped>
.file-management-layout {
  display: grid;
  grid-template-columns: 235px minmax(0, 1fr) 306px;
  gap: 10px;
  align-items: start;
}
.file-tree-panel,
.file-info-column {
  min-width: 0;
}
.file-side-title {
  height: 45px;
  padding: 0 14px;
  display: flex;
  align-items: center;
  border-bottom: 1px solid #e8edf3;
  color: #10213a;
  font-size: 14px;
  font-weight: 650;
}
.file-tree-root,
.file-tree-site,
.file-tree-children button,
.file-tree-recycle {
  width: 100%;
  min-height: 35px;
  padding: 0 14px;
  display: flex;
  align-items: center;
  gap: 8px;
  color: #455975;
  font-size: 12px;
  text-align: left;
}
.file-tree-root {
  padding-top: 8px;
  border: 0;
  background: transparent;
  cursor: pointer;
}
.file-tree-root.active { color: #079b4e; }
.file-system-tree { max-height: 625px; overflow: auto; }
.file-tree-node { display: flex; align-items: center; min-height: 23px; }
.file-tree-expand { border: 0; background: transparent; width: 19px; padding: 0; font-size: 18px; line-height: 19px; color: #52647d; cursor: pointer; }
.file-tree-link-marker { display: inline-block; flex: 0 0 19px; text-align: center; font-size: 12px; cursor: default; }
.file-tree-directory { min-width: 0; flex: 1; border: 0; background: transparent; display: flex; gap: 5px; align-items: center; padding: 2px 4px; text-align: left; color: #405370; font-size: 12px; cursor: pointer; }
.file-tree-directory:disabled { cursor: not-allowed; color: #7c8ba0; }
.file-tree-directory span { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.file-tree-directory .el-icon { color: #efb52e; }
.file-tree-directory.active { color: #079b4e; background: #e8f8ef; }
.file-image-preview { min-height: 240px; max-height: 70vh; display: flex; align-items: center; justify-content: center; overflow: auto; background: #f5f8fc; }
.file-image-preview img { display: block; max-width: 100%; max-height: 68vh; object-fit: contain; }
.file-image-error { margin: 0; color: #8d3b33; font-size: 13px; }
.file-site-group-title { margin-top: 8px; padding: 9px 14px 5px; border-top: 1px solid #edf1f5; color: #73849a; font-size: 11px; }
.file-readonly-label { padding: 5px 10px; background: #e8f8ef; border-radius: 4px; color: #079b4e; font-size: 12px; }
.file-tree-root .el-icon,
.file-tree-site .el-icon,
.file-tree-children .el-icon {
  color: #efb52e;
}
.file-tree-site {
  padding-left: 28px;
}
.file-tree-site.active {
  background: #e8f8ef;
  color: #079b4e;
}
.file-tree-children button {
  padding-left: 48px;
}
.file-tree-recycle {
  margin-top: 8px;
  border-top: 1px solid #edf1f5;
  color: #687990;
}
.file-info-column {
  display: grid;
  gap: 10px;
}
.file-info-card {
  overflow: hidden;
}
.file-info-folder {
  padding: 15px;
  display: flex;
  align-items: center;
  gap: 10px;
}
.file-info-folder .el-icon {
  color: #efb52e;
  font-size: 25px;
}
.file-info-folder strong {
  color: #182a45;
  font-size: 13px;
  overflow-wrap: anywhere;
}
.file-info-card dl {
  display: grid;
  grid-template-columns: 66px 1fr;
  gap: 10px 7px;
  padding: 0 15px 15px;
  margin: 0;
  font-size: 12px;
}
.file-info-card dt {
  color: #7c8ba0;
}
.file-info-card dd {
  margin: 0;
  color: #3e5270;
  overflow-wrap: anywhere;
}
.file-storage-card {
  padding-bottom: 15px;
}
.file-storage-card .file-side-title { justify-content: space-between; }
.file-storage-card .file-side-title button { border: 0; background: transparent; color: #61758e; font: inherit; font-size: 12px; cursor: pointer; }
.file-storage-card .file-side-title button:hover, .file-storage-card .file-side-title button:focus-visible { color: #079b4e; text-decoration: underline; }
.file-disk-note { margin: 0 0 12px; color: #63748c; font-size: 12px; line-height: 1.6; }
.file-disk-details { border: 1px solid #e5edf4; border-radius: 6px; }
.file-disk-details > div { display: flex; justify-content: space-between; gap: 12px; padding: 10px 12px; border-bottom: 1px solid #edf1f6; color: #63748c; font-size: 13px; }
.file-disk-details strong { color: #263955; }
.file-disk-details > small { display: block; padding: 10px 12px; color: #8592a3; }
.file-disk-error { color: #b24545; font-size: 13px; }
.file-storage-summary { display: flex; align-items: center; gap: 16px; padding: 16px; }
.file-storage-summary > div:last-child { display: grid; gap: 6px; font-size: 12px; color: #52647d; }
.file-storage-summary > div:last-child strong { color: #172b48; font-size: 14px; }
.file-storage-summary small { color: #8796a9; font-size: 11px; }
.file-storage-donut { width: 92px; height: 92px; flex: none; border-radius: 50%; display: grid; place-items: center; }
.file-storage-donut > div { width: 68px; height: 68px; border-radius: 50%; background: #fff; display: flex; flex-direction: column; justify-content: center; align-items: center; }
.file-storage-donut strong { color: #079b4e; font-size: 19px; }
.file-storage-donut small { margin-top: 2px; }
.file-storage-card > strong {
  display: inline-block;
  margin: 14px 4px 10px 16px;
  color: #08ad5b;
  font-size: 28px;
}
.file-storage-card > span {
  color: #73839a;
  font-size: 11px;
}
.file-storage-card .el-progress {
  margin: 0 16px;
}
.file-storage-card p {
  margin: 9px 16px 0;
  color: #8592a3;
  font-size: 10px;
}
.file-quick-actions {
  overflow: hidden;
}
.file-quick-actions button {
  width: 100%;
  height: 39px;
  padding: 0 15px;
  display: flex;
  align-items: center;
  gap: 9px;
  border-bottom: 1px solid #edf1f5;
  color: #445974;
  font-size: 12px;
}
.file-quick-actions button:disabled,
.file-tree-recycle:disabled { opacity: .45; cursor: not-allowed; }
.file-quick-actions .el-icon {
  color: #08ad5b;
  font-size: 16px;
}
.sftp-create-bar {
  display: grid;
  grid-template-columns: minmax(220px, 1fr) minmax(220px, 310px) auto;
  align-items: center;
  gap: 14px;
  padding: 15px;
  border: 1px solid #e5ebf1;
  border-radius: 7px;
  background: #f8fafc;
}
.sftp-create-bar strong {
  color: #172b48;
  font-size: 14px;
}
.sftp-create-bar p {
  margin: 5px 0 0;
  color: #7d8ca1;
  font-size: 11px;
}
.sftp-credential {
  margin-top: 12px;
}
.sftp-credential dl {
  display: grid;
  grid-template-columns: 58px minmax(0, 1fr);
  gap: 8px;
  margin: 10px 0 0;
  font-size: 12px;
}
.sftp-credential dt {
  color: #7d8796;
}
.sftp-credential dd {
  margin: 0;
  min-width: 0;
  color: #42536d;
}
.sftp-credential code,
.sftp-row code {
  color: #152b49;
  overflow-wrap: anywhere;
}
.sftp-table {
  min-height: 160px;
  margin-top: 12px;
  border: 1px solid #e5ebf1;
  border-radius: 7px;
  overflow: hidden;
}
.sftp-row {
  display: grid;
  grid-template-columns: minmax(150px, 1fr) 155px 75px 150px minmax(
      220px,
      auto
    );
  align-items: center;
  gap: 10px;
  min-height: 55px;
  padding: 8px 13px;
  border-bottom: 1px solid #edf1f5;
  color: #566981;
  font-size: 11px;
}
.sftp-row:last-child {
  border-bottom: 0;
}
.sftp-columns {
  min-height: 38px;
  background: #f6f8fa;
  color: #7b899c;
  font-weight: 650;
}
.sftp-site {
  display: grid;
  min-width: 0;
}
.sftp-site strong {
  color: #213753;
  font-size: 12px;
}
.sftp-site small {
  margin-top: 3px;
  color: #8492a4;
  overflow-wrap: anywhere;
}
.sftp-status {
  display: inline-flex;
  width: fit-content;
  padding: 3px 8px;
  border-radius: 4px;
}
.sftp-status.enabled {
  color: #079b4e;
  background: #e2f8ec;
}
.sftp-status.disabled {
  color: #8b97a7;
  background: #eef1f5;
}
.sftp-actions {
  display: flex;
  align-items: center;
  justify-content: flex-end;
  white-space: nowrap;
}
.sftp-actions .el-button + .el-button {
  margin-left: 7px;
}
@media (max-width: 760px) {
  .sftp-create-bar {
    grid-template-columns: 1fr;
  }
  .sftp-row {
    grid-template-columns: 1fr auto;
    gap: 7px 12px;
  }
  .sftp-columns {
    display: none;
  }
  .sftp-site,
  .sftp-actions {
    grid-column: 1 / -1;
  }
  .sftp-actions {
    justify-content: flex-start;
    flex-wrap: wrap;
  }
}
.file-manager {
  overflow: hidden;
  min-height: 752px;
  display: flex;
  flex-direction: column;
}
.file-manager .file-list { flex: 1; }
.file-manager .file-footer { margin-top: auto; }
@media (max-width: 1200px) {
  .file-management-layout {
    grid-template-columns: 205px minmax(0, 1fr);
  }
  .file-info-column {
    grid-column: 1 / -1;
    grid-template-columns: repeat(3, 1fr);
  }
}
@media (max-width: 760px) {
  .file-manager { min-height: 450px; }
  .file-management-layout {
    grid-template-columns: 1fr;
  }
  .file-tree-panel,
  .file-info-column {
    display: none;
  }
}
.file-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 20px;
  padding: 24px;
}
.file-header h2 {
  font-size: 17px;
  margin: 0 0 8px;
  color: #283c39;
}
.file-header p {
  font-size: 13px;
  color: #82908c;
  margin: 0;
}
.site-picker {
  display: flex;
  align-items: center;
  gap: 12px;
  font-size: 12px;
  color: #7a8c84;
  min-width: 0;
}
.site-picker select {
  max-width: 390px;
  min-width: 200px;
  padding: 10px 32px 10px 12px;
  border: 1px solid #dce5df;
  border-radius: 6px;
  background: #fff;
  color: #344c40;
  font: inherit;
  font-size: 13px;
}
.site-picker select:focus {
  outline: 2px solid #3d9873;
}
.file-toolbar {
  border-top: 1px solid #edf1ee;
  padding: 10px 12px;
  display: flex;
  justify-content: space-between;
  gap: 7px;
  flex-wrap: wrap;
}
.file-buttons,
.file-search {
  display: flex;
  align-items: center;
  gap: 4px;
}
.file-toolbar .el-button { padding: 5px 8px; height: 33px; font-size: 12px; }
.file-buttons .el-button + .el-button,
.file-search .el-button + .el-button {
  margin-left: 0;
}
.file-search .el-input {
  width: 158px;
}
.hidden-file-input {
  position: absolute;
  width: 1px;
  height: 1px;
  opacity: 0;
  pointer-events: none;
}
.file-path {
  padding: 14px 24px;
  background: #f7faf8;
  display: flex;
  align-items: center;
  gap: 9px;
  flex-wrap: wrap;
  font-size: 12px;
  color: #8a9b92;
  border-block: 1px solid #edf2ee;
}
.file-path-controls { display: flex; align-items: center; gap: 5px; flex: 1 1 390px; min-width: 240px; }
.file-path .file-path-controls button { width: 28px; height: 31px; justify-content: center; border: 1px solid #dce5ec; border-radius: 5px; background: #fff; color: #344965; font-size: 20px; line-height: 1; flex: none; }
.file-path .file-path-controls button:disabled { color: #b9c5d4; cursor: default; }
.file-path-controls form { min-width: 0; flex: 1; }
.file-path-controls input { width: 100%; height: 31px; padding: 0 10px; border: 1px solid #dce5ec; border-radius: 5px; outline: none; background: #fff; color: #344965; font: 12px/1.4 ui-monospace, monospace; }
.file-path-controls input:focus { border-color: #0aad60; }
:global(html.dark) .file-path-controls input, :global(html.dark) .file-path .file-path-controls button { background: #263548; border-color: #405068; color: #e5ebf3; }
.file-path button {
  border: 0;
  background: transparent;
  color: #52715e;
  cursor: pointer;
  display: flex;
  gap: 6px;
  align-items: center;
  padding: 0;
  font: inherit;
  max-width: 100%;
  overflow-wrap: anywhere;
}
.file-total {
  margin-left: auto;
  color: #98a29c;
  white-space: nowrap;
}
.file-path button:disabled {
  cursor: wait;
}
.file-list {
  min-height: 220px;
}
.file-row {
  display: grid;
  grid-template-columns: 18px minmax(170px, 1fr) 70px 140px 55px 64px 103px;
  gap: 9px;
  align-items: center;
  padding: 17px 24px;
  border-bottom: 1px solid #f0f3f1;
  font-size: 12px;
  color: #75837c;
}
.file-row > input[type="checkbox"] { width: 14px; height: 14px; accent-color: #079b4e; margin: 0; }
.file-row:not(.file-columns):hover {
  background: #fbfdfb;
}
.file-row.inspected { background: #effaf4; }
.file-row:focus-visible { outline: 2px solid #09a05a; outline-offset: -2px; }
.file-columns {
  background: #fcfdfc;
  font-size: 11px;
  padding-block: 12px;
  color: #98a29c;
}
.file-name {
  display: flex;
  align-items: center;
  gap: 12px;
  min-width: 0;
}
.file-name .el-icon {
  font-size: 21px;
  color: #829b92;
  flex-shrink: 0;
}
.file-name .folder { color: #eeb52c; }
.file-name .image { color: #62bb5a; }
.file-name .code { color: #4d6dc0; }
.file-name .markdown { color: #1688d6; }
.file-name button {
  padding: 3px 0;
  background: none;
  border: 0;
  cursor: pointer;
  text-align: left;
  color: #3c5348;
  font: inherit;
  font-size: 13px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.file-name button:disabled {
  cursor: default;
}
.kind-label {
  font-size: 10px;
  color: #a7a99c;
  white-space: nowrap;
}
.file-mode {
  font-family: ui-monospace, monospace;
}
.file-operations {
  display: flex;
  gap: 12px;
  align-items: center;
  justify-content: flex-end;
}
.file-operations .el-button {
  font-size: 12px;
  margin: 0;
}
.file-operations a {
  color: #32996b;
  text-decoration: none;
}
.file-footer {
  padding: 18px 24px;
  display: flex;
  justify-content: space-between;
  gap: 16px;
  align-items: center;
  font-size: 11px;
  color: #99a49e;
}
.upload-status {
  padding: 14px 24px;
  font-size: 12px;
  color: #528168;
  display: grid;
  gap: 8px;
}
.source-path {
  font:
    12px ui-monospace,
    monospace;
  padding: 10px 12px;
  margin: 0 0 16px;
  background: #f4f7f5;
  color: #586b5f;
  border-radius: 5px;
  overflow-wrap: anywhere;
}
.form-help {
  font-size: 12px;
  color: #92a094;
  line-height: 1.8;
  margin-top: 6px;
}
.file-editor :deep(textarea) {
  font:
    13px/1.7 ui-monospace,
    SFMono-Regular,
    Menlo,
    monospace;
  tab-size: 2;
}
.editor-foot {
  display: flex;
  justify-content: space-between;
  gap: 15px;
  font-size: 11px;
  color: #89978c;
  margin-top: 10px;
}
.over-limit {
  color: #dc655c;
}
.file-form-error {
  margin-top: 16px;
}
.trash-note {
  font-size: 12px;
  color: #82918a;
  line-height: 1.8;
  margin: 0 0 15px;
}
.trash-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 15px;
  padding: 15px 0;
  border-bottom: 1px solid #eff2ef;
}
.trash-row > div:first-child {
  min-width: 0;
}
.trash-row strong {
  font-size: 13px;
  overflow-wrap: anywhere;
  color: #466151;
  font-weight: 500;
}
.trash-row p {
  font-size: 11px;
  margin: 7px 0 0;
  color: #90a093;
}
.trash-row > div:last-child {
  display: flex;
  gap: 10px;
  flex-shrink: 0;
}
.trash-row .el-button {
  margin: 0;
  font-size: 12px;
}
.trash-list + .el-pagination {
  margin-top: 18px;
}
@media (max-width: 1100px) {
  .file-row {
    grid-template-columns: 16px minmax(155px, 1fr) 65px 115px 50px 60px 90px;
    gap: 8px;
    padding-inline: 18px;
  }
  .file-date {
    font-size: 11px;
  }
  .site-picker select {
    max-width: 280px;
  }
  .file-toolbar,
  .file-header {
    padding: 18px;
  }
}
@media (max-width: 760px) {
  .file-header {
    align-items: stretch;
    flex-direction: column;
    gap: 18px;
  }
  .site-picker {
    display: grid;
    gap: 8px;
  }
  .site-picker select {
    max-width: 100%;
    width: 100%;
    min-width: 0;
  }
  .file-toolbar {
    display: grid;
    gap: 14px;
  }
  .file-search .el-input {
    width: auto;
    flex: 1;
  }
  .file-search {
    width: 100%;
    min-width: 0;
  }
  .file-buttons {
    flex-wrap: wrap;
  }
  .file-path {
    padding: 14px 18px;
    gap: 7px;
  }
  .file-path-controls { flex-basis: 100%; }
  .file-columns {
    display: none;
  }
  .file-row {
    grid-template-columns: 18px minmax(0, 1fr) auto;
    gap: 7px 14px;
    padding: 15px 18px;
  }
  .file-row > input[type="checkbox"] { grid-column: 1; grid-row: 1; }
  .file-kind { display: none; }
  .file-name {
    grid-column: 2/-1;
    gap: 10px;
  }
  .file-name button {
    white-space: normal;
    overflow-wrap: anywhere;
  }
  .file-size {
    grid-column: 2;
    grid-row: 2;
  }
  .file-mode {
    grid-column: 3;
    grid-row: 2;
    justify-self: end;
  }
  .file-date {
    grid-column: 2;
    grid-row: 3;
    font-size: 10px;
  }
  .file-operations {
    grid-column: 3;
    grid-row: 3;
    gap: 12px;
  }
  .file-operations a,
  .file-operations button {
    padding-block: 8px;
  }
  .file-footer {
    padding: 16px 18px;
    flex-direction: column;
    align-items: flex-start;
  }
  .editor-foot {
    flex-direction: column;
    gap: 7px;
  }
  .trash-row {
    flex-wrap: wrap;
    gap: 6px;
  }
  .trash-row > div:first-child {
    width: 100%;
  }
  .trash-row > div:last-child {
    margin-left: auto;
  }
  .file-row .file-mode:before {
    content: "权限 ";
    font-family: inherit;
    color: #a2aca5;
  }
}
</style>
