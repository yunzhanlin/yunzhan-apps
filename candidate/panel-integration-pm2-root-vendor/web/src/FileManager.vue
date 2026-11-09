<script setup lang="ts">
import { formatPanelDateTime, panelTimeZone } from "./panelTime";
import type { AccessPlan } from "./menuPermissions";
import { apiURL } from "./panelBase";
import circleIcon from "./assets/bootstrap-icons/circle-fill.svg?raw";
import folderIcon from "./assets/bootstrap-icons/folder-fill.svg?raw";
import textFileIcon from "./assets/bootstrap-icons/file-earmark-text-fill.svg?raw";
import codeFileIcon from "./assets/bootstrap-icons/file-earmark-code-fill.svg?raw";
import imageFileIcon from "./assets/bootstrap-icons/file-earmark-image-fill.svg?raw";
import archiveFileIcon from "./assets/bootstrap-icons/file-earmark-zip-fill.svg?raw";
import markdownFileIcon from "./assets/bootstrap-icons/markdown-fill.svg?raw";
import otherFileIcon from "./assets/bootstrap-icons/file-earmark-fill.svg?raw";
import FileToolsMenu from "./FileToolsMenu.vue";
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from "vue";
import { ElMessage, ElMessageBox } from "element-plus";
import {
  Document,
  Upload,
  Plus,
  Delete,
  Connection,
  Key,
  ArrowLeft,
  ArrowRight,
  Top,
  CopyDocument,
  Search,
  Close,
  DocumentAdd,
  FolderAdd,
  Box,
  Lock,
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
  pinned?: boolean;
  size: number;
  mode: string;
  owner?: string;
  modified_at: string;
}
interface Listing {
  entries: Entry[];
  directory?: Entry;
  summary?: DirectorySummary;
  total: number;
  page: number;
  truncated: boolean;
}
interface DirectorySummary {
  directories: number;
  files: number;
  links: number;
  special: number;
  skipped: number;
  truncated: boolean;
  complete: boolean;
}
type StorageState = "complete" | "absent" | "excluded" | "partial" | "unavailable";
interface StorageCategory {
  id: string; label: string; paths: string[]; bytes: number | null; state: StorageState;
  scanned: number; skipped: number; deduplicated: number; foreign_mounts: number;
}
interface StorageUsage {
  filesystem_path: string; disk_total: number; disk_used: number; disk_available: number;
  other_bytes: number | null; categories: StorageCategory[]; complete: boolean; reconciled: boolean;
  scanned: number; limit: number; started_at: string; sampled_at: string; duration_ms: number;
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
interface FileShare {
  id: string;
  site_id: string;
  path: string;
  name: string;
  bytes: number;
  expires_at: number;
  revoked_at: number;
  downloads: number;
}
interface SMTPSettings { host: string; port: number; mode: string; username: string; from: string; enabled: boolean; has_password: boolean; updated_at: string }
interface CloudRemote { id: string; name: string; enabled: boolean; base_url: string }
interface CloudUploadResult { remote_path: string; bytes: number; sha256: string }
const props = defineProps<{
  api: <T>(path: string, method?: string, body?: unknown) => Promise<T>;
  sites: Site[];
  csrf: string;
  initialSiteID: string;
  access?: AccessPlan | null;
}>();
const canReadSystem = computed(() => props.access === undefined || props.access?.role === "admin" && props.access.menu_ids.includes("files"));
const canWriteSite = computed(() => props.access === undefined || !!props.access && props.access.role !== "viewer" && props.access.menu_ids.includes("files"));
const canReadDisk = computed(() => props.access === undefined || props.access?.role === "admin" && props.access.menu_ids.length === 12);
const canUseSharedInfrastructure = canReadDisk;
const emit = defineEmits<{ (event: "open-terminal"): void }>();
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
const storageUsage = ref<StorageUsage | null>(null);
const diskReady = ref(false), diskLoading = ref(false), diskDetailsOpen = ref(false), diskReadAt = ref(0), diskError = ref("");
const directory = ref(""),
  search = ref(""),
  searchSubdirectories = ref(false),
  page = ref(1),
  total = ref(0);
const entries = ref<Entry[]>([]),
  directoryInfo = ref<Entry | null>(null),
  directorySummary = ref<DirectorySummary | null>(null),
  truncated = ref(false),
  loading = ref(false),
  busy = ref(false),
  error = ref("");
const folderSizes = ref<Record<string, number>>({});
const folderSizeBusy = ref("");
const selectedPaths = ref<string[]>([]);
const inspectedPath = ref("");
const showStructure = ref(true), showDetails = ref(true), gridView = ref(false);
const showTabs = ref(false);
const propertiesOpen = ref(false);
function toggleDetails() {
  if (window.matchMedia("(max-width: 1100px)").matches) propertiesOpen.value = true;
  else showDetails.value = !showDetails.value;
}
const pageSize = ref(20), dragDepth = ref(0);
const contextMenu = ref<{ x: number; y: number; entry: Entry } | null>(null);
const fileClipboard = ref<{ site: string; path: string; name: string; cut: boolean } | null>(null);
const inspectedEntry = computed(() => entries.value.find((item) => item.path === inspectedPath.value));
const permissionTarget = computed(() => inspectedEntry.value || directoryInfo.value);
const canModifyPermission = computed(() => canWriteSite.value && !systemMode.value && !busy.value && !!permissionTarget.value && ['file', 'directory'].includes(permissionTarget.value.kind) && !!permissionTarget.value.path && permissionTarget.value.path !== '.');
const selectedEntries = computed(() => entries.value.filter((item) => selectedPaths.value.includes(item.path)));
const singleSelected = computed(() => selectedEntries.value.length === 1 ? selectedEntries.value[0] : undefined);
const dialog = ref(false),
  operation = ref("create"),
  source = ref(""),
  destination = ref(""),
  compressionFormat = ref(".zip"),
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
  if (isArchive(entry)) return "压缩包";
  const extension = name.split(".").pop();
  return ({ php: "PHP 文件", md: "Markdown", xml: "XML 文件", txt: "文本文件", html: "HTML 文件", htm: "HTML 文件", css: "CSS 文件", js: "JavaScript 文件", json: "JSON 文件", zip: "ZIP 压缩包" } as Record<string, string>)[extension || ""] || "文件";
}
function isArchive(entry: Entry) {
  return entry.kind === "file" && /\.(zip|tar|tar\.gz|tgz|tar\.bz2|tbz2|tar\.xz|txz)$/i.test(entry.name);
}
function unpackedName(name: string) {
  return name.replace(/\.(tar\.gz|tar\.bz2|tar\.xz|zip|tar|tgz|tbz2|txz)$/i, "") || "archive";
}
function fileIconClass(entry: Entry) {
  if (entry.kind === "directory") return "folder";
  if (imageType(entry) && entry.kind === "file") return "image";
  const type = fileTypeLabel(entry);
  if (type === "XML 文件") return "xml";
  if (["PHP 文件", "JavaScript 文件", "JSON 文件", "HTML 文件", "CSS 文件"].includes(type)) return "code";
  if (type === "Markdown") return "markdown";
  if (isArchive(entry)) return "archive";
  return "document";
}
function fileIcon(entry: Entry | null | undefined) {
  if (!entry || entry.kind === "directory") return folderIcon;
  if (entry.kind !== "file") return otherFileIcon;
  const type = fileIconClass(entry);
  if (type === "image") return imageFileIcon;
  if (type === "code" || type === "xml") return codeFileIcon;
  if (type === "markdown") return markdownFileIcon;
  if (type === "archive") return archiveFileIcon;
  return textFileIcon;
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
const shareOpen = ref(false), shareEntry = ref<Entry | null>(null), shareHours = ref(24),
  shareBusy = ref(false), shareError = ref(""), shareURL = ref(""), shareURLPath = ref(""), shareList = ref<FileShare[]>([]);
const mailSettings = ref<SMTPSettings | null>(null), mailConfigOpen = ref(false), mailRecipient = ref(""), mailBusy = ref(false), mailError = ref("");
const mailDraft = ref({ host: "", port: 587, mode: "starttls", username: "", from: "", password: "", enabled: true });
let fileDialogEpoch = 0, fileDialogsAlive = true;
function fileDialogCurrent(epoch: number) { return fileDialogsAlive && epoch === fileDialogEpoch; }
function resetSharedFileDialogs() {
  fileDialogEpoch++;
  shareOpen.value = false; shareEntry.value = null; shareURL.value = ""; shareURLPath.value = ""; shareList.value = []; shareError.value = ""; shareBusy.value = false;
  mailConfigOpen.value = false; mailSettings.value = null; mailRecipient.value = ""; mailError.value = ""; mailBusy.value = false;
  mailDraft.value = { host: "", port: 587, mode: "starttls", username: "", from: "", password: "", enabled: true };
  cloudOpen.value = false; cloudEntry.value = null; cloudRemotes.value = []; cloudRemoteID.value = ""; cloudResult.value = null; cloudError.value = ""; cloudBusy.value = false;
}
async function loadMailSettings() {
  if (!canUseSharedInfrastructure.value) { mailSettings.value = null; return; }
  const epoch = fileDialogEpoch;
  const settings = await props.api<SMTPSettings>("/mail/smtp");
  if (!fileDialogCurrent(epoch) || !canUseSharedInfrastructure.value) return;
  mailSettings.value = settings;
  mailDraft.value = { host: settings.host, port: settings.port, mode: settings.mode, username: settings.username, from: settings.from, password: "", enabled: settings.enabled || !settings.host };
}
async function openMailConfig() {
  if (!canUseSharedInfrastructure.value) { ElMessage.info("全局 SMTP 配置需要完整管理员授权"); return; }
  const epoch = fileDialogEpoch;
  mailError.value = "";
  try { await loadMailSettings(); if (fileDialogCurrent(epoch)) mailConfigOpen.value = true; }
  catch (error) { if (fileDialogCurrent(epoch)) mailError.value = (error as Error).message; }
}
async function saveMailConfig() {
  if (!canUseSharedInfrastructure.value || mailBusy.value) return;
  const epoch = fileDialogEpoch;
  mailBusy.value = true;
  mailError.value = "";
  try {
    const result = await props.api<SMTPSettings>("/mail/smtp", "PUT", { ...mailDraft.value });
    if (!fileDialogCurrent(epoch)) return;
    mailSettings.value = result;
    mailDraft.value.password = "";
    mailConfigOpen.value = false;
    ElMessage.success("SMTP 配置已保存");
  } catch (error) { if (fileDialogCurrent(epoch)) mailError.value = (error as Error).message; }
  finally { if (fileDialogCurrent(epoch)) mailBusy.value = false; }
}
async function sendShareMail() {
  if (!canUseSharedInfrastructure.value || !shareURLPath.value || !mailRecipient.value.trim() || mailBusy.value) return;
  const epoch = fileDialogEpoch;
  mailBusy.value = true;
  mailError.value = "";
  try {
    await props.api(`/sites/${siteID.value}/files/shares/send`, "POST", { url_path: shareURLPath.value, recipient: mailRecipient.value.trim() });
    if (fileDialogCurrent(epoch)) ElMessage.success("SMTP 服务器已接收分享邮件");
  } catch (error) { if (fileDialogCurrent(epoch)) mailError.value = (error as Error).message; }
  finally { if (fileDialogCurrent(epoch)) mailBusy.value = false; }
}
const cloudOpen = ref(false), cloudEntry = ref<Entry | null>(null), cloudRemotes = ref<CloudRemote[]>([]),
  cloudRemoteID = ref(""), cloudBusy = ref(false), cloudError = ref(""), cloudResult = ref<CloudUploadResult | null>(null);
watch(() => JSON.stringify([props.csrf, props.access, siteID.value, systemMode.value]), () => {
  if (shareBusy.value || mailBusy.value || cloudBusy.value) ElMessage.warning("站点或授权已变化；已提交操作的结果请在原站点核对");
  resetSharedFileDialogs();
}, { flush: "sync" });
watch(mailConfigOpen, open => { if (!open) mailDraft.value.password = ""; }, { flush: "sync" });
async function openFileCloud(entry: Entry) {
  if (!canUseSharedInfrastructure.value || entry.kind !== "file" || systemMode.value || shareBusy.value || mailBusy.value || cloudBusy.value) return;
  resetSharedFileDialogs(); const epoch = fileDialogEpoch;
  cloudEntry.value = entry;
  cloudResult.value = null;
  cloudError.value = "";
  cloudOpen.value = true;
  try {
    const result = await props.api<{ remotes: CloudRemote[] }>("/backups/remotes");
    if (!fileDialogCurrent(epoch)) return;
    cloudRemotes.value = result.remotes.filter(item => item.enabled);
    cloudRemoteID.value = cloudRemotes.value[0]?.id || "";
  } catch (error) { if (fileDialogCurrent(epoch)) cloudError.value = (error as Error).message; }
}
async function uploadFileCloud() {
  if (!canUseSharedInfrastructure.value || !cloudEntry.value || !cloudRemoteID.value || cloudBusy.value) return;
  const epoch = fileDialogEpoch;
  cloudBusy.value = true;
  cloudError.value = "";
  try {
    const result = await props.api<CloudUploadResult>(`/sites/${siteID.value}/files/cloud-upload`, "POST", { path: cloudEntry.value.path, remote_id: cloudRemoteID.value });
    if (!fileDialogCurrent(epoch)) return;
    cloudResult.value = result;
    ElMessage.success("远端文件与 SHA-256 校验通过");
  } catch (error) { if (fileDialogCurrent(epoch)) cloudError.value = (error as Error).message; }
  finally { if (fileDialogCurrent(epoch)) cloudBusy.value = false; }
}
async function loadFileShares() {
  if (!siteID.value) return;
  const epoch = fileDialogEpoch;
  const result = await props.api<FileShare[]>(`/sites/${siteID.value}/files/shares`);
  if (fileDialogCurrent(epoch)) shareList.value = result;
}
async function openFileShare(entry: Entry) {
  if (!canWriteSite.value || entry.kind !== "file" || systemMode.value || shareBusy.value || mailBusy.value || cloudBusy.value) return;
  resetSharedFileDialogs(); const epoch = fileDialogEpoch;
  shareEntry.value = entry;
  shareHours.value = 24;
  shareURL.value = "";
  shareURLPath.value = "";
  shareError.value = "";
  mailError.value = "";
  shareOpen.value = true;
  try { await Promise.all([loadFileShares(), loadMailSettings()]); } catch (error) { if (fileDialogCurrent(epoch)) shareError.value = (error as Error).message; }
}
async function createFileShare() {
  if (!canWriteSite.value || !shareEntry.value || shareBusy.value) return;
  const epoch = fileDialogEpoch;
  shareBusy.value = true;
  shareError.value = "";
  try {
    const result = await props.api<{ url_path: string; public_url: string }>(`/sites/${siteID.value}/files/shares`, "POST", { path: shareEntry.value.path, expires_hours: Number(shareHours.value) });
    if (!fileDialogCurrent(epoch)) return;
    shareURL.value = result.public_url;
    shareURLPath.value = result.url_path;
    await loadFileShares();
    if (fileDialogCurrent(epoch)) ElMessage.success("分享链接已创建，请立即复制保存");
  } catch (error) { if (fileDialogCurrent(epoch)) shareError.value = (error as Error).message; }
  finally { if (fileDialogCurrent(epoch)) shareBusy.value = false; }
}
async function revokeFileShare(item: FileShare) {
  if (!canWriteSite.value || shareBusy.value) return;
  const epoch = fileDialogEpoch, site = siteID.value;
  shareBusy.value = true;
  shareError.value = "";
  try {
    await ElMessageBox.confirm(`撤销“${item.name}”的分享链接？已有链接将立即失效。`, "撤销分享", { confirmButtonText: "撤销", cancelButtonText: "取消", type: "warning" });
    if (!fileDialogCurrent(epoch) || !canWriteSite.value) return;
    await props.api(`/sites/${site}/files/shares/${item.id}`, "DELETE");
    if (!fileDialogCurrent(epoch)) return;
    shareURL.value = "";
    shareURLPath.value = "";
    await loadFileShares();
    if (fileDialogCurrent(epoch)) ElMessage.success("链接已失效");
  } catch (error) { if (fileDialogCurrent(epoch) && error !== "cancel" && error !== "close") shareError.value = (error as Error).message; }
  finally { if (fileDialogCurrent(epoch)) shareBusy.value = false; }
}
async function copyShareURL() {
  try { await navigator.clipboard.writeText(shareURL.value); ElMessage.success("分享链接已复制"); }
  catch { ElMessage.warning("浏览器无法复制，请手动选择链接"); }
}
const uploadInput = ref<HTMLInputElement>(),
  uploadFolderInput = ref<HTMLInputElement>(),
  uploadProgress = ref(0),
  uploadName = ref("");
let transfer: XMLHttpRequest | undefined;
const uploadCancelled = ref(false);
const uploadSummary = ref("");
const uploadPending = ref<UploadItem[]>([]);
const uploadPendingDirectories = ref<string[]>([]);
const uploadPendingBase = ref("");
let requestSequence = 0;
let listedLocation = "";
const selected = computed(() =>
  available.value.find((s) => s.id === siteID.value),
);
const visiblePath = computed(() => systemMode.value ? systemDirectory.value : `/srv/panel/sites/${siteID.value}/public${directory.value ? "/" + directory.value : ""}`);
const directoryName = computed(() => systemMode.value
  ? systemDirectory.value.split('/').filter(Boolean).at(-1) || '/'
  : directory.value.split('/').filter(Boolean).at(-1) || selected.value?.name || '未选择站点');
const directoryContents = computed(() => {
  const count = directorySummary.value;
  if (!count) return "—";
  const extra = [count.links ? `${count.links} 个链接` : "", count.special ? `${count.special} 个特殊文件` : ""].filter(Boolean);
  return `${count.complete ? "" : "至少 "}${count.directories} 个文件夹，${count.files} 个文件${extra.length ? "，" + extra.join("，") : ""}`;
});
const directoryContentsNote = computed(() => {
  const count = directorySummary.value;
  if (!count) return "尚未读取目录数量";
  return `当前目录直接包含的项目，不受搜索或分页影响${count.truncated ? "；目录超过 10,000 项，仅统计前 10,000 项" : ""}${count.skipped ? `；${count.skipped} 项属性未能读取` : ""}`;
});
const inspectionName = computed(() => inspectedEntry.value?.name || directoryName.value);
const inspectionVisiblePath = computed(() => inspectedEntry.value
  ? systemMode.value ? inspectedEntry.value.path : `/srv/panel/sites/${siteID.value}/public/${inspectedEntry.value.path}`
  : visiblePath.value);
const pathDraft = ref(visiblePath.value);
const pathEditing = ref(false);
const pathInput = ref<HTMLInputElement>();
watch(visiblePath, value => { pathDraft.value = value; });
async function togglePathEditing() {
  pathEditing.value = !pathEditing.value;
  if (pathEditing.value) {
    await nextTick();
    pathInput.value?.focus();
    pathInput.value?.select();
  }
}
interface FileLocation { system: boolean; systemPath: string; site: string; relative: string }
const favoritesKey = "panel-files-favorites-v1";
function savedFavorites(): FileLocation[] {
  try {
    const value = JSON.parse(localStorage.getItem(favoritesKey) || "[]");
    if (!Array.isArray(value)) return [];
    return value.filter((item) => item && typeof item.system === "boolean" && typeof item.systemPath === "string" && typeof item.site === "string" && typeof item.relative === "string").slice(0, 20);
  } catch { return []; }
}
const favorites = ref<FileLocation[]>(savedFavorites());
const currentFavorite = computed(() => favorites.value.some((item) => item.system === systemMode.value && item.systemPath === systemDirectory.value && item.site === siteID.value && item.relative === directory.value));
function saveFavorites() { try { localStorage.setItem(favoritesKey, JSON.stringify(favorites.value)); } catch { ElMessage.warning("浏览器无法保存收藏夹"); } }
function favoriteCommand(command: string) {
  if (command === "toggle") {
    if (currentFavorite.value) favorites.value = favorites.value.filter((item) => !(item.system === systemMode.value && item.systemPath === systemDirectory.value && item.site === siteID.value && item.relative === directory.value));
    else favorites.value = [{ system: systemMode.value, systemPath: systemDirectory.value, site: siteID.value, relative: directory.value }, ...favorites.value].slice(0, 20);
    saveFavorites();
    return;
  }
  const index = Number(command.slice(5));
  const item = favorites.value[index];
  if (!command.startsWith("open:") || !Number.isInteger(index) || !item || busy.value) return;
  if (!item.system && !available.value.some((site) => site.id === item.site)) { ElMessage.warning("收藏的站点已不存在"); return; }
  systemMode.value = item.system;
  systemDirectory.value = item.systemPath;
  siteID.value = item.site;
  directory.value = item.relative;
  search.value = "";
  page.value = 1;
  rememberLocation();
  void load();
}
const contentSearchOpen = ref(false), contentSearchTerm = ref(""), contentSearchBusy = ref(false);
const contentSearchResults = ref<{ path: string; name: string }[]>([]);
const contentSearchNote = ref("");
let contentSearchRun = 0;
async function searchFileContents() {
  const term = contentSearchTerm.value.trim();
  if (systemMode.value || !siteID.value || contentSearchBusy.value) return;
  if (term.length < 2) { ElMessage.warning("至少输入 2 个字符"); return; }
  const run = ++contentSearchRun;
  const site = siteID.value, folder = directory.value;
  contentSearchBusy.value = true;
  contentSearchResults.value = [];
  contentSearchNote.value = "";
  try {
    const listing = await props.api<Listing>(`/sites/${site}/files?` + new URLSearchParams({ path: folder, page: "1", limit: "200" }));
    const candidates = listing.entries.filter((entry) => entry.kind === "file" && entry.size <= 32768);
    let cursor = 0, unreadable = 0;
    const matches: { path: string; name: string }[] = [];
    await Promise.all(Array.from({ length: Math.min(4, candidates.length) }, async () => {
      while (run === contentSearchRun) {
        const entry = candidates[cursor++];
        if (!entry) break;
        try {
          const data = await props.api<{ content: string }>(`/sites/${site}/files/text?path=${encodeURIComponent(entry.path)}`);
          if (data.content.includes(term)) matches.push({ path: entry.path, name: entry.name });
        } catch { unreadable++; }
      }
    }));
    if (run !== contentSearchRun) return;
    contentSearchResults.value = matches.sort((a, b) => a.path.localeCompare(b.path));
    const skipped = listing.entries.length - candidates.length + unreadable;
    contentSearchNote.value = `当前目录已扫描 ${candidates.length} 个不超过 32 KiB 的 UTF-8 文件${skipped ? `，跳过 ${skipped} 个不可读取或较大的项目` : ""}${listing.total > listing.entries.length ? "；仅检查前 200 项" : ""}。`;
  } catch (error) { if (run === contentSearchRun) contentSearchNote.value = (error as Error).message; }
  finally { if (run === contentSearchRun) contentSearchBusy.value = false; }
}
function openContentMatch(hit: { path: string; name: string }) {
  contentSearchOpen.value = false;
  void open("save", { name: hit.name, path: hit.path, kind: "file", size: 0, mode: "0644", modified_at: "" });
}
const history = ref<FileLocation[]>([{ system: systemMode.value, systemPath: systemDirectory.value, site: siteID.value, relative: directory.value }]);
const historyIndex = ref(0);
interface FileTab extends FileLocation { id: number }
let nextTabID = 2;
let switchingTab = false;
const fileTabs = ref<FileTab[]>([{ id: 1, ...history.value[0] }]);
const activeTabID = ref(1);
const pathCrumbs = computed(() => {
  const parts = visiblePath.value.split("/").filter(Boolean);
  return [{ name: "/", path: "/", system: true }, ...parts.map((name, i) => ({
    name,
    path: !systemMode.value && i >= 4 ? parts.slice(5, i + 1).join("/") : "/" + parts.slice(0, i + 1).join("/"),
    system: systemMode.value || i < 4,
  }))];
});
function tabName(tab: FileTab) {
  const value = tab.system ? tab.systemPath : `/srv/panel/sites/${tab.site}/public${tab.relative ? "/" + tab.relative : ""}`;
  return value.split("/").filter(Boolean).at(-1) || "根目录";
}
watch([systemMode, systemDirectory, siteID, directory], () => {
  if (switchingTab) return;
  const tab = fileTabs.value.find(item => item.id === activeTabID.value);
  if (tab) Object.assign(tab, { system: systemMode.value, systemPath: systemDirectory.value, site: siteID.value, relative: directory.value });
});
function switchFileTab(tab: FileTab) {
  if (busy.value || tab.id === activeTabID.value) return;
  switchingTab = true;
  activeTabID.value = tab.id;
  systemMode.value = tab.system;
  systemDirectory.value = tab.systemPath;
  siteID.value = tab.site;
  directory.value = tab.relative;
  search.value = "";
  page.value = 1;
  switchingTab = false;
  void load();
}
function addFileTab() {
  if (busy.value) return;
  const tab: FileTab = { id: nextTabID++, system: true, systemPath: "/", site: siteID.value, relative: "" };
  fileTabs.value.push(tab);
  switchFileTab(tab);
}
function closeFileTab(id: number) {
  if (fileTabs.value.length < 2 || busy.value) return;
  const index = fileTabs.value.findIndex(tab => tab.id === id);
  if (index < 0) return;
  fileTabs.value.splice(index, 1);
  if (activeTabID.value === id) {
    activeTabID.value = -1;
    switchFileTab(fileTabs.value[Math.max(0, index - 1)]);
  }
}
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
  pathEditing.value = false;
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
  compress: "创建压缩包",
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
async function calculateFolderSize(entry: Entry) {
  if (systemMode.value || entry.kind !== "directory" || folderSizeBusy.value) return;
  folderSizeBusy.value = entry.path;
  try {
    const result = await props.api<{ bytes: number; files: number; directories: number; skipped: number }>(
      endpoint("/size") + "?" + new URLSearchParams({ path: entry.path }),
    );
    if (!Number.isSafeInteger(result.bytes) || result.bytes < 0) throw new Error("目录大小读数无效");
    folderSizes.value = { ...folderSizes.value, [entry.path]: result.bytes };
    if (result.skipped) ElMessage.info(`已跳过 ${result.skipped} 个链接或特殊文件`);
  } catch (e) {
    ElMessage.error(`计算目录大小失败：${(e as Error).message}`);
  } finally {
    folderSizeBusy.value = "";
  }
}
function diskSize(n: number) {
  return n >= 1073741824 ? (n / 1073741824).toFixed(1) + " GB" : (n / 1048576).toFixed(1) + " MB";
}
function ownerName(entry?: Entry | null) {
  return entry?.owner === "0" ? "root" : entry?.owner === "33" ? "www-data" : entry?.owner || "—";
}
function validStorageUsage(data: StorageUsage): boolean {
  const bytes = (n: unknown) => Number.isSafeInteger(n) && (n as number) >= 0;
  const counts = (c: StorageCategory) => [c.scanned, c.skipped, c.deduplicated, c.foreign_mounts].every(bytes);
  if (!data || data.filesystem_path !== "/srv/panel" || !bytes(data.disk_total) || data.disk_total <= 0 || !bytes(data.disk_used) || data.disk_used > data.disk_total || !bytes(data.disk_available) || data.disk_available > data.disk_total - data.disk_used || typeof data.complete !== "boolean" || typeof data.reconciled !== "boolean" || !bytes(data.scanned) || !bytes(data.limit) || data.scanned > data.limit || !bytes(data.duration_ms) || !Number.isFinite(Date.parse(data.sampled_at)) || !Number.isFinite(Date.parse(data.started_at))) return false;
  if (!Array.isArray(data.categories) || data.categories.length !== 3) return false;
  const ids = ["websites", "databases", "logs"];
  for (const [i, c] of data.categories.entries()) {
    if (!c || c.id !== ids[i] || !Array.isArray(c.paths) || !c.paths.length || !c.paths.every(path => typeof path === "string" && path.startsWith("/")) || !counts(c) || !["complete", "absent", "excluded", "partial", "unavailable"].includes(c.state) || (c.bytes !== null && !bytes(c.bytes))) return false;
    if ((c.state === "unavailable") !== (c.bytes === null) || (["absent", "excluded"].includes(c.state) && c.bytes !== 0)) return false;
  }
  const complete = data.categories.every(c => ["complete", "absent", "excluded"].includes(c.state));
  const sum = data.categories.reduce((n, c) => n + (c.bytes ?? 0), 0);
  if (!bytes(sum) || data.complete !== complete || data.scanned !== data.categories.reduce((n,c) => n + c.scanned,0) || data.reconciled !== (complete && sum <= data.disk_used)) return false;
  return data.reconciled ? bytes(data.other_bytes) && data.other_bytes === data.disk_used - sum : data.other_bytes === null;
}
const storageRows = computed(() => {
  const labels = ["网站文件", "数据库", "日志文件", "其他占用"];
  const ids = ["websites", "databases", "logs", "other"];
  return ids.map((id, i) => {
    const c = diskReady.value ? storageUsage.value?.categories.find(c => c.id === id) : undefined;
    const amount = id === "other" && diskReady.value ? storageUsage.value?.other_bytes ?? null : c?.bytes ?? null;
    const partial = c?.state === "partial";
    const detail = id === "other" ? "分区已用量减去前三类，包含系统、软件及文件系统开销" : c ? `${c.paths.join("、")}；${storageStateLabel(c)}` : "读数暂不可用";
    return { id, label: labels[i], amount: amount === null ? "—" : `${partial ? "≥ " : ""}${diskSize(amount)}`, percent: amount === null || partial || !storageUsage.value?.reconciled ? "—" : `${(diskUsed.value ? amount / diskUsed.value * 100 : 0).toFixed(1)}%`, detail };
  });
});
function storageStateLabel(c: StorageCategory): string {
  if (c.state === "unavailable") return "未能读取";
  if (c.state === "partial") return "扫描不完整，仅显示已读取的占用";
  if (c.state === "absent") return "目录不存在，占用为零";
  if (c.state === "excluded") return "位于其他挂载，不计入本分区";
  return c.foreign_mounts ? "已排除内部独立挂载" : "读取完成";
}
async function loadDisk() {
  if (!canReadDisk.value) { diskReady.value = false; diskError.value = "当前账户未授权磁盘概览"; return; }
  if (diskLoading.value) return;
  diskLoading.value = true;
  try {
    const data = await props.api<StorageUsage>("/storage/usage");
    if (!validStorageUsage(data)) throw new Error("存储占用读数无效");
    storageUsage.value = data;
    diskUsed.value = data.disk_used;
    diskTotal.value = data.disk_total;
    diskAvailable.value = data.disk_available;
    diskReady.value = true;
    diskReadAt.value = Date.parse(data.sampled_at);
    diskError.value = "";
  } catch (error) {
    diskReady.value = false;
    storageUsage.value = null;
    diskError.value = (error as Error).message || "存储读数暂不可用";
  } finally { diskLoading.value = false; }
}
async function showDiskDetails() {
  diskDetailsOpen.value = true;
  await loadDisk();
}
void loadDisk();
const listDateFormatter = computed(() => new Intl.DateTimeFormat("en-GB", {
  timeZone: panelTimeZone.value,
  year: "numeric", month: "2-digit", day: "2-digit",
  hour: "2-digit", minute: "2-digit", second: "2-digit", hourCycle: "h23",
}));
function listDate(value: string): { day: string; time: string } {
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return { day: "—", time: "" };
  const parts = listDateFormatter.value.formatToParts(parsed);
  const part = (kind: string) => parts.find((item) => item.type === kind)?.value ?? "";
  return { day: `${part("year")}-${part("month")}-${part("day")}`, time: `${part("hour")}:${part("minute")}:${part("second")}` };
}
function date(value: string): string {
  const formatted = listDate(value);
  return formatted.time ? `${formatted.day} ${formatted.time}` : formatted.day;
}
function displayMode(value?: string): string {
  return value ? value.replace(/^0([0-7]{3,4})$/, "$1") : "—";
}
async function load() {
  if (!systemMode.value && !siteID.value) return;
  const seq = ++requestSequence;
  const location = systemMode.value ? `system:${systemDirectory.value}` : `site:${siteID.value}:${directory.value}`;
  if (location !== listedLocation) {
    entries.value = [];
    directoryInfo.value = null;
    directorySummary.value = null;
    inspectedPath.value = "";
    selectedPaths.value = [];
  }
  loading.value = true;
  error.value = "";
  try {
    const result = await props.api<Listing>(
      (systemMode.value ? "/filesystem" : endpoint()) +
        "?" +
        new URLSearchParams({
          path: systemMode.value ? systemDirectory.value : directory.value,
          search: search.value,
          recursive: !systemMode.value && searchSubdirectories.value && search.value.trim() ? "1" : "0",
          page: String(page.value),
          limit: String(pageSize.value),
        }),
    );
    if (seq !== requestSequence) return;
    entries.value = result.entries;
    folderSizes.value = {};
    const availablePaths = new Set(result.entries.map((entry) => entry.path));
    if (!availablePaths.has(inspectedPath.value)) inspectedPath.value = "";
    directoryInfo.value = result.directory || null;
    directorySummary.value = result.summary || null;
    selectedPaths.value = selectedPaths.value.filter((path) => availablePaths.has(path));
    listedLocation = location;
    total.value = result.total;
    page.value = result.page;
    truncated.value = result.truncated;
  } catch (e) {
    if (seq === requestSequence) {
      error.value = (e as Error).message;
      entries.value = [];
      directoryInfo.value = null;
      directorySummary.value = null;
      inspectedPath.value = "";
      selectedPaths.value = [];
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
  if (!canReadSystem.value) return;
  if (busy.value) return;
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
  if (!items.length) {
    siteID.value = "";
    if (!systemMode.value) { requestSequence++; entries.value = []; total.value = 0; clearPreview(); }
    return;
  }
  if (items.some((site) => site.id === siteID.value)) return;
  const next = items.find((site) => site.id === props.initialSiteID) || items.find((site) => site.id === recentSiteID()) || items[0];
  selectSite(next.id);
});
function navigate(path: string) {
  if (busy.value) return;
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
  compressionFormat.value = ".zip";
  source.value = entry?.path || "";
  content.value = "";
  savedContent.value = "";
  digest.value = "";
  mode.value = entry?.mode || "0644";
  formError.value = "";
  destination.value =
    kind === "compress"
      ? join((entry?.name || "archive") + ".zip")
      : kind === "extract"
        ? join(unpackedName(entry?.name || "archive") + "-unpacked")
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
async function newTextDocument() {
  await open('create');
  destination.value = join('新建文本文档.txt');
}
function setCompressionFormat(value: string) {
  const previous = compressionFormat.value;
  compressionFormat.value = value;
  if (operation.value === "compress" && destination.value.toLowerCase().endsWith(previous))
    destination.value = destination.value.slice(0, -previous.length) + value;
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
  if (operation.value === "compress" && !destination.value.toLowerCase().endsWith(compressionFormat.value)) {
    formError.value = `目标文件后缀须为 ${compressionFormat.value}，与所选压缩格式一致。`;
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
    const message = (e as Error).message;
    formError.value = /\bfile exists\b/i.test(message) ? "目标路径已存在，请更换名称或目录" : message;
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
function uploadFile(file: File, path: string, uploadSite: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    transfer = xhr;
    xhr.open(
      "POST",
      apiURL(
        `/sites/${uploadSite}/files/upload` +
        "?path=" +
        encodeURIComponent(path)),
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
    xhr.onerror = () => { transfer = undefined; reject(new Error("上传连接中断")); };
    xhr.ontimeout = () => { transfer = undefined; reject(new Error("上传超时")); };
    xhr.onabort = () => { transfer = undefined; reject(new Error("上传已取消")); };
    xhr.send(file);
  });
}
interface UploadItem { file: File; path: string }
function cancelUpload() {
  uploadCancelled.value = true;
  transfer?.abort();
}
function validUploadPath(value: string) {
  return value.length > 0 && value.length <= 1024 && !value.includes("\\") && value.split("/").every(part => part && part !== "." && part !== ".." && !part.startsWith(".panel-") && !/[\x00-\x1f\x7f]/.test(part));
}
async function uploadItems(items: UploadItem[], directories: string[], base = directory.value) {
  if (!canWriteSite.value || systemMode.value || busy.value || !siteID.value) return;
  if (!items.length && !directories.length) return;
  const targetSite = siteID.value;
  const paths = items.map(item => base ? `${base}/${item.path}` : item.path);
  const dirs = directories.map(path => base ? `${base}/${path}` : path);
  if (items.length > 2000 || items.some(item => item.file.size > 512 * 1024 * 1024) || items.reduce((sum, item) => sum + item.file.size, 0) > 2 * 1024 * 1024 * 1024) {
    ElMessage.error("一次最多上传 2000 个文件、总计 2 GiB，单文件不超过 512 MiB");
    return;
  }
  if ([...paths, ...dirs].some(path => !validUploadPath(path))) {
    ElMessage.error("上传目录包含无效或保留路径");
    return;
  }
  const uniquePaths = new Set(paths);
  if (uniquePaths.size !== paths.length || paths.some(path => dirs.includes(path))) {
    ElMessage.error("本次上传包含同名文件或文件与文件夹重名，请在本地整理后重试");
    return;
  }
  const parents = new Set(dirs);
  for (const path of paths) {
    const parts = path.split("/");
    for (let n = 1; n < parts.length; n++) parents.add(parts.slice(0, n).join("/"));
  }
  if (paths.some(path => parents.has(path))) {
    ElMessage.error("同一批上传中，文件与上级目录重名，请在本地整理后重试");
    return;
  }
  busy.value = true;
  uploadCancelled.value = false;
  uploadSummary.value = "";
  uploadPending.value = [];
  let completed = 0, conflicts = 0, problem = "";
  const conflictNames: string[] = [];
  try {
    for (const path of [...parents].sort((a, b) => a.split("/").length - b.split("/").length)) {
      if (uploadCancelled.value) break;
      await props.api(`/sites/${targetSite}/files/action`, "POST", { action: "mkdirs", path });
    }
    for (let i = 0; i < items.length; i++) {
      if (uploadCancelled.value) { uploadPending.value = items.slice(i); break; }
      uploadName.value = paths[i];
      uploadProgress.value = 0;
      try {
        await uploadFile(items[i].file, paths[i], targetSite);
        completed++;
      } catch (e) {
        const message = (e as Error).message;
        if (uploadCancelled.value) { uploadPending.value = items.slice(i); break; }
        if (/\bfile exists\b/i.test(message) || /目标路径已存在/.test(message)) {
          conflicts++;
          if (conflictNames.length < 3) conflictNames.push(paths[i]);
          continue;
        }
        problem = `${paths[i]}：${message}`;
        uploadPending.value = items.slice(i);
        break;
      }
    }
  } catch (e) {
    problem = (e as Error).message;
    if (!uploadCancelled.value) uploadPending.value = items;
  } finally {
    uploadPendingDirectories.value = uploadPending.value.length || problem ? directories : [];
    uploadPendingBase.value = base;
    uploadSummary.value = `已上传 ${completed} 个文件${dirs.length ? `；目录 ${dirs.length} 个` : ""}${conflicts ? `；跳过 ${conflicts} 个同名文件（${conflictNames.join("、")}${conflicts > conflictNames.length ? "等" : ""}，原文件未覆盖）` : ""}${uploadCancelled.value ? `；已取消，剩余 ${uploadPending.value.length} 个` : ""}${problem ? `；失败：${problem}` : ""}`;
    if (problem) ElMessage.error("上传未完成，详情见上传结果");
    else if (conflicts || uploadCancelled.value) ElMessage.warning(uploadSummary.value);
    else ElMessage.success(uploadSummary.value);
    transfer = undefined;
    uploadName.value = "";
    busy.value = false;
    await load();
  }
}
function retryUpload() {
  if ((!uploadPending.value.length && !uploadPendingDirectories.value.length) || busy.value) return;
  void uploadItems(uploadPending.value, uploadPendingDirectories.value, uploadPendingBase.value);
}
async function uploadChanged(event: Event) {
  const input = event.target as HTMLInputElement;
  const files = Array.from(input.files || []);
  input.value = "";
  if (!files.length) return;
  await uploadItems(files.map(file => ({ file, path: file.webkitRelativePath || file.name })), []);
}
interface DroppedEntry {
  name: string;
  isDirectory: boolean;
  isFile: boolean;
  file?: (success: (file: File) => void, error: (error: Error) => void) => void;
  createReader?: () => { readEntries: (success: (entries: DroppedEntry[]) => void, error: (error: Error) => void) => void };
}
async function collectDropped(event: DragEvent): Promise<{ items: UploadItem[]; dirs: string[] }> {
  const items: UploadItem[] = [], dirs: string[] = [];
  let seen = 0;
  async function walk(entry: DroppedEntry, prefix: string) {
    if (++seen > 2500) throw new Error("拖入项目超过 2500 项");
    const path = prefix ? `${prefix}/${entry.name}` : entry.name;
    if (!validUploadPath(path)) throw new Error("拖入内容包含无效路径");
    if (entry.isDirectory) {
      dirs.push(path);
      if (!entry.createReader) throw new Error("浏览器不支持读取此文件夹");
      const reader = entry.createReader();
      for (;;) {
        const children = await new Promise<DroppedEntry[]>((resolve, reject) => reader.readEntries(resolve, reject));
        if (!children.length) break;
        for (const child of children) await walk(child, path);
      }
    } else if (entry.isFile && entry.file) {
      const file = await new Promise<File>((resolve, reject) => entry.file!(resolve, reject));
      items.push({ file, path });
    }
  }
  const dt = event.dataTransfer;
  if (!dt) return { items, dirs };
  let handledItems = 0;
  for (const item of Array.from(dt.items)) {
    if (item.kind !== "file") continue;
    handledItems++;
    const entry = (item as DataTransferItem & { webkitGetAsEntry?: () => DroppedEntry | null }).webkitGetAsEntry?.();
    if (entry) { await walk(entry, ""); continue; }
    const file = item.getAsFile();
    if (!file) throw new Error("浏览器无法读取拖入的文件");
    if (++seen > 2500 || !validUploadPath(file.name)) throw new Error("拖入项目过多或包含无效路径");
    items.push({ file, path: file.name });
  }
  if (!handledItems) for (const file of Array.from(dt.files)) {
    if (++seen > 2500 || !validUploadPath(file.name)) throw new Error("拖入项目过多或包含无效路径");
    items.push({ file, path: file.name });
  }
  return { items, dirs };
}
function dragOver(event: DragEvent) {
  if (!canWriteSite.value || busy.value || systemMode.value) return;
  event.preventDefault();
  if (event.dataTransfer) event.dataTransfer.dropEffect = event.dataTransfer.types.includes("application/x-yunzhan-file") ? "move" : "copy";
}
function dragStart(event: DragEvent, entry: Entry) {
  if (!canWriteSite.value || systemMode.value || busy.value || entry.kind === "link" || entry.kind === "special") { event.preventDefault(); return; }
  event.dataTransfer?.setData("application/x-yunzhan-file", entry.path);
  if (event.dataTransfer) event.dataTransfer.effectAllowed = "move";
}
async function dropFiles(event: DragEvent, targetDir = directory.value) {
  event.preventDefault();
  event.stopPropagation();
  dragDepth.value = 0;
  if (!canWriteSite.value || systemMode.value || busy.value) return;
  const source = event.dataTransfer?.getData("application/x-yunzhan-file");
  if (source) {
    const entry = entries.value.find(item => item.path === source);
    if (!entry || targetDir === source || targetDir.startsWith(source + "/")) { ElMessage.warning("不能移动到自身目录"); return; }
    const target = targetDir ? `${targetDir}/${entry.name}` : entry.name;
    if (target === source) return;
    busy.value = true;
    try {
      await props.api(endpoint("/action"), "POST", { action: "rename", path: source, destination: target });
      ElMessage.success("已移动到 " + (targetDir || "网站根目录"));
      await load();
    } catch (e) { ElMessage.error((e as Error).message); }
    finally { busy.value = false; }
    return;
  }
  try {
    const { items, dirs } = await collectDropped(event);
    await uploadItems(items, dirs, targetDir);
  } catch (e) { ElMessage.error((e as Error).message); }
}
function downloadFile(entry: Entry) {
  if (entry.kind !== "file" || systemMode.value) return;
  const anchor = document.createElement("a");
  anchor.href = apiURL(endpoint("/download") + "?path=" + encodeURIComponent(entry.path));
  anchor.download = entry.name;
  anchor.click();
}
function copyOrCut(entry: Entry, cut: boolean) {
  if (systemMode.value || !["file", "directory"].includes(entry.kind)) return;
  fileClipboard.value = { site: siteID.value, path: entry.path, name: entry.name, cut };
  ElMessage.success(cut ? "已剪切，可在目标目录粘贴" : "已复制，可在目标目录粘贴");
}
async function pasteFiles(targetDir = directory.value) {
  const item = fileClipboard.value;
  if (!item || busy.value || systemMode.value) return;
  if (item.site !== siteID.value) { ElMessage.warning("暂不支持跨站点粘贴"); return; }
  const destinationPath = targetDir ? `${targetDir}/${item.name}` : item.name;
  if (destinationPath === item.path || destinationPath.startsWith(item.path + "/")) { ElMessage.warning("不能粘贴到自身目录"); return; }
  busy.value = true;
  try {
    await props.api(endpoint("/action"), "POST", { action: item.cut ? "rename" : "copy", path: item.path, destination: destinationPath });
    if (item.cut) fileClipboard.value = null;
    await load();
    ElMessage.success(item.cut ? "移动完成" : "复制完成");
  } catch (e) { ElMessage.error((e as Error).message); }
  finally { busy.value = false; }
}
function openContext(event: MouseEvent, entry: Entry) {
  event.preventDefault();
  inspectedPath.value = entry.path;
  if (!systemMode.value) selectedPaths.value = [entry.path];
  contextMenu.value = { x: Math.min(event.clientX, window.innerWidth - 210), y: Math.min(event.clientY, window.innerHeight - 390), entry };
}
function contextAction(action: string) {
  const entry = contextMenu.value?.entry;
  contextMenu.value = null;
  if (!entry) return;
  if (action === "open") entry.kind === "directory" ? (systemMode.value ? navigateSystem(entry.path) : navigate(entry.path)) : (isArchive(entry) ? void open("extract", entry) : canPreviewImage(entry) ? void previewImage(entry) : void open("save", entry));
  else if (action === "download") downloadFile(entry);
  else if (action === "copy" || action === "cut") copyOrCut(entry, action === "cut");
  else if (action === "paste") void pasteFiles(entry.kind === "directory" ? entry.path : directory.value);
  else command(action, entry);
}
function dismissContext() { contextMenu.value = null; }
onMounted(() => { document.addEventListener("click", dismissContext); document.addEventListener("keydown", escapeContext); });
function escapeContext(event: KeyboardEvent) { if (event.key === "Escape") dismissContext(); }
async function pinEntry(entry: Entry) {
  if (systemMode.value || busy.value || !['file', 'directory'].includes(entry.kind)) return;
  busy.value = true;
  try {
    await props.api(endpoint('/action'), 'POST', { action: entry.pinned ? 'unpin' : 'pin', path: entry.path });
    await load();
    ElMessage.success(entry.pinned ? '已取消置顶' : '已置顶，翻页后仍优先显示');
  } catch (error) { ElMessage.error((error as Error).message); }
  finally { busy.value = false; }
}
function command(kind: string, entry: Entry) {
  if (kind === "trash") void recycle(entry);
  else if (kind === "share") void openFileShare(entry);
  else if (kind === "cloud") void openFileCloud(entry);
  else if (kind === "pin" || kind === "unpin") void pinEntry(entry);
  else if (kind === "copy" || kind === "cut") copyOrCut(entry, kind === "cut");
  else if (kind === "paste") void pasteFiles(entry.path);
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
const fileTools = computed(() => [
  { command: "path", label: pathEditing.value ? "结束路径输入" : "输入文件路径", disabled: busy.value },
  { command: "refresh", label: "刷新当前目录", disabled: busy.value },
  { command: "tree", label: `${showStructure.value ? '隐藏' : '显示'}目录结构`, className: "file-tree-toggle" },
  { command: "info", label: "文件信息" },
  { command: "tabs", label: `${showTabs.value ? '隐藏' : '显示'}文件标签页` },
  { command: "view", label: gridView.value ? "列表视图" : "图标视图" },
  { command: "recursive", label: `${searchSubdirectories.value ? '关闭' : '开启'}子目录搜索`, disabled: busy.value || systemMode.value },
  { command: "content", label: "文件内容搜索", disabled: busy.value || systemMode.value, divided: true },
  { command: "favorite:toggle", label: currentFavorite.value ? "取消收藏当前目录" : "收藏当前目录" },
  ...favorites.value.map((favorite, index) => ({ command: `favorite:open:${index}`, label: tabName({ id: 0, ...favorite }) })),
  { command: "terminal", label: "终端", divided: true },
  { command: "disk", label: "磁盘容量" },
  { command: "sftp", label: "SFTP 账户", disabled: systemMode.value },
  { command: "trash", label: "回收站", disabled: systemMode.value },
  { command: "paste", label: "粘贴", disabled: busy.value || systemMode.value || !fileClipboard.value, divided: true },
]);
function toolbarMore(kind: string) {
  if (kind === "path") void togglePathEditing();
  else if (kind === "refresh") void load();
  else if (kind === "tree") showStructure.value = !showStructure.value;
  else if (kind === "info") toggleDetails();
  else if (kind === "tabs") showTabs.value = !showTabs.value;
  else if (kind === "view") gridView.value = !gridView.value;
  else if (kind === "content") contentSearchOpen.value = true;
  else if (kind === "terminal") emit("open-terminal");
  else if (kind === "trash") void showTrash();
  else if (kind === "recursive") { searchSubdirectories.value = !searchSubdirectories.value; void find(); }
  else if (kind.startsWith("favorite:")) favoriteCommand(kind.slice(9));
  else if (kind === "sftp") void showSFTP();
  else if (kind === "disk") void showDiskDetails();
  else if (kind === "paste") void pasteFiles();
  else if (["compress", "extract", "chmod"].includes(kind)) operateSelected(kind);
}
onBeforeUnmount(() => {
  fileDialogsAlive = false; resetSharedFileDialogs();
  requestSequence++;
  transfer?.abort();
  clearPreview();
  document.removeEventListener("click", dismissContext);
  document.removeEventListener("keydown", escapeContext);
});
</script>

<template>
  <div class="file-management-layout" :class="{ 'with-tree': showStructure, 'with-info': showDetails }">
    <aside v-if="showStructure" class="panel-card file-tree-panel">
      <div class="file-side-title">目录结构</div>
      <button v-if="canReadSystem" class="file-tree-root" :class="{ active: systemMode && systemDirectory === '/' }" @click="navigateSystem('/')">
        <span class="el-icon" aria-hidden="true" v-html="folderIcon" /><strong>/</strong>
      </button>
      <div v-if="canReadSystem" class="file-system-tree">
        <div v-for="node in treeNodes" :key="node.entry.path" class="file-tree-node" :style="{ paddingLeft: `${8 + node.depth * 17}px` }">
          <span v-if="node.entry.kind === 'link'" class="file-tree-expand file-tree-link-marker" aria-hidden="true">↗</span>
          <button v-else class="file-tree-expand" :aria-label="'展开 ' + node.entry.path" @click="toggleTree(node.entry)">{{ expandedPaths.includes(node.entry.path) ? '⌄' : '›' }}</button>
          <button class="file-tree-directory" :class="{ active: (systemMode && systemDirectory === node.entry.path) || (!systemMode && visiblePath === node.entry.path) }" :disabled="node.entry.kind === 'link'" :title="node.entry.kind === 'link' ? '符号链接仅展示，不能进入' : node.entry.path" @click="navigateSystem(node.entry.path)"><span class="el-icon" aria-hidden="true" v-html="folderIcon" /><span>{{ node.entry.name }}</span></button>
        </div>
      </div>
      <div class="file-site-group-title">托管网站目录</div>
      <button
        v-for="site in available"
        :key="site.id"
        :class="['file-tree-site', { active: !systemMode && site.id === siteID }]"
        @click="selectSite(site.id)"
      >
        <span class="el-icon" aria-hidden="true" v-html="folderIcon" /><span>{{ site.name }}</span>
      </button>
      <div v-if="selected && !systemMode" class="file-tree-children">
        <button
          v-for="entry in entries
            .filter((item) => item.kind === 'directory')
            .slice(0, 12)"
          :key="entry.path"
          @click="navigate(entry.path)"
        >
          <span class="el-icon" aria-hidden="true" v-html="folderIcon" /><span>{{ entry.name }}</span>
        </button>
      </div>
      <button class="file-tree-recycle" :disabled="systemMode || !canWriteSite" @click="showTrash">
        <el-icon><Delete /></el-icon>回收站
      </button>
    </aside>
    <section class="panel-card file-manager" :class="{ 'drop-active': dragDepth > 0, 'grid-view': gridView }" @dragenter="dragDepth++" @dragleave="dragDepth = Math.max(0, dragDepth - 1)" @dragover="dragOver" @drop="dropFiles($event)">
      <div v-if="showTabs" class="file-tabs" aria-label="文件标签页">
        <div v-for="tab in fileTabs" :key="tab.id" class="file-tab" :class="{ active: activeTabID === tab.id }">
          <button type="button" class="file-tab-name" @click="switchFileTab(tab)"><span class="el-icon" aria-hidden="true" v-html="folderIcon" />{{ tabName(tab) }}</button>
          <button v-if="fileTabs.length > 1" type="button" class="file-tab-close" :aria-label="`关闭 ${tabName(tab)} 标签`" @click="closeFileTab(tab.id)"><el-icon><Close /></el-icon></button>
        </div>
        <button type="button" class="file-tab-add" aria-label="新建文件标签" title="新建文件标签" @click="addFileTab"><el-icon><Plus /></el-icon></button>
      </div>
      <el-empty v-if="!selected && !systemMode" :description="canReadSystem ? '先创建网站，再管理它的文件。' : '当前账户暂无已授权的可管理网站'" />
      <template v-else>
        <div class="file-path">
          <div class="file-path-controls">
            <button type="button" class="file-path-navigation" aria-label="后退目录" title="后退" :disabled="busy || historyIndex === 0" @click="moveHistory(-1)"><el-icon><ArrowLeft /></el-icon></button>
            <button type="button" class="file-path-navigation" aria-label="前进目录" title="前进" :disabled="busy || historyIndex >= history.length - 1" @click="moveHistory(1)"><el-icon><ArrowRight /></el-icon></button>
            <button type="button" class="file-path-navigation" aria-label="上级目录" title="上级目录" :disabled="busy || (systemMode && systemDirectory === '/')" @click="goParent"><el-icon><Top /></el-icon></button>
            <div class="file-path-location">
              <div v-if="!pathEditing" class="file-breadcrumbs" aria-label="目录路径" :title="visiblePath"><template v-for="(crumb, index) in pathCrumbs" :key="`${crumb.system}:${crumb.path}`"><span v-if="index > 1" class="file-path-separator" aria-hidden="true">/</span><button type="button" :aria-current="index === pathCrumbs.length - 1 ? 'location' : undefined" :disabled="busy" @click="crumb.system ? navigateSystem(crumb.path) : navigate(crumb.path)">{{ crumb.name }}</button></template></div>
              <form v-else class="file-path-entry" @submit.prevent="jumpPath"><input ref="pathInput" v-model="pathDraft" aria-label="文件路径" title="输入服务器绝对路径后回车" spellcheck="false" :disabled="busy" @keydown.esc="pathEditing = false" /></form>
              <button type="button" class="file-path-copy" aria-label="复制文件路径" title="复制文件路径" @click="copyPath"><el-icon><CopyDocument /></el-icon></button>
            </div>
            <FileToolsMenu class="file-tools-inline" compact :items="fileTools" @command="toolbarMore" />
          </div>
        </div>
        <div class="file-toolbar">
          <div class="file-buttons">
            <el-dropdown trigger="click" :disabled="busy || !canWriteSite || systemMode" @command="(kind: string) => kind === 'folder' ? uploadFolderInput?.click() : uploadInput?.click()"><el-button type="primary" :icon="Upload" class="file-toolbar-upload" :disabled="busy || !canWriteSite || systemMode">上传</el-button><template #dropdown><el-dropdown-menu><el-dropdown-item command="file">上传文件</el-dropdown-item><el-dropdown-item command="folder">上传文件夹</el-dropdown-item><el-dropdown-item disabled>将文件或文件夹拖入此页也可上传</el-dropdown-item></el-dropdown-menu></template></el-dropdown>
            <el-button :icon="DocumentAdd" :disabled="busy || !canWriteSite || systemMode" @click="open('create')">新建文件</el-button>
            <el-button :icon="FolderAdd" :disabled="busy || !canWriteSite || systemMode" @click="open('mkdir')">新建文件夹</el-button>
            <el-button :icon="Box" :disabled="busy || !canWriteSite || systemMode || !singleSelected || !['file', 'directory'].includes(singleSelected.kind)" @click="operateSelected('compress')">压缩</el-button>
            <el-button :icon="Box" :disabled="busy || !canWriteSite || systemMode || !singleSelected || !isArchive(singleSelected)" @click="operateSelected('extract')">解压</el-button>
            <el-button :icon="Lock" :disabled="busy || !canWriteSite || systemMode || !singleSelected || !['file', 'directory'].includes(singleSelected.kind)" @click="operateSelected('chmod')">权限</el-button>
            <el-button :icon="Delete" :disabled="busy || !canWriteSite || systemMode || !singleSelected" @click="operateSelected('trash')">删除</el-button>
            <label class="site-picker"><select
            v-model="siteID"
            @change="selectSite(siteID)"
            aria-label="文件管理站点"
            :disabled="busy || dialog || trashOpen"
          ><option v-if="!available.length" value="">暂无托管站点</option><option v-for="site in available" :key="site.id" :value="site.id">{{ site.name }} · {{ site.domain }}</option></select></label>
            <span v-if="systemMode" class="file-readonly-label">只读</span>
          </div>
          <form class="file-search" @submit.prevent="find"><el-input v-model="search" aria-label="搜索文件或目录" :placeholder="searchSubdirectories ? '搜索当前目录及子目录…' : '搜索当前目录文件…'" clearable :disabled="busy" @clear="find"><template #suffix><button type="submit" aria-label="搜索文件" :disabled="busy"><el-icon><Search /></el-icon></button></template></el-input></form>
          <input
            ref="uploadInput"
            class="hidden-file-input"
            type="file"
            multiple
            aria-label="选择上传文件"
            :disabled="!canWriteSite || systemMode || busy"
            @change="uploadChanged"
          />
          <input ref="uploadFolderInput" class="hidden-file-input" type="file" webkitdirectory multiple aria-label="选择上传文件夹" :disabled="!canWriteSite || systemMode || busy" @change="uploadChanged" />
        </div>
        <div v-if="uploadName || uploadSummary" class="upload-status" role="status" aria-live="polite">
          <template v-if="uploadName">
            <div class="upload-status-heading"><span>正在上传 {{ uploadName }} · {{ uploadProgress === 100 ? "正在保存" : uploadProgress + "%" }}</span><el-button size="small" @click="cancelUpload">取消剩余上传</el-button></div>
            <el-progress :percentage="uploadProgress" :show-text="false" />
          </template>
          <div v-else class="upload-status-heading"><span>{{ uploadSummary }}</span><el-button v-if="uploadPending.length || uploadPendingDirectories.length" size="small" @click="retryUpload">重试剩余项目</el-button><el-button size="small" @click="uploadSummary = ''; uploadPending = []; uploadPendingDirectories = []">关闭</el-button></div>
        </div>
        <div v-if="dragDepth > 0 && !systemMode" class="file-drop-overlay" aria-live="polite">将文件或文件夹放到此处上传</div>
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
            :draggable="canWriteSite && !systemMode && !busy && ['file', 'directory'].includes(entry.kind)"
            tabindex="0"
            :aria-label="'查看 ' + entry.name + ' 的文件信息'"
            @click="inspectedPath = entry.path"
            @contextmenu="openContext($event, entry)"
            @dragstart="dragStart($event, entry)"
            @dragover="entry.kind === 'directory' ? dragOver($event) : undefined"
            @drop="entry.kind === 'directory' ? dropFiles($event, entry.path) : undefined"
            @keydown.enter="inspectedPath = entry.path"
            @keydown.space.prevent="inspectedPath = entry.path"
          >
            <input type="checkbox" :aria-label="'选择 ' + entry.name" :disabled="systemMode || busy" :checked="selectedPaths.includes(entry.path)" @change="(event: Event) => selectedPaths = (event.target as HTMLInputElement).checked ? [...selectedPaths, entry.path] : selectedPaths.filter((path) => path !== entry.path)" />
            <div class="file-name" :title="fileTypeLabel(entry)">
              <span class="el-icon file-entry-icon" :class="fileIconClass(entry)" aria-hidden="true" v-html="fileIcon(entry)"></span><button
                :disabled="busy || entry.kind !== 'directory' && (systemMode || entry.kind !== 'file')"
                :title="searchSubdirectories && search.trim() ? entry.path : entry.name"
                @click="
                  entry.kind === 'directory'
                    ? systemMode ? navigateSystem(entry.path) : navigate(entry.path)
                    : isArchive(entry) ? open('extract', entry) : canPreviewImage(entry) ? previewImage(entry) : open('save', entry)
                "
              >
                {{ searchSubdirectories && search.trim() ? entry.path : entry.name }}</button
              ><span v-if="entry.pinned" class="file-pinned" title="此项已置顶">置顶</span
              ><span v-if="entry.kind === 'link'" class="kind-label">链接</span
              ><span v-if="entry.kind === 'special'" class="kind-label"
                >特殊文件</span
              >
            </div>
            <span class="file-size"><button v-if="entry.kind === 'directory' && !systemMode" class="file-size-calculate" :disabled="!!folderSizeBusy" :aria-label="`计算 ${entry.name} 的目录大小`" :title="`计算 ${entry.name} 的目录大小`" @click.stop="calculateFolderSize(entry)">{{ folderSizeBusy === entry.path ? '计算中…' : folderSizes[entry.path] === undefined ? '-' : size(folderSizes[entry.path]) }}</button><template v-else>{{ entry.kind === "directory" ? "—" : size(entry.size) }}</template></span
            ><time class="file-date" :datetime="entry.modified_at"><span>{{ listDate(entry.modified_at).day }}</span> <span class="file-date-clock">{{ listDate(entry.modified_at).time }}</span></time>
            <span class="file-permissions" :title="'所有者：' + ownerName(entry)"><span class="file-mode">{{ displayMode(entry.mode) }}</span></span>
            <span class="file-type">{{ fileTypeLabel(entry) }}</span>
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
                @click="isArchive(entry) ? open('extract', entry) : canPreviewImage(entry) ? previewImage(entry) : open('save', entry)"
                >{{ isArchive(entry) ? '解压' : canPreviewImage(entry) ? '预览' : canWriteSite ? '编辑' : '查看' }}</el-button
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
                v-if="!systemMode"
                :disabled="busy"
                trigger="click"
                @command="(kind: string) => command(kind, entry)"
                ><el-button
                  link
                  type="primary"
                  :disabled="busy"
                  :aria-label="'更多操作 ' + entry.name"
                >更多⌄</el-button><template #dropdown
                  ><el-dropdown-menu
                    ><el-dropdown-item command="rename">重命名</el-dropdown-item
                    ><el-dropdown-item
                      v-if="['file', 'directory'].includes(entry.kind)"
                      command="chmod"
                      >修改权限</el-dropdown-item
                    ><el-dropdown-item
                      v-if="['file', 'directory'].includes(entry.kind)"
                      command="compress"
                      >创建压缩包</el-dropdown-item
                    ><el-dropdown-item v-if="['file', 'directory'].includes(entry.kind)" command="pin">{{ entry.pinned ? '取消置顶' : '置顶' }}</el-dropdown-item
                    ><el-dropdown-item v-if="entry.kind === 'file'" command="share">分享文件</el-dropdown-item
                    ><el-dropdown-item v-if="entry.kind === 'file' && canUseSharedInfrastructure" command="cloud">上传到云存储</el-dropdown-item
                    ><el-dropdown-item v-if="isArchive(entry)" command="extract"
                      >解压到新目录</el-dropdown-item
                    ><el-dropdown-item v-if="['file', 'directory'].includes(entry.kind)" command="copy">复制</el-dropdown-item
                    ><el-dropdown-item v-if="['file', 'directory'].includes(entry.kind)" command="cut">剪切</el-dropdown-item
                    ><el-dropdown-item v-if="entry.kind === 'directory' && fileClipboard" command="paste">粘贴到此文件夹</el-dropdown-item
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
          <div class="file-pagination-summary"><select v-model.number="pageSize" aria-label="每页数量" @change="page = 1; load()"><option :value="20">20条/页</option><option :value="50">50条/页</option><option :value="100">100条/页</option></select><span :title="`当前页 ${entries.filter(item => item.kind === 'directory').length} 个目录，${entries.filter(item => item.kind === 'file').length} 个文件`">共 {{ total }} 条<span v-if="systemMode"> · 服务器目录只读</span></span></div>
          <div class="file-pagination"><el-pagination
            v-model:current-page="page"
            :page-size="pageSize"
            :total="total"
            background
            layout="prev, pager, next"
            :pager-count="5"
            :disabled="busy"
            @current-change="load"
          /><span>共 {{ Math.max(1, Math.ceil(total / pageSize)) }} 页</span></div>
        </div>
      </template>
    </section>
    <aside v-if="showDetails" class="file-info-column">
      <section class="panel-card file-info-card">
        <div class="file-side-title file-info-title">文件信息<FileToolsMenu :items="fileTools" @command="toolbarMore" /></div>
        <div class="file-info-folder">
          <span class="el-icon file-entry-icon" :class="inspectedEntry ? fileIconClass(inspectedEntry) : 'folder'" aria-hidden="true" v-html="fileIcon(inspectedEntry)" /><strong>{{ inspectionName }}</strong>
        </div>
        <dl>
          <dt>类型</dt>
          <dd>{{ inspectedEntry ? fileTypeLabel(inspectedEntry) : systemMode ? '文件夹（只读）' : '文件夹' }}</dd>
          <dt>路径</dt>
          <dd class="file-info-path" :title="inspectionVisiblePath">{{ inspectionVisiblePath }}</dd>
          <dt>大小</dt>
          <dd>{{ inspectedEntry?.kind === 'file' ? size(inspectedEntry.size) : '未计算' }}</dd>
          <template v-if="!inspectedEntry"><dt>包含</dt><dd class="file-directory-contents" :title="directoryContentsNote">{{ directoryContents }}</dd></template>
          <dt>修改时间</dt>
          <dd>{{ inspectedEntry ? date(inspectedEntry.modified_at) : directoryInfo ? date(directoryInfo.modified_at) : '—' }}</dd>
          <dt>权限</dt>
          <dd class="file-info-permission"><span>{{ displayMode(inspectedEntry?.mode || directoryInfo?.mode) }}</span><el-button size="small" type="primary" plain :disabled="!canModifyPermission" :title="systemMode ? '服务器目录为只读' : permissionTarget?.path === '.' ? '托管站点根目录权限由运行环境维护，请选择文件或子目录' : undefined" @click="canModifyPermission && permissionTarget && open('chmod', permissionTarget)">修改权限</el-button></dd>
        </dl>
      </section>
      <section v-if="canReadDisk" class="panel-card file-info-card file-storage-card">
        <div class="file-side-title">存储使用<button type="button" @click="showDiskDetails">查看详情 ›</button></div>
        <div class="file-storage-summary">
          <div class="file-storage-donut" role="img" :aria-label="diskReady ? `分区已使用 ${diskPercent}%` : '分区占用读数暂不可用'">
            <el-progress type="circle" :width="86" :stroke-width="8" :percentage="diskReady ? diskPercent : 0" color="#08ad5b" aria-hidden="true"><strong>{{ diskReady ? `${diskPercent}%` : '—' }}</strong></el-progress>
          </div>
          <div class="file-storage-capacity">
            <div class="file-storage-total">{{ diskReady ? diskSize(diskUsed) : '—' }} / {{ diskReady ? diskSize(diskTotal) : '—' }}</div>
            <div class="file-storage-partition">{{ diskReady ? '面板数据分区' : '读数暂不可用' }}</div>
            <div class="file-storage-key"><span class="el-icon used" aria-hidden="true" v-html="circleIcon" /><span>已使用</span><span>{{ diskReady ? diskSize(diskUsed) : '—' }}</span></div>
            <div class="file-storage-key"><span class="el-icon available" aria-hidden="true" v-html="circleIcon" /><span>可用</span><span>{{ diskReady && diskAvailable !== null ? diskSize(diskAvailable) : '—' }}</span></div>
          </div>
        </div>
        <div class="file-storage-categories" aria-label="存储分类">
          <div v-for="row in storageRows" :key="row.id" :data-storage-category="row.id" :title="row.detail"><span class="file-storage-label"><span class="el-icon" :class="row.id" aria-hidden="true" v-html="circleIcon" />{{ row.label }}</span><span>{{ row.amount }}</span><span>{{ row.percent }}</span></div>
        </div>
        <p v-if="diskReady && !storageUsage?.complete" role="status">部分目录未读完，≥ 表示至少占用；可在详情中刷新。</p>
        <p v-else-if="diskReady && !storageUsage?.reconciled" role="status">分类与分区读数暂未吻合，请稍后刷新。</p>
      </section>
      <section class="panel-card file-quick-actions">
        <div class="file-side-title">快捷操作</div>
        <button :disabled="systemMode || !canWriteSite" @click="open('create')">
          <el-icon><Document /></el-icon>新建文件
        </button>
        <button :disabled="systemMode || !canWriteSite" @click="open('mkdir')">
          <span class="el-icon" aria-hidden="true" v-html="folderIcon" />新建文件夹
        </button>
        <button :disabled="systemMode || !canWriteSite" @click="uploadInput?.click()">
          <el-icon><Upload /></el-icon>上传文件
        </button>
        <button :disabled="systemMode || !canWriteSite" @click="newTextDocument">
          <el-icon><DocumentAdd /></el-icon>新建文本文档
        </button>
      </section>
    </aside>
  </div>
  <div v-if="contextMenu" class="file-context-menu" role="menu" aria-label="文件右键操作" :style="{ left: `${Math.max(8, contextMenu.x)}px`, top: `${Math.max(8, contextMenu.y)}px` }" @click.stop>
    <button v-if="!isArchive(contextMenu.entry)" role="menuitem" :disabled="contextMenu.entry.kind !== 'directory' && systemMode" @click="contextAction('open')">{{ contextMenu.entry.kind === 'directory' ? '打开' : canWriteSite ? '编辑 / 预览' : '查看 / 预览' }}</button>
    <button v-if="contextMenu.entry.kind === 'file' && !systemMode" role="menuitem" @click="contextAction('download')">下载</button>
    <template v-if="!systemMode">
      <button v-if="['file','directory'].includes(contextMenu.entry.kind)" role="menuitem" @click="contextAction('copy')">复制</button>
      <button v-if="['file','directory'].includes(contextMenu.entry.kind)" role="menuitem" @click="contextAction('cut')">剪切</button>
      <button v-if="fileClipboard && contextMenu.entry.kind === 'directory'" role="menuitem" @click="contextAction('paste')">粘贴到此文件夹</button>
      <button role="menuitem" @click="contextAction('rename')">重命名</button>
      <button v-if="['file','directory'].includes(contextMenu.entry.kind)" role="menuitem" @click="contextAction('chmod')">权限</button>
      <button v-if="['file','directory'].includes(contextMenu.entry.kind)" role="menuitem" @click="contextAction('compress')">创建压缩包</button>
      <button v-if="['file','directory'].includes(contextMenu.entry.kind)" role="menuitem" @click="contextAction('pin')">{{ contextMenu.entry.pinned ? '取消置顶' : '置顶' }}</button>
      <button v-if="contextMenu.entry.kind === 'file'" role="menuitem" @click="contextAction('share')">分享文件</button>
      <button v-if="contextMenu.entry.kind === 'file' && canUseSharedInfrastructure" role="menuitem" @click="contextAction('cloud')">上传到云存储</button>
      <button v-if="isArchive(contextMenu.entry)" role="menuitem" @click="contextAction('extract')">解压到新目录</button>
      <button class="danger" role="menuitem" @click="contextAction('trash')">移入回收站</button>
    </template>
    <button role="menuitem" @click="propertiesOpen = true; dismissContext()">属性</button>
  </div>
  <el-dialog v-model="propertiesOpen" title="文件属性" width="min(500px, 94vw)">
    <dl class="file-properties">
      <dt>名称</dt><dd>{{ inspectionName }}</dd>
      <dt>类型</dt><dd>{{ inspectedEntry ? fileTypeLabel(inspectedEntry) : '目录' }}</dd>
      <dt>路径</dt><dd>{{ inspectionVisiblePath }}</dd>
      <template v-if="inspectedEntry?.kind === 'file'"><dt>大小</dt><dd>{{ size(inspectedEntry.size) }}</dd></template>
      <template v-if="!inspectedEntry"><dt>包含</dt><dd class="file-directory-contents" :title="directoryContentsNote">{{ directoryContents }}</dd></template>
      <dt>权限</dt><dd>{{ displayMode(inspectedEntry?.mode || directoryInfo?.mode) }}</dd>
      <dt>所有者</dt><dd>{{ ownerName(inspectedEntry || directoryInfo) }}</dd>
      <dt>修改时间</dt><dd>{{ inspectedEntry ? date(inspectedEntry.modified_at) : directoryInfo ? date(directoryInfo.modified_at) : '—' }}</dd>
    </dl>
    <template #footer><el-button @click="propertiesOpen = false">关闭</el-button></template>
  </el-dialog>
  <el-dialog v-model="shareOpen" title="分享文件" width="min(560px, 94vw)" :close-on-click-modal="false">
    <p>当前文件：{{ shareEntry?.name }}。链接包含独立随机令牌，有效期内可下载创建时的文件快照；撤销后立即失效。公开访问受面板入口的 IP 白名单限制。</p>
    <div class="file-share-form"><el-select v-model="shareHours" aria-label="分享有效期"><el-option label="1 小时" :value="1" /><el-option label="24 小时" :value="24" /><el-option label="7 天" :value="168" /></el-select><el-button type="primary" :loading="shareBusy" @click="createFileShare">创建链接</el-button></div>
    <div v-if="shareURL" class="file-share-url"><el-input :model-value="shareURL" readonly aria-label="新建分享链接" /><el-button @click="copyShareURL">复制链接</el-button></div>
    <div v-if="shareURL && canUseSharedInfrastructure" class="file-share-mail"><el-input v-model="mailRecipient" type="email" maxlength="254" placeholder="收件人邮箱" aria-label="分享邮件收件人" /><el-button type="primary" :loading="mailBusy" :disabled="!mailSettings?.enabled || !mailRecipient.trim()" @click="sendShareMail">发送邮件</el-button><el-button link @click="openMailConfig">SMTP 设置</el-button></div>
    <div v-if="shareURL && !mailSettings?.enabled" class="file-disk-note">要由面板直接发送分享链接，请先配置并启用 SMTP。</div>
    <el-alert v-if="mailError" :title="mailError" type="error" :closable="false" />
    <el-alert v-if="shareError" :title="shareError" type="error" :closable="false" />
    <div class="file-share-history"><strong>此站点的分享记录</strong><div v-for="item in shareList" :key="item.id"><span>{{ item.name }} · {{ item.revoked_at ? '已撤销' : item.expires_at <= Date.now() / 1000 ? '已过期' : '有效至 ' + formatPanelDateTime(item.expires_at * 1000) }} · 下载 {{ item.downloads }} 次</span><el-button v-if="!item.revoked_at" link type="danger" :disabled="shareBusy" @click="revokeFileShare(item)">撤销</el-button></div><small v-if="!shareList.length">暂无分享</small></div>
  </el-dialog>
  <el-dialog v-model="mailConfigOpen" title="SMTP 邮件设置" width="min(520px, 94vw)" append-to-body :close-on-click-modal="false">
    <p>分享邮件由面板通过加密连接发送。密码仅保存在服务器加密数据库中；留空则保留现有密码。</p>
    <el-form label-width="94px" class="file-smtp-form">
      <el-form-item label="服务器"><el-input v-model="mailDraft.host" maxlength="253" placeholder="smtp.example.com" aria-label="SMTP 服务器" /></el-form-item>
      <el-form-item label="端口"><el-input-number v-model="mailDraft.port" :min="1" :max="65535" aria-label="SMTP 端口" /></el-form-item>
      <el-form-item label="加密"><el-select v-model="mailDraft.mode" aria-label="SMTP 加密方式"><el-option label="STARTTLS（通常为 587）" value="starttls" /><el-option label="TLS（通常为 465）" value="tls" /></el-select></el-form-item>
      <el-form-item label="登录账号"><el-input v-model="mailDraft.username" maxlength="254" aria-label="SMTP 登录账号" /></el-form-item>
      <el-form-item label="密码"><el-input v-model="mailDraft.password" type="password" show-password maxlength="4096" :placeholder="mailSettings?.has_password ? '留空保留原密码' : '按服务商要求填写'" aria-label="SMTP 密码" /></el-form-item>
      <el-form-item label="发件邮箱"><el-input v-model="mailDraft.from" type="email" maxlength="254" placeholder="panel@example.com" aria-label="SMTP 发件邮箱" /></el-form-item>
      <el-form-item label="启用"><el-switch v-model="mailDraft.enabled" aria-label="启用 SMTP" /></el-form-item>
    </el-form>
    <el-alert v-if="mailError" :title="mailError" type="error" :closable="false" />
    <template #footer><el-button @click="mailConfigOpen = false">取消</el-button><el-button type="primary" :loading="mailBusy" @click="saveMailConfig">保存设置</el-button></template>
  </el-dialog>
  <el-dialog v-model="cloudOpen" title="上传到云存储" width="min(520px, 94vw)" :close-on-click-modal="false">
    <p>将 {{ cloudEntry?.name }} 上传到已配置的 WebDAV。服务器会读取远端文件核对大小和 SHA-256，重名文件不会被覆盖。</p>
    <div class="file-share-form"><el-select v-model="cloudRemoteID" aria-label="WebDAV 远端" placeholder="选择云存储"><el-option v-for="item in cloudRemotes" :key="item.id" :label="item.name" :value="item.id" /></el-select><el-button type="primary" :loading="cloudBusy" :disabled="!cloudRemoteID" @click="uploadFileCloud">开始上传</el-button></div>
    <p v-if="!cloudRemotes.length && !cloudError">还没有启用的 WebDAV 云存储。请先在“备份”页面添加并测试连接。</p>
    <el-alert v-if="cloudError" :title="cloudError" type="error" :closable="false" />
    <div v-if="cloudResult" class="file-cloud-result">远端位置：{{ cloudResult.remote_path }}<br>大小：{{ cloudResult.bytes }} 字节<br>SHA-256：{{ cloudResult.sha256 }}</div>
  </el-dialog>
  <el-dialog v-model="contentSearchOpen" title="文件内容搜索" width="min(620px, 94vw)" @closed="contentSearchRun++; contentSearchBusy = false">
    <p class="file-search-scope">仅搜索当前受管站点目录的前 200 项；文本文件上限 32 KiB，不读取服务器其他目录。</p>
    <div class="file-content-search-form"><el-input v-model="contentSearchTerm" placeholder="输入要查找的文字" aria-label="文件内容关键词" :disabled="contentSearchBusy" @keyup.enter="searchFileContents" /><el-button type="primary" :loading="contentSearchBusy" @click="searchFileContents">搜索</el-button></div>
    <p v-if="contentSearchNote" class="file-search-scope" role="status">{{ contentSearchNote }}</p>
    <div v-if="contentSearchResults.length" class="file-content-results"><button v-for="hit in contentSearchResults" :key="hit.path" type="button" @click="openContentMatch(hit)"><el-icon><Document /></el-icon><span>{{ hit.path }}</span></button></div>
    <el-empty v-else-if="contentSearchNote && !contentSearchBusy" description="没有匹配的文本文件" :image-size="48" />
  </el-dialog>
  <el-dialog v-model="diskDetailsOpen" title="存储使用详情" width="min(560px, 94vw)" top="8vh">
    <p class="file-disk-note">统计 /srv/panel 所在分区的实际占用，排除独立挂载；硬链接只计一次，符号链接只计自身。分类百分比以分区已用量为基数，运行中的文件可能变化。</p>
    <div v-if="diskReady" class="file-disk-details">
      <div><span>总容量</span><strong>{{ diskSize(diskTotal) }}</strong></div>
      <div><span>已使用</span><strong>{{ diskSize(diskUsed) }}（{{ diskPercent }}%）</strong></div>
      <div><span>可用</span><strong>{{ diskAvailable === null ? '—' : diskSize(diskAvailable) }}</strong></div>
      <div v-for="row in storageRows" :key="row.id"><span>{{ row.label }}</span><strong>{{ row.amount }}（{{ row.percent }}）</strong></div>
      <small>读取时间：{{ formatPanelDateTime(diskReadAt) }}</small>
    </div>
    <div v-if="diskReady && storageUsage" class="file-storage-sources">
      <p v-for="c in storageUsage.categories" :key="c.id"><strong>{{ c.label }}</strong>：{{ c.paths.join('、') }}<br>{{ storageStateLabel(c) }}<span v-if="c.deduplicated">；去重 {{ c.deduplicated }} 项</span><span v-if="c.skipped">；未能读取 {{ c.skipped }} 项</span></p>
      <p>其他占用包含操作系统、软件和文件系统开销，不能等同于其他文件大小。数据库目录内的事务日志归入数据库。</p>
    </div>
    <p v-else class="file-disk-error">{{ diskLoading ? '正在读取磁盘容量…' : diskError }}</p>
    <template #footer><el-button :loading="diskLoading" @click="loadDisk">刷新读数</el-button><el-button type="primary" @click="diskDetailsOpen = false">完成</el-button></template>
  </el-dialog>
  <el-dialog
    v-model="dialog"
    :title="operation === 'save' && !canWriteSite ? '查看文本' : dialogTitles[operation]"
    :width="editing ? 'min(920px, 94vw)' : 'min(540px, 94vw)'"
    :close-on-click-modal="false"
    :before-close="closeDialog"
    destroy-on-close
    class="file-dialog"
  >
    <el-form label-position="top" @submit.prevent="submit">
      <el-form-item v-if="operation === 'compress'" label="压缩格式">
        <el-select :model-value="compressionFormat" aria-label="压缩格式" :disabled="busy" @change="setCompressionFormat">
          <el-option label="ZIP" value=".zip" />
          <el-option label="TAR" value=".tar" />
          <el-option label="TAR.GZ" value=".tar.gz" />
          <el-option label="TAR.BZ2" value=".tar.bz2" />
          <el-option label="TAR.XZ" value=".tar.xz" />
        </el-select>
      </el-form-item>
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
          :readonly="!canWriteSite"
          type="textarea"
          :rows="18"
          resize="vertical"
          aria-label="文件文本内容"
          :disabled="busy"
          spellcheck="false"
          class="file-editor"
        />
        <div class="editor-foot">
          <span>{{
            !canWriteSite
              ? "当前账户仅可查看文件，不能修改或保存。"
              : operation === "save"
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
        title="在当前目录生成 ZIP、TAR、TAR.GZ、TAR.BZ2 或 TAR.XZ，可从文件列表下载。压缩前内容及压缩包均不超过 512 MiB，最多 10,000 项。"
        type="info"
        :closable="false"
      />
      <el-alert
        v-if="operation === 'extract'"
        title="完整检查压缩包后才创建目标目录。解压总大小上限 512 MiB，链接与越界路径会被拒绝。"
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
        v-if="canWriteSite"
        type="primary"
        :loading="busy"
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
          <el-button link type="primary" :disabled="busy" @click="restore(item)"
            >恢复</el-button
          ><el-button link type="danger" :disabled="busy" @click="purge(item)"
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
.file-tree-directory .el-icon, .file-tree-root .el-icon, .file-tree-site .el-icon, .file-tree-children .el-icon { font-size: 16px; }
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
.file-storage-categories { margin: 0 16px; padding-top: 7px; border-top: 1px solid #e5edf4; }
.file-storage-categories > div { display: grid; grid-template-columns: minmax(0, 1fr) auto 48px; gap: 8px; align-items: center; min-height: 23.5px; color: #52647d; font-size: 13px; }
.file-storage-categories > div > span:last-child { text-align: right; }
.file-storage-label { display: flex; align-items: center; gap: 7px; white-space: nowrap; }
.file-storage-label .el-icon { width: 12px; height: 12px; font-size: 12px; flex: none; color: #a8cbd3; }
.file-storage-label .el-icon.websites { color: #4094ef; }
.file-storage-label .el-icon.databases { color: #715bd5; }
.file-storage-label .el-icon.logs { color: #ffb632; }
.file-storage-sources { color: #63748c; font-size: 12px; line-height: 1.6; overflow-wrap: anywhere; }
.file-storage-sources p { margin: 12px 0 0; }
.file-storage-summary { display: flex; align-items: center; gap: 16px; padding: 10px 16px 17px; }
.file-storage-capacity { min-width: 0; display: grid; gap: 5px; font-size: 13px; color: #52647d; }
.file-storage-total { color: #344b6b; white-space: nowrap; }
.file-storage-partition { color: #63748c; font-size: 12px; }
.file-storage-key { display: flex; align-items: center; gap: 6px; white-space: nowrap; }
.file-storage-key .el-icon { width: 12px; height: 12px; font-size: 12px; flex: none; }
.file-storage-key .used { color: #08ad5b; }
.file-storage-key .available { color: #c2cbd6; }
.file-storage-key > span:last-child { margin-left: 3px; }
.file-storage-donut { width: 86px; height: 86px; flex: none; }
.file-storage-donut strong { color: #079b4e; font-size: 20px; font-weight: 600; }
.file-storage-donut .el-progress { margin: 0; }
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
:global(html.dark .file-path-controls input), :global(html.dark .file-path .file-path-controls button) { background: #263548; border-color: #405068; color: #e5ebf3; }
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
.file-entry-icon.folder { color: #eeb52c; }
.file-entry-icon.image { color: #96cc7f; }
.file-entry-icon.code { color: #6658bc; }
.file-entry-icon.xml { color: #86c748; }
.file-entry-icon.document { color: #b7c0ca; }
.file-entry-icon.archive { color: #dbad4b; }
.file-entry-icon.markdown { color: #087bff; }
.file-entry-icon :deep(svg) { width: 100%; height: 100%; }
.file-pinned { color: #0b9f55; background: #e9f7ef; border-radius: 3px; padding: 1px 5px; font-size: 11px; flex-shrink: 0; }
.file-share-form, .file-share-url { display: flex; gap: 10px; margin: 14px 0; }
.file-share-form .el-select { width: 150px; }
.file-share-url .el-input { min-width: 0; }
.file-share-history { border-top: 1px solid #e5ebef; padding-top: 12px; max-height: min(240px, 32vh); overflow-y: auto; overscroll-behavior: contain; }
.file-share-history > div { display: flex; justify-content: space-between; align-items: center; gap: 12px; padding: 7px 0; border-bottom: 1px solid #edf1f3; font-size: 12px; }
.file-share-history > div span { overflow-wrap: anywhere; }
.file-share-mail { display: flex; gap: 8px; align-items: center; margin: 10px 0; }
.file-share-mail .el-input { flex: 1; min-width: 0; }
@media (max-width: 600px) { .file-share-mail { flex-wrap: wrap; } .file-share-mail .el-input { flex-basis: 100%; } }
.file-cloud-result { padding: 10px 12px; border-radius: 4px; background: #edf9f2; color: #176344; font-size: 12px; line-height: 1.8; overflow-wrap: anywhere; }
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
  font-size: 13px;
  margin: 0;
}
.file-operations .el-button.is-link {
  height: auto;
  min-height: 0;
  padding: 0;
  border: 0;
  background: transparent;
  box-shadow: none;
  border-radius: 0;
  color: #08ad5b;
}
.file-operations a {
  color: #08ad5b;
  font-size: 13px;
  text-decoration: none;
}
.file-operations > a, .file-operations > :deep(.el-dropdown) {
  border-left: 1px solid #d8e1ed;
  padding-left: 9px;
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
.upload-status-heading { display: flex; align-items: center; justify-content: space-between; gap: 10px; }
.upload-status-heading span { min-width: 0; overflow-wrap: anywhere; }
.upload-status-heading .el-button { flex: none; }
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

/* Keep the supplied three-column file reference and retain extra tools in its path menu. */
.file-management-layout { grid-template-columns: minmax(0, 1fr); gap: 8px; }
.file-management-layout.with-tree { grid-template-columns: 235px minmax(0, 1fr); }
.file-management-layout.with-info { grid-template-columns: minmax(0, 1fr) 306px; }
.file-management-layout.with-tree.with-info { grid-template-columns: 235px minmax(0, 1fr) 306px; }
.file-management-layout .file-info-column { grid-column: auto; grid-template-columns: 1fr; }
.file-manager { position: relative; min-height: max(520px, calc(100vh - 192px)); background: #fff; }
.file-tree-panel { height: max(520px, calc(100vh - 192px)); overflow-y: auto; }
.file-tabs { display: flex; align-items: end; gap: 2px; min-height: 50px; padding: 0 22px; border-bottom: 1px solid #e6eaf0; overflow-x: auto; }
.file-tab { display: flex; align-items: center; gap: 8px; min-width: 155px; height: 31px; padding: 0 10px; border: 1px solid #dfe5ec; border-bottom-color: transparent; background: #f8fafc; color: #435975; }
.file-tab.active { background: #fff; color: #0aab5e; }
.file-tab-name { border: 0; background: none; color: inherit; font: 15px inherit; flex: 1; min-width: 0; text-align: left; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; cursor: pointer; display: flex; align-items: center; gap: 7px; }
.file-tab-name .el-icon { color: #f0ba36; font-size: 17px; }
.file-tab-close,.file-tab-add { border: 0; background: transparent; color: #667893; font-size: 20px; cursor: pointer; }
.file-tab-add { height: 31px; min-width: 34px; border: 1px solid #dfe5ec; background: #f8fafc; }
.file-path { padding: 10px 16px !important; border: 0 !important; gap: 6px; flex-wrap: nowrap; background: #fff; }
.file-path-controls { flex: 1 1 auto; min-width: 0; gap: 6px; }
.file-path .file-path-controls .file-path-navigation { width: 34px; height: 34px; }
.file-path-location { display: flex; align-items: center; flex: 1; min-width: 0; height: 34px; border: 1px solid #e1e7ee; border-radius: 5px; background: #fff; }
.file-path-location:focus-within { border-color: #0aad60; }
.file-path-location .file-breadcrumbs { border: 0; height: 32px; }
.file-path-location .file-path-entry input { border: 0; height: 32px; }
.file-path .file-path-controls .file-path-location .file-path-copy { width: 34px; height: 32px; border: 0; background: transparent; }
:global(html.dark .file-path-location) { background: var(--panel-surface, #202c3a); border-color: #405068; }
.file-breadcrumbs { flex: 1; min-width: 80px; height: 34px; display: flex; align-items: center; gap: 4px; padding: 0 8px; overflow-x: auto; white-space: nowrap; border: 1px solid #e1e7ee; border-radius: 5px; background: #fff; }
.file-breadcrumbs button { width: auto !important; min-width: fit-content !important; flex: none; height: 30px !important; border: 0 !important; border-radius: 0 !important; padding: 0 3px !important; color: #14233d; font-size: 13px !important; white-space: nowrap !important; overflow-wrap: normal !important; }
.file-breadcrumbs button:first-child, .file-path-separator { color: #71819a; }
.file-path-separator { flex: none; }
.file-breadcrumbs button:hover:not(:disabled) { color: #07964f; }
.file-breadcrumbs button:focus-visible { outline-offset: -2px; }
.file-path-entry { flex: 1; min-width: 0; }
.file-path-entry input { height: 34px; font-family: inherit; font-size: 13px; line-height: 1.4; }
:global(html.dark .file-breadcrumbs) { background: #263548; border-color: #405068; }
:global(html.dark .file-breadcrumbs button) { color: #e5ebf3; }
:global(html.dark .file-breadcrumbs button:first-child), :global(html.dark .file-path-separator) { color: #aab8c9; }
:global(html.dark .file-breadcrumbs button:hover:not(:disabled)) { color: #60dda0; }
.file-toolbar .file-search { flex: 1 0 180px; max-width: 206px; margin-left: auto; min-width: 0; }
.file-toolbar .file-search .el-input { width: 100%; flex: 1; min-width: 0; }
.file-search button { display: grid; place-items: center; border: 0; padding: 2px; background: transparent; color: #627590; font-size: 17px; cursor: pointer; }
.file-search-recursive { display: flex; align-items: center; gap: 4px; flex: none; white-space: nowrap; color: #667890; font-size: 12px; cursor: pointer; }
.file-search-recursive input { width: 14px; height: 14px; margin: 0; accent-color: #0bae5a; }
.file-path .file-search .el-button { margin: 0; }
.file-toolbar { padding: 8px 16px 16px !important; display: flex; flex-wrap: wrap; align-items: center; gap: 6px; border-top: 0; border-bottom: 0; }
.file-buttons { flex-wrap: wrap; white-space: nowrap; gap: 6px; min-width: 0; }
.file-toolbar .el-button { height: 35px; padding: 5px 8px; border-color: #dce4ec; color: #344966; background: #fff; font-size: 14px; }
.file-toolbar .el-button--primary { color: #fff; border-color: #06a854; background: linear-gradient(180deg, #10b862, #05a653); }
.file-toolbar .file-toolbar-upload { width: 78px; }
.file-buttons .site-picker, .file-buttons .file-readonly-label { display: none; }
.file-buttons .site-picker { margin-left: 2px; }
.file-buttons .site-picker select { height: 34px; min-width: 145px; max-width: 230px; padding: 3px 26px 3px 8px; color: #40536c; border-color: #dce4ec; }
:global(html.dark .file-buttons .site-picker select) { color: var(--panel-text, #e5ebf3); }
.file-toolbar-right { margin-left: auto; display: flex; align-items: center; gap: 4px; white-space: nowrap; }
.file-toolbar-right > button:not(.el-button) { width: 32px; height: 34px; border: 1px solid #dce4ec; background: #fff; color: #50617a; cursor: pointer; }
.file-toolbar-right > button.active { border-color: #0bb461; color: #09a452; background: #eaf8ef; }
.file-list { min-height: 360px; overflow-x: auto; margin: 0 16px; }
.file-row { grid-template-columns: 20px minmax(145px, 1fr) 82px 160px 64px 100px 134px; min-width: 760px; gap: 10px; min-height: 34px; padding: 4px 12px !important; font-size: 14px; }
.file-columns { position: sticky; top: 0; z-index: 1; background: #f7f9fb !important; font-size: 14px; font-weight: 600; color: #31445f; }
.file-columns > span:last-child { text-align: right; }
.file-name { gap: 13px; padding-left: 4px; }
.file-columns > span:first-of-type { padding-left: 4px; }
.file-name .el-icon { font-size: 19px; }
.folder-icon { display: flex; width: 100%; height: 100%; }
.folder-icon :deep(svg) { width: 100%; height: 100%; }
.file-side-title { font-size: 18px; }
.file-info-title { justify-content: space-between; }
.file-management-layout.with-info .file-tools-inline { display: none; }
.file-path-controls .file-tools-inline :deep(button) { width: 34px; height: 34px; }
.file-tree-directory, .file-tree-root, .file-tree-site, .file-tree-children button, .file-tree-recycle { font-size: 14px; }
.file-info-folder strong, .file-info-card dl { font-size: 14px; }
.file-info-card dl { gap: 4px 7px; padding-bottom: 13px; }
.file-info-path { min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.file-info-permission { display: flex; align-items: center; justify-content: space-between; gap: 8px; }
.file-info-permission .el-button { height: 28px; padding: 0 8px; font-size: 13px; }
.file-quick-actions button { height: 34px; font-size: 14px; }
.file-size-calculate:not(:hover):not(:focus-visible) { color: inherit; }
.file-name button { font-size: 14px; }
.file-size-calculate { border: 0; padding: 0; background: transparent; color: #0aa651; font: inherit; cursor: pointer; white-space: nowrap; }
.file-size-calculate:hover { text-decoration: underline; }
.file-size-calculate:disabled { color: #8895a8; cursor: wait; }
.file-protection,.file-note { color: #8d99aa; }
.file-permissions { white-space: nowrap; color: #475a72; }
.file-mode { font-family: inherit; }
.file-date { display: block; line-height: 1.4; white-space: nowrap; }
.file-type { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.file-operations { white-space: nowrap; gap: 9px; }
.file-footer { min-height: 70px; padding: 10px 16px; border-top: 0; color: #40536c; font-size: 13px; align-items: center; }
.file-pagination { margin-left: auto; display: flex; align-items: center; gap: 14px; white-space: nowrap; }
.file-pagination-summary { display: flex; align-items: center; gap: 16px; }
.file-pagination-summary select { height: 34px; border: 1px solid #dce4ec; border-radius: 4px; background: var(--panel-surface, #fff); color: var(--panel-text, #445875); padding: 0 12px; font: inherit; }
.file-pagination :deep(.el-pagination) { --el-pagination-button-width: 34px; --el-pagination-button-height: 34px; }
.file-pagination :deep(.btn-prev), .file-pagination :deep(.btn-next), .file-pagination :deep(.el-pager li) { border: 1px solid var(--panel-border, #dce4ec); border-radius: 4px; background: var(--panel-surface, #fff); color: var(--panel-text, #445875); }
.file-pagination :deep(.el-pager li.is-active) { border-color: var(--el-color-primary); background: var(--el-color-primary); color: #fff; }
.file-pagination :deep(.el-pagination.is-background button:disabled) { background: var(--panel-surface, #fff); color: var(--el-text-color-placeholder); }
.file-drop-overlay { position: absolute; inset: 60px 12px 12px; z-index: 8; pointer-events: none; display: grid; place-items: center; border: 2px dashed #0cae5c; background: #eafbf1dd; color: #087e44; font-size: 20px; font-weight: 600; }
.file-search-scope { margin: 0 0 12px; color: #687a90; font-size: 12px; line-height: 1.6; }
.file-content-search-form { display: flex; gap: 10px; margin-bottom: 12px; }
.file-content-search-form .el-input { flex: 1; }
.file-content-results { max-height: 320px; overflow: auto; display: grid; border-top: 1px solid #e5ebf1; }
.file-content-results button { display: flex; align-items: center; gap: 8px; min-width: 0; padding: 10px 6px; border: 0; border-bottom: 1px solid #e5ebf1; background: #fff; color: #0a9e52; text-align: left; cursor: pointer; }
.file-content-results button:hover { background: #f0faf4; }
.file-content-results span { overflow-wrap: anywhere; }
.file-properties { display: grid; grid-template-columns: 64px minmax(0, 1fr); gap: 14px 12px; margin: 0; line-height: 1.6; }
.file-properties dt { color: var(--el-text-color-secondary); }
.file-properties dd { margin: 0; overflow-wrap: anywhere; color: var(--el-text-color-primary); }
.file-context-menu { position: fixed; z-index: 5000; width: 195px; max-height: 75vh; overflow-y: auto; padding: 5px; border: 1px solid #dfe6ee; border-radius: 5px; box-shadow: 0 9px 28px #14263b2b; background: #fff; display: grid; }
.file-context-menu button { border: 0; border-radius: 3px; min-height: 31px; padding: 5px 11px; color: #34475f; text-align: left; font: 12px inherit; background: transparent; cursor: pointer; }
.file-context-menu button:hover { background: #edf8f1; color: #079a50; }
.file-context-menu button.danger { color: #d34848; }
.file-context-menu button:disabled { color: #aab5c2; cursor: default; }
@media (max-width: 760px) { .file-list { margin: 0; } }
.grid-view .file-list { display: grid; grid-template-columns: repeat(auto-fill, minmax(145px, 1fr)); gap: 12px; align-content: start; padding: 18px; }
.grid-view .file-list .file-columns { display: none; }
.grid-view .file-row:not(.file-columns) { min-width: 0; min-height: 135px; display: flex; flex-direction: column; align-items: stretch; justify-content: center; border: 1px solid #e3e9ef; border-radius: 5px; padding: 12px !important; text-align: center; }
.grid-view .file-row > input,.grid-view .file-permissions,.grid-view .file-date,.grid-view .file-type,.grid-view .file-operations { display: none; }
.grid-view .file-name { flex-direction: column; gap: 7px; }
.grid-view .file-name .el-icon { font-size: 37px; }
.grid-view .file-name button { max-width: 100%; text-align: center; }
.grid-view .file-size { text-align: center; }
@media (min-width: 1101px) and (max-width: 1480px) {
  .file-management-layout.with-tree.with-info { grid-template-columns: 205px minmax(0, 1fr); }
  .file-management-layout .file-info-column { grid-column: 1 / -1; grid-template-columns: repeat(3, minmax(0, 1fr)); }
}
@media (max-width: 1480px) {
  .file-management-layout.with-info .file-tools-inline { display: inline-flex; }
  .file-info-title :deep(.file-tools-menu) { display: none; }
}
@media (max-width: 1100px) {
  .file-management-layout.with-tree,.file-management-layout.with-info,.file-management-layout.with-tree.with-info { grid-template-columns: minmax(0,1fr); }
  .file-tree-panel,.file-info-column { display: none !important; }
  :global(.file-tree-toggle) { display: none; }
  .file-buttons .site-picker { display: flex; }
}
@media (max-width: 760px) {
  .file-tabs { padding-inline: 12px; }
  .file-path { padding: 10px 12px !important; display: grid; }
  .file-path-controls { min-width: 0; width: 100%; }
  .file-path-controls { gap: 5px; }
  .file-path .file-path-controls .file-path-navigation { width: 28px; height: 31px; }
  .file-path-controls .file-tools-inline :deep(button) { width: 28px; height: 31px; }
  .file-toolbar .file-search { width: 100%; max-width: none; margin-left: 0; }
  .file-toolbar { padding: 10px 12px !important; display: grid; overflow: visible; }
  .file-buttons { flex-wrap: wrap; white-space: normal; }
  .file-buttons .site-picker { order: -1; width: 100%; margin: 0 0 3px; }
  .file-buttons .site-picker select { width: 100%; max-width: none; }
  .file-toolbar-right { margin-left: 0; justify-content: flex-end; }
  .upload-status { padding: 10px 12px; }
  .upload-status-heading { align-items: flex-start; flex-wrap: wrap; }
  .file-row { min-width: 0; grid-template-columns: 20px minmax(0, 1fr) auto; gap: 8px 10px; padding: 12px !important; }
  .file-columns,.file-type { display: none; }
  .file-row > input[type="checkbox"] { grid-column: 1; grid-row: 1; }
  .file-name { grid-column: 2 / 4; grid-row: 1; }
  .file-size { grid-column: 2; grid-row: 2; }
  .file-permissions { grid-column: 3; grid-row: 2; justify-self: end; }
  .file-date { grid-column: 2; grid-row: 3; font-size: 12px; }
  .file-date-clock { display: block; }
  .file-operations { grid-column: 3; grid-row: 3; justify-self: end; }
  .file-footer { flex-wrap: wrap; padding: 12px; }
  .file-pagination { margin-left: 0; }
}
</style>
