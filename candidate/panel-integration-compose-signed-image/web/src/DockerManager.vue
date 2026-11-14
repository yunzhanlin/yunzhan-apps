<script setup lang="ts">
import { formatPanelDateTime } from "./panelTime";
import DockerContainerMetrics from "./DockerContainerMetrics.vue";
import RabbitMQQueues from "./RabbitMQQueues.vue";
import { randomId } from "./randomId";
import { composeHostPortSettings, isComposeHostPort, isPhpMyAdminTemplate } from "./composeHostPorts";
import { canBindDockerProjectSite } from "./dockerProjectSiteBinding";
import { dockerCreateFingerprint, dockerCreateStorageKey, readDockerCreateRequest, type RetainedDockerCreate } from "./dockerCreateRequest";
import { computed, ref, watch, onBeforeUnmount } from "vue";
import { canOpenAppModule, type AccessPlan } from "./menuPermissions";
import { ElMessage, ElMessageBox } from "element-plus";
import {
  Box,
  Delete,
  Document,
  Plus,
  Refresh,
  VideoPlay,
} from "@element-plus/icons-vue";

interface Overview {
  available: boolean;
  active: boolean;
  version: string;
  api_version: string;
  architecture: string;
  containers: number;
  running: number;
  stopped: number;
  images: number;
  storage_driver: string;
  data_root: string;
}
interface DockerContainer {
  Id: string;
  Names: string[];
  Image: string;
  ImageID: string;
  Command: string;
  Created: number;
  State: string;
  Status: string;
  Ports: {
    IP: string;
    PrivatePort: number;
    PublicPort: number;
    Type: string;
  }[];
  Labels: Record<string, string>;
  PanelProtected?: boolean;
  PanelProtectionReason?: string;
}
interface DockerImage {
  Id: string;
  RepoTags: string[];
  RepoDigests: string[];
  Created: number;
  Size: number;
  Containers: number;
}
interface DockerNetwork {
  Id: string;
  Name: string;
  Driver: string;
  Scope: string;
  Internal: boolean;
  Attachable: boolean;
  Labels: Record<string, string> | null;
  Containers: Record<string, unknown> | null;
}
interface DockerVolume {
  Name: string;
  Driver: string;
  Mountpoint: string;
  Scope: string;
  Labels: Record<string, string> | null;
}
interface DockerProject {
  id: string;
  name: string;
  engine_name: string;
  services: number;
  containers: number;
  running: number;
  state: string;
  template_id?: string;
  initial_credentials?: boolean;
  mysql_server_id?: string;
  healthy?: number;
  host_port?: number;
  site_name?: string;
  created_at: string;
}

const credentialTemplates = {
  rabbitmq: {
    usernameKey: "RABBITMQ_DEFAULT_USER", passwordKey: "RABBITMQ_DEFAULT_PASS",
    defaultUsername: "", primary: "管理界面（HTTP）", secondary: "消息连接（AMQP）",
  },
  mongodb: {
    usernameKey: "MONGO_INITDB_ROOT_USERNAME", passwordKey: "MONGO_INITDB_ROOT_PASSWORD",
    defaultUsername: "", primary: "数据库连接（MongoDB）", secondary: null,
  },
  openlitespeed: {
    usernameKey: null, passwordKey: "CLOUDSTACK_ADMIN_PASSWORD",
    defaultUsername: "admin", primary: "网站（HTTP）", secondary: "WebAdmin 管理端口",
  },
  elasticsearch: {
    usernameKey: null, passwordKey: "ELASTIC_PASSWORD",
    defaultUsername: "elastic", primary: "检索接口（HTTP）", secondary: null,
  },
} as const;

type CredentialTemplate = keyof typeof credentialTemplates | "openlitespeed-194";
interface CredentialDetails {
  projectName: string;
  template: CredentialTemplate;
  username: string;
  password: string;
  endpoints: { label: string; address: string }[];
}

const credentialsOpen = ref(false);
const credentials = ref<CredentialDetails>();
const credentialsLoading = ref(false);
const credentialsError = ref("");
const passwordVisible = ref(false);

function isCredentialTemplate(value?: string): value is CredentialTemplate {
  return value === "openlitespeed-194" || (value !== undefined && Object.hasOwn(credentialTemplates, value));
}

function readCredentials(item: DockerProject, value: unknown): CredentialDetails {
  const template = item.template_id;
  if (!isCredentialTemplate(template) || !value || typeof value !== "object") {
    throw new Error("无法核对项目凭据");
  }
  const response = value as Record<string, unknown>;
  const definition = credentialTemplates[template === "openlitespeed-194" ? "openlitespeed" : template];
  const port = response.host_port;
  const fields = response.credentials;
  if (response.project_id !== item.id || response.template_id !== template ||
      !isComposeHostPort(template, port) ||
      (item.host_port && port !== item.host_port) || !fields || typeof fields !== "object") {
    throw new Error("无法核对项目凭据");
  }
  const secrets = fields as Record<string, unknown>;
  const username = definition.usernameKey ? secrets[definition.usernameKey] : definition.defaultUsername;
  const password = secrets[definition.passwordKey];
  if (typeof username !== "string" || !username || typeof password !== "string" || !password) {
    throw new Error("项目缺少初始账号或密码");
  }
  const endpoints: CredentialDetails["endpoints"] = [{ label: definition.primary, address: `127.0.0.1:${port}` }];
  if (definition.secondary) endpoints.push({ label: definition.secondary, address: `127.0.0.1:${port + 1}` });
  return { projectName: item.name, template, username, password, endpoints };
}

interface DockerTemplate {
  compatibility_detail?: string;
  id: string;
  name: string;
  image: string;
  description: string;
  container_port: number;
}
interface DockerJob {
  job_id: string;
  kind?: string;
  project_id?: string;
  state: string;
  error?: string;
  message?: string;
  container_id?: string;
  image?: string;
}
const props = defineProps<{
  api: <T>(path: string, method?: string, body?: unknown, idempotencyKey?: string) => Promise<T>;
  csrf: string;
  access: AccessPlan | null;
}>();
const visible = ref(false),
  loading = ref(false),
  busy = ref(false),
  tab = ref("projects"),
  overview = ref<Overview | null>(null),
  containers = ref<DockerContainer[]>([]),
  images = ref<DockerImage[]>([]),
  projects = ref<DockerProject[]>([]),
  networks = ref<DockerNetwork[]>([]),
  volumes = ref<DockerVolume[]>([]),
  templates = ref<DockerTemplate[]>([]),
  createOpen = ref(false),
  projectOpen = ref(false),
  bindingOpen = ref(false),
  bindingProject = ref<DockerProject | null>(null),
  networkOpen = ref(false),
  logsOpen = ref(false),
  logs = ref(""),
  logsName = ref("");
const managedTemplate = ref<"phpmyadmin">();
const metricsContainer = ref<DockerContainer>();
const rabbitQueues = ref<DockerProject>();
const visibleProjects = computed(() =>
  managedTemplate.value ? projects.value.filter(project => isPhpMyAdminTemplate(project.template_id)) : projects.value,
);

function openRabbitQueues(item: DockerProject) {
  if (contextCurrent(contextToken()) && item.template_id === "rabbitmq" && item.state === "running" && /^[a-f0-9]{32}$/.test(item.id)) {
    rabbitQueues.value = item;
  }
}

function phpMyAdminURL(project: DockerProject): string {
  if (!isPhpMyAdminTemplate(project.template_id) || project.state !== "running" ||
      project.services !== 1 || project.running !== 1 || project.healthy !== 1 ||
      !isComposeHostPort("phpmyadmin", project.host_port)) return "";
  return `http://127.0.0.1:${project.host_port}/`;
}

const projectForm = ref({
  name: "",
  mode: "template",
  templateId: "nginx-static",
  hostPort: "18080",
  compose:
    "services:\n  app:\n    image: alpine:3.22\n    restart: unless-stopped\n",
});
const projectPorts = computed(() => composeHostPortSettings(projectForm.value.templateId));
const bindingForm = ref({ name: "", slug: "", domain: "" });
const networkForm = ref({ name: "", internal: false });
const form = ref({
  name: "",
  image: "",
  restart: "unless-stopped",
  hostPort: "",
  containerPort: "",
  protocol: "tcp",
  command: "",
  environment: "",
});
const pendingCreate=ref<RetainedDockerCreate|null>(null),originalCreateJob=ref<DockerJob|null>(null),createRecoveryError=ref(""),createBlocked=ref(false);
const createActor=()=>(props.access as (AccessPlan & {user_id?:string})|null)?.user_id||"";
let managerEpoch = 0, alive = true, resetting = false, loadSequence = 0, logSequence = 0, credentialSequence = 0, bindingEpoch = 0, projectEpoch=0, busySequence = 0;
const authority = () => JSON.stringify([props.csrf, props.access]);
function contextToken() { return { epoch: managerEpoch, authority: authority() }; }
function contextCurrent(token: ReturnType<typeof contextToken>) {
  return alive && visible.value && Boolean(props.csrf) && canOpenAppModule(props.access, "docker-manager") && token.epoch === managerEpoch && token.authority === authority();
}
class ObsoleteContext extends Error {}
function contextAPI(token: ReturnType<typeof contextToken>, current = () => true) {
  return async <T>(path: string, method?: string, body?: unknown, key?: string): Promise<T> => {
    if (!contextCurrent(token) || !current()) throw new ObsoleteContext();
    const value = await props.api<T>(path, method, body, key);
    if (!contextCurrent(token) || !current()) throw new ObsoleteContext();
    return value;
  };
}
function startBusy() { busy.value = true; return ++busySequence; }
function finishBusy(token: ReturnType<typeof contextToken>, ticket: number) { if (contextCurrent(token) && ticket === busySequence) busy.value = false; }
function reportError(token: ReturnType<typeof contextToken>, error: unknown) {
  if (contextCurrent(token) && !(error instanceof ObsoleteContext) && error instanceof Error && error.message) ElMessage.error(error.message);
}
function resetManager() {
  if (resetting) return;
  resetting = true;
  try {
    managerEpoch++; loadSequence++; logSequence++; credentialSequence++; bindingEpoch++; busySequence++;
    visible.value = false; loading.value = false; busy.value = false;
    managedTemplate.value = undefined;
    overview.value = null; containers.value = []; images.value = []; projects.value = []; networks.value = []; volumes.value = []; templates.value = [];
    credentialsOpen.value = false; clearCredentials(); logsOpen.value = false; logs.value = ""; logsName.value = ""; metricsContainer.value = undefined; rabbitQueues.value = undefined;
    createOpen.value = false; projectOpen.value = false; bindingOpen.value = false; networkOpen.value = false; bindingProject.value = null;
    form.value = { name: "", image: "", restart: "unless-stopped", hostPort: "", containerPort: "", protocol: "tcp", command: "", environment: "" };
    projectForm.value = { name: "", mode: "template", templateId: "nginx-static", hostPort: "18080", compose: "" };
    bindingForm.value = { name: "", slug: "", domain: "" }; networkForm.value = { name: "", internal: false };
    pendingCreate.value=null;originalCreateJob.value=null;createRecoveryError.value="";createBlocked.value=false;
    // Already submitted jobs and retained original requests belong to the server/history.
    // Closing this UI must neither cancel them nor discard/replay their request keys.
  } finally { resetting = false; }
}
watch(() => [props.csrf, JSON.stringify(props.access)], resetManager, { flush: "sync" });
watch(visible, value => { if (!value) resetManager(); }, { flush: "sync" });
function clearCredentials() {
  credentials.value = undefined;
  credentialsLoading.value = false;
  credentialsError.value = "";
  passwordVisible.value = false;
}
watch(credentialsOpen, value => {
  if (!value) {
    credentialSequence++;
    clearCredentials();
  }
}, { flush: "sync" });
watch(logsOpen, value => { if (!value) { logSequence++; logs.value = ""; logsName.value = ""; } }, { flush: "sync" });
watch(() => [bindingOpen.value, bindingProject.value?.id], () => { bindingEpoch++; }, { flush: "sync" });
watch(projectOpen,()=>{projectEpoch++;},{flush:"sync"});
onBeforeUnmount(() => { alive = false; resetManager(); });

async function showCredentials(item: DockerProject) {
  const token = contextToken();
  if (!contextCurrent(token) || !isCredentialTemplate(item.template_id)) return;
  clearCredentials();
  credentialsLoading.value = true;
  credentialsOpen.value = true;
  const sequence = ++credentialSequence, current = () => credentialsOpen.value && sequence === credentialSequence;
  try {
    const response = await contextAPI(token, current)<unknown>(`/docker/projects/${item.id}/credentials`, "POST", {});
    if (contextCurrent(token) && current()) credentials.value = readCredentials(item, response);
  } catch {
    if (contextCurrent(token) && current()) credentialsError.value = "无法读取此项目的初始凭据，请重新打开后重试。";
  } finally {
    if (contextCurrent(token) && current()) credentialsLoading.value = false;
  }
}

async function copyCredential(field: "username" | "password") {
  const token = contextToken();
  const sequence = credentialSequence;
  const current = () => contextCurrent(token) && credentialsOpen.value && sequence === credentialSequence;
  const details = credentials.value;
  if (!current() || !details || (field === "password" && !passwordVisible.value)) return;
  try {
    await navigator.clipboard.writeText(details[field]);
    if (current()) ElMessage.success(field === "password" ? "已复制密码" : "已复制用户名");
  } catch {
    if (current()) ElMessage.error("无法访问剪贴板，请手动复制。");
  }
}
const taggedImages = computed(() =>
  images.value
    .flatMap((image) => image.RepoTags || [])
    .filter((name) => name !== "<none>:<none>"),
);
const short = (id: string) => id.replace(/^sha256:/, "").slice(0, 12);
const nameOf = (item: DockerContainer) =>
  item.Names?.[0]?.replace(/^\//, "") || short(item.Id);
type ContainerAction = "start" | "stop" | "restart" | "pause" | "unpause";

const containerStates = {
  created: { label: "已创建", tone: "info" },
  running: { label: "运行中", tone: "success" },
  paused: { label: "已暂停", tone: "warning" },
  restarting: { label: "重启中", tone: "warning" },
  exited: { label: "已退出", tone: "info" },
  dead: { label: "异常停止", tone: "danger" },
  removing: { label: "正在移除", tone: "warning" },
} as const;

function containerState(item: DockerContainer) {
  if (retainedContainer(item)) return { label: "镜像保留（受保护）", tone: "info" as const };
  if (Object.hasOwn(containerStates, item.State)) return containerStates[item.State as keyof typeof containerStates];
  return { label: "状态未知", tone: "info" as const };
}

function containerActions(item: DockerContainer): ContainerAction[] {
  if (retainedContainer(item)) return [];
  switch (item.State) {
    case "running": return ["stop", "restart", "pause"];
    case "paused": return ["unpause"];
    case "restarting": return ["stop"];
    case "created":
    case "exited": return ["start"];
    default: return [];
  }
}

const containerActionLabels: Record<ContainerAction, { title: string; result: string; tone: "success" | "warning" | "primary" }> = {
  start: { title: "启动", result: "容器已启动", tone: "success" },
  stop: { title: "停止", result: "容器已停止", tone: "warning" },
  restart: { title: "重启", result: "容器已重启", tone: "primary" },
  pause: { title: "暂停", result: "容器已暂停", tone: "warning" },
  unpause: { title: "恢复", result: "容器已恢复", tone: "success" },
};

function canRemoveContainer(item: DockerContainer) {
  return !retainedContainer(item) && ["created", "exited", "dead"].includes(item.State);
}

function retainedContainer(item: DockerContainer) {
  return item.PanelProtected === true || item.Names?.some(name => name.replace(/^\//, "").startsWith("yunzhan-retain-memcached-")) || item.Labels?.["io.yunzhan.owner"] === "yunzhan.memcached-image-retention.v1" || Object.hasOwn(item.Labels || {}, "io.yunzhan.retention-sha256");
}
const retentionWarning = "应用更新原镜像保留锚点必须保持未启动，禁止通用操作或删除";
const bytes = (n: number) =>
  n >= 1073741824
    ? (n / 1073741824).toFixed(1) + " GB"
    : n >= 1048576
      ? (n / 1048576).toFixed(1) + " MB"
      : (n / 1024).toFixed(1) + " KB";
const date = (seconds: number) =>
  formatPanelDateTime(seconds * 1000);

async function load() {
  const token = contextToken(), sequence = ++loadSequence;
  if (!contextCurrent(token)) return;
  const api = contextAPI(token, () => sequence === loadSequence);
  loading.value = true;
  try {
    const [
      status,
      containerData,
      imageData,
      projectData,
      networkData,
      volumeData,
      templateData,
    ] = await Promise.all([
      api<Overview>("/docker"),
      api<{ containers: DockerContainer[] }>("/docker/containers"),
      api<{ images: DockerImage[] }>("/docker/images"),
      api<{ projects: DockerProject[] }>("/docker/projects"),
      api<{ networks: DockerNetwork[] }>("/docker/networks"),
      api<{ volumes: DockerVolume[] }>("/docker/volumes"),
      api<{ templates: DockerTemplate[] }>("/docker/templates"),
    ]);
    if (!contextCurrent(token) || sequence !== loadSequence) return;
    overview.value = status;
    containers.value = containerData.containers || [];
    images.value = imageData.images || [];
    projects.value = projectData.projects || [];
    networks.value = networkData.networks || [];
    volumes.value = volumeData.volumes || [];
    templates.value = templateData.templates || [];
  } catch (e) {
    if (sequence === loadSequence) reportError(token, e);
  } finally {
    if (contextCurrent(token) && sequence === loadSequence) loading.value = false;
  }
}
function open(template?: "phpmyadmin") {
  if (!alive || !props.csrf || !canOpenAppModule(props.access, "docker-manager")) return;
  managedTemplate.value = template;
  if (template) tab.value = "projects";
  visible.value = true;
  restoreCreateRequest();
  void load();
}
async function openTemplate(templateId: string) {
  if (!alive || !props.csrf || !canOpenAppModule(props.access, "docker-manager")) return;
  managedTemplate.value = undefined;
  visible.value = true;
  const token = contextToken();
  await load();
  if (!contextCurrent(token)) return;
  const template = templates.value.find((item) => item.id === templateId);
  if (!template || template.compatibility_detail) {
    ElMessage.error(template?.compatibility_detail || "应用模板暂不可用");
    return;
  }
  newProject();
  projectForm.value.templateId = templateId;
  const occupied = new Set(containers.value.flatMap((item) => item.Ports?.map((port) => port.PublicPort) || []));
  const ports = composeHostPortSettings(templateId);
  let port = ports.preferred;
  while (port <= ports.max && (occupied.has(port) || (ports.usesNextPort && occupied.has(port + 1)))) port++;
  projectForm.value.hostPort = port <= ports.max ? String(port) : "";
  projectOpen.value = true;
}
defineExpose({ open, openTemplate });

async function waitJob(job: DockerJob, token: ReturnType<typeof contextToken>, compose = false, expectedProject?: string) {
  const api = contextAPI(token);
  const id = job?.job_id, project = job?.project_id;
  function validate(value: DockerJob) {
    if (!value || !/^[a-f0-9]{32}$/.test(id || "") || value.job_id !== id || (value.kind || "") !== (compose ? "compose" : "") ||
      compose && (!/^[a-f0-9]{32}$/.test(project || "") || value.project_id !== project || expectedProject !== undefined && value.project_id !== expectedProject) ||
      !compose && value.project_id !== undefined && value.project_id !== "")
      throw new Error("Docker 任务身份无法核对；请在任务列表核对原任务，未自动重发");
    if (!["queued", "running", "succeeded", "failed"].includes(value.state) || value.error !== undefined && (typeof value.error !== "string" || value.error.length > 4096) ||
      value.state !== "failed" && Boolean(value.error))
      throw new Error("Docker 任务状态无法核对；保留原任务，未自动重发");
  }
  validate(job);
  const deadline = Date.now() + 20 * 60 * 1000;
  while (["queued", "running"].includes(job.state) && Date.now() < deadline) {
    await new Promise((resolve) => setTimeout(resolve, 900));
    job = await api<DockerJob>(`/docker/job-observations/${id}`);
    validate(job);
  }
  if (!contextCurrent(token)) throw new ObsoleteContext();
  if (job.state !== "succeeded")
    throw new Error(job.error || "Docker 作业未完成");
  return job;
}
async function pull() {
  const token = contextToken(); if (!contextCurrent(token)) return;
  const api = contextAPI(token);
  let image = "";
  try {
    const result = await ElMessageBox.prompt(
      "输入完整镜像名称与标签，例如 alpine:3.22。拉取过程在后台执行。",
      "拉取镜像",
      {
        inputPlaceholder: "alpine:3.22",
        confirmButtonText: "开始拉取",
        cancelButtonText: "取消",
        inputValidator: (value: string) => !!value.trim() || "请输入镜像名称",
      },
    );
    if (!contextCurrent(token)) return;
    image = result.value.trim();
  } catch {
    return;
  }
  const ticket = startBusy();
  try {
    let job = await api<DockerJob>("/docker/jobs", "POST", {
      action: "pull",
      image,
    });
    job = await waitJob(job, token);
    if (!contextCurrent(token)) return;
    ElMessage.success(`镜像 ${job.image} 已拉取`);
    await load();
  } catch (e) {
    reportError(token, e);
  } finally {
    finishBusy(token, ticket);
  }
}
function newContainer() {
  form.value = {
    name: "",
    image: taggedImages.value[0] || "",
    restart: "unless-stopped",
    hostPort: "",
    containerPort: "",
    protocol: "tcp",
    command: "",
    environment: "",
  };
  createOpen.value = true;
}
function parseEnvironment() {
  return form.value.environment
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      const i = line.indexOf("=");
      if (i < 1) throw new Error(`环境变量格式错误：${line}`);
      return { name: line.slice(0, i), value: line.slice(i + 1) };
    });
}
async function createContainer() {
  const token = contextToken(); if (!contextCurrent(token)) return;
  const api = contextAPI(token);
  const ticket = startBusy();
  try {
    const ports = [];
    if (form.value.hostPort || form.value.containerPort) {
      if (!form.value.hostPort || !form.value.containerPort)
        throw new Error("主机端口与容器端口需要同时填写");
      ports.push({
        host_port: Number(form.value.hostPort),
        container_port: Number(form.value.containerPort),
        protocol: form.value.protocol,
      });
    }
    const command = form.value.command.trim()
      ? ["sh", "-c", form.value.command.trim()]
      : [];
    const name = form.value.name.trim();
    let job = await api<DockerJob>("/docker/jobs", "POST", {
      action: "create",
      image: form.value.image.trim(),
      name,
      restart: form.value.restart,
      ports,
      environment: parseEnvironment(),
      command,
    });
    job = await waitJob(job, token);
    if (!contextCurrent(token)) return;
    createOpen.value = false;
    ElMessage.success(`容器 ${name} 已创建`);
    await load();
  } catch (e) {
    reportError(token, e);
  } finally {
    finishBusy(token, ticket);
  }
}
async function action(
  item: DockerContainer,
  actionName: ContainerAction,
) {
  if (retainedContainer(item)) { ElMessage.warning(retentionWarning); return; }
  if (busy.value || !containerActions(item).includes(actionName) || !/^[a-f0-9]{64}$/.test(item.Id)) return;
  const token = contextToken(); if (!contextCurrent(token)) return;
  const api = contextAPI(token);
  const ticket = startBusy();
  try {
    await api(`/docker/containers/${item.Id}/${actionName}`, "POST", {});
    if (!contextCurrent(token)) return;
    ElMessage.success(containerActionLabels[actionName].result);
    await load();
  } catch (e) {
    reportError(token, e);
    if (contextCurrent(token)) await load();
  } finally {
    finishBusy(token, ticket);
  }
}
async function showLogs(item: DockerContainer) {
  const token = contextToken(); if (!contextCurrent(token)) return;
  logs.value = ""; logsName.value = nameOf(item); logsOpen.value = true;
  const sequence = ++logSequence, current = () => logsOpen.value && sequence === logSequence;
  const api = contextAPI(token, current);
  const ticket = startBusy();
  try {
    const data = await api<{ logs: string }>(
      `/docker/containers/${item.Id}/logs`,
    );
    logs.value = data.logs || "暂无日志输出";
    logsName.value = nameOf(item);
    logsOpen.value = true;
  } catch (e) {
    if (current()) reportError(token, e);
  } finally {
    finishBusy(token, ticket);
  }
}
async function removeContainer(item: DockerContainer) {
  if (retainedContainer(item)) { ElMessage.warning(retentionWarning); return; }
  const token = contextToken(); if (!contextCurrent(token)) return;
  const api = contextAPI(token); let ticket = 0;
  if (!canRemoveContainer(item)) {
    ElMessage.warning("请确认容器已停止，再执行删除");
    return;
  }
  const id = short(item.Id);
  try {
    const result = await ElMessageBox.prompt(
      `请输入容器 ID ${id} 确认删除。`,
      "删除容器",
      {
        inputPlaceholder: id,
        inputValidator: (value: string) => value === id || "容器 ID 不匹配",
        confirmButtonText: "永久删除",
        cancelButtonText: "取消",
        type: "warning",
      },
    );
    if (!contextCurrent(token)) return;
    ticket = startBusy();
    await api(`/docker/containers/${item.Id}`, "DELETE", {
      confirm_id: result.value,
    });
    ElMessage.success("容器已删除");
    await load();
  } catch (e) {
    reportError(token, e);
  } finally {
    finishBusy(token, ticket);
  }
}
async function removeImage(item: DockerImage) {
  const token = contextToken(); if (!contextCurrent(token)) return;
  const api = contextAPI(token); let ticket = 0;
  const id = short(item.Id);
  try {
    const result = await ElMessageBox.prompt(
      `请输入镜像 ID ${id} 确认删除。被容器引用时会拒绝。`,
      "删除镜像",
      {
        inputPlaceholder: id,
        inputValidator: (value: string) => value === id || "镜像 ID 不匹配",
        confirmButtonText: "永久删除",
        cancelButtonText: "取消",
        type: "warning",
      },
    );
    if (!contextCurrent(token)) return;
    ticket = startBusy();
    await api(
      `/docker/images/${item.Id.replace(/^sha256:/, "")}`,
      "DELETE",
      { confirm_id: result.value },
    );
    ElMessage.success("镜像已删除");
    await load();
  } catch (e) {
    reportError(token, e);
  } finally {
    finishBusy(token, ticket);
  }
}

function newProject() {
  restoreCreateRequest();
  if(pendingCreate.value||createBlocked.value){projectOpen.value=true;return;}
  projectForm.value = {
    name: "",
    mode: "template",
    templateId: templates.value.find((item) => !item.compatibility_detail)?.id || "nginx-static",
    hostPort: "18080",
    compose:
      "services:\n  app:\n    image: alpine:3.22\n    restart: unless-stopped\n",
  };
  projectOpen.value = true;
}
async function createProject() {
  const token = contextToken(),epoch=projectEpoch; if (!contextCurrent(token)||!projectOpen.value||busy.value) return;
  restoreCreateRequest();if(pendingCreate.value||createBlocked.value)return;
  const { mode, templateId, hostPort } = projectForm.value;
  if (mode === "template" && !isComposeHostPort(templateId, Number(hostPort))) {
    ElMessage.error(`请输入 1024–${composeHostPortSettings(templateId).max} 之间的本机端口。`);
    return;
  }
  const current=()=>projectOpen.value&&projectEpoch===epoch;
  const api = contextAPI(token,current);
  const ticket = startBusy();
  try {
    const body =
      projectForm.value.mode === "template"
        ? {
            name: projectForm.value.name.trim(),
            template_id: projectForm.value.templateId,
            host_port: Number(projectForm.value.hostPort),
            compose: "",
          }
        : {
            name: projectForm.value.name.trim(),
            template_id: "",
            host_port: 0,
            compose: projectForm.value.compose,
          };
    const actor=createActor(),storageKey=dockerCreateStorageKey(actor);
    if(!storageKey)throw new Error("无法核对创建请求所属账户，未提交");
    const fingerprint=await dockerCreateFingerprint(body);
    if(!contextCurrent(token)||!current())return;
    const retained:RetainedDockerCreate={format:1,actor,key:randomId(),fingerprint};
    sessionStorage.setItem(storageKey,JSON.stringify(retained));
    pendingCreate.value=retained;originalCreateJob.value=null;createRecoveryError.value="";
    const completed=await waitJob(await api<DockerJob>("/docker/projects", "POST", body,retained.key), token, true);
    if (!contextCurrent(token)||!current()) return;
    finishCreateRequest(retained,completed);
    projectOpen.value = false;
    ElMessage.success(`Compose 项目 ${body.name} 已创建并启动`);
    await load();
  } catch (e) {
    if(contextCurrent(token)&&current()&&!(e instanceof ObsoleteContext))createRecoveryError.value=(e instanceof Error?e.message:"创建结果未确认；请只核对原任务").slice(0,4096);
    if(contextCurrent(token)&&current()&&(e as {status?:number;requestNotAccepted?:boolean})?.status===400&&(e as {requestNotAccepted?:boolean})?.requestNotAccepted===true){
      const retained=pendingCreate.value,key=dockerCreateStorageKey(createActor());
      if(retained&&retained.actor===createActor()&&sessionStorage.getItem(key)===JSON.stringify(retained)){sessionStorage.removeItem(key);pendingCreate.value=null;}
    }
    reportError(token, e);
  } finally {
    finishBusy(token, ticket);
  }
}
function restoreCreateRequest(){
  const actor=createActor(),key=dockerCreateStorageKey(actor);
  if(!key){createBlocked.value=true;createRecoveryError.value="无法核对原请求所属账户，未提交创建";return;}
  try{
    const raw=sessionStorage.getItem(key),retained=readDockerCreateRequest(raw,actor);
    if(raw&&!retained){createBlocked.value=true;createRecoveryError.value="原创建请求记录无法核对；未覆盖记录或重新创建";return;}
    pendingCreate.value=retained;createBlocked.value=false;
  }catch{createBlocked.value=true;createRecoveryError.value="浏览器无法保留原始创建请求，未提交创建";}
}
function finishCreateRequest(retained:RetainedDockerCreate,job:DockerJob){
  if(createActor()!==retained.actor||pendingCreate.value?.key!==retained.key||job.kind!=="compose"||!/^[a-f0-9]{32}$/.test(job.job_id)||!/^[a-f0-9]{32}$/.test(job.project_id||"")||!["succeeded","failed"].includes(job.state))throw new Error("原始创建完成回执无法核对，未清除原请求");
  const key=dockerCreateStorageKey(retained.actor),raw=sessionStorage.getItem(key);
  if(raw!==JSON.stringify(retained))throw new Error("原创建请求记录已改变，未清除其他请求");
  sessionStorage.removeItem(key);pendingCreate.value=null;originalCreateJob.value=null;createRecoveryError.value="";createBlocked.value=false;
}
async function checkOriginalCreate(){
  const token=contextToken(),retained=pendingCreate.value;
  if(!retained||!contextCurrent(token)||busy.value||retained.actor!==createActor())return;
  const current=()=>pendingCreate.value?.key===retained.key&&createActor()===retained.actor,api=contextAPI(token,current),ticket=startBusy();
  try{
    const out=await api<{found:boolean;job_id?:string;project_id?:string;pending?:boolean;job?:DockerJob;error?:string}>("/docker/project-requests/"+retained.key);
    if(out?.found===false){createRecoveryError.value="尚未发现原请求回执；未重发请求，请核对后台任务";return;}
    if(out?.found!==true||!/^[a-f0-9]{32}$/.test(out.job_id||"")||!/^[a-f0-9]{32}$/.test(out.project_id||""))throw new Error("原创建请求身份无法核对，未重新创建");
    if(out.pending===true&&!out.job){createRecoveryError.value="原请求已保存，执行状态尚未确认；未重新创建";return;}
    const job=out.job;
    if(!job||job.job_id!==out.job_id||job.project_id!==out.project_id||job.kind!=="compose"||!["queued","running","succeeded","failed"].includes(job.state)||job.state!=="failed"&&Boolean(job.error))throw new Error("原创建任务回执无法核对，未重新创建");
    originalCreateJob.value=job;
    if(job.state==="succeeded"){
      finishCreateRequest(retained,job);projectOpen.value=false;ElMessage.success("已核对原始创建任务成功，未重复提交");await load();
    }else createRecoveryError.value=job.state==="failed"?(job.error||"原任务失败，保留原回执"): "原始创建任务仍在执行；仅核对，不重新提交";
  }catch(e){if(contextCurrent(token)&&current()&&!(e instanceof ObsoleteContext))createRecoveryError.value=(e instanceof Error?e.message:"原任务暂时无法核对").slice(0,4096);reportError(token,e);}
  finally{finishBusy(token,ticket);}
}
function acknowledgeFailedCreate(){
  const retained=pendingCreate.value,job=originalCreateJob.value;
  if(!retained||!job||job.state!=="failed"||!contextCurrent(contextToken())||busy.value)return;
  try{finishCreateRequest(retained,job);newProject();}catch(e){reportError(contextToken(),e);}
}
function openBinding(item: DockerProject) {
  if (!contextCurrent(contextToken())) return;
  bindingProject.value = item;
  const slug = item.name.toLowerCase().replace(/[^a-z0-9-]+/g, "-").replace(/^-|-$/g, "").slice(0, 32);
  bindingForm.value = { name: item.name + " 网站", slug: /^[a-z][a-z0-9-]{2,31}$/.test(slug) ? slug : "wordpress-site", domain: "" };
  bindingOpen.value = true;
}
async function bindProjectSite() {
  const token = contextToken(), epoch = bindingEpoch;
  const item = bindingProject.value;
  const current = () => bindingOpen.value && bindingProject.value?.id === item?.id && epoch === bindingEpoch;
  if (!item || !contextCurrent(token) || !current()) return;
  const api = contextAPI(token, current), ticket = startBusy();
  try {
    const body = { ...bindingForm.value, domain: bindingForm.value.domain.trim().toLowerCase() };
    const signature = JSON.stringify([item.id, body]);
    const stored = sessionStorage.getItem("panel-pending-app-site");
    let pending: { signature: string; key: string } | null = null;
    try { pending = stored ? JSON.parse(stored) : null; } catch { /* Ignore stale browser state. */ }
    const key = pending?.signature === signature ? pending.key : randomId();
    const retainedRequest = JSON.stringify({ signature, key });
    sessionStorage.setItem("panel-pending-app-site", retainedRequest);
    const result = await api<{ job_id: string }>(`/docker/projects/${item.id}/sites`, "POST", body, key);
    if (!/^[a-f0-9]{32}$/.test(result?.job_id || "")) throw new Error("网站创建任务身份无法核对；保留原请求，未自动重发");
    const deadline = Date.now() + 3 * 60 * 1000;
    let state = "queued", error = "", siteID = "";
    while (["queued", "running"].includes(state) && Date.now() < deadline) {
      await new Promise((resolve) => setTimeout(resolve, 900));
      const job = await api<{ id: string; site_id: string; kind: string; state: string; error: string }>(`/jobs/${result.job_id}`);
      if (!job || job.id !== result.job_id || job.kind !== "create_site" || !/^[a-f0-9]{32}$/.test(job.site_id || "") || siteID && job.site_id !== siteID)
        throw new Error("网站创建任务身份无法核对；保留原请求，未自动重发");
      if (!["queued", "running", "succeeded", "failed", "needs_attention"].includes(job.state) || typeof job.error !== "string" || ["queued", "running", "succeeded"].includes(job.state) && job.error !== "")
        throw new Error("网站创建任务状态无法核对；保留原请求，未自动重发");
      siteID = job.site_id;
      state = job.state;
      error = job.error;
    }
    if (state !== "succeeded") throw new Error(error || "网站创建任务尚未确认成功，请在任务列表核对原任务；保留原请求，未自动重发");
    if (sessionStorage.getItem("panel-pending-app-site") === retainedRequest) sessionStorage.removeItem("panel-pending-app-site");
    bindingOpen.value = false;
    ElMessage.success(`网站 ${body.domain} 已绑定，域名请解析到本机并在网站设置中启用公网入口`);
  } catch (e) {
    if (current()) reportError(token, e);
  } finally {
    finishBusy(token, ticket);
  }
}
async function projectAction(
  item: DockerProject,
  actionName: "start" | "stop" | "restart" | "update",
) {
  const token = contextToken(); if (!contextCurrent(token)) return;
  const api = contextAPI(token);
  const ticket = startBusy();
  try {
    const job = await api<DockerJob>(
      `/docker/projects/${item.id}/${actionName}`,
      "POST",
      {},
    );
    await waitJob(job, token, true, item.id);
    if (!contextCurrent(token)) return;
    ElMessage.success(
      {
        start: "项目已启动",
        stop: "项目已停止",
        restart: "项目已重启",
        update: "镜像已更新并重新部署",
      }[actionName],
    );
    await load();
  } catch (e) {
    reportError(token, e);
  } finally {
    finishBusy(token, ticket);
  }
}
async function showProjectLogs(item: DockerProject) {
  const token = contextToken(); if (!contextCurrent(token)) return;
  logs.value = ""; logsName.value = item.name; logsOpen.value = true;
  const sequence = ++logSequence, current = () => logsOpen.value && sequence === logSequence;
  const api = contextAPI(token, current);
  const ticket = startBusy();
  try {
    const data = await api<{ logs: string }>(
      `/docker/projects/${item.id}/logs`,
    );
    logs.value = data.logs || "暂无日志输出";
    logsName.value = item.name;
    logsOpen.value = true;
  } catch (e) {
    if (current()) reportError(token, e);
  } finally {
    finishBusy(token, ticket);
  }
}
async function removeProject(item: DockerProject) {
  const token = contextToken(); if (!contextCurrent(token)) return;
  const api = contextAPI(token); let ticket = 0;
  try {
    const result = await ElMessageBox.prompt(
      `请输入项目名称 ${item.name} 确认删除。命名卷和镜像会保留。`,
      "删除 Compose 项目",
      {
        inputPlaceholder: item.name,
        inputValidator: (value: string) =>
          value === item.name || "项目名称不匹配",
        confirmButtonText: "删除项目",
        cancelButtonText: "取消",
        type: "warning",
      },
    );
    if (!contextCurrent(token)) return;
    ticket = startBusy();
    await waitJob(
      await api<DockerJob>(`/docker/projects/${item.id}`, "DELETE", {
        confirm_name: result.value,
      }),
      token,
      true,
      item.id,
    );
    if (!contextCurrent(token)) return;
    ElMessage.success("项目已删除，命名卷和镜像已保留");
    await load();
  } catch (e) {
    reportError(token, e);
  } finally {
    finishBusy(token, ticket);
  }
}
function newNetwork() {
  networkForm.value = { name: "", internal: false };
  networkOpen.value = true;
}
async function createNetwork() {
  const token = contextToken(); if (!contextCurrent(token)) return;
  const api = contextAPI(token);
  const ticket = startBusy();
  try {
    await api("/docker/networks", "POST", { ...networkForm.value });
    networkOpen.value = false;
    ElMessage.success("Docker 网络已创建");
    await load();
  } catch (e) {
    reportError(token, e);
  } finally {
    finishBusy(token, ticket);
  }
}
async function createVolume() {
  const token = contextToken(); if (!contextCurrent(token)) return;
  const api = contextAPI(token); let ticket = 0;
  try {
    const result = await ElMessageBox.prompt(
      "输入新卷名称。卷由 local 驱动创建。",
      "创建 Docker 卷",
      {
        inputPlaceholder: "例如 app-data",
        confirmButtonText: "创建",
        cancelButtonText: "取消",
        inputValidator: (value: string) => !!value.trim() || "请输入卷名称",
      },
    );
    if (!contextCurrent(token)) return;
    ticket = startBusy();
    await api("/docker/volumes", "POST", { name: result.value.trim() });
    ElMessage.success("Docker 卷已创建");
    await load();
  } catch (e) {
    reportError(token, e);
  } finally {
    finishBusy(token, ticket);
  }
}
const managed = (labels: Record<string, string> | null) =>
  labels?.["com.yunzhan.panel.managed"] === "true";
const composeProjectOf = (labels: Record<string, string> | null) =>
  labels?.["com.docker.compose.project"] || "";
const orphanComposeVolume = (item: DockerVolume) => {
  const project = composeProjectOf(item.Labels);
  return (
    /^panel_[a-f0-9]{12}$/.test(project) &&
    !projects.value.some((candidate) => candidate.engine_name === project)
  );
};
const deletableVolume = (item: DockerVolume) =>
  managed(item.Labels) || orphanComposeVolume(item);
async function removeNetwork(item: DockerNetwork) {
  const token = contextToken(); if (!contextCurrent(token)) return;
  const api = contextAPI(token); let ticket = 0;
  try {
    const result = await ElMessageBox.prompt(
      `请输入网络名称 ${item.Name} 确认删除。`,
      "删除 Docker 网络",
      {
        inputPlaceholder: item.Name,
        inputValidator: (value: string) =>
          value === item.Name || "网络名称不匹配",
        confirmButtonText: "永久删除",
        cancelButtonText: "取消",
        type: "warning",
      },
    );
    if (!contextCurrent(token)) return;
    ticket = startBusy();
    await api(`/docker/networks/${item.Id}`, "DELETE", {
      confirm_name: result.value,
    });
    ElMessage.success("Docker 网络已删除");
    await load();
  } catch (e) {
    reportError(token, e);
  } finally {
    finishBusy(token, ticket);
  }
}
async function removeVolume(item: DockerVolume) {
  const token = contextToken(); if (!contextCurrent(token)) return;
  const api = contextAPI(token); let ticket = 0;
  try {
    const result = await ElMessageBox.prompt(
      `请输入卷名称 ${item.Name} 确认删除。被容器引用时会拒绝。`,
      "删除 Docker 卷",
      {
        inputPlaceholder: item.Name,
        inputValidator: (value: string) =>
          value === item.Name || "卷名称不匹配",
        confirmButtonText: "永久删除",
        cancelButtonText: "取消",
        type: "warning",
      },
    );
    if (!contextCurrent(token)) return;
    ticket = startBusy();
    await api(`/docker/volumes/${item.Name}`, "DELETE", {
      confirm_name: result.value,
    });
    ElMessage.success("Docker 卷已删除");
    await load();
  } catch (e) {
    reportError(token, e);
  } finally {
    finishBusy(token, ticket);
  }
}
</script>

<template>
  <el-dialog
    v-model="visible"
    :title="managedTemplate ? 'phpMyAdmin 管理' : 'Docker 管理'"
    width="min(1180px, 96vw)"
    :close-on-click-modal="false"
    class="docker-dialog"
  >
    <div v-if="overview && !managedTemplate" class="docker-summary">
      <div>
        <span>Engine</span><strong>{{ overview.version }}</strong
        ><small>API {{ overview.api_version }}</small>
      </div>
      <div>
        <span>运行中</span><strong>{{ overview.running }}</strong
        ><small>共 {{ overview.containers }} 个容器</small>
      </div>
      <div>
        <span>镜像</span><strong>{{ overview.images }}</strong
        ><small>{{ overview.architecture }}</small>
      </div>
      <div>
        <span>存储驱动</span><strong>{{ overview.storage_driver }}</strong
        ><small>{{ overview.data_root }}</small>
      </div>
    </div>
    <div class="docker-toolbar">
      <el-tabs v-if="!managedTemplate" v-model="tab">
        <el-tab-pane label="Compose 项目" name="projects" />
        <el-tab-pane label="容器" name="containers" />
        <el-tab-pane label="镜像" name="images" />
        <el-tab-pane label="网络" name="networks" />
        <el-tab-pane label="卷" name="volumes" />
      </el-tabs>
      <div>
        <el-button :icon="Refresh" :disabled="busy" @click="load"
          >刷新</el-button
        >
        <el-button
          v-if="tab === 'images'"
          type="primary"
          :icon="Plus"
          :disabled="busy"
          @click="pull"
          >拉取镜像</el-button
        >
        <el-button
          v-if="tab === 'containers'"
          type="primary"
          :icon="Plus"
          :disabled="busy || !images.length"
          data-docker-create
          @click="newContainer"
          >创建容器</el-button
        >
        <el-button
          v-if="tab === 'projects' && !managedTemplate"
          type="primary"
          :icon="Plus"
          :disabled="busy"
          data-compose-create
          @click="newProject"
          >{{ pendingCreate ? "核对原创建" : "创建项目" }}</el-button
        >
        <el-button
          v-if="tab === 'networks'"
          type="primary"
          :icon="Plus"
          :disabled="busy"
          @click="newNetwork"
          >创建网络</el-button
        >
        <el-button
          v-if="tab === 'volumes'"
          type="primary"
          :icon="Plus"
          :disabled="busy"
          @click="createVolume"
          >创建卷</el-button
        >
      </div>
    </div>
    <div v-loading="loading" class="docker-list">
      <template v-if="tab === 'projects'">
        <p v-if="managedTemplate && visibleProjects.some(project => phpMyAdminURL(project))">
          管理地址只监听服务器回环端口。远程浏览时，请先将该端口转发到本机，再用数据库账号登录。
        </p>
        <div class="docker-row project-row docker-columns">
          <span>项目</span><span>服务</span><span>容器</span><span>状态</span
          ><span>操作</span>
        </div>
        <div
          v-for="item in visibleProjects"
          :key="item.id"
          class="docker-row project-row"
          :data-compose-project="item.name"
        >
          <div>
            <strong>{{ item.name }}</strong
            ><small>{{ item.engine_name }} · {{ item.id.slice(0, 12) }}</small><small v-if="item.site_name">网站：{{ item.site_name }}</small>
            <small v-if="phpMyAdminURL(item)"><code>{{ phpMyAdminURL(item) }}</code></small>
            <small v-if="isPhpMyAdminTemplate(item.template_id) && item.mysql_server_id">数据库：云栈 MySQL</small>
          </div>
          <span>{{ item.services }} 个服务</span>
          <span>{{ item.running }} / {{ item.containers }} 运行</span>
          <div>
            <el-tag
              :type="
                item.state === 'running'
                  ? 'success'
                  : item.state === 'stopped'
                    ? 'info'
                    : 'warning'
              "
              size="small"
              >{{
                item.state === "running"
                  ? "运行中"
                  : item.state === "stopped"
                    ? "已停止"
                    : "暂无容器"
              }}</el-tag
            ><small>{{ Number.isSafeInteger(item.healthy) ? item.healthy : "未知" }} / {{ item.services }} 健康检查通过</small><small>{{
              formatPanelDateTime(item.created_at)
            }}</small>
          </div>
          <div class="docker-actions">
            <el-button v-if="isCredentialTemplate(item.template_id) && (item.template_id !== 'elasticsearch' || item.initial_credentials)" link type="primary" :disabled="busy" @click="showCredentials(item)">访问凭据</el-button>
            <el-button v-if="item.template_id === 'rabbitmq'" link type="primary" :disabled="busy || item.state !== 'running'"
              @click="openRabbitQueues(item)">查看队列</el-button>
            <el-link v-if="phpMyAdminURL(item)" type="primary" :href="phpMyAdminURL(item)" target="_blank" rel="noopener noreferrer">打开 phpMyAdmin</el-link>
            <el-button
              v-if="canBindDockerProjectSite(item)"
              link
              type="success"
              :disabled="busy"
              @click="openBinding(item)"
              >绑定网站</el-button
            >
            <el-button
              v-if="item.state !== 'running'"
              link
              type="success"
              :disabled="busy || item.state === 'empty'"
              @click="projectAction(item, 'start')"
              >启动</el-button
            >
            <el-button
              v-else
              link
              type="warning"
              :disabled="busy"
              @click="projectAction(item, 'stop')"
              >停止</el-button
            >
            <el-button
              v-if="item.state === 'running'"
              link
              type="primary"
              :disabled="busy"
              @click="projectAction(item, 'restart')"
              >重启</el-button
            >
            <el-button
              link
              type="primary"
              :disabled="busy"
              @click="projectAction(item, 'update')"
              >更新</el-button
            >
            <el-button
              link
              type="primary"
              :icon="Document"
              :disabled="busy"
              @click="showProjectLogs(item)"
              >日志</el-button
            >
            <el-button
              link
              type="danger"
              :icon="Delete"
              :disabled="busy"
              @click="removeProject(item)"
              >删除</el-button
            >
          </div>
        </div>
        <el-empty
          v-if="!loading && !visibleProjects.length"
          :description="managedTemplate ? '暂无 phpMyAdmin 实例' : '还没有 Compose 项目，可使用应用模板或受限 Compose 创建'"
          :image-size="72"
        />
      </template>
      <template v-if="tab === 'containers'">
        <div class="docker-row docker-columns">
          <span>名称 / ID</span><span>镜像</span><span>端口</span
          ><span>状态</span><span>操作</span>
        </div>
        <div
          v-for="item in containers"
          :key="item.Id"
          class="docker-row"
          :data-docker-container="nameOf(item)"
        >
          <div>
            <strong>{{ nameOf(item) }}</strong
            ><small>{{ short(item.Id) }}</small>
            <small v-if="retainedContainer(item)">{{ item.PanelProtectionReason || retentionWarning }}</small>
          </div>
          <span>{{ item.Image }}</span>
          <span>{{
            item.Ports?.length
              ? item.Ports.map(
                  (p) =>
                    `${p.IP || "—"}:${p.PublicPort || "—"}→${p.PrivatePort}/${p.Type}`,
                ).join(" · ")
              : "—"
          }}</span>
          <div>
            <el-tag
              :type="containerState(item).tone"
              size="small"
              >{{ containerState(item).label }}</el-tag
            ><small>{{ item.Status }}</small>
          </div>
          <div class="docker-actions">
            <el-button
              v-for="operation in containerActions(item)"
              :key="operation"
              link
              :type="containerActionLabels[operation].tone"
              :icon="operation === 'start' || operation === 'unpause' ? VideoPlay : undefined"
              :disabled="busy || !/^[a-f0-9]{64}$/.test(item.Id)"
              @click="action(item, operation)"
              >{{ containerActionLabels[operation].title }}</el-button
            >
            <el-button link type="primary" :disabled="busy || !/^[a-f0-9]{64}$/.test(item.Id)"
              @click="metricsContainer = item">诊断</el-button>
            <el-button
              link
              type="primary"
              :icon="Document"
              :disabled="busy"
              @click="showLogs(item)"
              >日志</el-button
            >
            <el-button
              link
              type="danger"
              :icon="Delete"
              :disabled="busy || !canRemoveContainer(item)"
              @click="removeContainer(item)"
              >删除</el-button
            >
          </div>
        </div>
        <el-empty
          v-if="!loading && !containers.length"
          description="还没有容器，先拉取镜像并创建容器"
          :image-size="72"
        />
      </template>
      <template v-if="tab === 'images'">
        <div class="docker-row image-row docker-columns">
          <span>仓库标签</span><span>镜像 ID</span><span>大小</span
          ><span>创建时间</span><span>操作</span>
        </div>
        <div
          v-for="item in images"
          :key="item.Id"
          class="docker-row image-row"
          :data-docker-image="short(item.Id)"
        >
          <div>
            <strong>{{ item.RepoTags?.join(" · ") || "(none)" }}</strong
            ><small>{{ item.RepoDigests?.[0] || "本地镜像" }}</small>
          </div>
          <code>{{ short(item.Id) }}</code
          ><span>{{ bytes(item.Size) }}</span
          ><time>{{ date(item.Created) }}</time>
          <div class="docker-actions">
            <el-button
              link
              type="danger"
              :icon="Delete"
              :disabled="busy"
              @click="removeImage(item)"
              >删除</el-button
            >
          </div>
        </div>
        <el-empty
          v-if="!loading && !images.length"
          description="还没有镜像"
          :image-size="72"
        />
      </template>
      <template v-if="tab === 'networks'">
        <div class="docker-row resource-row docker-columns">
          <span>网络</span><span>驱动</span><span>范围</span><span>容器</span
          ><span>操作</span>
        </div>
        <div
          v-for="item in networks"
          :key="item.Id"
          class="docker-row resource-row"
          :data-docker-network="item.Name"
        >
          <div>
            <strong>{{ item.Name }}</strong
            ><small>{{ short(item.Id) }}</small>
          </div>
          <span
            >{{ item.Driver
            }}<small>{{ item.Internal ? "内部网络" : "普通网络" }}</small></span
          >
          <span>{{ item.Scope }}</span
          ><span>{{ Object.keys(item.Containers || {}).length }}</span>
          <div class="docker-actions">
            <el-tag v-if="!managed(item.Labels)" size="small" type="info"
              >系统</el-tag
            ><el-button
              v-else
              link
              type="danger"
              :icon="Delete"
              :disabled="busy"
              @click="removeNetwork(item)"
              >删除</el-button
            >
          </div>
        </div>
      </template>
      <template v-if="tab === 'volumes'">
        <div class="docker-row resource-row docker-columns">
          <span>卷</span><span>驱动</span><span>范围</span><span>挂载点</span
          ><span>操作</span>
        </div>
        <div
          v-for="item in volumes"
          :key="item.Name"
          class="docker-row resource-row"
          :data-docker-volume="item.Name"
        >
          <div>
            <strong>{{ item.Name }}</strong
            ><small>{{
              managed(item.Labels) ? "面板创建" : "Compose / 系统资源"
            }}</small>
          </div>
          <span>{{ item.Driver }}</span
          ><span>{{ item.Scope }}</span
          ><code>{{ item.Mountpoint }}</code>
          <div class="docker-actions">
            <el-button
              v-if="deletableVolume(item)"
              link
              type="danger"
              :icon="Delete"
              :disabled="busy"
              @click="removeVolume(item)"
              >删除</el-button
            ><el-tag v-else size="small" type="info">{{
              composeProjectOf(item.Labels) ? "受项目管理" : "系统"
            }}</el-tag>
          </div>
        </div>
        <el-empty
          v-if="!loading && !volumes.length"
          description="还没有 Docker 卷"
          :image-size="72"
        />
      </template>
    </div>
    <template #footer
      ><el-button :disabled="busy" @click="visible = false"
        >关闭</el-button
      ></template
    >
  </el-dialog>
  <el-dialog
    v-model="createOpen"
    title="创建容器"
    width="min(700px, 94vw)"
    :close-on-click-modal="false"
  >
    <el-form label-position="top" @submit.prevent="createContainer">
      <div class="docker-form-grid">
        <el-form-item label="容器名称"
          ><el-input
            v-model="form.name"
            maxlength="63"
            placeholder="例如 web-demo"
        /></el-form-item>
        <el-form-item label="镜像"
          ><el-select v-model="form.image" filterable allow-create
            ><el-option
              v-for="image in taggedImages"
              :key="image"
              :label="image"
              :value="image" /></el-select
        ></el-form-item>
        <el-form-item label="重启策略"
          ><el-select v-model="form.restart"
            ><el-option label="除非手动停止" value="unless-stopped" /><el-option
              label="失败时重启"
              value="on-failure" /><el-option
              label="不自动重启"
              value="no" /></el-select
        ></el-form-item>
        <el-form-item label="协议"
          ><el-select v-model="form.protocol"
            ><el-option label="TCP" value="tcp" /><el-option
              label="UDP"
              value="udp" /></el-select
        ></el-form-item>
        <el-form-item label="主机端口（仅监听 127.0.0.1）"
          ><el-input
            v-model="form.hostPort"
            inputmode="numeric"
            placeholder="例如 18080"
        /></el-form-item>
        <el-form-item label="容器端口"
          ><el-input
            v-model="form.containerPort"
            inputmode="numeric"
            placeholder="例如 80"
        /></el-form-item>
      </div>
      <el-form-item label="启动命令（可选）"
        ><el-input v-model="form.command" placeholder="例如 sleep 3600" />
        <div class="form-help">
          命令在容器内通过 sh -c 执行，不挂载宿主机目录。
        </div></el-form-item
      >
      <el-form-item label="环境变量（每行 KEY=value，可选）"
        ><el-input
          v-model="form.environment"
          type="textarea"
          :rows="5"
          spellcheck="false"
      /></el-form-item>
      <el-alert
        title="首版容器只允许回环端口映射，不开放宿主机目录、特权模式或 Docker Socket。"
        type="info"
        :closable="false"
      />
    </el-form>
    <template #footer
      ><el-button :disabled="busy" @click="createOpen = false">取消</el-button
      ><el-button
        type="primary"
        :loading="busy"
        :disabled="!form.name || !form.image"
        @click="createContainer"
        >创建并启动</el-button
      ></template
    >
  </el-dialog>
  <el-dialog
    v-model="projectOpen"
    title="创建 Compose 项目"
    width="min(780px, 95vw)"
    :close-on-click-modal="false"
  >
    <section v-if="pendingCreate || createBlocked || createRecoveryError" class="docker-create-receipt" role="status">
      <p>{{ createRecoveryError || "已保留原始创建请求；只核对原任务，不重复创建。" }}</p>
      <p v-if="originalCreateJob">原任务：{{ originalCreateJob.job_id }} · {{ originalCreateJob.state }}</p>
      <el-button v-if="pendingCreate" :disabled="busy" @click="checkOriginalCreate">核对原创建任务</el-button>
      <el-button v-if="originalCreateJob?.state === 'failed'" :disabled="busy" @click="acknowledgeFailedCreate">已核对失败，允许新建</el-button>
    </section>
    <el-form label-position="top" :disabled="Boolean(pendingCreate) || createBlocked" @submit.prevent="createProject">
      <div class="docker-form-grid">
        <el-form-item label="项目名称"
          ><el-input
            v-model="projectForm.name"
            maxlength="40"
            placeholder="例如 company-web"
        /></el-form-item>
        <el-form-item label="创建方式"
          ><el-radio-group v-model="projectForm.mode"
            ><el-radio-button value="template">应用模板</el-radio-button
            ><el-radio-button value="compose"
              >自定义 Compose</el-radio-button
            ></el-radio-group
          ></el-form-item
        >
      </div>
      <template v-if="projectForm.mode === 'template'">
        <el-form-item label="应用模板"
          ><el-select v-model="projectForm.templateId"
            ><el-option
              v-for="item in templates"
              :key="item.id"
              :label="`${item.name} · ${item.image}`"
              :value="item.id"
              :disabled="Boolean(item.compatibility_detail)"
              ><strong>{{ item.name }}</strong
              ><span class="template-option">{{
                item.compatibility_detail || item.description
              }}</span></el-option
            ></el-select
          ></el-form-item
        >
        <el-form-item label="主机回环端口"
          ><el-input
            v-model="projectForm.hostPort"
            inputmode="numeric"
            placeholder="例如 18080"
          />
          <div class="form-help">
            只监听 127.0.0.1。{{ projectPorts.detail }}需要公网访问时可绑定受管 Nginx 站点。
          </div></el-form-item
        >
      </template>
      <el-form-item v-else label="Compose YAML"
        ><el-input
          v-model="projectForm.compose"
          type="textarea"
          :rows="14"
          spellcheck="false"
          class="compose-editor"
        />
        <div class="form-help">
          镜像必须写明标签或摘要；端口必须使用 127.0.0.1 和 1024 以上主机端口。
        </div></el-form-item
      >
      <el-alert
        title="项目拒绝 build、宿主机目录、特权/设备、host 网络、外部文件、外部卷与外部网络。删除项目会保留命名卷和镜像。"
        type="info"
        :closable="false"
      />
    </el-form>
    <template #footer
      ><el-button :disabled="busy" @click="projectOpen = false">取消</el-button
      ><el-button
        type="primary"
        :loading="busy"
        :disabled="
          busy || Boolean(pendingCreate) || createBlocked ||
          !projectForm.name ||
          (projectForm.mode === 'template'
            ? !projectForm.templateId || !projectForm.hostPort
            : !projectForm.compose)
        "
        @click="createProject"
        >创建并启动</el-button
      ></template
    >
  </el-dialog>
  <el-dialog
    v-model="bindingOpen"
    :title="`绑定网站 · ${bindingProject?.name || 'WordPress'}`"
    width="min(520px, 94vw)"
    :close-on-click-modal="false"
  >
    <el-form label-position="top" @submit.prevent="bindProjectSite">
      <el-form-item label="网站名称"><el-input v-model="bindingForm.name" maxlength="60" /></el-form-item>
      <el-form-item label="网站标识"><el-input v-model="bindingForm.slug" maxlength="32" placeholder="wordpress-site" /></el-form-item>
      <el-form-item label="主域名"><el-input v-model="bindingForm.domain" placeholder="blog.example.com" /></el-form-item>
      <el-alert title="将创建受管 Nginx 网站并代理到应用回环端口，保留原始 Host。域名解析和公网入口可在网站设置中配置。" type="info" :closable="false" />
    </el-form>
    <template #footer>
      <el-button :disabled="busy" @click="bindingOpen = false">取消</el-button>
      <el-button type="primary" :loading="busy" :disabled="!bindingForm.name || !bindingForm.slug || !bindingForm.domain" @click="bindProjectSite">创建并绑定</el-button>
    </template>
  </el-dialog>
  <el-dialog
    v-model="networkOpen"
    title="创建 Docker 网络"
    width="min(520px, 94vw)"
    :close-on-click-modal="false"
  >
    <el-form label-position="top" @submit.prevent="createNetwork"
      ><el-form-item label="网络名称"
        ><el-input
          v-model="networkForm.name"
          maxlength="63"
          placeholder="例如 app-network" /></el-form-item
      ><el-form-item
        ><el-checkbox v-model="networkForm.internal"
          >内部网络（禁止外部访问）</el-checkbox
        ></el-form-item
      ><el-alert
        title="网络使用 bridge 驱动并带面板归属标签；正在被容器使用时不能删除。"
        type="info"
        :closable="false"
    /></el-form>
    <template #footer
      ><el-button :disabled="busy" @click="networkOpen = false">取消</el-button
      ><el-button
        type="primary"
        :loading="busy"
        :disabled="!networkForm.name"
        @click="createNetwork"
        >创建</el-button
      ></template
    >
  </el-dialog>
  <RabbitMQQueues v-if="rabbitQueues" :key="rabbitQueues.id" :api="api" :project="rabbitQueues"
    @close="rabbitQueues = undefined" />
  <DockerContainerMetrics v-if="metricsContainer" :key="metricsContainer.Id" :api="api" :id="metricsContainer.Id"
    :name="nameOf(metricsContainer)" @close="metricsContainer = undefined" />
  <el-dialog
    v-model="logsOpen"
    :title="logsName + ' · 最近日志'"
    width="min(900px, 94vw)"
  >
    <pre class="docker-logs">{{ logs }}</pre>
    <template #footer
      ><el-button @click="logsOpen = false">关闭</el-button></template
    ></el-dialog
  >
  <el-dialog v-model="credentialsOpen" title="连接信息与初始凭据" width="min(640px, 94vw)" destroy-on-close>
    <p v-if="credentialsLoading" role="status">正在读取项目凭据…</p>
    <el-alert v-else-if="credentialsError" :title="credentialsError" type="error" :closable="false" />
    <template v-else-if="credentials">
      <h3 class="credential-project">{{ credentials.projectName }}</h3>
      <p>地址仅在服务器本机可用。远程连接请使用 SSH 隧道。</p>
      <dl class="credential-details">
        <template v-for="endpoint in credentials.endpoints" :key="endpoint.label">
          <dt>{{ endpoint.label }}</dt>
          <dd><code>{{ endpoint.address }}</code></dd>
        </template>
        <template v-if="credentials.template === 'mongodb'">
          <dt>认证数据库</dt>
          <dd><code>admin</code></dd>
        </template>
        <dt>用户名</dt>
        <dd>
          <code>{{ credentials.username }}</code>
          <el-button link type="primary" @click="copyCredential('username')">复制用户名</el-button>
        </dd>
        <dt>密码</dt>
        <dd>
          <code v-if="passwordVisible">{{ credentials.password }}</code>
          <span v-else>已隐藏</span>
          <el-button link type="primary" :aria-pressed="passwordVisible" @click="passwordVisible = !passwordVisible">
            {{ passwordVisible ? "隐藏密码" : "显示密码" }}
          </el-button>
          <el-button v-if="passwordVisible" link type="primary" @click="copyCredential('password')">复制密码</el-button>
        </dd>
      </dl>
      <p>应用内修改过密码时，请使用修改后的密码。</p>
    </template>
    <template #footer>
      <el-button @click="credentialsOpen = false">关闭</el-button>
    </template>
  </el-dialog>
</template>

<style scoped>
.credential-project {
  margin-top: 0;
  overflow-wrap: anywhere;
}
.credential-details {
  display: grid;
  gap: 10px 18px;
  grid-template-columns: minmax(100px, max-content) minmax(0, 1fr);
}
.credential-details dd {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 8px;
  margin: 0;
  overflow-wrap: anywhere;
}
.credential-details code {
  min-width: 0;
}
@media (max-width: 520px) {
  .credential-details { grid-template-columns: minmax(0, 1fr); }
  .credential-details dd { margin-bottom: 6px; }
}
.docker-summary {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 10px;
  margin-bottom: 12px;
}
.docker-summary > div {
  display: grid;
  gap: 5px;
  padding: 14px;
  border: 1px solid #e4eaf1;
  border-radius: 7px;
  background: #f9fbfc;
  min-width: 0;
}
.docker-summary span,
.docker-summary small {
  color: #7c8ba0;
  font-size: 11px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.docker-summary strong {
  color: #152a47;
  font-size: 21px;
}
.docker-toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  border-bottom: 1px solid #e8edf3;
}
.docker-toolbar :deep(.el-tabs__header) {
  margin: 0;
}
.docker-list {
  min-height: 260px;
  border: 1px solid #e4eaf1;
  border-top: 0;
  border-radius: 0 0 7px 7px;
  overflow: hidden;
}
.docker-row {
  display: grid;
  grid-template-columns:
    minmax(150px, 1fr) minmax(130px, 1fr) minmax(150px, 1.1fr)
    135px minmax(270px, auto);
  gap: 12px;
  align-items: center;
  min-height: 58px;
  padding: 9px 14px;
  border-bottom: 1px solid #edf1f5;
  color: #53667f;
  font-size: 11px;
}
.docker-row:last-child {
  border-bottom: 0;
}
.docker-columns {
  min-height: 38px;
  background: #f5f7fa;
  color: #74849b;
  font-weight: 650;
}
.docker-row > div {
  min-width: 0;
}
.docker-row strong,
.docker-row small {
  display: block;
  overflow-wrap: anywhere;
}
.docker-row strong {
  color: #1a304e;
  font-size: 12px;
}
.docker-row small {
  margin-top: 4px;
  color: #8795a7;
  font-size: 10px;
}
.docker-row code {
  color: #1d385b;
}
.docker-actions {
  display: flex;
  justify-content: flex-end;
  align-items: center;
  white-space: nowrap;
}
.docker-actions .el-button + .el-button {
  margin-left: 7px;
}
.image-row {
  grid-template-columns: minmax(230px, 1.5fr) 110px 90px 155px 90px;
}
.project-row {
  grid-template-columns: minmax(190px, 1.25fr) 85px 100px 135px minmax(
      330px,
      auto
    );
}
.resource-row {
  grid-template-columns:
    minmax(190px, 1.25fr) 120px 90px minmax(180px, 1fr)
    110px;
}
.resource-row code {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.template-option {
  margin-left: 10px;
  color: #8795a7;
  font-size: 11px;
}
.compose-editor :deep(textarea) {
  font:
    12px/1.55 ui-monospace,
    SFMono-Regular,
    Menlo,
    monospace;
}
.docker-form-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 0 14px;
}
.form-help {
  margin-top: 5px;
  color: #8b98a9;
  font-size: 11px;
}
.docker-logs {
  min-height: 280px;
  max-height: 60vh;
  margin: 0;
  padding: 16px;
  overflow: auto;
  border-radius: 6px;
  background: #111820;
  color: #d7e6dc;
  font:
    12px/1.65 ui-monospace,
    SFMono-Regular,
    Menlo,
    monospace;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
}
@media (max-width: 760px) {
  .docker-summary {
    grid-template-columns: 1fr 1fr;
  }
  .docker-toolbar {
    align-items: stretch;
    flex-direction: column;
    gap: 10px;
    padding-bottom: 10px;
  }
  .docker-row,
  .image-row,
  .project-row,
  .resource-row {
    grid-template-columns: 1fr auto;
    gap: 7px 12px;
    padding: 13px;
  }
  .docker-columns {
    display: none;
  }
  .docker-row > div:first-child,
  .docker-actions {
    grid-column: 1/-1;
  }
  .docker-actions {
    justify-content: flex-start;
    flex-wrap: wrap;
  }
  .docker-form-grid {
    grid-template-columns: 1fr;
  }
}
</style>
