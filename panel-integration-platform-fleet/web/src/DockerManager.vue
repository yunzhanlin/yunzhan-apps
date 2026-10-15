<script setup lang="ts">
import { formatPanelDateTime } from "./panelTime";
import { randomId } from "./randomId";
import { computed, ref } from "vue";
import { ElMessage, ElMessageBox } from "element-plus";
const credentialsOpen=ref(false),credentials=ref<unknown>();
async function showCredentials(item:DockerProject){try{credentials.value=await props.api(`/docker/projects/${item.id}/credentials`,"POST",{});credentialsOpen.value=true}catch(e){ElMessage.error(e instanceof Error?e.message:String(e))}}
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
  host_port?: number;
  site_name?: string;
  created_at: string;
}
interface DockerTemplate {
  id: string;
  name: string;
  image: string;
  description: string;
  container_port: number;
}
interface DockerJob {
  job_id: string;
  state: string;
  error?: string;
  message?: string;
  container_id?: string;
  image?: string;
}
const props = defineProps<{
  api: <T>(path: string, method?: string, body?: unknown, idempotencyKey?: string) => Promise<T>;
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
const projectForm = ref({
  name: "",
  mode: "template",
  templateId: "nginx-static",
  hostPort: "18080",
  compose:
    "services:\n  app:\n    image: alpine:3.22\n    restart: unless-stopped\n",
});
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
const taggedImages = computed(() =>
  images.value
    .flatMap((image) => image.RepoTags || [])
    .filter((name) => name !== "<none>:<none>"),
);
const short = (id: string) => id.replace(/^sha256:/, "").slice(0, 12);
const nameOf = (item: DockerContainer) =>
  item.Names?.[0]?.replace(/^\//, "") || short(item.Id);
const bytes = (n: number) =>
  n >= 1073741824
    ? (n / 1073741824).toFixed(1) + " GB"
    : n >= 1048576
      ? (n / 1048576).toFixed(1) + " MB"
      : (n / 1024).toFixed(1) + " KB";
const date = (seconds: number) =>
  formatPanelDateTime(seconds * 1000);

async function load() {
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
      props.api<Overview>("/docker"),
      props.api<{ containers: DockerContainer[] }>("/docker/containers"),
      props.api<{ images: DockerImage[] }>("/docker/images"),
      props.api<{ projects: DockerProject[] }>("/docker/projects"),
      props.api<{ networks: DockerNetwork[] }>("/docker/networks"),
      props.api<{ volumes: DockerVolume[] }>("/docker/volumes"),
      props.api<{ templates: DockerTemplate[] }>("/docker/templates"),
    ]);
    overview.value = status;
    containers.value = containerData.containers || [];
    images.value = imageData.images || [];
    projects.value = projectData.projects || [];
    networks.value = networkData.networks || [];
    volumes.value = volumeData.volumes || [];
    templates.value = templateData.templates || [];
  } catch (e) {
    ElMessage.error((e as Error).message);
  } finally {
    loading.value = false;
  }
}
function open() {
  visible.value = true;
  void load();
}
async function openTemplate(templateId: string) {
  visible.value = true;
  await load();
  if (!templates.value.some((template) => template.id === templateId)) {
    ElMessage.error("应用模板暂不可用");
    return;
  }
  newProject();
  projectForm.value.templateId = templateId;
  const occupied = new Set(containers.value.flatMap((item) => item.Ports?.map((port) => port.PublicPort) || []));
  let port = 18080;
  while (occupied.has(port) && port < 65535) port++;
  projectForm.value.hostPort = String(port);
  projectOpen.value = true;
}
defineExpose({ open, openTemplate });

async function waitJob(job: DockerJob) {
  const deadline = Date.now() + 20 * 60 * 1000;
  while (["queued", "running"].includes(job.state) && Date.now() < deadline) {
    await new Promise((resolve) => setTimeout(resolve, 900));
    job = await props.api<DockerJob>(`/docker/jobs/${job.job_id}`);
  }
  if (job.state !== "succeeded")
    throw new Error(job.error || "Docker 作业未完成");
  return job;
}
async function pull() {
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
    image = result.value.trim();
  } catch {
    return;
  }
  busy.value = true;
  try {
    let job = await props.api<DockerJob>("/docker/jobs", "POST", {
      action: "pull",
      image,
    });
    job = await waitJob(job);
    ElMessage.success(`镜像 ${job.image} 已拉取`);
    await load();
  } catch (e) {
    ElMessage.error((e as Error).message);
  } finally {
    busy.value = false;
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
  busy.value = true;
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
    let job = await props.api<DockerJob>("/docker/jobs", "POST", {
      action: "create",
      image: form.value.image.trim(),
      name: form.value.name.trim(),
      restart: form.value.restart,
      ports,
      environment: parseEnvironment(),
      command,
    });
    job = await waitJob(job);
    createOpen.value = false;
    ElMessage.success(`容器 ${form.value.name} 已创建`);
    await load();
  } catch (e) {
    ElMessage.error((e as Error).message);
  } finally {
    busy.value = false;
  }
}
async function action(
  item: DockerContainer,
  actionName: "start" | "stop" | "restart",
) {
  busy.value = true;
  try {
    await props.api(`/docker/containers/${item.Id}/${actionName}`, "POST", {});
    ElMessage.success(
      { start: "容器已启动", stop: "容器已停止", restart: "容器已重启" }[
        actionName
      ],
    );
    await load();
  } catch (e) {
    ElMessage.error((e as Error).message);
  } finally {
    busy.value = false;
  }
}
async function showLogs(item: DockerContainer) {
  busy.value = true;
  try {
    const data = await props.api<{ logs: string }>(
      `/docker/containers/${item.Id}/logs`,
    );
    logs.value = data.logs || "暂无日志输出";
    logsName.value = nameOf(item);
    logsOpen.value = true;
  } catch (e) {
    ElMessage.error((e as Error).message);
  } finally {
    busy.value = false;
  }
}
async function removeContainer(item: DockerContainer) {
  if (item.State === "running") {
    ElMessage.warning("请先停止容器，再执行删除");
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
    busy.value = true;
    await props.api(`/docker/containers/${item.Id}`, "DELETE", {
      confirm_id: result.value,
    });
    ElMessage.success("容器已删除");
    await load();
  } catch (e) {
    if (e instanceof Error && e.message) ElMessage.error(e.message);
  } finally {
    busy.value = false;
  }
}
async function removeImage(item: DockerImage) {
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
    busy.value = true;
    await props.api(
      `/docker/images/${item.Id.replace(/^sha256:/, "")}`,
      "DELETE",
      { confirm_id: result.value },
    );
    ElMessage.success("镜像已删除");
    await load();
  } catch (e) {
    if (e instanceof Error && e.message) ElMessage.error(e.message);
  } finally {
    busy.value = false;
  }
}

function newProject() {
  projectForm.value = {
    name: "",
    mode: "template",
    templateId: templates.value[0]?.id || "nginx-static",
    hostPort: "18080",
    compose:
      "services:\n  app:\n    image: alpine:3.22\n    restart: unless-stopped\n",
  };
  projectOpen.value = true;
}
async function createProject() {
  busy.value = true;
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
    await waitJob(await props.api<DockerJob>("/docker/projects", "POST", body));
    projectOpen.value = false;
    ElMessage.success(`Compose 项目 ${body.name} 已创建并启动`);
    await load();
  } catch (e) {
    ElMessage.error((e as Error).message);
  } finally {
    busy.value = false;
  }
}
function openBinding(item: DockerProject) {
  bindingProject.value = item;
  const slug = item.name.toLowerCase().replace(/[^a-z0-9-]+/g, "-").replace(/^-|-$/g, "").slice(0, 32);
  bindingForm.value = { name: item.name + " 网站", slug: /^[a-z][a-z0-9-]{2,31}$/.test(slug) ? slug : "wordpress-site", domain: "" };
  bindingOpen.value = true;
}
async function bindProjectSite() {
  const item = bindingProject.value;
  if (!item) return;
  busy.value = true;
  try {
    const body = { ...bindingForm.value, domain: bindingForm.value.domain.trim().toLowerCase() };
    const signature = JSON.stringify([item.id, body]);
    const stored = sessionStorage.getItem("panel-pending-app-site");
    let pending: { signature: string; key: string } | null = null;
    try { pending = stored ? JSON.parse(stored) : null; } catch { /* Ignore stale browser state. */ }
    const key = pending?.signature === signature ? pending.key : randomId();
    sessionStorage.setItem("panel-pending-app-site", JSON.stringify({ signature, key }));
    const result = await props.api<{ job_id: string }>(`/docker/projects/${item.id}/sites`, "POST", body, key);
    const deadline = Date.now() + 3 * 60 * 1000;
    let state = "queued", error = "";
    while (["queued", "running"].includes(state) && Date.now() < deadline) {
      await new Promise((resolve) => setTimeout(resolve, 900));
      const job = await props.api<{ state: string; error?: string }>(`/jobs/${result.job_id}`);
      state = job.state;
      error = job.error || "";
    }
    if (state !== "running") throw new Error(error || "网站创建任务需要在任务列表中处理");
    sessionStorage.removeItem("panel-pending-app-site");
    bindingOpen.value = false;
    ElMessage.success(`网站 ${body.domain} 已绑定，域名请解析到本机并在网站设置中启用公网入口`);
  } catch (e) {
    ElMessage.error((e as Error).message);
  } finally {
    busy.value = false;
  }
}
async function projectAction(
  item: DockerProject,
  actionName: "start" | "stop" | "restart" | "update",
) {
  busy.value = true;
  try {
    const job = await props.api<DockerJob>(
      `/docker/projects/${item.id}/${actionName}`,
      "POST",
      {},
    );
    await waitJob(job);
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
    ElMessage.error((e as Error).message);
  } finally {
    busy.value = false;
  }
}
async function showProjectLogs(item: DockerProject) {
  busy.value = true;
  try {
    const data = await props.api<{ logs: string }>(
      `/docker/projects/${item.id}/logs`,
    );
    logs.value = data.logs || "暂无日志输出";
    logsName.value = item.name;
    logsOpen.value = true;
  } catch (e) {
    ElMessage.error((e as Error).message);
  } finally {
    busy.value = false;
  }
}
async function removeProject(item: DockerProject) {
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
    busy.value = true;
    await waitJob(
      await props.api<DockerJob>(`/docker/projects/${item.id}`, "DELETE", {
        confirm_name: result.value,
      }),
    );
    ElMessage.success("项目已删除，命名卷和镜像已保留");
    await load();
  } catch (e) {
    if (e instanceof Error && e.message) ElMessage.error(e.message);
  } finally {
    busy.value = false;
  }
}
function newNetwork() {
  networkForm.value = { name: "", internal: false };
  networkOpen.value = true;
}
async function createNetwork() {
  busy.value = true;
  try {
    await props.api("/docker/networks", "POST", networkForm.value);
    networkOpen.value = false;
    ElMessage.success("Docker 网络已创建");
    await load();
  } catch (e) {
    ElMessage.error((e as Error).message);
  } finally {
    busy.value = false;
  }
}
async function createVolume() {
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
    busy.value = true;
    await props.api("/docker/volumes", "POST", { name: result.value.trim() });
    ElMessage.success("Docker 卷已创建");
    await load();
  } catch (e) {
    if (e instanceof Error && e.message) ElMessage.error(e.message);
  } finally {
    busy.value = false;
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
    busy.value = true;
    await props.api(`/docker/networks/${item.Id}`, "DELETE", {
      confirm_name: result.value,
    });
    ElMessage.success("Docker 网络已删除");
    await load();
  } catch (e) {
    if (e instanceof Error && e.message) ElMessage.error(e.message);
  } finally {
    busy.value = false;
  }
}
async function removeVolume(item: DockerVolume) {
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
    busy.value = true;
    await props.api(`/docker/volumes/${item.Name}`, "DELETE", {
      confirm_name: result.value,
    });
    ElMessage.success("Docker 卷已删除");
    await load();
  } catch (e) {
    if (e instanceof Error && e.message) ElMessage.error(e.message);
  } finally {
    busy.value = false;
  }
}
</script>

<template>
  <el-dialog
    v-model="visible"
    title="Docker 管理"
    width="min(1180px, 96vw)"
    :close-on-click-modal="false"
    class="docker-dialog"
  >
    <div v-if="overview" class="docker-summary">
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
      <el-tabs v-model="tab">
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
          v-if="tab === 'projects'"
          type="primary"
          :icon="Plus"
          :disabled="busy"
          data-compose-create
          @click="newProject"
          >创建项目</el-button
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
        <div class="docker-row project-row docker-columns">
          <span>项目</span><span>服务</span><span>容器</span><span>状态</span
          ><span>操作</span>
        </div>
        <div
          v-for="item in projects"
          :key="item.id"
          class="docker-row project-row"
          :data-compose-project="item.name"
        >
          <div>
            <strong>{{ item.name }}</strong
            ><small>{{ item.engine_name }} · {{ item.id.slice(0, 12) }}</small><small v-if="item.site_name">网站：{{ item.site_name }}</small>
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
            ><small>{{
              formatPanelDateTime(item.created_at)
            }}</small>
          </div>
          <div class="docker-actions">
            <el-button v-if="['mongodb','rabbitmq','openlitespeed'].includes(item.template_id||'')" link type="primary" :disabled="busy" @click="showCredentials(item)">访问凭据</el-button>
            <el-button
              v-if="(item.template_id === 'wordpress-blog' || item.template_id === 'openlitespeed' || item.template_id?.startsWith('php-legacy-')) && item.state === 'running' && !item.site_name"
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
          v-if="!loading && !projects.length"
          description="还没有 Compose 项目，可使用应用模板或受限 Compose 创建"
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
              :type="item.State === 'running' ? 'success' : 'info'"
              size="small"
              >{{ item.State === "running" ? "运行中" : "已停止" }}</el-tag
            ><small>{{ item.Status }}</small>
          </div>
          <div class="docker-actions">
            <el-button
              v-if="item.State !== 'running'"
              link
              type="success"
              :icon="VideoPlay"
              :disabled="busy"
              @click="action(item, 'start')"
              >启动</el-button
            >
            <el-button
              v-else
              link
              type="warning"
              :disabled="busy"
              @click="action(item, 'stop')"
              >停止</el-button
            >
            <el-button
              v-if="item.State === 'running'"
              link
              type="primary"
              :disabled="busy"
              @click="action(item, 'restart')"
              >重启</el-button
            >
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
              :disabled="busy"
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
    <el-form label-position="top" @submit.prevent="createProject">
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
              ><strong>{{ item.name }}</strong
              ><span class="template-option">{{
                item.description
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
            只监听 127.0.0.1；需要公网访问时再通过受管 Nginx 站点反向代理。
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
  <el-dialog v-model="credentialsOpen" title="访问凭据 · 仅管理员可读取" width="640px" destroy-on-close @closed="credentials=undefined">
    <el-alert title="凭据不会缓存到浏览器。请妥善保存；面板只记录读取操作，不记录密码内容。" type="warning" :closable="false"/>
    <pre style="white-space:pre-wrap;overflow-wrap:anywhere">{{JSON.stringify(credentials,null,2)}}</pre>
  </el-dialog>
</template>

<style scoped>
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
