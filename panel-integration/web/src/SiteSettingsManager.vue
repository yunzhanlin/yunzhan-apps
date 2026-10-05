<script setup lang="ts">
import PHPWorkerManager from "./PHPWorkerManager.vue";
import { formatPanelDateTime } from "./panelTime";
import { computed, ref, watch } from "vue";
import { ElMessage, ElMessageBox } from "element-plus";
interface Rule {
  pattern: string;
  replacement: string;
  flag: string;
}
interface PHPSettings {
  extensions?: string[];
  memory_mb: number;
  max_execution_seconds: number;
  upload_mb: number;
  post_mb: number;
  timezone: string;
  display_errors: boolean;
  max_children: number;
  max_requests: number;
}
interface Settings {
  public_ingress?: boolean;
  waf_enabled?: boolean;
  acme?: boolean;
  tls?: { certificate_id: string; redirect: boolean } | null;
  php?: PHPSettings | null;
  domains: string[];
  document_root: string;
  index_files: string[];
  mode: string;
  rewrite: string;
  rules: Rule[];
  proxy_url: string;
  redirect_url: string;
  redirect_code: number;
  preserve_uri: boolean;
  web_server?: "nginx" | "apache";
}
interface Site {
  id: string;
  name: string;
  domain: string;
  status: string;
  php_version_id: string;
  settings: Settings;
  settings_revision: number;
}
interface Preview {
  php_current?: string;
  php_candidate?: string;
  current: string;
  candidate: string;
  config_sha: string;
  revision: number;
}
const props = defineProps<{
  siteId: string;
  initialTab?: string;
  api: <T>(path: string, method?: string, body?: unknown) => Promise<T>;
  onJob: (id: string) => Promise<void>;
}>();
const visible = defineModel<boolean>({ default: false });
const site = ref<Site | null>(null),
  form = ref<Settings | null>(null),
  domains = ref(""),
  indexes = ref("");
const tab = ref("basic"),
  loading = ref(false),
  busy = ref(false),
  error = ref(""),
  preview = ref<Preview | null>(null);
const logKind = ref("access"),
  logText = ref(""),
  logTime = ref(""),
  logLoading = ref(false),
  logError = ref("");
const baseline = ref("");
const certificates = ref<
  {
    id: string;
    name: string;
    domains: string[];
    not_after: string;
    status: string;
    trusted: boolean;
  }[]
>([]);
const certificateError = ref("");
async function loadCertificates() {
  certificateError.value = "";
  try {
    certificates.value =
      await props.api<typeof certificates.value>("/certificates");
  } catch (e) {
    certificateError.value = (e as Error).message;
  }
}
function setACME(value: unknown) {
  if (form.value) form.value.acme = !!value;
}
function setPublicIngress(value: unknown) {
  if (form.value) form.value.public_ingress = !!value;
}
function setWebServer(value: unknown) {
  if (!form.value) return;
  form.value.web_server = value === "apache" ? "apache" : "nginx";
  if (form.value.web_server === "apache" && form.value.mode !== "files") {
    form.value.mode = "files";
  }
}
function setTLS(enabled: unknown) {
  if (form.value)
    form.value.tls = enabled ? { certificate_id: "", redirect: false } : null;
}
const extensions = ref<
    {
      extension: { id: string; name: string; version: string };
      status: string;
    }[]
  >([]),
  extensionError = ref("");
async function loadExtensions() {
  extensions.value = [];
  extensionError.value = "";
  if (!site.value?.php_version_id) return;
  try {
    extensions.value = await props.api<typeof extensions.value>(
      `/php/extensions/${site.value.php_version_id}`,
    );
  } catch (e) {
    extensionError.value = (e as Error).message;
  }
}

function setPHP(enabled: unknown) {
  if (!form.value) return;
  form.value.php = enabled
    ? {
        memory_mb: 128,
        max_execution_seconds: 60,
        upload_mb: 2,
        post_mb: 8,
        timezone: "UTC",
        display_errors: false,
        max_children: 3,
        max_requests: 500,
      }
    : null;
}

function payload(): Settings {
  return {
    ...form.value!,
    domains: domains.value
      .split(/\s+/)
      .map((x) => x.trim().toLowerCase())
      .filter(Boolean),
    index_files: indexes.value.split(/[\s,，]+/).filter(Boolean),
  };
}
const signature = computed(() => (form.value ? JSON.stringify(payload()) : ""));
const dirty = computed(() => signature.value !== baseline.value);
watch(signature, () => {
  preview.value = null;
});
const endpoint = (suffix = "") => `/sites/${props.siteId}/settings${suffix}`;
async function load() {
  if (!props.siteId) return;
  loading.value = true;
  error.value = "";
  try {
    const value = await props.api<Site>(endpoint());
    site.value = value;
    form.value = structuredClone(value.settings);
    domains.value = value.settings.domains.join("\n");
    indexes.value = value.settings.index_files.join(", ");
    baseline.value = JSON.stringify(payload());
    preview.value = null;
    await Promise.all([loadExtensions(), loadCertificates()]);
  } catch (e) {
    error.value = (e as Error).message;
  } finally {
    loading.value = false;
  }
}
watch(
  () => [visible.value, props.siteId],
  () => {
    if (visible.value) {
      tab.value = props.initialTab || "basic";
      site.value = null;
      form.value = null;
      void load();
    }
  },
);
async function close(done: () => void) {
  if (busy.value) return;
  if (dirty.value && form.value) {
    try {
      await ElMessageBox.confirm(
        "关闭后将丢弃尚未提交的网站设置。",
        "放弃本次修改",
        { confirmButtonText: "放弃修改", cancelButtonText: "继续编辑" },
      );
    } catch {
      return;
    }
  }
  done();
}
async function reload() {
  if (dirty.value) {
    try {
      await ElMessageBox.confirm(
        "重新读取会替换尚未提交的表单。",
        "重新读取设置",
        { confirmButtonText: "重新读取", cancelButtonText: "保留编辑" },
      );
    } catch {
      return;
    }
  }
  await load();
}
async function makePreview() {
  if (!site.value || !form.value) return;
  busy.value = true;
  error.value = "";
  try {
    preview.value = await props.api<Preview>(endpoint("/preview"), "POST", {
      settings: payload(),
      expected_revision: site.value.settings_revision,
    });
    tab.value = "preview";
  } catch (e) {
    error.value = (e as Error).message;
  } finally {
    busy.value = false;
  }
}
async function submit() {
  if (!site.value || !preview.value) return;
  busy.value = true;
  error.value = "";
  try {
    const result = await props.api<{ job_id: string }>(endpoint(), "POST", {
      settings: payload(),
      expected_revision: site.value.settings_revision,
      expected_config_sha: preview.value.config_sha,
    });
    baseline.value = signature.value;
    visible.value = false;
    ElMessage.success("网站配置任务已提交");
    await props.onJob(result.job_id);
  } catch (e) {
    error.value = (e as Error).message;
  } finally {
    busy.value = false;
  }
}
async function logs() {
  if (!props.siteId) return;
  logLoading.value = true;
  logError.value = "";
  try {
    const data = await props.api<{ content: string; sampled_at: string }>(
      `/sites/${props.siteId}/logs?kind=${logKind.value}`,
    );
    logText.value = data.content;
    logTime.value = data.sampled_at;
  } catch (e) {
    logError.value = (e as Error).message;
  } finally {
    logLoading.value = false;
  }
}
watch(tab, (value: unknown) => {
  if (value === "logs") void logs();
});
const rewriteOptions = [
  { value: "none", label: "无伪静态" },
  { value: "wordpress", label: "WordPress / 通用 PHP 前端入口" },
  { value: "thinkphp", label: "ThinkPHP 路径参数" },
  { value: "spa", label: "单页应用 · index.html" },
  { value: "custom", label: "自定义规则" },
];
</script>
<template>
  <el-dialog
    v-model="visible"
    :title="site ? '网站设置 · ' + site.name : '网站设置'"
    width="min(1060px, 95vw)"
    :close-on-click-modal="false"
    :before-close="close"
    class="website-settings-dialog"
    destroy-on-close
  >
    <div v-loading="loading" class="website-settings">
      <div v-if="site" class="settings-context">
        <span>{{ site.domain }}</span
        ><el-tag size="small" type="info">{{
          site.php_version_id
            ? site.php_version_id.replace("php-", "PHP ")
            : "静态站点"
        }}</el-tag
        ><el-tag size="small" type="success">{{
          form?.web_server === "apache" ? "Apache" : "Nginx"
        }}</el-tag
        ><span>配置版本 {{ site.settings_revision }}</span
        ><el-button link type="primary" :disabled="busy" @click="reload"
          >重新读取</el-button
        >
      </div>
      <el-alert
        v-if="error"
        :title="error"
        type="error"
        :closable="false"
        show-icon
        class="settings-error"
      />
      <el-tabs v-if="form" v-model="tab">
        <el-tab-pane label="网站防护" name="waf">
          <el-form label-position="top" :disabled="busy" class="settings-form">
            <el-form-item label="Nginx 请求防火墙">
              <el-switch :model-value="form.waf_enabled !== false" aria-label="为此网站启用 WAF" @change="form.waf_enabled = !!$event" />
              <div class="settings-help">关闭后，此网站的 HTTP 与 HTTPS 入口均不加载面板 WAF 规则；其他网站保持原状态。需先在软件商店安装 Nginx 请求防火墙，全局规则才会生效。</div>
            </el-form-item>
            <el-alert type="info" :closable="false" title="保存前请生成配置预览；应用时会执行 Nginx 配置检查并验证网站入口，失败自动恢复原配置。" />
          </el-form>
        </el-tab-pane>
        <el-tab-pane label="SSL / HTTPS" name="tls">
          <el-form label-position="top" :disabled="busy" class="settings-form">
            <el-form-item label="ACME HTTP 验证入口"
              ><el-switch
                :model-value="!!form.acme"
                @change="setACME"
                aria-label="ACME HTTP 验证入口"
              />
              <div class="settings-help">
                自动申请证书时启用，用于验证域名归属。关闭后该站点不能自动续期。
              </div></el-form-item
            >
            <el-form-item label="启用 HTTPS">
              <el-switch
                :model-value="!!form.tls"
                aria-label="启用 HTTPS"
                @change="setTLS"
              />
            </el-form-item>
            <el-alert
              v-if="certificateError"
              :title="certificateError"
              type="error"
              :closable="false"
            />
            <template v-if="form.tls">
              <el-form-item label="站点证书">
                <el-select
                  v-model="form.tls.certificate_id"
                  aria-label="站点证书"
                  placeholder="选择已上传的证书"
                  style="width: 100%"
                >
                  <el-option
                    v-for="cert in certificates"
                    :key="cert.id"
                    :value="cert.id"
                    :label="cert.name + ' · ' + cert.domains.join(', ')"
                    :disabled="
                      ['expired', 'not_yet_valid'].includes(cert.status)
                    "
                  />
                </el-select>
                <div class="settings-help">
                  证书必须覆盖主域名和全部附加域名。可在侧栏“SSL
                  证书”中上传新证书。
                </div>
              </el-form-item>
              <el-form-item label="强制 HTTPS">
                <el-switch
                  v-model="form.tls.redirect"
                  aria-label="强制 HTTPS"
                />
                <div class="settings-help">
                  启用后，HTTP 请求会永久重定向到 HTTPS，并保留路径和查询参数。
                </div>
              </el-form-item>
              <el-alert
                :title="
                  form.public_ingress
                    ? '标准 HTTPS 使用 443 端口。使用自签名或私有 CA 证书时，浏览器需要信任对应 CA。'
                    : '当前开发环境的 HTTPS 端口为 19102。使用自签名或私有 CA 证书时，浏览器需要信任对应 CA。'
                "
                type="info"
                :closable="false"
                show-icon
              />
            </template>
          </el-form>
        </el-tab-pane>
        <el-tab-pane label="域名与目录" name="basic"
          ><el-form label-position="top" :disabled="busy" class="settings-form"
            ><el-form-item label="Web 服务">
              <el-radio-group
                :model-value="form.web_server || 'nginx'"
                aria-label="Web 服务"
                @change="setWebServer"
              >
                <el-radio-button value="nginx">Nginx</el-radio-button>
                <el-radio-button value="apache">Apache 2.4.68</el-radio-button>
              </el-radio-group>
              <div class="settings-help">
                Apache 网站仍由 Nginx 处理 80/443、HTTPS 和
                ACME，再转发到只监听回环地址的
                Apache；切换前会校验配置和实际页面。
              </div>
            </el-form-item>
            <el-form-item label="标准网站端口（80 / 443）">
              <el-switch
                :model-value="!!form.public_ingress"
                @change="setPublicIngress"
                aria-label="标准网站端口"
              />
              <div class="settings-help">
                启用后通过服务器的 IPv4 / IPv6
                标准端口提供此网站；请将域名解析到服务器，HTTPS
                还需绑定证书。开发 VM 的标准端口不转发到 Mac。
              </div>
            </el-form-item>
            <div class="settings-grid">
              <el-form-item label="附加域名"
                ><el-input
                  v-model="domains"
                  type="textarea"
                  :rows="5"
                  aria-label="附加域名"
                  placeholder="www.example.com&#10;example.com"
                />
                <div class="settings-help">
                  每行一个，最多 20 个。创建时的主域名始终保留；公网访问还需配置
                  DNS 与监听入口。
                </div></el-form-item
              >
              <div>
                <el-form-item label="文档目录"
                  ><el-input
                    v-model="form.document_root"
                    aria-label="网站文档目录"
                    placeholder="留空使用网站根目录，例如 app/public"
                  />
                  <div class="settings-help">
                    目录需已存在于网站根目录内，可先在文件管理中创建。
                  </div></el-form-item
                ><el-form-item label="默认首页"
                  ><el-input
                    v-model="indexes"
                    aria-label="网站默认首页"
                    placeholder="index.php, index.html"
                  />
                  <div class="settings-help">
                    按顺序查找，以逗号分隔。静态站点会跳过 PHP 首页。
                  </div></el-form-item
                >
              </div>
            </div></el-form
          ></el-tab-pane
        >
        <el-tab-pane label="路由与代理" name="routing"
          ><el-form label-position="top" :disabled="busy" class="settings-form"
            ><el-form-item label="服务模式"
              ><el-radio-group v-model="form.mode" aria-label="网站服务模式"
                ><el-radio-button value="files">网站文件</el-radio-button
                ><el-radio-button value="proxy">反向代理</el-radio-button
                ><el-radio-button value="redirect"
                  >重定向</el-radio-button
                ></el-radio-group
              ></el-form-item
            >
            <template v-if="form.mode === 'files'"
              ><el-form-item label="伪静态模板"
                ><el-select v-model="form.rewrite" aria-label="伪静态模板"
                  ><el-option
                    v-for="option in rewriteOptions"
                    :key="option.value"
                    :value="option.value"
                    :label="option.label"
                    :disabled="
                      ['wordpress', 'thinkphp'].includes(option.value) &&
                      !site?.php_version_id
                    "
                /></el-select>
                <div class="settings-help">
                  模板根据文件是否存在决定回退入口；自定义规则按填写顺序执行。
                </div></el-form-item
              >
              <div v-if="form.rewrite === 'custom'" class="rewrite-rules">
                <div
                  v-for="(rule, index) in form.rules"
                  :key="index"
                  class="rewrite-rule"
                >
                  <el-input
                    v-model="rule.pattern"
                    :aria-label="'规则正则 ' + (index + 1)"
                    placeholder="^/post/([0-9]+)$"
                  /><el-input
                    v-model="rule.replacement"
                    :aria-label="'替换路径 ' + (index + 1)"
                    placeholder="/index.php?id=$1&amp;$args"
                  /><el-select
                    v-model="rule.flag"
                    :aria-label="'规则动作 ' + (index + 1)"
                    ><el-option
                      label="last · 重新匹配"
                      value="last" /><el-option
                      label="break · 停止重写"
                      value="break" /></el-select
                  ><el-button
                    link
                    type="danger"
                    :aria-label="'删除规则 ' + (index + 1)"
                    @click="form.rules.splice(index, 1)"
                    >删除</el-button
                  >
                </div>
                <el-button
                  :disabled="form.rules.length >= 20"
                  @click="
                    form.rules.push({
                      pattern: '^/post/([0-9]+)$',
                      replacement: '/index.php?id=$1&$args',
                      flag: 'last',
                    })
                  "
                  >添加规则</el-button
                >
                <p class="settings-help">
                  受限正则，每条最多 256 字符；目标为站内路径，可使用
                  $1–$9、$uri、$args、$query_string、$is_args。
                </p>
              </div></template
            >
            <template v-if="form.mode === 'proxy'"
              ><el-form-item label="上游地址"
                ><el-input
                  v-model="form.proxy_url"
                  aria-label="代理上游地址"
                  placeholder="http://127.0.0.1:8080/"
                />
                <div class="settings-help">
                  支持 HTTP / HTTPS 和 WebSocket。HTTPS
                  上游会校验证书；地址不要包含账号密码或查询参数。
                </div></el-form-item
              ><el-alert
                title="提交后会验证实际首页响应。上游无法连接或返回服务器错误时，将尝试恢复上一版配置。"
                type="info"
                :closable="false"
            /></template>
            <template v-if="form.mode === 'redirect'"
              ><el-form-item label="目标地址"
                ><el-input
                  v-model="form.redirect_url"
                  aria-label="重定向目标地址"
                  placeholder="https://www.example.com"
              /></el-form-item>
              <div class="settings-grid">
                <el-form-item label="重定向状态码"
                  ><el-select
                    v-model="form.redirect_code"
                    aria-label="重定向状态码"
                    ><el-option :value="302" label="302 · 临时跳转" /><el-option
                      :value="301"
                      label="301 · 永久跳转" /><el-option
                      :value="307"
                      label="307 · 临时，保留方法" /><el-option
                      :value="308"
                      label="308 · 永久，保留方法" /></el-select></el-form-item
                ><el-form-item label="访问路径"
                  ><el-checkbox v-model="form.preserve_uri"
                    >保留原路径和查询参数</el-checkbox
                  >
                  <div class="settings-help">
                    勾选时，目标地址只填写协议、域名和可选端口。
                  </div></el-form-item
                >
              </div></template
            >
          </el-form></el-tab-pane
        >
        <el-tab-pane label="PHP 参数" name="php">
          <p class="settings-help">
            参数跟随本站点的 PHP 版本和
            CLI。保存时先验证独立候选池，再切换网站入口。
          </p>
          <el-alert
            v-if="!site?.php_version_id"
            title="当前为静态站点，PHP 参数将在绑定 PHP 后生效。"
            type="info"
            :closable="false"
          />
          <el-checkbox :model-value="!!form.php" @change="setPHP"
            >使用本站点的独立 PHP 参数</el-checkbox
          >
          <el-form
            v-if="form.php"
            label-position="top"
            class="settings-grid php-settings-form"
          >
            <el-form-item
              label="本站启用的独立扩展"
              class="php-extension-selection"
            >
              <el-alert
                v-if="extensionError"
                :title="extensionError"
                type="error"
                :closable="false"
              />
              <el-checkbox-group
                :model-value="form.php.extensions || []"
                @update:model-value="
                  (value: unknown) => {
                    if (form?.php) form.php.extensions = value as string[];
                  }
                "
              >
                <el-checkbox
                  v-for="item in extensions"
                  :key="item.extension.id"
                  :value="item.extension.id"
                  :disabled="
                    item.status !== 'installed' &&
                    !form.php.extensions?.includes(item.extension.id)
                  "
                  >{{ item.extension.name }} {{ item.extension.version
                  }}{{
                    item.status === "installed"
                      ? ""
                      : item.status === "needs_attention"
                        ? "（需核对）"
                        : "（尚未安装）"
                  }}</el-checkbox
                >
              </el-checkbox-group>
              <p class="settings-help">
                先在「运行环境 → 独立扩展」为此 PHP 版本安装。切换 PHP
                时，目标版本也必须安装所选扩展。关闭独立 PHP
                参数会同时停用这些扩展。
              </p>
            </el-form-item>
            <el-form-item label="内存限制（MiB）"
              ><el-input-number
                v-model="form.php.memory_mb"
                :min="32"
                :max="2048"
                :step="32"
                aria-label="PHP 内存限制"
            /></el-form-item>
            <el-form-item label="脚本执行上限（秒）"
              ><el-input-number
                v-model="form.php.max_execution_seconds"
                :min="0"
                :max="3600"
                aria-label="PHP 执行时间"
              /><small class="settings-help"
                >0 表示不限执行时间</small
              ></el-form-item
            >
            <el-form-item label="单文件上传上限（MiB）"
              ><el-input-number
                v-model="form.php.upload_mb"
                :min="1"
                :max="512"
                aria-label="PHP 上传上限"
            /></el-form-item>
            <el-form-item label="POST 请求上限（MiB）"
              ><el-input-number
                v-model="form.php.post_mb"
                :min="1"
                :max="512"
                aria-label="PHP POST 上限"
              /><small class="settings-help"
                >不得小于上传上限或超过内存限制</small
              ></el-form-item
            >
            <el-form-item label="PHP 时区"
              ><el-select
                v-model="form.php.timezone"
                filterable
                allow-create
                default-first-option
                aria-label="PHP 时区"
                ><el-option
                  v-for="zone in [
                    'UTC',
                    'Asia/Shanghai',
                    'Asia/Hong_Kong',
                    'Asia/Tokyo',
                    'Europe/London',
                    'America/New_York',
                  ]"
                  :key="zone"
                  :label="zone"
                  :value="zone" /></el-select
            ></el-form-item>
            <el-form-item label="页面错误信息"
              ><el-switch
                v-model="form.php.display_errors"
                aria-label="显示 PHP 错误"
              /><small class="settings-help"
                >错误日志仍会保留</small
              ></el-form-item
            >
            <el-form-item label="FPM 最大子进程"
              ><el-input-number
                v-model="form.php.max_children"
                :min="1"
                :max="32"
                aria-label="FPM 最大子进程"
            /></el-form-item>
            <el-form-item label="每个子进程的回收请求数"
              ><el-input-number
                v-model="form.php.max_requests"
                :min="1"
                :max="10000"
                aria-label="FPM 回收请求数"
            /></el-form-item>
          </el-form>
        </el-tab-pane>
        <el-tab-pane label="PHP 进程" name="workers">
          <PHPWorkerManager v-if="tab === 'workers' && site" :key="site.id" :site-id="site.id" :php-version="site.php_version_id" :site-status="site.status" :api="api" />
        </el-tab-pane>
        <el-tab-pane label="配置预览" name="preview"
          ><template v-if="preview"
            ><div class="preview-note">
              提交后会执行所选 Web 服务、Nginx
              入口和实际请求验证。设置表单或实际配置变化后，需要重新生成预览。
            </div>
            <div class="config-comparison">
              <section>
                <h3>当前配置</h3>
                <pre tabindex="0" aria-label="当前网站配置">{{
                  preview.current
                }}</pre>
              </section>
              <section>
                <h3>待应用配置</h3>
                <pre tabindex="0" aria-label="待应用网站配置">{{
                  preview.candidate
                }}</pre>
              </section>
            </div>
            <div
              v-if="preview.php_current || preview.php_candidate"
              class="config-comparison"
            >
              <section>
                <h3>当前 FPM 配置</h3>
                <pre tabindex="0" aria-label="当前 FPM 配置">{{
                  preview.php_current || "未绑定 PHP"
                }}</pre>
              </section>
              <section>
                <h3>候选 FPM 配置</h3>
                <pre tabindex="0" aria-label="候选 FPM 配置">{{
                  preview.php_candidate || "不启用 FPM"
                }}</pre>
              </section>
            </div></template
          >
          <el-empty
            v-else
            description="先编辑设置，再点击“生成配置预览”。"
            :image-size="90"
        /></el-tab-pane>
        <el-tab-pane label="访问与错误日志" name="logs"
          ><div class="logs-toolbar">
            <el-radio-group v-model="logKind" @change="logs"
              ><el-radio-button value="access">访问日志</el-radio-button
              ><el-radio-button value="error"
                >错误日志</el-radio-button
              ></el-radio-group
            ><el-button :loading="logLoading" @click="logs">刷新日志</el-button
            ><small v-if="logTime">{{
              formatPanelDateTime(logTime)
            }}</small>
          </div>
          <el-alert
            v-if="logError"
            :title="logError"
            type="error"
            :closable="false"
          />
          <pre
            v-loading="logLoading"
            class="website-log"
            tabindex="0"
            aria-label="网站日志内容"
            >{{
              logText ||
              "暂无独立日志。首次保存网站设置后会启用，实际访问后可刷新查看。"
            }}</pre>
          <p class="settings-help">
            显示最近 64
            KiB。访问日志保留原始路径，查询参数不会写入；错误日志中的查询值在读取时隐藏。
          </p></el-tab-pane
        >
      </el-tabs>
    </div>
    <template #footer
      ><div class="settings-footer">
        <span v-if="site?.status === 'stopped'"
          >网站当前停用，保存后仍保持停用。</span
        ><span v-else-if="dirty">有尚未提交的修改</span
        ><span v-else>先预览，再应用</span>
        <div>
          <el-button :disabled="busy" @click="close(() => (visible = false))"
            >关闭</el-button
          ><el-button
            :loading="busy && !preview"
            :disabled="loading || !form"
            @click="makePreview"
            >生成配置预览</el-button
          ><el-button
            type="primary"
            :disabled="!preview || loading"
            :loading="busy && !!preview"
            @click="submit"
            >应用此配置</el-button
          >
        </div>
      </div></template
    >
  </el-dialog>
</template>
<style scoped>
.website-settings {
  min-height: 330px;
}
.settings-context {
  display: flex;
  align-items: center;
  gap: 14px;
  color: #8b9a90;
  font-size: 12px;
  margin-bottom: 16px;
  flex-wrap: wrap;
}
.settings-context > span:first-child {
  font-size: 13px;
  color: #3e6150;
  overflow-wrap: anywhere;
}
.settings-context .el-button {
  margin-left: auto;
}
.settings-error {
  margin-bottom: 15px;
}
.settings-form {
  padding: 14px 1px 6px;
}
.settings-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 30px;
}
.settings-help {
  font-size: 12px;
  line-height: 1.8;
  color: #8c9b90;
  margin: 8px 0 0;
}
.settings-form .el-select {
  width: 100%;
}
.rewrite-rules {
  padding: 4px 0 15px;
}
.rewrite-rule {
  display: grid;
  grid-template-columns: 1.05fr 1.25fr 180px 45px;
  gap: 10px;
  margin-bottom: 12px;
}
.rewrite-rule :deep(input) {
  font-family: ui-monospace, monospace;
  font-size: 12px;
}
.preview-note {
  font-size: 12px;
  line-height: 1.8;
  color: #84938a;
  padding: 10px 0 18px;
}
.config-comparison {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 18px;
}
.config-comparison section {
  min-width: 0;
}
.config-comparison h3 {
  font-size: 12px;
  margin: 0 0 10px;
  color: #5b7163;
}
.config-comparison pre,
.website-log {
  font:
    11px/1.85 ui-monospace,
    SFMono-Regular,
    Menlo,
    monospace;
  max-height: 420px;
  min-height: 260px;
  overflow: auto;
  background: #f5f8f5;
  border: 1px solid #e4eae5;
  border-radius: 6px;
  color: #557263;
  padding: 16px;
  margin: 0;
  white-space: pre;
}
.config-comparison pre {
  height: 400px;
}
.logs-toolbar {
  display: flex;
  align-items: center;
  gap: 12px;
  flex-wrap: wrap;
  padding: 12px 0 18px;
}
.logs-toolbar small {
  margin-left: auto;
  font-size: 11px;
  color: #95a095;
}
.website-log {
  min-height: 340px;
}
.settings-footer {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 14px;
}
.settings-footer > span {
  font-size: 11px;
  color: #8c9e8e;
}
.settings-footer > div {
  display: flex;
  gap: 8px;
}
.settings-footer .el-button + .el-button {
  margin-left: 0;
}
@media (max-width: 760px) {
  .settings-grid,
  .config-comparison {
    grid-template-columns: 1fr;
    gap: 15px;
  }
  .settings-context {
    gap: 9px;
  }
  .settings-context .el-button {
    margin-left: 0;
  }
  .rewrite-rule {
    grid-template-columns: 1fr auto;
    gap: 8px;
    padding: 12px 0;
    border-bottom: 1px solid #edf1ee;
  }
  .rewrite-rule > .el-input {
    grid-column: 1/-1;
  }
  .rewrite-rule > .el-select {
    grid-column: 1;
  }
  .settings-footer {
    flex-direction: column;
    align-items: stretch;
  }
  .settings-footer > div {
    flex-wrap: wrap;
    justify-content: flex-end;
  }
  .settings-footer .el-button {
    padding: 10px;
    font-size: 12px;
  }
  .config-comparison pre {
    height: 280px;
    min-height: 200px;
  }
  .logs-toolbar small {
    width: 100%;
    margin-left: 0;
  }
  .website-log {
    min-height: 280px;
  }
  .website-settings :deep(.el-tabs__item) {
    font-size: 12px;
    padding: 0 14px;
  }
}
</style>

<style scoped>
.php-settings-form {
  gap: 18px 24px;
  margin-top: 20px;
}
.php-settings-form .el-select,
.php-settings-form .el-input-number {
  width: 100%;
}
.php-settings-form small {
  width: 100%;
  margin-top: 6px;
}
</style>

<style>
.website-settings-dialog.el-dialog {
  margin: 16px auto;
  max-height: calc(100dvh - 32px);
  display: flex;
  flex-direction: column;
}
.website-settings-dialog .el-dialog__header,
.website-settings-dialog .el-dialog__footer {
  flex-shrink: 0;
}
.website-settings-dialog .el-dialog__body {
  flex: 1;
  min-height: 0;
  overflow: auto;
}
.website-settings-dialog .config-comparison + .config-comparison {
  margin-top: 24px;
}
</style>

<style scoped>
.php-extension-selection {
  grid-column: 1 / -1;
}
</style>
