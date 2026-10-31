// Reverse only the exact reviewed PHP preview/CAS UI additions. Existing
// whole-App and build-script digests remain unchanged; unknown edits survive
// the normalization or fail an exact-fragment assertion.
import assert from 'node:assert/strict';
const edits = [
  [
    "import { useMobileNavigation } from \"./mobileNavigation\";\nimport { phpSecurityFor, phpSecurityExposure } from \"./phpSecurity\";\nimport { parsePHPSwitchPreview, samePHPSwitchContext, type PHPSwitchContext, type PHPSwitchPreview } from \"./phpSwitchPreview\";\nimport { softwareInstallState, uniqueSoftwareStatus } from \"./softwareState\";\nimport { reconcileRuntimeChoices } from \"./runtimeSelection\";\nimport type { SecurityAppCatalogItem, SecurityAppStatus } from \"./SecurityAppManager.vue\";\nimport PanelIcon from \"./PanelIcon.vue\";\nimport { computed, defineAsyncComponent, nextTick, onMounted, onUnmounted, ref, shallowRef, watch } from \"vue\";\nimport { ElMessage, ElMessageBox } from \"element-plus\";\nimport {\n",
    "import { useMobileNavigation } from \"./mobileNavigation\";\nimport { phpSecurityFor, phpSecurityExposure } from \"./phpSecurity\";\nimport { softwareInstallState, uniqueSoftwareStatus } from \"./softwareState\";\nimport { reconcileRuntimeChoices } from \"./runtimeSelection\";\nimport type { SecurityAppCatalogItem, SecurityAppStatus } from \"./SecurityAppManager.vue\";\nimport PanelIcon from \"./PanelIcon.vue\";\nimport { computed, defineAsyncComponent, nextTick, onMounted, onUnmounted, ref, shallowRef } from \"vue\";\nimport { ElMessage, ElMessageBox } from \"element-plus\";\nimport {\n"
  ],
  [
    "  runtime_instance_id: string;\n  php_version_id: string;\n  settings_revision: number;\n}\ninterface Job {\n",
    "  runtime_instance_id: string;\n  php_version_id: string;\n}\ninterface Job {\n"
  ],
  [
    "  phpSelection = ref(\"\"),\n  submittingPHP = ref(false);\nconst phpPreview = shallowRef<PHPSwitchPreview>();\nlet phpPreviewEpoch = 0;\nfunction phpSwitchContext(): PHPSwitchContext | null {\n  const site = sites.value.find(item => item.id === phpTarget.value?.id);\n  if (!phpOpen.value || !site || !accessPlan.value || ![\"admin\", \"operator\"].includes(accessPlan.value.role) || !canOpenView(accessPlan.value, \"sites\")) return null;\n  return {site_id:site.id, release_id:phpSelection.value, current_release_id:site.php_version_id,\n    revision:site.settings_revision, access:JSON.stringify(accessPlan.value)};\n}\nwatch(() => JSON.stringify(phpSwitchContext()), () => { phpPreviewEpoch++; phpPreview.value = undefined; }, {flush:\"sync\"});\nconst installedPHP = computed(() =>\n  runtimes.value.installed.filter(\n",
    "  phpSelection = ref(\"\"),\n  submittingPHP = ref(false);\nconst installedPHP = computed(() =>\n  runtimes.value.installed.filter(\n"
  ],
  [
    "}\nfunction choosePHP(site: Site) {\n  if (submittingPHP.value) return;\n  phpTarget.value = site;\n  phpSelection.value = site.php_version_id;\n  phpOpen.value = true;\n}\nasync function readPHPPreview() {\n  const context = phpSwitchContext(), epoch = phpPreviewEpoch;\n  if (!context) throw Error(\"网站或账户权限已变化，请重新打开 PHP 切换\");\n  const value = await api<unknown>(`/sites/${context.site_id}/php/preview`, \"POST\", {release_id:context.release_id});\n  if (epoch !== phpPreviewEpoch || !samePHPSwitchContext(context, phpSwitchContext())) throw Error(\"PHP 选择或网站状态已变化，原预览已失效\");\n  const preview = parsePHPSwitchPreview(value, context);\n  phpPreview.value = preview;\n  return {context,preview,epoch};\n}\nasync function previewPHP() {\n  if (submittingPHP.value) return;\n  submittingPHP.value = true;\n  try { await readPHPPreview(); } catch(e) { ElMessage.error((e as Error).message); }\n  finally { submittingPHP.value = false; }\n}\nasync function switchPHP() {\n  if (!phpTarget.value || submittingPHP.value) return;\n  submittingPHP.value = true;\n  try {\n    const {context,preview,epoch} = await readPHPPreview();\n    if (epoch !== phpPreviewEpoch || !samePHPSwitchContext(context, phpSwitchContext())) throw Error(\"网站状态已变化，请重新预览\");\n    const result = await api<{ job_id: string }>(\n      `/sites/${context.site_id}/php`,\n      \"POST\",\n      { release_id: context.release_id, expected_config_sha: preview.config_sha },\n    );\n    phpOpen.value = false;\n",
    "}\nfunction choosePHP(site: Site) {\n  phpTarget.value = site;\n  phpSelection.value = site.php_version_id;\n  phpOpen.value = true;\n}\nasync function switchPHP() {\n  if (!phpTarget.value) return;\n  submittingPHP.value = true;\n  try {\n    const result = await api<{ job_id: string }>(\n      `/sites/${phpTarget.value.id}/php`,\n      \"POST\",\n      { release_id: phpSelection.value },\n    );\n    phpOpen.value = false;\n"
  ],
  [
    "      v-model=\"phpOpen\"\n      title=\"网站 PHP 版本\"\n      width=\"760px\"\n      class=\"create-dialog\"\n      :close-on-click-modal=\"false\"\n      :close-on-press-escape=\"!submittingPHP\"\n      :show-close=\"!submittingPHP\"\n    >\n      <template v-if=\"phpTarget\"\n",
    "      v-model=\"phpOpen\"\n      title=\"网站 PHP 版本\"\n      width=\"500px\"\n      class=\"create-dialog\"\n      :close-on-click-modal=\"false\"\n    >\n      <template v-if=\"phpTarget\"\n"
  ],
  [
    "          v-model=\"phpSelection\"\n          aria-label=\"目标 PHP 版本\"\n          :disabled=\"submittingPHP\"\n          style=\"width: 100%\"\n          ><el-option value=\"\" label=\"静态站点（禁止执行 PHP）\" /><el-option\n",
    "          v-model=\"phpSelection\"\n          aria-label=\"目标 PHP 版本\"\n          style=\"width: 100%\"\n          ><el-option value=\"\" label=\"静态站点（禁止执行 PHP）\" /><el-option\n"
  ],
  [
    "          CLI 绑定；失败保留原版本。\n        </p>\n        <p v-if=\"phpPreview\" data-testid=\"php-switch-preview-mode\">\n          {{ phpPreview.preserves_custom_config ? \"仅替换 PHP 绑定与受管健康检查，保留其余网站配置。\" : \"该操作将重新生成网站配置，请核对下方预览。\" }}\n        </p>\n        <details v-if=\"phpPreview\" data-testid=\"php-switch-config-preview\">\n          <summary>查看当前配置与切换后配置</summary>\n          <p>当前配置</p><pre style=\"max-height:220px;overflow:auto;white-space:pre-wrap\">{{ phpPreview.current }}</pre>\n          <p>切换后配置</p><pre style=\"max-height:220px;overflow:auto;white-space:pre-wrap\">{{ phpPreview.candidate }}</pre>\n        </details>\n        <div class=\"dialog-actions\">\n          <el-button :disabled=\"submittingPHP\" @click=\"phpOpen = false\">取消</el-button>\n          <el-button :disabled=\"submittingPHP\" @click=\"previewPHP\">预览配置</el-button\n          ><el-button type=\"primary\" :loading=\"submittingPHP\" @click=\"switchPHP\"\n            >验证并切换</el-button\n",
    "          CLI 绑定；失败保留原版本。\n        </p>\n        <div class=\"dialog-actions\">\n          <el-button @click=\"phpOpen = false\">取消</el-button\n          ><el-button type=\"primary\" :loading=\"submittingPHP\" @click=\"switchPHP\"\n            >验证并切换</el-button\n"
  ]
];
export function beforePHPSwitchPreviewApp(text) {
 for (const [current, previous] of edits) {
  assert.equal(text.split(current).length, 2, 'missing or duplicate reviewed PHP preview UI fragment');
  text = text.replace(current, () => previous);
 }
 return text;
}
