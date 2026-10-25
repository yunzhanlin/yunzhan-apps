interface UpdateRecord {
  update_available?: boolean;
  update_supported?: boolean;
  update_kind?: string;
}

// Static labels/navigation only; these functions do not infer versions, grant
// update permission or submit a request. The backend's exact status owns that.
export function registryManualUpdateReview(status?: UpdateRecord): boolean {
  return status?.update_kind === "compose-review" || status?.update_kind === "runtime-host-review" || status?.update_kind === "waf-config-review" || status?.update_kind === "memcached-unix-migration";
}
export function registryUpdateActionLabel(status?: UpdateRecord): string {
  if (status?.update_kind === "memcached-unix-migration") return "查看迁移方案";
  if (status?.update_kind === "waf-config-review") return "核对 WAF 配置";
  if (status?.update_kind === "runtime-host-review") return "核对 Docker 宿主";
  if (status?.update_supported === true) return status.update_kind === "runtime-package-review" ? "核对应用包" : "更新应用";
  return status?.update_kind === "compose-review" ? "核对容器更新" : "需升级面板";
}
export function registryUpdateBadge(status?: UpdateRecord): string {
  if (status?.update_kind === "memcached-unix-migration") return "需新建 Socket 实例";
  if (status?.update_kind === "waf-config-review") return "配置待核对";
  if (status?.update_kind === "runtime-package-review") return "应用包待核对";
  if (status?.update_kind === "runtime-host-review") return "更新待核对";
  return "有新版";
}
