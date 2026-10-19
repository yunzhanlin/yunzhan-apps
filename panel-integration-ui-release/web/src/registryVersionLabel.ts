interface VersionRecord {
  installed?: boolean;
  state_known?: boolean;
  version_known?: boolean;
  installed_version?: string;
  version_source?: string;
  update_available?: boolean;
  instances?: unknown[];
}
function version(value: unknown): string | undefined {
  return typeof value === "string" && value.length <= 128 && /^[0-9]+(?:\.[0-9]+){0,3}(?:-[A-Za-z0-9]+(?:[.-][A-Za-z0-9]+)*)?$/.test(value) ? value : undefined;
}

// Presentation only: never compare an upstream program version with a package
// revision, infer an update, change a status or grant an installation action.
export function registryVersionLabel(provider: string, catalogVersion: string, status?: VersionRecord): string {
  const repository = version(catalogVersion) || "版本待核对";
  const installed = status?.installed === true && status.state_known !== false && status.version_known === true ? version(status.installed_version) : undefined;
  if (provider === "runtime") return `已安装记录 ${installed || "版本待核对"} · 仓库安装包 ${repository}`;
  if (provider === "compose" && status?.installed === true && status.state_known !== false && Array.isArray(status.instances) && status.instances.length > 1 && status.instances.length <= 128)
    return `已安装 ${status.instances.length} 个实例（分别核对版本） · 仓库应用包 ${repository}`;
  if (status?.version_source === "upstream-image")
    return `镜像程序 ${installed || "版本待核对"} · 仓库应用包 ${repository}（应用包修订待核对）`;
  const arrow = installed && status?.update_available === true ? " → " : " · ";
  return `已安装应用包 ${installed || "版本待核对"}${arrow}仓库应用包 ${repository}`;
}
