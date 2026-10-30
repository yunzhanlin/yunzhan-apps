export type NFSReportKind = "server" | "clients";
const record = (value: unknown): value is Record<string, unknown> => !!value && typeof value === "object" && !Array.isArray(value);
const resource = (value: unknown): value is string => typeof value === "string" && /^[a-z][a-z0-9-]{2,31}$/.test(value);

export function nfsSectionKind(section: string): NFSReportKind | undefined {
  if (["server", "listener", "export", "export-remove"].includes(section)) return "server";
  if (["mounts", "mount", "unmount"].includes(section)) return "clients";
  return undefined;
}

export function nfsReportKind(value: unknown): NFSReportKind | undefined {
  if (!record(value)) return undefined;
  const config = value.config;
  const server = record(config) && Array.isArray(config.exports) && Number.isSafeInteger(config.revision) && Number(config.revision) >= 0
    && typeof config.bind_address === "string" && config.bind_address.length > 0 && Number.isInteger(config.port) && Number(config.port) >= 1024 && Number(config.port) <= 65535;
  const serverReceipt = typeof value.actual_nfs_v4_rpc === "boolean" && Number.isSafeInteger(value.exports) && Number(value.exports) >= 0 && typeof value.encrypted === "boolean"
    || typeof value.service_active === "boolean" && value.exports_and_files_retained === true;
  const client = Array.isArray(value.mounts) || resource(value.mounted) && value.path === "/srv/panel/nfs/" + value.mounted || resource(value.unmounted);
  if ((server || serverReceipt) && client) return undefined;
  if (server || serverReceipt) return "server";
  if (client) return "clients";
  return undefined;
}

export function nfsReportForSection(section: string, value: unknown): Record<string, unknown> | undefined {
  const kind = nfsSectionKind(section);
  return kind && kind === nfsReportKind(value) ? value as Record<string, unknown> : undefined;
}

export function nfsSectionReadAction(kind: NFSReportKind): "server-report" | "run" {
  return kind === "server" ? "server-report" : "run";
}
