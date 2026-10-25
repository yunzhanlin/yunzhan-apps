type InitialInspection = "server-report" | "policies" | "run";

// This is an inspection selector, not an API permission grant. Unknown future
// modules stay manual until their opening behavior has been reviewed.
const modules = new Set([
  "site-diagnosis", "network-threat-detection", "website-analytics", "files-sync",
  "daily-report", "website-statistics-v2", "enterprise-tamper-proof", "load-balance",
  "mobile-pwa", "apache-waf", "php-code-security", "task-manager",
  "website-tamper-proof", "user-manager", "file-monitor", "disk-analysis",
  "platform-ops", "nfs-manager", "pm2-manager", "pure-ftpd",
]);

export function initialModuleInspection(
  id: string, definition: unknown, installed: unknown, loadSucceeded: unknown,
): InitialInspection | undefined {
  if (loadSucceeded !== true || installed !== true || !modules.has(id)
    || !definition || typeof definition !== "object" || Array.isArray(definition)) return;
  const d = definition as { id?: unknown; actions?: unknown; fields?: unknown };
  if (d.id !== id || !Array.isArray(d.actions) || d.actions.length > 64
    || d.actions.some(action => typeof action !== "string" || !/^[a-z][a-z0-9-]{0,63}$/.test(action))
    || new Set(d.actions).size !== d.actions.length) return;
  if (d.fields !== null && (!Array.isArray(d.fields) || d.fields.length > 64
    || d.fields.some(field => !field || typeof field !== "object" || Array.isArray(field)
      || typeof field.key !== "string" || !/^[a-z][a-z0-9_]{0,63}$/.test(field.key)
      || typeof field.kind !== "string" || !/^[a-z][a-z0-9-]{0,63}$/.test(field.kind))
    || new Set(d.fields.map(field => field.key)).size !== d.fields.length)) return;

  // These views already read their configuration/stored reports via GET.
  // Even the sync plan inventory's POST run is wrapped in report/history
  // persistence. Opening a workspace must not perform that explicit action.
  if (id === "apache-waf" || id === "daily-report" || id === "files-sync") return;
  if (id === "nfs-manager") return d.actions.includes("server-report") ? "server-report" : undefined;
  if (d.actions.includes("policies")) return "policies";
  if (d.actions.includes("run") && id !== "platform-ops"
    && (!(d.fields as { kind: string }[] | null)?.some(field => field.kind === "site")
      || id === "pure-ftpd")) return "run";
}
