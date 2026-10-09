export const menuPermissionIDs = ["overview", "sites", "databases", "files", "security", "runtimes", "schedules", "monitor", "terminal", "panel-access", "audit", "system-tools"] as const;
export interface AccessPlan { role: "admin" | "operator" | "viewer"; menu_ids: string[] }
export function validAccessPlan(value: unknown): value is AccessPlan {
  const v = value as AccessPlan;
  return !!v && ["admin", "operator", "viewer"].includes(v.role) && Array.isArray(v.menu_ids)
    && v.menu_ids.length <= menuPermissionIDs.length && new Set(v.menu_ids).size === v.menu_ids.length
    && v.menu_ids.every(id => (menuPermissionIDs as readonly string[]).includes(id)
      && (v.role === "admin" || ["overview", "sites", "files", "monitor"].includes(id)));
}
export function canOpenView(access: AccessPlan | null, key: string): boolean {
  if (!access) return false;
  if (key === "account") return true;
  const aliases: Record<string, string> = { jobs: "audit", backups: "system-tools", certificates: "sites" };
  return access.menu_ids.includes(aliases[key] || key);
}
// Background refresh must not issue unauthorized global queries or reuse the
// previous account's data; the server independently checks every request.
export function canReadPath(access: AccessPlan | null, value: string): boolean {
  if (!access) return false;
  const root = value.split("?")[0].split("/")[1];
  if (["me", "account"].includes(root)) return true;
  if (root === "sites") return value.split("?")[0] === "/sites"
    ? access.menu_ids.some(id => ["sites", "files"].includes(id))
    : access.role === "admin" && access.menu_ids.includes("sites");
  if (root === "overview") return access.menu_ids.includes("overview");
  if (root === "monitor") return access.menu_ids.includes("monitor");
  if (access.role !== "admin") return false;
  if (root === "app-modules") return access.menu_ids.includes("security")
    && /^\/app-modules\/network-threat-detection\/operations(?:\/[a-f0-9]{32})?$/.test(value.split("?")[0]);
  const menu: Record<string, string> = { certificates: "sites", jobs: "audit", audit: "audit", notifications: "audit", runtimes: "runtimes", software: "runtimes", "app-registry": "runtimes" };
  return !!menu[root] && access.menu_ids.includes(menu[root]);
}
