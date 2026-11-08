export interface SoftwareStateRecord {
  id: string;
  installed: boolean;
  enabled: boolean;
  healthy: boolean;
  state_unknown?: boolean;
}

export type SoftwareInstallState = "unknown" | "installed" | "absent";

// Missing, duplicate, or malformed responses are not proof of absence.
// Older executors omit state_unknown; an explicit false remains compatible.
export function uniqueSoftwareStatus<T extends SoftwareStateRecord>(rows: readonly T[], id: string): T | undefined {
  const matches = rows.filter(row => row?.id === id);
  return matches.length === 1 ? matches[0] : undefined;
}

export function softwareInstallState(status?: SoftwareStateRecord | null): SoftwareInstallState {
  if (!status || typeof status.installed !== "boolean" || typeof status.enabled !== "boolean" ||
      typeof status.healthy !== "boolean" || (status.state_unknown !== undefined && status.state_unknown !== false) ||
      (!status.installed && status.healthy)) return "unknown";
  return status.installed ? "installed" : "absent";
}
