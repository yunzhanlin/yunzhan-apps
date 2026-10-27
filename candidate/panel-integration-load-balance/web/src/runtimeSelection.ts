// Pure display selection only. These values never install or activate a runtime.
export interface RuntimeChoiceRelease {
  id: string; version: string; channel: string;
  installation_allowed?: boolean;
  security?: { status: string };
}
export interface RuntimeChoiceFamily {
  family: string; state: string; releases?: readonly RuntimeChoiceRelease[];
  versions: readonly string[];
}
export interface RuntimeChoiceSnapshot {
  catalog: readonly RuntimeChoiceFamily[];
  installed: readonly { id: string; family: string; version: string; status: string }[];
  active_nginx?: string;
}
const validFamily = (value: unknown): value is string => typeof value === "string" && /^[a-z][a-z0-9-]{0,31}$/.test(value);
const validID = (value: unknown): value is string => typeof value === "string" && /^[a-z][a-z0-9.+_-]{1,126}$/.test(value);
const validVersion = (value: unknown): value is string => typeof value === "string" && /^[0-9]{1,9}(?:\.[0-9]{1,9}){1,3}(?:[-+][a-zA-Z0-9.~+-]{1,64})?$/.test(value);
function versionOrder(a: RuntimeChoiceRelease, b: RuntimeChoiceRelease): number {
  const left = a.version.split(/[-+]/, 1)[0].split(".").map(Number);
  const right = b.version.split(/[-+]/, 1)[0].split(".").map(Number);
  for (let i = 0; i < Math.max(left.length, right.length); i++) {
    if ((left[i] || 0) !== (right[i] || 0)) return (right[i] || 0) - (left[i] || 0);
  }
  return a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
}
function selectable(family: RuntimeChoiceFamily, release: RuntimeChoiceRelease): boolean {
  return family.state === "available" && release.channel !== "eol" &&
    release.security?.status !== "affected" && release.installation_allowed !== false &&
    (family.family !== "php" || release.installation_allowed === true);
}

/**
 * Unmarked defaults follow fresh server data. Explicit, still-valid user choices
 * survive polling. An account/authorization reset must clear BOTH input maps.
 * No receipt, binary, running-service or website-migration claim is inferred.
 */
export function reconcileRuntimeChoices(
  snapshot: RuntimeChoiceSnapshot,
  current: Readonly<Record<string, string>> = {},
  explicit: Readonly<Record<string, string>> = {},
): { selected: Record<string, string>; explicit: Record<string, string> } {
  const selected: Record<string, string> = Object.create(null);
  const kept: Record<string, string> = Object.create(null);
  if (!snapshot || !Array.isArray(snapshot.catalog) || snapshot.catalog.length > 32 ||
      !Array.isArray(snapshot.installed) || snapshot.installed.length > 1024) return { selected, explicit: kept };
  const familyCounts = new Map<string, number>(), releaseCounts = new Map<string, number>();
  const installations = new Map<string, RuntimeChoiceSnapshot["installed"][number]>();
  const duplicateInstalled = new Set<string>();
  for (const row of snapshot.installed) {
    if (!row || !validID(row.id)) continue;
    if (installations.has(row.id)) duplicateInstalled.add(row.id);
    else installations.set(row.id, row);
  }
  for (const row of snapshot.catalog) {
    if (!row || !validFamily(row.family)) continue;
    familyCounts.set(row.family, (familyCounts.get(row.family) || 0) + 1);
    if (Array.isArray(row.releases) && row.releases.length <= 256) {
      for (const release of row.releases) if (release && validID(release.id)) {
        releaseCounts.set(release.id, (releaseCounts.get(release.id) || 0) + 1);
      }
    }
  }
  for (const family of snapshot.catalog) {
    if (!family || !validFamily(family.family) || familyCounts.get(family.family) !== 1) continue;
    if (!Array.isArray(family.releases) || family.releases.length === 0) {
      // Legacy labels are display-only: absence of an exact release never
      // grants native installation. The existing installability guard stays.
      const label = Array.isArray(family.versions) ? family.versions.find(validVersion) : undefined;
      if (label) selected[family.family] = label;
      continue;
    }
    if (family.releases.length > 256) continue;
    const releases: RuntimeChoiceRelease[] = family.releases.filter((release: RuntimeChoiceRelease) => release && validID(release.id) &&
      release.id.startsWith(family.family + "-") && validVersion(release.version) &&
      typeof release.channel === "string" && release.channel.length <= 32 &&
      releaseCounts.get(release.id) === 1);
    const installed = (release: RuntimeChoiceRelease) => {
      const row = installations.get(release.id);
      return !!row && !duplicateInstalled.has(release.id) && row.status === "installed" &&
        row.family === family.family && row.version === release.version;
    };
    const chosen = explicit[family.family];
    if (chosen && chosen === current[family.family]) {
      const release = releases.find(row => row.id === chosen);
      if (release && (installed(release) || selectable(family, release))) {
        selected[family.family] = chosen; kept[family.family] = chosen; continue;
      }
    }
    const actual = releases.filter(installed);
    if (family.family === "nginx") {
      const active = actual.find(row => row.id === snapshot.active_nginx);
      if (active) { selected[family.family] = active.id; continue; }
    }
    const maintained = actual.filter(row => row.channel !== "eol" &&
      row.security?.status !== "affected" && (family.family !== "php" || row.installation_allowed === true));
    const candidate = maintained.sort(versionOrder)[0] || actual.sort(versionOrder)[0] ||
      releases.find(row => selectable(family, row));
    if (candidate) selected[family.family] = candidate.id;
  }
  return { selected, explicit: kept };
}

