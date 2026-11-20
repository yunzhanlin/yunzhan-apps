export interface HardeningParameter {
  key: string; actual: string; target: string; original: string; managed: boolean;
  original_known: boolean; reversible: boolean; drift: boolean; detail: string;
}
export interface HardeningTransaction {
  id: string; sha256: string; action: string; started_at: string; finished_at?: string;
  from_profile: string; to_profile: string; state: string; recovery_permitted: boolean; detail: string;
}
export interface HardeningInspection {
  format: number; checked_at: string; installed: boolean; healthy: boolean; version: string;
  profile: string; config_matches: boolean; originals_complete: boolean; parameters: HardeningParameter[];
  pending: HardeningTransaction | null; history: HardeningTransaction[]; retained_temporaries: number; detail: string;
}

const transaction = (row: HardeningTransaction) => ({
  id: row.id, sha256: row.sha256, action: row.action, state: row.state,
  started_at: row.started_at, finished_at: row.finished_at || null,
  from_profile: row.from_profile, to_profile: row.to_profile,
  recovery_permitted: row.recovery_permitted, detail: row.detail,
});

export function buildHardeningAuditExport(source: HardeningInspection) {
  const checked = Date.parse(source.checked_at);
  if (!Number.isFinite(checked) || source.format !== 1) throw new Error("无法核对本次检查时间，未导出");
  const report = {
    format: 1, kind: "yunzhan-system-hardening-inspection", checked_at: source.checked_at,
    installed: source.installed, healthy: source.healthy, version: source.version,
    profile: source.profile, config_matches: source.config_matches, originals_complete: source.originals_complete,
    detail: source.detail, retained_temporaries: source.retained_temporaries,
    parameters: source.parameters.map(row => ({
      key: row.key, actual: row.actual || null, target: row.managed ? row.target : null,
      original: row.original_known ? row.original : null, managed: row.managed,
      original_known: row.original_known, reversible: row.reversible, drift: row.drift, detail: row.detail,
    })),
    pending: source.pending === null ? null : transaction(source.pending),
    history: source.history.map(transaction),
  };
  const stamp = new Date(checked).toISOString().slice(0, 19).replaceAll(":", "");
  return { filename: `yunzhan-hardening-${stamp}Z.json`, text: JSON.stringify(report, null, 2) + "\n" };
}
