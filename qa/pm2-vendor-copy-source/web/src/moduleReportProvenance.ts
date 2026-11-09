export type ReportOrigin = "stored" | "request" | "retained";
export interface ReportProvenance { origin: ReportOrigin; generatedAt?: string }
// An envelope timestamp is evidence about the saved report, never a new clock
// or a reason to mark old worker/configuration fields healthy now.
export function moduleReportProvenance(value: unknown, origin: ReportOrigin): ReportProvenance {
  const result: ReportProvenance = { origin };
  if (!value || typeof value !== "object" || Array.isArray(value) || !Object.hasOwn(value, "result")) return result;
  const stamp = (value as Record<string, unknown>).time;
  if (typeof stamp !== "string" || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/.test(stamp)) return result;
  const parsed = Date.parse(stamp);
  if (Number.isFinite(parsed) && new Date(parsed).toISOString().replace(".000Z", "Z") === stamp) result.generatedAt = stamp;
  return result;
}
export function moduleReportProvenanceNotice(value?: ReportProvenance): string {
  if (!value || value.origin === "request") return "";
  const time = value.generatedAt ? `生成于 ${value.generatedAt}（UTC）` : "生成时间未记录或无法核对";
  if (value.origin === "retained") return `重新打开的保留读数 · ${time}。这不是本次新读取；请刷新报告核对当前情况。`;
  return `保存的历史报告 · ${time}。状态、告警和可用性仅反映报告当时；请刷新报告核对当前情况。`;
}
