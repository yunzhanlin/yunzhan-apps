export interface AnalyticsQueryContext {
  site_id: string;
  from_time: string;
  to_time: string;
  search: string;
  status_code: number;
  min_seconds: number;
  only_bots: boolean;
}
const keys = ["from_time","to_time","search","status_code","min_seconds","only_bots"];
function time(value: unknown): string | undefined {
  if (value === "" || value === undefined || value === null) return "";
  if (value instanceof Date) return Number.isFinite(value.getTime()) ? value.toISOString() : undefined;
  if (typeof value !== "string" || value.length > 64 || !/^\d{4}-\d{2}-\d{2}T(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d(?:\.\d{1,3})?(?:Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)$/.test(value)) return undefined;
  const parsed = new Date(value);
  if (!Number.isFinite(parsed.getTime())) return undefined;
  // Date normalizes impossible calendar dates; an RFC3339 backend does not.
  const calendar = value.slice(0,10), date = new Date(calendar+"T00:00:00Z");
  if (!Number.isFinite(date.getTime()) || date.toISOString().slice(0,10) !== calendar) return undefined;
  return parsed.toISOString();
}
function fields(site: unknown, filters: Record<string, unknown>): AnalyticsQueryContext | undefined {
  if (typeof site !== "string" || !/^[a-f0-9]{32}$/.test(site)) return undefined;
  const from = time(filters.from_time), to = time(filters.to_time);
  if (from === undefined || to === undefined || from && to && to <= from) return undefined;
  const search = filters.search ?? "", status = filters.status_code, seconds = filters.min_seconds, bots = filters.only_bots;
  if (typeof search !== "string" || new TextEncoder().encode(search).length > 256 ||
    typeof status !== "number" || !Number.isInteger(status) || status !== 0 && (status < 100 || status > 599) ||
    typeof seconds !== "number" || !Number.isFinite(seconds) || seconds < 0 || seconds > 3600 || typeof bots !== "boolean") return undefined;
  return {site_id:site,from_time:from,to_time:to,search,status_code:status,min_seconds:seconds,only_bots:bots};
}
export function analyticsQueryContext(report: unknown): AnalyticsQueryContext | undefined {
  if (!report || typeof report !== "object" || Array.isArray(report)) return undefined;
  const value = report as Record<string,unknown>, filters = value.filters;
  if (!filters || typeof filters !== "object" || Array.isArray(filters) || Object.keys(filters).length !== keys.length || !keys.every(key=>Object.hasOwn(filters,key))) return undefined;
  return fields(value.site_id,filters as Record<string,unknown>);
}
export function analyticsQueryMatches(context: AnalyticsQueryContext, draft: Record<string,unknown>): boolean {
  const value = fields(draft.site_id,draft);
  return !!value && Object.keys(context).every(key=>context[key as keyof AnalyticsQueryContext]===value[key as keyof AnalyticsQueryContext]);
}
export function restoreAnalyticsQuery(context: AnalyticsQueryContext | undefined, sites: {id:string}[]): AnalyticsQueryContext | undefined {
  // No secrets, confirmations, actions, revisions or unrelated application fields
  // are restored from a retained report. A removed/inaccessible site is not guessed.
  return context && sites.some(site=>site.id===context.site_id) ? {...context} : undefined;
}
