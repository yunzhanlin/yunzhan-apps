export interface BrowserAnalyticsQuery {
  readonly site: string;
  readonly key: string;
  readonly from: string;
  readonly to: string;
  readonly problem: string;
}

function date(value: unknown): string | undefined {
  if (value === null || value === undefined || value === "") return "";
  if (!(value instanceof Date) || !Number.isFinite(value.getTime())) return undefined;
  // The collector stores received times as whole Unix seconds, and the
  // server returns RFC3339 without a fractional part. The picker shows seconds.
  return new Date(Math.floor(value.getTime() / 1000) * 1000).toISOString();
}

export function browserAnalyticsQuery(site: string, start: unknown, end: unknown): BrowserAnalyticsQuery {
  const from = date(start), to = date(end);
  const key = JSON.stringify([site, from ?? "invalid-start", to ?? "invalid-end"]);
  let problem = "";
  if (!/^[a-f0-9]{32}$/.test(site)) problem = "请选择统计网站。";
  else if (from === undefined || to === undefined) problem = "统计时间无效，请重新选择。";
  else if (!!from !== !!to) problem = "请同时选择开始和结束时间，或清空两项使用默认时间范围。";
  else if (from && to && from >= to) problem = "结束时间必须晚于开始时间。";
  return Object.freeze({site, key, from: from ?? "", to: to ?? "", problem});
}

export function browserAnalyticsQueryParams(query: BrowserAnalyticsQuery): URLSearchParams {
  if (query.problem) throw new Error(query.problem);
  const params = new URLSearchParams();
  if (query.from) { params.set("from", query.from); params.set("to", query.to); }
  return params;
}

// Reports carry the actual server range. An explicit range must describe the
// same instants, including when RFC3339 uses a different offset or precision.
export function browserAnalyticsReportMatches(query: BrowserAnalyticsQuery, report: unknown): boolean {
  if (query.problem || !report || typeof report !== "object" || Array.isArray(report)) return false;
  const {from, to} = report as Record<string, unknown>;
  const stamp = /^\d{4}-\d{2}-\d{2}T(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d(?:\.\d{1,9})?(?:Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)$/;
  if (typeof from !== "string" || typeof to !== "string" || !stamp.test(from) || !stamp.test(to)) return false;
  const a = Date.parse(from), b = Date.parse(to);
  if (!Number.isFinite(a) || !Number.isFinite(b) || a >= b) return false;
  return !query.from || a === Date.parse(query.from) && b === Date.parse(query.to);
}

export interface BrowserAnalyticsQueryTicket {
  readonly key: string;
  readonly generation: number;
}

export function browserAnalyticsQueryFence() {
  let generation = 0;
  return {
    capture(key: string): BrowserAnalyticsQueryTicket {
      return Object.freeze({key, generation: ++generation});
    },
    invalidate(): void { ++generation; },
    current(ticket: BrowserAnalyticsQueryTicket, key: string): boolean {
      return ticket.generation === generation && ticket.key === key;
    },
  };
}
