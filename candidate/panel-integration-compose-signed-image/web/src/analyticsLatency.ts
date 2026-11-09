export const latencySampleLimit = 250000;
const bounds = [.05, .1, .25, .5, 1, 2, 5, 10, null];
const ranges = ["0–50 ms", ">50–100 ms", ">100–250 ms", ">250–500 ms", ">500–1000 ms", ">1–2 s", ">2–5 s", ">5–10 s", ">10 s"];
export type LatencyView = {
  requests: number;
  available: boolean;
  limited: boolean;
  partial: boolean;
  quantiles: { label: string; seconds: number | null }[];
  buckets: { range: string; requests: number; percent: number }[];
};
const record = (v: unknown): v is Record<string, unknown> => !!v && typeof v === "object" && !Array.isArray(v);
const count = (v: unknown): v is number => typeof v === "number" && Number.isSafeInteger(v) && v >= 0;
const seconds = (v: unknown): v is number => typeof v === "number" && Number.isFinite(v) && v >= 0 && v <= 86400;

// Unknown/older or internally inconsistent reports are not coerced to zeros.
// The UI only displays the closed, aggregate server contract; no raw samples.
export function analyticsLatencyView(value: unknown): LatencyView | undefined {
  if (!record(value) || value.source !== "nginx_request_time" || value.method !== "nearest_rank" || value.sample_limit !== latencySampleLimit || !count(value.requests) || !count(value.samples) || typeof value.quantiles_available !== "boolean" || typeof value.sample_limited !== "boolean" || typeof value.population_partial !== "boolean") return;
  const p = [value.p50_seconds, value.p90_seconds, value.p95_seconds, value.p99_seconds];
  if (value.quantiles_available) {
    if (value.sample_limited || value.requests === 0 || value.requests > latencySampleLimit || value.samples !== value.requests || !p.every(seconds) || p.some((v, i) => i > 0 && Number(v) < Number(p[i - 1]))) return;
  } else if (p.some(v => v !== null) || value.samples !== 0 || (value.sample_limited ? value.requests <= latencySampleLimit : value.requests !== 0)) return;
  if (!Array.isArray(value.histogram) || value.histogram.length !== 9) return;
  const buckets: LatencyView["buckets"] = [];
  for (const [i, b] of value.histogram.entries()) {
    if (!record(b) || b.range !== ranges[i] || b.upper_seconds !== bounds[i] || !count(b.requests) || b.requests > value.requests || typeof b.percent !== "number" || !Number.isFinite(b.percent) || Math.abs(b.percent - (value.requests ? 100 * b.requests / value.requests : 0)) > 1e-7) return;
    buckets.push({ range: ranges[i]!, requests: b.requests, percent: b.percent });
  }
  if (buckets.reduce((n, b) => n + b.requests, 0) !== value.requests) return;
  return {requests: value.requests, available: value.quantiles_available, limited: value.sample_limited, partial: value.population_partial, quantiles: ["P50", "P90", "P95", "P99"].map((label, i) => ({label, seconds: value.quantiles_available ? Number(p[i]) : null})), buckets};
}

export function latencySecondsLabel(value: number | null): string {
  return value === null ? "—" : `${value.toFixed(3)} s`;
}
