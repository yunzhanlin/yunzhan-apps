export interface PanelHealthInput {
  permitted: boolean;
  overview: unknown;
  readError: string;
  receivedAt: number | null;
  monotonicNow: number;
  wallNow: number;
}
export interface PanelHealthState { label: string; kind: "ok" | "warning" | "error" }

// Only the independently authorized overview read establishes server health.
// Catalog, form and unrelated feature errors must not claim an offline server.
export function panelHealthState(input: PanelHealthInput): PanelHealthState {
  if (!input.permitted) return {label:"服务器状态未授权",kind:"warning"};
  if (input.readError) return {label:"服务器状态读取失败",kind:"error"};
  if (!input.overview) return {label:"正在获取服务器状态",kind:"warning"};
  const value = input.overview as Record<string, unknown>;
  if (typeof value.nginx_active !== "boolean" || typeof value.sampled_at !== "string")
    return {label:"服务器状态未能核对",kind:"warning"};
  const age = input.receivedAt === null ? NaN : input.monotonicNow - input.receivedAt;
  if (!Number.isFinite(age) || age < 0 || age > 45_000)
    return {label:"服务器状态已过期",kind:"warning"};
  const sampled = Date.parse(value.sampled_at);
  if (!Number.isFinite(sampled) || !Number.isFinite(input.wallNow) || input.wallNow - sampled > 90_000 || sampled - input.wallNow > 30_000)
    return {label:"服务器采样时间需核对",kind:"warning"};
  if (!value.nginx_active) return {label:"网站入口待检查",kind:"warning"};
  return {label:"服务器运行正常",kind:"ok"};
}

// An inactive website entrance can still have a fresh CPU/memory sample. All
// other warning/error states above mean that freshness was not established.
export function panelSampleIsCurrent(input: PanelHealthInput): boolean {
  const health = panelHealthState(input);
  return health.kind === "ok" || health.label === "网站入口待检查";
}
