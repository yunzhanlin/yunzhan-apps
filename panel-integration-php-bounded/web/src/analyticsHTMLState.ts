export interface AnalyticsHTMLBuild {
  job_id: string;
  state: string;
  error?: string;
  architecture?: string;
  nginx_version?: string;
  integrity_verified: boolean;
  module_abi_validated: boolean;
  build_only: boolean;
  steps: { time: string; message: string }[];
}
export interface AnalyticsHTMLActive {
  active: boolean;
  state: string;
  job_id?: string;
  worker_acknowledged?: boolean;
  error?: string;
}
const validID = (value: unknown): value is string => typeof value === "string" && /^[a-f0-9]{32}$/.test(value);
export function analyticsHTMLBuildReady(value?: AnalyticsHTMLBuild): boolean {
  return !!value && validID(value.job_id) && value.state === "ready" && !value.error &&
    value.integrity_verified === true && value.module_abi_validated === true && value.build_only === true;
}
export function analyticsHTMLActiveReady(value?: AnalyticsHTMLActive): boolean {
  return !!value && value.active === true && value.state === "active" &&
    value.worker_acknowledged === true && validID(value.job_id) && !value.error;
}
export function analyticsHTMLActivationAcknowledged(value: unknown, id: string): boolean {
  const out = value as {job_id?: unknown; active?: unknown; worker_acknowledged?: unknown; site_auto_injection?: unknown} | null;
  return !!out && validID(id) && out.job_id === id && out.active === true &&
    out.worker_acknowledged === true && out.site_auto_injection === false;
}
export function analyticsCollectorEnabled<T extends {enabled: boolean; auto_inject_html?: boolean}>(settings: T, enabled: boolean): T {
  // Stopping the collector must explicitly remove auto-injection as well. Do
  // not submit a stale true flag, even when the optional engine is unhealthy.
  return {...settings, enabled, auto_inject_html: enabled ? settings.auto_inject_html : false};
}
