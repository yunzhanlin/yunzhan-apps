export interface PHPSwitchContext {
  site_id: string;
  release_id: string;
  current_release_id: string;
  revision: number;
  access: string;
}
export interface PHPSwitchPreview {
  protocol: "php-vhost-switch-v1";
  site_id: string;
  release_id: string;
  revision: number;
  current: string;
  candidate: string;
  config_sha: string;
  preserves_custom_config: boolean;
}
export function samePHPSwitchContext(a: PHPSwitchContext | null, b: PHPSwitchContext | null): boolean {
  return !!a && !!b && a.site_id === b.site_id && a.release_id === b.release_id
    && a.current_release_id === b.current_release_id && a.revision === b.revision && a.access === b.access;
}
export function parsePHPSwitchPreview(value: unknown, context: PHPSwitchContext): PHPSwitchPreview {
  const v = value as PHPSwitchPreview;
  const bounded = (text: unknown): text is string => typeof text === "string" && text.length > 0
    && new TextEncoder().encode(text).byteLength <= 65536 && !text.includes("\0");
  if (!v || v.protocol !== "php-vhost-switch-v1" || !/^[a-f0-9]{32}$/.test(context.site_id)
    || v.site_id !== context.site_id || v.release_id !== context.release_id
    || !Number.isSafeInteger(v.revision) || v.revision < 0 || v.revision !== context.revision
    || !bounded(v.current) || !bounded(v.candidate) || !/^[a-f0-9]{64}$/.test(v.config_sha)
    || typeof v.preserves_custom_config !== "boolean") throw Error("PHP 切换预览与当前网站不一致，请重新预览");
  return v;
}
