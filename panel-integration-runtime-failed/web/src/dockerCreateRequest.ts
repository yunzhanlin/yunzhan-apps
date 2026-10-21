import { browserSHA256 } from "./browserSHA256.ts";

export interface RetainedDockerCreate {
  format: 1;
  actor: string;
  key: string;
  fingerprint: string;
}
const id = (v: unknown): v is string => typeof v === "string" && /^[a-f0-9]{32}$/.test(v);
const requestKey=(v:unknown):v is string=>typeof v==="string"&&(/^[a-f0-9]{32}$/.test(v)||/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(v));
export function dockerCreateStorageKey(actor: unknown): string {
  return id(actor) ? "panel-docker-create-v1:" + actor : "";
}
// No Compose YAML, password, CSRF token or private request body is persisted.
// Actor identity is re-established by the authenticated parent, not storage.
export function readDockerCreateRequest(raw: string | null, actor: string): RetainedDockerCreate | null {
  if (!raw || !id(actor) || raw.length > 512) return null;
  try {
    const v = JSON.parse(raw);
    return v && typeof v === "object" && !Array.isArray(v) &&
      Object.keys(v).sort().join(",") === "actor,fingerprint,format,key" &&
      v.format === 1 && v.actor === actor && requestKey(v.key) &&
      typeof v.fingerprint === "string" && /^[a-f0-9]{64}$/.test(v.fingerprint) ? v : null;
  } catch { return null; }
}
export async function dockerCreateFingerprint(body: unknown): Promise<string> {
  const serialized = JSON.stringify(body);
  if (typeof serialized !== "string") throw new Error("无法核对创建请求内容，未提交");
  return browserSHA256(serialized);
}
