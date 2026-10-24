export const memcachedUnixVersion = "1.6.45-compat4";
export const memcachedConsoleBytes = 48 * 1024;
export interface MemcachedCacheInput {
  action: "get" | "add" | "cas" | "delete" | "stats";
  key_base64?: string;
  value_base64?: string;
  cas?: string;
  ttl_seconds?: number;
  flags?: number;
  stats?: string;
}
export interface MemcachedCacheResult {
  action: string;
  found: boolean;
  changed: boolean;
  value_base64?: string;
  value_bytes?: number;
  cas?: string;
  flags: number;
  ttl_remaining: number;
  stale?: boolean;
  statistics?: Record<string, string>;
}
export interface MemcachedWorkspace {
  format: number;
  project_id: string;
  name: string;
  site_id: string;
  version: string;
  state: "running" | "stopped";
  state_known: boolean;
  healthy: boolean;
  socket_path: string;
  cache_mb: number;
  memory_limit_mb: number;
  item_limit_mb: number;
  editor_limit_bytes: number;
  network_mode: string;
  runtime_sha256: string;
  cache?: MemcachedCacheResult;
}
export interface MemcachedControlInput {
  action: "start" | "stop" | "restart";
  expected_runtime_sha256: string;
  acknowledge_cache_loss: boolean;
}
export interface MemcachedControlOperation {
  format: number;
  request_id: string;
  project_id: string;
  actor_id: string;
  input: MemcachedControlInput;
}
export interface MemcachedControlResult {
  format: number;
  request_id: string;
  project_id: string;
  operation_sha256: string;
  state: "completed" | "refused" | "unknown";
  final_state?: string;
  runtime_sha256?: string;
}
export interface MemcachedControlRow {
  operation: MemcachedControlOperation;
  state: "reserved" | "unknown" | "completed";
  result?: MemcachedControlResult;
}
const id = /^[a-f0-9]{32}$/,
  sha = /^[a-f0-9]{64}$/;
export function validMemcachedWorkspace(
  v: MemcachedWorkspace,
  project: string,
): boolean {
  const base =
    v?.site_id === ""
      ? "/var/lib/panel-executor/memcached-sockets"
      : "/srv/panel/memcached";
  return (
    !!v &&
    id.test(project) &&
    v.format === 1 &&
    v.project_id === project &&
    typeof v.name === "string" &&
    typeof v.site_id === "string" &&
    (v.site_id === "" || id.test(v.site_id)) &&
    v.version === memcachedUnixVersion &&
    ["running", "stopped"].includes(v.state) &&
    v.state_known === true &&
    v.healthy === (v.state === "running") &&
    v.socket_path === base + "/" + project + "/cache.sock" &&
    v.cache_mb === 128 &&
    v.memory_limit_mb === 192 &&
    v.item_limit_mb === 4 &&
    v.editor_limit_bytes === memcachedConsoleBytes &&
    v.network_mode === "none" &&
    sha.test(v.runtime_sha256)
  );
}
export function memcachedBase64Bytes(value: string, limit: number): Uint8Array {
  if (typeof value !== "string" || value.length > Math.ceil(limit / 3) * 4)
    throw new Error("规范 Base64 或容量不符合限制");
  let bytes: Uint8Array;
  try {
    bytes = Uint8Array.from(atob(value), (c) => c.charCodeAt(0));
  } catch {
    throw new Error("请输入规范 Base64");
  }
  if (bytes.length > limit || bytesToMemcachedBase64(bytes) !== value)
    throw new Error("Base64 不规范或数据超限");
  return bytes;
}
export function bytesToMemcachedBase64(bytes: Uint8Array): string {
  let text = "";
  for (let i = 0; i < bytes.length; i++) text += String.fromCharCode(bytes[i]);
  return btoa(text);
}
export function memcachedInputBytes(
  value: string,
  mode: string,
  limit: number,
): string {
  const bytes =
    mode === "base64"
      ? memcachedBase64Bytes(value, limit)
      : new TextEncoder().encode(value);
  if (
    mode !== "base64" &&
    new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes) !==
      value
  )
    throw new Error("文本包含不完整 Unicode；未替换字节，请使用规范 Base64");
  if (bytes.length > limit)
    throw new Error("数据超过编辑器固定容量，未截断、删除或重新写入");
  return bytesToMemcachedBase64(bytes);
}
export function memcachedValueText(value: string, mode: string): string {
  const bytes = memcachedBase64Bytes(value, memcachedConsoleBytes);
  if (mode === "base64") return value;
  try {
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(
      bytes,
    );
  } catch {
    throw new Error("该值不是完整 UTF-8，请切换 Base64 查看；未替换无效字节");
  }
}
export function memcachedKeyBase64(value: string, mode: string): string {
  const canonical = memcachedInputBytes(value, mode, 250),
    bytes = memcachedBase64Bytes(canonical, 250);
  if (!bytes.length) throw new Error("缓存键不能为空");
  if (canonical.length > 250 && bytes.some((b) => b <= 32 || b === 127))
    throw new Error(
      "固定1.6.45协议限制：含空白或控制字节的键最多186字节；未连接或发送命令",
    );
  return canonical;
}

export function validMemcachedControlRow(
  row: MemcachedControlRow,
  actor: string,
): boolean {
  const op = row?.operation,
    incoming = op?.input,
    out = row?.result;
  if (
    !row ||
    !op ||
    op.format !== 1 ||
    !id.test(op.request_id) ||
    !id.test(op.project_id) ||
    op.actor_id !== actor ||
    !incoming ||
    !["start", "stop", "restart"].includes(incoming.action) ||
    !sha.test(incoming.expected_runtime_sha256) ||
    incoming.acknowledge_cache_loss !== (incoming.action !== "start") ||
    !["reserved", "unknown", "completed"].includes(row.state) ||
    (row.state === "completed") !== !!out
  )
    return false;
  if (!out) return true;
  if (
    out.format !== 1 ||
    out.request_id !== op.request_id ||
    out.project_id !== op.project_id ||
    !sha.test(out.operation_sha256)
  )
    return false;
  return (
    (out.state === "completed" &&
      out.final_state ===
        (incoming.action === "stop" ? "stopped" : "running") &&
      sha.test(out.runtime_sha256 || "")) ||
    (out.state === "refused" && !out.final_state && !out.runtime_sha256)
  );
}
