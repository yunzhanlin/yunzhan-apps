import { registryFingerprint } from "./registryRequestIdentity";
import { menuPermissionIDs, validAccessPlan } from "./menuPermissions";

export const streamVersion = "1.9.0";
export const streamBasePath = "/app-registry/load-balance/stream";
export type StreamNode = { address: string; weight: number; backup: boolean };
export type StreamPolicy = {
  protocol: "tcp" | "udp"; port: number; nodes: StreamNode[];
  method: "round-robin" | "least-connections" | "source-ip";
  connect_milliseconds: number; session_seconds: number; max_sessions: number;
  udp_requests: number; udp_responses: number;
};
export type StreamEntry = StreamPolicy & { format: number; revision: number; name: string; probe_port: number; removed: boolean };
export type StreamMutation = { format: number; action: "create" | "replace" | "remove"; name: string; expected_revision: number; expected_fingerprint: string; policy: StreamPolicy | null };
export type StreamOperation = { format: number; kind: string; request_id: string; actor_id: string; mutation: StreamMutation };
export type StreamResult = { format: number; request_id: string; operation_sha256: string; state: "committed" | "refused-before-issue" | "refused-before-effects"; seed_sha256?: string; final_event_sha256?: string; configuration_sha256?: string; service_observation_sha256?: string; preflight_refusal?: string };
export type StreamRow = { created_at: string; operation: StreamOperation; access_revision: number; manifest_sha256: string; state: "reserved" | "issued" | "unknown" | "completed"; result?: StreamResult };
export type StreamHistory = { format: number; actor_id: string; offset: number; total: number; next_offset: number | null; rows: StreamRow[] };
export type StreamWorkspace = {
  format: number; version: string; available: boolean;
  state: "unavailable" | "empty" | "busy-or-unknown" | "unknown" | "degraded" | "cold-boot-ready" | "running" | "stopped";
  detail: string; bind_address: string; configuration_verified: boolean; generation: number;
  request_id: string; configuration_sha256: string; entries: StreamEntry[];
  available_memory_bytes: number; memory_high_bytes: number; memory_max_bytes: number; retiring_workers: number;
};
export type StreamTicket = { format: number; actor_id: string; request_id: string; mutation_sha256: string };
type RecordValue = Record<string, unknown>;
const bad = () => new Error("TCP/UDP 数据或原请求身份无法核对；没有重新提交操作");
function object(value: unknown): RecordValue {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) throw bad();
  return value as RecordValue;
}
function keys(value: unknown, required: readonly string[], optional: readonly string[] = []): RecordValue {
  const v = object(value);
  if (required.some(k => !Object.hasOwn(v, k)) || Object.keys(v).some(k => !required.includes(k) && !optional.includes(k))) throw bad();
  return v;
}
function integer(value: unknown, min: number, max: number): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < min || value > max) throw bad();
  return value;
}
function text(value: unknown, max = 2048): string {
  if (typeof value !== "string" || value.length === 0 || new TextEncoder().encode(value).length > max || /[\x00-\x08\x0b\x0c\x0e-\x1f]/.test(value)) throw bad();
  return value;
}
export function streamID(value: unknown): value is string { return typeof value === "string" && /^[a-f0-9]{32}$/.test(value); }
function digest(value: unknown): value is string { return typeof value === "string" && /^[a-f0-9]{64}$/.test(value) && value !== "0".repeat(64); }
export function streamFullAdmin(access: unknown, actor: string): boolean {
  const v = access as RecordValue | null;
  return streamID(actor) && validAccessPlan(access) && access.role === "admin" && access.menu_ids.length === menuPermissionIDs.length
    && v?.user_id === actor && Number.isSafeInteger(v?.permission_revision) && Number(v?.permission_revision) > 0;
}
export function streamName(value: unknown): string {
  const name = text(value, 253), labels = name.split(".");
  if (labels.length < 2 || name.length < 3 || /^(?:\d{1,3}\.){3}\d{1,3}$/.test(name) || labels.some(s => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(s))) throw new Error("入口名称须为小写域名式标识，不含协议、路径或 IP 地址");
  return name;
}
function nodeAddress(raw: unknown, listener: number, probe = 0): string {
  const address = text(raw, 80), match = /^(?:\[([a-f0-9:]+)\]|((?:\d{1,3}\.){3}\d{1,3})):([1-9]\d{0,4})$/.exec(address);
  if (!match) throw new Error("后端须为规范的 IPv4:端口 或 [IPv6]:端口，不接受 DNS 名称");
  const port = Number(match[3]);
  if (port > 65535 || [19100, 19102, 19080].includes(port)) throw bad();
  let loopback = false;
  if (match[2]) {
    const parts = match[2].split(".").map(Number);
    if (parts.some(n => n > 255) || parts.join(".") !== match[2] || parts[0] === 0 && parts.every(n => n === 0) || parts[0]! >= 224 && parts[0]! <= 239 || parts[0] === 169 && parts[1] === 254 || match[2] === "255.255.255.255" || match[2] === "100.100.100.200") throw bad();
    loopback = parts[0] === 127;
  } else {
    const ip = match[1]!;
    let canonical: string;
    try { canonical = new URL(`http://[${ip}]/`).hostname.slice(1, -1); } catch { throw bad(); }
    if (canonical !== ip || ip === "::" || ip.startsWith("ff") || /^fe[89ab]/.test(ip) || ip.startsWith("::ffff:") || ip === "fd00:ec2::254") throw bad();
    loopback = ip === "::1";
  }
  if (loopback && (port === listener || port === probe)) throw bad();
  return address;
}
const policyKeys = ["protocol", "port", "nodes", "method", "connect_milliseconds", "session_seconds", "max_sessions", "udp_requests", "udp_responses"] as const;
function policyFields(v: RecordValue, probe = 0): StreamPolicy {
  if (v.protocol !== "tcp" && v.protocol !== "udp" || !["round-robin", "least-connections", "source-ip"].includes(String(v.method)) || !Array.isArray(v.nodes) || v.nodes.length < 2 || v.nodes.length > 16) throw bad();
  const port = integer(v.port, 20000, 60000);
  const nodes = v.nodes.map(value => {
    const n = keys(value, ["address", "weight", "backup"]);
    if (typeof n.backup !== "boolean" || n.backup && v.method === "source-ip") throw bad();
    return { address: nodeAddress(n.address, port, probe), weight: integer(n.weight, 1, 100), backup: n.backup };
  });
  if (new Set(nodes.map(n => n.address)).size !== nodes.length || nodes.every(n => n.backup)) throw bad();
  return {
    protocol: v.protocol, port, nodes, method: v.method as StreamPolicy["method"],
    connect_milliseconds: integer(v.connect_milliseconds, 500, 5000), session_seconds: integer(v.session_seconds, 2, 600), max_sessions: integer(v.max_sessions, 16, 512),
    udp_requests: integer(v.udp_requests, v.protocol === "tcp" ? 0 : 1, v.protocol === "tcp" ? 0 : 64), udp_responses: integer(v.udp_responses, 0, v.protocol === "tcp" ? 0 : 64),
  };
}
export function streamPolicy(value: unknown): StreamPolicy { return policyFields(keys(value, policyKeys)); }
export function streamEntry(value: unknown): StreamEntry {
  const v = keys(value, ["format", "revision", "name", "probe_port", "removed", ...policyKeys]);
  if (v.format !== 1 || typeof v.removed !== "boolean") throw bad();
  const probe = integer(v.probe_port, 20000, 60000), p = policyFields(v, probe);
  if (probe === p.port) throw bad();
  // Property order is part of Go's canonical wire and optimistic concurrency.
  return { format: 1, revision: integer(v.revision, 1, Number.MAX_SAFE_INTEGER), name: streamName(v.name), protocol: p.protocol, port: p.port, probe_port: probe, nodes: p.nodes, method: p.method, connect_milliseconds: p.connect_milliseconds, session_seconds: p.session_seconds, max_sessions: p.max_sessions, udp_requests: p.udp_requests, udp_responses: p.udp_responses, removed: v.removed };
}
export function streamEntryFingerprint(value: unknown): string {
  const e = streamEntry(value);
  return `${registryFingerprint(e.name).slice(0, 20)}:${e.revision}:${registryFingerprint(JSON.stringify(e)).slice(0, 24)}`;
}
export function streamMutation(value: unknown): StreamMutation {
  const v = keys(value, ["format", "action", "name", "expected_revision", "expected_fingerprint", "policy"]);
  if (v.format !== 1 || !["create", "replace", "remove"].includes(String(v.action))) throw bad();
  const revision = integer(v.expected_revision, 0, Number.MAX_SAFE_INTEGER), fingerprint = v.expected_fingerprint;
  if (typeof fingerprint !== "string" || (v.action === "create" ? revision !== 0 || fingerprint !== "" : revision === 0 || !/^[a-f0-9]{20}:[1-9]\d*:[a-f0-9]{24}$/.test(fingerprint) || fingerprint.split(":")[1] !== String(revision))) throw bad();
  const name = streamName(v.name);
  if (v.action !== "create" && !fingerprint.startsWith(registryFingerprint(name).slice(0, 20) + ":")) throw bad();
  if (v.action === "remove" ? v.policy !== null : v.policy === null) throw bad();
  return { format: 1, action: v.action as StreamMutation["action"], name, expected_revision: revision, expected_fingerprint: fingerprint, policy: v.action === "remove" ? null : streamPolicy(v.policy) };
}
export function streamMutationHash(value: unknown): string { return registryFingerprint(JSON.stringify(streamMutation(value))); }
export function streamTicket(actor: string, id: string, mutation: unknown): StreamTicket {
  if (!streamID(actor) || !streamID(id)) throw bad();
  return { format: 1, actor_id: actor, request_id: id, mutation_sha256: streamMutationHash(mutation) };
}
export function parseStreamTicket(value: unknown, actor: string): StreamTicket {
  const v = keys(value, ["format", "actor_id", "request_id", "mutation_sha256"]);
  if (v.format !== 1 || v.actor_id !== actor || !streamID(actor) || !streamID(v.request_id) || !digest(v.mutation_sha256)) throw bad();
  return v as StreamTicket;
}
export function streamTicketKey(actor: string): string {
  if (!streamID(actor)) throw bad();
  return `yunzhan.load-balance.stream.original.v1.${actor}`;
}
export function streamRow(value: unknown, actor: string, ticket?: StreamTicket): StreamRow {
  const v = keys(value, ["created_at", "operation", "access_revision", "manifest_sha256", "state"], ["result"]);
  const o = keys(v.operation, ["format", "kind", "request_id", "actor_id", "mutation"]);
  if (o.format !== 1 || o.kind !== "load-balance-stream-control-v1" || o.actor_id !== actor || !streamID(actor) || !streamID(o.request_id) || !digest(v.manifest_sha256) || !["reserved", "issued", "unknown", "completed"].includes(String(v.state))) throw bad();
  const operation: StreamOperation = { format: 1, kind: o.kind, request_id: o.request_id, actor_id: actor, mutation: streamMutation(o.mutation) };
  if (ticket && (ticket.actor_id !== actor || ticket.request_id !== operation.request_id || ticket.mutation_sha256 !== streamMutationHash(operation.mutation))) throw bad();
  const at = text(v.created_at, 20);
  if (!/^20\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ$/.test(at) || !Number.isFinite(Date.parse(at)) || Date.parse(at) < Date.UTC(2026, 0, 1) || new Date(at).toISOString().replace(".000Z", "Z") !== at) throw bad();
  const row: StreamRow = { created_at: at, operation, access_revision: integer(v.access_revision, 1, Number.MAX_SAFE_INTEGER), manifest_sha256: v.manifest_sha256, state: v.state as StreamRow["state"] };
  if ((row.state === "completed") !== Object.hasOwn(v, "result")) throw bad();
  if (row.state === "completed") {
    const hashes = ["seed_sha256", "final_event_sha256", "configuration_sha256", "service_observation_sha256"] as const;
    const r = keys(v.result, ["format", "request_id", "operation_sha256", "state"], [...hashes, "preflight_refusal"]);
    if (r.format !== 1 || r.request_id !== operation.request_id || r.operation_sha256 !== registryFingerprint(JSON.stringify(operation)) || !["committed", "refused-before-issue", "refused-before-effects"].includes(String(r.state)) || hashes.some(k => r.state === "committed" ? !digest(r[k]) : Object.hasOwn(r, k))) throw bad();
    if (r.state === "refused-before-effects") {
      const raw = text(r.preflight_refusal, 2048);
      const p = keys(JSON.parse(raw), ["format", "request_id", "version", "operation_sha256", "manifest_sha256", "installed_sha256", "programme_inputs_sha256", "actor_observation_sha256", "original_request_sha256", "stage"]);
      const canonical = { format: p.format, request_id: p.request_id, version: p.version, operation_sha256: p.operation_sha256, manifest_sha256: p.manifest_sha256, installed_sha256: p.installed_sha256, programme_inputs_sha256: p.programme_inputs_sha256, actor_observation_sha256: p.actor_observation_sha256, original_request_sha256: p.original_request_sha256, stage: p.stage };
      if (raw !== JSON.stringify(canonical) || p.format !== 1 || p.request_id !== operation.request_id || p.version !== streamVersion || p.operation_sha256 !== r.operation_sha256 || p.manifest_sha256 !== row.manifest_sha256 || !["kernel-preflight", "control-preflight"].includes(String(p.stage)) || [p.operation_sha256, p.manifest_sha256, p.installed_sha256, p.programme_inputs_sha256, p.actor_observation_sha256, p.original_request_sha256].some(h => !digest(h))) throw bad();
    } else if (Object.hasOwn(r, "preflight_refusal")) throw bad();
    row.result = r as StreamResult;
  }
  return row;
}
export function streamHistory(value: unknown, actor: string, offset: number): StreamHistory {
  const v = keys(value, ["format", "actor_id", "offset", "total", "next_offset", "rows"]);
  if (v.format !== 1 || v.actor_id !== actor || v.offset !== offset || integer(offset, 0, 4096) % 32 !== 0 || !Array.isArray(v.rows) || v.rows.length > 32) throw bad();
  const total = integer(v.total, 0, 4096), rows = v.rows.map(r => streamRow(r, actor));
  if (rows.length !== Math.min(32, Math.max(0, total - offset)) || new Set(rows.map(r => r.operation.request_id)).size !== rows.length || (v.next_offset !== (offset + rows.length < total ? offset + 32 : null))) throw bad();
  return { format: 1, actor_id: actor, offset, total, next_offset: v.next_offset as number | null, rows };
}
export function streamWorkspace(value: unknown): StreamWorkspace {
  const v = keys(value, ["format", "version", "available", "state", "detail", "bind_address", "configuration_verified", "generation", "request_id", "configuration_sha256", "entries", "available_memory_bytes", "memory_high_bytes", "memory_max_bytes", "retiring_workers"]);
  if (v.format !== 1 || v.version !== streamVersion || typeof v.available !== "boolean" || typeof v.configuration_verified !== "boolean" || v.bind_address !== "127.0.0.1" || !["unavailable", "empty", "busy-or-unknown", "unknown", "degraded", "cold-boot-ready", "running", "stopped"].includes(String(v.state)) || !Array.isArray(v.entries) || v.entries.length > 128) throw bad();
  text(v.detail);
  const generation = integer(v.generation, 0, 128), retiring = integer(v.retiring_workers, 0, 1), entries = v.entries.map(streamEntry);
  integer(v.available_memory_bytes, 0, Number.MAX_SAFE_INTEGER);
  integer(v.memory_high_bytes, 0, Number.MAX_SAFE_INTEGER);
  integer(v.memory_max_bytes, 0, 1476395008);
  if (!v.available && v.state !== "unavailable" || v.state !== "unavailable" && !v.available || v.configuration_verified !== ["running", "stopped"].includes(String(v.state)) || ["unavailable", "empty", "busy-or-unknown"].includes(String(v.state)) && generation !== 0 || ["degraded", "cold-boot-ready", "running", "stopped"].includes(String(v.state)) && generation === 0 || v.state !== "running" && retiring !== 0) throw bad();
  if (generation === 0) {
    if (entries.length || v.request_id !== "" || v.configuration_sha256 !== "" || v.memory_high_bytes !== 0 || v.memory_max_bytes !== 0 || retiring !== 0) throw bad();
  } else if (!streamID(v.request_id) || !digest(v.configuration_sha256) || Number(v.memory_high_bytes) < 128 * 1024 * 1024 || Number(v.memory_max_bytes) < Number(v.memory_high_bytes) || new Set(entries.map(e => e.name)).size !== entries.length || v.state === "running" && !entries.some(e => !e.removed) || v.state === "stopped" && entries.some(e => !e.removed)) throw bad();
  return { ...v, entries } as StreamWorkspace;
}
