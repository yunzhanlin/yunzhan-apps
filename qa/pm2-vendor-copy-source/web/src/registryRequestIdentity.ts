// This hash is a local equality fingerprint, not an authorization or signature.
// A portable implementation keeps plain-HTTP panels independent of WebCrypto's
// secure-context-only digest API. The server still validates every binding.
export function registryFingerprint(text: string): string {
  const input = new TextEncoder().encode(text);
  if (input.length > 24 * 1024) throw new Error("应用请求过大，未提交");
  const data = new Uint8Array(Math.ceil((input.length + 9) / 64) * 64);
  data.set(input); data[input.length] = 0x80;
  const view = new DataView(data.buffer);
  view.setUint32(data.length - 4, input.length * 8);
  const k = [0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
  const h = [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
  const w = new Uint32Array(64);
  const rotr = (x: number, n: number) => (x >>> n) | (x << (32 - n));
  for (let offset = 0; offset < data.length; offset += 64) {
    for (let i = 0; i < 16; i++) w[i] = view.getUint32(offset + i * 4);
    for (let i = 16; i < 64; i++) {
      const x = w[i - 15], y = w[i - 2];
      w[i] = (w[i - 16] + (rotr(x,7)^rotr(x,18)^(x>>>3)) + w[i - 7] + (rotr(y,17)^rotr(y,19)^(y>>>10))) >>> 0;
    }
    let [a,b,c,d,e,f,g,z] = h;
    for (let i = 0; i < 64; i++) {
      const t1 = (z + (rotr(e,6)^rotr(e,11)^rotr(e,25)) + ((e&f)^(~e&g)) + k[i] + w[i]) >>> 0;
      const t2 = ((rotr(a,2)^rotr(a,13)^rotr(a,22)) + ((a&b)^(a&c)^(b&c))) >>> 0;
      z=g; g=f; f=e; e=(d+t1)>>>0; d=c; c=b; b=a; a=(t1+t2)>>>0;
    }
    for (const [i, value] of [a,b,c,d,e,f,g,z].entries()) h[i] = (h[i] + value) >>> 0;
  }
  return h.map(value => value.toString(16).padStart(8, "0")).join("");
}

const storageKey = "panel-registry-pending-v1";
const idPattern = /^[a-f0-9]{32}$/;
const hashPattern = /^[a-f0-9]{64}$/;
const pathPattern = /^\/app-registry\/([a-z0-9-]{2,64})\/(install|update)$/;
const keyPattern = /^[a-f0-9-]{32,64}$/;
const terminal = (state: string) => state === "succeeded" || state === "failed";
export interface RegistryPendingRequest {
  app: string; action: "install" | "update"; key: string; fingerprint: string;
  version: string; sha256: string; job?: string; provider?: string;
}
export interface RegistryRequestTicket extends RegistryPendingRequest { actor: string }
export interface RegistryRequestOutcome {
  app_id: string; action: string; job_id: string; provider: string;
  state: string; state_known: boolean; version: string; sha256: string;
}
type Store = Pick<Storage, "getItem" | "setItem" | "removeItem">;

function canonicalWire(wire: string): { canonical: string; version: string; sha256: string } {
  if (new TextEncoder().encode(wire).length > 20 * 1024) throw new Error("应用请求过大，未提交");
  const body = JSON.parse(wire);
  if (!body || Array.isArray(body) || typeof body !== "object" ||
      typeof body.expected_version !== "string" || !/^[A-Za-z0-9.+_-]{1,64}$/.test(body.expected_version) ||
      typeof body.expected_sha256 !== "string" || !hashPattern.test(body.expected_sha256)) throw new Error("应用请求版本或摘要无效，未提交");
  let nodes = 0;
  function encode(value: unknown, depth: number): string {
    if (++nodes > 2048 || depth > 32) throw new Error("应用请求结构过大，未提交");
    if (value === null || typeof value !== "object") return JSON.stringify(value);
    if (Array.isArray(value)) return `[${value.map(item => encode(item, depth + 1)).join(",")}]`;
    return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${encode((value as Record<string, unknown>)[key], depth + 1)}`).join(",")}}`;
  }
  return { canonical: encode(body, 0), version: body.expected_version, sha256: body.expected_sha256 };
}

function validPending(value: unknown): value is RegistryPendingRequest {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const v = value as RegistryPendingRequest;
  return Object.keys(v).every(k => ["app","action","key","fingerprint","version","sha256","job","provider"].includes(k)) &&
    typeof v.app === "string" && pathPattern.test(`/app-registry/${v.app}/${v.action}`) &&
    typeof v.key === "string" && keyPattern.test(v.key) && typeof v.fingerprint === "string" && hashPattern.test(v.fingerprint) &&
    typeof v.version === "string" && /^[A-Za-z0-9.+_-]{1,64}$/.test(v.version) && typeof v.sha256 === "string" && hashPattern.test(v.sha256) &&
    (v.job === undefined || (typeof v.job === "string" && idPattern.test(v.job))) &&
    (v.provider === undefined || ["runtime","panel-module","compose"].includes(v.provider));
}

export class RegistryRequestIdentity {
  private actor = "";
  private pending = new Map<string, RegistryPendingRequest>();
  private storageError = "";
  constructor(private storage: Store, private newKey: () => string, private changed: () => void = () => {}) {}
  clear(): void {
    this.actor = ""; this.pending.clear(); this.storageError = "";
    try { this.storage.removeItem(storageKey); } catch { /* begin fails closed if storage cannot be written. */ }
    this.changed();
  }
  bind(actor: string, restore = false): void {
    this.actor = actor; this.pending.clear(); this.storageError = "";
    if (!idPattern.test(actor)) { this.storageError = "面板尚未提供账户请求标识，请升级面板"; this.changed(); return; }
    try {
      const raw = this.storage.getItem(storageKey);
      if (restore && raw) {
        if (raw.length > 48 * 1024) throw new Error("record too large");
        const saved = JSON.parse(raw);
        if (!saved || saved.format !== 1 || Object.keys(saved).some(k => !["format","actor","pending"].includes(k)) ||
            !idPattern.test(saved.actor) || !Array.isArray(saved.pending) || saved.pending.length > 64 || !saved.pending.every(validPending) ||
            new Set(saved.pending.map((v: RegistryPendingRequest) => v.app)).size !== saved.pending.length ||
            new Set(saved.pending.map((v: RegistryPendingRequest) => v.key)).size !== saved.pending.length) throw new Error("invalid record");
        if (saved.actor === actor) for (const value of saved.pending) this.pending.set(value.app, { ...value });
        else this.storage.removeItem(storageKey);
      } else this.storage.removeItem(storageKey);
    } catch { this.storageError = "浏览器待确认记录不可读取，请先核对后台安装任务；未提交新任务"; }
    this.changed();
  }
  list(): RegistryPendingRequest[] { return Array.from(this.pending.values(), value => ({ ...value })); }
  private save(next: Map<string, RegistryPendingRequest>): void {
    try { this.storage.setItem(storageKey, JSON.stringify({ format: 1, actor: this.actor, pending: Array.from(next.values()) })); }
    catch { throw new Error("浏览器不能保存待确认请求，未提交新任务；请允许本站会话存储"); }
    this.pending = next; this.changed();
  }
  begin(path: string, wire: string): RegistryRequestTicket {
    if (this.storageError) throw new Error(this.storageError);
    const match = pathPattern.exec(path);
    if (!match || !idPattern.test(this.actor)) throw new Error("应用请求或账户标识无效，未提交");
    const body = canonicalWire(wire);
    const old = this.pending.get(match[1]);
    const fingerprint = registryFingerprint(`${path}\n${body.canonical}`);
    if (old) {
      if (old.action !== match[2] || old.fingerprint !== fingerprint) throw new Error("该应用有待确认的原请求，请先点击“核对原任务”；未提交不同配置的新任务");
      return { ...old, actor: this.actor };
    }
    if (this.pending.size >= 64) throw new Error("待确认应用请求已达上限，请先核对原任务");
    const key = this.newKey();
    if (!keyPattern.test(key) || this.list().some(v => v.key === key)) throw new Error("无法生成独立的应用请求标识，未提交");
    const value: RegistryPendingRequest = { app: match[1], action: match[2] as "install" | "update", key, fingerprint, version: body.version, sha256: body.sha256 };
    this.save(new Map(this.pending).set(value.app, value)); // Persist BEFORE fetch.
    return { ...value, actor: this.actor };
  }
  accepted(ticket: RegistryRequestTicket, data: unknown): void {
    const old = this.pending.get(ticket.app);
    if (ticket.actor !== this.actor || !old || old.key !== ticket.key || !data || typeof data !== "object") return;
    const result = data as { job_id?: unknown; provider?: unknown; project_id?: unknown };
    if (typeof result.job_id !== "string" || !idPattern.test(result.job_id) || (old.job && old.job !== result.job_id)) throw new Error("原应用任务标识不一致，已保留请求，未重新提交");
    const provider = typeof result.provider === "string" ? result.provider : typeof result.project_id === "string" ? "compose" : "";
    if (!["runtime","panel-module","compose"].includes(provider) || (old.provider && old.provider !== provider)) throw new Error("原应用任务类型不一致，已保留请求，未重新提交");
    this.save(new Map(this.pending).set(old.app, { ...old, job: result.job_id, provider }));
  }
  observe(ticket: RegistryPendingRequest, result: RegistryRequestOutcome): boolean {
    const old = this.pending.get(ticket.app);
    if (!old || old.key !== ticket.key || !result || result.app_id !== old.app || result.action !== old.action ||
        result.version !== old.version || result.sha256 !== old.sha256) throw new Error("原应用请求状态不可核对，已保留请求");
    if (result.state === "closed_without_submission" && result.state_known === true && result.job_id === "" && result.provider === "" && !old.job) {
      const next = new Map(this.pending); next.delete(old.app); this.save(next); return true;
    }
    if (!idPattern.test(result.job_id) ||
        (old.job && old.job !== result.job_id) || !["runtime","panel-module","compose"].includes(result.provider) ||
        (old.provider && old.provider !== result.provider) || typeof result.state_known !== "boolean" ||
        !(result.state_known ? ["queued","running","succeeded","failed","needs_attention"].includes(result.state) : result.state === "unknown")) throw new Error("原应用请求状态不可核对，已保留请求");
    const next = new Map(this.pending);
    if (result.state_known && terminal(result.state)) next.delete(old.app);
    else next.set(old.app, { ...old, job: result.job_id, provider: result.provider });
    this.save(next);
    return result.state_known && terminal(result.state);
  }
  terminalJobs(jobs: { id: string; state: string }[]): void {
    const next = new Map(this.pending);
    for (const old of next.values()) if (old.provider !== "compose" && old.job && jobs.some(job => job.id === old.job && terminal(job.state))) next.delete(old.app);
    if (next.size !== this.pending.size) this.save(next);
  }
}
