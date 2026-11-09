export interface MemcachedUpdateInput {
  expected_version: string; expected_sha256: string;
  expected_project_sha256: string; acknowledge_cache_loss: true;
}
export interface MemcachedUpdateTicket { key: string; input: MemcachedUpdateInput }
const id = /^[a-f0-9]{32}$/, sha = /^[a-f0-9]{64}$/;
type Store = Pick<Storage, "getItem" | "setItem" | "removeItem">;
function validInput(v: MemcachedUpdateInput): boolean {
  return !!v && Object.keys(v).sort().join() === "acknowledge_cache_loss,expected_project_sha256,expected_sha256,expected_version" &&
    v.expected_version === "1.6.45-compat2" && sha.test(v.expected_sha256) && sha.test(v.expected_project_sha256) && v.acknowledge_cache_loss === true;
}
// A local write-ahead identity, never authority. A restored ticket is ONLY for
// GET status; this helper never offers a resend/rotate key for an unknown job.
export class MemcachedUpdateIdentity {
  private store: Store;
  private actor: string;
  private random: () => string;
  constructor(store: Store, actor: string, random: () => string) {
    if (!id.test(actor)) throw new Error("账户身份未加载，不能开始更新");
    this.store = store; this.actor = actor; this.random = random;
  }
  private name(project: string): string {
    if (!id.test(project)) throw new Error("原项目标识无效");
    return `panel-memcached-update-v1-${this.actor}-${project}`;
  }
  read(project: string): MemcachedUpdateTicket | undefined {
    const raw = this.store.getItem(this.name(project)); if (raw === null) return;
    if (raw.length > 4096) throw new Error("原更新本地记录超限，未覆盖或重发");
    const v = JSON.parse(raw);
    if (!v || Object.keys(v).sort().join() !== "input,key" || !id.test(v.key) || !validInput(v.input)) throw new Error("原更新本地记录不能核对，未覆盖或重发");
    return v;
  }
  begin(project: string, input: MemcachedUpdateInput): MemcachedUpdateTicket {
    if (this.read(project)) throw new Error("已保留原更新请求，只能核对其状态");
    if (!validInput(input)) throw new Error("必须完整核对版本、摘要、原项目，并确认缓存可能清空");
    const random = this.random();
    // The shared cryptographic browser generator emits canonical UUIDv4,
    // while this native/Core protocol uses the SAME 128-bit value as 32 hex.
    // Never truncate, accept arbitrary punctuation or weaken the server ID.
    const key = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(random) ? random.replaceAll("-", "") : random;
    if (!id.test(key)) throw new Error("无法创建原更新标识");
    const ticket = { key, input: { ...input } }, raw = JSON.stringify(ticket);
    this.store.setItem(this.name(project), raw);
    if (this.store.getItem(this.name(project)) !== raw) throw new Error("原更新标识未能持久化，未提交");
    return ticket;
  }
  finish(project: string, key: string, known: boolean, state: string): void {
    const ticket = this.read(project);
    if (!ticket || ticket.key !== key || !known || !["committed", "rolled_back", "failed_safe", "closed_without_submission"].includes(state)) throw new Error("原事务未可靠结束，不能更换请求标识");
    this.store.removeItem(this.name(project));
    if (this.read(project)) throw new Error("原事务本地记录未能清理，请重新核对");
  }
}
