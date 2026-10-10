export interface RegistrySource {
  source: string;
  stale: boolean;
  fetched_at?: string;
  checked_at?: string;
  resolved_commit?: string;
  error?: string;
}
interface RegistrySnapshot { catalog: unknown; source: RegistrySource }
export interface RegistryReadTicket {
  generation: number;
  sequence: number;
  checkBarrier: number;
  checkPending: boolean;
  kind: "poll" | "check";
}
export interface RegistryCheckReceipt { checked_at: string; resolved_commit?: string }

// Session-local display evidence, not a trust decision or persistent credential.
// A cached read updates status rows but does not turn a failed check into success.
export class RegistryFreshness<T extends RegistrySnapshot> {
  private generation = 1;
  private sequence = 0;
  private checkBarrier = 0;
  private pendingCheck = 0;
  private lastApplied = 0;
  private failedSource: RegistrySource | undefined;
  private receipt: RegistryCheckReceipt | undefined;
  private receiptCatalog = "";

  reset(): void {
    this.generation++;
    this.sequence = this.checkBarrier = this.pendingCheck = this.lastApplied = 0;
    this.failedSource = this.receipt = undefined;
    this.receiptCatalog = "";
  }

  begin(kind: "poll" | "check"): RegistryReadTicket {
    const sequence = ++this.sequence;
    if (kind === "check") this.checkBarrier = this.pendingCheck = sequence;
    return { generation: this.generation, sequence, checkBarrier: this.checkBarrier, checkPending: this.pendingCheck !== 0, kind };
  }

  isCurrentCheck(ticket: RegistryReadTicket): boolean {
    return ticket.generation === this.generation && ticket.kind === "check" && ticket.sequence === this.checkBarrier;
  }

  complete(ticket: RegistryReadTicket, next: T): T | undefined {
    if (ticket.generation !== this.generation) return;
    if (ticket.kind === "check") {
      if (!this.isCurrentCheck(ticket)) return;
      this.pendingCheck = 0;
    } else if (ticket.checkPending || this.pendingCheck || ticket.checkBarrier !== this.checkBarrier || ticket.sequence < this.lastApplied) return;
    this.lastApplied = ticket.sequence;
    const source = next.source;
    const catalog = this.catalogIdentity(next.catalog);
    if (source.stale) {
      this.failedSource = { ...source };
      this.receipt = undefined;
      this.receiptCatalog = "";
    } else if (source.source === "github" && source.checked_at) {
      // The official client verifies the immutable catalog before returning this.
      // A custom signed source may legitimately have no GitHub commit number.
      this.failedSource = undefined;
      const validTime = Number.isFinite(Date.parse(source.checked_at));
      const validCommit = source.resolved_commit === undefined || /^[0-9a-f]{40}$/.test(source.resolved_commit);
      this.receipt = catalog && validTime && validCommit ? { checked_at: source.checked_at, resolved_commit: source.resolved_commit } : undefined;
      this.receiptCatalog = this.receipt ? catalog : "";
    } else if (this.failedSource) {
      // A subsequent TTL read has not contacted the repository. Keep the failure
      // visible and updates locked while still accepting current installed rows.
      next = { ...next, source: { ...source, ...this.failedSource, stale: true } };
    } else if (!catalog || catalog !== this.receiptCatalog) {
      this.receipt = undefined;
      this.receiptCatalog = "";
    }
    return next;
  }

  failure(ticket: RegistryReadTicket, previous: T, error: string): T | undefined {
    return this.complete(ticket, { ...previous, source: { source: "unavailable", stale: true, fetched_at: previous.source.fetched_at, error } });
  }

  lastSuccessfulCheck(): RegistryCheckReceipt | undefined {
    return this.receipt ? { ...this.receipt } : undefined;
  }

  private catalogIdentity(catalog: unknown): string {
    try {
      const encoded = JSON.stringify(catalog);
      return encoded && encoded.length <= 1 << 20 ? encoded : "";
    } catch { return ""; }
  }
}
