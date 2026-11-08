// One in-flight read per account generation. An old account's pending read
// neither blocks the new account nor releases its independent in-flight read.
export class EpochReadGate {
  private readonly active = new Set<number>();
  acquire(epoch: number): (() => void) | undefined {
    if (this.active.has(epoch)) return undefined;
    this.active.add(epoch);
    let released = false;
    return () => {
      if (released) return;
      released = true;
      this.active.delete(epoch);
    };
  }
}
