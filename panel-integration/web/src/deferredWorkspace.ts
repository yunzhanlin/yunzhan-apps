/** Load executable UI code only; never retain accounts, API results or drafts. */
export class WorkspaceCodeLoadError extends Error {
  constructor(cause: unknown) {
    super(cause instanceof Error ? cause.message.slice(0, 512) : "应用界面资源读取失败");
    this.name = "WorkspaceCodeLoadError";
  }
}
export class DeferredWorkspace<T> {
  private generation = 0;
  private disposed = false;
  private loaded: T | undefined;
  private pending: Promise<T> | undefined;
  private codeFailure: WorkspaceCodeLoadError | undefined;
  constructor(private readonly loader: () => Promise<T>) {}
  begin(): number {
    if (this.disposed) throw new Error("应用界面已关闭");
    return ++this.generation;
  }
  current(ticket: number): boolean { return !this.disposed && ticket === this.generation; }
  reset(): void { this.generation++; }
  dispose(): void { this.reset(); this.disposed = true; }
  async load(ticket: number): Promise<T | undefined> {
    if (!this.current(ticket)) return undefined;
    if (this.loaded !== undefined) return this.loaded;
    // A browser can retain a failed module-map record even after the network
    // recovers. Another import of the identical URL is not a reliable retry.
    // Keep this a document-level resource failure, not an account result.
    if (this.codeFailure) throw this.codeFailure;
    if (!this.pending) {
      const request = Promise.resolve().then(this.loader).catch(cause => {
        const failure = new WorkspaceCodeLoadError(cause);
        if (!this.disposed) this.codeFailure = failure;
        throw failure;
      });
      this.pending = request;
      void request.then(value => {
        if (!this.disposed) this.loaded = value;
        if (this.pending === request) this.pending = undefined;
      }, () => { if (this.pending === request) this.pending = undefined; });
    }
    const value = await this.pending;
    return this.current(ticket) ? value : undefined;
  }
}

export type WorkspaceAPI = <T>(path: string, method?: string, body?: unknown, key?: string) => Promise<T>;
const expiredWorkspace = () => new Error("账户或应用上下文已改变，未复用旧结果或继续发送请求；此前已提交的操作须核对原任务，不视为取消或成功");
export function scopeWorkspaceAPI(api: WorkspaceAPI, current: () => boolean): WorkspaceAPI {
  return async <T>(path: string, method?: string, body?: unknown, key?: string): Promise<T> => {
    if (!current()) throw expiredWorkspace();
    const value = await api<T>(path, method, body, key);
    if (!current()) throw expiredWorkspace();
    return value;
  };
}
export function scopeWorkspaceOperation<Args extends unknown[], Result>(operation: (...args: Args) => Promise<Result>, current: () => boolean): (...args: Args) => Promise<Result> {
  return async (...args) => {
    if (!current()) throw expiredWorkspace();
    const result = await operation(...args);
    if (!current()) throw expiredWorkspace();
    return result;
  };
}
