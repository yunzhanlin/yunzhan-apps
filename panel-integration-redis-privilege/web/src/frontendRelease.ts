// Public build identity only. Never execute fetched HTML, reload automatically,
// cancel accepted server work, replay a request or touch retained request keys.
export const frontendReleaseBytes = 16 * 1024;
export const frontendReleaseTimeout = 3000;
export const frontendReleaseInterval = 60_000;
export type FrontendReleaseStatus = { kind: "idle" | "current" | "updated" | "unknown" };

function assetURL(value: string, base: string): string | undefined {
  try {
    const origin = new URL(base), url = new URL(value, origin);
    if (!/^https?:$/.test(origin.protocol) || url.origin !== origin.origin || url.username || url.password || url.search || url.hash ||
      !/^(?:\/[A-Za-z0-9._~%-]+)*\/assets\/index-[A-Za-z0-9_-]{6,64}\.js$/.test(url.pathname)) return;
    return url.href;
  } catch { return; }
}

// Recognise only the single external module emitted by the normal Vite build.
// Bounded string inspection does not create a document, load images or execute
// any returned markup. Ambiguous/inline/foreign entries remain unknown.
export function frontendEntry(html: string, base: string): string | undefined {
  if (new TextEncoder().encode(html).byteLength > frontendReleaseBytes) return;
  const modules = [...html.matchAll(/<script\b[^>]*>/gi)].map(v => v[0]).filter(tag => /\stype\s*=\s*(["'])module\1(?=\s|>)/i.test(tag));
  if (modules.length !== 1) return;
  const sources = [...modules[0].matchAll(/\ssrc\s*=\s*(["'])([^"'<>]+)\1(?=\s|>)/gi)];
  return sources.length === 1 ? assetURL(sources[0][2], base) : undefined;
}

export function assertFrontendMutationCurrent(status: FrontendReleaseStatus, method: string, path: string) {
  if (status.kind === "updated" && !["GET", "HEAD"].includes(method) && !(method === "POST" && path === "/logout"))
    throw new Error("面板界面已更新，请先刷新页面；已提交的后台任务继续执行，不会自动重发。");
}

type Options = {
  indexURL: string;
  loadedEntry: string;
  publish: (status: FrontendReleaseStatus) => void;
  fetch?: typeof fetch;
  now?: () => number;
};

export class FrontendReleaseWatch {
  private readonly loaded: string | undefined;
  private readonly index: string;
  private readonly read: typeof fetch;
  private readonly now: () => number;
  private stopped = false;
  private updated = false;
  private lastStarted = -Infinity;
  private sequence = 0;
  private inFlight?: Promise<void>;
  private controller?: AbortController;

  constructor(private readonly options: Options) {
    this.index = new URL(options.indexURL).href;
    this.loaded = assetURL(options.loadedEntry, this.index);
    this.read = options.fetch || fetch.bind(globalThis);
    this.now = options.now || (() => performance.now());
  }

  check(): Promise<void> {
    if (this.stopped || this.updated) return Promise.resolve();
    if (this.inFlight) return this.inFlight;
    if (this.now() - this.lastStarted < frontendReleaseInterval) return Promise.resolve();
    this.lastStarted = this.now();
    const sequence = ++this.sequence, controller = new AbortController();
    this.controller = controller;
    const promise = this.observe(sequence, controller);
    this.inFlight = promise;
    void promise.finally(() => { if (this.inFlight === promise) this.inFlight = undefined; });
    return promise;
  }

  private async observe(sequence: number, controller: AbortController) {
    const current = () => !this.stopped && this.sequence === sequence && !controller.signal.aborted;
    const timer = setTimeout(() => controller.abort(), frontendReleaseTimeout);
    try {
      if (!this.loaded) throw new Error("unknown entry");
      const response = await this.read(this.index, { method: "GET", credentials: "same-origin", cache: "no-store", redirect: "error", signal: controller.signal, headers: { Accept: "text/html" } });
      if (!current()) return;
      if (response.status !== 200 || response.redirected || !response.url || new URL(response.url).href !== this.index ||
        !/^text\/html(?:\s*;|$)/i.test(response.headers.get("Content-Type") || "") || !response.body) throw new Error("unknown document");
      const size = response.headers.get("Content-Length");
      if (size !== null && (!/^[0-9]+$/.test(size) || Number(size) > frontendReleaseBytes)) throw new Error("document budget");
      const reader = response.body.getReader(), decoder = new TextDecoder("utf-8", { fatal: true });
      let bytes = 0, html = "", finished = false;
      try {
        while (true) {
          const part = await reader.read();
          if (!current()) return;
          if (part.done) { html += decoder.decode(); finished = true; break; }
          bytes += part.value.byteLength;
          if (bytes > frontendReleaseBytes) throw new Error("document budget");
          html += decoder.decode(part.value, { stream: true });
        }
      } finally {
        if (!finished) void reader.cancel().catch(() => {});
        reader.releaseLock();
      }
      const entry = frontendEntry(html, this.index);
      if (!entry) throw new Error("unknown document entry");
      if (!current()) return;
      this.updated = entry !== this.loaded;
      this.options.publish({ kind: this.updated ? "updated" : "current" });
    } catch {
      if (!this.stopped && this.sequence === sequence && !this.updated) this.options.publish({ kind: "unknown" });
    } finally {
      clearTimeout(timer);
      controller.abort();
      if (this.controller === controller) this.controller = undefined;
    }
  }

  dispose() { this.stopped = true; this.sequence++; this.controller?.abort(); }
}
