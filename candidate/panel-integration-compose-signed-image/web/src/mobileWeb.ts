// Web install state is local browser capability, never server health or authority.
export interface InstallPrompt extends Event {
  prompt(): Promise<unknown>;
  userChoice: Promise<{ outcome: "accepted" | "dismissed" }>;
}
const change = "yunzhan-web-install-state";
let pending: InstallPrompt | undefined;
let installing = false;
let owner: Window | undefined;
export function mobileWebURL(href: string): string | undefined {
  try {
    const url = new URL(href);
    if (!["http:", "https:"].includes(url.protocol) || url.username || url.password) return;
    const entry = /^\/([A-Za-z0-9]{8,10}|[a-f0-9]{32,64})\//.exec(url.pathname);
    return url.origin + (entry ? `/${entry[1]}/` : "/");
  } catch { return; }
}
export function mobileWebIsLoopback(href: string): boolean {
  try { const h=new URL(href).hostname;return h === "localhost" || h.endsWith(".localhost") || h === "[::1]" || /^127\./.test(h); } catch { return false; }
}
export function trackMobileWebInstall(target: Window): void {
  if (owner) return;
  owner = target;
  target.addEventListener("beforeinstallprompt", event => {
    const next=event as InstallPrompt;
    if (typeof next.prompt !== "function" || !next.userChoice || typeof next.userChoice.then !== "function") return;
    event.preventDefault();pending=next;target.dispatchEvent(new Event(change));
  });
  target.addEventListener("appinstalled",()=>{pending=undefined;target.dispatchEvent(new Event(change));});
}
export function mobileWebInstallAvailable(): boolean { return !!pending && !installing; }
export function watchMobileWebInstall(callback: () => void): () => void {
  owner?.addEventListener(change,callback);return ()=>owner?.removeEventListener(change,callback);
}
export async function requestMobileWebInstall(): Promise<"accepted" | "dismissed" | "unavailable"> {
  const original=pending;
  if (!original || installing) return "unavailable";
  installing=true;owner?.dispatchEvent(new Event(change));
  try {await original.prompt();return (await original.userChoice).outcome;}
  finally {if(pending===original)pending=undefined;installing=false;owner?.dispatchEvent(new Event(change));}
}
