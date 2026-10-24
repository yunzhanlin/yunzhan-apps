export interface WafSiteChoice {
  id: string; name: string; domain: string; status: string;
  settings: { waf_enabled: boolean; web_server: "nginx" | "apache" };
}
type ReadPage = (path: string) => Promise<unknown>;
const canonicalID = (v: unknown): v is string => typeof v === "string" && /^[a-f0-9]{32}$/.test(v);
const record = (v: unknown): v is Record<string, unknown> => !!v && typeof v === "object" && !Array.isArray(v);
const keys = (v: Record<string, unknown>, names: string[]) => Object.keys(v).sort().join(",") === [...names].sort().join(",");

// Publish only a complete bounded list. Failed/malformed/later pages must not
// silently turn an unavailable inventory into an empty or partial success.
export async function readWafSites(engine: "nginx-waf" | "apache-waf", read: ReadPage, current: () => boolean): Promise<WafSiteChoice[]> {
  if (engine !== "nginx-waf" && engine !== "apache-waf") throw new Error("防火墙标识无效");
  const server = engine === "apache-waf" ? "apache" : "nginx", sites: WafSiteChoice[] = [];
  let cursor = "";
  for (let page = 0; page < 32; page++) {
    if (!current()) throw new Error("原防火墙工作区已关闭，未替换网站列表");
    const out = await read(`/software/${engine}/sites${cursor ? `?cursor=${cursor}` : ""}`);
    if (!current()) throw new Error("原防火墙工作区已关闭，未替换网站列表");
    if (!record(out) || !keys(out, ["sites", "next_cursor"]) || !Array.isArray(out.sites) || out.sites.length > 128 || typeof out.next_cursor !== "string") throw new Error("防火墙网站分页不可核对；未显示部分列表");
    let previous = cursor;
    for (const site of out.sites) {
      if (!record(site) || !keys(site, ["id", "name", "domain", "status", "settings"]) || !canonicalID(site.id) || site.id <= previous || typeof site.name !== "string" || site.name.length > 160 || typeof site.domain !== "string" || !site.domain || site.domain.length > 253 || typeof site.status !== "string" || site.status.length > 80 || !record(site.settings) || !keys(site.settings, ["waf_enabled", "web_server"]) || typeof site.settings.waf_enabled !== "boolean" || site.settings.web_server !== server) throw new Error("防火墙网站信息不可核对；未显示部分列表");
      previous = site.id;
      sites.push(site as unknown as WafSiteChoice);
    }
    if (!out.next_cursor) return sites;
    if (!canonicalID(out.next_cursor) || out.sites.length !== 128 || out.next_cursor !== previous || out.next_cursor <= cursor) throw new Error("防火墙网站分页游标无效；未显示部分列表");
    cursor = out.next_cursor;
  }
  throw new Error("防火墙网站列表超过 4096 个展示上限；未显示不完整列表，请缩小受管站点规模");
}
