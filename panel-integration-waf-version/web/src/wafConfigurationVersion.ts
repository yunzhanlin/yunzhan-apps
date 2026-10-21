// Keep programme capability and installed app identity separate. Unknown
// versions never enable a configuration write merely by comparing equal.
const nginxVersions = new Set(["2.0.1", "2.1.0", "2.1.1", "2.2.0", "2.3.0", "2.4.0", "2.5.0", "2.5.1", "2.5.2"]);

export function wafConfigurationVersionMatches(engine: string, installed: boolean, version: unknown, implementation: unknown): boolean {
  if (engine === "apache-waf") return typeof installed === "boolean";
  if (engine !== "nginx-waf" || typeof installed !== "boolean" || typeof implementation !== "string" || !nginxVersions.has(implementation)) return false;
  return !installed || typeof version === "string" && version === implementation;
}
