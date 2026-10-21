const securitySoftwareIDs = new Set([
  "nginx-waf",
  "system-hardening",
  "intrusion-prevention",
]);

export function isSecuritySoftware(id: string): boolean {
  return securitySoftwareIDs.has(id);
}

export function softwareManagerKind(app: { id: string; family: string }): "security" | "module" | null {
  if (isSecuritySoftware(app.id)) return "security";
  if (app.family === "module" && /^[a-z0-9][a-z0-9-]{1,62}$/.test(app.id)) return "module";
  return null;
}
