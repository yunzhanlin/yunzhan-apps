import { createHash } from "node:crypto";

export function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

export function pretty(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

export function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

export const idPattern = /^[a-z0-9][a-z0-9-]{1,62}$/;
export const targetPattern = /^[a-z0-9][a-z0-9._-]{1,127}$/;
export const allowedProviders = new Set(["runtime", "compose", "panel-module"]);
export const allowedStages = new Set(["ready", "integration", "design"]);
export const allowedCategories = new Set(["deployment", "professional"]);
export const allowedProbes = new Set(["binary", "systemd", "tcp", "http", "panel-api"]);

export function validateManifest(app) {
  const errors = [];
  if (app.schema_version !== 1) errors.push("schema_version must be 1");
  if (!idPattern.test(app.id || "")) errors.push("invalid id");
  if (typeof app.name !== "string" || app.name.length < 2 || app.name.length > 80) errors.push("invalid name");
  if (!allowedCategories.has(app.category)) errors.push("invalid category");
  if (!allowedStages.has(app.stage)) errors.push("invalid stage");
  if (!allowedProviders.has(app.delivery?.provider)) errors.push("invalid provider");
  if (!targetPattern.test(app.delivery?.target || "")) errors.push("invalid delivery target");
  if (!allowedProbes.has(app.health?.probe)) errors.push("invalid health probe");
  if (!Array.isArray(app.capabilities) || app.capabilities.length < 1 || app.capabilities.length > 12) errors.push("invalid capabilities");
  if (!Array.isArray(app.compatibility?.os) || !app.compatibility.os.length) errors.push("missing compatible os");
  if (!Array.isArray(app.compatibility?.architectures) || !app.compatibility.architectures.length) errors.push("missing architectures");
  if (typeof app.uninstall?.preserve_data !== "boolean" || typeof app.uninstall?.reference_check !== "boolean") errors.push("invalid uninstall policy");
  if (app.delivery?.provider === "compose" && !app.delivery.image) errors.push("compose package needs an image");
  if (app.risk === "eol" && (app.delivery?.provider !== "compose" || app.delivery?.isolation !== "legacy-container" || !/^php-legacy-(52|53|54|55|56|70|71|72|73|74|80|81)$/.test(app.delivery?.target || "") || !/^devilbox\/php-fpm:[0-9.]+-mods@sha256:[a-f0-9]{64}$/.test(app.delivery?.image || ""))) errors.push("EOL PHP requires the fixed isolated container contract");
  return errors;
}
