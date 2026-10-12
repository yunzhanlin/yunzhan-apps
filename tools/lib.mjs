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
  if (typeof app.version !== "string" || app.version.length > 80 || !/^[0-9]+(?:\.[0-9]+){0,3}(?:-[A-Za-z0-9]+(?:[.-][A-Za-z0-9]+)*)?$/.test(app.version)) errors.push("invalid version");
  if (typeof app.name !== "string" || app.name.length < 2 || app.name.length > 80) errors.push("invalid name");
  if (!allowedCategories.has(app.category)) errors.push("invalid category");
  if (!allowedStages.has(app.stage)) errors.push("invalid stage");
  if (!allowedProviders.has(app.delivery?.provider)) errors.push("invalid provider");
  if (!targetPattern.test(app.delivery?.target || "")) errors.push("invalid delivery target");
  if (!allowedProbes.has(app.health?.probe)) errors.push("invalid health probe");
  if (!Array.isArray(app.capabilities) || app.capabilities.length < 1 || app.capabilities.length > 12) errors.push("invalid capabilities");
  const requirements=app.required_panel_features;
  const retirement="statistics-cursor-retirement-v1";
  if(Object.hasOwn(app,"required_panel_features")){
    if(!Array.isArray(requirements)||requirements.length<1||requirements.length>8||new Set(requirements).size!==requirements.length||requirements.some(feature=>typeof feature!=="string"||!idPattern.test(feature))||app.delivery?.provider!=="panel-module")errors.push("invalid required panel features");
    if(Array.isArray(requirements)&&requirements.some(feature=>feature!==retirement))errors.push("required panel feature has no reviewed implementation");
    if(Array.isArray(requirements)&&requirements.includes(retirement)&&(app.id!=="website-statistics-v2"||app.delivery?.target!==app.id))errors.push("statistics handler requirement belongs only to website-statistics-v2");
  }
  if(app.id==="website-statistics-v2"&&typeof app.version==="string"&&/^[0-9]+(?:\.[0-9]+){0,3}(?:-[A-Za-z0-9]+(?:[.-][A-Za-z0-9]+)*)?$/.test(app.version)){
    const parts=app.version.split("-")[0].split(".").map(BigInt),floor=[2n,4n,1n];let comparison=0;
    if(parts.some(value=>value>18446744073709551615n))errors.push("statistics version cannot be safely compared");
    for(let i=0;i<Math.max(parts.length,floor.length);i++){const a=parts[i]??0n,b=floor[i]??0n;if(a!==b){comparison=a>b?1:-1;break;}}
    if(comparison>=0&&(!Array.isArray(requirements)||!requirements.includes(retirement)))errors.push("new statistics package requires the actual cursor-retirement panel handler");
  }
  if (!Array.isArray(app.compatibility?.os) || !app.compatibility.os.length) errors.push("missing compatible os");
  if (!Array.isArray(app.compatibility?.architectures) || !app.compatibility.architectures.length) errors.push("missing architectures");
  if (typeof app.uninstall?.preserve_data !== "boolean" || typeof app.uninstall?.reference_check !== "boolean") errors.push("invalid uninstall policy");
  if (app.delivery?.provider === "compose" && !app.delivery.image) errors.push("compose package needs an image");
  if (app.risk === "eol" && (app.delivery?.provider !== "compose" || app.delivery?.isolation !== "legacy-container" || !/^php-legacy-(52|53|54|55|56|70|71|72|73|74|80|81)$/.test(app.delivery?.target || "") || !/^devilbox\/php-fpm:[0-9.]+-mods@sha256:[a-f0-9]{64}$/.test(app.delivery?.image || ""))) errors.push("EOL PHP requires the fixed isolated container contract");
  if (Object.hasOwn(app, "rule_data_channel")) {
    const channel = app.rule_data_channel;
    if (app.id !== "network-threat-detection" || app.delivery?.provider !== "panel-module" || app.delivery?.target !== app.id || Object.hasOwn(app, "rule_feeds") || !channel || typeof channel !== "object" || Array.isArray(channel) || Object.keys(channel).sort().join(",") !== "engine,format,id" || channel.id !== "et-open-web-bsd-v1" || channel.format !== 1 || channel.engine !== "suricata-8.0") errors.push("rule data channel requires the fixed passive IDS ABI without URLs, scripts or inline feeds");
  }
  return errors;
}
