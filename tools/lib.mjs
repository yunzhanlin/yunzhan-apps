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
  const identity="statistics-request-identity-v1";
  const geography="statistics-geodata-v2";
  const maintenance="platform-maintenance-v1";
  const disk="disk-inode-usage-v1";
  const hostDisk="disk-host-jobs-v1";
  const memcached="compose-memcached-digest-v1";
  const analyticsSession="analytics-session-lifecycle-v1";
  const hardening="hardening-reversible-journal-v1";
  const intrusion="intrusion-preserving-journal-v2";
  const wafHealth="waf-bound-health-v1";
  const runtimePackage="runtime-package-version-v1";
  const mobileNative="mobile-native-delivery-v132";
  const memcachedImage="memcached:1.6.45-alpine@sha256:9e4de012dc607573052061c0bcb38abc775e1dd59b24e7ac38d1892842094aaf";
  const memcachedScope=app.id==="memcached"&&app.version==="1.6.45-compat2"&&app.delivery?.provider==="compose";
  const runtimePackageScope=app.id==="nginx"&&app.version==="1.30.6-compat1"&&app.delivery?.provider==="runtime";
  if(Object.hasOwn(app,"required_panel_features")){
    if(!Array.isArray(requirements)||requirements.length<1||requirements.length>8||new Set(requirements).size!==requirements.length||requirements.some(feature=>typeof feature!=="string"||!idPattern.test(feature))||(app.delivery?.provider!=="panel-module"&&!memcachedScope&&!runtimePackageScope))errors.push("invalid required panel features");
    if(Array.isArray(requirements)&&requirements.some(feature=>feature!==retirement&&feature!==identity&&feature!==geography&&feature!==maintenance&&feature!==disk&&feature!==hostDisk&&feature!==memcached&&feature!==analyticsSession&&feature!==hardening&&feature!==intrusion&&feature!==wafHealth&&feature!==runtimePackage&&feature!==mobileNative))errors.push("required panel feature has no reviewed implementation");
    if(Array.isArray(requirements)&&requirements.includes(wafHealth)&&(app.id!=="nginx-waf"||app.version!=="2.5.2"||app.delivery?.provider!=="panel-module"||app.delivery?.target!==app.id||app.delivery?.manage_route!=="security"||requirements.length!==1))errors.push("site-bound health handler belongs only to exact Nginx WAF2.5.2");
    if(Array.isArray(requirements)&&requirements.includes(intrusion)&&(app.id!=="anti-intrusion"||app.version!=="1.1.0"||app.delivery?.provider!=="panel-module"||app.delivery?.target!=="intrusion-prevention"||app.delivery?.manage_route!=="security"||requirements.length!==1))errors.push("preserving intrusion journal belongs only to exact anti-intrusion1.1.0 and its fixed executor target");
    if(Array.isArray(requirements)&&requirements.includes(hardening)&&(app.id!=="system-hardening"||app.version!=="1.1.0"||app.delivery?.provider!=="panel-module"||app.delivery?.target!==app.id||app.delivery?.manage_route!=="security"||requirements.length!==1))errors.push("reversible hardening journal handler belongs only to exact system-hardening1.1.0");
    if(Array.isArray(requirements)&&requirements.includes(analyticsSession)&&(app.id!=="website-analytics"||app.version!=="2.3.1"||app.delivery?.provider!=="panel-module"||app.delivery?.target!==app.id||app.delivery?.manage_route!=="app-modules"||requirements.length!==1))errors.push("analytics session handler belongs only to exact website-analytics2.3.1");
    if(Array.isArray(requirements)&&requirements.some(feature=>feature===retirement||feature===identity||feature===geography)&&(app.id!=="website-statistics-v2"||app.delivery?.target!==app.id))errors.push("statistics handler requirement belongs only to website-statistics-v2");
    if(Array.isArray(requirements)&&requirements.includes(maintenance)&&(app.id!=="platform-ops"||app.version!=="1.3.0"||app.delivery?.target!==app.id))errors.push("maintenance handler belongs only to exact platform-ops1.3.0");
    if(Array.isArray(requirements)&&requirements.includes(disk)&&(app.id!=="disk-analysis"||!["1.3.0","1.4.0"].includes(app.version)||app.delivery?.target!==app.id||app.delivery?.manage_route!=="app-modules"))errors.push("inode usage handler belongs only to exact disk-analysis1.3.0 or1.4.0");
    if(Array.isArray(requirements)&&requirements.includes(hostDisk)&&(app.id!=="disk-analysis"||app.version!=="1.4.0"||app.delivery?.target!==app.id||app.delivery?.manage_route!=="app-modules"))errors.push("host disk handler belongs only to exact disk-analysis1.4.0");
  }
  // Only exact published mobile identities are legacy-compatible. A new label
  // cannot borrow old delivery metadata or a foreign fixed executor target.
  const mobileScope=app.id==="mobile"||app.delivery?.target==="mobile-pwa";
  const legacyMobile=["1.0","1.0-compat1","1.1.0","1.2.0","1.3.0"];
  if(mobileScope&&!legacyMobile.includes(app.version)||Array.isArray(requirements)&&requirements.includes(mobileNative)){
    if(app.id!=="mobile"||app.version!=="1.3.2"||app.delivery?.provider!=="panel-module"||app.delivery?.target!=="mobile-pwa"||app.delivery?.manage_route!=="app-modules"||!Array.isArray(requirements)||requirements.length!==1||requirements[0]!==mobileNative)errors.push("native mobile1.3.2 requires its exact fixed delivery metadata handler");
  }
  // An exact native target cannot borrow an old/foreign package label to evade
  // the compiled handler. Keep historical Nginx endpoints immutable, while new
  // programme/revision identities require an independently reviewed binding.
  let newNginx=false;
  if(app.id==="nginx"&&typeof app.version==="string"&&/^[0-9]+(?:\.[0-9]+){0,3}(?:-[A-Za-z0-9]+(?:[.-][A-Za-z0-9]+)*)?$/.test(app.version)){
    const parts=app.version.split("-")[0].split(".").map(BigInt),floor=[1n,30n,6n];let comparison=0;
    if(parts.some(value=>value>18446744073709551615n))errors.push("Nginx runtime package version cannot be safely compared");
    for(let i=0;i<Math.max(parts.length,floor.length);i++){const a=parts[i]??0n,b=floor[i]??0n;if(a!==b){comparison=a>b?1:-1;break;}}
    newNginx=comparison>=0;
  }
  if(newNginx||app.delivery?.target==="nginx-1.30.6"||Array.isArray(requirements)&&requirements.includes(runtimePackage)){
    if(!runtimePackageScope||app.delivery?.target!=="nginx-1.30.6"||app.delivery?.manage_route!=="sites"||!Array.isArray(requirements)||requirements.length!==1||requirements[0]!==runtimePackage)errors.push("Nginx1.30.6-compat1 requires its exact native target and compiled runtime/package version handler");
  }
  if(app.id==="nginx-waf"&&typeof app.version==="string"&&/^[0-9]+(?:\.[0-9]+){0,3}(?:-[A-Za-z0-9]+(?:[.-][A-Za-z0-9]+)*)?$/.test(app.version)){
    const parts=app.version.split("-")[0].split(".").map(BigInt),floor=[2n,5n,2n];let comparison=0;
    if(parts.some(value=>value>18446744073709551615n))errors.push("WAF health version cannot be safely compared");
    for(let i=0;i<Math.max(parts.length,floor.length);i++){const a=parts[i]??0n,b=floor[i]??0n;if(a!==b){comparison=a>b?1:-1;break;}}
    if(comparison>=0&&(app.version!=="2.5.2"||app.delivery?.provider!=="panel-module"||app.delivery?.target!==app.id||app.delivery?.manage_route!=="security"||!Array.isArray(requirements)||requirements.length!==1||requirements[0]!==wafHealth))errors.push("Nginx WAF2.5.2 requires its exact independently compiled site-bound health handler");
  }
  if(app.id==="anti-intrusion"&&typeof app.version==="string"&&/^[0-9]+(?:\.[0-9]+){0,3}(?:-[A-Za-z0-9]+(?:[.-][A-Za-z0-9]+)*)?$/.test(app.version)){
    const parts=app.version.split("-")[0].split(".").map(BigInt),floor=[1n,1n,0n];let comparison=0;
    if(parts.some(value=>value>18446744073709551615n))errors.push("intrusion version cannot be safely compared");
    for(let i=0;i<Math.max(parts.length,floor.length);i++){const a=parts[i]??0n,b=floor[i]??0n;if(a!==b){comparison=a>b?1:-1;break;}}
    if(comparison>=0&&(app.version!=="1.1.0"||app.delivery?.provider!=="panel-module"||app.delivery?.target!=="intrusion-prevention"||app.delivery?.manage_route!=="security"||!Array.isArray(requirements)||requirements.length!==1||requirements[0]!==intrusion))errors.push("intrusion1.1.0 requires its exact independently compiled process-lifetime bound journal handler");
  }
  if(app.id==="system-hardening"&&typeof app.version==="string"&&/^[0-9]+(?:\.[0-9]+){0,3}(?:-[A-Za-z0-9]+(?:[.-][A-Za-z0-9]+)*)?$/.test(app.version)){
    const parts=app.version.split("-")[0].split(".").map(BigInt),floor=[1n,1n,0n];let comparison=0;
    if(parts.some(value=>value>18446744073709551615n))errors.push("hardening version cannot be safely compared");
    for(let i=0;i<Math.max(parts.length,floor.length);i++){const a=parts[i]??0n,b=floor[i]??0n;if(a!==b){comparison=a>b?1:-1;break;}}
    if(comparison>=0&&(app.version!=="1.1.0"||app.delivery?.provider!=="panel-module"||app.delivery?.target!==app.id||app.delivery?.manage_route!=="security"||!Array.isArray(requirements)||requirements.length!==1||requirements[0]!==hardening))errors.push("hardening1.1.0 requires its exact independently compiled reversible journal handler");
  }
  // A new application revision cannot borrow the previous collector merely
  // by changing its advertised version. Preserve the historical2.3.0 package.
  if(app.id==="website-analytics"&&typeof app.version==="string"&&/^[0-9]+(?:\.[0-9]+){0,3}(?:-[A-Za-z0-9]+(?:[.-][A-Za-z0-9]+)*)?$/.test(app.version)){
    const parts=app.version.split("-")[0].split(".").map(BigInt),floor=[2n,3n,1n];let comparison=0;
    if(parts.some(value=>value>18446744073709551615n))errors.push("analytics session version cannot be safely compared");
    for(let i=0;i<Math.max(parts.length,floor.length);i++){const a=parts[i]??0n,b=floor[i]??0n;if(a!==b){comparison=a>b?1:-1;break;}}
    if(comparison>=0&&(app.version!=="2.3.1"||app.delivery?.provider!=="panel-module"||app.delivery?.target!==app.id||app.delivery?.manage_route!=="app-modules"||!Array.isArray(requirements)||requirements.length!==1||requirements[0]!==analyticsSession))errors.push("analytics2.3.1 requires its exact independently compiled session lifecycle handler");
  }
  // This is ONE reviewed Compose ABI, not a general provider exemption.
  // Only the immutable published compat1 and exact pinned compat2 are reviewed;
  // aliases/future revisions must get an explicit handler review, not inherit it.
  if(app.id==="memcached"&&!["1.6.45-compat1","1.6.45-compat2"].includes(app.version))errors.push("Memcached application revision has no reviewed exact handler");
  if(memcachedScope||app.id==="memcached"&&app.version==="1.6.45-compat2"||Array.isArray(requirements)&&requirements.includes(memcached)){
    if(!memcachedScope||app.delivery?.target!=="memcached-cache"||app.delivery?.manage_route!=="docker"||Object.hasOwn(app.delivery??{},"isolation")||app.delivery?.image!==memcachedImage||!Array.isArray(requirements)||requirements.length!==1||requirements[0]!==memcached)errors.push("Memcached compat2 requires its exact fixed OCI index, single handler and Compose template");
  }
  if(app.id==="disk-analysis"&&typeof app.version==="string"&&/^[0-9]+(?:\.[0-9]+){0,3}(?:-[A-Za-z0-9]+(?:[.-][A-Za-z0-9]+)*)?$/.test(app.version)){
    const parts=app.version.split("-")[0].split(".").map(BigInt),floor=[1n,3n,0n];let comparison=0;
    if(parts.some(value=>value>18446744073709551615n))errors.push("disk usage version cannot be safely compared");
    for(let i=0;i<Math.max(parts.length,floor.length);i++){const a=parts[i]??0n,b=floor[i]??0n;if(a!==b){comparison=a>b?1:-1;break;}}
    if(comparison>=0){
      if(app.version==="1.3.0"){
        if(!Array.isArray(requirements)||requirements.length!==1||requirements[0]!==disk)errors.push("disk analysis1.3 needs bounded inode allocation handler");
      }else if(app.version==="1.4.0"){
        if(!Array.isArray(requirements)||requirements.length!==2||!requirements.includes(disk)||!requirements.includes(hostDisk))errors.push("disk analysis1.4 needs both inode usage and independent host job handlers");
      }else errors.push("disk analysis new format requires exact reviewed1.3.0 or1.4.0, not aliases or unreviewed revisions");
    }
  }
  if(app.id==="platform-ops"&&typeof app.version==="string"&&/^[0-9]+(?:\.[0-9]+){0,3}(?:-[A-Za-z0-9]+(?:[.-][A-Za-z0-9]+)*)?$/.test(app.version)){
    const parts=app.version.split("-")[0].split(".").map(BigInt),floor=[1n,3n,0n];let comparison=0;
    if(parts.some(value=>value>18446744073709551615n))errors.push("maintenance version cannot be safely compared");
    for(let i=0;i<Math.max(parts.length,floor.length);i++){const a=parts[i]??0n,b=floor[i]??0n;if(a!==b){comparison=a>b?1:-1;break;}}
    if(comparison>=0&&(app.version!=="1.3.0"||!Array.isArray(requirements)||!requirements.includes(maintenance)))errors.push("maintenance1.3 needs exact version and independent authorization/original-native-receipt handler");
  }
  if(app.id==="website-statistics-v2"&&typeof app.version==="string"&&/^[0-9]+(?:\.[0-9]+){0,3}(?:-[A-Za-z0-9]+(?:[.-][A-Za-z0-9]+)*)?$/.test(app.version)){
    const parts=app.version.split("-")[0].split(".").map(BigInt),floor=[2n,4n,1n];let comparison=0;
    if(parts.some(value=>value>18446744073709551615n))errors.push("statistics version cannot be safely compared");
    for(let i=0;i<Math.max(parts.length,floor.length);i++){const a=parts[i]??0n,b=floor[i]??0n;if(a!==b){comparison=a>b?1:-1;break;}}
    if(comparison>=0&&(!Array.isArray(requirements)||!requirements.includes(retirement)))errors.push("new statistics package requires the actual cursor-retirement panel handler");
    const identityFloor=[2n,5n,0n];let identityComparison=0;
    for(let i=0;i<Math.max(parts.length,identityFloor.length);i++){const a=parts[i]??0n,b=identityFloor[i]??0n;if(a!==b){identityComparison=a>b?1:-1;break;}}
    if(identityComparison>=0){
      if(!Array.isArray(requirements)||!requirements.includes(identity))errors.push("statistics2.5 requires the actual request identity, migration and gzip panel handler");
      if(app.version!=="2.5.0"&&app.version!=="2.6.0")errors.push("statistics new format requires exact reviewed2.5.0 or2.6.0, not aliases or unreviewed revisions");
    }
  }
  const geoPresent=Object.hasOwn(app,"geo_data_channel"),geoRequired=Array.isArray(requirements)&&requirements.includes(geography);
  if(geoPresent||geoRequired||app.id==="website-statistics-v2"&&app.version==="2.6.0"){
    const channel=app.geo_data_channel;
    if(app.id!=="website-statistics-v2"||app.version!=="2.6.0"||app.delivery?.provider!=="panel-module"||app.delivery?.target!==app.id||!geoRequired||!channel||typeof channel!=="object"||Array.isArray(channel)||Object.keys(channel).sort().join(",")!=="format,id"||channel.id!=="dbip-city-lite-v1"||channel.format!==1)errors.push("geography requires exact2.6 with bounded-reader ABI and fixed signed data channel; no URLs, keys or scripts");
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
