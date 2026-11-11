const labels: Record<string, string> = {
  binding: "实际域名绑定",
  http: "站点 HTTP",
  dns: "域名解析",
  tls_certificate: "HTTPS 证书",
  nginx: "Nginx 配置",
  files: "网站文件抽查",
};
const verdicts: Record<string, string> = { pass: "通过", warn: "需核对", fail: "失败" };
const entities: Record<string, string> = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#39;",
};

function html(value: unknown): string {
  return (typeof value === "string" || typeof value === "number" ? String(value) : "")
    .replace(/[&<>"']/g, (character) => entities[character]);
}

function diagnosisSection(report: Record<string, unknown>): string {
  const checks = (report.checks || {}) as Record<string, Record<string, unknown>>;
  const keys = Array.isArray(report.check_order) ? report.check_order : Object.keys(checks);
  const rows = keys.filter((key: unknown): key is string =>
    typeof key === "string" && Object.hasOwn(labels, key) && Object.hasOwn(checks, key),
  ).map((key) => {
    const check = checks[key];
    if (!check || typeof check !== "object") return "";
    const verdict = typeof check.verdict === "string" && Object.hasOwn(verdicts, check.verdict)
      ? verdicts[check.verdict]
      : (check.ok ?? check.valid) === true ? "通过" : "需核对";
    const http = typeof check.status === "number" ? `HTTP ${html(check.status)}` : "";
    const milliseconds = typeof check.response_ms === "number" ? `${html(check.response_ms)} 毫秒` : "";
    const metadata = [http, milliseconds].filter(Boolean).join(" · ");
    return `<tr><th scope="row">${labels[key]}</th><td>${verdict}</td><td>${html(check.detail)}${metadata ? `<p>${metadata}</p>` : ""}</td></tr>`;
  });
  return `<section><h2>${html(report.domain)}${html(report.path)}</h2><p>${html(report.checked_at)}</p>
<table><thead><tr><th scope="col">检查项</th><th scope="col">结果</th><th scope="col">说明</th></tr></thead>
<tbody>${rows.join("")}</tbody></table><p>${html(report.scope)}</p></section>`;
}

export function renderSiteDiagnosisHTML(report: Record<string, unknown>): string {
  const sections = Array.isArray(report.diagnoses)
    ? report.diagnoses.filter((row) => row && typeof row === "object").map((row) =>
        row.report && typeof row.report === "object" ? diagnosisSection(row.report) :
          `<section><h2>${html(row.site_id)}</h2><p>${html(row.error)}</p></section>`,
      )
    : [diagnosisSection(report)];
  return `<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>网站诊断</title>
<style>body{margin:2rem auto;padding:0 1rem;max-width:64rem;color:#172535;font:1rem/1.55 system-ui,sans-serif}table{width:100%;border-collapse:collapse}th,td{text-align:left;vertical-align:top;border:1px solid #cfd6df;padding:.6rem}thead{background:#eef3f8}p{margin:.4rem 0;overflow-wrap:anywhere}</style></head>
<body><h1>网站诊断</h1>${sections.join("")}</body></html>`;
}
