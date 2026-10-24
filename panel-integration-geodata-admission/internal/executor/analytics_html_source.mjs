// First-party, opt-in response transformation. No network or filesystem API.
// This source is bundled with the pinned MIT parse5 / BSD entities parser.
import { Parser, defaultTreeAdapter } from "parse5";

export const MAX_PREFIX_BYTES = 65536;
export const MAX_PREFIX_CHUNKS = 512;
export const MAX_NODES = 4096;
export const MAX_DEPTH = 128;

function boundedParser() {
  let nodes = 0;
  let parser;
  const allocate = () => { if (++nodes > MAX_NODES) throw new Error("node budget"); };
  const adapter = { ...defaultTreeAdapter };
  for (const name of ["createDocument", "createDocumentFragment", "createElement", "createCommentNode", "createTextNode"]) {
    adapter[name] = (...args) => { allocate(); return defaultTreeAdapter[name](...args); };
  }
  // parse5 calls this after each stack push. Do not allow a malicious prefix
  // to build an unbounded template/foreign-content nesting stack.
  adapter.onItemPush = node => {
    if (parser && parser.openElements.stackTop >= MAX_DEPTH) throw new Error("stack budget");
    let depth = 0;
    for (let parent = node; parent; parent = parent.parentNode) {
      if (++depth > MAX_DEPTH) throw new Error("depth budget");
    }
  };
  parser = new Parser({ treeAdapter: adapter, sourceCodeLocationInfo: true, scriptingEnabled: true });
  return parser;
}

export function eligible(r) {
  if (r.method !== "GET" || r.status !== 200 || !/^[a-f0-9]{32}$/.test(r.variables.panel_analytics_site || "")) return false;
  if (r.headersIn.Range || r.headersOut["Content-Encoding"] || r.headersOut["Content-Disposition"]) return false;
  const type = String(r.headersOut["Content-Type"] || "").split(";");
  if (type.shift().trim().toLowerCase() !== "text/html") return false;
  let charsets = 0;
  for (const part of type) {
    const parameter = part.trim();
    if (!/^charset\s*=/i.test(parameter)) continue;
    const value = parameter.replace(/^charset\s*=\s*/i, "").replace(/^"(.*)"$/, "$1").toLowerCase();
    if (++charsets > 1 || !["utf-8", "utf8"].includes(value)) return false;
  }
  return true;
}

// A VM/context is bound to one HTTP request by ngx_http_js_module. header()
// starts a fresh state even when QuickJS contexts are reused; release it as
// soon as we inject, hit a limit, or reach EOF. No cross-request/site cache.
let state;
export function header(r) {
  state = undefined;
  if (!eligible(r)) return;
  state = { buffers: [], bytes: 0, chunks: 0, text: "", decoder: new TextDecoder("utf-8", { fatal: true }), parser: boundedParser() };
  // A transformation changes representation length and strong validators.
  // Do not change CSP, cookies, privacy headers, or redirect/cache policy.
  for (const name of ["Content-Length", "ETag", "Last-Modified", "Accept-Ranges"]) delete r.headersOut[name];
}

function flushOriginal(r, data, flags) {
  const old = state;
  state = undefined;
  if (old && old.buffers.length) r.sendBuffer(Buffer.concat(old.buffers));
  r.sendBuffer(data, flags);
  r.done();
}

export function body(r, data, flags) {
  if (!state) { r.sendBuffer(data, flags); r.done(); return; }
  if (state.bytes + data.length > MAX_PREFIX_BYTES || ++state.chunks > MAX_PREFIX_CHUNKS) {
    flushOriginal(r, data, flags); return;
  }
  // The original Buffer bytes are authoritative. Decode only a bounded prefix
  // to locate a real head end-tag; never reserialize HTML or response bodies.
  const copy = Buffer.from(data);
  state.buffers.push(copy);
  state.bytes += copy.length;
  try {
    const text = state.decoder.decode(copy, { stream: !flags.last });
    state.text += text;
    state.parser.tokenizer.write(text, flags.last);
    const location = state.parser.headElement && state.parser.headElement.sourceCodeLocation;
    if (location && location.startTag && location.endTag) {
      const original = Buffer.concat(state.buffers);
      // The UTF-8 decoder strips the initial BOM, as does HTML encoding
      // detection. Preserve it in the response and account for its raw bytes.
      const bom = original.length >= 3 && original[0] === 0xef && original[1] === 0xbb && original[2] === 0xbf ? 3 : 0;
      const offset = bom + Buffer.byteLength(state.text.slice(0, location.endTag.startOffset), "utf8");
      if (offset < 0 || offset > original.length || !/^<\/head(?:\s|>)/i.test(original.subarray(offset).toString("utf8"))) throw new Error("offset mismatch");
      const script = Buffer.from('<script defer src="/__yunzhan/analytics/auto.js?site=' + r.variables.panel_analytics_site + '"></script>');
      const transformed = Buffer.concat([original.subarray(0, offset), script, original.subarray(offset)]);
      state = undefined;
      r.sendBuffer(transformed, flags);
      r.done();
      return;
    }
    if (flags.last || (state.parser.headElement && !state.parser.openElements.items.includes(state.parser.headElement))) {
      // An implicitly closed/missing head is not a safe insertion target.
      const original = Buffer.concat(state.buffers);
      state = undefined;
      r.sendBuffer(original, flags);
      r.done();
    }
  } catch (_) {
    // Invalid encoding, parser/offset error or resource budget: preserve every
    // original byte. Header validators were already cleared, never fabricated.
    const original = Buffer.concat(state.buffers);
    state = undefined;
    r.sendBuffer(original, flags);
    r.done();
  }
}

// Reached only through the separately managed Unix-socket health server.
// The fingerprint belongs to this worker's loaded immutable configuration;
// filesystem state alone cannot acknowledge a successful reload.
export function health(r) {
  const job = r.variables.panel_analytics_engine || "";
  const program = r.variables.panel_analytics_program_sha || "";
  if (!/^[a-f0-9]{32}$/.test(job) || !/^[a-f0-9]{64}$/.test(program)) { r.return(503); return; }
  r.headersOut["Content-Type"] = "application/json";
  r.headersOut["Cache-Control"] = "no-store";
  r.return(200, JSON.stringify({ protocol: "yunzhan-analytics-html-v1", job_id: job, program_sha256: program }));
}

export default { header, body, health };
