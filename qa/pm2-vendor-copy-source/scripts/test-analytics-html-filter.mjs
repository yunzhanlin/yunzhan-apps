import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import vm from "node:vm";
import filter, { MAX_PREFIX_BYTES, MAX_PREFIX_CHUNKS } from "../internal/executor/analytics_html_vendor/analytics-html.js";

const vendor = new URL("../internal/executor/analytics_html_vendor/", import.meta.url);
const proof = JSON.parse(readFileSync(new URL("source.json", vendor), "utf8"));
for (const [name, sha] of Object.entries(proof.files)) assert.equal(createHash("sha256").update(readFileSync(new URL(name, vendor))).digest("hex"), sha);
const id = "a".repeat(32), script = '<script defer src="/__yunzhan/analytics/auto.js?site=' + id + '"></script>';
function transform(input, sizes = [8192], overrides = {}) {
  const original = Buffer.isBuffer(input) ? input : Buffer.from(input);
  const chunks = [];
  let done = false;
  const r = { method: "GET", status: 200, variables: { panel_analytics_site: id }, headersIn: {}, headersOut: { "Content-Type": "text/html; charset=utf-8", "Content-Length": String(original.length), ETag: '"original"', "Last-Modified": "yesterday", "Accept-Ranges": "bytes", "Content-Security-Policy": "script-src 'self'", "Set-Cookie": "original-cookie" }, sendBuffer: b => chunks.push(Buffer.from(b)), done: () => { done = true; }, ...overrides };
  const before = { ...r.headersOut };
  filter.header(r);
  let offset = 0, index = 0;
  while (offset < original.length) {
    const end = Math.min(original.length, offset + sizes[index++ % sizes.length]);
    const chunk = original.subarray(offset, end);
    if (done) chunks.push(chunk); else filter.body(r, chunk, { last: end === original.length });
    offset = end;
  }
  if (!original.length && !done) filter.body(r, Buffer.alloc(0), { last: true });
  return { output: Buffer.concat(chunks), headers: r.headersOut, before, done };
}
let tested = 0;
const valid = [
  '<!doctype html><html><head><title>中文😀</title></head><body>original</body></html>',
  '<head><script>const untouched = "</head>";</script></head><body>original</body>',
  '<head><!-- </head> --><style>a::after{content:"</head>"}</style></head>',
  '<HEAD><meta name="literal" content="</head>"><title>value &lt;/head&gt;</title></HeAd >',
  '<head><script><!-- <script>"</head>"</script> --></script></head>',
  '<head><template><head></head><div title="</head>"></div></template></head>',
  '\ufeff<head><title>😎</title></head>',
  '<head><noscript>literal </head></noscript></head>',
];
for (const html of valid) {
  const expected = Buffer.from(html.slice(0, html.toLowerCase().lastIndexOf("</head")) + script + html.slice(html.toLowerCase().lastIndexOf("</head")));
  for (const sizes of [[65536], [1, 3, 7], [2], [5, 13, 19]]) {
    const result = transform(html, sizes);
    assert.deepEqual(result.output, expected, html);
    assert.equal(result.headers["Content-Length"], undefined);
    assert.equal(result.headers.ETag, undefined);
    assert.equal(result.headers["Content-Security-Policy"], result.before["Content-Security-Policy"]);
    assert.equal(result.headers["Set-Cookie"], "original-cookie");
    tested++;
  }
}
const quoted = transform(valid[1], [1, 3]).output.toString();
new vm.Script(quoted.match(/<script>([\s\S]*?)<\/script>/)[1]);
for (const input of [
  '<html><body>no explicit head</body></html>',
  '<head><title>implicit close</title><body>no end-tag</body>',
  '<!-- <head></head> --><body>literal only</body>',
  '<head><script>unterminated "</head>"',
  '<head>' + '<template>'.repeat(200) + '</template>'.repeat(200) + '</head>',
  '<head>' + '<meta>'.repeat(4100) + '</head>',
  '<head>' + 'x'.repeat(MAX_PREFIX_BYTES + 1) + '</head>',
  Buffer.concat([Buffer.from('<head><title>'), Buffer.from([0xff]), Buffer.from('</title></head>')]),
]) { assert.deepEqual(transform(input, [11, 17]).output, Buffer.from(input)); tested++; }
assert.deepEqual(transform('<head><title>' + 'x'.repeat(MAX_PREFIX_CHUNKS + 1) + '</title></head>', [1]).output, Buffer.from('<head><title>' + 'x'.repeat(MAX_PREFIX_CHUNKS + 1) + '</title></head>')); tested++;
for (const overrides of [
  { method: "HEAD" }, { method: "POST" }, { status: 206 }, { status: 404 },
  { variables: { panel_analytics_site: '";bad' } }, { headersIn: { Range: "bytes=0-8" } },
  ...["application/json", "text/javascript", "image/svg+xml", "text/html; charset=gbk", "text/html; charset=utf8; charset=latin1"].map(type => ({ headersOut: { "Content-Type": type, ETag: '"keep"', "Content-Length": "37" } })),
  { headersOut: { "Content-Type": "text/html", "Content-Encoding": "gzip", "Content-Length": "37" } },
  { headersOut: { "Content-Type": "text/html", "Content-Disposition": "attachment" } },
]) { const result = transform('<head></head><body>original</body>', [2, 5], overrides); assert.deepEqual(result.output, Buffer.from('<head></head><body>original</body>')); assert.deepEqual(result.headers, result.before); tested++; }
// Header starts a new request and drops abandoned parser state, not a site cache.
transform('<head><title>unfinished');
assert.equal(transform('<head></head>').output.toString(), '<head>' + script + '</head>'); tested++;
for (const variables of [{panel_analytics_engine:id,panel_analytics_program_sha:"b".repeat(64)}, {panel_analytics_engine:"../bad",panel_analytics_program_sha:"b".repeat(64)}, {panel_analytics_engine:id,panel_analytics_program_sha:"untrusted"}]) {
  let code, value;
  const r={variables,headersOut:{},return:(status,body)=>{code=status;value=body;}};
  filter.health(r);
  if (variables.panel_analytics_engine===id && variables.panel_analytics_program_sha.length===64) {
    assert.equal(code,200);assert.deepEqual(JSON.parse(value),{protocol:"yunzhan-analytics-html-v1",job_id:id,program_sha256:"b".repeat(64)});assert.equal(r.headersOut["Cache-Control"],"no-store");
  } else {assert.equal(code,503);assert.equal(value,undefined);}
  tested++;
}
console.log(`PASS analytics HTML filter: ${tested} context/byte/chunk/header/resource/isolation cases; generated bundle SHA ${proof.files["analytics-html.js"]}`);
