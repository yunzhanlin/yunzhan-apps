import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { reviewedHTTPSFixtureScopes } from '../tools/run-https-fixture-ci.mjs';
import { siteTLSFixtureMember, originalSiteTLSFixtureSHA, correctedSiteTLSFixtureSHA, correctSiteTLSFixture, originalSiteTLSFixture, reviewedSiteTLSReplacement, originalSiteTLSCIRunner } from '../tools/site-tls-fixture-ci.mjs';

const repo = fileURLToPath(new URL('../', import.meta.url));
const sha = value => createHash('sha256').update(value).digest('hex');
const original = fs.readFileSync(repo + 'panel-integration-file-manager/' + siteTLSFixtureMember);
function temporary(t) {
  const parent = repo + '.local'; fs.mkdirSync(parent, { recursive: true });
  const dir = fs.mkdtempSync(parent + '/site-tls-fixture-unit-'); fs.chmodSync(dir, 0o700);
  t.after(() => fs.rmSync(dir, { recursive: true }));
  return dir;
}

test('one exact historical assertion is replaced by actual directive classification and all other old bytes are reversible', () => {
  assert.equal(sha(original), originalSiteTLSFixtureSHA);
  const corrected = correctSiteTLSFixture(original);
  assert.equal(sha(corrected), correctedSiteTLSFixtureSHA);
  assert(originalSiteTLSFixture(corrected).equals(original));
  assert(corrected.equals(fs.readFileSync(repo + 'panel-integration-compiler-memory/' + siteTLSFixtureMember)));
  const text = corrected.toString();
  for (const value of ['renderedSiteHasTLSListener(plain)', 'TestRenderedTLSListenerDetectorRequiresAnActualDirective', 'TestPlainSiteHealthBody443PrefixIsNotAListener', '"health-site-id"', '"health-hash"', '"IPv4"', '"IPv6"', '"bare-port"', '"private-TLS"', '"different-TLS-port"', '"port-prefix"', '"unix-path"', '"443" + strings.Repeat("a", 29)']) assert(text.includes(value), value);
});
test('unknown assertions or production members cannot be corrected or relabelled as the original test', () => {
  for (const bytes of [Buffer.concat([original, Buffer.from('\n')]), Buffer.from(original.toString().replace('site.Settings.TLS = nil', 'site.Settings.TLS = &core.SiteTLS{}')), fs.readFileSync(repo + 'panel-integration-file-manager/internal/executor/site_public.go'), correctSiteTLSFixture(original)]) assert.throws(() => correctSiteTLSFixture(bytes));
  assert.throws(() => originalSiteTLSFixture(original));
});
test('all56 indexed scopes retain exact original source and already-corrected tests create no overlay', t => {
  assert.equal(Object.keys(reviewedHTTPSFixtureScopes).length, 56);
  let changed = 0, already = 0;
  for (const [name, expected] of Object.entries(reviewedHTTPSFixtureScopes)) {
    const source = repo + name, rawIndex = fs.readFileSync(source + '/source-sha256.json'), index = JSON.parse(rawIndex), before = fs.readFileSync(source + '/' + siteTLSFixtureMember), dir = temporary(t);
    assert.equal(sha(rawIndex), expected.index_sha256);
    assert.equal(index.release.frozen_inputs_sha256, expected.inputs);
    assert.equal(Object.keys(index.files).length, expected.files);
    const result = reviewedSiteTLSReplacement(source, dir, index);
    if (index.files[siteTLSFixtureMember] === correctedSiteTLSFixtureSHA) { already++; assert.equal(result, null); assert.deepEqual(fs.readdirSync(dir), []); }
    else {
      changed++; assert.equal(index.files[siteTLSFixtureMember], originalSiteTLSFixtureSHA);
      assert.equal(result.target, source + '/' + siteTLSFixtureMember);
      assert.equal(path.dirname(result.replacement), dir); assert.equal(sha(fs.readFileSync(result.replacement)), correctedSiteTLSFixtureSHA);
      const st = fs.lstatSync(result.replacement); assert(st.isFile() && !st.isSymbolicLink() && st.nlink === 1 && st.uid === process.getuid() && (st.mode & 511) === 384);
      assert(result.actual_listen_directives_required && result.deterministic_health443_case_added);
      assert.throws(() => reviewedSiteTLSReplacement(source, dir, index));
    }
    assert(fs.readFileSync(source + '/source-sha256.json').equals(rawIndex));
    assert(fs.readFileSync(source + '/' + siteTLSFixtureMember).equals(before));
  }
  assert(changed > 0 && already > 0 && changed + already === 56);
});
test('private replacement admission refuses forged indices, foreign or linked scopes and unsafe directories', t => {
  const source = repo + 'panel-integration-file-manager', index = JSON.parse(fs.readFileSync(source + '/source-sha256.json')), dir = temporary(t), changed = structuredClone(index);
  changed.files[siteTLSFixtureMember] = '0'.repeat(64); assert.throws(() => reviewedSiteTLSReplacement(source, dir, changed));
  assert.deepEqual(fs.readdirSync(dir), []);
  fs.chmodSync(dir, 0o755); assert.throws(() => reviewedSiteTLSReplacement(source, dir, index)); fs.chmodSync(dir, 0o700);
  const link = dir + '/linked'; fs.symlinkSync(dir, link); assert.throws(() => reviewedSiteTLSReplacement(source, link, index));
  assert.throws(() => reviewedSiteTLSReplacement(dir, dir, index));
  assert.throws(() => reviewedSiteTLSReplacement(source + '/', dir, index));
});
test('the complete prior CI runner and workflow are retained and arbitrary command or deadline changes refuse', () => {
  const raw = fs.readFileSync(repo + 'tools/run-https-fixture-ci.mjs'), restored = originalSiteTLSCIRunner(raw);
  assert.equal(sha(raw), '948fb862a143078e1428fc9d4a4ca18397a134938bef96f61ea24ae03bc1664e');
  assert.equal(sha(restored), '76df04fe88a526c9bc0e0007f76130c08368e203ce8a4fa53f349ac97a243b1e');
  assert.equal(originalSiteTLSCIRunner(restored), restored);
  assert.equal(sha(fs.readFileSync(repo + '.github/workflows/verify.yml')), '3682cf6cbb573d1ca20d2373265fc2b12b6982af9449aac828827c354b7e09a3');
  for (const text of [raw.toString().replace('args.slice(1)', "['./internal/executor']"), raw.toString().replace("process.env.GITHUB_ACTIONS==='true'", 'true'), raw.toString().replace('unchanged(source,index);assert(!result.error', 'assert(!result.error'), raw.toString() + '\n// unknown change']) assert.throws(() => originalSiteTLSCIRunner(Buffer.from(text)));
});
