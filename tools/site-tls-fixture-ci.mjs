// CI-only correction of an exact historical _test.go substring false positive.
// Runtime sources, frozen exports, source indices and test commands never change.
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';

const repo = fileURLToPath(new URL('../', import.meta.url));
const sha = value => createHash('sha256').update(value).digest('hex');
export const siteTLSFixtureMember = 'internal/executor/site_tls_test.go';
export const originalSiteTLSFixtureSHA = 'dd4c4aef5e0f555cbec00edbc7a837fdad8077671178ac8fc7f0952217877929';
export const correctedSiteTLSFixtureSHA = 'ff2b7793efc28dd290d77ec635b16eba0c686c93f1f68a6e9ced1b9a255dc89a';
const oldImports = '\t"local/panel/internal/core"\n';
const newImports = oldImports + '\t"net"\n\t"regexp"\n';
const oldCheck = 'strings.Contains(plain, ":443")';
const newCheck = 'renderedSiteHasTLSListener(plain)';
const marker = '\n// Inspect actual generated listen directives.';

function currentFixture() {
  const raw = fs.readFileSync(repo + 'panel-integration-compiler-memory/' + siteTLSFixtureMember);
  assert.equal(sha(raw), correctedSiteTLSFixtureSHA, 'Only the actual already-frozen corrected fixture is authoritative');
  return raw;
}
export function correctSiteTLSFixture(raw) {
  assert(Buffer.isBuffer(raw));
  assert.equal(sha(raw), originalSiteTLSFixtureSHA, 'Unknown historical fixture must refuse');
  const current = currentFixture().toString(), start = current.indexOf(marker);
  assert(start > 0 && current.split(marker).length === 2);
  let text = raw.toString();
  for (const [from, to] of [[oldImports, newImports], [oldCheck, newCheck]]) {
    assert.equal(text.split(from).length, 2, 'Every classifier/import replacement must be unique');
    text = text.replace(from, () => to);
  }
  const corrected = Buffer.from(text + current.slice(start));
  assert.equal(sha(corrected), correctedSiteTLSFixtureSHA);
  return corrected;
}
export function originalSiteTLSFixture(raw) {
  assert.equal(sha(raw), correctedSiteTLSFixtureSHA);
  let text = raw.toString();
  assert.equal(text.split(marker).length, 2);
  text = text.slice(0, text.indexOf(marker));
  for (const [from, to] of [[newImports, oldImports], [newCheck, oldCheck]]) {
    assert.equal(text.split(from).length, 2);
    text = text.replace(from, () => to);
  }
  assert.equal(sha(text), originalSiteTLSFixtureSHA, 'All other original fixture and assertion bytes stay exact');
  return Buffer.from(text);
}

// The caller first validates the complete immutable scope using its original
// allowlisted sourceIndex(). Rebind that exact index and this one test member.
export function reviewedSiteTLSReplacement(source, dir, index) {
  assert(path.isAbsolute(source) && fs.realpathSync(source) === source && path.dirname(source) + path.sep === repo);
  const root = fs.lstatSync(dir);
  assert(path.isAbsolute(dir) && fs.realpathSync(dir) === dir && root.isDirectory() && !root.isSymbolicLink() && root.uid === process.getuid() && (root.mode & 511) === 448);
  assert.deepEqual(JSON.parse(fs.readFileSync(source + '/source-sha256.json')), index);
  if (!Object.hasOwn(index.files, siteTLSFixtureMember)) return null;
  assert(!Object.hasOwn(index.test_overrides ?? {}, siteTLSFixtureMember));
  const target = source + '/' + siteTLSFixtureMember, st = fs.lstatSync(target);
  assert(st.isFile() && !st.isSymbolicLink() && st.nlink === 1 && st.size <= 2 << 20 && fs.realpathSync(target) === target);
  const raw = fs.readFileSync(target);
  assert.equal(sha(raw), index.files[siteTLSFixtureMember]);
  if (sha(raw) === correctedSiteTLSFixtureSHA) return null;
  assert.equal(sha(raw), originalSiteTLSFixtureSHA);
  const replacement = dir + '/reviewed-site-tls-fixture_test.go', corrected = correctSiteTLSFixture(raw);
  fs.writeFileSync(replacement, corrected, { flag: 'wx', mode: 0o600 });
  return { target, replacement, original_sha256: sha(raw), corrected_sha256: sha(corrected), original_assertions_preserved_except_exact_listener_classifier: true, actual_listen_directives_required: true, deterministic_health443_case_added: true };
}

// Prove the complete prior runner, including every original argument, scope,
// marker and deadline, is unchanged after removing precisely these three hooks.
export function originalSiteTLSCIRunner(raw) {
  assert(Buffer.isBuffer(raw));
  const old = '76df04fe88a526c9bc0e0007f76130c08368e203ce8a4fa53f349ac97a243b1e';
  if (sha(raw) === old) return raw;
  let text = raw.toString();
  const hooks = [
    "import{reviewedSiteTLSReplacement}from'./site-tls-fixture-ci.mjs';\n",
    '  const siteTLS=reviewedSiteTLSReplacement(source,dir,index);if(siteTLS)Replace[siteTLS.target]=siteTLS.replacement;\n',
    "  if(siteTLS)console.log(JSON.stringify({scope:path.basename(source),CI_test_fixture_only:'internal/executor/site_tls_test.go',...siteTLS,production_source_overrides:0,immutable_exports_changed:false,original_listen_and_port_boundaries_retained:true,all50_commercial:false}));\n",
  ];
  for (const hook of hooks) {
    assert.equal(text.split(hook).length, 2);
    text = text.replace(hook, '');
  }
  assert.equal(sha(text), old, 'Unknown runner changes cannot enter a test fixture correction');
  return Buffer.from(text);
}
