import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { correctAnalyticsSessionFixture, originalAnalyticsSessionFixture, reviewedAnalyticsReplacement, analyticsFixtureMember, originalAnalyticsFixtureSHA, correctedAnalyticsFixtureSHA, alreadyCorrectedAnalyticsFixtureSHA, analyticsFixturePlan } from '../tools/analytics-report-fixture-ci.mjs';
import { reviewedHTTPSFixtureScopes } from '../tools/run-https-fixture-ci.mjs';

const repo = fileURLToPath(new URL('../', import.meta.url));
const sha = value => createHash('sha256').update(value).digest('hex');
const source = repo + 'panel-integration-analytics-session';
const raw = fs.readFileSync(source + '/' + analyticsFixtureMember);
function temporary(t) {
  fs.mkdirSync(repo + '.local', { recursive: true });
  const dir = fs.mkdtempSync(repo + '.local/analytics-session-fixture-');
  fs.chmodSync(dir, 0o700);
  t.after(() => fs.rmSync(dir, { recursive: true }));
  return dir;
}
test('UTC-boundary fixture retains every original journey and performance assertion byte', () => {
  assert.equal(sha(raw), originalAnalyticsFixtureSHA);
  const corrected = correctAnalyticsSessionFixture(raw);
  assert.equal(sha(corrected), correctedAnalyticsFixtureSHA);
  assert(originalAnalyticsSessionFixture(corrected).equals(raw));
  for (const text of ['overview["active_visitors"] != 1', 'overview["sessions"] != 2', 'overview["pv"] != 2', 'session.Last != oldAt', 'session.Last != currentAt', 'inp["samples"] != 2', 'inp["p75"] != float64(120)']) assert(corrected.includes(text), text);
  assert.equal(analyticsFixturePlan.insert.split('time.Date(').length - 1, 7);
  assert(analyticsFixturePlan.insert.includes('time.Now()'));
});
test('explicit journey window and independent current-day window are both asserted across UTC and local zones', () => {
  const text = correctAnalyticsSessionFixture(raw).toString();
  assert(text.includes('now.Add(-2*time.Hour).Format(time.RFC3339)'));
  assert(text.includes('day, err := a.Store.analyticsReport(context.Background(), config.SiteID, "", "", now)'));
  for (const value of ['0, 0, 0, 0, time.UTC', '0, 30, 0, 0, time.UTC', '0, 59, 59, 0, time.UTC', '1, 0, 0, 0, time.UTC', '12, 0, 0, 0, time.UTC', 'time.FixedZone("east", 8*60*60)', 'time.FixedZone("west", -7*60*60)', 'dayOverview["sessions"] != expectedPV', 'dayOverview["active_visitors"] != expectedActive']) assert(text.includes(value), value);
});
test('changed assertions, production bytes and unreviewed corrected fixtures are refused', () => {
  for (const bytes of [Buffer.concat([raw, Buffer.from('\n// altered')]), Buffer.from(raw.toString().replace('overview["pv"] != 2', 'false')), fs.readFileSync(source + '/internal/core/analytics.go')]) assert.throws(() => correctAnalyticsSessionFixture(bytes));
  assert.throws(() => originalAnalyticsSessionFixture(Buffer.concat([correctAnalyticsSessionFixture(raw), Buffer.from('\n')])));
});
test('all original indexed scopes keep the genuine immutable fixture; no source export is overwritten', () => {
  let available = 0, alreadyCorrected = 0, absent = 0;
  for (const [scope, expected] of Object.entries(reviewedHTTPSFixtureScopes)) {
    const indexRaw = fs.readFileSync(repo + scope + '/source-sha256.json');
    assert.equal(sha(indexRaw), expected.index_sha256);
    const index = JSON.parse(indexRaw);
    if (Object.hasOwn(index.files, analyticsFixtureMember)) {
      if (index.files[analyticsFixtureMember] === originalAnalyticsFixtureSHA) available++;
      else { assert.equal(index.files[analyticsFixtureMember], alreadyCorrectedAnalyticsFixtureSHA); alreadyCorrected++; }
      assert.equal(sha(fs.readFileSync(repo + scope + '/' + analyticsFixtureMember)), index.files[analyticsFixtureMember]);
    } else absent++;
  }
  assert.deepEqual({ available, alreadyCorrected, absent }, { available: 2, alreadyCorrected: 37, absent: 17 });
});
test('genuine later fixed scopes and pre-feature scopes need no extra overlay', t => {
  for (const scope of ['panel-integration-memcached-retirement-handler', 'panel-integration']) {
    const dir = temporary(t), root = repo + scope, index = JSON.parse(fs.readFileSync(root + '/source-sha256.json'));
    assert.equal(reviewedAnalyticsReplacement(root, dir, index), null);
    assert.deepEqual(fs.readdirSync(dir), []);
  }
});
test('private replacement is exclusive, indexed and does not modify the original member', t => {
  const dir = temporary(t), index = JSON.parse(fs.readFileSync(source + '/source-sha256.json'));
  const result = reviewedAnalyticsReplacement(source, dir, index);
  assert.equal(result.target, source + '/' + analyticsFixtureMember);
  assert.equal(sha(fs.readFileSync(result.replacement)), correctedAnalyticsFixtureSHA);
  assert.equal(fs.lstatSync(result.replacement).mode & 511, 384);
  assert.equal(sha(fs.readFileSync(result.target)), originalAnalyticsFixtureSHA);
  assert.throws(() => reviewedAnalyticsReplacement(source, dir, index));
  assert.equal(sha(fs.readFileSync(result.replacement)), correctedAnalyticsFixtureSHA);
});
test('index drift, unsafe output directories, links and foreign roots fail before an output write', t => {
  const index = JSON.parse(fs.readFileSync(source + '/source-sha256.json'));
  const dir = temporary(t), changed = structuredClone(index);
  changed.files[analyticsFixtureMember] = '0'.repeat(64);
  assert.throws(() => reviewedAnalyticsReplacement(source, dir, changed));
  assert.deepEqual(fs.readdirSync(dir), []);
  fs.chmodSync(dir, 0o755);
  assert.throws(() => reviewedAnalyticsReplacement(source, dir, index));
  fs.chmodSync(dir, 0o700);
  const linked = dir + '/linked'; fs.symlinkSync(dir, linked);
  assert.throws(() => reviewedAnalyticsReplacement(source, linked, index));
  assert.throws(() => reviewedAnalyticsReplacement(dir, dir, index));
});
test('CI preserves the entire original workflow, full Go arguments and every other runner byte', () => {
  assert.equal(sha(fs.readFileSync(repo + '.github/workflows/verify.yml')), '3682cf6cbb573d1ca20d2373265fc2b12b6982af9449aac828827c354b7e09a3');
  let driver = fs.readFileSync(repo + 'tools/run-https-fixture-ci.mjs', 'utf8');
  const addedImport = "import{reviewedAnalyticsReplacement}from'./analytics-report-fixture-ci.mjs';\n";
  assert.equal(driver.split(addedImport).length, 2); driver = driver.replace(addedImport, '');
  const added = [
    "  const extra=reviewedHTTPSReplacement(source,dir),overlay=dir+'/overlay.json';",
    "  const analytics=reviewedAnalyticsReplacement(source,dir,index),Replace={[extra.target]:extra.replacement};if(analytics)Replace[analytics.target]=analytics.replacement;",
    "  fs.writeFileSync(overlay,JSON.stringify({Replace}),{flag:'wx',mode:0o600});",
    "  if(analytics)console.log(JSON.stringify({scope:path.basename(source),CI_test_fixture_only:'internal/core/analytics_session_test.go',...analytics,production_source_overrides:0,immutable_exports_changed:false,original_assertions_byte_exact:true,all50_commercial:false}));",
  ].join('\n');
  const original = "  const extra=reviewedHTTPSReplacement(source,dir),overlay=dir+'/overlay.json';fs.writeFileSync(overlay,JSON.stringify({Replace:{[extra.target]:extra.replacement}}),{flag:'wx',mode:0o600});";
  assert.equal(driver.split(added).length, 2); driver = driver.replace(added, () => original);
  assert.equal(sha(driver), '001e9cf0bc075ecc215b49f6ac72d001bc87da018c65c82dfff3517551f27a30');
});
