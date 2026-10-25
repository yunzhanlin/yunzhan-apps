// CI-only deterministic report-window fixtures; no production or frozen-source edits.
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';

const repo = fileURLToPath(new URL('../', import.meta.url));
const sha = value => createHash('sha256').update(value).digest('hex');
export const analyticsFixtureMember = 'internal/core/analytics_session_test.go';
export const originalAnalyticsFixtureSHA = '978c7595a34aed1b9df40f3fee5c97265e96dcebb9edef309b6069dddd501707';
export const correctedAnalyticsFixtureSHA = '1b73f895be87608a170b9ca1f8adb9502357883d5d49a75f9fc242951f9f2b3b';
export const alreadyCorrectedAnalyticsFixtureSHA = 'd673322ad44c9b22b9f4f6c838329758e35e103da0b1d5d81ae6be4f56ac65f7';
export const analyticsFixturePlan = {
  "insert": "\tfor _, now := range []time.Time{\n\t\ttime.Now(),\n\t\ttime.Date(2026, 10, 25, 0, 0, 0, 0, time.UTC),\n\t\ttime.Date(2026, 10, 25, 0, 30, 0, 0, time.UTC),\n\t\ttime.Date(2026, 10, 25, 0, 59, 59, 0, time.UTC),\n\t\ttime.Date(2026, 10, 25, 1, 0, 0, 0, time.UTC),\n\t\ttime.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC),\n\t\ttime.Date(2026, 10, 25, 8, 30, 0, 0, time.FixedZone(\"east\", 8*60*60)),\n\t\ttime.Date(2026, 10, 24, 17, 30, 0, 0, time.FixedZone(\"west\", -7*60*60)),\n\t} {\n\t\tt.Run(now.Format(time.RFC3339), func(t *testing.T) {",
  "closing": "\n\t\t// Preserve the independent current-day default; the journey fixture asks\n\t\t// for its own explicit two-hour window rather than changing production.\n\t\tday, err := a.Store.analyticsReport(context.Background(), config.SiteID, \"\", \"\", now)\n\t\tif err != nil { t.Fatal(err) }\n\t\tstart := now.UTC().Truncate(24*time.Hour).Unix()\n\t\texpectedPV, expectedActive := 0, 0\n\t\tif oldAt >= start { expectedPV++ }\n\t\tif currentAt >= start { expectedPV++; expectedActive = 1 }\n\t\tdayOverview := day[\"overview\"].(map[string]any)\n\t\tif dayOverview[\"pv\"] != expectedPV || dayOverview[\"sessions\"] != expectedPV || dayOverview[\"active_visitors\"] != expectedActive {\n\t\t\tt.Fatal(\"current-day default changed or passive performance became activity\", dayOverview, expectedPV, expectedActive)\n\t\t}\n\t\t})\n\t}\n}\n\nfunc TestAnalyticsSessionPatch",
  "oldNow": "\tnow := time.Now()",
  "oldCall": "a.Store.analyticsReport(context.Background(), config.SiteID, \"\", \"\", now)",
  "newCall": "a.Store.analyticsReport(context.Background(), config.SiteID, now.Add(-2*time.Hour).Format(time.RFC3339), \"\", now)",
  "oldClose": "\n}\n\nfunc TestAnalyticsSessionPatch",
  "oldSetup": "\ta, _, config := analyticsFixture(t, true)\n",
  "newSetup": "\t\t\ta, _, config := analyticsFixture(t, true)\n"
};

export function correctAnalyticsSessionFixture(raw) {
  assert(Buffer.isBuffer(raw));
  assert.equal(sha(raw), originalAnalyticsFixtureSHA, 'Only the original indexed test fixture may change');
  const p = analyticsFixturePlan;
  let text = raw.toString();
  for (const [from, to] of [
    [p.oldSetup, ''],
    [p.oldNow, p.insert + p.newSetup],
    [p.oldCall, p.newCall],
    [p.oldClose, p.closing],
  ]) {
    assert.equal(text.split(from).length, 2, 'Every replacement must be unique');
    text = text.replace(from, () => to);
  }
  assert.equal(sha(text), correctedAnalyticsFixtureSHA);
  return Buffer.from(text);
}

export function originalAnalyticsSessionFixture(raw) {
  assert.equal(sha(raw), correctedAnalyticsFixtureSHA, 'Unknown replacement cannot restore original assertions');
  const p = analyticsFixturePlan;
  let text = raw.toString();
  for (const [from, to] of [
    [p.closing, p.oldClose],
    [p.newCall, p.oldCall],
    [p.insert + p.newSetup, p.oldSetup + p.oldNow],
  ]) {
    assert.equal(text.split(from).length, 2);
    text = text.replace(from, () => to);
  }
  assert.equal(sha(text), originalAnalyticsFixtureSHA, 'Every original assertion byte must remain');
  return Buffer.from(text);
}

// The caller first validates the complete immutable scope with sourceIndex().
// This function additionally binds the only permitted member and output identity.
export function reviewedAnalyticsReplacement(source, dir, index) {
  assert(path.isAbsolute(source) && fs.realpathSync(source) === source && path.dirname(source) + path.sep === repo);
  const root = fs.lstatSync(dir);
  assert(path.isAbsolute(dir) && fs.realpathSync(dir) === dir && root.isDirectory() && !root.isSymbolicLink() && root.uid === process.getuid() && (root.mode & 511) === 448);
  assert.deepEqual(JSON.parse(fs.readFileSync(source + '/source-sha256.json')), index);
  if (!Object.hasOwn(index.files, analyticsFixtureMember)) return null;
  assert(!Object.hasOwn(index.test_overrides ?? {}, analyticsFixtureMember));
  const target = source + '/' + analyticsFixtureMember, stat = fs.lstatSync(target);
  assert(stat.isFile() && !stat.isSymbolicLink() && stat.nlink === 1 && fs.realpathSync(target) === target);
  const raw = fs.readFileSync(target);
  assert.equal(sha(raw), index.files[analyticsFixtureMember]);
  if (index.files[analyticsFixtureMember] === alreadyCorrectedAnalyticsFixtureSHA) return null;
  assert.equal(index.files[analyticsFixtureMember], originalAnalyticsFixtureSHA);
  assert.equal(sha(raw), originalAnalyticsFixtureSHA);
  const replacement = dir + '/reviewed-analytics-session-fixture_test.go';
  const corrected = correctAnalyticsSessionFixture(raw);
  fs.writeFileSync(replacement, corrected, { flag: 'wx', mode: 0o600 });
  return { target, replacement, original_sha256: sha(raw), corrected_sha256: sha(corrected), original_assertions_byte_exact: true, deterministic_clocks: 8 };
}
