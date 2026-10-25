// Mandatory actual Linux Root filesystem/descriptor/lock models; no app install.
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { verifyPHPPublisherCISource, phpPublisherCIScope } from './run-php-publisher-ci.mjs';

export const phpPublisherNativeTests = Object.freeze([
  'TestRuntimePHPFPMVersionRequiresExactNativeSAPIAndToken',
  'TestRuntimePHPArtifactELFRequiresExact64BitArchitecture',
  'TestRuntimePHPArtifactMetadataRejectsPrivilegeBitsEvenWhenSandboxForbidsCreatingThem',
  'TestRuntimePHPPublisherTreeRejectsUnsealedOrChangedAuthorityWithoutRepair',
  'TestRuntimePHPPublisherHeldIdentityDetectsChangesAndProducerNeverAdopts',
  'TestRuntimeSupersededCompileOOMProofKeepsOldFailureAndIndependentLeases',
]);
export function phpPublisherNativeCIArguments() { return ['test', '-race', '-json', './internal/executor', '-run=^(' + phpPublisherNativeTests.join('|') + ')$', '-count=1']; }
export function verifyPHPPublisherNativeEvents(rows) {
  assert(rows.length > 0 && rows.at(-1).Action === 'pass' && rows.at(-1).Package === 'local/panel/internal/executor');
  assert(!rows.some(v => v.Action === 'skip' || v.Action === 'fail'));
  const passed = rows.filter(v => v.Action === 'pass' && v.Test);
  assert.equal(passed.length, 120); assert.deepEqual(passed.filter(v => !v.Test.includes('/')).map(v => v.Test).sort(), [...phpPublisherNativeTests].sort());
  return { top_level: 6, including_subtests: 120, failed: 0, skipped: 0 };
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  assert(process.argv.length === 3 && process.getuid() === 0 && process.platform === 'linux' && process.env.GITHUB_ACTIONS === 'true' && process.env.GITHUB_REPOSITORY === 'yunzhanlin/yunzhan-apps');
  const go = process.argv[2]; assert(path.isAbsolute(go) && fs.realpathSync(go) === go);
  const source = fs.realpathSync(process.cwd()); verifyPHPPublisherCISource(source);
  const out = spawnSync(go, phpPublisherNativeCIArguments(), { cwd: source, encoding: 'utf8', maxBuffer: 16 << 20 });
  process.stdout.write(out.stdout || ''); process.stderr.write(out.stderr || ''); verifyPHPPublisherCISource(source);
  assert(!out.error && !out.signal); assert.equal(out.status, 0);
  const rows = out.stdout.trim().split('\n').map(JSON.parse), counts = verifyPHPPublisherNativeEvents(rows);
  console.log(JSON.stringify({ ...counts, source_inputs: phpPublisherCIScope.inputs, actual_Root_Linux_race_models: true, installed_application_acceptance: false, all50_commercial: false }));
}
