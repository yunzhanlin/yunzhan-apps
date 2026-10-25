// Exact already-frozen current source, never a historical or runtime overlay.
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const repo = fileURLToPath(new URL('../', import.meta.url));
const sha = value => createHash('sha256').update(value).digest('hex');
export const phpPublisherCIScope = Object.freeze({
  name: 'panel-integration-php-publisher',
  inputs: 'dba4ca826b5c2d37cb4c348a9f20a51f1093b2f4b59223ce31366ddd453abd70',
  indexSHA: '286b57d0a6c181ab4010fe97966d46ad52db532cd0f99e265914a7873080c49e',
  files: 1940,
  Go: 1475,
});
export function verifyPHPPublisherCISource(source) {
  const bound = phpPublisherCIScope;
  assert.equal(source, repo + bound.name); assert.equal(fs.realpathSync(source), source);
  const raw = fs.readFileSync(source + '/source-sha256.json'); assert.equal(sha(raw), bound.indexSHA);
  const index = JSON.parse(raw); assert.equal(index.release.frozen_inputs_sha256, bound.inputs); assert.deepEqual(index.test_overrides, {});
  assert.equal(Object.keys(index.files).length, bound.files); assert.equal(Object.keys(index.files).filter(n => n.endsWith('.go')).length, bound.Go);
  for (const [name, expected] of Object.entries(index.files)) {
    assert.equal(path.posix.normalize(name), name); assert(!path.isAbsolute(name) && !name.split('/').some(p => ['..', '.git', '.local', 'node_modules'].includes(p)));
    const file = source + '/' + name, st = fs.lstatSync(file);
    assert(st.isFile() && !st.isSymbolicLink() && st.nlink === 1 && st.size <= 2 << 20 && fs.realpathSync(file) === file);
    assert.equal(sha(fs.readFileSync(file)), expected, name);
  }
  assert.equal(index.files['internal/executor/site_tls_test.go'], 'ff2b7793efc28dd290d77ec635b16eba0c686c93f1f68a6e9ced1b9a255dc89a');
  assert.equal(index.files['internal/executor/app_load_balance_https_linux_test.go'], '026dce1a592366561eecba2ba4e7eb1c16828285f226c3fd9140e79be8e98ff3');
  assert.equal(index.files['internal/core/analytics_session_test.go'], 'd673322ad44c9b22b9f4f6c838329758e35e103da0b1d5d81ae6be4f56ac65f7');
  return index;
}
export function phpPublisherCIArguments(args) { assert.deepEqual(args, ['test', '-p', '1', './...', '-count=1']); return args; }
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  assert(process.getuid() === 0 && process.platform === 'linux' && process.env.GITHUB_ACTIONS === 'true' && process.env.GITHUB_REPOSITORY === 'yunzhanlin/yunzhan-apps');
  const go = process.argv[2], args = phpPublisherCIArguments(process.argv.slice(3)); assert(path.isAbsolute(go) && fs.realpathSync(go) === go);
  const source = fs.realpathSync(process.cwd()); verifyPHPPublisherCISource(source);
  console.log(JSON.stringify({ source_inputs: phpPublisherCIScope.inputs, original_full_arguments: args, source_or_test_overrides: 0, installed_application_acceptance: false }));
  const out = spawnSync(go, args, { cwd: source, stdio: 'inherit' }); verifyPHPPublisherCISource(source);
  assert(!out.error && !out.signal); assert.equal(out.status, 0);
}
