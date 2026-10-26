// Exact cumulative frozen source. No filter, overlay, private input or deadline bypass.
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
const repo = fileURLToPath(new URL('../', import.meta.url));
const sha = b => createHash('sha256').update(b).digest('hex');
export const runtimeMemoryWaitCIScope = Object.freeze({
  name: 'panel-integration-runtime-memory-wait',
  inputs: 'd09edb15d2bcc2b098aabcb6f6ad5517aba4736309afe1cf9d630fb11dabe20a',
  indexSHA: 'b50fbb4c8d48b49aa962d26335e6045b28f8f5b4f4c2569b170bb6b3abfd5031',
  files: 1948,
  Go: 1478,
});
export function verifyRuntimeMemoryWaitCISource(source) {
  const bound = runtimeMemoryWaitCIScope;
  assert.equal(source, repo + bound.name); assert.equal(fs.realpathSync(source), source);
  const raw = fs.readFileSync(source + '/source-sha256.json'); assert.equal(sha(raw), bound.indexSHA);
  const index = JSON.parse(raw); assert.equal(index.release.frozen_inputs_sha256, bound.inputs); assert.deepEqual(index.test_overrides, {});
  assert.equal(Object.keys(index.files).length, bound.files); assert.equal(Object.keys(index.files).filter(n => n.endsWith('.go')).length, bound.Go);
  for (const [name, expected] of Object.entries(index.files)) {
    assert.equal(path.posix.normalize(name), name);
    assert(!path.isAbsolute(name) && !name.split('/').some(p => ['..', '.git', '.local', 'node_modules'].includes(p)));
    const file = source + '/' + name, st = fs.lstatSync(file);
    assert(st.isFile() && !st.isSymbolicLink() && st.nlink === 1 && st.size <= 2 << 20 && fs.realpathSync(file) === file);
    assert.equal(sha(fs.readFileSync(file)), expected, name);
  }
  assert.equal(index.files['dev/panel-install@.service'], 'bf2432e1084dce9629be620dfab2ed47995c9bbfa86a70285990f4d6fb1cd947');
  assert.equal(index.files['internal/executor/site_tls_test.go'], 'ff2b7793efc28dd290d77ec635b16eba0c686c93f1f68a6e9ced1b9a255dc89a');
  assert.equal(index.files['internal/executor/app_load_balance_https_linux_test.go'], '026dce1a592366561eecba2ba4e7eb1c16828285f226c3fd9140e79be8e98ff3');
  assert.equal(index.files['internal/core/analytics_session_test.go'], 'd673322ad44c9b22b9f4f6c838329758e35e103da0b1d5d81ae6be4f56ac65f7');
  return index;
}
export function runtimeMemoryWaitCIArguments(args) { assert.deepEqual(args, ['test', '-p', '1', './...', '-count=1']); return args; }
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  assert(process.getuid() === 0 && process.platform === 'linux' && process.env.GITHUB_ACTIONS === 'true' && process.env.GITHUB_REPOSITORY === 'yunzhanlin/yunzhan-apps');
  const go = process.argv[2], args = runtimeMemoryWaitCIArguments(process.argv.slice(3)); assert(path.isAbsolute(go) && fs.realpathSync(go) === go);
  const source = fs.realpathSync(process.cwd()); verifyRuntimeMemoryWaitCISource(source);
  console.log(JSON.stringify({ source_inputs: runtimeMemoryWaitCIScope.inputs, complete_arguments: args, source_overrides: 0, installed_acceptance: false }));
  const out = spawnSync(go, args, { cwd: source, stdio: 'inherit' }); verifyRuntimeMemoryWaitCISource(source);
  assert(!out.error && !out.signal); assert.equal(out.status, 0);
}
