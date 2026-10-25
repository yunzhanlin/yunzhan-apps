// Run the already-corrected frozen tests directly. No test or runtime overlay.
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const repo = fileURLToPath(new URL('../', import.meta.url));
const sha = value => createHash('sha256').update(value).digest('hex');
export const compilerMemoryCIScope = Object.freeze({
  name: 'panel-integration-compiler-memory',
  inputs: '1976023758cc006612e897538cad1af1b5d57332fa8a32a1d130fc546b223d15',
  indexSHA: '911b5d13f3e1e62ba4d040e5916baeb68624435b4cc71bef7dbff33f7b802ac4',
  files: 1934,
  Go: 1469,
});

export function verifyCompilerMemoryCISource(source) {
  const bound = compilerMemoryCIScope;
  assert.equal(source, repo + bound.name);
  assert.equal(fs.realpathSync(source), source);
  const raw = fs.readFileSync(source + '/source-sha256.json');
  assert.equal(sha(raw), bound.indexSHA);
  const index = JSON.parse(raw);
  assert.equal(index.release.frozen_inputs_sha256, bound.inputs);
  assert.deepEqual(index.test_overrides, {});
  assert.equal(Object.keys(index.files).length, bound.files);
  assert.equal(Object.keys(index.files).filter(name => name.endsWith('.go')).length, bound.Go);
  for (const [name, expected] of Object.entries(index.files)) {
    assert.equal(path.posix.normalize(name), name);
    assert(!path.isAbsolute(name) && !name.split('/').some(part => ['..', '.local', '.git', 'node_modules'].includes(part)));
    const file = source + '/' + name, stat = fs.lstatSync(file);
    assert(stat.isFile() && !stat.isSymbolicLink() && stat.nlink === 1 && stat.size <= 2 << 20);
    assert.equal(fs.realpathSync(file), file);
    assert.equal(sha(fs.readFileSync(file)), expected, name);
  }
  // These fixes are already actual frozen source, not the old CI-only inputs.
  assert.equal(index.files['internal/executor/app_load_balance_https_linux_test.go'], '026dce1a592366561eecba2ba4e7eb1c16828285f226c3fd9140e79be8e98ff3');
  assert.equal(index.files['internal/core/analytics_session_test.go'], 'd673322ad44c9b22b9f4f6c838329758e35e103da0b1d5d81ae6be4f56ac65f7');
  return index;
}

export function compilerMemoryCIArguments(args) {
  assert.deepEqual(args, ['test', '-p', '1', './...', '-count=1']);
  return args;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  assert(process.getuid() === 0 && process.platform === 'linux' && process.env.GITHUB_ACTIONS === 'true' && process.env.GITHUB_REPOSITORY === 'yunzhanlin/yunzhan-apps');
  const go = process.argv[2], args = compilerMemoryCIArguments(process.argv.slice(3));
  assert(path.isAbsolute(go) && fs.realpathSync(go) === go);
  const source = fs.realpathSync(process.cwd());
  verifyCompilerMemoryCISource(source);
  console.log(JSON.stringify({ source_inputs: compilerMemoryCIScope.inputs, original_full_arguments: args, source_or_test_overrides: 0, installed_application_acceptance: false }));
  const result = spawnSync(go, args, { cwd: source, stdio: 'inherit' });
  verifyCompilerMemoryCISource(source);
  assert(!result.error && !result.signal);
  assert.equal(result.status, 0);
}
