// Closed source-contract regression. Ordinary Go tests exercise the policy.
import fs from 'node:fs';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { test } from 'node:test';
import { beforeLoadBalanceStreamBuild } from './release-build-baseline.mjs';
const sha = b => createHash('sha256').update(b).digest('hex');
const read = n => fs.readFileSync(new URL('../' + n, import.meta.url), 'utf8');
const install = read('internal/executor/install_linux.go');
const linux = read('internal/executor/runtime_php_memory_admission_linux.go');
const model = read('internal/executor/runtime_php_memory_admission.go');
const wait = read('internal/executor/runtime_php_memory_wait.go');

test('builder changes only the command-boundary admission; initial admission remains immediate', () => {
  assert.equal(install.split('waitRuntimePHPWorkerMemory(ctx, release)').length - 1, 1);
  assert.equal(sha(install.replace('waitRuntimePHPWorkerMemory(ctx, release)', 'admitRuntimePHPWorkerMemory(release)')), '103a96d8e164515ffb8c950ca12ce54048c3ac422cf666bd1a5655fd4ce50f51');
  assert(install.indexOf('waitRuntimePHPWorkerMemory(ctx, release)') < install.indexOf('scope, err := beginRuntimeCompilerScope()'));
  assert.equal((install.match(/admitRuntimePHPWorkerMemory\(r\)/g) || []).length, 1);
});

test('memory parser and original thresholds are byte-identical after reviewed shortage typing', () => {
  const original = model
    .replace(/\/\/ Only this exact internal error[\s\S]*?(?=\/\/ A closed release decision)/, '')
    .replace(/return &runtimePHPCompilerMemoryShortage\{fmt\.Sprintf\(([^\n]+)\)\}/, 'return fmt.Errorf($1)')
    .replace(/return &runtimePHPCompilerMemoryShortage\{("PHP 编译所在[^\n]+")\}/, 'return errors.New($1)');
  assert.equal(sha(original), 'e6688c8d2dbee29c2c35fb63c53a048fb7d7d922cd73bc9aed1c995d6a8a69ce');
});

test('all actual kernel, parent and host probes remain exact; no cache or controller writes', () => {
  const wrapper = /\/\/ Source command boundaries[\s\S]*?(?=func admitRuntimePHPCompilerKernelMemory)/.exec(linux);
  assert(wrapper);
  const original = linux.replace('\t"context"\n', '').replace('\t"time"\n', '').replace(wrapper[0], '');
  assert.equal(sha(original), 'a00da78658781c122ab7e8160da2b38949267f5ec8e7fd2eaee6e11dfd86311e');
  assert(wrapper[0].includes('return admitRuntimePHPWorkerMemory(r)'));
  assert(!/exec\.|WriteFile|Fadvise|Fsync|memory\.reclaim|drop_caches/.test(wrapper[0]));
});

test('finite wait inherits the original deadline and admits only an exact internal capacity error', () => {
  assert(wait.includes('context.WithTimeout(ctx, runtimePHPCompilerMemoryWait)'));
  assert(wait.includes('runtimePHPCompilerMemoryWait = 90 * time.Second'));
  assert(wait.includes('runtimePHPCompilerMemoryPoll = 2 * time.Second'));
  assert(wait.includes('runtimePHPCompilerMemoryRetries = 45'));
  assert(wait.includes('err.(*runtimePHPCompilerMemoryShortage)'));
  assert(!/context\.Background|exec\.|os\.|syscall\.|runtimeBuildCache/.test(wait));
});

test('original300-minute1GiB zero-swap installer and four-hour build budget are retained', () => {
  assert.equal(sha(read('dev/panel-install@.service')), 'bf2432e1084dce9629be620dfab2ed47995c9bbfa86a70285990f4d6fb1cd947');
  assert(install.includes('return 4 * time.Hour'));
});

test('native case is explicit and labels synthetic pressure without claiming an app install', () => {
  const native = read('internal/executor/runtime_php_memory_wait_native_linux_test.go');
  assert(native.includes('PANEL_QA_RUNTIME_PHP_WAIT_NATIVE'));
  assert(native.includes('actual_host_pressure_not_injected'));
  assert(native.includes('compiler_or_command_or_runtime_publication'));
  assert(!/buildCommand\(|exec\.Command|os\.Remove|os\.Rename/.test(native));
});

test('ordinary build adds only this mandatory source-contract gate', () => {
  const line = '(cd "$BUILD_ROOT" && /opt/homebrew/bin/node --test scripts/test-runtime-memory-wait.mjs) 2>&1 | tee -a "$STAGE/$NAME/BUILD_CHECKS.txt"\n';
  assert.equal(read('packaging/build-release.sh').split(line).length, 2);
  assert.equal(sha(beforeLoadBalanceStreamBuild(read('packaging/build-release.sh')).replace(line, '')), '36fb70ab2a5ab8a9a8883dc05e08f6dc474a8ae6a67b2fc6139647cd5e79c481');
});

test('publisher source contract retains every original assertion around the one reviewed wait call', () => {
  const original = read('scripts/test-native-queue-unit-snapshot.mjs')
    .replace(" const current=read('internal/executor/install_linux.go'),leaf=read('internal/executor/runtime_php_publication_linux.go'),tick=String.fromCharCode(96);\n const waiting='waitRuntimePHPWorkerMemory(ctx, release)';\n assert.equal(current.split(waiting).length,2);\n const install=current.replace(waiting,'admitRuntimePHPWorkerMemory(release)');", " const install=read('internal/executor/install_linux.go'),leaf=read('internal/executor/runtime_php_publication_linux.go'),tick=String.fromCharCode(96);");
  // The queue wrapper has its own exact baseline contract. This test protects
  // every assertion in the independent PHP producer contract, not L4 additions.
  const begin = original.indexOf("test('producer changes"), end = original.indexOf("test('new observation");
  assert(begin > 0 && end > begin);
  assert.equal(sha(original.slice(begin, end)), '672a40e8fc410b42366868e56e69fe70ad3a4a9bed31da5c35000f79af1663f9');
});
