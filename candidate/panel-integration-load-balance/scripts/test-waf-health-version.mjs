import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

const source = fs.readFileSync(new URL('../web/src/WafWorkspace.vue', import.meta.url), 'utf8');
const names = ['ccObservationSupported', 'bodyRotationSupported', 'bodyRetentionSupported'];
const expressions = names.map(name => {
  const line = source.split('\n').find(value => value.startsWith('const ' + name + ' = computed('));
  assert(line, name);
  return line;
}).join('\n') + '\nresult = [' + names.join(',') + '];';
function supported(version, installed = true, apache = false) {
  const context = { apache, status: { value: { installed, version } }, computed: fn => fn(), result: null };
  vm.runInNewContext(expressions, context, { timeout: 100 });
  return Array.from(context.result);
}
test('actual WAF UI retains all three existing capability controls on the exact health hotfix version', () => {
  for (const version of ['2.5.0', '2.5.1', '2.5.2', '2.6.0']) assert.deepEqual(supported(version), [true, true, true]);
  assert.deepEqual(supported('2.4.0'), [true, true, false]);
  assert.deepEqual(supported('2.3.0'), [true, false, false]);
  for (const version of ['', '2.5.2-preview', '2.5.3', '2.6.0-preview', '2.6.1', 'future']) assert.deepEqual(supported(version), [false, false, false]);
  assert.deepEqual(supported('2.5.2', false), [false, false, false]);
  assert.deepEqual(supported('2.5.2', true, true), [false, false, false]);
});
