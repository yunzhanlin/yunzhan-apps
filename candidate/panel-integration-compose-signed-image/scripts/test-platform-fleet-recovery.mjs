import { test } from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {clearFleetRecovery, readFleetRecovery, writeFleetRecovery} from '../web/src/platformFleetRecovery.ts';

const account = 'a'.repeat(32), installation = 'b'.repeat(32);
const rows = ['c', 'd'].map(id => ({
  actor_id: 'e'.repeat(32),
  operation: { request_id: id.repeat(32), command: 'nginx-check', expected_plan_sha256: 'c'.repeat(64), confirm: '' },
  endpoint_sha256: 'a'.repeat(64),
  grant_sha256: 'b'.repeat(64),
  state: 'needs_attention',
}));

function storage() {
  const data = new Map();
  return {
    data,
    getItem: key => data.get(key) || null,
    setItem: (key, value) => data.set(key, value),
    removeItem: key => data.delete(key),
  };
}

test('restored batch contains only the original request metadata and digests', () => {
  const memory = storage();
  assert.deepEqual(readFleetRecovery(memory, account, installation), []);
  writeFleetRecovery(memory, account, installation, rows);
  assert.deepEqual(readFleetRecovery(memory, account, installation), rows);
  const raw = [...memory.data.values()][0];
  assert(!raw.includes('https://') && !raw.includes('"token"') && !raw.includes('"url"'));
  assert.throws(() => writeFleetRecovery(memory, account, installation,
    [{...rows[0], token:'secret'}, rows[1]]), /无法保存原批次身份/);
  assert.throws(() => writeFleetRecovery(memory, account, installation,
    [{...rows[0], operation:{...rows[0].operation, command:'nginx-reload'}}, rows[1]]), /无法保存原批次身份/);
  assert.throws(() => writeFleetRecovery(memory, account, installation, [rows[0], rows[0]]), /无法保存原批次身份/);
});
test('accounts and app installations keep independent storage; corrupt records refuse recovery', () => {
  const memory = storage();
  const second = 'f'.repeat(32);
  writeFleetRecovery(memory, account, installation, rows);
  assert.deepEqual(readFleetRecovery(memory, second, installation), []);
  assert.deepEqual(readFleetRecovery(memory, account, second), []);
  writeFleetRecovery(memory, second, installation, rows);
  clearFleetRecovery(memory, second, installation);
  assert.deepEqual(readFleetRecovery(memory, account, installation), rows);
  assert.deepEqual(readFleetRecovery(memory, second, installation), []);
  const key = [...memory.data.keys()][0];
  memory.setItem(key, 'malformed');
  assert.throws(() => readFleetRecovery(memory, account, installation));
});
test('the component saves before dispatch and restored rows invoke only the fixed status endpoint', () => {
  const vue = readFileSync(new URL('../web/src/PlatformMaintenanceFleetCheck.vue', import.meta.url), 'utf8');
  const submit = vue.slice(vue.indexOf('async function submit()'), vue.indexOf('async function inspect('));
  const inspect = vue.slice(vue.indexOf('async function inspect('), vue.indexOf('</script>'));
  assert(submit.indexOf('writeFleetRecovery') > 0);
  assert(submit.indexOf('writeFleetRecovery') < submit.indexOf("base + '/fleet/checks'"));
  assert.match(inspect, /digest\(url\) !== recovery.endpoint_sha256/);
  assert.match(inspect, /digest\(token\) !== recovery.grant_sha256/);
  assert.match(inspect, /base \+ '\/commands\/status'/);
  assert.doesNotMatch(inspect, /\/fleet\/checks/);
});
