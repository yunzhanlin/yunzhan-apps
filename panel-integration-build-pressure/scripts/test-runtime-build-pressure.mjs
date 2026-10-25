import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';

// Contract/model checks only. Actual kernel allocation and PHP installation
// require independent native evidence. No caller-controlled memory budget.
const source = fs.readFileSync(new URL('../dev/panel-install@.service', import.meta.url), 'utf8');
const expected = {
  Unit: { Description: 'Panel verified runtime installer %i', After: 'network-online.target', Wants: 'network-online.target' },
  Service: {
    Slice: 'system.slice', Type: 'oneshot', ExecStart: '/opt/panel/bin/panel-executor --install-job %i', TimeoutStartSec: '300min',
    KillMode: 'control-group', NoNewPrivileges: 'true', ProtectControlGroups: 'true', TasksMax: '512', MemoryAccounting: 'true',
    MemoryHigh: '768M', MemoryMax: '768M', MemorySwapMax: '0', OOMPolicy: 'stop', OOMScoreAdjust: '500',
    Environment: 'GOMEMLIMIT=128MiB', UMask: '0022', PrivateTmp: 'true', ProtectHome: 'true', ProtectSystem: 'strict',
    ReadWritePaths: '/var/lib/panel-executor /var/cache/panel-runtime-build /opt/panel/runtimes /opt/panel/php-extensions',
    RestrictAddressFamilies: 'AF_UNIX AF_INET AF_INET6',
  },
};
function decode(text) {
  assert.equal(typeof text, 'string'); assert(text.length > 0 && text.length <= 8192 && !/[\r\0]/u.test(text));
  const result = {}; let section;
  for (const raw of text.split('\n')) {
    const line = raw.trim(); if (!line || line.startsWith('#')) continue;
    if (line.startsWith('[')) { assert(/^\[(Unit|Service)\]$/u.test(line)); section = line.slice(1, -1); assert(!result[section]); result[section] = {}; continue; }
    assert(section); const index = line.indexOf('='); assert(index > 0);
    const key = line.slice(0, index), value = line.slice(index + 1); assert(!Object.hasOwn(result[section], key));
    result[section][key] = value;
  }
  return result;
}
function check(text) { assert.deepEqual(decode(text), expected); }

test('runtime build avoids premature high-limit reclaim within the original finite hard ceiling', () => {
  check(source);
  const observed = 681811968; // actual retained Main compiler-pressure diagnostic
  assert(observed > 640 * 1024 ** 2 && observed < 768 * 1024 ** 2);
  assert.equal(decode(source).Service.MemoryHigh, decode(source).Service.MemoryMax);
});
test('all original hard resource, sandbox, command and writable-path boundaries remain closed', () => {
  for (const [key, bad] of [
    ['MemoryHigh', '640M'], ['MemoryHigh', 'infinity'], ['MemoryMax', '1G'], ['MemoryMax', 'infinity'],
    ['MemorySwapMax', '1G'], ['TasksMax', 'infinity'], ['TimeoutStartSec', 'infinity'], ['KillMode', 'process'],
    ['NoNewPrivileges', 'false'], ['ProtectControlGroups', 'false'], ['PrivateTmp', 'false'], ['ProtectHome', 'false'],
    ['ProtectSystem', 'false'], ['ReadWritePaths', '/'], ['RestrictAddressFamilies', 'AF_UNIX AF_INET AF_INET6 AF_PACKET'],
    ['ExecStart', '/bin/sh -c caller-command'], ['Environment', 'GOMEMLIMIT=2GiB'],
  ]) assert.throws(() => check(source.replace(new RegExp('^' + key + '=.*$', 'mu'), key + '=' + bad)), key + '=' + bad);
});
test('duplicate sections, duplicate settings and unknown fields cannot mask the policy', () => {
  for (const addition of ['\n[Service]\nMemoryMax=1G\n', '\nMemoryMax=768M\n', '\nDelegate=true\n', '\nStartupMemoryHigh=infinity\n'])
    assert.throws(() => check(source + addition));
  assert.throws(() => decode(source.replace('[Service]', '[Unknown]')));
});
test('the fixed original snapshot builder must run this contract before publishing', () => {
  const build = fs.readFileSync(new URL('../packaging/build-release.sh', import.meta.url), 'utf8');
  assert(build.includes('node --test scripts/test-runtime-build-pressure.mjs'));
  assert(build.includes('MemorySwapMax') === false); // policy stays in the signed unit, not ad-hoc build edits
});
