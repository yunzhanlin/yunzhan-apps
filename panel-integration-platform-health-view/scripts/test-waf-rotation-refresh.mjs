import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRotationRefresh } from '../web/src/wafRotationRefresh.ts';

function fixture() {
  const state = { status: { generation: 1, checked: 1 }, reads: 0, evidence: 0,
    applied: undefined, error: '', supported: true, fail: false, busy: false,
    draft: { enabled: false, rotate_mib: 3 } };
  const refresh = createRotationRefresh({
    supported: () => state.supported,
    readStatus: async () => { state.reads++; return { ...state.status }; },
    applyStatus: value => { state.applied = value; },
    fingerprint: value => String(value.generation),
    refreshEvidence: async () => {
      state.evidence++;
      if (state.fail) throw new Error('inventory temporarily locked');
      return !state.busy;
    },
    clearError: () => { state.error = ''; },
    onError: error => { state.error = error.message; },
  });
  return { state, refresh };
}

test('new rotation refreshes evidence; a check-clock tick does not rescan', async () => {
  const { state, refresh } = fixture();
  await refresh();
  state.status.checked++;
  await refresh();
  assert.equal(state.evidence, 1);
  state.status.generation++;
  await refresh();
  assert.equal(state.evidence, 2);
  assert.deepEqual(state.draft, { enabled: false, rotate_mib: 3 });
});

test('failed inventory is visible and retried on the same fingerprint', async () => {
  const { state, refresh } = fixture();
  state.fail = true;
  await refresh();
  assert.match(state.error, /temporarily locked/);
  assert.equal(state.applied.generation, 1);
  state.fail = false;
  await refresh();
  assert.equal(state.evidence, 2);
  assert.equal(state.error, '');
});

test('busy evidence is not accepted as refreshed', async () => {
  const { state, refresh } = fixture();
  state.busy = true;
  await refresh();
  state.busy = false;
  await refresh();
  assert.equal(state.evidence, 2);
});

test('overlapping polls share one request; disabled refresh is read-only no-op', async () => {
  const { state, refresh } = fixture();
  const first = refresh(), second = refresh();
  assert.equal(first, second);
  await Promise.all([first, second]);
  assert.equal(state.reads, 1);
  assert.equal(state.evidence, 1);
  state.supported = false;
  await refresh();
  assert.equal(state.reads, 1);
});
