const target = /^[a-z0-9][a-z0-9-]{2,63}$/;
const site = /^[a-f0-9]{32}$/;
const fileLimit = 8 * 1024 * 1024, scanLimit = 256 * 1024 * 1024;
const actions = ['create', 'update', 'unchanged', 'conflict'] as const;
type Action = typeof actions[number];
type Change = Exclude<Action, 'unchanged'>;
type Row = {path: string; action: Change; source_bytes: number; target_bytes?: number; reason?: 'untracked_target' | 'target_changed'};
type Identity = {remote_target_id: string; site_id: string; revision: number; excludes: string[]};
export type RemoteSyncPreview = Identity & {
  format: 1; counts: Record<Action, number>; source_files: number; source_bytes: number;
  transfer_bytes: number; rows: Row[]; rows_limited: boolean;
};
const count = (n: unknown, max: number): n is number => typeof n === 'number' && Number.isSafeInteger(n) && n >= 0 && n <= max;
const matches = (s: unknown, pattern: RegExp): s is string => typeof s === 'string' && pattern.test(s);
const object = (x: unknown): x is Record<string, unknown> => !!x && typeof x === 'object' && !Array.isArray(x);
const encoder = new TextEncoder();
function filePath(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && encoder.encode(value).length <= 1024
    && !/[\\\x00-\x1f\x7f]/.test(value)
    && value.split('/').every(part => part && part !== '.' && part !== '..' && !part.startsWith('.panel-'));
}
function identity(input: unknown, revision: unknown): Identity | undefined {
  if (!object(input) || !matches(input.remote_target_id, target) || !matches(input.site_id, site) || !count(revision, Number.MAX_SAFE_INTEGER) || !revision) return;
  let excluded = input.excludes ?? [];
  if (typeof excluded === 'string') {
    try { excluded = JSON.parse(excluded || '[]'); } catch { return; }
  }
  if (!Array.isArray(excluded) || excluded.length > 64 || !excluded.every(filePath)) return;
  return {remote_target_id: input.remote_target_id, site_id: input.site_id, revision, excludes: [...excluded].sort()};
}
export function remoteSyncPreview(value: unknown): RemoteSyncPreview | undefined {
  if (!object(value) || value.format !== 1 || !Array.isArray(value.excludes) || !object(value.counts)
    || !count(value.source_files, 10_000) || !count(value.source_bytes, scanLimit)
    || !count(value.transfer_bytes, value.source_bytes) || typeof value.rows_limited !== 'boolean'
    || !Array.isArray(value.rows) || value.rows.length > 128) return;
  const scope = identity(value, value.revision);
  if (!scope || Object.keys(value.counts).length !== actions.length) return;
  const counts = {} as Record<Action, number>;
  for (const action of actions) {
    const n = value.counts[action];
    if (!count(n, value.source_files)) return;
    counts[action] = n;
  }
  if (actions.reduce((n, action) => n + counts[action], 0) !== value.source_files) return;
  const seen = new Set<string>(), rows: Row[] = [];
  const displayed = {create: 0, update: 0, conflict: 0};
  let displayedTransfer = 0;
  for (const r of value.rows) {
    if (!object(r) || !filePath(r.path) || seen.has(r.path) || !count(r.source_bytes, fileLimit)
      || (r.action !== 'create' && r.action !== 'update' && r.action !== 'conflict')) return;
    const row: Row = {path: r.path, action: r.action, source_bytes: r.source_bytes};
    if (row.action === 'create') {
      if (r.target_bytes !== undefined) return;
    } else {
      if (!count(r.target_bytes, fileLimit)) return;
      row.target_bytes = r.target_bytes;
    }
    if (row.action === 'conflict') {
      if (r.reason !== 'untracked_target' && r.reason !== 'target_changed') return;
      row.reason = r.reason;
    } else {
      if (r.reason !== undefined) return;
      displayedTransfer += row.source_bytes;
    }
    if (++displayed[row.action] > counts[row.action]) return;
    seen.add(row.path);
    rows.push(row);
  }
  if (value.rows_limited !== (rows.length < counts.create + counts.update + counts.conflict)
    || displayedTransfer > value.transfer_bytes || !value.rows_limited && displayedTransfer !== value.transfer_bytes) return;
  return {...scope, format: 1, counts, source_files: value.source_files, source_bytes: value.source_bytes,
    transfer_bytes: value.transfer_bytes, rows, rows_limited: value.rows_limited};
}
export function remotePreviewMatches(preview: RemoteSyncPreview, input: unknown, revision: unknown): boolean {
  const scope = identity(input, revision);
  return !!scope && scope.site_id === preview.site_id && scope.remote_target_id === preview.remote_target_id
    && scope.revision === preview.revision && JSON.stringify(scope.excludes) === JSON.stringify(preview.excludes);
}
