export type FleetState = 'completed' | 'failed' | 'needs_attention' | 'not_dispatched';

export interface FleetOperation {
  request_id: string;
  command: 'nginx-check';
  expected_plan_sha256: string;
  confirm: '';
}

export interface FleetRecoveryRow {
  actor_id: string;
  operation: FleetOperation;
  endpoint_sha256: string;
  grant_sha256: string;
  state: FleetState;
}

const storageKey = (actor: string, installation: string) => 'panel-fleet-nginx-check-v1:' + actor + ':' + installation;
const validHex = (value: unknown, size: number): value is string =>
  typeof value === 'string' && value.length === size && /^[a-f0-9]+$/.test(value);

function validRow(input: unknown): input is FleetRecoveryRow {
  if (!input || typeof input !== 'object') return false;
  const row = input as FleetRecoveryRow;
  const operation = row.operation;
  return Object.keys(row).length === 5 && validHex(row.actor_id, 32) &&
    validHex(row.endpoint_sha256, 64) && validHex(row.grant_sha256, 64) &&
    ['completed', 'failed', 'needs_attention', 'not_dispatched'].includes(row.state) &&
    Boolean(operation && Object.keys(operation).length === 4 && validHex(operation.request_id, 32) &&
      operation.command === 'nginx-check' && validHex(operation.expected_plan_sha256, 64) && operation.confirm === '');
}

export function readFleetRecovery(storage: Pick<Storage, 'getItem'>, actor: string, installation: string): FleetRecoveryRow[] {
  if (!validHex(actor, 32) || !validHex(installation, 32)) throw Error('运行身份尚未核对');
  const raw = storage.getItem(storageKey(actor, installation));
  if (!raw) return [];
  if (raw.length > 8192) throw Error('原批次记录超过容量');
  const saved = JSON.parse(raw);
  if (!saved || Object.keys(saved).length !== 4 || saved.format !== 1 || saved.actor !== actor || saved.installation !== installation ||
      !Array.isArray(saved.rows) || saved.rows.length < 2 || saved.rows.length > 8 ||
      !saved.rows.every(validRow) || new Set(saved.rows.map((row: FleetRecoveryRow) => row.operation.request_id)).size !== saved.rows.length) {
    throw Error('原批次记录不可解析');
  }
  return saved.rows;
}

export function writeFleetRecovery(storage: Pick<Storage, 'setItem'>, actor: string, installation: string, rows: FleetRecoveryRow[]) {
  if (!validHex(actor, 32) || !validHex(installation, 32) || rows.length < 2 || rows.length > 8 ||
      !rows.every(validRow) || new Set(rows.map(row => row.operation.request_id)).size !== rows.length) {
    throw Error('无法保存原批次身份');
  }
  const records = rows.map(({ actor_id, operation, endpoint_sha256, grant_sha256, state }) => ({
    actor_id,
    operation: {
      request_id: operation.request_id, command: operation.command,
      expected_plan_sha256: operation.expected_plan_sha256, confirm: operation.confirm,
    },
    endpoint_sha256, grant_sha256, state,
  }));
  storage.setItem(storageKey(actor, installation), JSON.stringify({format: 1, actor, installation, rows: records}));
}

export function clearFleetRecovery(storage: Pick<Storage, 'removeItem'>, actor: string, installation: string) {
  if (!validHex(actor, 32) || !validHex(installation, 32)) throw Error('运行身份尚未核对');
  storage.removeItem(storageKey(actor, installation));
}
