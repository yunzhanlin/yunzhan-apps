type Row = Record<string, unknown>;
const projectID = /^[a-z][a-z0-9-]{2,31}$/;
const sha256 = /^[a-f0-9]{64}$/;
const row = (value: unknown): value is Row => !!value && typeof value === 'object' && !Array.isArray(value);
const integer = (value: unknown, min: number, max: number): value is number => Number.isInteger(value) && Number(value) >= min && Number(value) <= max;

export function pm2ProjectsReadKnown(value: unknown): value is Row {
  if (!row(value) || value.projects_readonly !== true || value.configuration_not_inspected !== true || value.configuration_or_deployment_replayed !== false || value.history_or_report_written !== false || typeof value.project_page_complete !== 'boolean' || !integer(value.total, 0, 512) || !integer(value.limit, 1, 64) || !integer(value.offset, 0, value.total) || !Array.isArray(value.apps) || !Array.isArray(value.unreadable_projects)) return false;
  if (value.apps.length + value.unreadable_projects.length !== Math.min(value.limit, value.total - value.offset)) return false;
  const seen = new Set<string>();
  let complete = value.unreadable_projects.length === 0;
  for (const entry of value.apps) {
    if (!row(entry) || !row(entry.app) || typeof entry.app.id !== 'string' || !projectID.test(entry.app.id) || seen.has(entry.app.id) || typeof entry.original_project_sha256 !== 'string' || !sha256.test(entry.original_project_sha256) || typeof entry.app.site_id !== 'string' || !/^[a-f0-9]{32}$/.test(entry.app.site_id) || !integer(entry.app.revision, 0, Number.MAX_SAFE_INTEGER) || entry.app.environment_cipher !== undefined || typeof entry.state_known !== 'boolean') return false;
    seen.add(entry.app.id);
    if (entry.state_known) {
      if (!['active', 'inactive', 'failed'].includes(String(entry.state)) || typeof entry.boot_enabled !== 'boolean') return false;
    } else {
      complete = false;
      if (entry.state !== 'unknown' || entry.boot_enabled !== null || typeof entry.error !== 'string' || !entry.error) return false;
    }
  }
  for (const entry of value.unreadable_projects) {
    if (!row(entry) || typeof entry.resource_id !== 'string' || !projectID.test(entry.resource_id) || seen.has(entry.resource_id) || entry.state !== 'unknown' || typeof entry.error !== 'string' || !entry.error) return false;
    seen.add(entry.resource_id);
  }
  return value.project_page_complete === complete;
}

export function pm2StopReplyMatches(id: unknown, value: unknown): value is Row {
  return typeof id === 'string' && projectID.test(id) && row(value) && value.id === id && value.action === 'stop' && value.ok === true && value.state === 'inactive' && value.boot_enabled === false && value.service_outcome_verified === true && value.configuration_preserved === true && value.configuration_or_deployment_replayed === false && typeof value.original_project_sha256 === 'string' && sha256.test(value.original_project_sha256) && typeof value.history_persisted === 'boolean' && typeof value.last_report_persisted === 'boolean' && (value.history_persisted && value.last_report_persisted || typeof value.persistence_warning === 'string' && value.persistence_warning.length > 0);
}
