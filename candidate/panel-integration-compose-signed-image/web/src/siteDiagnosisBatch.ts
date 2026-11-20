import {siteDiagnosisCheckLabels} from './siteDiagnosisReport.ts';

export type DiagnosisState = 'failed' | 'warning' | 'passed' | 'unknown';
export type DiagnosisSite = {
  id: string;
  domain: string;
  report?: Record<string, unknown>;
  state: DiagnosisState;
  http?: number;
  responseMs?: number;
  issues: string[];
};
const order: DiagnosisState[] = ['failed', 'unknown', 'warning', 'passed'];
const object = (x: unknown): x is Record<string, unknown> => !!x && typeof x === 'object' && !Array.isArray(x);
const siteID = /^[0-9a-f]{32}$/;
function validDomain(s: string): boolean {
  return s.length <= 253 && s.includes('.') && !/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(s)
    && s.split('.').every(label => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label));
}
const num = (n: unknown, lo: number, hi: number): n is number => typeof n === 'number' && Number.isSafeInteger(n) && n >= lo && n <= hi;

export function siteDiagnosisBatch(value: unknown): DiagnosisSite[] | undefined {
  if (!object(value) || !Array.isArray(value.diagnoses) || !num(value.site_count, 1, 4) || value.diagnoses.length !== value.site_count) return;
  const seen = new Set<string>();
  const rows: Array<DiagnosisSite & { failures: number; warnings: number; httpFailed: boolean }> = [];
  for (const row of value.diagnoses) {
    if (!object(row) || typeof row.site_id !== 'string' || !siteID.test(row.site_id) || seen.has(row.site_id)) return;
    const id = row.site_id;
    seen.add(id);
    const unknown = {id, domain: id, state: 'unknown' as const, issues: [], failures: 0, warnings: 0, httpFailed: false};
    const report = row.report;
    if (!object(report) || row.error !== undefined || report.site_id !== id || typeof report.domain !== 'string' || !validDomain(report.domain)
      || typeof report.path !== 'string' || !report.path.startsWith('/') || report.path.length > 512
      || !object(report.checks) || !Array.isArray(report.check_order)) {
      rows.push(unknown);
      continue;
    }
    const keys = report.check_order;
    const fixed = ['binding','http','dns','tls_certificate','nginx','files'];
    const extra = ['apache_config','apache_listener'];
    const expected = keys.length === fixed.length ? fixed : [...fixed,...extra];
    if (keys.length !== expected.length || new Set(keys).size !== keys.length
      || !expected.every(key => keys.includes(key)) || Object.keys(report.checks).length !== keys.length
      || report.total_checks !== keys.length) {
      rows.push({...unknown, domain: report.domain});
      continue;
    }
    const checks = report.checks;
    const problems: string[] = [];
    let failures = 0, warnings = 0, passed = 0, malformed = false;
    for (const key of keys) {
      const check = checks[key];
      if (!object(check) || (check.verdict !== 'fail' && check.verdict !== 'warn' && check.verdict !== 'pass')) {
        malformed = true;
        break;
      }
      if (check.verdict === 'pass') passed++;
      else {
        if (check.verdict === 'fail') failures++; else warnings++;
        problems.push(siteDiagnosisCheckLabels[key]);
      }
    }
    if (malformed || report.passed_checks !== passed || report.score !== Math.floor(passed * 100 / keys.length)) {
      rows.push({...unknown, domain: report.domain});
      continue;
    }
    const http = checks.http as Record<string, unknown>;
    rows.push({id, domain: report.domain, report, state: failures ? 'failed' : warnings ? 'warning' : 'passed', issues: problems,
      failures, warnings, httpFailed: http.verdict === 'fail',
      http: num(http.status, 100, 599) ? http.status : undefined,
      responseMs: num(http.response_ms, 0, 120000) ? http.response_ms : undefined});
  }
  return rows.sort((a,b) => order.indexOf(a.state) - order.indexOf(b.state)
    || Number(b.httpFailed) - Number(a.httpFailed)
    || b.failures - a.failures || b.warnings - a.warnings)
    .map(({failures, warnings, httpFailed, ...row}) => row);
}
