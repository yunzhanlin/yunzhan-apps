export function statisticsHistoryNotice(report: Record<string, unknown>): string | undefined {
 const positive = (value: unknown) => typeof value === 'number' && Number.isFinite(value) && value > 0;
 const issues: string[] = [];
 if (positive(report.history_deferred_compressed_sources)) issues.push('压缩归档校验超过本次时间预算，已延后重试；本次未提交该归档数据，不代表损坏或已读完');
 if (positive(report.history_unsupported_rotation_sources)) issues.push('存在当前模式不能核对的轮转命名，未静默忽略为完整历史');
 if (positive(report.history_compressed_sources)) {
  issues.push(report.history_gzip_import_enabled === true
   ? '压缩归档仍有待处理、超限或拒绝读取的来源；完整校验通过后才提交请求和进度'
   : '当前应用未启用压缩日志导入；压缩归档不计入，不能据此认定访问历史完整');
 }
 if (positive(report.history_blocked_sources)) issues.push('日志身份或进度存在冲突/缺失；不会从头重置');
 if (report.history_missing_log === true) issues.push('当前没有可核对的访问日志');
 if (positive(report.history_invalid_lines)) issues.push('存在无效行或无法核对请求标识的旧压缩行，未将其冒充已采集请求');
 return issues.length ? issues.join('。') + '。已有历史和原始日志保留，请核对轮转方式与查询范围。' : undefined;
}


export type StatisticsCoverage = {
 state: 'partial' | 'unknown' | 'empty' | 'matched';
 count: number | undefined;
 first: string;
 last: string;
 checkedAt: string;
 backlog: number | undefined;
 evicted: number | undefined;
 beforeRetention: boolean;
 worker: 'fresh' | 'stale' | 'unknown';
 workerCheckedAt: string;
};

const safeCount = (value: unknown): number | undefined =>
 typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 ? value : undefined;

function utcTimestamp(value: unknown): string | undefined {
 if (value === '') return '';
 if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(value)) return;
 const ms = Date.parse(value);
 if (Number.isFinite(ms) && new Date(ms).toISOString() === value.slice(0, -1) + '.000Z') return value;
}

export function statisticsCoverage(report: Record<string, unknown>): StatisticsCoverage | undefined {
 if (report.history_persistent !== true) return;
 const count = safeCount(report.requests);
 const backlog = safeCount(report.history_backlog_bytes);
 const evicted = safeCount(report.history_evicted_rows);
 const first = utcTimestamp(report.history_first_request);
 const last = utcTimestamp(report.history_last_request);
 const checkedAt = utcTimestamp(report.history_checked_at);
 const workerCheckedAt = utcTimestamp(report.history_worker_checked_at);
 const sourceCounts = ['history_blocked_sources','history_compressed_sources','history_unsupported_rotation_sources','history_invalid_lines','history_deferred_compressed_sources']
   .map(key => safeCount(report[key]));
 const missing = report.history_missing_log;
 const beforeRetention = report.history_before_retention;
 const partial = report.partial === true || missing === true || beforeRetention === true
   || [backlog, evicted, ...sourceCounts].some(value => value !== undefined && value > 0);
 const boundedTimestamps = first !== undefined && last !== undefined && Boolean(first) === Boolean(last)
   && (!first || last >= first);
 const complete = report.partial === false && missing === false && beforeRetention === false
   && [count, backlog, evicted, ...sourceCounts].every(value => value !== undefined)
   && boundedTimestamps && Boolean(checkedAt) && (count === 0 || Boolean(first));
 const workerError = report.history_worker_error;
 const worker = typeof workerError === 'string' && workerError !== '' || report.history_worker_fresh === false ? 'stale'
   : report.history_worker_fresh === true && workerError === '' && workerCheckedAt ? 'fresh' : 'unknown';
 return {
   state: partial ? 'partial' : !complete ? 'unknown' : count === 0 ? 'empty' : 'matched',
   count, first: boundedTimestamps ? first || '' : '', last: boundedTimestamps ? last || '' : '',
   checkedAt: checkedAt || '', backlog, evicted, beforeRetention: beforeRetention === true,
   worker, workerCheckedAt: workerCheckedAt || '',
 };
}
