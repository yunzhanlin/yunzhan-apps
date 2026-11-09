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

