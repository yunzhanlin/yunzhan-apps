import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';

// This is the exact reviewed pre-2.4.1 catalog entry, not a replacement for an
// installed-update proof. Historical cohort hashes must retain their own version.
const previousStatistics = {
  "id": "website-statistics-v2",
  "name": "Website statistics-v2",
  "category": "professional",
  "version": "2.4.0",
  "summary": "真实访问日志后台增量采集到有界 SQLite 历史，30 天保留、全站最多 25 万行；时间、状态、路径/IP 和爬虫筛选，错误及慢请求明细。新增请求总耗时精确 P50/P90/P95/P99 与九段分布；无样本或超限不伪造分位数。慢请求阈值不筛除其他请求。检查点与请求同事务提交；压缩导入及地理信息未提供，需要对应版本面板处理器。",
  "stage": "ready",
  "risk": "maintained",
  "provider": "panel-module",
  "target": "website-statistics-v2",
  "manage_route": "app-modules",
  "capabilities": [
    "小时趋势",
    "独立 IP",
    "爬虫识别",
    "错误数",
    "路径排行",
    "来源统计",
    "时间与状态筛选",
    "路径/IP 筛选",
    "慢请求明细",
    "后台增量采集与 30 天有界持久历史",
    "检查点与请求同事务及中断保护",
    "精确 P50/P90/P95/P99、九段耗时分布及空样本/超限告警"
  ],
  "package_url": "https://raw.githubusercontent.com/yunzhanlin/yunzhan-apps/main/dist/apps/website-statistics-v2/2.4.0/manifest.json",
  "sha256": "45a02dd14bd30421d238d32a1453656faca5f9282991eafe3f67056d64322124"
};
const sha=b=>createHash('sha256').update(b).digest('hex');

export async function catalogBeforeStatistics241(catalog) {
 assert.equal(catalog.apps.length,50);
 const actual=catalog.apps.find(a=>a.id==='website-statistics-v2');
 assert.equal(actual.version,'2.5.0');
 const latest=await readFile(new URL('../dist/apps/website-statistics-v2/2.5.0/manifest.json',import.meta.url));
 assert.equal(sha(latest),actual.sha256);
 assert.deepEqual(JSON.parse(latest).required_panel_features,['statistics-cursor-retirement-v1','statistics-request-identity-v1']);
 const current=await readFile(new URL('../dist/apps/website-statistics-v2/2.4.1/manifest.json',import.meta.url));
 assert.equal(sha(current),'8b0bc77a7ddba94e1a29ea434c080b6c40c212d1edc592b904f757a3aa74f74e');
 assert.deepEqual(JSON.parse(current).required_panel_features,['statistics-cursor-retirement-v1']);
 const old=await readFile(new URL('../dist/apps/website-statistics-v2/2.4.0/manifest.json',import.meta.url));
 assert.equal(sha(old),previousStatistics.sha256);
 assert.ok(Date.parse(catalog.generated_at)>=Date.parse('2026-10-11T22:33:53Z'));
 return {...catalog,generated_at:'2026-10-11T22:33:53Z',apps:catalog.apps.map(a=>a.id===previousStatistics.id?structuredClone(previousStatistics):a)};
}
