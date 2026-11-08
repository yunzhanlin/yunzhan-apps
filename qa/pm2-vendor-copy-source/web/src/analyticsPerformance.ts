export interface AnalyticsMetric {samples:number;p75?:number}
export interface AnalyticsPerformancePage {path:string;kind:"document"|"spa";navigations:number;metrics:Record<string,AnalyticsMetric>}
export interface AnalyticsPerformancePages {rows:AnalyticsPerformancePage[];partial:boolean;sampled_visits:number;group_limit:number}
export const documentPerformanceMetrics=[{key:"ttfb",label:"TTFB"},{key:"fcp",label:"FCP"},{key:"lcp",label:"LCP"},{key:"cls",label:"CLS"},{key:"inp",label:"INP"}] as const;
export const routePerformanceMetrics=[{key:"route_ready_ms",label:"路由就绪耗时"}] as const;

export function analyticsMetricText(metric:AnalyticsMetric|undefined,key:string):string {
  if(!metric||metric.samples===0)return "无样本";
  const value=metric.p75;
  if(!Number.isSafeInteger(metric.samples)||metric.samples<1||metric.samples>5000||typeof value!=="number"||!Number.isFinite(value)||value<0||value>(key==="cls"?100:300000))return "未核实";
  return `${value.toFixed(key==="cls"?3:1)}${key==="cls"?"":" ms"} · ${metric.samples} 个样本`;
}

export function analyticsPerformanceRows(pages:AnalyticsPerformancePages|undefined,kind:string,query:string):AnalyticsPerformancePage[] {
  if(!pages||!Array.isArray(pages.rows))return [];
  const needle=query.trim().toLowerCase();
  return pages.rows.slice(0,100).filter(row=>(row.kind==="document"||row.kind==="spa")&&typeof row.path==="string"&&(!kind||row.kind===kind)&&row.path.toLowerCase().includes(needle));
}
