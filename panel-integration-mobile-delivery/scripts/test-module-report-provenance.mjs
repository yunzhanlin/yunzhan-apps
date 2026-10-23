import test from 'node:test';import assert from 'node:assert/strict';import {readFileSync} from 'node:fs';
import ts from '../web/node_modules/typescript/lib/typescript.js';
const source=readFileSync(new URL('../web/src/AppModuleManager.vue',import.meta.url),'utf8'),helper=readFileSync(new URL('../web/src/moduleReportProvenance.ts',import.meta.url),'utf8'),compile=s=>ts.transpileModule(s,{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText;
const {moduleReportProvenance, moduleReportProvenanceNotice}=await import('data:text/javascript;base64,'+Buffer.from(compile(helper)).toString('base64'));
const start=source.indexOf('function setReport('),end=source.indexOf('async function show(',start);assert(start>0&&end>start);
function fixture(){const b={reportProvenance:{value:undefined},moduleReportProvenance,reportStateUnknown:{value:true},report:{value:undefined},definition:{value:{id:'website-statistics-v2'}}};return{b,set:new Function('b','with(b){'+compile(source.slice(start,end))+';return setReport;}')(b)};}
test('actual saved-report setter preserves exact old result and labels its original UTC time, not current health',()=>{
 const f=fixture(),data={history_worker_fresh:true,geography_error:'old unavailable result',requests:2},saved={time:'2026-10-18T11:20:06Z',action:'run',result:data};
 f.set(saved,'stored');assert.equal(f.b.report.value,data);assert.deepEqual(f.b.report.value,data);assert.equal(f.b.reportProvenance.value.generatedAt,saved.time);
 const notice=moduleReportProvenanceNotice(f.b.reportProvenance.value);assert(notice.includes('保存的历史报告')&&notice.includes(saved.time)&&notice.includes('仅反映报告当时')&&notice.includes('刷新报告'));assert.equal(saved.result.history_worker_fresh,true,'do not rewrite a historical server receipt');
});
test('actual new request clears historical provenance without injecting current timestamps into backend data',()=>{
 const f=fixture();f.set({time:'2026-10-18T11:20:06Z',result:{old:true}},'stored');const current={requests:0};f.set(current);assert.equal(f.b.report.value,current);assert.equal(moduleReportProvenanceNotice(f.b.reportProvenance.value),'');assert.deepEqual(current,{requests:0});
});
test('retained platform snapshot is never labelled as a new server request',()=>{
 const f=fixture(),data={hosts:[],checked_at:'2026-10-18T11:20:06Z'};f.set(data,'retained');assert.equal(f.b.report.value,data);assert(moduleReportProvenanceNotice(f.b.reportProvenance.value).includes('不是本次新读取'));assert.equal(f.b.reportProvenance.value.generatedAt,undefined);
});
test('missing malformed impossible offset fractional and oversized timestamps remain explicitly unknown',()=>{
 for(const value of [null,{},[],{time:'2026-10-18T11:20:06Z'},...['2026-02-30T11:20:06Z','2026-10-18T11:20:06+00:00','2026-10-18T11:20:06.001Z','bad','x'.repeat(10000),123,null].map(time=>({time,result:{}}))]){
  const meta=moduleReportProvenance(value,'stored');assert.equal(meta.generatedAt,undefined);assert(moduleReportProvenanceNotice(meta).includes('生成时间未记录或无法核对'));
 }
});
test('both actual stored-report reads and remembered snapshot use explicit origin, with visible accessible warning and scope clearing',()=>{
 assert.equal((source.match(/setReport\(page\.report, 'stored'\)/g)||[]).length,2);assert(source.includes("setReport(previous, 'retained')"));assert(source.includes('role="status"'));assert.equal((source.match(/v-if="report && !reportStateUnknown && reportProvenanceNotice"/g)||[]).length,2);assert(source.includes("reportProvenance.value = undefined; }, {flush:'sync'}"));
 assert(source.indexOf(':title="reportProvenanceNotice"')>source.indexOf('class="workflow-result"'),'Stored parent report must not label independently read analytics/WAF or geodata workspaces');
});
