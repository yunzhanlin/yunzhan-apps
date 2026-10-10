import {test} from 'node:test';import assert from 'node:assert/strict';import {readFileSync} from 'node:fs';
import ts from '../web/node_modules/typescript/lib/typescript.js';
const read=p=>readFileSync(new URL('../'+p,import.meta.url),'utf8');
const source=read('web/src/loadBalanceReportExport.ts');
const compiled=ts.transpileModule(source,{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText;
const {loadBalanceReportExportHref}=await import('data:text/javascript;base64,'+Buffer.from(compiled).toString('base64'));
const now=Date.parse('2026-10-10T12:00:00Z'),id='a'.repeat(32),sha='b'.repeat(64);
const receipt={format:1,module:'load-balance',action:'transactions',id,sha256:sha,bytes:1234,expires_at:'2026-10-10T12:05:00.123456789Z'};
const report={load_transactions:[],records_retained:true,configuration_changed:false,report_export:receipt};
const url=`/api/app-modules/load-balance/report-export/${id}?sha256=${sha}`;
test('the current actual report uses a closed same-origin authenticated attachment URL',()=>{
 assert.equal(loadBalanceReportExportHref('transactions',report,now),url);
 assert.equal(loadBalanceReportExportHref('reports',report,now),url);
 assert.equal(loadBalanceReportExportHref('transaction-archive',{...report,report_export:{...receipt,action:'archive-transaction'}},now),url);
 assert.equal(loadBalanceReportExportHref('history',{events:[],report_export:{...receipt,action:'history'}},now),url);
});
test('receipt scope never turns another workspace or secret-bearing result into a download',()=>{
 for(const section of ['entries','entry','health','recovery','history','overview','version','unknown'])assert.equal(loadBalanceReportExportHref(section,report,now),undefined);
 for(const action of ['run','history','save','remove','archive-transaction','unknown'])assert.equal(loadBalanceReportExportHref('transactions',{...report,report_export:{...receipt,action}},now),undefined);
 for(const value of [undefined,[],{}, {...report,token:'private'}, {...report,report_export:[]}, {...report,report_export:null}])assert.equal(loadBalanceReportExportHref('transactions',value,now),undefined);
});
test('identity, digest, size, schema and UTC expiry fail closed',()=>{
 for(const patch of [{format:2},{module:'other'},{id:'../download'},{id:id.toUpperCase()},{sha256:sha.toUpperCase()},{sha256:'b'.repeat(63)},{bytes:0},{bytes:1048577},{bytes:'1234'},{bytes:1.2},{expires_at:'2026-10-10T11:59:59Z'},{expires_at:'2026-10-10T12:05:00+00:00'},{expires_at:'garbage'},{url:'https://external.invalid'},{path:'/etc/shadow'}])assert.equal(loadBalanceReportExportHref('transactions',{...report,report_export:{...receipt,...patch}},now),undefined);
 assert.equal(loadBalanceReportExportHref('transactions',report,NaN),undefined);
 assert.equal(loadBalanceReportExportHref('transactions',report,Date.parse(receipt.expires_at)),undefined);
 const {bytes,...missing}=receipt;assert.equal(loadBalanceReportExportHref('transactions',{...report,report_export:missing},now),undefined);
});
test('the actual manager renders an HTTP attachment and never falls back to LB Blob downloads',()=>{
 const manager=read('web/src/AppModuleManager.vue');
 assert.match(manager,/loadBalanceReportExportHref\(activeTab\.value,exportableReport\.value,reportExportNow\.value\)/);
 assert.match(manager,/tag="a" :href="busy \? undefined : nativeReportExportHref"/);
 assert.match(manager,/target="_blank" rel="noopener noreferrer"/);
 assert.match(manager,/actual\.token \|\| definition\.value\?\.id==='load-balance'/);
 assert.match(manager,/window\.clearInterval\(reportExportTimer\)/);
 assert.match(manager,/history\.value=undefined/);
 assert.match(manager,/过期、账户切换或面板重启后请重新查询本页/);
 assert.match(read('packaging/build-release.sh'),/node --test scripts\/test-load-balance-report-export\.mjs/);
 const core=read('internal/core/load_balance_report_export.go');assert.match(core,/a\.authorize/);assert.match(core,/entry\.Owner != loadBalanceExportOwner\(u\)/);assert.match(core,/X-Content-SHA256/);assert.doesNotMatch(core,/a\.Executor|os\.ReadFile|os\.WriteFile|exec\.Command/);
});
