import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {fileURLToPath}from 'node:url';
import {verifyAnalyticsQueryExecution,queryRoot,queryScenarios}from '../tools/check-analytics-query-execution.mjs';
const root=fileURLToPath(new URL('../',import.meta.url)),names=JSON.parse(fs.readFileSync(root+'tools/analytics-query-execution.json')).Node_test_names;
const make=()=>{
 const tests=[queryRoot,...queryScenarios.map(n=>queryRoot+'/'+n)],rows=tests.flatMap(Test=>['run','pass'].map(Action=>({Package:'local/panel/internal/appcatalog',Action,Test})));
 rows.push({Package:'local/panel/internal/appcatalog',Action:'pass'});
 const tap=names.map((n,i)=>'ok '+(i+1)+' - '+n).join('\n')+'\n# tests 8\n# pass 8\n# fail 0\n# cancelled 0\n# skipped 0\n# todo 0\n';
 return {rows,tap};
};
test('source execution parser accepts an explicitly synthetic complete fixture without calling it native proof',()=>{const {rows,tap}=make();assert.equal(verifyAnalyticsQueryExecution(rows,tap,'aarch64').actual_Vue_component_cases,4);});
for(const kind of ['empty','missing','duplicate','skip','failed','foreign','package-missing','empty-Node','missing-Vue','wrong-Node','skipped-Node','failed-Node'])test('query CI gate rejects '+kind,()=>{
 let {rows,tap}=make();
 if(kind==='empty')rows=[];if(kind==='missing')rows.pop();if(kind==='duplicate')rows.push(rows[0]);if(kind==='skip')rows[0].Action='skip';if(kind==='failed')rows[0].Action='fail';if(kind==='foreign')rows[0].Test='TestOther';if(kind==='package-missing')rows=rows.filter(r=>r.Test);
 if(kind==='empty-Node')tap='';if(kind==='missing-Vue')tap=tap.replace(/^ok 5 - .+\n/m,'');if(kind==='wrong-Node')tap=tap.replace(names[0],'unrelated');if(kind==='skipped-Node')tap+='# SKIP\n';if(kind==='failed-Node')tap=tap.replace('# fail 0','# fail 1');
 assert.throws(()=>verifyAnalyticsQueryExecution(rows,tap,'aarch64'));
});
