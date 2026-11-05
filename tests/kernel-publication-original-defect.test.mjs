import test from'node:test';
import assert from'node:assert/strict';
import{publicationOriginalDefect as expected,verifyPublicationOriginalDefect as verify}from'../tools/check-kernel-publication-original-defect.mjs';
function fixture(){
 const Package='local/panel/internal/executor',rows=[];
 for(const Test of expected.expected_failed_tests){rows.push({Package,Test,Action:'run'});if(expected.expected_http409_tests.includes(Test))rows.push({Package,Test,Action:'output',Output:'reader observed an unpublished private record: HTTP 409 {"error":"original incomplete record"}\n'});rows.push({Package,Test,Action:'fail'})}
 rows.push({Package,Action:'fail'});return rows;
}
test('original publication defect gate requires all exact failed cases and original response witnesses',()=>{
 for(const architecture of['x86_64','aarch64']){const v=verify(fixture(),architecture);assert.equal(v.original_failed_cases,31);assert.equal(v.actual_unpublished_record_observations,28);assert.equal(v.installed_or_store_acceptance,false);assert.equal(v.explicit_test_only_overlay_files,1);assert.equal(v.normal_candidate_source_overlays,0)}
});
for(const kind of['empty','missing-run','missing-failure','duplicate-run','duplicate-failure','skip','passed-case','passed-package','missing-package-failure','foreign-case','foreign-package','missing-witness','duplicate-witness','wrong-status'])test('original publication defect evidence rejects '+kind,()=>{
 let rows=fixture();switch(kind){
 case'empty':rows=[];break;
 case'missing-run':rows.splice(rows.findIndex(r=>r.Action==='run'),1);break;
 case'missing-failure':rows.splice(rows.findIndex(r=>r.Action==='fail'&&r.Test),1);break;
 case'duplicate-run':rows.push({...rows.find(r=>r.Action==='run')});break;
 case'duplicate-failure':rows.push({...rows.find(r=>r.Action==='fail'&&r.Test)});break;
 case'skip':rows[0].Action='skip';break;
 case'passed-case':rows.find(r=>r.Action==='fail'&&r.Test).Action='pass';break;
 case'passed-package':rows[rows.length-1].Action='pass';break;
 case'missing-package-failure':rows=rows.filter(r=>r.Test);break;
 case'foreign-case':rows[0].Test='TestForeign';break;
 case'foreign-package':rows[0].Package='foreign/package';break;
 case'missing-witness':rows.splice(rows.findIndex(r=>r.Action==='output'),1);break;
 case'duplicate-witness':rows.push({...rows.find(r=>r.Action==='output')});break;
 case'wrong-status':{const r=rows.find(r=>r.Action==='output');r.Output=r.Output.replace('HTTP 409 ','HTTP 401 ');break}
 }assert.throws(()=>verify(rows,'x86_64'));
});
