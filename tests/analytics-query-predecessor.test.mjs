import test from 'node:test';
import assert from 'node:assert/strict';
import {verifyAnalyticsQueryPredecessor as verify} from '../tools/check-analytics-query-predecessor.mjs';
const Package='local/panel/internal/appcatalog',prefix='TestPublishedCandidateRepositoryCurrentSignedManifestABI';
const ids=['website-analytics',...Array.from({length:49},(_,i)=>'owned-app-'+i)];
function events(){return[
 {Package,Action:'run',Test:prefix},...ids.flatMap(id=>[{Package,Action:'run',Test:prefix+'/'+id},{Package,Action:id==='website-analytics'?'fail':'pass',Test:prefix+'/'+id}]),
 {Package,Action:'output',Test:prefix+'/website-analytics',Output:'actual compiled verifier rejects the candidate manifest 网站分析 2.4.1 须声明固定完整版本和四个必需处理器'},
 {Package,Action:'fail',Test:prefix},{Package,Action:'fail'},
 ]}
test('unchanged predecessor must actually refuse only analytics242 and pass other49',()=>{assert.equal(verify(events(),ids).other49_apps_passed,true)});
for(const mutation of ['empty','skip','missing','duplicate','foreign-package','missing-original-refusal','wrong-failure','fake-package-success','missing-package-failure'])test('Analytics query predecessor refuses '+mutation,()=>{
 const rows=events();
 if(mutation==='empty')rows.splice(0);
 else if(mutation==='skip')rows[1].Action='skip';
 else if(mutation==='missing')rows.splice(1,1);
 else if(mutation==='duplicate')rows.push({...rows[1]});
 else if(mutation==='foreign-package')rows[0].Package='foreign';
 else if(mutation==='missing-original-refusal')rows.find(r=>r.Action==='output').Output='unrelated error';
 else if(mutation==='wrong-failure')rows.find(r=>r.Test===prefix+'/website-analytics'&&r.Action==='fail').Action='pass';
 else if(mutation==='fake-package-success')rows.push({Package,Action:'pass'});
 else rows.splice(rows.findIndex(r=>r.Action==='fail'&&!r.Test),1);
 assert.throws(()=>verify(rows,ids));
});
