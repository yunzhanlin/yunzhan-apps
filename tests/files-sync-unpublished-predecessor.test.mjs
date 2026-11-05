import test from 'node:test';
import assert from 'node:assert/strict';
import {verifyFilesSyncUnpublishedPredecessor as verify} from '../tools/check-files-sync-unpublished-predecessor.mjs';
const Package='local/panel/internal/appcatalog',prefix='TestPublishedCandidateRepositoryCurrentSignedManifestABI';
const ids=['files-sync',...Array.from({length:49},(_,i)=>'owned-app-'+i)];
function events(){return[
 {Package,Action:'run',Test:prefix},...ids.flatMap(id=>[{Package,Action:'run',Test:prefix+'/'+id},{Package,Action:id==='files-sync'?'fail':'pass',Test:prefix+'/'+id}]),
 {Package,Action:'output',Test:prefix+'/files-sync',Output:'actual compiled verifier rejects the candidate manifest 独立备份须声明精确文件同步2.0.0及本机Root私有副本处理器'},
 {Package,Action:'fail',Test:prefix},{Package,Action:'fail'},
 ]}
test('unchanged predecessor must actually refuse only files-sync201 and pass other49',()=>{assert.equal(verify(events(),ids).other49_apps_passed,true)});
for(const mutation of ['empty','skip','missing','duplicate','foreign-package','missing-original-refusal','wrong-failure','fake-package-success','missing-package-failure'])test('Files Sync unpublished retention predecessor refuses '+mutation,()=>{
 const rows=events();
 if(mutation==='empty')rows.splice(0);
 else if(mutation==='skip')rows[1].Action='skip';
 else if(mutation==='missing')rows.splice(1,1);
 else if(mutation==='duplicate')rows.push({...rows[1]});
 else if(mutation==='foreign-package')rows[0].Package='foreign';
 else if(mutation==='missing-original-refusal')rows.find(r=>r.Action==='output').Output='unrelated error';
 else if(mutation==='wrong-failure')rows.find(r=>r.Test===prefix+'/files-sync'&&r.Action==='fail').Action='pass';
 else if(mutation==='fake-package-success')rows.push({Package,Action:'pass'});
 else rows.splice(rows.findIndex(r=>r.Action==='fail'&&!r.Test),1);
 assert.throws(()=>verify(rows,ids));
});
