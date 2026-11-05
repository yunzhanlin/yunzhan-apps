import test from 'node:test';
import assert from 'node:assert/strict';
import {verifyFilesSyncIndependentPredecessor as verify} from '../tools/check-files-sync-independent-predecessor.mjs';
const Package='local/panel/internal/appcatalog',prefix='TestPublishedCandidateRepositoryCurrentSignedManifestABI';
const ids=['files-sync',...Array.from({length:49},(_,i)=>'owned-app-'+i)];
function events(){return[
 {Package,Action:'run',Test:prefix},...ids.flatMap(id=>[{Package,Action:'run',Test:prefix+'/'+id},{Package,Action:id==='files-sync'?'fail':'pass',Test:prefix+'/'+id}]),
 {Package,Action:'output',Test:prefix+'/files-sync',Output:'unsupported compiled handler files-sync-root-independent-backup-v1'},
 {Package,Action:'fail',Test:prefix},{Package,Action:'fail'},
 ]}
test('unchanged predecessor must actually refuse only Files Sync200 and pass other49',()=>{assert.equal(verify(events(),ids).other49_apps_passed,true)});
for(const mutation of ['empty','skip','missing','duplicate','foreign-package','missing-feature','wrong-failure','fake-package-success','missing-package-failure'])test('Files Sync predecessor refuses '+mutation,()=>{
 const rows=events();
 if(mutation==='empty')rows.splice(0);
 else if(mutation==='skip')rows[1].Action='skip';
 else if(mutation==='missing')rows.splice(1,1);
 else if(mutation==='duplicate')rows.push({...rows[1]});
 else if(mutation==='foreign-package')rows[0].Package='foreign';
 else if(mutation==='missing-feature')rows.find(r=>r.Action==='output').Output='unrelated error';
 else if(mutation==='wrong-failure')rows.find(r=>r.Test===prefix+'/files-sync'&&r.Action==='fail').Action='pass';
 else if(mutation==='fake-package-success')rows.push({Package,Action:'pass'});
 else rows.splice(rows.findIndex(r=>r.Action==='fail'&&!r.Test),1);
 assert.throws(()=>verify(rows,ids));
});
