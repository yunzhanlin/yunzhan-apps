import test from'node:test';
import assert from'node:assert/strict';
import {verifyEnterpriseKernelPredecessor}from'../tools/check-enterprise-kernel-predecessor.mjs';
const prefix='TestPublishedCandidateRepositoryCurrentSignedManifestABI',Package='local/panel/internal/appcatalog';
const ids=['website-tamper-proof','enterprise-tamper-proof',...Array.from({length:48},(_,i)=>'owned-test-'+i)];
function events(era){
 const refused=era==='immediate-C60'?['enterprise-tamper-proof']:['enterprise-tamper-proof','website-tamper-proof'];
 return [{Package,Action:'run',Test:prefix},...ids.flatMap(id=>[{Package,Action:'run',Test:prefix+'/'+id},{Package,Action:refused.includes(id)?'fail':'pass',Test:prefix+'/'+id}]),{Package,Action:'output',Output:'enterprise-integrity-kernel-ownership-v1 integrity-kernel-inode-journal-v1'},{Package,Action:'fail',Test:prefix},{Package,Action:'fail'}];
}
for(const era of['immediate-C60','legacy-C59']){
 test('predecessor validator requires all fifty real events for '+era,()=>{const result=verifyEnterpriseKernelPredecessor(events(era),ids,era);assert.equal(result.other_apps_passed,era==='immediate-C60'?49:48)});
 for(const[name,change]of[
  ['empty',rows=>rows.splice(0)],['skipped',rows=>rows.push({Package,Action:'skip',Test:prefix+'/enterprise-tamper-proof'})],['duplicate',rows=>rows.push(structuredClone(rows[1]))],['missing',rows=>rows.splice(1,1)],['wrong failure',rows=>rows.find(row=>row.Test===prefix+'/enterprise-tamper-proof'&&row.Action==='fail').Action='pass'],['fake package success',rows=>rows.push({Package,Action:'pass'})],['foreign package',rows=>rows[0].Package='foreign'],['missing exact ABI refusal',rows=>rows.find(row=>row.Action==='output').Output='generic failure'],
 ])test('predecessor '+era+' refuses '+name,()=>{const rows=events(era);change(rows);assert.throws(()=>verifyEnterpriseKernelPredecessor(rows,ids,era))});
}
