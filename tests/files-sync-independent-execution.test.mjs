import test from 'node:test';
import assert from 'node:assert/strict';
import {filesSyncIndependentExecution as spec,verifyFilesSyncIndependentExecution as verify} from '../tools/check-files-sync-independent-execution.mjs';
function events(packages){
 return Object.entries(packages).flatMap(([Package,names])=>[
  ...names.flatMap(Test=>[{Package,Action:'run',Test},{Package,Action:'pass',Test}]),{Package,Action:'pass'},
 ]);
}
function fixture(architecture='x86_64'){
 const Package='local/panel/internal/executor';
 const core=events(spec.core_packages),root=events({[Package]:spec.Root_executor_cases}),sftp=events({[Package]:spec.unprivileged_SFTP_cases});
 root.push({Package,Action:'output',Test:'TestRemoteIndependentRootPrivateCopyNamespace',Output:'actual_Root_private_uid=0 actual_private_mode=0600 actual_UID33_private_read=EACCES'});
 sftp.push({Package,Action:'output',Test:'TestRemoteIndependentCopyTrueMidReadKillPreservesPartialAndRecovers',Output:'actual_native_read_partial_bytes=32768 actual_signal=SIGKILL preserved_original_inode=true new_complete_attempt=true'});
 const identity={system:'Linux',architecture,uid:1001,euid:1001,groups:[],native_sftp_sha256:'a'.repeat(64),status:['CapInh','CapPrm','CapEff','CapBnd','CapAmb'].map(k=>k+':\t0000000000000000').join('\n')+'\nNoNewPrivs:\t1\n'};
 return{core,root,sftp,identity};
}
for(const arch of ['x86_64','aarch64'])test('Files Sync gate requires the exact Core, Root and unprivileged execution on '+arch,()=>{
 const f=fixture(arch),r=verify(f.core,f.root,f.sftp,f.identity,arch);
 assert.equal(r.core_PASS,31);assert.equal(r.Root_PASS,8);assert.equal(r.unprivileged_SFTP_PASS,72);assert.equal(r.unprivileged_SFTP_roots,61);assert.equal(r.normal_installed_or_store_acceptance,false);
});
for(const stream of ['core','root','sftp'])for(const mutation of ['empty','missing-run','missing-pass','duplicate-pass','skip','foreign-case','foreign-package','missing-package-completion'])test('Files Sync gate refuses '+stream+' '+mutation,()=>{
 const f=fixture(),rows=f[stream];
 if(mutation==='empty')rows.splice(0);
 else if(mutation==='missing-run')rows.splice(rows.findIndex(r=>r.Action==='run'),1);
 else if(mutation==='missing-pass')rows.splice(rows.findIndex(r=>r.Action==='pass'&&r.Test),1);
 else if(mutation==='duplicate-pass')rows.push({...rows.find(r=>r.Action==='pass'&&r.Test)});
 else if(mutation==='skip')rows[1].Action='skip';
 else if(mutation==='foreign-case')rows[1].Test='TestForeign';
 else if(mutation==='foreign-package')rows[0].Package='foreign';
 else rows.splice(rows.findIndex(r=>r.Action==='pass'&&!r.Test),1);
 assert.throws(()=>verify(f.core,f.root,f.sftp,f.identity,'x86_64'));
});
for(const mutation of ['Root-instead-of-user','effective-Root','supplementary-group','different-architecture','different-platform','no-new-privileges-missing','bad-SFTP-pin',...'CapInh CapPrm CapEff CapBnd CapAmb'.split(' '),'missing-private-read-witness','borrowed-private-read-witness','missing-genuine-kill','borrowed-genuine-kill'])test('Files Sync gate refuses '+mutation,()=>{
 const f=fixture();
 switch(mutation){
 case 'Root-instead-of-user':f.identity.uid=f.identity.euid=0;break;
 case 'effective-Root':f.identity.euid=0;break;
 case 'supplementary-group':f.identity.groups=[0];break;
 case 'different-architecture':f.identity.architecture='aarch64';break;
 case 'different-platform':f.identity.system='Darwin';break;
 case 'no-new-privileges-missing':f.identity.status=f.identity.status.replace('NoNewPrivs:\t1','NoNewPrivs:\t0');break;
 case 'bad-SFTP-pin':f.identity.native_sftp_sha256='unmeasured';break;
 case 'missing-private-read-witness':f.root.pop();break;
 case 'borrowed-private-read-witness':f.root.at(-1).Test=spec.Root_executor_cases[0];break;
 case 'missing-genuine-kill':f.sftp.pop();break;
 case 'borrowed-genuine-kill':f.sftp.at(-1).Test=spec.unprivileged_SFTP_cases[0];break;
 default:f.identity.status=f.identity.status.replace(mutation+':\t0000000000000000',mutation+':\t0000000000000001');
 }
 assert.throws(()=>verify(f.core,f.root,f.sftp,f.identity,'x86_64'));
});
