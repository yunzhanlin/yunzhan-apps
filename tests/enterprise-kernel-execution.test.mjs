import test from'node:test';
import assert from'node:assert/strict';
import {enterpriseKernelExecution as expected,verifyEnterpriseKernelExecution as verify}from'../tools/check-enterprise-kernel-execution.mjs';
function fixture(){
 const core=[],executor=[];
 for(const[pkg,names]of Object.entries(expected.packages)){
  const rows=pkg.endsWith('/executor')?executor:core;
  for(const name of names)rows.push({Package:pkg,Action:'run',Test:name},{Package:pkg,Action:'pass',Test:name});rows.push({Package:pkg,Action:'pass'});
 }
 const Package='local/panel/internal/executor';
 for(const name of['TestIntegrityKernelOwnedNativeRoundTrip','TestIntegrityKernelEnterpriseOwnedNativeRoundTrip'])executor.push({Package,Action:'output',Test:name+'/complete-with-held-writer-and-exclusion',Output:'actual_uid33_protection='+JSON.stringify({blocked:{'held-write':1,truncate:1,'new-open':1,'new-entry':1,rename:1,unlink:1,'outside-hardlink':1},excluded_write:true})+'\n'});
 for(const Test of['TestIntegrityKernelProgramUpgradeFenceRetainsOriginalReadonlyQueues','TestIntegrityKernelEnterpriseProgramUpgradeFenceRetainsOriginalReadonlyQueues'])executor.push({Package,Action:'output',Test,Output:'actual Root programme queue: active kernel request refused'});
 return{core,executor};
}
test('enterprise source validator retains all old cases and requires each independent app witness',()=>{
 for(const arch of['x86_64','aarch64']){const f=fixture(),result=verify(f.core,f.executor,arch);assert.equal(result.PASS['local/panel/internal/executor'],86);assert.equal(result.PASS['local/panel/internal/core'],35);assert.equal(result.PASS['local/panel/internal/appcatalog'],22);assert.equal(result.installed_or_store_acceptance,false)}
});
for(const kind of['empty','missing-pass','duplicate-pass','skip','foreign-case','no-package-pass','missing-enterprise-writer','borrowed-writer','excluded-not-writable','held-writer-succeeded','missing-enterprise-fence','borrowed-fence'])test('enterprise source evidence refuses '+kind,()=>{
 const f=fixture();switch(kind){
 case'empty':f.executor=[];break;
 case'missing-pass':f.executor.splice(f.executor.findIndex(r=>r.Action==='pass'&&r.Test),1);break;
 case'duplicate-pass':f.executor.push({...f.executor.find(r=>r.Action==='pass'&&r.Test)});break;
 case'skip':f.executor[1].Action='skip';break;
 case'foreign-case':f.executor[1].Test='TestForeign';break;
 case'no-package-pass':f.executor=f.executor.filter(r=>r.Test||r.Action!=='pass');break;
 case'missing-enterprise-writer':f.executor=f.executor.filter(r=>!(r.Output?.includes('actual_uid33_protection=')&&r.Test?.includes('Enterprise')));break;
 case'borrowed-writer':f.executor.find(r=>r.Output?.includes('actual_uid33_protection=')&&r.Test?.includes('Enterprise')).Test='TestIntegrityKernelOwnedNativeRoundTrip/complete-with-held-writer-and-exclusion';break;
 case'excluded-not-writable':{const r=f.executor.find(r=>r.Output?.includes('actual_uid33_protection='));r.Output=r.Output.replace('"excluded_write":true','"excluded_write":false');break}
 case'held-writer-succeeded':{const r=f.executor.find(r=>r.Output?.includes('actual_uid33_protection='));r.Output=r.Output.replace('"held-write":1','"held-write":0');break}
 case'missing-enterprise-fence':f.executor=f.executor.filter(r=>!(r.Output?.includes('actual Root programme queue:')&&r.Test?.includes('Enterprise')));break;
 case'borrowed-fence':f.executor.find(r=>r.Output?.includes('actual Root programme queue:')&&r.Test?.includes('Enterprise')).Test='TestIntegrityKernelProgramUpgradeFenceRetainsOriginalReadonlyQueues';break;
 }
 assert.throws(()=>verify(f.core,f.executor,'x86_64'));
});
