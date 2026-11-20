import {test} from 'node:test';
import assert from 'node:assert/strict';
import {parseApacheRuntimeStatus} from '../web/src/apacheRuntime.ts';
import {apacheBodyBuildRow} from '../web/src/apacheBodyBuild.ts';
const baseline={selected_id:'apache-2.4.68',running_id:'apache-2.4.68',service_state:'active',recommended_id:'apache-2.4.71',target_installed:true,native_engine_required:true,waf_version:'2.5.1',activation_needed:true,checked_at:'2026-11-21T00:00:00Z'};
test('installing the fixed runtime does not claim existing sites are patched',()=>{
 assert.equal(parseApacheRuntimeStatus(baseline).activation_needed,true);
 const active={...baseline,selected_id:'apache-2.4.71',running_id:'apache-2.4.71',activation_needed:false};
 assert.equal(parseApacheRuntimeStatus(active).activation_needed,false);
 for(const patch of [{activation_needed:false},{target_installed:'true'},{running_id:''},{selected_id:'apache-2.4.70'},{running_id:'apache-2.4.70'},{checked_at:'unknown'}])assert.throws(()=>parseApacheRuntimeStatus({...baseline,...patch}));
 assert.throws(()=>parseApacheRuntimeStatus({...active,target_installed:false}));
 assert.equal(parseApacheRuntimeStatus({...active,target_installed:false,activation_needed:true}).activation_needed,true);
 assert.equal(parseApacheRuntimeStatus({...baseline,service_state:'inactive',running_id:''}).activation_needed,true);
});
test('current engine inventory admits the exact new runtime without expanding legacy retention',()=>{
 const row={job_id:'a'.repeat(32),state:'ready',build_only:true,architecture:'arm64',engine_version:'2.9.15-yz5',yajl_version:'2.1.0-debian5-yz1',crs_version:'4.30.0',apache_version:'2.4.71',integrity_verified:true,module_abi_validated:true,elf_hardening_validated:true,compiler_groups_collected:true,steps:[]};
 assert.equal(apacheBodyBuildRow(row),true);assert.equal(apacheBodyBuildRow({...row,apache_version:'2.4.70'}),false);
 assert.equal(apacheBodyBuildRow({...row,apache_version:'2.4.71',state:'retained_unsupported',engine_version:'2.9.15-yz4',error:'retained only',historical_integrity_verified:true,integrity_verified:false,module_abi_validated:false,elf_hardening_validated:false,compiler_groups_collected:false}),false);
});
