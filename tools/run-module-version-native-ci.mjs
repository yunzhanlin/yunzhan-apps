import fs from'node:fs';import path from'node:path';import assert from'node:assert/strict';import{createHash}from'node:crypto';import{spawnSync}from'node:child_process';import{fileURLToPath}from'node:url';
assert(process.platform==='linux'&&process.arch==='x64'&&process.geteuid()===0,'Actual Linux Root AMD64 CI fixture only');
const go=process.argv[2],race=process.argv[3]==='--race';assert(process.argv.length===(race?4:3)&&path.isAbsolute(go));
const root=fileURLToPath(new URL('../',import.meta.url)),source=path.join(root,'panel-integration-module-version'),sha=b=>createHash('sha256').update(b).digest('hex'),index=JSON.parse(fs.readFileSync(source+'/source-sha256.json'));
assert(index.release.frozen_inputs_sha256==="41c4295d400488bc6d69faa6a36a3a9556fc50b0b7e14d2011b083b964113cb4"&&Object.keys(index.files).length===1796&&Object.keys(index.test_overrides).length===0);
const verify=()=>{for(const[n,h]of Object.entries(index.files)){const s=fs.lstatSync(source+'/'+n);assert(s.isFile()&&!s.isSymbolicLink()&&s.nlink===1);assert.equal(sha(fs.readFileSync(source+'/'+n)),h,n);}};verify();
const groups=[
 {pkg:'core',expectedPasses:78,names:['TestSignedInstallVersionAllDeclaredModulesKeepExactIdentity','TestSignedInstallLegacyEmptyVersionOriginalIsResolvedWithoutMutation','TestSignedInstallVersionRejectsBorrowedOrChangedOriginalBeforeDispatch','TestSignedInstallWorkerUsesRetainedVersionOnlyInExecutionEnvelope','TestNativeMobileCannotBorrowUnsignedNoopForeignOrRevokedQueueBinding']},
 {pkg:'executor',expectedPasses:93,names:['TestApacheNativeBodySiteNoopPurePlanPreservesPolicyAndEngine','TestApacheNativeBodySiteNoopAllowsOnlyReviewedRemoteIPRelocation','TestApacheNativeBodySiteNoopNeverPromotesForeignCandidate','TestApacheNativeBodySiteNoopPrivateTripletPreservationAndChangeRefusal','TestApacheBodyNativeExactConfigurationAllowsOnlySealedIncludes','TestApacheBodySiteManifestPreservesUnrelatedReceiptFields','TestApacheBodySiteEditsNoImplicitCapabilityOrOrphanErasure','TestApacheBodySiteEditPendingAbsenceIsNotUnknown','TestApacheMetadataSiteNoopPreservesUnrelatedStoppedService','TestApacheBodyConfigurationClosedEnableReapplyDisablePreservesOutsideBytes','TestApacheBodyConfigurationEffectiveModesAndSeparateSites','TestApacheBodyConfigurationForeignEditsAndUnknownProgramsRefused','TestApacheNativeLifecyclePrivateVersionAndRevisionAreNotRequestFlags','TestApacheNativeCandidatePreservesOutsideAndRemovesOnlyExactBodyBlocks','TestMobileSelectedVersionSinkPreservesLegacyAndRefusesInstallOverwrite','TestSignedMobileCoreUnixExactInstallAndExplicitStoreUpdate']}
],out={ok:false,race,source_inputs:index.release.frozen_inputs_sha256,source_overlays:0,private_integration_not_host_app_installation:true,all50_commercial:false,groups:{}};
for(const g of groups){
 const args=['test','-json','-count=1','-timeout=180s',...(race?['-race']:[]),'./internal/'+g.pkg,'-run=^('+g.names.join('|')+')$'];
 const z=spawnSync(go,args,{cwd:source,env:{...process.env,PANEL_QA_APACHE_METADATA_NOOP:'1',PANEL_QA_APACHE_BODY_NOOP:'1'},encoding:'utf8',timeout:240000,maxBuffer:8<<20});
 // Preserve the complete child evidence even when it fails. Asynchronous
 // stdout followed by an assertion can lose the actual failure tail in CI.
 const logs=path.join(root,'.local');fs.mkdirSync(logs,{recursive:true});
 const stem=path.join(logs,'module-version-native-ci-'+g.pkg+(race?'-race':''));
 fs.writeFileSync(stem+'.stdout.jsonl',z.stdout??'',{flag:'wx',mode:0o600});
 fs.writeFileSync(stem+'.stderr.log',z.stderr??'',{flag:'wx',mode:0o600});
 fs.writeFileSync(stem+'.process.json',JSON.stringify({status:z.status,signal:z.signal,error:z.error?.message,stdout_sha256:sha(z.stdout??''),stderr_sha256:sha(z.stderr??'')})+'\n',{flag:'wx',mode:0o600});
 fs.writeSync(1,z.stdout??'');fs.writeSync(2,z.stderr??'');
 assert.equal(z.error,undefined);assert.equal(z.status,0);
 const events=z.stdout.trim().split('\n').map(s=>JSON.parse(s));assert(!events.some(e=>e.Action==='fail'||e.Action==='skip'));
 const passed=events.filter(e=>e.Action==='pass'&&e.Test).map(e=>e.Test);assert.deepEqual(passed.filter(n=>!n.includes('/')).sort(),g.names.toSorted());assert.equal(passed.length,g.expectedPasses);
 out.groups[g.pkg]={passed:passed.length,top_level:g.names.length,failed:0,skipped:0,stdout_sha256:sha(z.stdout)};
}
verify();out.ok=true;fs.mkdirSync(path.join(root,'.local'),{recursive:true});const record=path.join(root,'.local/module-version-native-ci'+(race?'-race':'')+'-proof.json');fs.writeFileSync(record,JSON.stringify(out,null,2)+'\n',{flag:'wx',mode:0o600});console.log(JSON.stringify(out));
