import fs from'node:fs';import path from'node:path';import assert from'node:assert/strict';import{createHash}from'node:crypto';import{spawnSync}from'node:child_process';import{fileURLToPath}from'node:url';
assert(process.platform==='linux'&&process.arch==='x64'&&process.geteuid()===0,'Actual Linux Root AMD64 CI fixture only');
const go=process.argv[2],race=process.argv[3]==='--race';assert(process.argv.length===(race?4:3)&&path.isAbsolute(go));
const root=fileURLToPath(new URL('../',import.meta.url)),source=path.join(root,'panel-integration-redis-cli'),sha=b=>createHash('sha256').update(b).digest('hex'),index=JSON.parse(fs.readFileSync(source+'/source-sha256.json'));
assert(index.release.frozen_inputs_sha256==="5ddc86484adc44a7f89d23a5b2c76cc52dc57bc02dd4b39ab85049fedaf883fe"&&Object.keys(index.files).length===1809&&Object.keys(index.test_overrides).length===0);
const verify=()=>{for(const[n,h]of Object.entries(index.files)){const s=fs.lstatSync(source+'/'+n);assert(s.isFile()&&!s.isSymbolicLink()&&s.nlink===1);assert.equal(sha(fs.readFileSync(source+'/'+n)),h,n);}};verify();
const groups=[
  {
    "name": "Core_authority",
    "pkg": "core",
    "expectedPasses": 90,
    "names": [
      "TestSignedInstallVersionAllDeclaredModulesKeepExactIdentity",
      "TestSignedInstallLegacyEmptyVersionOriginalIsResolvedWithoutMutation",
      "TestSignedInstallVersionRejectsBorrowedOrChangedOriginalBeforeDispatch",
      "TestSignedInstallWorkerUsesRetainedVersionOnlyInExecutionEnvelope",
      "TestNativeMobileCannotBorrowUnsignedNoopForeignOrRevokedQueueBinding",
      "TestRedisACLAuthenticationModeValidation",
      "TestRedisACLCreateAlwaysSelectsSecureIdentity",
      "TestRedisACLCredentialsRequireCurrentDatabaseAdminCSRFAndOrigin",
      "TestRedisACLCredentialsReturnOnlyAppIdentityWithDurableAudit",
      "TestRedisACLCredentialsRevocationDuringReadDoesNotReturnPassword",
      "TestRedisACLCredentialsInvalidSinkAndFailedAuditNeverDisclose"
    ]
  },
  {
    "name": "Signed_modules_and_Apache",
    "pkg": "executor",
    "expectedPasses": 93,
    "names": [
      "TestApacheNativeBodySiteNoopPurePlanPreservesPolicyAndEngine",
      "TestApacheNativeBodySiteNoopAllowsOnlyReviewedRemoteIPRelocation",
      "TestApacheNativeBodySiteNoopNeverPromotesForeignCandidate",
      "TestApacheNativeBodySiteNoopPrivateTripletPreservationAndChangeRefusal",
      "TestApacheBodyNativeExactConfigurationAllowsOnlySealedIncludes",
      "TestApacheBodySiteManifestPreservesUnrelatedReceiptFields",
      "TestApacheBodySiteEditsNoImplicitCapabilityOrOrphanErasure",
      "TestApacheBodySiteEditPendingAbsenceIsNotUnknown",
      "TestApacheMetadataSiteNoopPreservesUnrelatedStoppedService",
      "TestApacheBodyConfigurationClosedEnableReapplyDisablePreservesOutsideBytes",
      "TestApacheBodyConfigurationEffectiveModesAndSeparateSites",
      "TestApacheBodyConfigurationForeignEditsAndUnknownProgramsRefused",
      "TestApacheNativeLifecyclePrivateVersionAndRevisionAreNotRequestFlags",
      "TestApacheNativeCandidatePreservesOutsideAndRemovesOnlyExactBodyBlocks",
      "TestMobileSelectedVersionSinkPreservesLegacyAndRefusesInstallOverwrite",
      "TestSignedMobileCoreUnixExactInstallAndExplicitStoreUpdate"
    ]
  },
  {
    "name": "Compose_private_CLI",
    "pkg": "executor",
    "expectedPasses": 13,
    "names": [
      "TestComposeCLIPrivateConfigIndependentOfHiddenPersonalHome",
      "TestComposeCLIPrivateConfigRefusesExistingUnsafeOrForeignStateWithoutRepair"
    ]
  },
  {
    "name": "Redis_native_contracts",
    "pkg": "executor",
    "expectedPasses": 7,
    "names": [
      "TestRedisACLSecretClosedIdentityAndHashOnlyConfig",
      "TestRedisACLSecretFileRootMetadataNotPermissionProbe",
      "TestRedisACLRESPBoundedTypedReplies",
      "TestRedisACLRESPRealPrivateStreamAUTHSELECTBeforeCommand",
      "TestRedisACLRESPAuthenticationFailureNeverExecutesOrEchoes",
      "TestRedisACLRESPCancellationClosesPrivateConnection",
      "TestRedisACLRESPFixedCommandsAndNoLegacyFallback"
    ]
  },
  {
    "name": "Redis_verified_kernel_peers",
    "pkg": "executor",
    "expectedPasses": 32,
    "names": [
      "TestRedisPeerUnitIdentityClosedAndInstanceBound",
      "TestRedisPeerCgroupV1V2AndHybridUseActualSystemdDomain",
      "TestRedisPeerKernelStatusRequiresAllNonRootIDsNoSavedCapabilities",
      "TestRedisPeerDirectoryIsRootOwnedGroupPrivateNotAWorldSocketClaim",
      "TestRedisPeerRootAccountRejectedBeforeAnyFileOrConnection",
      "TestRedisPeerLegacyACLNeverDialsOrFallsBack",
      "TestRedisPeerKernelMatchingIdentityUsesTheSameConnectionForAUTH",
      "TestRedisPeerKernelSameUIDForeignPIDReceivesNoAUTHBytes",
      "TestRedisPeerKernelGenerationChangeAndCancellationSendNoAUTH",
      "TestRedisPeerKernelWrongOwnerAndUnknownDirectoryNeverRepairOrConnect"
    ]
  }
],out={ok:false,race,source_inputs:index.release.frozen_inputs_sha256,source_overlays:0,private_integration_not_host_app_installation:true,all50_commercial:false,groups:{}};
for(const g of groups){
 const args=['test','-json','-count=1','-timeout=180s',...(race?['-race']:[]),'./internal/'+g.pkg,'-run=^('+g.names.join('|')+')$'];
 const z=spawnSync(go,args,{cwd:source,env:{...process.env,PANEL_QA_APACHE_METADATA_NOOP:'1',PANEL_QA_APACHE_BODY_NOOP:'1'},encoding:'utf8',timeout:240000,maxBuffer:8<<20});
 // Preserve the complete child evidence even when it fails. Asynchronous
 // stdout followed by an assertion can lose the actual failure tail in CI.
 const logs=path.join(root,'.local');fs.mkdirSync(logs,{recursive:true});
 const stem=path.join(logs,'redis-cli-native-ci-'+g.name+(race?'-race':''));
 fs.writeFileSync(stem+'.stdout.jsonl',z.stdout??'',{flag:'wx',mode:0o600});
 fs.writeFileSync(stem+'.stderr.log',z.stderr??'',{flag:'wx',mode:0o600});
 fs.writeFileSync(stem+'.process.json',JSON.stringify({status:z.status,signal:z.signal,error:z.error?.message,stdout_sha256:sha(z.stdout??''),stderr_sha256:sha(z.stderr??'')})+'\n',{flag:'wx',mode:0o600});
 fs.writeSync(1,z.stdout??'');fs.writeSync(2,z.stderr??'');
 assert.equal(z.error,undefined);assert.equal(z.status,0);
 const events=z.stdout.trim().split('\n').map(s=>JSON.parse(s));assert(!events.some(e=>e.Action==='fail'||e.Action==='skip'));
 const passed=events.filter(e=>e.Action==='pass'&&e.Test).map(e=>e.Test);assert.deepEqual(passed.filter(n=>!n.includes('/')).sort(),g.names.toSorted());assert.equal(passed.length,g.expectedPasses);
 out.groups[g.name]={passed:passed.length,top_level:g.names.length,failed:0,skipped:0,stdout_sha256:sha(z.stdout)};
}
verify();out.ok=true;fs.mkdirSync(path.join(root,'.local'),{recursive:true});const record=path.join(root,'.local/redis-cli-native-ci'+(race?'-race':'')+'-proof.json');fs.writeFileSync(record,JSON.stringify(out,null,2)+'\n',{flag:'wx',mode:0o600});console.log(JSON.stringify(out));
