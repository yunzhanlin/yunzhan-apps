// Static frozen-input contracts only. Linux behavior has a separate real QA gate.
import test from'node:test';import assert from'node:assert/strict';import fs from'node:fs';import path from'node:path';import{fileURLToPath}from'node:url';import{createHash}from'node:crypto';
const root=fileURLToPath(new URL('..',import.meta.url)),read=n=>fs.readFileSync(path.join(root,n),'utf8'),sha=b=>createHash('sha256').update(b).digest('hex');
test('all original13-property predicates and legacy5s reader stay exact beneath the additional L4 fence',()=>{
 const ids=read('internal/executor/program_upgrade_ids_linux.go'),queues=read('internal/executor/program_upgrade_queues_linux.go');
 assert.equal(sha(ids.slice(ids.indexOf('func programQueueIDSIdleUnit('))),"c6180dba37d9036f10ea0ad032ac9885a9c6306519bf23e2a10e46d3cb094488");
	const entry='func CheckProgramUpgradeQueues() error {\n';
	const fencedEntry=entry+'\tif err := checkLegacyProgramUpgradeQueues(); err != nil {\n\t\treturn err\n\t}\n\tctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)\n\tdefer cancel()\n\treturn checkLoadBalanceStreamUpgrade(ctx, nil)\n}\n\n// Preserves all existing application, recovery and filesystem checks. The\n// private L4 controllers call this PLUS their independently self-bound fence;\n// they never pass a general native-unit prefix or selected-ID exemption here.\nfunc checkLegacyProgramUpgradeQueues() error {\n';
	// Undo only this exact, additional fail-closed wrapper before comparing the
	// original input. Neither native-unit exemptions nor changed legacy checks
	// can be hidden by updating a whole-file digest.
	assert.equal(queues.split(fencedEntry).length,2);
	const legacyQueues=queues.replace(fencedEntry,()=>entry);
	const oldBranch='return closedRuntimeFailedInstall(ctx, name, run) || closedRuntimeCompileOOMInstall(ctx, name, run)',newBranch=oldBranch+' || closedRuntimeSupersededCompileOOMInstall(ctx, name, run)';
	assert.equal(legacyQueues.split(newBranch).length,2);
	assert.equal(sha(legacyQueues),'bcf8ef698c5d3cdd3482ea219ad1a336735a1f80dcee2461aee19d8b707c4ed3');
	assert.equal(sha(legacyQueues.replace(newBranch,()=>oldBranch)),"7a365f2a28a5b38f93266450fe4d27f98084517b69da4c4ebb4fc47624da7da4");
 assert(queues.includes('context.WithTimeout(context.Background(), 5*time.Second)'));
 const originalLoop="\tfor _, unit := range []string{threatIDSService, \"panel-network-ids-check.service\", \"panel-network-ids-recover.service\"} {\n\t\traw, err := s.Config.Run(ctx, \"/usr/bin/systemctl\", \"show\", unit, \"--property=Id,LoadState,ActiveState,SubState,MainPID,Job,FragmentPath,DropInPaths,Transient,NeedDaemonReload,UnitFileState,ExecMainCode,ExecMainStatus\")\n\t\tif err != nil || !programQueueIDSIdleUnit(unit, raw) {\n\t\t\treturn nil, errors.New(\"IDS recovered native unit is not trusted and idle; upgrade refused\")\n\t\t}\n\t}\n",newLoop="\tif err := programQueueIDSVerifyIdleUnits(ctx, s.Config.Run); err != nil {\n\t\treturn nil, err\n\t}\n",oldCommand="\tif name != \"/usr/bin/systemctl\" || len(args) != 3 || args[0] != \"show\" || (args[1] != threatIDSService && args[1] != \"panel-network-ids-check.service\" && args[1] != \"panel-network-ids-recover.service\") || args[2] != \"--property=Id,LoadState,ActiveState,SubState,MainPID,Job,FragmentPath,DropInPaths,Transient,NeedDaemonReload,UnitFileState,ExecMainCode,ExecMainStatus\" {";
 assert.equal(ids.split(newLoop).length,2);
 const command='\tif !programQueueIDSObservationCommand(name, args) {';
 assert.equal(ids.split(command).length,2);
 const reversed=ids.replace(newLoop,()=>originalLoop).replace(command,()=>oldCommand);
 assert.equal(sha(reversed),"176122054507f8db2dad933590fc0428cb6b315702ee172ef574681bad11333f");
});

test('superseded OOM branch preserves both original unpublished protocols and cannot mutate jobs or services',()=>{
 const proof=read('internal/executor/program_upgrade_runtime_successor_linux.go'),core=read('internal/core/runtime_php_publication.go');
 assert.equal(sha(read('internal/executor/program_upgrade_runtime_compile_oom_linux.go')),'174c81f08b3215402b4ff0ee9d14dd7aa0fa0e24c08a2e25dad91d0f77758ef1');
 assert.equal(sha(read('internal/core/runtime_compile_oom_upgrade.go')),'06c7de138a4a3625b24cba22d45b3ac6105c6ed99123ab5f00f53e1963f163e1');
 for(const v of ['runtimeCompileOOMReadLease(records, ".native-start.lock")','fence: runtimeCompileOOMBuildFence','runtimeCompileOOMUnitStopped(show)','w.final == nil','!w.final()','core.ValidID(w.evidence.PublisherJobID)','bytes.Equal(raw, canonical)','ValidateRuntimeSupersededCompileOOMInstall(ctx, evidence)'])assert(proof.includes(v),v);
 assert(!/\b(?:WriteFile|Mkdir|Remove|Chmod|StartUnit|RestartUnit|InstallJob|startInstall|Retry|Recover)\s*\(|reset-failed|context\.WithTimeout|context\.WithoutCancel|time\.Sleep/.test(proof));
 assert(core.includes('&sql.TxOptions{ReadOnly: true}')&&!/\.(?:Exec|ExecContext)\s*\(/.test(core));
 for(const v of ['old.JobID == in.PublisherJobID','start.Before(oldEnd)','installed.Before(staged)','installed.After(sealed)','RuntimeCompileOOMError','j.Payload != "{}"','status != "installed"','verification != "sha256:"+r.SHA256'])assert(core.includes(v),v);
});
test('producer changes are precisely reversible and final held-byte rehash is mandatory without budget growth',()=>{
 const current=read('internal/executor/install_linux.go'),leaf=read('internal/executor/runtime_php_publication_linux.go'),tick=String.fromCharCode(96);
 const waiting='waitRuntimePHPWorkerMemory(ctx, release)';
 assert.equal(current.split(waiting).length,2);
 const install=current.replace(waiting,'admitRuntimePHPWorkerMemory(release)');
 const field='\tPublication     *RuntimePHPPublication  '+tick+'json:"publication,omitempty"'+tick+'\n';
 const seal='\t\tmanifest.Publication, e = sealRuntimePHPPublication(ctx, r, id, temp, RunCommand)\n\t\tif e != nil {\n\t\t\treturn e\n\t\t}\n\t\tif e = add(core.RuntimePHPPublicationStep); e != nil {\n\t\t\treturn e\n\t\t}\n';
 assert.equal(install.split(field).length,2);assert.equal(install.split(seal).length,2);
 assert.equal(sha(install),'103a96d8e164515ffb8c950ca12ce54048c3ac422cf666bd1a5655fd4ce50f51');
 assert.equal(sha(install.replace(field,'').replace(seal,'')),'8b1613ff3f7fa0d926383d6847ba987071bb9dd2bbd06871c94c29602bc48c82');
 for(const v of ['prefix != r.Prefix()+".pending-"+id','runtimecatalog.RuntimeInstallAdmission(r)','os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC','make([]byte, 32<<10)','total > 256<<20','f.file.Seek(0, io.SeekStart)','got != want','!tree.bytesCurrent(ctx)','filepath.Join(prefix, "sbin/php-fpm"), "-n", "-v"'])assert(leaf.includes(v),v);
 assert(!/context\.WithTimeout|context\.WithoutCancel|time\.Sleep/.test(leaf));
 const native=read('internal/executor/runtime_php_publication_linux_test.go'),whole=read('internal/executor/program_upgrade_runtime_successor_linux_test.go');
 for(const v of ['"file-bytes"','"file-replace-same-bytes"','"manifest-replace"','"publisher-replace"','if w.final()'])assert(native.includes(v),v);
 assert(whole.includes('f.WriteAt([]byte("changed same-size original model"), 100)'));
});

test('new observation is one closed three-unit13-field read with unchanged per-unit byte limits',()=>{
 const text=read('internal/executor/program_upgrade_ids_units_linux.go');
 for(const value of['3*4096+2','len(block)+1 > 4096','len(blocks) != 3','seen[unit]','programQueueIDSIdleUnit(unit, block+"\\n")','ctx == nil || ctx.Err() != nil || run == nil','err != nil || ctx.Err() != nil || !programQueueIDSIdleUnits(raw)','reflect.DeepEqual(args, programQueueIDSUnitArgs())'])assert(text.includes(value),value);
 assert.equal((text.match(/raw, err := run\(ctx, "\/usr\/bin\/systemctl"/g)||[]).length,1);
 assert(!/context\.With|time\.After|time\.Sleep|exec\.|os\.|WriteFile|Mkdir|reset-failed/.test(text));
 assert(text.includes('return []string{"show", threatIDSService, "panel-network-ids-check.service", "panel-network-ids-recover.service", programQueueIDSUnitProperties}'));
});
test('Linux unit models keep missing duplicate modified cancellation no-cache and fixed-command cases',()=>{
 const text=read('internal/executor/program_upgrade_ids_units_linux_test.go');
 for(const value of['TestProgramQueueIDSCompleteThreeUnitSnapshotPreservesAllOldPredicates','TestProgramQueueIDSObservationCommandIsStillClosed','TestProgramQueueIDSFreshSnapshotUsesOneReadAndNeverCachesOrExtendsDeadline','calls != 2','context.WithCancel','LoadState=not-found','MainPID=123','Job=123 start','DropInPaths=/foreign.conf','NeedDaemonReload=yes','Transient=yes','ExecMainStatus=1','Id=foreign-'])assert(text.includes(value),value);
 assert(!text.includes('t.Skip('));
});
test('real QA observes the entire original5s entrypoint three times and is not installer acceptance',()=>{
 const text=read('internal/executor/program_upgrade_ids_units_native_qa_linux_test.go');
 for(const value of['PANEL_NATIVE_QUEUE_OBSERVATION_QA_ROOT','native-queue-observation24bmbh','CheckProgramUpgradeQueues()','5*time.Second','attempt < 3','no_installer_or_service_action=true'])assert(text.includes(value),value);
 assert(!text.includes('time.Sleep')&&!text.includes('context.WithoutCancel')&&!text.includes('reset-failed'));
});

