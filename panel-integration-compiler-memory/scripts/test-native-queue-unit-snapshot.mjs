// Static frozen-input contracts only. Linux behavior has a separate real QA gate.
import test from'node:test';import assert from'node:assert/strict';import fs from'node:fs';import path from'node:path';import{fileURLToPath}from'node:url';import{createHash}from'node:crypto';
const root=fileURLToPath(new URL('..',import.meta.url)),read=n=>fs.readFileSync(path.join(root,n),'utf8'),sha=b=>createHash('sha256').update(b).digest('hex');
test('all original13-property unit predicates and original global5s full reader stay byte exact',()=>{
 const ids=read('internal/executor/program_upgrade_ids_linux.go'),queues=read('internal/executor/program_upgrade_queues_linux.go');
 assert.equal(sha(ids.slice(ids.indexOf('func programQueueIDSIdleUnit('))),"c6180dba37d9036f10ea0ad032ac9885a9c6306519bf23e2a10e46d3cb094488");
 assert.equal(sha(queues),"7a365f2a28a5b38f93266450fe4d27f98084517b69da4c4ebb4fc47624da7da4");
 assert(queues.includes('context.WithTimeout(context.Background(), 5*time.Second)'));
 const originalLoop="\tfor _, unit := range []string{threatIDSService, \"panel-network-ids-check.service\", \"panel-network-ids-recover.service\"} {\n\t\traw, err := s.Config.Run(ctx, \"/usr/bin/systemctl\", \"show\", unit, \"--property=Id,LoadState,ActiveState,SubState,MainPID,Job,FragmentPath,DropInPaths,Transient,NeedDaemonReload,UnitFileState,ExecMainCode,ExecMainStatus\")\n\t\tif err != nil || !programQueueIDSIdleUnit(unit, raw) {\n\t\t\treturn nil, errors.New(\"IDS recovered native unit is not trusted and idle; upgrade refused\")\n\t\t}\n\t}\n",newLoop="\tif err := programQueueIDSVerifyIdleUnits(ctx, s.Config.Run); err != nil {\n\t\treturn nil, err\n\t}\n",oldCommand="\tif name != \"/usr/bin/systemctl\" || len(args) != 3 || args[0] != \"show\" || (args[1] != threatIDSService && args[1] != \"panel-network-ids-check.service\" && args[1] != \"panel-network-ids-recover.service\") || args[2] != \"--property=Id,LoadState,ActiveState,SubState,MainPID,Job,FragmentPath,DropInPaths,Transient,NeedDaemonReload,UnitFileState,ExecMainCode,ExecMainStatus\" {";
 assert.equal(ids.split(newLoop).length,2);
 const command='\tif !programQueueIDSObservationCommand(name, args) {';
 assert.equal(ids.split(command).length,2);
 const reversed=ids.replace(newLoop,()=>originalLoop).replace(command,()=>oldCommand);
 assert.equal(sha(reversed),"176122054507f8db2dad933590fc0428cb6b315702ee172ef574681bad11333f");
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

