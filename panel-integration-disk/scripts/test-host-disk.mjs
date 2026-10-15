import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import * as h from '../web/src/hostDisk.ts';
import {access,state,mount,selection,job,reply,finishedReply,capacity} from './host-disk-fixture.mjs';
test('UI candidate capability matches both fixed program gates without claiming installation',()=>{
 const core=readFileSync(new URL('../internal/core/software_apps.go',import.meta.url),'utf8');
 const worker=readFileSync(new URL('../internal/diskjob/contract.go',import.meta.url),'utf8');
 assert(core.includes('const DiskAnalysisAppVersion = "'+h.hostDiskVersion+'"'));
 assert(worker.includes('const HostAppVersion = "'+h.hostDiskVersion+'"'));
});
test('full host authority does not follow a single menu or an old role',()=>{
 assert(h.hostDiskAllowed(access));
 for(const v of [undefined,null,{role:'admin',menu_ids:['system-tools']},{...access,role:'operator'},{...access,menu_ids:[...access.menu_ids,'future']}])assert.equal(h.hostDiskAllowed(v),false);
});
test('whole sanitized inventory requires current instance and excludes remote, virtual and malformed mounts',()=>{
 assert(h.validHostState(state));assert.deepEqual(h.hostSelection(state,'31',''),selection);
 const extra=structuredClone(state);extra.inventory.host.actor_id='untrusted';assert.deepEqual(h.hostSelection(extra,'31',''),selection);
 assert.equal(h.hostSelection(state,'32',''),undefined);
 for(const alter of [s=>s.inventory.inventory.mount_list_complete=false,s=>s.inventory.inventory.mounts.push({...mount}),s=>s.inventory.inventory.mounts[0]=null,s=>s.inventory.host.mount_namespace_id='0:0',s=>s.app_manifest_sha256='',s=>s.inventory.inventory.mounts[0].filesystem_class='future']){const s=structuredClone(state);alter(s);assert.equal(h.validHostState(s),false);}
 assert(h.validHostState({format:1,installed:true,app_version:'1.3.0',installation_id:'',app_manifest_sha256:'',inventory:null}));
});
test('path choices are literal Linux relative paths, not decoded URLs or shell commands',()=>{
 for(const p of ['', 'srv/example', '中文/😀', 'a\\b', '%2e%2e'])assert(h.hostRelative(p),p);
 for(const p of ['/etc','../etc','a/../b','a//b','a/','a\nb','\ud800','x'.repeat(4096)])assert.equal(h.hostRelative(p),false,p);
 assert.equal(h.hostSelection(state,'31','../etc'),undefined);
});
test('decimal values retain uint64 precision; unknown is never zero',()=>{
 assert.equal(h.hostBytes('0'),'0 B');assert.equal(h.hostBytes('1024'),'1.0 KiB');assert.equal(h.hostCount('9007199254740993'),'9007199254740993');
 assert.equal(h.hostBytes('18446744073709551615'),'15.9 EiB');
 for(const v of [null,undefined,0,-1,'01','1.0','18446744073709551616']){assert.equal(h.hostBytes(v),'未知');assert.equal(h.hostCount(v),'未知');}
 assert.equal(h.hostCapacityValue(capacity,'total_bytes'),'1.0 TiB');assert.equal(h.hostCapacityValue(capacity,'free_inodes'),'未知');
 assert.equal(h.hostCapacityValue({...capacity,state:'unavailable'},'total_bytes'),'未知');
});
test('original job and typed receipt identity cannot be swapped; settling is not completed',()=>{
 assert(h.validHostJob(job));assert(h.validHostReply(reply,job));assert(h.validHostReply(finishedReply,job));
 for(const change of [r=>r.job.id='a'.repeat(32),r=>r.job.request.actor_id='a'.repeat(32),r=>r.terminal_verified=true,r=>r.observation.request.selection.mount_binding_sha256='a'.repeat(64),r=>r.observation.progress.report.regular_allocated_bytes=123]){const r=structuredClone(reply);change(r);assert.equal(h.validHostReply(r,job),false);}
 const settling=structuredClone(reply);settling.observation.state='settling';settling.observation.result=structuredClone(finishedReply.result);assert(h.validHostReply(settling,job));
 const invalid=structuredClone(finishedReply);invalid.result.report.enumeration_complete=true;assert.equal(h.validHostReply(invalid,job),false);
 const failed=structuredClone(finishedReply);failed.job.state='failed';failed.result.state='failed';failed.result.report.state='failed';failed.result.report.index_flushed=false;assert(h.validHostReply(failed,job));
});
test('directory drill is checked against the original mount and only chooses a new range',()=>{
 const row={path:'/srv/example/a.bin',logical_bytes:'0',allocated_bytes:'0',path_actionable:true,link_count:1};
 assert.equal(h.hostDrillDirectory(mount,row,false),'srv/example');
 assert.equal(h.hostDrillDirectory({...mount,mount_point:'/srv/example'},row,false),'');
 for(const r of [{...row,path:'/srv/../etc'},{...row,path_actionable:false},{...row,path:'/srv/examples/foreign'}])assert.equal(h.hostDrillDirectory({...mount,mount_point:'/srv/example'},r,true),undefined);
 assert.equal(h.hostDrillDirectory(undefined,row,true),undefined);
 const component=readFileSync(new URL('../web/src/HostDiskWorkspace.vue',import.meta.url),'utf8');
 const choose=component.slice(component.indexOf('function chooseDirectory('),component.indexOf('function exportResult('));assert.doesNotMatch(choose,/props\.api|submit\(|submitOriginal\(/);
 assert.doesNotMatch(component,/localStorage|sessionStorage|v-html|innerHTML|reset-failed/);
 assert.match(component,/base \+ '\/requests\/' \+ original.key/);
 assert.match(component,/props\.api<.*>\(base \+ '\/jobs', 'POST', original.selection, original.key\)/);
});
