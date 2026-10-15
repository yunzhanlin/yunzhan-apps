import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {platformFleetView,platformBytes,platformHostFilter} from '../web/src/platformHealthView.ts';
const at='2026-10-15T20:00:00Z',now=Date.parse(at);
function sample(){return {hosts:[{id:'first-host',url:'https://example.invalid',expected_sha:'a'.repeat(64),healthy:true,telemetry_complete:true,status:200,report:{version:'app-modules-1',time:at,health:{cpu_cores:2,cpu_available:true,cpu_percent:0,memory_available:true,memory_percent:25,memory_total:4096,memory_used:1024,disk_percent_available:true,disk_percent:50,disk_total:8192,disk_used:4096,nginx_active:false,sampled_at:at,hostname:'original-host',os:'Debian GNU/Linux 13',arch:'amd64'}}}],checked_at:at,scope:'HTTPS and health protocol only'};}
test('view keeps measured zero, exact original identity, all percentages, capacities and inactive Nginx',()=>{
 const raw=sample(),v=platformFleetView(raw,now);assert(v);assert.equal(v.hosts[0].source,raw.hosts[0]);assert.equal(v.hosts[0].metrics[0].percent,0);assert.equal(v.hosts[0].metrics[1].capacity,'1.0 KiB / 4.0 KiB');assert.equal(v.hosts[0].nginx,'未运行');assert.equal(v.passed,1);assert.equal(v.unknownMetrics,0);assert.equal(v.stale,false);
 assert.equal(platformBytes(Number.MAX_SAFE_INTEGER),'8.0 PiB');for(const n of [-1,NaN,Infinity,'0',null])assert.equal(platformBytes(n),'未知');
});
test('unavailable CPU is unknown, not measured zero or fully complete telemetry',()=>{
 const raw=sample();Object.assign(raw.hosts[0].report.health,{cpu_available:false,cpu_percent:null});raw.hosts[0].telemetry_complete=false;
 const v=platformFleetView(raw,now);assert(v);assert.equal(v.hosts[0].metrics[0].percent,null);assert.equal(v.passed,1);assert.equal(v.unknownMetrics,1);assert.equal(v.hosts[0].metrics[1].percent,25);
});
test('real failures never carry old metrics, and no partial or duplicate inventory is silently rendered',()=>{
 const raw=sample(),failure={id:'second-host',url:'https://second.invalid',expected_sha:'b'.repeat(64),healthy:false,telemetry_complete:false,status:401,error:'Protocol denied'};raw.hosts.push(failure);
 const v=platformFleetView(raw,now);assert.deepEqual(v.hosts.map(h=>h.id),['first-host','second-host']);assert.equal(v.failed,1);assert.equal(v.hosts[1].metrics.every(m=>m.percent===null),true);assert.equal(v.hosts[1].nginx,'未知');
 for(const mutate of [r=>r.hosts.push({...r.hosts[0]}),r=>r.hosts[1].report=r.hosts[0].report,r=>r.hosts[1].status='401',r=>r.hosts[1].status=999,r=>r.hosts[0].token='unwanted',r=>r.partial=true]){const r=structuredClone(raw);mutate(r);assert.equal(platformFleetView(r,now),undefined);}
});
test('contradictory availability, coercion, invalid capacities and telemetry mismatch fail closed',()=>{
 for(const mutate of [h=>h.cpu_percent='0',h=>h.cpu_percent=NaN,h=>h.cpu_percent=101,h=>h.cpu_available=false,h=>h.memory_used=4097,h=>h.memory_total=0,h=>h.memory_available='true',h=>delete h.disk_percent,h=>h.disk_percent=-1,h=>h.cpu_cores=0,h=>h.sampled_at='invalid',h=>h.nginx_active='false']){const r=sample();mutate(r.hosts[0].report.health);assert.equal(platformFleetView(r,now),undefined);}
 const r=sample();r.hosts[0].telemetry_complete=false;assert.equal(platformFleetView(r,now),undefined);
});
test('a retained or future-clock snapshot is explicitly stale without inventing a new check',()=>{
 assert.equal(platformFleetView(sample(),now+120001).stale,true);assert.equal(platformFleetView(sample(),now-30001).stale,true);assert.equal(platformFleetView(sample(),now+120000).stale,false);
 const empty={hosts:[],checked_at:at,scope:'empty actual snapshot'};assert.deepEqual(platformFleetView(empty,now).hosts,[]);assert.equal(platformFleetView({...empty,hosts:Array(13).fill(sample().hosts[0])},now),undefined);
});
test('local query and status filtering preserve registration order and never alter original SHA',()=>{
 const r=sample();r.hosts.push({...structuredClone(r.hosts[0]),id:'second-host',url:'https://another.invalid'});const v=platformFleetView(r,now);
 assert.deepEqual(platformHostFilter(v.hosts,'DEBIAN','all').map(h=>h.id),['first-host','second-host']);assert.deepEqual(platformHostFilter(v.hosts,'another','all').map(h=>h.id),['second-host']);assert.deepEqual(platformHostFilter(v.hosts,'','failed'),[]);assert.deepEqual(platformHostFilter(v.hosts,'','unknown'),[]);assert.equal(r.hosts[0].expected_sha,'a'.repeat(64));
});
test('actual component uses accessible wrapping cards, explicit availability and original selection without side effects',()=>{
 const component=readFileSync(new URL('../web/src/PlatformHealthReport.vue',import.meta.url),'utf8');assert.match(component,/metric.percent===null\?'未知'/);assert.match(component,/v-if="metric.percent!==null"/);assert.match(component,/emit\('select',host.source\)/);assert.match(component,/<time :datetime=/);assert.match(component,/<details/);assert.match(component,/保持登记顺序/);assert.match(component,/clearInterval\(timer\)/);assert.match(component,/@media\(max-width:640px\)/);assert.doesNotMatch(component,/v-html|fetch\(|props.api|localStorage|sessionStorage/);
 const parent=readFileSync(new URL('../web/src/AppModuleReport.vue',import.meta.url),'utf8');assert.match(parent,/<PlatformHealthReport v-else-if="id==='platform-ops' && report.hosts !== undefined" :report="report" @select="choose"/);
});
