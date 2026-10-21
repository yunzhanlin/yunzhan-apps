// Pure selectors and the actual compiled report handlers; not native/installed QA.
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import ts from '../web/node_modules/typescript/lib/typescript.js';
import {diskPath,diskDirectorySelection,diskFileSelection,diskValueNotice,diskAllocationBasis} from '../web/src/diskUsage.ts';
const reportSource=readFileSync(new URL('../web/src/AppModuleReport.vue',import.meta.url),'utf8');
const compile=source=>ts.transpileModule(source,{compilerOptions:{target:ts.ScriptTarget.ES2022}}).outputText;

test('drill paths preserve selected root and reject unsafe, malformed and oversized UTF8 paths',()=>{
 assert.deepEqual(diskDirectorySelection('assets','nested'),{path:'assets/nested',drill:true});
 assert.deepEqual(diskDirectorySelection('assets','.'),{path:'assets',drill:true});
 assert.deepEqual(diskDirectorySelection('','.'),{path:'',drill:true});
 assert.deepEqual(diskDirectorySelection('.','nested'),{path:'nested',drill:true});
 for(const value of [null,undefined,[],{},42,'/etc','../etc','a/../b','a//b','a/','a\\b','.panel-private','nested/.panel-record','x\ny','x\u0000y','x\u007fy','\ud800','\udfff']){
  assert.equal(diskPath(value),false,String(value));assert.equal(diskDirectorySelection('assets',value),undefined);assert.equal(diskDirectorySelection(value,'nested'),undefined);
 }
 const part='界'.repeat(85),valid=Array(4).fill(part).join('/');assert.equal(new TextEncoder().encode(valid).length,1023);assert.equal(diskPath(valid),true);
 assert.equal(diskDirectorySelection(valid,'z'),undefined);assert.equal(diskPath(Array(5).fill(part).join('/')),false);
 assert.equal(diskDirectorySelection(undefined,'nested'),undefined);assert.equal(diskDirectorySelection('assets',''),undefined);
});
test('file rows require true original eligibility and a directory matching the complete path',()=>{
 const row=Object.freeze({path:'assets/a.bin',directory:'assets',can_drill:true,bytes:1,token:'not-a-navigation-field'});
 assert.deepEqual(diskFileSelection(row),{path:'assets',drill:true});
 assert.deepEqual(diskFileSelection({path:'a.bin',directory:'.',can_drill:true}),{path:'',drill:true});
 for(const bad of [null,{},[],{...row,can_drill:undefined},{...row,can_drill:false},{...row,can_drill:'true'},{...row,directory:'foreign'},{...row,path:'../../etc'},{...row,path:'broken\nname'},{...row,directory:undefined}])assert.equal(diskFileSelection(bad),undefined);
 assert.equal(row.token,'not-a-navigation-field');
});
test('unknown allocation/filesystem counters stay unknown and genuine zeros remain displayable',()=>{
 const report={allocation_basis:diskAllocationBasis,filesystem_available:true,filesystem_inodes_available:true};
 for(const key of ['total_bytes','allocated_bytes','allocated_file_bytes','unique_logical_bytes','files','unique_files','hardlink_entries','sparse_candidates','filesystem_used_bytes','filesystem_available_bytes','filesystem_reserved_bytes','filesystem_free_inodes']){
  assert.equal(diskValueNotice(report,key,0),undefined,key);
  for(const value of [null,undefined,'0',NaN,Infinity,-1,0.5])assert.equal(diskValueNotice(report,key,value),'未知',key);
  assert.equal(diskValueNotice(report,key,Number.MAX_SAFE_INTEGER+1),'超出精确显示范围');
 }
 assert.equal(diskValueNotice(report,'filesystem_capacity_bytes',0),'未知');
 assert.equal(diskValueNotice({...report,filesystem_available:false},'filesystem_available_bytes',0),'未知');
 assert.equal(diskValueNotice({...report,filesystem_inodes_available:false},'filesystem_free_inodes',0),'未知');
 assert.equal(diskValueNotice({},'allocated_bytes',0),'分配块计算方式未核对');
 assert.equal(diskValueNotice(report,'scan_complete',true),undefined);
});
test('actual compiled report formatter uses availability guards without converting unknown to zero',()=>{
 const code=compile(reportSource.slice(reportSource.indexOf('function format('),reportSource.indexOf('function rows(')));
 const props={id:'disk-analysis',report:{allocation_basis:diskAllocationBasis,filesystem_available:false}};
 const format=new Function('props','diskValueNotice',code+';return format;')(props,diskValueNotice);
 assert.equal(format('filesystem_available_bytes',0),'未知');assert.equal(format('allocated_bytes',null),'未知');
 assert.equal(format('allocated_bytes',0),'0 B');assert.equal(format('unique_files',0),'0');
 props.report.filesystem_available=true;assert.equal(format('filesystem_available_bytes',0),'0 B');
 assert.equal(format('allocated_bytes',Number.MAX_SAFE_INTEGER+1),'超出精确显示范围');
 assert.match(format('allocation_basis',diskAllocationBasis),/inode 去重/);
 props.report.allocation_basis='unproven';assert.equal(format('allocated_bytes',123),'分配块计算方式未核对');
});
test('actual compiled file and directory clicks emit only checked navigation and never mutate inputs',()=>{
 const source=reportSource.slice(reportSource.indexOf('function choose('),reportSource.indexOf('function chartRows('))+reportSource.slice(reportSource.indexOf('function directory('),reportSource.indexOf('function mobileDownloadURL('));
 const props={id:'disk-analysis',report:{path:'assets'}},events=[];
 const {choose,directory}=new Function('props','emit','diskFileSelection','diskDirectorySelection',compile(source)+';return {choose,directory};')(props,(event,row)=>events.push({event,row}),diskFileSelection,diskDirectorySelection);
 choose({path:'assets/a.bin',directory:'assets',can_drill:true});directory('nested');directory('../etc');directory('a\nb');choose(null);choose({path:'/etc',directory:'.',can_drill:true});
 assert.deepEqual(events,[{event:'select',row:{path:'assets',drill:true}},{event:'select',row:{path:'assets/nested',drill:true}}]);
 assert.equal(props.report.path,'assets');assert.doesNotMatch(source,/fetch\(|props\.api|execute\(/);
 assert(reportSource.includes('仅统计，不能下钻'));assert(reportSource.includes('reportLabel(key)'));
});
test('new disk metrics and limitations are translated without claiming sparse extent verification',()=>{
 for(const key of ['allocated_bytes','unique_logical_bytes','unique_files','hardlink_entries','sparse_candidates','filesystem_available_bytes','scan_complete','classification_limited'])assert(reportSource.includes(key));
 for(const text of ['逻辑大小（按路径累计）','稀疏或压缩候选数','不单独证明稀疏区','所在文件系统总容量（非本站占用）'])assert(reportSource.includes(text));
 assert.match(readFileSync(new URL('../packaging/build-release.sh',import.meta.url),'utf8'),/test-disk-usage\.mjs/);
});
test('disk-only bounded native tables keep path controls first and do not restore the resize feedback path',()=>{
 assert.match(reportSource,/v-if="id === 'disk-analysis'" class="disk-table-scroll"/);
 assert.match(reportSource,/v-else-if="id === 'disk-analysis' && key === 'largest_files'" class="disk-table-scroll"/);
 assert.match(reportSource,/v-if="diskFileSelection\(row\)" type="button"/);
 assert.match(reportSource,/v-if="key === 'directories' && diskDirectorySelection\(report\.path, row\.name\)" type="button"/);
 assert.match(reportSource,/\.disk-table-scroll\s*\{[^}]*overflow: auto;/);
 assert.match(reportSource,/\.disk-path-button:focus-visible/);
 assert.doesNotMatch(reportSource,/preventDefault\(|ResizeObserver loop|addEventListener\(['"]error/);
});
