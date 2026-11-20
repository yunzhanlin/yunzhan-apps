import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';
assert.equal(process.platform,'linux');assert(['x64','arm64'].includes(process.arch));
assert.equal(process.env.GITHUB_ACTIONS,'true');assert.equal(process.env.GITHUB_REPOSITORY,'yunzhanlin/yunzhan-apps');assert.equal(process.argv.length,4);
const root=fileURLToPath(new URL('../',import.meta.url)),sdk=path.resolve(process.argv[3]),go=fs.realpathSync(process.argv[2]);assert.equal(fs.realpathSync(sdk),sdk);assert.equal(path.basename(sdk),'panel-integration-compose-signed-image');assert(path.isAbsolute(go)&&fs.lstatSync(go).isFile());
const sha=b=>createHash('sha256').update(b).digest('hex');
const legacy=fs.existsSync(path.join(sdk,'source-sha256.json'));
let sdkFiles,metadata,originalSDKInputs,programmeSource;
if(legacy){
 const raw=fs.readFileSync(path.join(sdk,'source-sha256.json'));
 assert.equal(sha(raw),'c43524684f47e9f88c5237f1a19cdb24171c728ebcb1843555b217e3bbdc8bc3');
 const index=JSON.parse(raw);assert.equal(index.release.frozen_inputs_sha256,'7fcf5fe021cefe421ecf1da4c8ac1c5c81e95b075416dbb79dbd11dc92d00830');assert.equal(Object.keys(index.files).length,2668);
 sdkFiles=Object.fromEntries(Object.entries(index.files).map(([name,digest])=>[name,{sha256:digest}]));
 metadata=['source-sha256.json','release-source-inputs.json'];originalSDKInputs=2668;programmeSource=index.release.frozen_inputs_sha256;
}else{
 const raw=fs.readFileSync(path.join(sdk,'SOURCE_INPUTS.json'));
 assert.equal(sha(raw),'926a38003393ae141b75444b393a2966a20ef39099196eacb0229cbcfe564a7b');
 const index=JSON.parse(raw);assert.equal(index.format,1);assert.equal(index.inputs_sha256,'5eaded11f824722c9e6f13de5110946dfab10b9259cd73f38f227af74fc99569');
 assert.equal(Object.keys(index.files).length,18388);
 sdkFiles=Object.fromEntries(Object.entries(index.files).filter(([name])=>!name.startsWith('web/node_modules/')));
 assert.equal(Object.keys(sdkFiles).length,2685);metadata=['SOURCE_INPUTS.json'];originalSDKInputs=2685;programmeSource=index.inputs_sha256;
}
function verifySDK(base,extra=[]){
 const actual=[];
 function visit(dir){for(const name of fs.readdirSync(dir)){const file=path.join(dir,name),st=fs.lstatSync(file);assert(!st.isSymbolicLink()&&fs.realpathSync(file)===file);if(st.isDirectory())visit(file);else{assert(st.isFile()&&st.nlink===1&&st.size<=4<<20);actual.push(path.relative(base,file).split(path.sep).join('/'));}}}
 visit(base);assert.deepEqual(actual.sort(),[...Object.keys(sdkFiles),...metadata,...extra].sort());
 for(const[name,info]of Object.entries(sdkFiles)){
  const file=path.join(base,name),st=fs.lstatSync(file);assert.equal(sha(fs.readFileSync(file)),info.sha256,name);
  if(!legacy){assert.equal(st.size,info.bytes,name);assert.equal(st.mode&0o111,info.mode&0o111,name);}
 }
 // Verify the whole original index again after copying and after native tests.
 if(!legacy)assert.equal(sha(fs.readFileSync(path.join(base,'SOURCE_INPUTS.json'))),'926a38003393ae141b75444b393a2966a20ef39099196eacb0229cbcfe564a7b');
 else assert.equal(sha(fs.readFileSync(path.join(base,'source-sha256.json'))),'c43524684f47e9f88c5237f1a19cdb24171c728ebcb1843555b217e3bbdc8bc3');
}
verifySDK(sdk);const channel=fs.existsSync(path.join(root,'registry/candidate-apps.json'))?'candidate':'stable',publication=channel==='candidate'?path.join(root,'candidate'):root;const catalog=JSON.parse(fs.readFileSync(path.join(publication,'dist/catalog-v1.json')));assert.equal(catalog.apps.length,40);assert.equal(new Set(catalog.apps.map(a=>a.id)).size,40);
const parent=fs.mkdtempSync(path.join(os.tmpdir(),'yunzhan-active40-abi-')),work=path.join(parent,'source');fs.cpSync(sdk,work,{recursive:true,force:false,errorOnExist:true});const observer='internal/appcatalog/current_active40_external_observer_test.go';fs.writeFileSync(path.join(work,observer),fs.readFileSync(path.join(root,'tests/active40-consumer-observer.go')),{flag:'wx'});verifySDK(work,[observer]);
try{const result=spawnSync(go,['test','-json','-count=1','-run','^TestActiveFortySignedManifestABI$','-ldflags=-X local/panel/internal/appcatalog.officialCatalogChannel='+channel,'./internal/appcatalog','-args','-active40-registry-root',publication],{cwd:work,encoding:'utf8',timeout:600000,maxBuffer:4<<20,env:{...process.env,GOTOOLCHAIN:'local',GOFLAGS:'-p=2',GOMAXPROCS:'2',CGO_ENABLED:'0'}});process.stdout.write(result.stdout||'');process.stderr.write(result.stderr||'');assert.equal(result.status,0);assert(!result.error&&!result.signal);const events=result.stdout.trim().split('\n').map(line=>JSON.parse(line));assert(!events.some(e=>e.Action==='skip'||e.Action==='fail'));const passed=events.filter(e=>e.Action==='pass'&&e.Test).map(e=>e.Test).sort();assert.deepEqual(passed,['TestActiveFortySignedManifestABI',...catalog.apps.map(a=>'TestActiveFortySignedManifestABI/'+a.id)].sort());verifySDK(sdk);verifySDK(work,[observer]);console.log(JSON.stringify({ok:true,actual_native_linux_abi:true,architecture:process.arch,channel,applications:40,tests:41,skips:0,failures:0,original_SDK_inputs:originalSDKInputs,programme_source_inputs_sha256:programmeSource,retained_previous_reader_ABI:legacy,production_source_overlays:0,external_test_observers:1,application_installation:false,all40_commercial:false}));}finally{fs.rmSync(parent,{recursive:true,force:true});}
