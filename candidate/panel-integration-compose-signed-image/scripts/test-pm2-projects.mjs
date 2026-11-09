import assert from 'node:assert/strict';
import test from 'node:test';
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {beforePM2ProjectsBuild} from './release-build-baseline.mjs';
import ts from '../web/node_modules/typescript/lib/typescript.js';
import {pm2ProjectsReadKnown,pm2StopReplyMatches} from '../web/src/pm2Projects.ts';

const project=()=>({app:{id:'owned-project',site_id:'a'.repeat(32),revision:7,entry:'app.js',port:24431},original_project_sha256:'b'.repeat(64),state:'active',state_known:true,boot_enabled:true});
const page=()=>({apps:[project()],unreadable_projects:[],total:1,limit:32,offset:0,project_page_complete:true,projects_readonly:true,configuration_not_inspected:true,configuration_or_deployment_replayed:false,history_or_report_written:false});
const stopped=()=>({id:'owned-project',action:'stop',ok:true,state:'inactive',boot_enabled:false,service_outcome_verified:true,configuration_preserved:true,configuration_or_deployment_replayed:false,original_project_sha256:'b'.repeat(64),history_persisted:true,last_report_persisted:true});

test('mandatory PM2 gate is exactly additive to the original signed C68r3 build contract',()=>{
 const text=readFileSync(new URL('../packaging/build-release.sh',import.meta.url),'utf8');
 const addition='(cd "$BUILD_ROOT" && /opt/homebrew/bin/node --test scripts/test-pm2-projects.mjs) 2>&1 | tee -a "$STAGE/$NAME/BUILD_CHECKS.txt"\n';
 assert.equal(createHash('sha256').update(beforePM2ProjectsBuild(text)).digest('hex'),'5a6a416b51cb0f0c7844a41c47ff2aa239ba8364ff7475e8b95be286b065cdb2');
 for(const changed of [text.replace(addition,''),text.replace(addition,addition+addition),text.replace(addition,addition.replace('--test','--check')),text.replace(addition,'')+addition])assert.throws(()=>beforePM2ProjectsBuild(changed));
});

test('read-only pages preserve unknown projects and unavailable services instead of inventing an empty success',()=>{
 assert.equal(pm2ProjectsReadKnown(page()),true);
 const unknown=page();Object.assign(unknown.apps[0],{state:'unknown',state_known:false,boot_enabled:null,error:'Original observation unavailable'});unknown.project_page_complete=false;
 assert.equal(pm2ProjectsReadKnown(unknown),true);
 const unreadable=page();unreadable.apps=[];unreadable.unreadable_projects=[{resource_id:'owned-project',state:'unknown',error:'Original project retained'}];unreadable.project_page_complete=false;
 assert.equal(pm2ProjectsReadKnown(unreadable),true);
 assert.equal(pm2ProjectsReadKnown({...unreadable,project_page_complete:true}),false);
 assert.equal(pm2ProjectsReadKnown({...unknown,project_page_complete:true}),false);
 assert.equal(pm2ProjectsReadKnown({...page(),apps:[]}),false);
 const duplicate=page();duplicate.apps.push(project());duplicate.total=2;
 assert.equal(pm2ProjectsReadKnown(duplicate),false);
 const secret=page();secret.apps[0].app.environment_cipher='original-private-value';assert.equal(pm2ProjectsReadKnown(secret),false);
 const forged=page();forged.apps[0].app.revision=Number.MAX_SAFE_INTEGER+1;assert.equal(pm2ProjectsReadKnown(forged),false);
 for(const patch of [{limit:65},{offset:2},{total:513},{history_or_report_written:true},{configuration_not_inspected:false},{configuration_or_deployment_replayed:true},{projects_readonly:false}])assert.equal(pm2ProjectsReadKnown({...page(),...patch}),false);
});

test('only an exact project stop receipt can separate service outcome from failed persistence',()=>{
 assert.equal(pm2StopReplyMatches('owned-project',stopped()),true);
 assert.equal(pm2StopReplyMatches('different-project',stopped()),false);
 for(const patch of [{ok:false},{state:'unknown'},{state:'active'},{boot_enabled:true},{service_outcome_verified:false},{configuration_preserved:false},{configuration_or_deployment_replayed:true},{original_project_sha256:'x'},{history_persisted:undefined},{last_report_persisted:undefined},{history_persisted:false},{last_report_persisted:false}])assert.equal(pm2StopReplyMatches('owned-project',{...stopped(),...patch}),false);
 assert.equal(pm2StopReplyMatches('owned-project',{...stopped(),history_persisted:false,last_report_persisted:false,persistence_warning:'Service stopped; original records retained.'}),true);
 assert.equal(pm2StopReplyMatches('owned-project',{...stopped(),last_report_persisted:false,persistence_warning:'Original report could not be saved.'}),true);
});

test('actual component retains a verified stop receipt while refreshing by GET, including persistence and refresh failures',async()=>{
 const source=readFileSync(new URL('../web/src/AppModuleManager.vue',import.meta.url),'utf8');
 const execute=source.slice(source.indexOf('async function execute('),source.indexOf('async function reviewRemoteTicket('));
 const code=ts.transpileModule(execute,{compilerOptions:{target:ts.ScriptTarget.ES2022}}).outputText;
 for(const mode of ['healthy','persistence-failed','refresh-failed','foreign-reply']) {
  const calls=[];let manualRead=false;
  const bindings={definition:{value:{id:'pm2-manager',actions:['run','stop']}},installed:{value:true},installedUnknown:{value:false},integrityModule:{value:false},visible:{value:true},busy:{value:false},error:{value:''},reportStateUnknown:{value:true},report:{value:undefined},form:{value:{resource_id:'owned-project',expected_revision:7}},selectedPlanID:{value:'owned-project'},pm2StopOutcome:{value:undefined},pm2ProjectOffset:{value:0},pm2ConfigurationObservation:{value:undefined},pm2ProjectsReadKnown,pm2StopReplyMatches,canExecutePHP:()=>true,idsAccessGeneration:1,inputBody:()=>({resource_id:'owned-project',expected_revision:7}),setReport:v=>{bindings.report.value=v;bindings.reportStateUnknown.value=false;},ElMessage:{success:()=>{}},props:{api:async(path,method,body)=>{
   calls.push({path,method,body});
   if(path.endsWith('/stop'))return {...stopped(),...(mode==='foreign-reply'?{id:'different-project'}:{}),...(mode==='persistence-failed'?{history_persisted:false,last_report_persisted:false,persistence_warning:'Original records retained; service independently stopped.'}:{})};
   assert.equal(path,'/app-modules/pm2-manager/projects?limit=32&offset=0');assert.equal(method,'GET');assert.equal(body,undefined);
   if(mode==='refresh-failed'&&!manualRead)throw Error('Original service list unavailable');
   return page();
  }}};
  const actions=new Function('bindings','with(bindings){'+code+';return {execute,readPM2Projects};}')(bindings);
  await actions.execute('stop');
  assert.equal(calls.filter(x=>x.method==='POST').length,1);assert.equal(bindings.busy.value,false);
  if(mode==='foreign-reply') {assert.equal(calls.length,1);assert.equal(bindings.pm2StopOutcome.value,undefined);assert.match(bindings.error.value,/回执/);continue;}
  assert.equal(calls.length,2,bindings.error.value);assert.equal(bindings.pm2StopOutcome.value.id,'owned-project');
  if(mode==='persistence-failed')assert.match(bindings.pm2StopOutcome.value.persistence_warning,/retained/);
  if(mode==='refresh-failed') {assert.match(bindings.error.value,/已收到原项目停止/);manualRead=true;await actions.readPM2Projects();assert.equal(calls.length,3);assert.equal(calls.filter(x=>x.method==='POST').length,1);}
  else assert.equal(bindings.reportStateUnknown.value,true,'live observation must not repair an unknown stored report');
 }
});
