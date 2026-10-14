// Source/evidence integrity only; does not manufacture or repeat native proof.
import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
const read=p=>readFile(new URL('../'+p,import.meta.url)),sha=b=>createHash('sha256').update(b).digest('hex');
const prior=p=>'registry/reviewed-sources/0.1.0-dev.proapps24siteselectbfhe/'+p;
test('site picker fix has a new exact frozen signed source and preserves original BFFR authority',async()=>{
 const r=JSON.parse(await read('registry/module-site-picker-release.json')),i=JSON.parse(await read(prior('source-sha256.json'))),f=JSON.parse(await read(prior('release-source-inputs.json')));
 assert.equal(sha(await read(prior('source-sha256.json'))),'8460b19bce554247e4d4c5d8d26334d1c52388d070fcc6a98c72f84c78815868');assert.equal(sha(await read(prior('release-source-inputs.json'))),'67856ff5ef2c2c8615da20900969a723f16b334a9e0779326ffd7730263e3fd9');
 const oldRaw=await read('registry/reviewed-sources/0.1.0-dev.proapps24diskinodebffr/source-sha256.json'),old=JSON.parse(oldRaw);
 assert.equal(sha(oldRaw),'31f507d0e49c93d31e72ce6866bebca1215f5fcc6073d5f37e1582cb80a86631');assert.equal(sha(await read('registry/reviewed-sources/0.1.0-dev.proapps24diskinodebffr/release-source-inputs.json')),'1595e16876c99f684b2ddf5674f5e296c1c78053d438bb250355985a0455865e');
 assert.deepEqual(i.release,{archive:'panel-'+r.program+'-linux-amd64.tar.gz',archive_sha256:r.normal_original_key_archives.amd64,frozen_inputs_sha256:r.source_inputs_sha256});assert.equal(f.frozen_inputs_sha256,r.source_inputs_sha256);
 assert.deepEqual(Object.keys(i.files).filter(k=>i.files[k]!==old.files[k]).sort(),r.only_source_changes);assert.deepEqual(Object.keys(old.files).filter(k=>!(k in i.files)),[]);assert.deepEqual(i.test_overrides??{},{});assert.equal(r.source_overrides,0);
 for(const name of r.only_source_changes){assert.equal(i.files[name],f.files[name]);assert.equal(sha(await read(prior(name))),i.files[name]);}
 const manager=(await read(prior('web/src/AppModuleManager.vue'))).toString(),start=manager.indexOf('v-else-if="field.kind === \'site\'"'),control=manager.slice(start,manager.indexOf('</el-select>',start));
 for(const text of [':teleported="false"',':persistent="false"','filterable','clearable','v-model="form[field.key]"',':value="site.id"'])assert(control.includes(text));
 assert(!manager.includes('window.ResizeObserver')&&!manager.includes('ResizeObserver loop'));
});
test('old installed data proof and real UI failures remain separate from diagnostics and new UI deployment',async()=>{
 const r=JSON.parse(await read('registry/module-site-picker-release.json')),e={};for(const [name,pin]of Object.entries(r.evidence_sha256)){const b=await read('registry/reviewed-site-picker/24bfhe/'+name);assert.equal(sha(b),pin,name);e[name]=JSON.parse(b);}
 for(const arch of ['arm64','amd64']){const p=e['program-'+arch+'.json'];assert.equal(p.ok,true);assert.equal(p.version,r.previous_program);assert.equal(p.source_inputs_sha256,r.reviewed_previous_program_qa.source_inputs_sha256);assert.equal(p.application_installs_updates,0);assert.equal(p.protected_table_projections_unchanged,94);assert.equal(p.app_records,20);assert.equal(p.nginx_master_pid,r.reviewed_previous_program_qa[arch+'_nginx_pid']);assert.equal(p.disk_analysis_version,r.reviewed_previous_program_qa[arch+'_original_disk_app_version']);
  const ui=e['installed-ui-failure-'+arch+'.json'];assert.equal(ui.ok,false);assert.equal(ui.program,r.previous_program);assert.equal(ui.native_metadata_checks.length,2);assert(ui.geometry.window_errors.some(s=>s.includes('ResizeObserver loop')));assert.equal(ui.application_installs_updates,0);
 }
 const diag=e['select-props-diagnostic.json'];assert.equal(diag.ok,true);assert.equal(diag.unmodified_application_ui_acceptance,false);assert.equal(diag.patched_selects[0].persistent,false);assert.equal(diag.patched_selects[0].teleported,false);
 const source=e['source-ui.json'],index=JSON.parse(await read(prior('source-sha256.json')));assert.equal(source.ok,true);assert.equal(source.installed_fixed_release_acceptance,false);assert.equal(source.source_inputs_sha256,r.source_inputs_sha256);for(const [name,pin]of Object.entries(source.sources))assert.equal(index.files[name],pin,name);assert.equal(source.original_open_dropdown_document_width,449);assert.equal(source.fixed_open_dropdown_document_width,390);assert.deepEqual(source.window_errors,[]);
 for(const key of ['commercial_all50','main_delivered','catalog_and_all50_packages_changed','historical_bffr_evidence_and_failures_rewritten'])assert.equal(r[key],false,key);assert.equal(r.verification.installed_new_fixed_release_ui_verified,false);assert.equal(r.application_installs_updates,0);
});
