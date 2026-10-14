// Immutable source and genuine prior failures, not invented installed success.
import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
const read=p=>readFile(new URL('../'+p,import.meta.url)),sha=b=>createHash('sha256').update(b).digest('hex');
test('site picker width fix has independently new frozen archive authority and only two product inputs change',async()=>{
 const r=JSON.parse(await read('registry/module-site-picker-fit-release.json')),i=JSON.parse(await read('registry/reviewed-sources/0.1.0-dev.proapps24sitefitbfhp/source-sha256.json')),f=JSON.parse(await read('registry/reviewed-sources/0.1.0-dev.proapps24sitefitbfhp/release-source-inputs.json'));
 assert.equal(sha(await read('registry/reviewed-sources/0.1.0-dev.proapps24sitefitbfhp/source-sha256.json')),'017a9ded828ea2c70ebb575f32fe0230293ad8102057374e99babaad1a11ebd0');assert.equal(sha(await read('registry/reviewed-sources/0.1.0-dev.proapps24sitefitbfhp/release-source-inputs.json')),'d74fb3d70c56e8e24ebd6307fb7d311e43204b576cc839755a9e573d45a4c258');
 const root='registry/reviewed-sources/'+r.previous_program+'/',oldRaw=await read(root+'source-sha256.json'),old=JSON.parse(oldRaw);assert.equal(sha(oldRaw),r.previous_indexes.source_sha256);assert.equal(sha(await read(root+'release-source-inputs.json')),r.previous_indexes.release_inputs_sha256);
 assert.deepEqual(i.release,{archive:'panel-'+r.program+'-linux-amd64.tar.gz',archive_sha256:r.normal_original_key_archives.amd64,frozen_inputs_sha256:r.source_inputs_sha256});assert.equal(f.frozen_inputs_sha256,r.source_inputs_sha256);assert.deepEqual(i.test_overrides??{},{});assert.equal(r.source_overrides,0);assert.equal(r.frozen_files,16972);
 assert.deepEqual(Object.keys(i.files).filter(p=>i.files[p]!==old.files[p]).sort(),r.only_source_changes);assert.deepEqual(Object.keys(old.files).filter(p=>!(p in i.files)),[]);
 for(const p of r.only_source_changes){assert.equal(i.files[p],f.files[p]);assert.equal(sha(await read('panel-integration-geography/'+p)),i.files[p]);assert.equal(sha(await read(root+p)),old.files[p]);}
 const source=(await read('panel-integration-geography/web/src/AppModuleManager.vue')).toString(),start=source.indexOf('v-else-if="field.kind === \'site\'"'),select=source.slice(start,source.indexOf('</el-select>',start));
 for(const text of [':teleported="false"',':persistent="false"',':fit-input-width="true"','filterable','clearable','v-model="form[field.key]"',':value="site.id"'])assert(select.includes(text),text);assert.doesNotMatch(source,/window\.ResizeObserver\s*=|ResizeObserver loop|ResizeObserver\.prototype/);
});
test('prior BFHE real popup failures and original upgrade proofs remain distinct from new source-only geometry',async()=>{
 const r=JSON.parse(await read('registry/module-site-picker-fit-release.json')),e={};for(const [p,pin]of Object.entries(r.evidence_sha256)){const b=await read('registry/reviewed-site-picker-fit/24bfhp/'+p);assert.equal(sha(b),pin,p);e[p]=JSON.parse(b);}
 for(const arch of ['arm64','amd64']){const p=e['program-'+arch+'.json'];assert(p.ok);assert.equal(p.version,r.previous_program);assert.equal(p.protected_table_projections_unchanged,94);assert.equal(p.app_records,20);assert.equal(p.application_installs_updates,0);
  const ui=e['installed-popup-failure-'+arch+'.json'];assert.equal(ui.ok,false);assert.equal(ui.program,r.previous_program);assert.equal(ui.checks.length,3);assert.deepEqual(ui.closed_geometry.window_errors,[]);assert.deepEqual(ui.open_popup_geometry.window_errors,[]);assert(ui.open_popup_geometry.popup.right>390);assert.deepEqual(ui.assets,[ui.expected_asset]);assert.equal(ui.application_installs_updates,0);
 }
 const ui=e['source-popup.json'];assert(ui.ok);assert.equal(ui.source_inputs_sha256,r.source_inputs_sha256);assert.equal(ui.closed_document_width,390);assert.equal(ui.open_document_width,390);assert(ui.popup.left>=0&&ui.popup.right<=390);assert.equal(ui.visible_options,82);assert.deepEqual(ui.window_errors,[]);assert.equal(ui.installed_acceptance,false);
 const i=JSON.parse(await read('panel-integration-geography/source-sha256.json'));for(const [p,pin]of Object.entries(ui.sources))assert.equal(i.files[p],pin,p);
 assert.equal(e['previous-ci.json'].head,'a7f2e45af641c22d9835063e6779429a5467d122');assert.equal(e['previous-ci.json'].conclusion,'success');
 for(const p of ['commercial_all50','main_delivered','new_full_installed_ui_acceptance','previous_full_installed_ui_acceptance','historical_bffr_and_bfhe_evidence_rewritten','catalog_and_all50_packages_changed'])assert.equal(r[p],false,p);assert.equal(r.application_installs_updates,0);
});
