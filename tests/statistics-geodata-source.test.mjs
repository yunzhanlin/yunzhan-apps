import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile,lstat} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {validateManifest} from '../tools/lib.mjs';
const root=fileURLToPath(new URL('../panel-integration-geography/',import.meta.url));
const read=p=>readFile(path.join(root,p));
const sha=b=>createHash('sha256').update(b).digest('hex');
test('current geography/WAF/retention/repository/export implementation is exact signed BEXH source; earlier source indexes are retained',async()=>{
 const index=JSON.parse(await read('source-sha256.json')),release=JSON.parse(await read('release-source-inputs.json'));
 assert.deepEqual(index.release,{archive:'panel-0.1.0-dev.proapps24geoevidencebexh-linux-amd64.tar.gz',archive_sha256:'cd30cc376ba6c827bccc6f480c0e6c1f805adea30c99c351bd6f0332a2ef9434',frozen_inputs_sha256:'83ff19a32f424744c5d0850460a38ce7e1901aca129ade1a80d4c5d0925055d0'});
 assert.equal(Object.keys(index.files).length,1292);assert.equal(Object.keys(index.test_overrides??{}).length,0);
 for(const [name,digest]of Object.entries(index.files)){
  assert(!name.startsWith('/')&&!name.split('/').includes('..'));
  const s=await lstat(path.join(root,name));assert(s.isFile()&&!s.isSymbolicLink());
  assert.equal(sha(await read(name)),digest,name);
 }
 assert.deepEqual(index.release,{archive:release.archive,archive_sha256:release.archive_sha256,frozen_inputs_sha256:release.frozen_inputs_sha256});
 for(const [name,digest]of Object.entries(release.files))assert.equal(index.files[name],digest,name);
 for(const p of ['internal/geodata/geodata.go','internal/geodata/structure_stream.go','internal/executor/app_statistics_geodata_cache.go','internal/executor/app_statistics_geodata_store_linux.go','internal/executor/app_statistics_geodata_verify_linux.go','internal/appcatalog/panel_features.go','internal/core/statistics_geodata_export.go','internal/executor/app_statistics_geodata_export_linux.go'])assert(Object.hasOwn(release.files,p),p);
});
test('candidate history remains integration and signed2.6 delivery keeps commercial qualification unproven',async()=>{
 const candidate=JSON.parse(await readFile(new URL('../registry/candidates/website-statistics-v2-2.6.0.json',import.meta.url)));
 assert.equal(candidate.stage,'integration');assert.deepEqual(validateManifest(candidate),[]);
 const catalog=JSON.parse(await readFile(new URL('../dist/catalog-v1.json',import.meta.url)));
 assert.equal(catalog.apps.find(a=>a.id===candidate.id).version,'2.6.0');
 const manifest=JSON.parse(await readFile(new URL('../dist/apps/website-statistics-v2/2.6.0/manifest.json',import.meta.url)));
 assert.deepEqual(validateManifest(manifest),[]);assert.equal(manifest.stage,'ready');assert.match(manifest.summary,/商用.*仍在验收/);
 const schema=JSON.parse(await readFile(new URL('../schema/app.schema.json',import.meta.url)));
 const clause=schema.allOf.find(c=>c.if?.properties?.version?.const==='2.6.0');
 assert.deepEqual(clause.then.required,['geo_data_channel','required_panel_features']);
 assert.deepEqual(clause.then.properties.required_panel_features.allOf.map(v=>v.contains.const),candidate.required_panel_features);
});
