import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {officialCatalogBaseURL} from '../tools/official-channel.mjs';
import {candidateSource} from '../tools/candidate-source.mjs';
import {createHash,createPublicKey,verify} from 'node:crypto';
import {readPreStreamPublication} from './helpers/pre-stream-publication.mjs';
import {schemaBeforeDiskCancel} from './helpers/disk-cancel-schema.mjs';
const read=p=>readFile(new URL('../'+p,import.meta.url),'utf8');

test('publisher channels are two closed official paths without arbitrary URL or fallback',()=>{
  assert.equal(officialCatalogBaseURL(),'https://raw.githubusercontent.com/yunzhanlin/yunzhan-apps/main');
  assert.equal(officialCatalogBaseURL('candidate'),'https://raw.githubusercontent.com/yunzhanlin/yunzhan-apps/refs/heads/codex/app-candidate/candidate');
  for(const value of ['',null,true,{},[], 'main','Stable','candidate\n','https://untrusted.invalid','candidate/../../main'])assert.throws(()=>officialCatalogBaseURL(value));
});

test('actual catalogue URLs agree with the publisher channel and immutable versions',async()=>{
  const source=JSON.parse(await read('registry/apps.json')),catalog=JSON.parse(await read('dist/catalog-v1.json'));
  const base=officialCatalogBaseURL(source.channel===undefined?'stable':source.channel);
  assert.equal(catalog.apps.length,50);
  for(const item of catalog.apps)assert.equal(item.package_url,`${base}/dist/apps/${item.id}/${item.version}/manifest.json`);
  assert.equal(JSON.parse(await read('dist/apps/load-balance/1.8.5/manifest.json')).version,'1.8.5');
  assert.equal(JSON.parse(await read('registry/functional-contracts.json')).commercial_feature_parity_complete,false);
});

test('separate candidate catalogue changes exactly its declared known identities and never mutates stable metadata',async()=>{
  const stable=JSON.parse(await read('registry/apps.json')),patch=JSON.parse(await read('registry/candidate-apps.json'));
  const before=JSON.stringify(stable),source=candidateSource(stable,patch),catalog=JSON.parse(await read('candidate/dist/catalog-v1.json'));
  assert.equal(JSON.stringify(stable),before);assert.equal(source.apps.length,50);
  const changes=source.apps.filter((a,i)=>JSON.stringify(a)!==JSON.stringify(stable.apps[i])).map(a=>a.id);
  assert.deepEqual(changes,['pm2-manager','website-analytics','files-sync','nginx-waf','enterprise-tamper-proof','load-balance','apache-waf','website-tamper-proof','disk-analysis','anti-intrusion','nfs-manager']);assert.deepEqual(patch.apps.map(a=>a.id),['pm2-manager','nginx-waf','load-balance','apache-waf','disk-analysis','anti-intrusion','nfs-manager','website-analytics','website-tamper-proof','enterprise-tamper-proof','files-sync']);assert.equal(stable.apps.find(a=>a.id==='load-balance').version,'1.8.5');assert.equal(stable.apps.find(a=>a.id==='disk-analysis').version,'1.4.0');assert.equal(source.apps.find(a=>a.id==='disk-analysis').version,'1.4.1');
  const originalTamper=stable.apps.find(a=>a.id==='website-tamper-proof'),tamper=source.apps.find(a=>a.id==='website-tamper-proof');assert.equal(originalTamper.version,'1.4.1');assert.equal(tamper.version,'1.5.0');assert.deepEqual(tamper.required_panel_features,['integrity-kernel-inode-journal-v1']);assert.deepEqual(tamper.delivery,originalTamper.delivery);assert.deepEqual(tamper.compatibility,originalTamper.compatibility);
  const originalEnterprise=stable.apps.find(a=>a.id==='enterprise-tamper-proof'),enterprise=source.apps.find(a=>a.id==='enterprise-tamper-proof');assert.equal(originalEnterprise.version,'1.4.1');assert.equal(enterprise.version,'1.5.0');assert.deepEqual(enterprise.required_panel_features,['enterprise-integrity-kernel-ownership-v1']);assert.deepEqual(enterprise.delivery,originalEnterprise.delivery);assert.deepEqual(enterprise.compatibility,originalEnterprise.compatibility);assert.deepEqual(JSON.parse(await read('dist/apps/enterprise-tamper-proof/1.4.1/manifest.json')),originalEnterprise);
  const originalSync=stable.apps.find(a=>a.id==='files-sync'),sync=source.apps.find(a=>a.id==='files-sync');assert.equal(originalSync.version,'1.9.0');assert.equal(sync.version,'2.0.1');assert.deepEqual(sync.required_panel_features,['files-sync-root-independent-backup-v1','files-sync-unpublished-retention-v1']);assert.deepEqual(sync.delivery,originalSync.delivery);assert.deepEqual(sync.compatibility,originalSync.compatibility);assert.deepEqual(JSON.parse(await read('dist/apps/files-sync/1.9.0/manifest.json')),originalSync);assert.deepEqual(JSON.parse(await read('candidate/dist/apps/files-sync/2.0.1/manifest.json')),sync);
  const originalAnalytics=stable.apps.find(a=>a.id==='website-analytics'),analytics=source.apps.find(a=>a.id==='website-analytics');
  assert.equal(originalAnalytics.version,'2.3.1');assert.deepEqual(originalAnalytics.required_panel_features,['analytics-session-lifecycle-v1']);
  assert.equal(analytics.version,'2.4.2');assert.deepEqual(analytics.required_panel_features,['analytics-session-lifecycle-v1','analytics-managed-client-address-v1','analytics-route-readiness-v1','analytics-navigation-order-v1','website-analytics-query-context-v1']);
  assert.deepEqual(analytics.delivery,originalAnalytics.delivery);assert.deepEqual(analytics.compatibility,originalAnalytics.compatibility);
  assert.deepEqual(JSON.parse(await read('dist/apps/website-analytics/2.3.1/manifest.json')),originalAnalytics);
  assert.deepEqual(JSON.parse(await read('candidate/dist/apps/website-analytics/2.4.2/manifest.json')),analytics);
  assert.equal(createHash('sha256').update(await read('candidate/dist/apps/website-analytics/2.3.2/manifest.json')).digest('hex'),'7dc753e299b2801066ae6faa36e92d36169ee0bdc5f992192a5f9dd6861b8a8d');
  assert.equal(createHash('sha256').update(await read('candidate/dist/apps/website-analytics/2.4.0/manifest.json')).digest('hex'),'2c38b82f758ca0aff2c667107d8d35c345281a62a4036985eb81a29c2e195333');
  assert.equal(catalog.apps.find(a=>a.id==='website-analytics').sha256,createHash('sha256').update(await read('candidate/dist/apps/website-analytics/2.4.2/manifest.json')).digest('hex'));
  const originalApache=stable.apps.find(a=>a.id==='apache-waf'),apache=source.apps.find(a=>a.id==='apache-waf');assert.equal(originalApache.version,'2.3.0');assert.equal(apache.version,'2.5.1');assert.deepEqual(apache.required_panel_features,['apache-native-body-site-transactions-v1','apache-native-cc-site-transactions-v1','apache-cc-log-archive-v1']);assert.deepEqual(apache.delivery,originalApache.delivery);assert.deepEqual(apache.compatibility,originalApache.compatibility);
  assert.equal(createHash('sha256').update(await read('dist/apps/apache-waf/2.3.0/manifest.json')).digest('hex'),'77be45eb12785e802943d26bde3fcb76eb3e4cc9bc264f387e67be290f7be6bb');
  assert.equal(createHash('sha256').update(await read('candidate/dist/apps/apache-waf/2.4.0/manifest.json')).digest('hex'),'24c70a38581a46593ad404f07b9ba12e60e8434a2bfacaf36255942063a41038');
  assert.equal(createHash('sha256').update(await read('candidate/dist/apps/apache-waf/2.5.0/manifest.json')).digest('hex'),'fa070a05545a057150c8e1352378c8b41b31416cd6996351a1302e2b0d6c24b9');
  assert.equal(catalog.apps.find(a=>a.id==='apache-waf').sha256,createHash('sha256').update(await read('candidate/dist/apps/apache-waf/2.5.1/manifest.json')).digest('hex'));
  const originalPM2=stable.apps.find(a=>a.id==='pm2-manager'),pm2=source.apps.find(a=>a.id==='pm2-manager');assert.equal(originalPM2.version,'7.0.4-compat5');assert.equal(pm2.version,'7.0.4-compat9');assert.deepEqual(pm2.delivery,originalPM2.delivery);assert.deepEqual(pm2.compatibility,originalPM2.compatibility);
  assert.equal(createHash('sha256').update(await read('dist/apps/pm2-manager/7.0.4-compat5/manifest.json')).digest('hex'),'246ea50006668bcba010e258df8026be06d8e22a4a4bc5b091522bbab0fc11df');
  assert.equal(catalog.apps.find(a=>a.id==='pm2-manager').sha256,createHash('sha256').update(await read('candidate/dist/apps/pm2-manager/7.0.4-compat9/manifest.json')).digest('hex'));
  assert.equal(createHash('sha256').update(await read('candidate/dist/apps/pm2-manager/7.0.4-compat6/manifest.json')).digest('hex'),'c50e001bb183eb9ead1c556e74c12be19cb1b754cc1f8a6ade44e92085b8e33e');
  assert.equal(createHash('sha256').update(await read('candidate/dist/apps/pm2-manager/7.0.4-compat7/manifest.json')).digest('hex'),'ba5a893e0fba47e8402933b526d3411f6b0d1e8df0f60f52ad992374f6fba49f');
  assert.equal(createHash('sha256').update(await read('candidate/dist/apps/pm2-manager/7.0.4-compat8/manifest.json')).digest('hex'),'b8279030a67c261ae559d17108cbd1d73f82bb3dd8e3f03f0c094581df21f9c3');
  const originalNFS=stable.apps.find(a=>a.id==='nfs-manager'),nfs=source.apps.find(a=>a.id==='nfs-manager');assert.equal(originalNFS.version,'1.3.0');assert.equal(nfs.version,'1.3.1');assert.deepEqual(nfs.delivery,originalNFS.delivery);assert.deepEqual(nfs.compatibility,originalNFS.compatibility);
  assert.equal(createHash('sha256').update(await read('dist/apps/nfs-manager/1.3.0/manifest.json')).digest('hex'),'c37a0d23ddb10a3e14e13c5304bbec0df0a3acf6954ab869ce40c9d253ad59ec');
  assert.equal(catalog.apps.find(a=>a.id==='nfs-manager').sha256,'c9d887dee3eb717bab1046e7977511b5d9190452a9eb43cceec330c22c307144');
  assert.equal(stable.apps.find(a=>a.id==='anti-intrusion').version,'1.1.0');
  const intrusion=source.apps.find(a=>a.id==='anti-intrusion');assert.equal(intrusion.version,'1.1.1');assert.deepEqual(intrusion.required_panel_features,['intrusion-preserving-journal-v2','intrusion-upstream0112-v1']);assert.deepEqual(intrusion.delivery,stable.apps.find(a=>a.id==='anti-intrusion').delivery);
  assert.equal(stable.apps.find(a=>a.id==='nginx-waf').version,'2.5.2');
  const waf=source.apps.find(a=>a.id==='nginx-waf');assert.equal(waf.version,'2.6.0');assert.deepEqual(waf.required_panel_features,['waf-country-signed-data-v1']);assert.deepEqual(waf.country_data_channel,{id:'dbip-country-lite-v1',format:1});assert.deepEqual(waf.compatibility,stable.apps.find(a=>a.id==='nginx-waf').compatibility);
  assert.equal(source.apps.find(a=>a.id==='load-balance').version,'1.9.0');
  for(const item of catalog.apps)assert.equal(item.package_url,`${officialCatalogBaseURL('candidate')}/dist/apps/${item.id}/${item.version}/manifest.json`);
  for(const changed of [{...patch,channel:'https://untrusted.invalid'}, {...patch,apps:[patch.apps[0],patch.apps[0]]}, {...patch,apps:[{...patch.apps[0],id:'unknown-application'}]}, {...patch,key:'untrusted'}])assert.throws(()=>candidateSource(stable,changed));
});

test('both real signatures are valid while stable publication remains byte-identical to the authentic predecessor',async()=>{
  const key=await read('signatures/catalog-v1.pub.pem');
  assert.equal(createHash('sha256').update(key).digest('hex'),'659ea4edcecaf23a586e2ff371616fde5f6ee7c219fb70fa978816e2b10acf75');
  for(const prefix of ['', 'candidate/']){
    const raw=await read(prefix+'dist/catalog-v1.json'),bundle=JSON.parse(await read(prefix+'signatures/catalog-v1.bundle.json'));
    assert.equal(bundle.catalog,raw);assert(verify(null,Buffer.from(raw),createPublicKey(key),Buffer.from(bundle.signature,'base64')));
  }
  for(const name of ['registry/apps.json','dist/catalog-v1.json','signatures/catalog-v1.sig','signatures/catalog-v1.bundle.json','signatures/catalog-v1.pub.pem'])assert.equal(await read(name),readPreStreamPublication(name));
  assert.deepEqual(schemaBeforeDiskCancel(await read('schema/app.schema.json')),JSON.parse(readPreStreamPublication('schema/app.schema.json')));
});
