import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {validateManifest} from '../tools/lib.mjs';
import {loadBalanceStreamErrors,loadBalanceStreamFeature} from '../tools/load-balance-stream-contract.mjs';
const source=JSON.parse(await readFile(new URL('../registry/candidate-apps.json',import.meta.url),'utf8'));
const current=source.apps.find(a=>a.id==='load-balance');
test('exact stream candidate metadata is gated, bounded and not a commercial completion claim',()=>{
  assert.equal(current.version,'1.9.0');
  assert.equal(source.channel,'candidate');
  assert.deepEqual(loadBalanceStreamErrors(current),[]);
  assert.deepEqual(validateManifest(current),[]);
  assert.deepEqual(current.required_panel_features,[loadBalanceStreamFeature]);
  assert.match(current.summary,/回环/);assert.match(current.summary,/不开放公网/);
});
test('foreign targets, borrowed features, aliases and unpreserving metadata fail closed',()=>{
  const fixture=structuredClone(current);
  fixture.version='1.9.0';fixture.required_panel_features=[loadBalanceStreamFeature];
  const changes=[
    m=>m.id='memcached',m=>m.version='1.8.5',m=>m.version='1.9.0-compat1',m=>m.version='1.9.1',m=>m.version='2.0.0',
    m=>m.stage='integration',m=>m.risk='maintained',m=>m.category='deployment',
    m=>delete m.required_panel_features,m=>m.required_panel_features=[],m=>m.required_panel_features=['waf-bound-health-v1'],m=>m.required_panel_features.push(loadBalanceStreamFeature),
    m=>m.delivery.target='nginx',m=>m.delivery.provider='runtime',m=>m.delivery.manage_route='security',m=>m.delivery.image='unreviewed:latest',
    m=>m.compatibility.os.pop(),m=>m.compatibility.architectures.push('arm64'),m=>m.compatibility.architectures=['x86_64','arm64'],
    m=>m.health.target='invented',m=>m.uninstall.preserve_data=false,m=>m.uninstall.reference_check=false,
    m=>m.geo_data_channel={},m=>m.rule_data_channel={},m=>m.rule_feeds=[{}],
  ];
  for(const change of changes){const m=structuredClone(fixture);change(m);assert(validateManifest(m).length,change.toString());}
});
test('all historical HTTP manifests retain their old distributor contract',async()=>{
  const legacy=JSON.parse(await readFile(new URL('../dist/apps/load-balance/1.8.5/manifest.json',import.meta.url),'utf8'));
  assert.equal(loadBalanceStreamErrors(legacy),null);assert.deepEqual(validateManifest(legacy),[]);
  assert.equal(loadBalanceStreamErrors({...legacy,id:'foreign-copy'} )?.length>0,true);
});
