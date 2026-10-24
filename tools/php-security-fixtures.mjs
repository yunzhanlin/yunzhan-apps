import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {phpSecurityBindings,phpSecurityFeature} from './php-security-contract.mjs';
export function phpSecurityCases(root){
  const result=[];
  for(const[id,b]of Object.entries(phpSecurityBindings)){
    let previous;
    for(const version of [b.previous,b.previous+'-compat1']){
      const base=path.join(root,'dist/apps',id,version),raw=fs.readFileSync(base+'/manifest.json');
      assert.equal(fs.readFileSync(base+'/manifest.json.sha256','utf8'),createHash('sha256').update(raw).digest('hex')+'  manifest.json\n');
      const manifest=JSON.parse(raw);assert.equal(manifest.id,id);assert.equal(manifest.version,version);
      assert(!Object.hasOwn(manifest,'required_panel_features'));
      result.push({name:id+':historical:'+version,valid:true,manifest});previous=manifest;
    }
    const exact=structuredClone(previous);exact.version=b.patched+'-compat1';exact.delivery.target='php-'+b.patched;exact.required_panel_features=[phpSecurityFeature];
    result.push({name:id+':exact',valid:true,manifest:exact});
    const mutations=[
      ['missing',m=>delete m.required_panel_features],['empty',m=>m.required_panel_features=[]],['null',m=>m.required_panel_features=null],['string',m=>m.required_panel_features=phpSecurityFeature],
      ['duplicate',m=>m.required_panel_features=[phpSecurityFeature,phpSecurityFeature]],['extra',m=>m.required_panel_features=[phpSecurityFeature,'runtime-package-version-v1']],['wrong-feature',m=>m.required_panel_features=['runtime-package-version-v1']],['future-feature',m=>m.required_panel_features=['php-security-20261022-v1']],
      ['foreign-id',m=>m.id='daily-report'],['foreign-without-feature',m=>{m.id='daily-report';delete m.required_panel_features;}],['foreign-scope',m=>{m.id='daily-report';m.delivery.target='daily-report';}],
      ['foreign-target',m=>m.delivery.target='nginx-1.30.6'],['other-branch',m=>m.delivery.target='php-'+(id==='php-85'?'8.2.35':'8.5.12')],['old-target',m=>m.delivery.target='php-'+b.previous],
      ['route',m=>m.delivery.manage_route='security'],['missing-route',m=>delete m.delivery.manage_route],['module',m=>m.delivery.provider='panel-module'],['compose',m=>{m.delivery.provider='compose';m.delivery.image='php:latest';}],
      ['legacy-feature',m=>{m.version=b.previous+'-compat1';m.delivery.target='php-'+b.previous;}],['old-label-new-target',m=>{m.version=b.previous;delete m.required_panel_features;}],
    ];
    for(const version of [b.patched,b.patched+'-compat2',b.patched+'-compat01','0'+b.patched+'-compat1','9.0.0-compat1','18446744073709551616.0.0','unknown'])for(const withFeature of [true,false])mutations.push(['unreviewed:'+version+':'+withFeature,m=>{m.version=version;if(!withFeature)delete m.required_panel_features;}]);
    for(const[name,mutate]of mutations){const manifest=structuredClone(exact);mutate(manifest);result.push({name:id+':'+name,valid:false,manifest});}
  }
  const current=JSON.parse(fs.readFileSync(path.join(root,'registry/apps.json')));assert.equal(current.apps.length,50);
  for(const manifest of current.apps)result.push({name:'current50:'+manifest.id,valid:true,manifest});
  return result;
}
