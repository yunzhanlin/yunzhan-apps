import fs from'node:fs';import path from'node:path';import assert from'node:assert/strict';
export function memcachedUnixCases(root){
 const current=JSON.parse(fs.readFileSync(path.join(root,'registry/apps.json'))).apps,base=current.find(a=>a.id==='memcached');assert(current.length===50&&base.version==='1.6.45-compat4');
 const cases=current.map(manifest=>({name:'current50:'+manifest.id,valid:true,manifest:structuredClone(manifest)}));
 const reverse=structuredClone(base);reverse.required_panel_features.reverse();cases.push({name:'unix-reversed',valid:true,manifest:reverse});
 const integration=structuredClone(base);integration.stage='integration';cases.push({name:'unix-integration-not-installation',valid:true,manifest:integration});
 for(const version of['1.6.45-compat1','1.6.45-compat2'])cases.push({name:'legacy:'+version,valid:true,manifest:JSON.parse(fs.readFileSync(path.join(root,'dist/apps/memcached',version,'manifest.json')))});
 const changes=[
  ['unsupported-design-stage',m=>m.stage='design'],
  ['version-bare',m=>m.version='1.6.45'],['version-prototype',m=>m.version='1.6.45-compat3'],['version-alias',m=>m.version='1.6.45-compat04'],['version-extra',m=>m.version='1.6.45-compat4.0'],['version-future',m=>m.version='1.6.46-compat4'],
  ['foreign-id',m=>m.id='redis'],['provider',m=>m.delivery.provider='runtime'],['target',m=>m.delivery.target='redis'],['route',m=>m.delivery.manage_route='terminal'],['image-tag',m=>m.delivery.image='memcached:latest'],['isolation',m=>m.delivery.isolation='legacy-container'],['host-port',m=>m.delivery.host_port=11211],
  ['features-missing',m=>delete m.required_panel_features],['features-null',m=>m.required_panel_features=null],['features-string',m=>m.required_panel_features='compose-memcached-unix-v1'],['features-empty',m=>m.required_panel_features=[]],
  ['two-handler-prototype',m=>m.required_panel_features=m.required_panel_features.filter(f=>f!=='compose-memcached-retirement-v1')],['duplicate',m=>m.required_panel_features[2]=m.required_panel_features[1]],['future-feature',m=>m.required_panel_features[2]='compose-memcached-retirement-v2'],['extra-feature',m=>m.required_panel_features.push('runtime-package-version-v1')],
  ['tcp-health',m=>m.health.probe='tcp'],['foreign-health',m=>m.health.target='http://foreign.invalid'],['extra-health',m=>m.health.url='http://foreign.invalid'],['discard-evidence',m=>m.uninstall.preserve_data=false],['no-reference-check',m=>m.uninstall.reference_check=false],
 ];
 for(const[name,change]of changes){const manifest=structuredClone(base);change(manifest);cases.push({name,valid:false,manifest});}
 return cases;
}
