import fs from'node:fs';import path from'node:path';
export function intrusionUbuntu22Cases(root){
 const read=n=>JSON.parse(fs.readFileSync(path.join(root,n))),catalog=read('candidate/dist/catalog-v1.json');
 const cases=catalog.apps.map(a=>({name:'current50:'+a.id,valid:true,manifest:read('candidate/dist/apps/'+a.id+'/'+a.version+'/manifest.json')}));
 const app=cases.find(c=>c.name==='current50:anti-intrusion').manifest;
 if(app.version!=='1.1.1')throw Error('actual111 manifest required');
 cases.push({name:'original110',valid:true,manifest:read('dist/apps/anti-intrusion/1.1.0/manifest.json')});
 const journal='intrusion-preserving-journal-v2',compat='intrusion-upstream0112-v1';
 const changes=[['missing',x=>delete x.required_panel_features],['empty',x=>x.required_panel_features=[]],['old-only',x=>x.required_panel_features=[journal]],['new-only',x=>x.required_panel_features=[compat]],['reordered',x=>x.required_panel_features=[compat,journal]],['duplicate',x=>x.required_panel_features.push(compat)],['extra',x=>x.required_panel_features.push('hardening-reversible-journal-v1')],['borrowed-app',x=>x.id='system-hardening'],['executor-as-app',x=>x.id='intrusion-prevention'],['other-target',x=>x.delivery.target='system-hardening'],['other-route',x=>x.delivery.manage_route='app-modules'],['runtime',x=>x.delivery.provider='runtime'],['compose',x=>x.delivery.provider='compose'],['old-version',x=>x.version='1.1.0'],['alias',x=>x.version='1.1.1-alias'],['future',x=>x.version='1.1.2'],['leading-zero',x=>x.version='01.1.1']];
 for(const[name,change]of changes){const manifest=structuredClone(app);change(manifest);cases.push({name,manifest,valid:false});}
 const stream=cases.find(c=>c.name==='current50:load-balance').manifest;
 for(const[name,change]of [['missing-feature',x=>delete x.required_panel_features],['old-version',x=>x.version='1.8.5'],['future-version',x=>x.version='1.9.1'],['alias',x=>x.version='1.9.0-rc1'],['wrong-OS',x=>x.compatibility.os[0]='unknown'],['duplicate-OS',x=>x.compatibility.os[0]=x.compatibility.os[1]],['missing-architecture',x=>x.compatibility.architectures.pop()],['wrong-probe',x=>x.health.probe='http'],['wrong-health-target',x=>x.health.target='/api/software'],['wrong-risk',x=>x.risk='safe'],['missing-risk',x=>delete x.risk],['lost-data',x=>x.uninstall.preserve_data=false]]){
  const manifest=structuredClone(stream);change(manifest);cases.push({name:'LB:'+name,manifest,valid:false});
 }
 return cases;
}
