// Historical assertions still consume the authentic previous schema. Before
// returning it, prove that today's complete schema adds exactly the reviewed
// disk1.4.1 feature, branch and mandatory guard and changes nothing else.
import assert from 'node:assert/strict';
import {readPreStreamPublication} from './pre-stream-publication.mjs';
const feature='disk-host-cancel-seal-v1';
const expectedFeatures=['disk-inode-usage-v1','disk-host-jobs-v1',feature];
export function schemaBeforeDiskCancel(raw){
 const current=JSON.parse(raw),previous=JSON.parse(readPreStreamPublication('schema/app.schema.json'));
 const flags=current.properties.required_panel_features.items.enum;assert.equal(flags.filter(v=>v===feature).length,1);flags.splice(flags.indexOf(feature),1);
 const scopes=current.allOf[0].then.oneOf,branches=scopes.filter(x=>x.properties?.id?.const==='disk-analysis'&&x.properties.version?.const==='1.4.1');assert.equal(branches.length,1);
 const scope=branches[0],requirements={minItems:3,maxItems:3,items:{enum:expectedFeatures},allOf:expectedFeatures.map(value=>({contains:{const:value}}))};
 assert.deepEqual(scope,{properties:{id:{const:'disk-analysis'},version:{const:'1.4.1'},delivery:{properties:{provider:{const:'panel-module'},target:{const:'disk-analysis'},manage_route:{const:'app-modules'}}},required_panel_features:requirements}});
 scopes.splice(scopes.indexOf(scope),1);
 const guards=current.allOf.filter(x=>x.if?.properties?.id?.const==='disk-analysis'&&x.if.properties.version?.const==='1.4.1');assert.equal(guards.length,1);const guard=guards[0];
 assert.deepEqual(guard,{if:{required:['id','version'],properties:{id:{const:'disk-analysis'},version:{const:'1.4.1'}}},then:{required:['required_panel_features'],properties:{required_panel_features:requirements}}});
 current.allOf.splice(current.allOf.indexOf(guard),1);assert.deepEqual(current,previous,'Every previous schema property, branch, order and guard must remain exact');
 return previous;
}
