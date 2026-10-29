// Verify the exact new country schema before exposing the previous schema to
// historical assertions. Removed old guards and foreign additions remain visible.
import assert from'node:assert/strict';
const feature='waf-country-signed-data-v1',channel={type:'object',additionalProperties:false,required:['id','format'],properties:{id:{const:'dbip-country-lite-v1'},format:{const:1}}};
const props={id:{const:'nginx-waf'},version:{const:'2.6.0'},delivery:{required:['provider','target','manage_route'],properties:{provider:{const:'panel-module'},target:{const:'nginx-waf'},manage_route:{const:'security'}},additionalProperties:false},required_panel_features:{minItems:1,maxItems:1,items:{const:feature}},country_data_channel:channel};
const body={required:['id','version','delivery','required_panel_features','country_data_channel'],properties:props,not:{required:['geo_data_channel']}};
const guard={if:{anyOf:[{required:['id','version'],properties:{id:{const:'nginx-waf'},version:{const:'2.6.0'}}},{required:['country_data_channel']},{required:['required_panel_features'],properties:{required_panel_features:{contains:{const:feature}}}}]},then:body};
export function schemaBeforeCountry(current){
 assert.deepEqual(current.properties.country_data_channel,channel);delete current.properties.country_data_channel;
 const flags=current.properties.required_panel_features.items.enum;assert.equal(flags.filter(v=>v===feature).length,1);flags.splice(flags.indexOf(feature),1);
 const branches=current.allOf[0].then.oneOf,selected=branches.filter(v=>v.properties?.id?.const==='nginx-waf'&&v.properties?.version?.const==='2.6.0');assert.equal(selected.length,1);assert.deepEqual(selected[0],body);branches.splice(branches.indexOf(selected[0]),1);
 const matches=current.allOf.filter(v=>v.if?.anyOf?.some(x=>x.required?.includes('country_data_channel')));assert.equal(matches.length,1);assert.deepEqual(matches[0],guard);current.allOf.splice(current.allOf.indexOf(matches[0]),1);return current;
}
