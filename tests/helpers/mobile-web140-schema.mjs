import assert from 'node:assert/strict';
import{canonical,sha256}from'../../tools/lib.mjs';
export const mobileWebFeature="mobile-web-workspace-v140";
const scope={"properties":{"id":{"const":"mobile"},"version":{"const":"1.4.0"},"delivery":{"required":["provider","target","manage_route"],"properties":{"provider":{"const":"panel-module"},"target":{"const":"mobile-pwa"},"manage_route":{"const":"app-modules"}}},"required_panel_features":{"minItems":1,"maxItems":1,"items":{"const":"mobile-web-workspace-v140"}}}};
const selector={"required":["required_panel_features"],"properties":{"required_panel_features":{"contains":{"const":"mobile-web-workspace-v140"}}}};
const closed={"required":["id","version","delivery","required_panel_features"],"properties":{"id":{"const":"mobile"},"version":{"const":"1.4.0"},"delivery":{"required":["provider","target","manage_route"],"properties":{"provider":{"const":"panel-module"},"target":{"const":"mobile-pwa"},"manage_route":{"const":"app-modules"}}},"required_panel_features":{"minItems":1,"maxItems":1,"items":{"const":"mobile-web-workspace-v140"}}}};
export function schemaBeforeMobileWeb(value){
 const s=structuredClone(value),flags=s.properties.required_panel_features.items.enum,branches=s.allOf[0].then.oneOf,guard=s.allOf[1];
 const isWeb=v=>v?.properties?.id?.const==='mobile'&&v?.properties?.version?.const==='1.4.0';
 if(!flags.includes(mobileWebFeature)&&!branches.some(isWeb)&&!JSON.stringify(guard).includes(mobileWebFeature))return s;
 assert.equal(flags.filter(f=>f===mobileWebFeature).length,1);assert.equal(flags.indexOf(mobileWebFeature),37);assert.equal(flags.pop(),mobileWebFeature);
 assert.equal(branches.filter(isWeb).length,1);assert.deepEqual(branches.pop(),scope);
 assert.equal(guard.if.anyOf.filter(v=>JSON.stringify(v).includes(mobileWebFeature)).length,1);assert.deepEqual(guard.if.anyOf.pop(),selector);
 assert.equal(guard.then.oneOf.filter(isWeb).length,1);assert.deepEqual(guard.then.oneOf.pop(),closed);
 assert.equal(sha256(canonical(s)),'0105ee9d341599939aa01c62fdb9026e9bed52285bc8fd0be2cbfdeff9f785c1','Every preWeb140 schema predicate and order remains exact');return s;
}
