import assert from 'node:assert/strict';
import {canonical,sha256}from'../../tools/lib.mjs';
import {pm2MaintenanceFeature,pm2MaintenanceScope,pm2MaintenanceGuard}from'../../tools/pm2-maintenance-contract.mjs';
import {schemaBeforePM2RootVendor}from'./pm2-root-vendor-schema.mjs';
export function schemaBeforePM2Maintenance(value){
 const s=schemaBeforePM2RootVendor(value),flags=s.properties.required_panel_features.items.enum,branches=s.allOf[0].then.oneOf;
 if(!flags.includes(pm2MaintenanceFeature))return s;
 assert.equal(flags.filter(v=>v===pm2MaintenanceFeature).length,1);assert.equal(flags.pop(),pm2MaintenanceFeature);
 assert.deepEqual(branches.pop(),pm2MaintenanceScope);assert.deepEqual(s.allOf.pop(),pm2MaintenanceGuard);
 assert.equal(sha256(canonical(s)),'1baa1e14325e5b2e236a14ecee42bdd09a7cb112c2df86ba77017c4e9c0f38d9','Every prePM2 C68r3 schema predicate must remain exact');
 return s;
}

