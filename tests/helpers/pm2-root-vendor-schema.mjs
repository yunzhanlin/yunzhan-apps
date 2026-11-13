import {schemaBeforeIntrusionDebian12} from './intrusion-debian12-schema.mjs';
import assert from 'node:assert/strict';
import {canonical,sha256} from '../../tools/lib.mjs';
import {pm2MaintenanceGuard} from '../../tools/pm2-maintenance-contract.mjs';
import {pm2RootVendorFeature,pm2RootVendorScope,pm2RootVendorGuard,pm2LegacyMaintenanceWithRootVendor} from '../../tools/pm2-root-vendor-contract.mjs';

export function schemaBeforePM2RootVendor(value){
 const s=schemaBeforeIntrusionDebian12(value),flags=s.properties.required_panel_features.items.enum,branches=s.allOf[0].then.oneOf;
 if(!flags.includes(pm2RootVendorFeature))return s;
 assert.equal(flags.filter(f=>f===pm2RootVendorFeature).length,1);
 assert.equal(flags.pop(),pm2RootVendorFeature);
 assert.deepEqual(branches.pop(),pm2RootVendorScope);
 assert.deepEqual(s.allOf.pop(),pm2RootVendorGuard);
 assert.deepEqual(s.allOf.pop(),pm2LegacyMaintenanceWithRootVendor);
 s.allOf.push(pm2MaintenanceGuard);
 assert.equal(sha256(canonical(s)),'02f341da39960324cc8830e02506387b762fce848323dd108b05ff2e50a0f6e7','Every prePM2 Root vendor schema predicate must remain exact');
 return s;
}
