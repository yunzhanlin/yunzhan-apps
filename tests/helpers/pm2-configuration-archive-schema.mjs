import{schemaBeforeMobileWeb}from'./mobile-web140-schema.mjs';
import assert from 'node:assert/strict';
import {canonical,sha256} from '../../tools/lib.mjs';
import {pm2ConfigurationArchiveFeature as feature,pm2ConfigurationArchiveScope as scope,pm2ConfigurationArchiveGuard as guard} from '../../tools/pm2-configuration-archive-contract.mjs';
import {pm2LegacyMaintenanceWithRootVendor as original} from '../../tools/pm2-root-vendor-contract.mjs';
export function schemaBeforePM2ConfigurationArchive(value){
 const s=schemaBeforeMobileWeb(value),flags=s.properties.required_panel_features.items.enum,branches=s.allOf[0].then.oneOf;
 if(!flags.includes(feature)){assert(!s.allOf.some(v=>v?.then?.properties?.required_panel_features?.items?.const===feature));return s;}
 assert.equal(flags.filter(v=>v===feature).length,1);assert.equal(flags.pop(),feature);assert.deepEqual(branches.pop(),scope);assert.deepEqual(s.allOf.pop(),guard);
 const expanded=structuredClone(original);expanded.if.allOf[1]={not:{anyOf:[structuredClone(original.if.allOf[1].not),{required:['required_panel_features'],...structuredClone(scope)}]}};
 assert.deepEqual(s.allOf[36],expanded);s.allOf[36]=structuredClone(original);assert.equal(sha256(canonical(s)),"d84732a1b661b1e378b7eef009d126ed9ab70b11561692ccfb64cd7ddb1030d4",'Every prePM2Archive publisher schema predicate remains exact');return s;
}
