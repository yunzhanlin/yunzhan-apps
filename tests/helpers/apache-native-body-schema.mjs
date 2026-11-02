// Remove only the exact independently reviewed Apache2.4 schema extension.
// All older predicates remain visible to the existing historical comparisons.
import assert from 'node:assert/strict';
import {canonical,sha256} from '../../tools/lib.mjs';
import{schemaBeforeAnalyticsClientAddress}from'./analytics-client-schema.mjs';
export function schemaBeforeApacheNativeBody(value){
 const s=schemaBeforeAnalyticsClientAddress(value),feature='apache-native-body-site-transactions-v1',flags=s.properties.required_panel_features.items.enum;
 if(!flags.includes(feature))return s;
 assert.equal(flags.filter(f=>f===feature).length,1,'Unknown Apache schema feature extension');assert.equal(flags.at(-1),feature,'Unknown Apache schema feature order');flags.pop();
 const branches=s.allOf[0].then.oneOf;
 assert.equal(branches.filter(b=>b.properties?.id?.const==='apache-waf'&&b.properties?.version?.const==='2.4.0').length,1,'Unknown Apache capability registration');
 assert.equal(sha256(canonical(branches.at(-1))),'23a83c7f2769d68c7943e7ead28f94f9a457445a0bd9229b10f4be59ceb6bfbc','Unknown Apache capability predicate');branches.pop();
 assert.equal(sha256(canonical(s.allOf.at(-1))),'ae5db2445dd77d6cbebd98458ac9c23b9222a24c3da63bcdc4825fa4fae248ee','Unknown Apache identity/version schema scope');s.allOf.pop();
 return s;
}
