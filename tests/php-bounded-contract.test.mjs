import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {fileURLToPath} from 'node:url';
import {validateManifest} from '../tools/lib.mjs';
import {phpBoundedCases} from '../tools/php-bounded-fixtures.mjs';
import {phpBoundedFeature,exactPHPBoundedPackage} from '../tools/php-bounded-contract.mjs';
import {phpSecurityBindings,phpSecurityFeature} from '../tools/php-security-contract.mjs';
const root=fileURLToPath(new URL('../',import.meta.url));
test('bounded PHP compat2 independently requires both exact handlers and retains every earlier PHP rejection/current50 identity',()=>{
 const cases=phpBoundedCases(root);for(const c of cases){const errors=validateManifest(c.manifest);assert.equal(errors.length===0,c.valid,c.name+': '+errors.join('; '));}
 assert.equal(cases.filter(c=>c.name.includes(':bounded-exact')).length,4);assert.equal(cases.filter(c=>c.name.includes(':bounded-reversed')).length,4);
 assert.equal(cases.filter(c=>c.name.includes(':historical:')).length,8);assert.equal(cases.filter(c=>c.name.startsWith('current50:')).length,50);assert.equal(cases.filter(c=>!c.valid).length,236);
 for(const c of cases)assert.equal(exactPHPBoundedPackage(c.manifest),c.valid&&c.name.includes(':bounded-'),c.name);
});
test('independent schema compat2 scope is exactly four fixed runtimes and two distinct mandatory handlers',()=>{
 const schema=JSON.parse(fs.readFileSync(new URL('../schema/app.schema.json',import.meta.url)));
 assert(schema.properties.required_panel_features.items.enum.includes(phpBoundedFeature));
 const guard=schema.allOf.find(c=>c.if?.properties?.required_panel_features?.contains?.const===phpBoundedFeature);assert(guard);assert.equal(guard.then.oneOf.length,4);
 for(const c of guard.then.oneOf){const p=c.properties,b=phpSecurityBindings[p.id.const];assert(b);assert.equal(p.version.const,b.patched+'-compat2');assert.equal(p.delivery.properties.target.const,'php-'+b.patched);assert.equal(p.delivery.properties.provider.const,'runtime');assert.equal(p.delivery.properties.manage_route.const,'runtimes');assert.equal(p.required_panel_features.minItems,2);assert.equal(p.required_panel_features.maxItems,2);assert.deepEqual(p.required_panel_features.items.enum,[phpSecurityFeature,phpBoundedFeature]);assert.deepEqual(p.required_panel_features.allOf,[{contains:{const:phpSecurityFeature}},{contains:{const:phpBoundedFeature}}]);}
});
