import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {fileURLToPath} from 'node:url';
import {validateManifest} from '../tools/lib.mjs';
import {phpSecurityCases} from '../tools/php-security-fixtures.mjs';
import {phpSecurityBindings,phpSecurityFeature,exactPHPSecurityPackage} from '../tools/php-security-contract.mjs';
const root=fileURLToPath(new URL('../',import.meta.url));
test('four reviewed PHP security packages cannot borrow old source identities, foreign routes, aliases or future labels',()=>{
  const cases=phpSecurityCases(root);for(const c of cases){const errors=validateManifest(c.manifest);assert.equal(errors.length===0,c.valid,c.name+': '+errors.join('; '));}
  assert.equal(cases.filter(c=>c.name.endsWith(':exact')).length,4);assert.equal(cases.filter(c=>c.name.includes(':historical:')).length,8);assert.equal(cases.filter(c=>c.name.startsWith('current50:')).length,50);assert.equal(cases.filter(c=>!c.valid).length,136);
  for(const c of cases.filter(c=>c.name.includes(':historical:')))assert.equal(exactPHPSecurityPackage(c.manifest),false,'An old installed package is not implicitly patched');
});
test('independent Draft2020 schema requires exact native PHP feature scope and retains all8 published predecessor identities',()=>{
  const s=JSON.parse(fs.readFileSync(new URL('../schema/app.schema.json',import.meta.url)));assert(s.properties.required_panel_features.items.enum.includes(phpSecurityFeature));
  const scopes=s.allOf[0].then.oneOf.filter(c=>Object.hasOwn(phpSecurityBindings,c.properties.id.const));assert.equal(scopes.length,4);
  for(const scope of scopes){const p=scope.properties,b=phpSecurityBindings[p.id.const];assert.equal(p.version.const,b.patched+'-compat1');assert.deepEqual(scope.required,['id','version','delivery','required_panel_features']);assert.equal(p.delivery.properties.target.const,'php-'+b.patched);assert.equal(p.delivery.properties.provider.const,'runtime');assert.equal(p.delivery.properties.manage_route.const,'runtimes');assert.deepEqual(p.required_panel_features,{minItems:1,maxItems:1,items:{const:phpSecurityFeature}});}
  const guard=s.allOf.find(c=>c.if?.anyOf?.some(a=>a.properties?.required_panel_features?.contains?.const===phpSecurityFeature));assert(guard);assert.equal(guard.then.oneOf.length,8);assert.deepEqual(guard.then.oneOf.slice(4),scopes);
});
