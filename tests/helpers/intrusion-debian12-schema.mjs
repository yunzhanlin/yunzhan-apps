import assert from 'node:assert/strict';

export function schemaBeforeIntrusionDebian12(value) {
 const current = structuredClone(value);
 const feature = 'intrusion-debian12-v1';
 const required = {
  minItems: 3, maxItems: 3,
  prefixItems: ['intrusion-preserving-journal-v2', 'intrusion-upstream0112-v1', feature].map(constant => ({const: constant})),
  items: false,
 };
 const compatibility = {
  required: ['os', 'architectures'],
  properties: {
   os: {const: ['debian-12', 'debian-13', 'ubuntu-22.04', 'ubuntu-24.04']},
   architectures: {const: ['amd64', 'arm64']},
  },
 };
 const identity = {id: {const: 'anti-intrusion'}, version: {const: '1.1.2'}};
 const flags = current.properties.required_panel_features.items.enum;
 const hasVersion = properties => properties?.id?.const === 'anti-intrusion' && properties?.version?.const === '1.1.2';
 if (!flags.includes(feature) &&
     !current.allOf[0].then.oneOf.some(branch => hasVersion(branch.properties)) &&
     !current.allOf.some(guard => hasVersion(guard.if?.properties))) return current;
 assert.equal(flags.filter(flag => flag === feature).length, 1);
 assert.equal(flags.pop(), feature);
 const branches = current.allOf[0].then.oneOf;
 assert.deepEqual(branches.pop(), {properties: {
  ...identity,
  delivery: {properties: {provider: {const: 'panel-module'}, target: {const: 'intrusion-prevention'}, manage_route: {const: 'security'}}},
  required_panel_features: required, compatibility,
 }});
 assert.deepEqual(current.allOf.pop(), {
  if: {required: ['id', 'version'], properties: identity},
  then: {required: ['required_panel_features', 'compatibility'], properties: {required_panel_features: required, compatibility}},
 });
 return current;
}
