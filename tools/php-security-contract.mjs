// Fixed application/package metadata contract, not an advisory feed or a
// claim that any existing website process has changed its PHP binary.
export const phpSecurityFeature = 'php-security-20261021-v1';
export const phpSecurityBindings = Object.freeze({
  'php-82': Object.freeze({previous:'8.2.33',patched:'8.2.35'}),
  'php-83': Object.freeze({previous:'8.3.33',patched:'8.3.36'}),
  'php-84': Object.freeze({previous:'8.4.25',patched:'8.4.27'}),
  'php-85': Object.freeze({previous:'8.5.10',patched:'8.5.12'}),
});
export function exactPHPSecurityPackage(app) {
  const binding=Object.hasOwn(phpSecurityBindings,app?.id)?phpSecurityBindings[app.id]:null;
  return Boolean(binding&&app.version===binding.patched+'-compat1'&&app.delivery?.provider==='runtime'&&app.delivery?.target==='php-'+binding.patched&&app.delivery?.manage_route==='runtimes'&&Array.isArray(app.required_panel_features)&&app.required_panel_features.length===1&&app.required_panel_features[0]===phpSecurityFeature);
}
export function phpSecurityErrors(app) {
  const binding=Object.hasOwn(phpSecurityBindings,app?.id)?phpSecurityBindings[app.id]:null;
  const has=Array.isArray(app.required_panel_features)&&app.required_panel_features.includes(phpSecurityFeature);
  const targetScoped=Object.values(phpSecurityBindings).some(b=>app.delivery?.target==='php-'+b.patched);
  if(!binding&&!has&&!targetScoped)return [];
  if(binding&&[binding.previous,binding.previous+'-compat1'].includes(app.version)&&!Object.hasOwn(app,'required_panel_features')&&app.delivery?.provider==='runtime'&&app.delivery?.target==='php-'+binding.previous&&app.delivery?.manage_route==='runtimes')return [];
  return exactPHPSecurityPackage(app)?[]:['PHP security packages require one of four exact reviewed versions, matching native target and their single compiled admission feature; legacy packages are immutable, not implicitly patched'];
}
