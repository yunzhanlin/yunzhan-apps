import {phpSecurityBindings,phpSecurityFeature} from './php-security-contract.mjs';

export const phpBoundedFeature='php-bounded-native-build-v1';

export function exactPHPBoundedPackage(app){
 const binding=phpSecurityBindings[app.id],features=app.required_panel_features;
 return Boolean(binding&&app.version===binding.patched+'-compat2'&&app.delivery?.provider==='runtime'&&app.delivery?.target==='php-'+binding.patched&&app.delivery?.manage_route==='runtimes'&&Array.isArray(features)&&features.length===2&&new Set(features).size===2&&features.includes(phpSecurityFeature)&&features.includes(phpBoundedFeature));
}

// null means the unchanged legacy security contract still owns this manifest.
// New compat2 labels and the new capability may NEVER fall through to another
// provider/application, or borrow only the earlier security-catalog feature.
export function phpBoundedErrors(app){
 const binding=phpSecurityBindings[app.id],features=app.required_panel_features;
 const claimed=Array.isArray(features)&&features.includes(phpBoundedFeature);
 if(!claimed&&!(binding&&app.version===binding.patched+'-compat2'))return null;
 return exactPHPBoundedPackage(app)?[]:['PHP compat2 requires an exact reviewed branch/target,security patch and bounded native-build handlers'];
}
