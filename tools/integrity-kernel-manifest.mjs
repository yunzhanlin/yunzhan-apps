export const integrityKernelFeature='integrity-kernel-inode-journal-v1';
export function integrityKernelErrors(app){
 const features=app.required_panel_features,mentions=Array.isArray(features)&&features.includes(integrityKernelFeature);
 if(app.id!=='website-tamper-proof')return mentions?['inode journal handler belongs only to website-tamper-proof1.5.0']:null;
 if(typeof app.version!=='string')return ['kernel protection version is not a string'];
 const base=app.version.split('-')[0];
 if(!/^(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*)){0,3}$/.test(base))return ['kernel protection version is not canonical'];
 const parts=base.split('.').map(BigInt),floor=[1n,5n,0n];let comparison=0;
 for(let i=0;i<Math.max(parts.length,floor.length);i++){const a=parts[i]??0n,b=floor[i]??0n;if(a!==b){comparison=a>b?1:-1;break;}}
 if(!mentions&&comparison<0)return null;
 if(app.version!=='1.5.0'||app.delivery?.provider!=='panel-module'||app.delivery?.target!==app.id||app.delivery?.manage_route!=='app-modules'||!Array.isArray(features)||features.length!==1||features[0]!==integrityKernelFeature)return ['kernel protection requires exact1.5.0, fixed module identity and its complete inode/admission journal handler'];
 return [];
}

// Independent enterprise scope; the published website validator above remains intact.
export const enterpriseKernelFeature='enterprise-integrity-kernel-ownership-v1';
export function enterpriseKernelErrors(app){
 const features=app.required_panel_features,mentions=Array.isArray(features)&&features.includes(enterpriseKernelFeature);
 if(app.id!=='enterprise-tamper-proof')return mentions?['inode journal handler belongs only to enterprise-tamper-proof1.5.0']:null;
 if(typeof app.version!=='string')return ['kernel protection version is not a string'];
 const base=app.version.split('-')[0];
 if(!/^(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*)){0,3}$/.test(base))return ['kernel protection version is not canonical'];
 const parts=base.split('.').map(BigInt),floor=[1n,5n,0n];let comparison=0;
 for(let i=0;i<Math.max(parts.length,floor.length);i++){const a=parts[i]??0n,b=floor[i]??0n;if(a!==b){comparison=a>b?1:-1;break;}}
 if(!mentions&&comparison<0)return null;
 if(app.version!=='1.5.0'||app.delivery?.provider!=='panel-module'||app.delivery?.target!==app.id||app.delivery?.manage_route!=='app-modules'||!Array.isArray(features)||features.length!==1||features[0]!==enterpriseKernelFeature)return ['kernel protection requires exact1.5.0, fixed module identity and its complete inode/admission journal handler'];
 return [];
}
