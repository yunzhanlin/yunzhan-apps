// Closed reviewed distributor ABI; installer readiness is not commercial acceptance.
export const memcachedUnixVersion='1.6.45-compat4';
export const memcachedUnixFeature='compose-memcached-unix-v1';
export const memcachedUnixRetirementFeature='compose-memcached-retirement-v1';
export const memcachedDigestFeature='compose-memcached-digest-v1';
export const memcachedUnixImage='memcached:1.6.45-alpine@sha256:9e4de012dc607573052061c0bcb38abc775e1dd59b24e7ac38d1892842094aaf';
export function memcachedUnixErrors(app){
 const req=app?.required_panel_features,claimed=Array.isArray(req)&&(req.includes(memcachedUnixFeature)||req.includes(memcachedUnixRetirementFeature));
 if(app?.id!=='memcached'&&!claimed)return null;
 if(app?.id==='memcached'&&['1.6.45-compat1','1.6.45-compat2'].includes(app.version)&&!claimed)return null;
 const errors=[],d=app?.delivery;
 if(app?.schema_version!==1||app.id!=='memcached'||app.version!==memcachedUnixVersion||!['integration','ready'].includes(app.stage))errors.push('Unix cache requires exact compat4 identity');
 if(!d||d.provider!=='compose'||d.target!=='memcached-cache'||d.manage_route!=='docker'||d.image!==memcachedUnixImage||Object.keys(d).sort().join(',')!=='image,manage_route,provider,target')errors.push('Unix cache cannot inherit a mutable image, port or legacy delivery override');
 if(!Array.isArray(req)||req.length!==3||new Set(req).size!==3||!req.includes(memcachedUnixFeature)||!req.includes(memcachedDigestFeature)||!req.includes(memcachedUnixRetirementFeature))errors.push('All three independently compiled Socket, digest and safe-retirement handlers are required');
 if(!app.health||app.health.probe!=='panel-api'||app.health.target!=='memcached-unix-workspace'||Object.keys(app.health).sort().join(',')!=='probe,target')errors.push('No TCP or invented health route for a networkless Socket instance');
 if(!app.uninstall||app.uninstall.preserve_data!==true||app.uninstall.reference_check!==true||Object.keys(app.uninstall).sort().join(',')!=='preserve_data,reference_check')errors.push('Original ownership records and references must be preserved');
 return errors;
}
