// Publisher-side metadata assembly only. Clients receive one complete signed
// catalogue, never an unsigned overlay or a browser-selected repository.
export function candidateSource(stable, candidate) {
  if(stable?.schema_version!==1||!Array.isArray(stable.apps)||stable.apps.length!==50||stable.channel!==undefined&&stable.channel!=='stable')throw Error('candidate requires the complete unchanged stable source');
  if(candidate?.schema_version!==1||candidate.channel!=='candidate'||!Array.isArray(candidate.apps)||candidate.apps.length<1||candidate.apps.length>50||Object.keys(candidate).some(k=>!['schema_version','channel','generated_at','apps'].includes(k)))throw Error('invalid fixed candidate source');
  if(typeof candidate.generated_at!=='string'||!/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/.test(candidate.generated_at)||!Number.isFinite(Date.parse(candidate.generated_at))||Date.parse(candidate.generated_at)<Date.parse(stable.generated_at))throw Error('invalid candidate publication time');
  const known=new Set(stable.apps.map(a=>a.id));if(known.size!==50)throw Error('duplicate stable application');
  const selected=new Map();
  for(const app of candidate.apps){if(!app||!known.has(app.id)||selected.has(app.id))throw Error('candidate cannot add unknown or duplicate identities');selected.set(app.id,app);}
  return {...stable,channel:'candidate',generated_at:candidate.generated_at,apps:stable.apps.map(a=>selected.get(a.id)??a)};
}
