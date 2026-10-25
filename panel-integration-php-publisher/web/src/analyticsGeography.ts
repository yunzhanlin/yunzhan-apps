export const geoStatuses = ['located','non_public','missing_ip','invalid_ip','unavailable','not_found','lookup_error','lookup_limited'] as const;
const labels = ['有国家/地区记录','内网或保留地址','缺少 IP','IP 格式无效','地理库不可用','库中没有记录','查询或记录异常','超出本次查询预算'];
const object = (v:unknown):v is Record<string,unknown> => !!v && typeof v==='object' && !Array.isArray(v);
const count = (v:unknown):v is number => typeof v==='number' && Number.isSafeInteger(v) && v>=0;
const name = (v:unknown):v is string => typeof v==='string' && new TextEncoder().encode(v).length<=256 && !/[\u0000-\u001f\u007f-\u009f]/.test(v);
type Rank = {countryCode:string;country:string;region:string;city:string;requests:number};
export type GeographyView = {
  requests:number;available:boolean;partial:boolean;stale:boolean;release:string;
  counts:{status:string;label:string;requests:number}[];
  countries:Rank[];cities:Rank[];cityUnknown:number;cityOther:number;lookups:number;
};
function ranks(value:unknown,city:boolean):Rank[]|undefined {
  if(!Array.isArray(value)||value.length>(city?100:676))return;
  const rows:Rank[]=[],seen=new Set<string>();
  for(const raw of value) {
    if(!object(raw)||typeof raw.country_code!=='string'||!/^[A-Z]{2}$/.test(raw.country_code)||raw.country_code==='ZZ'||!name(raw.country)||!count(raw.requests)||raw.requests===0)return;
    const region=raw.region??'',place=raw.city??'';
    if(!name(region)||!name(place)||city&&place==='')return;
    const key=city?JSON.stringify([raw.country_code,region,place]):raw.country_code;
    if(seen.has(key))return;seen.add(key);
    rows.push({countryCode:raw.country_code,country:raw.country,region,city:place,requests:raw.requests});
  }
  return rows;
}
// Reject inconsistent populations and untrusted provider links. No default
// zeros, browser geolocation, online lookup, or visitor identifier is exposed.
export function analyticsGeographyView(value:unknown):GeographyView|undefined {
  if(!object(value)||value.format!==1||value.method!=='offline_ip_network'||!count(value.requests)||!count(value.lookups)||value.lookups>5000||value.lookups>value.requests||value.lookup_limit!==5000||typeof value.population_partial!=='boolean'||!object(value.metadata)||typeof value.metadata.available!=='boolean'||!object(value.counts)||Object.keys(value.counts).length!==geoStatuses.length)return;
  const counts:GeographyView['counts']=[];
  for(const [i,status] of geoStatuses.entries()) {
    const requests=value.counts[status];if(!count(requests))return;
    counts.push({status,label:labels[i]!,requests});
  }
  if(counts.reduce((n,row)=>n+row.requests,0)!==value.requests)return;
  const countries=ranks(value.countries,false),cities=ranks(value.cities,true);
  const located=Number(value.counts.located),metadata=value.metadata;
  if(!countries||!cities||!count(value.city_unknown_requests)||!count(value.city_other_requests)||countries.reduce((n,r)=>n+r.requests,0)!==located||cities.reduce((n,r)=>n+r.requests,0)+value.city_unknown_requests+value.city_other_requests!==located)return;
  if(!metadata.available&&located!==0)return;
  if(metadata.available&&(typeof metadata.release!=='string'||!/^20[2-9][0-9]-(0[1-9]|1[0-2])$/.test(metadata.release)||!count(metadata.build_epoch)||metadata.build_epoch===0||typeof metadata.stale!=='boolean'||typeof metadata.manifest_sha256!=='string'||!/^[0-9a-f]{64}$/.test(metadata.manifest_sha256)||typeof metadata.sha256!=='string'||!/^[0-9a-f]{64}$/.test(metadata.sha256)||metadata.license!=='https://creativecommons.org/licenses/by/4.0/'||metadata.attribution!=='IP Geolocation by DB-IP'||metadata.attribution_url!=='https://db-ip.com/'))return;
  return {requests:value.requests,available:metadata.available===true,partial:value.population_partial===true,stale:metadata.available===true&&metadata.stale===true,release:metadata.available===true?String(metadata.release):'',counts,countries,cities,cityUnknown:value.city_unknown_requests,cityOther:value.city_other_requests,lookups:value.lookups};
}
