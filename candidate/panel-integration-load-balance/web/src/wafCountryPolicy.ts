import {browserSHA256} from './browserSHA256';
import {readCountryDetail,type CountryDetail} from './wafCountryIdentity';

export interface CountryDataset {dataset:string;data_manifest_sha256:string;release:string;revision:number;countries:string[]}
export interface CountryRule {mode:'off'|'inherit'|'observe'|'block';list:''|'allow'|'deny';countries:string[]}
export interface CountrySite {site_id:string;rule:CountryRule}
export interface CountryPolicy {enabled:boolean;data:CountryDataset;global:CountryRule;sites:CountrySite[]}

// A completed original data receipt supplies a DRAFT only. The ordinary WAF
// preview/apply independently verifies the current instance and every file.
export function countryDraftFromOriginal(value:CountryDetail,actor:string):CountryPolicy {
 const detail=readCountryDetail(value,actor,value?.request?.id);
 const cache=detail.result?.cache;
 if(detail.request.state!=='succeeded'||detail.result?.state!=='succeeded'||!cache||
    cache.dataset!==cache.data_manifest_sha256+'-'+browserSHA256(JSON.stringify(cache.countries)))throw Error('原数据集没有完整提交，未载入地域策略草稿');
 return {enabled:false,data:{dataset:cache.dataset,data_manifest_sha256:cache.data_manifest_sha256,
  release:cache.release,revision:cache.revision,countries:[...cache.countries]},
  global:{mode:'off',list:'',countries:[]},sites:[]};
}
export function countryPolicyDraftProblem(policy:CountryPolicy|undefined):string {
 if(!policy)return '';
 const selected=new Set(policy.data.countries);
 for(const [name,rule]of [['全局',policy.global],...policy.sites.map(s=>[s.site_id,s.rule])] as [string,CountryRule][]){
  if(rule.mode==='off'||rule.mode==='inherit')continue;
  if(!['block','observe'].includes(rule.mode)||!['allow','deny'].includes(rule.list)||rule.countries.length===0||
   rule.countries.some(c=>!selected.has(c)))return name+'：请选择名单类型和至少一个已准备的地区';
 }
 return '';
}
export function countryDataAgeDays(release:string,now=Date.now()):number|undefined {
 if(!/^20[2-9][0-9]-(0[1-9]|1[0-2])$/.test(release)||!Number.isFinite(now))return;
 return Math.max(0,Math.floor((now-Date.parse(release+'-01T00:00:00Z'))/86400000));
}
