export function resourcePercent(value:unknown,available?:unknown,legacyZeroUnknown=false):number|null {
 if(available!==undefined&&available!==true)return null;
 if(typeof value!=='number'||!Number.isFinite(value)||value<0||value>100)return null;
 if(legacyZeroUnknown&&value===0&&available!==true)return null;
 return value;
}
export function resourceSeries(values:(number|null)[]):string[] {
 const segments:string[]=[],current:string[]=[];
 const flush=()=>{if(current.length>=2)segments.push(current.join(' '));current.length=0;};
 values.forEach((value,i)=>{if(resourcePercent(value)===null){flush();return}current.push(`${values.length>1?i/(values.length-1)*720:0},${180-value!*1.6}`)});
 flush();return segments;
}
