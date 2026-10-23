// Bounded historical evidence, never a hash alias or runtime adapter. Earlier
// claims read the real signed pre-compat2 catalog. Test-source chains remove
// ONLY this exact import/call and verify the entire original test file digest.
import assert from'node:assert/strict';import{createHash}from'node:crypto';import{catalogBeforeMemcachedCompat2Bytes}from'./previous-memcached-catalog.mjs';
import {preAnalyticsWorkflowRead} from './pre-analytics-workflow.mjs';
import {preNativeMobileRead} from './pre-native-mobile-release.mjs';
export const historicalTestSHA={
 'tests/disk-host-diagnostic-candidate.test.mjs':'18073b3e23c09e40c8ff4790776e4a893f423a6db869d9474340f92e9ccd7560',
 'tests/disk-host-installed-diagnostic-acceptance.test.mjs':'6de05360bb89aaacf94e01fa016df0520fc369fbd7d237b3e3311f24f921b29c',
 'tests/disk-host-reason-candidate.test.mjs':'c1312d3c48a3915f0b19dfd32322cf7fcde20c1665c21a09ba8bd88c722a2d8c',
 'tests/disk-host-reason-installed-acceptance.test.mjs':'00641f69d90f29bfef4c0c2b436b7cc8ac1e5d901207c006675340da8ac8c19f',
 'tests/disk-host-runtime-fix.test.mjs':'64c2b4c382108f013080da9647a897bb3bbdcab0352987756de8708e4a20fd62',
 'tests/platform-fleet-candidate.test.mjs':'2bcbb73277b6074c840ce11b1c5a9a3faa14577294d587012a38e12e013b1a4e',
 'tests/platform-health-view-candidate.test.mjs':'630f59a3839dbc30f51d9b4db5a36f199c9d1fd71b10db9887ff5507370daf11'
};
export function originalPreMemcachedTest(path,bytes){
 const pin=historicalTestSHA[path];assert(pin,'not an explicitly reviewed historical test');let text=bytes.toString();
 const added="import {preMemcachedRead} from './pre-memcached-evidence-read.mjs';\n",current='read=p=>preMemcachedRead(p,readFile(path.join(root,p)))';
 assert.equal(text.split(added).length,2);assert.equal(text.split(current).length,2);text=text.replace(added,'').replace(current,'read=p=>readFile(path.join(root,p))');
 const result=Buffer.from(text);assert.equal(createHash('sha256').update(result).digest('hex'),pin,'historical assertions changed beyond exact boundary reader');return result;
}
export async function preMemcachedRead(path,actual){
 const bytes=await actual;
 if(path==='dist/catalog-v1.json')return catalogBeforeMemcachedCompat2Bytes();
 if(Object.hasOwn(historicalTestSHA,path))return originalPreMemcachedTest(path,bytes);
 return preAnalyticsWorkflowRead(path,preNativeMobileRead(path,bytes));
}
