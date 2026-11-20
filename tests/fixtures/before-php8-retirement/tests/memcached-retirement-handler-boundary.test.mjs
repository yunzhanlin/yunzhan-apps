import test from'node:test';import assert from'node:assert/strict';import fs from'node:fs';import{verifyOldMemcachedRefusal as verify,oldMemcachedRefusal}from'../tools/verify-memcached-retirement-handler-boundary.mjs';import{fileURLToPath}from'node:url';
const repo=fileURLToPath(new URL('../',import.meta.url)),ids=JSON.parse(fs.readFileSync(repo+'/dist/catalog-v1.json')).apps.map(a=>a.id),prefix='TestPublishedRepositoryCurrentSignedManifestABI';
function result(){
 const events=ids.filter(id=>id!=='memcached').map(id=>({Action:'pass',Test:prefix+'/'+id}));
 events.push({Action:'output',Test:prefix+'/memcached',Output:oldMemcachedRefusal},{Action:'fail',Test:prefix+'/memcached'},{Action:'fail',Test:prefix},{Action:'fail'});
 return{status:1,error:null,signal:null,stdout:events.map(v=>JSON.stringify(v)).join('\n')+'\n'};
}
test('only actual original two-handler contract refusal and the remaining49 passes qualify as negative ABI, not installation',()=>{
 assert.deepEqual(verify(result(),ids),{other49_passed:49,only_memcached_closed_three_handler_contract_refused:true,old_compiled_handler_unchanged:true,source_overlays:0,application_installation:false});
});
test('success missing coverage duplicate events skips unrelated errors timeout or borrowed unsupported-feature reason fail closed',()=>{
 const cases=[
  v=>v.status=0,v=>v.status=null,v=>v.signal='SIGTERM',v=>v.error={message:'timeout'},
  v=>v.stdout=v.stdout.replace(oldMemcachedRefusal,'面板处理器不支持 compose-memcached-retirement-v1'),
  v=>v.stdout=v.stdout.replace(oldMemcachedRefusal,'wrong error'),
  v=>v.stdout=v.stdout.split('\n').filter(l=>!l.includes(prefix+'/'+ids.find(id=>id!=='memcached'))).join('\n'),
  v=>v.stdout+=JSON.stringify({Action:'pass',Test:prefix+'/memcached'})+'\n',
  v=>v.stdout+=JSON.stringify({Action:'skip',Test:prefix+'/redis'})+'\n',
  v=>v.stdout+=JSON.stringify({Action:'fail',Test:prefix+'/php-82'})+'\n',
  v=>v.stdout+=JSON.stringify({Action:'pass',Test:prefix+'/nginx'})+'\n',
  v=>v.stdout+='not JSON\n',v=>v.stdout='',v=>v.stdout='x'.repeat(4<<20)
 ];
 for(const mutate of cases){const v=result();mutate(v);assert.throws(()=>verify(v,ids));}
 assert.throws(()=>verify(result(),ids.slice(1)));assert.throws(()=>verify(result(),[...ids.slice(1),ids[1]]));
});
