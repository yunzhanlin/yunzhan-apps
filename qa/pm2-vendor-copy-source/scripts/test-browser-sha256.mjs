import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {browserSHA256} from '../web/src/browserSHA256.ts';
import {dockerCreateFingerprint} from '../web/src/dockerCreateRequest.ts';
import {platformObservation,platformMutationReplyMatches} from '../web/src/platformManagementReceipt.ts';

test('real receipt SHA-256 does not require secure-context crypto, fetch or storage',async()=>{
 const names=['crypto','fetch','localStorage','sessionStorage'],original=new Map(names.map(name=>[name,Object.getOwnPropertyDescriptor(globalThis,name)]));
 for(const name of names)Object.defineProperty(globalThis,name,{configurable:true,get(){assert.fail('receipt digest accessed '+name);}});
 try{
  assert.equal(browserSHA256(''),'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  assert.equal(browserSHA256('abc'),'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  for(const value of ['云栈🧱\u0000\ud800',...Array.from([55,56,63,64,65,127,128,129,1048576],n=>'x'.repeat(n))])assert.equal(browserSHA256(value),createHash('sha256').update(value).digest('hex'));
  const body={name:'owned-http-fixture',compose:'PASSWORD=synthetic-only\n',host_port:23864};
  assert.equal(await dockerCreateFingerprint(body),createHash('sha256').update(JSON.stringify(body)).digest('hex'));
  for(const v of [undefined,()=>0,Symbol('not-a-body')])await assert.rejects(dockerCreateFingerprint(v),/无法核对/);
  const token='4'.repeat(64),tokenID=createHash('sha256').update(token).digest('hex');
  const observation=await platformObservation('revoke-token',{token});assert.equal(observation.tokenID,tokenID);assert(!JSON.stringify(observation).includes(token));
  assert(await platformMutationReplyMatches(observation,{revoked:true,token_id:tokenID,already_absent:false}));
  assert(await platformMutationReplyMatches(await platformObservation('issue-token',{}),{token,token_id:tokenID,scope:'health-read-only',endpoint:'/api/platform/agent'}));
 }finally{for(const[name,descriptor]of original)if(descriptor)Object.defineProperty(globalThis,name,descriptor);else delete globalThis[name];}
});
