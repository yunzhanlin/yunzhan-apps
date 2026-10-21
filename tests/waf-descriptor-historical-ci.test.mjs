import test from 'node:test';import assert from 'node:assert/strict';import fs from 'node:fs';import{createHash}from'node:crypto';
import {preNginxRuntimeRead} from './pre-nginx-runtime-release.mjs';
const read=n=>preNginxRuntimeRead(n,fs.readFileSync(new URL('../'+n,import.meta.url))),sha=b=>createHash('sha256').update(b).digest('hex');
test('historical thirteen complete gates differ only by three explicit package-scheduling flags; race cases, budgets and immutable sources remain intact',()=>{
 const original=read('registry/reviewed-ci/before-waf-descriptor24bivw.yml');assert.equal(sha(original),'c93c334516132dda6d754108238e55b381a661b14ce8921afc3a70ef5869651c');
 let actual=read('.github/workflows/verify.yml').toString();const at=actual.indexOf('\n  waf-descriptor-native-amd64:\n');if(at>=0)actual=actual.slice(0,at);
 let expected=original.toString();for(const selector of ['^TestWAF','^Test(WAF|IsolatedLegacyPHP)','^Test(LegacySync|IsolatedLegacyPHP|WAF)']){
  const before='sudo "$(command -v go)" test -race ./internal/core ./internal/executor ./internal/appcatalog -run '+"'"+selector+"'"+' -count=1';
  assert.equal(expected.split(before).length-1,1,selector);expected=expected.replace(before,before.replace('test -race ','test -race -p 1 '));
 }
 assert.equal(actual,expected,'No other historical gate command, test, source, timeout, approval or failure policy may change');
 assert(!actual.includes('continue-on-error'));assert(!actual.includes('-overlay='));
});
