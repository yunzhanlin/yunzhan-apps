import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {wafConfigurationVersionMatches as matches} from '../web/src/wafConfigurationVersion.ts';

test('installed app must equal a known programme implementation, not just be older',()=>{
  for(const version of ['2.0.1','2.1.0','2.1.1','2.2.0','2.3.0','2.4.0','2.5.0','2.5.1','2.5.2']){
    assert.equal(matches('nginx-waf',true,version,version),true);
    if(version!=='2.5.2')assert.equal(matches('nginx-waf',true,version,'2.5.2'),false);
  }
  for(const version of ['',undefined,null,{},252,'2.5.3','2.6.0','latest','v2.5.2','2.5.2 ']){
    assert.equal(matches('nginx-waf',true,version,'2.5.2'),false);
    assert.equal(matches('nginx-waf',true,version,version),false);
    assert.equal(matches('nginx-waf',false,undefined,version),false);
  }
});
test('fresh install requires a known implementation; Apache path is independent',()=>{
  assert.equal(matches('nginx-waf',false,undefined,'2.5.2'),true);
  assert.equal(matches('apache-waf',true,'2.2.0','2.3.0'),false);
  assert.equal(matches('apache-waf',true,'2.3.0','2.3.0'),true);
  assert.equal(matches('apache-waf',true,'2.4.0','2.4.0'),true);
  assert.equal(matches('apache-waf',true,'2.3.0','2.4.0'),false);
  assert.equal(matches('apache-waf',true,'2.4.0','2.3.0'),false);
  for(const value of [undefined,null,{},'2.4.0-compat1','2.5.0'])assert.equal(matches('apache-waf',true,value,value),false);
  assert.equal(matches('foreign',true,'2.5.2','2.5.2'),false);
  assert.equal(matches('nginx-waf',undefined,'2.5.2','2.5.2'),false);
});
test('workspace blocks new previews/writes but preserves exact pending-task rechecks',()=>{
  const source=readFileSync(new URL('../web/src/WafWorkspace.vue',import.meta.url),'utf8');
  assert.match(source,/if \(!configurationVersionMatches\.value\) throw new Error/);
  assert.match(source,/if \(!pendingApply\.value\?\.job && !configurationVersionMatches\.value\)/);
  assert.match(source,/:disabled="busy \|\| !configurationVersionMatches" @click="showPreview"/);
  assert.match(source,/:disabled="busy \|\| \(!pendingApply\?\.job && !configurationVersionMatches\)" @click="apply"/);
  assert.match(source,/原任务恢复与日志读取仍可使用/);
});
