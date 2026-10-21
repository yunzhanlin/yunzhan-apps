import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {bodyInventoryPresentation} from '../web/src/wafBodyInventory.ts';

test('unknown, failed or partial inventory is not presented as zero backups',()=>{
  for(const count of [0,3,8]) {
    const state=bodyInventoryPresentation(false,count);
    assert.equal(state.verified,false);assert.match(state.label,/待核对/);assert.match(state.empty,/不可核验/);
    assert.doesNotMatch(state.label,/保留 0/);assert.doesNotMatch(state.empty,/没有/);
  }
});
test('only a fully verified bounded inventory can report empty or a count',()=>{
  assert.deepEqual(bodyInventoryPresentation(true,0),{verified:true,label:'保留 0 / 8 份备份',empty:'没有元数据日志备份'});
  assert.equal(bodyInventoryPresentation(true,8).label,'保留 8 / 8 份备份');
  for(const count of [-1,9,Infinity,NaN,1.5])assert.equal(bodyInventoryPresentation(true,count).verified,false);
});
test('workspace does not render stale rows or allow rotation on unknown inventory',()=>{
  const source=readFileSync(new URL('../web/src/WafWorkspace.vue',import.meta.url),'utf8');
  assert.match(source,/bodyInventoryKnown\.value=!out\.inventory_warning/);
  assert.match(source,/catch\(e\) \{bodyInventoryKnown\.value=false;throw e;\}/);
  assert.match(source,/<el-table v-if="bodyInventoryView\.verified"/);
  assert.match(source,/:disabled="!bodyInventoryView\.verified \|\| bodyRetentionPreventRotation/);
  assert.doesNotMatch(source,/· 保留 \{\{bodyArchives\.length\}\}/);
});
