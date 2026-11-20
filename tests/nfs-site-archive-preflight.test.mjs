import assert from 'node:assert/strict';
import {test} from 'node:test';
import {readFile} from 'node:fs/promises';
import {validateManifest} from '../tools/lib.mjs';
const old=JSON.parse(await readFile(new URL('../candidate/dist/apps/nfs-manager/1.3.1/manifest.json',import.meta.url)));
const current=JSON.parse(await readFile(new URL('../candidate/dist/apps/nfs-manager/1.3.2/manifest.json',import.meta.url)));
test('NFS preserves the old signed manifest and pins the 1.3.2 handler',()=>{
 assert.deepEqual(validateManifest(old),[]);assert.deepEqual(validateManifest(current),[]);
 assert.deepEqual(current.required_panel_features,['nfs-site-archive-preflight-v1']);
 for(const bad of [
  {...current,required_panel_features:[]},{...current,required_panel_features:[...current.required_panel_features,...current.required_panel_features]},
  {...current,version:'1.3.1'},{...current,version:'1.3.2-preview'},{...current,version:'1.3.3',required_panel_features:[]},
  {...current,version:'2.0.0',required_panel_features:[]},{...current,id:'file-monitor'},
  {...current,delivery:{...current.delivery,target:'file-monitor'}},{...current,delivery:{...current.delivery,manage_route:'software'}}
 ])assert(validateManifest(bad).length>0);
});
