import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {validateManifest} from '../tools/lib.mjs';

const registry=JSON.parse(await readFile(new URL('../registry/apps.json',import.meta.url),'utf8'));
const app=registry.apps.find(row=>row.id==='network-threat-detection');
test('new rule ABI uses a new immutable app version and closed data-only channel',()=>{
 assert.equal(app.version,'1.3.1');assert.equal(validateManifest(app).length,0);
 assert.deepEqual(app.rule_data_channel,{id:'et-open-web-bsd-v1',format:1,engine:'suricata-8.0'});
 assert.equal(app.delivery.provider,'panel-module');assert.equal(app.delivery.target,app.id);
});
test('rule channel cannot introduce paths, scripts, unknown keys or another application',()=>{
 for(const channel of [null,[],{}, {...app.rule_data_channel,url:'https://external.invalid'}, {...app.rule_data_channel,path:'../rules'}, {...app.rule_data_channel,script:'install.sh'}, {...app.rule_data_channel,id:'et-open-pro'}, {...app.rule_data_channel,engine:'suricata-7.0'}, {...app.rule_data_channel,format:2}]) assert(validateManifest({...app,rule_data_channel:channel}).length>0);
 for(const changed of [{id:'site-diagnosis'},{delivery:{provider:'compose',target:app.id,image:'example'}},{delivery:{provider:'panel-module',target:'other'}},{rule_feeds:[]}]) assert(validateManifest({...app,...changed}).length>0);
});
