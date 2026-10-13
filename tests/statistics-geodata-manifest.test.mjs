import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {validateManifest} from '../tools/lib.mjs';
const source=JSON.parse(await readFile(new URL('../registry/apps.json',import.meta.url),'utf8'));
const original=JSON.parse(await readFile(new URL('../dist/apps/website-statistics-v2/2.5.0/manifest.json',import.meta.url),'utf8'));
const candidate=()=>({...structuredClone(original),version:'2.6.0',geo_data_channel:{id:'dbip-city-lite-v1',format:1},required_panel_features:['statistics-cursor-retirement-v1','statistics-request-identity-v1','statistics-geodata-v2']});
test('original2.5 remains valid and bounded2.6 has an independent fixed data channel',()=>{
 assert.deepEqual(validateManifest(original),[]);assert.deepEqual(validateManifest(candidate()),[]);
 for(const version of ['2.6','2.6.0-compat1','2.6.1','2.7.0'])assert(validateManifest({...candidate(),version}).length>0);
});
test('channel cannot supply a URL, key, script, provider or old prototype ABI',()=>{
 for(const change of [{geo_data_channel:null},{geo_data_channel:{id:'dbip-city-lite-v1',format:1,url:'http://127.0.0.1/'}},{geo_data_channel:{id:'dbip-city-lite-v1',format:1,key:'caller-key'}},{geo_data_channel:{id:'dbip-city-lite-v1',format:1,script:'caller-command'}},{geo_data_channel:{id:'dbip-city-lite-v1',format:2}},{id:'daily-report'},{delivery:{provider:'runtime',target:'website-statistics-v2'}},{version:'2.5.0'},{required_panel_features:['statistics-cursor-retirement-v1','statistics-request-identity-v1','statistics-geodata-v1']}])assert(validateManifest({...candidate(),...change}).length>0,JSON.stringify(change));
 const missing=candidate();delete missing.geo_data_channel;assert(validateManifest(missing).length>0);
});
