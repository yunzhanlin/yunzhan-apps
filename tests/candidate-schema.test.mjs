import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {candidateSchema} from '../tools/candidate-schema.mjs';
async function fixture(t){
 const root=await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(),'yunzhan-candidate-schema-')));t.after(()=>fs.rm(root,{recursive:true,force:true}));await fs.mkdir(path.join(root,'schema'));
 const value={$schema:'https://json-schema.org/draft/2020-12/schema',$id:'https://github.com/yunzhanlin/yunzhan-apps/schema/app.schema.json',properties:{required_panel_features:{items:{enum:['original-feature']}}},allOf:[]};await fs.writeFile(path.join(root,'schema/app.schema.json'),JSON.stringify(value)+'\n');return root;
}
test('candidate build refreshes the current schema ABI byte-exactly while leaving versioned packages unchanged',async t=>{
 const root=await fixture(t),source=path.join(root,'schema/app.schema.json'),target=path.join(root,'candidate/schema/app.schema.json');assert((await candidateSchema(root)).changed);assert((await fs.readFile(source)).equals(await fs.readFile(target)));
 await fs.mkdir(path.join(root,'candidate/dist'),{recursive:true});await fs.writeFile(path.join(root,'candidate/dist/retained-manifest'),'original immutable bytes');
 const value=JSON.parse(await fs.readFile(source));value.properties.required_panel_features.items.enum.push('new-reviewed-feature');await fs.writeFile(source,JSON.stringify(value,null,2)+'\n');assert((await candidateSchema(root)).changed);assert((await fs.readFile(source)).equals(await fs.readFile(target)));assert(!(await candidateSchema(root)).changed);assert.equal(await fs.readFile(path.join(root,'candidate/dist/retained-manifest'),'utf8'),'original immutable bytes');
});
test('schema synchronization refuses unsafe links, hardlinks and unrecognized ABI without changing outside bytes',async t=>{
 const outside=await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(),'yunzhan-schema-outside-')));t.after(()=>fs.rm(outside,{recursive:true,force:true}));const sentinel=path.join(outside,'sentinel');await fs.writeFile(sentinel,'outside data');
 const linked=await fixture(t);await fs.symlink(outside,path.join(linked,'candidate'));await assert.rejects(candidateSchema(linked),/ordinary/);
 const source=await fixture(t);await fs.unlink(path.join(source,'schema/app.schema.json'));await fs.symlink(sentinel,path.join(source,'schema/app.schema.json'));await assert.rejects(candidateSchema(source),/ordinary/);
 const hard=await fixture(t);await candidateSchema(hard);const target=path.join(hard,'candidate/schema/app.schema.json');await fs.link(target,path.join(outside,'hardlink'));await assert.rejects(candidateSchema(hard),/ordinary/);
 const invalid=await fixture(t);await candidateSchema(invalid);const before=await fs.readFile(path.join(invalid,'candidate/schema/app.schema.json'));await fs.writeFile(path.join(invalid,'schema/app.schema.json'),'{}');await assert.rejects(candidateSchema(invalid),/fixed publisher ABI/);assert((await fs.readFile(path.join(invalid,'candidate/schema/app.schema.json'))).equals(before));assert.equal(await fs.readFile(sentinel,'utf8'),'outside data');
});
