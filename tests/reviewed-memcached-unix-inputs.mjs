// Exact historical inputs for earlier release assertions; current50 acceptance is separate.
import fs from'node:fs';import path from'node:path';import{fileURLToPath,pathToFileURL}from'node:url';import assert from'node:assert/strict';import{createHash}from'node:crypto';
import{exactReviewedPreMemcachedRepository,predecessorScope}from'../tools/reviewed-pre-memcached-repository.mjs';
import{phpBoundedCases}from'../tools/php-bounded-fixtures.mjs';
const sha=b=>createHash('sha256').update(b).digest('hex'),schemaSHA='c0d4934cb2432645e4fcca13682d11580393e302479842001fbc5787c932f081',validated=new Set();
const mapped=new Set(['dist/catalog-v1.json','dist/catalog-v1.json.sha256','registry/apps.json','signatures/catalog-v1.pub.pem','signatures/catalog-v1.sig','signatures/catalog-v1.bundle.json']);
function canonical(root){const base=path.resolve(root);assert(fs.realpathSync(base)===base);return base;}
function originalCatalogRoot(root){
 const base=canonical(root);
 if(!validated.has(base)){exactReviewedPreMemcachedRepository(['--repo-root',predecessorScope],base);validated.add(base);}
 return path.join(base,predecessorScope);
}
export function historicalMemcachedUnixInput(root,name){
 assert(typeof name==='string'&&path.posix.normalize(name)===name&&!path.isAbsolute(name)&&!name.split('/').includes('..'));
 const base=canonical(root),file=mapped.has(name)?path.join(originalCatalogRoot(base),name):path.join(base,name);
 const raw=fs.readFileSync(file);return raw;
}
export function historicalMemcachedUnixSchemaURL(meta){
 const base=canonical(fileURLToPath(new URL('../',meta))),file=path.join(base,'registry/reviewed-distributors/before-memcached-unix24blfi/schema/app.schema.json'),s=fs.lstatSync(file);
 assert(s.isFile()&&!s.isSymbolicLink()&&s.nlink===1&&fs.realpathSync(file)===file);assert.equal(sha(fs.readFileSync(file)),schemaSHA);return pathToFileURL(file);
}
export function historicalPHPBoundedCases(root){
 const cases=phpBoundedCases(root),registry=JSON.parse(historicalMemcachedUnixInput(root,'registry/apps.json')),selected=cases.filter(c=>c.name.startsWith('current50:'));
 assert.equal(selected.length,50);assert.equal(new Set(selected.map(c=>c.name)).size,50);
 const before=JSON.stringify(cases.filter(c=>!c.name.startsWith('current50:')));
 const result=cases.map(c=>{if(!c.name.startsWith('current50:'))return c;const id=c.name.slice('current50:'.length),manifest=registry.apps.find(a=>a.id===id);assert(manifest);return{...c,manifest:structuredClone(manifest)};});
 assert.equal(JSON.stringify(result.filter(c=>!c.name.startsWith('current50:'))),before,'Every original positive and236 negative fixture outside exact historical50 remains byte-identical');
 return result;
}
