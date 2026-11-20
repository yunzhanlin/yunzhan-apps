import test from'node:test';import assert from'node:assert/strict';import fs from'node:fs';import{createHash}from'node:crypto';
const read=n=>fs.readFileSync(new URL('../'+n,import.meta.url)),sha=b=>createHash('sha256').update(b).digest('hex');
const oldName='TestCurrentMobileCatalogPreservesActualFrozenIDSConsumerAuthorityAndAll1510Rules',newName='TestCurrentMemcachedCatalogPreservesActualFrozenIDSConsumerAuthorityAndAll1510Rules';
const oldSHA='bc0dcdbcd0bcd5e75c889471a9e26168c951f943f772e0400d328af8d3e5f84f',newSHA='247c8db6cc762413c0779f8cb8a251b16d01b641b109981f084076c20f104813',oldPath='registry/reviewed-catalogs/before-php-security24bkhe/signatures/catalog-v1.bundle.json';
const marker='// A five-application release cannot renew or replace the separately signed IDS cohort.\n';
test('both genuine IDS catalog generations retain identical complete authority,1510-rule and expiry assertions',()=>{
 const raw=read('tests/ids-data-verifier/ruledata_test.go').toString(),start=raw.indexOf(marker),end=raw.indexOf('func TestPublishedIDSRuleDataActualFrozenConsumerVerifiesBothOriginalKeySignaturesAndAll1510Rules',start);
 assert(start>0&&end>start);assert.equal(raw.split(marker).length,2);
 const oldStart=raw.indexOf('func '+oldName+'('),oldEnd=raw.indexOf(marker,oldStart),old=raw.slice(oldStart,oldEnd),added=raw.slice(start,end);
 assert.equal(added,marker+old.replace(oldName,newName).replace(oldPath,'signatures/catalog-v1.bundle.json').replace(oldSHA,newSHA).replaceAll('mobile publication','Memcached publication'));
 const original=raw.slice(0,start)+raw.slice(end),restored=original.replace(oldPath,'signatures/catalog-v1.bundle.json');assert.equal(original.split(oldPath).length,2);
 assert.equal(sha(restored),'5fae9483b1d8d51f6292ef183458f46c6f73923c60b468380efff587197379ba','Every original consumer check, corruption case, rule asset, clock and expiry assertion must remain byte-exact');
 for(const[path,digest]of[[oldPath,oldSHA],['signatures/catalog-v1.bundle.json',newSHA]]){const bundle=JSON.parse(read(path));assert.equal(sha(bundle.catalog),digest);}
});
