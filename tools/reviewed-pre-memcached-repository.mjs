// Read-only, exact original-key predecessor for earlier compiled ABI consumers.
// This never repairs, signs, downloads or treats an old handler as supporting new features.
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import {createHash,createPublicKey,verify} from 'node:crypto';
export const predecessorScope='registry/reviewed-catalogs/before-php-security24bkhe';
export const predecessorIdentity={
 catalog:'bc0dcdbcd0bcd5e75c889471a9e26168c951f943f772e0400d328af8d3e5f84f',
 public_key:'659ea4edcecaf23a586e2ff371616fde5f6ee7c219fb70fa978816e2b10acf75',
 signature:'d130ac3dcb3823ca4f04b30eaa0d37fbf2d75ef48d1a187c3c499ae9434a1ed5',
 bundle:'326f93d738d3d230edb79790238e7cf9c34d51fad620df153cf8d68568a660db',
 registry:'359d9a72d1d7ca3855c7fce9794613dc06c4d925b8787e0834f195e4f983b597',
 workflow:'d4f4c1f77641e83d1895de4dad70b5844628a63b57fcbd59c1258bdb75964dc7'
};
const sha=b=>createHash('sha256').update(b).digest('hex');
export function exactReviewedPreMemcachedRepository(args,repository){
 const root=path.resolve(repository);
 assert.equal(fs.realpathSync(root),root,'Repository root must be canonical');
 assert(!fs.lstatSync(root).isSymbolicLink()&&fs.lstatSync(root).isDirectory());
 if(args.length===0)return root+path.sep;
 assert.deepEqual(args,['--repo-root',predecessorScope],'No arbitrary source, repository or current-consumer override');
 const target=path.join(root,predecessorScope);
 assert.equal(fs.realpathSync(target),target);
 const read=name=>{
  assert(path.posix.normalize(name)===name&&!path.isAbsolute(name)&&!name.split('/').includes('..'));
  const file=path.join(target,name),s=fs.lstatSync(file);
  assert(s.isFile()&&!s.isSymbolicLink()&&s.nlink===1&&s.size>0&&s.size<1048576);
  assert.equal(fs.realpathSync(file),file);
  const raw=fs.readFileSync(file);assert.equal(raw.length,s.size);return raw;
 };
 const named={
  catalog:'dist/catalog-v1.json',public_key:'signatures/catalog-v1.pub.pem',
  signature:'signatures/catalog-v1.sig',bundle:'signatures/catalog-v1.bundle.json',
  registry:'registry/apps.json',workflow:'.github/workflows/verify.yml'
 };
 const bytes=Object.fromEntries(Object.entries(named).map(([k,n])=>[k,read(n)]));
 for(const[k,raw]of Object.entries(bytes))assert.equal(sha(raw),predecessorIdentity[k],k);
 const catalog=JSON.parse(bytes.catalog),bundle=JSON.parse(bytes.bundle);
 assert.equal(bundle.catalog,bytes.catalog.toString());
 assert.equal(bundle.signature,bytes.signature.toString().trim());
 assert(verify(null,bytes.catalog,createPublicKey(bytes.public_key),Buffer.from(bundle.signature,'base64')));
 assert.equal(catalog.apps.length,50);assert.equal(new Set(catalog.apps.map(a=>a.id)).size,50);
 const expected=[...Object.values(named),'dist/catalog-v1.json.sha256'];
 assert.equal(read('dist/catalog-v1.json.sha256').toString(),predecessorIdentity.catalog+'  catalog-v1.json\n');
 for(const app of catalog.apps){
  assert(/^[a-z0-9-]+$/.test(app.id)&&/^[0-9A-Za-z.-]+$/.test(app.version));
  const name='dist/apps/'+app.id+'/'+app.version+'/manifest.json',raw=read(name),m=JSON.parse(raw);
  assert.equal(sha(raw),app.sha256,app.id);
  assert.equal(read(name+'.sha256').toString(),app.sha256+'  manifest.json\n');
  assert.equal(m.id,app.id);assert.equal(m.version,app.version);
  expected.push(name,name+'.sha256');
 }
 const files=[];
 function walk(name){
  assert(files.length<=107);
  const directory=path.join(target,name),s=fs.lstatSync(directory);
  assert(s.isDirectory()&&!s.isSymbolicLink()&&fs.realpathSync(directory)===directory);
  for(const leaf of fs.readdirSync(directory)){
   const member=path.posix.join(name,leaf),stat=fs.lstatSync(path.join(target,member));
   assert(!stat.isSymbolicLink());
   if(stat.isDirectory())walk(member);
   else {assert(stat.isFile()&&stat.nlink===1);files.push(member);}
  }
 }
 walk('');assert.equal(files.length,107);assert.deepEqual(files.sort(),expected.sort());
 // Verify identity again after the bounded inventory; no synthetic old signature.
 for(const[k,name]of Object.entries(named))assert.equal(sha(read(name)),predecessorIdentity[k],k);
 return target+path.sep;
}
