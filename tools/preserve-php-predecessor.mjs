// Preserve the genuine signed predecessor only after its exact CodeReview CI
// receipt and verified Git merge. Never synthesizes signatures or old success.
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import {fileURLToPath} from 'node:url';
import {createHash,createPublicKey,verify} from 'node:crypto';
import {execFileSync} from 'node:child_process';
const root=fileURLToPath(new URL('../',import.meta.url)),args=process.argv.slice(2);
assert(args.length===4&&args[0]==='--ci'&&args[2]==='--merge');
const sha=b=>createHash('sha256').update(b).digest('hex'),head='f635d1b815b682e637b0bb0487fa05991bba18f5';
const names=["apache-preservation-native-amd64","docker-observation-native-amd64","files-sync-opening-native-amd64","frontend-release-native-amd64","hardening-native-amd64","ids-capture-recovery-native-amd64","intrusion-admission-native-amd64","intrusion-native-amd64","intrusion-ui-native-amd64","legacy-sync-native-amd64","mobile-delivery-native-amd64","nginx-runtime-signed-native-amd64","pm2-readiness-native-amd64","runtime-failed-native-amd64","runtime-health-native-amd64","runtime-package-native-amd64","statistics-stop-native-amd64","verify","waf-configuration-inspection-native-amd64","waf-configuration-review-native-amd64","waf-descriptor-native-amd64","waf-health-native-amd64","waf-version-native-amd64"];
const receipts=args.filter((_,n)=>n%2===1).map(p=>{assert(path.isAbsolute(p)&&fs.realpathSync(p)===p);const s=fs.lstatSync(p);assert(s.isFile()&&s.nlink===1&&!s.isSymbolicLink()&&s.size<1048576);return JSON.parse(fs.readFileSync(p));});
const[ci,merge]=receipts;
assert(ci.headRevision===head&&ci.hasMore===false&&ci.checks.length===23);
assert.deepEqual(ci.checks.map(c=>c.name).sort(),names);
assert(ci.checks.every(c=>c.head_sha===head&&c.status==='completed'&&c.conclusion==='success'));
assert(ci.statuses.every(c=>c.state==='success'));
assert(merge.merged===true&&merge.expected_head===head&&/^[a-f0-9]{40}$/.test(merge.merge_commit_sha));
assert.deepEqual(execFileSync('git',['ls-remote','--exit-code','origin','refs/heads/main'],{cwd:root,encoding:'utf8',timeout:20000}).trim().split(/\s+/),[merge.merge_commit_sha,'refs/heads/main']);
// The current branch may already append the next unaccepted source/CI gate.
// Read the actual reviewed merge tree, never that mutable working tree or a
// reconstructed predecessor. The exact CI head, remote main and all original
// hashes/signatures below are still independently mandatory.
const read=name=>{assert(!path.isAbsolute(name)&&path.posix.normalize(name)===name&&!name.split('/').includes('..'));const value=execFileSync('git',['show',merge.merge_commit_sha+':'+name],{cwd:root,maxBuffer:1048576,timeout:10000});assert(value.length<1048576);return value;};
const catalog=read('dist/catalog-v1.json'),pub=read('signatures/catalog-v1.pub.pem'),signature=read('signatures/catalog-v1.sig'),bundle=read('signatures/catalog-v1.bundle.json');
assert.equal(sha(catalog),'bc0dcdbcd0bcd5e75c889471a9e26168c951f943f772e0400d328af8d3e5f84f');
assert.equal(sha(pub),'659ea4edcecaf23a586e2ff371616fde5f6ee7c219fb70fa978816e2b10acf75');
assert.equal(sha(signature),'d130ac3dcb3823ca4f04b30eaa0d37fbf2d75ef48d1a187c3c499ae9434a1ed5');
assert.equal(sha(bundle),'326f93d738d3d230edb79790238e7cf9c34d51fad620df153cf8d68568a660db');
const b=JSON.parse(bundle);assert.equal(b.catalog,catalog.toString());assert.equal(b.signature,signature.toString().trim());
assert(verify(null,catalog,createPublicKey(pub),Buffer.from(b.signature,'base64')));
assert.equal(sha(read('registry/apps.json')),'359d9a72d1d7ca3855c7fce9794613dc06c4d925b8787e0834f195e4f983b597');
assert.equal(sha(read('.github/workflows/verify.yml')),'d4f4c1f77641e83d1895de4dad70b5844628a63b57fcbd59c1258bdb75964dc7');
const c=JSON.parse(catalog);assert(c.apps.length===50&&new Set(c.apps.map(a=>a.id)).size===50);
const files=['registry/apps.json','dist/catalog-v1.json','dist/catalog-v1.json.sha256','signatures/catalog-v1.pub.pem','signatures/catalog-v1.sig','signatures/catalog-v1.bundle.json','.github/workflows/verify.yml'];
for(const app of c.apps){assert(/^[a-z0-9-]+$/.test(app.id)&&/^[0-9A-Za-z.-]+$/.test(app.version));const n='dist/apps/'+app.id+'/'+app.version+'/manifest.json';assert.equal(sha(read(n)),app.sha256);assert.equal(read(n+'.sha256').toString(),app.sha256+'  manifest.json\n');files.push(n,n+'.sha256');}
assert.equal(files.length,107);
const output=path.join(root,'registry/reviewed-catalogs/before-php-security24bkhe');
assert(!fs.existsSync(output),'Unknown prior outcome: inspect the original snapshot, never overwrite it');
const payload=Object.fromEntries(files.map(n=>[n,read(n)]));
fs.mkdirSync(output,{mode:0o755});
for(const[n,bytes]of Object.entries(payload)){const target=path.join(output,n);fs.mkdirSync(path.dirname(target),{recursive:true,mode:0o755});fs.writeFileSync(target,bytes,{flag:'wx',mode:0o644});assert(fs.readFileSync(target).equals(bytes));assert(read(n).equals(bytes));}
console.log(JSON.stringify({ok:true,files:107,original_signed_predecessor:true,source_head:head,merge_commit:merge.merge_commit_sha,retained_catalog_sha256:sha(catalog),new_signature_operations:0,no_app_installation:true,all50_commercial:false}));
