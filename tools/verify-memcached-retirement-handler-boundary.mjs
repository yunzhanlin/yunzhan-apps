import assert from'node:assert/strict';import fs from'node:fs';import path from'node:path';import{fileURLToPath}from'node:url';import{spawnSync}from'node:child_process';import{createHash,createPublicKey,verify}from'node:crypto';
export const oldMemcachedRefusal='Memcached Unix Socket 仅接受固定完整 compat4、固定 OCI 镜像及两个独立处理器声明';
export function verifyOldMemcachedRefusal(result,ids){
 assert.equal(result.status,1);assert(!result.error&&!result.signal);
 assert.equal(ids.length,50);assert.equal(new Set(ids).size,50);assert(ids.includes('memcached'));
 assert.equal(typeof result.stdout,'string');assert(result.stdout.length>0&&result.stdout.length<4<<20);
 const events=result.stdout.trim().split('\n').map(line=>JSON.parse(line)),prefix='TestPublishedRepositoryCurrentSignedManifestABI';
 assert(events.length<4096);assert(!events.some(e=>e.Action==='skip'));
 assert.deepEqual(events.filter(e=>e.Action==='fail'&&e.Test).map(e=>e.Test).sort(),[prefix,prefix+'/memcached']);
 assert.deepEqual(events.filter(e=>e.Action==='pass'&&e.Test).map(e=>e.Test).sort(),ids.filter(id=>id!=='memcached').map(id=>prefix+'/'+id).sort());
 assert.equal(events.filter(e=>!e.Test&&e.Action==='fail').length,1);
 assert(events.some(e=>e.Test===prefix+'/memcached'&&e.Output?.includes(oldMemcachedRefusal)));
 return{other49_passed:49,only_memcached_closed_three_handler_contract_refused:true,old_compiled_handler_unchanged:true,source_overlays:0,application_installation:false};
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 assert.equal(process.platform,'linux');assert.equal(process.getuid(),0);
 assert(process.argv.length===3&&path.isAbsolute(process.argv[2]),'Only an explicit Go executable; no source/repository/trust override');
 const root=fileURLToPath(new URL('../',import.meta.url)),source=root+'panel-integration-memcached-retirement/',sha=b=>createHash('sha256').update(b).digest('hex'),read=n=>fs.readFileSync(root+n);
 const indexRaw=fs.readFileSync(source+'source-sha256.json'),index=JSON.parse(indexRaw);
 assert.equal(sha(indexRaw),'1c0ff2ce9e52521e0ea559c0556c4b7ecf1996bce9b2e278ec5dfd0bd054b282');assert.equal(sha(fs.readFileSync(source+'release-source-inputs.json')),'cd0b08f7a6d72a3c3cab051cfa701e0f7d1bcb9866a8e9af925ffd2c261970b5');
 assert.equal(index.release.frozen_inputs_sha256,'324e66f7d7f4a9686bfb32ab2ff966538ae26955dc1a567bc6ee746679702495');
 assert.equal(Object.keys(index.files).length,1919);assert.deepEqual(index.test_overrides,{});
 function sources(){for(const[n,digest]of Object.entries(index.files)){
  assert(path.posix.normalize(n)===n&&!path.isAbsolute(n)&&!n.split('/').includes('..'));
  const file=source+n,s=fs.lstatSync(file);assert(s.isFile()&&!s.isSymbolicLink()&&s.nlink===1&&fs.realpathSync(file)===file);assert.equal(sha(fs.readFileSync(file)),digest,n);
 }}
 sources();const raw=read('dist/catalog-v1.json'),pub=read('signatures/catalog-v1.pub.pem'),signature=read('signatures/catalog-v1.sig').toString().trim(),bundle=JSON.parse(read('signatures/catalog-v1.bundle.json'));
 assert.equal(sha(pub),'659ea4edcecaf23a586e2ff371616fde5f6ee7c219fb70fa978816e2b10acf75');assert.equal(bundle.catalog,raw.toString());assert.equal(bundle.signature,signature);assert(verify(null,raw,createPublicKey(pub),Buffer.from(signature,'base64')));
 const catalog=JSON.parse(raw),item=catalog.apps.find(a=>a.id==='memcached');assert.equal(catalog.apps.length,50);assert.equal(new Set(catalog.apps.map(a=>a.id)).size,50);assert.equal(item?.version,'1.6.45-compat4');
 const bytes=read('dist/apps/memcached/1.6.45-compat4/manifest.json'),manifest=JSON.parse(bytes);assert.equal(sha(bytes),item.sha256);
 assert.deepEqual([...manifest.required_panel_features].sort(),['compose-memcached-digest-v1','compose-memcached-retirement-v1','compose-memcached-unix-v1']);
 assert.equal(manifest.delivery.provider,'compose');assert.equal(manifest.delivery.target,'memcached-cache');assert.equal(manifest.delivery.manage_route,'docker');
 const go=fs.realpathSync(process.argv[2]),st=fs.lstatSync(go);assert(st.isFile()&&!st.isSymbolicLink()&&(st.mode&0o111));
 const result=spawnSync(go,['test','-json','./internal/appcatalog','-run','^TestPublishedRepositoryCurrentSignedManifestABI$','-count=1','-args','-published-app-registry-root',root],{cwd:source,encoding:'utf8',timeout:180000,maxBuffer:4<<20});
 process.stdout.write(result.stdout??'');process.stderr.write(result.stderr??'');sources();console.log(JSON.stringify(verifyOldMemcachedRefusal(result,catalog.apps.map(a=>a.id))));
}
