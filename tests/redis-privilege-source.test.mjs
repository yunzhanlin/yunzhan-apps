import test from'node:test';
import fs from'node:fs';
import path from'node:path';
import assert from'node:assert/strict';
import{createHash}from'node:crypto';
import{fileURLToPath}from'node:url';
const root=fileURLToPath(new URL('../',import.meta.url)),scope='panel-integration-redis-privilege/',read=n=>fs.readFileSync(root+n),json=n=>JSON.parse(read(n)),sha=b=>createHash('sha256').update(b).digest('hex');
test('F44 exports the exact ordinary1358-Go-source candidate with zero overrides and only the reviewed Redis delta',()=>{
 const raw=read(scope+'source-sha256.json'),index=JSON.parse(raw),oldRaw=read('panel-integration-geodata-admission/source-sha256.json'),old=JSON.parse(oldRaw);
 assert.equal(sha(raw),'808d7eb3a5d913e186808d7913dc98acdd53cb0754330b009c0a9652ceb93d9e');
 assert.equal(sha(oldRaw),'ea16ede378153191b7265807399078fcaabc3940aa322d21b9dd8ded79d188f4');
 assert.deepEqual(index.test_overrides,{});assert.equal(Object.keys(index.files).length,1813);
 assert.deepEqual(json(scope+'release-source-inputs.json'),{...index.release,files:index.files});
 assert.equal(sha(read(scope+'release-source-inputs.json')),'3641596879bdc4f6f069e0aea1b91e8f37e921a7e3107f9ac726df982d2adcc6');
 assert.equal(index.release.frozen_inputs_sha256,'7eda920eaa2431390acfceb1dd797fd53b5d5eb0464602a10742ad1ebe527903');
 assert.equal(index.release.archive,'panel-0.1.0-dev.proapps24redisprivbkxu-linux-amd64.tar.gz');
 assert.equal(index.release.archive_sha256,'7f8fbb30825401d3f0da1fb19e1a206fb111ea9318ac28677a17f129eaa663ee');
 assert.deepEqual(Object.keys(old.files).filter(n=>old.files[n]!==index.files[n]),['dev/panel-redis@.service','internal/executor/redis_linux.go']);
 assert.deepEqual(Object.keys(index.files).filter(n=>!old.files[n]),['internal/executor/redis_privilege_linux.go','internal/executor/redis_privilege_linux_test.go','internal/executor/redis_privilege_native_qa_linux_test.go']);
 assert.equal(Object.keys(index.files).filter(n=>n.endsWith('.go')).length,1358);
 for(const[n,h]of Object.entries(index.files)){
  assert.equal(path.posix.normalize(n),n);assert(!path.isAbsolute(n)&&!n.split('/').some(v=>['..','.git','.local','node_modules'].includes(v)));
  const s=fs.lstatSync(root+scope+n);assert(s.isFile()&&!s.isSymbolicLink()&&s.nlink===1);assert.equal(sha(read(scope+n)),h,n);
 }
 assert.equal(sha(read('dist/catalog-v1.json')),'bc0dcdbcd0bcd5e75c889471a9e26168c951f943f772e0400d328af8d3e5f84f');
 assert.equal(index.files['web/src/FileManager.vue'],'f4ae7a99782e0705d9e7cc34b2b6df130fee5fdf5546afc3cad4d9b1370f92bc');
 assert(!Object.keys(index.files).some(n=>n.includes('memcached_unix')||n.includes('memcached_sandbox')));
});
test('the default Redis entry uses the locked-thread zero-capability handover and retains every existing identity/authentication check',()=>{
 const code=read(scope+'internal/executor/redis_linux.go').toString(),helper=read(scope+'internal/executor/redis_privilege_linux.go').toString();
 const begin=code.indexOf('func ServeRedis('),end=code.indexOf('\nfunc redisPing(',begin),serve=code.slice(begin,end);
 for(const text of ['runtimeUseLock()','validateRedisServingAuth(instance)','LoadRuntime(release.ID)','user.Lookup("panel-redis")','validateRedisNewRuntimeDirectory(id, uint32(gid))','return redisExecUnprivileged(binary, filepath.Join(redisConfig(id), "redis.conf"), uid, gid)'])assert(serve.includes(text),text);
 for(const text of ['runtime.LockOSThread()','defer runtime.UnlockOSThread()','unix.PR_GET_NO_NEW_PRIVS','unix.PR_CAP_AMBIENT_CLEAR_ALL','unix.Capset','unix.Capget','/proc/thread-self/status','taskSafeProcessStatus','unix.Getresuid()','unix.Getresgid()'])assert(helper.includes(text),text);
 const unit=read(scope+'dev/panel-redis@.service').toString();
 for(const text of ['User=root\n','Group=panel-redis\n','NoNewPrivileges=true\n','CapabilityBoundingSet=CAP_CHOWN CAP_SETGID CAP_SETUID\n','AmbientCapabilities=CAP_SETUID\n','RuntimeDirectoryMode=0770\n','ProtectSystem=strict\n','RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\n'])assert(unit.includes(text),text);
 assert(!unit.includes('CAP_SYS_ADMIN')&&!unit.includes('CAP_DAC_OVERRIDE')&&!helper.includes('os.Getenv'));
});
test('all30 original workflow jobs remain byte-exact before the bounded independent Root product-helper gate',()=>{
 const raw=read('.github/workflows/verify.yml'),at=raw.indexOf('\n  redis-privilege-native-amd64:\n');assert.equal(at,100752);
 assert.equal(sha(raw.subarray(0,at)),'7c2822a1682818f1af51ed820f40ec192c48084cf54c302a27d86b52c7a932a4');
 const gate=raw.subarray(at).toString();
 for(const text of ['timeout-minutes: 20','panel_redis_privilege_native_qa','tools/run-redis-privilege-native-ci.py','tools/run-redis-privilege-packaging-ci.py','sudo "$(command -v go)" test -p 1 ./...','tests/redis-privilege-source.test.mjs'])assert(gate.includes(text),text);
 for(const text of ['continue-on-error','reset-failed','pkill','killall','--overlay'])assert(!gate.includes(text),text);
 const runner=read('tools/run-redis-privilege-native-ci.py').toString();
 for(const text of ["os.geteuid()==0","Never adopts an existing host account","-test.run=^TestRedisPrivilegeNativeExecHandover$","CapabilityBoundingSet=CAP_CHOWN CAP_SETGID CAP_SETUID","AmbientCapabilities=CAP_SETUID","'models':3","'installed_Redis_or_store_API_acceptance':False","'all50_commercial':False"])assert(runner.includes(text),text);
 assert.equal(sha(read('tools/redis-privilege-ci-probe.py')),'f802291a311263384a57c6bab1440335ae92e85ca6d57fbe90644f5b748dd85d');
 const packaging=read('tools/run-redis-privilege-packaging-ci.py').toString();assert(packaging.includes('result.testsRun==264')&&packaging.includes('not result.skipped'));
});

