import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
const root=fileURLToPath(new URL('../',import.meta.url)),scope='panel-integration-redis-cli/';
const read=n=>fs.readFileSync(root+n),json=n=>JSON.parse(read(n)),sha=b=>createHash('sha256').update(b).digest('hex');
const inputs='943aaf12007348b29857d0865f7635f55beaf8fbc0e1279c97e9da6a2d9b9f74',indexSHA='cdde3866712e222a3f87ca7e4dfa38c2aa7a269574ed959e4848fcf8781e1c71';
test('Redis and Compose candidate is exactly1805 normal frozen members with1351 Go sources and zero overlays',()=>{
 const raw=read(scope+'source-sha256.json'),index=JSON.parse(raw);assert.equal(sha(raw),indexSHA);
 assert.equal(index.release.frozen_inputs_sha256,inputs);assert.equal(index.release.archive_sha256,'b2f00cc540b575ba84965b7cfb4e6bd6749880dda935879a96443e875df12c2f');
 assert.equal(index.release.archive,'panel-0.1.0-dev.proapps24composeclibksv-linux-amd64.tar.gz');
 assert.equal(Object.keys(index.files).length,1805);assert.equal(Object.keys(index.files).filter(n=>n.endsWith('.go')).length,1351);
 assert.deepEqual(index.test_overrides,{});assert.deepEqual(json(scope+'release-source-inputs.json'),{...index.release,files:index.files});
 for(const[n,h]of Object.entries(index.files)){
  assert.equal(path.posix.normalize(n),n);assert(!path.isAbsolute(n)&&!n.split('/').some(v=>['..','.git','.local','node_modules'].includes(v)));
  const s=fs.lstatSync(root+scope+n);assert(s.isFile()&&!s.isSymbolicLink()&&s.nlink===1);assert.equal(sha(read(scope+n)),h,n);
 }
});
test('F39 remains byte-exact and only six reviewed members and nine additions differ,without unfinished Memcached profiles',()=>{
 const oldRaw=read('panel-integration-module-version/source-sha256.json'),old=JSON.parse(oldRaw),now=json(scope+'source-sha256.json');
 assert.equal(sha(oldRaw),'37b5a6885fc685204ca8b15f2bc2d873013749a25987973d39bd8386dcbff491');
 assert.equal(old.release.frozen_inputs_sha256,'41c4295d400488bc6d69faa6a36a3a9556fc50b0b7e14d2011b083b964113cb4');
 assert(Object.keys(old.files).every(n=>Object.hasOwn(now.files,n)));
 assert.deepEqual(Object.keys(old.files).filter(n=>old.files[n]!==now.files[n]).sort(),["internal/core/redis.go","internal/executor/docker_compose_linux.go","internal/executor/redis_keys_linux.go","internal/executor/redis_linux.go","packaging/build-release.sh","web/src/RedisManager.vue"]);
 assert.deepEqual(Object.keys(now.files).filter(n=>!Object.hasOwn(old.files,n)).sort(),["internal/core/redis_auth.go","internal/core/redis_auth_test.go","internal/executor/docker_compose_cli_linux.go","internal/executor/docker_compose_cli_linux_test.go","internal/executor/redis_auth_linux.go","internal/executor/redis_auth_linux_test.go","internal/executor/redis_auth_native_qa_linux_test.go","internal/executor/redis_resp_linux.go","scripts/test-redis-credentials.mjs"]);
 for(const n of ['internal/executor/program_upgrade_queues_linux.go','internal/executor/runtime_install_resources_linux.go','internal/executor/install_linux.go','internal/runtimecatalog/catalog.go','web/src/FileManager.vue'])assert.equal(now.files[n],old.files[n],n);
 assert.equal(now.files['web/src/FileManager.vue'],'f4ae7a99782e0705d9e7cc34b2b6df130fee5fdf5546afc3cad4d9b1370f92bc');
 assert(!Object.keys(now.files).some(n=>n.includes('memcached_unix')||n.includes('memcached_sandbox')));
 const feature=read(scope+'internal/appcatalog/panel_features.go').toString();assert(!feature.includes('MemcachedSandboxFeature')&&!feature.includes('MemcachedUnixFeature'));
});
test('all28 original verification jobs remain byte-identical before an independent29th full native gate',()=>{
 const raw=read('.github/workflows/verify.yml'),at=raw.indexOf('\n  redis-cli-native-amd64:\n');assert.equal(at,97793);
 assert.equal(sha(raw.subarray(0,at)),'67af85a872488ab748a1128b2e1cf72b11797e90b94639945c996d3b06694e65');
 const gate=raw.subarray(at).toString();
 for(const x of ['panel-integration-redis-cli','tools/run-redis-cli-isolated-ci.py','go vet ./...','TestPublishedRepositoryCurrentSignedManifestABI','scripts/test-redis-credentials.mjs','test_*.py'])assert(gate.includes(x),x);
 for(const x of ['continue-on-error','-overlay=','reset-failed','killall','pkill'])assert(!gate.includes(x),x);
});
test('new privileged CI reuses exact Root tool-sealing and private mount guards with a genuine unchanged Apache prerequisite',()=>{
 const old=read('tools/run-module-version-isolated-ci.py').toString(),now=read('tools/run-redis-cli-isolated-ci.py').toString();
 const functions=s=>s.slice(s.indexOf('def opt_identity('),s.indexOf('def main('));assert.equal(functions(now),functions(old));
 for(const x of ['prepare-module-version-apache-ci.py','run-redis-cli-native-ci.mjs',"go,'--race'",'host_opt_identity_unchanged','existing_host_parent_permission_changes'])assert(now.includes(x),x);
 const runner=read('tools/run-redis-cli-native-ci.mjs').toString();
 const groupStart=runner.indexOf('const groups='),groupEnd=runner.indexOf('],out={',groupStart);assert(groupStart>0&&groupEnd>groupStart);
 const groups=JSON.parse(runner.slice(groupStart+'const groups='.length,groupEnd+1));assert.deepEqual(groups.map(g=>g.expectedPasses),[90,93,13,7]);assert.deepEqual(groups.map(g=>g.names.length),[11,16,2,7]);
 for(const x of [inputs,"e.Action==='skip'",'private_integration_not_host_app_installation:true','all50_commercial:false'])assert(runner.includes(x),x);
 assert(runner.includes("out.groups[g.name]")&&runner.includes("'redis-cli-native-ci-'+g.name"));
});
test('Compose namespace repair pins a closed empty Root configuration without personal credentials or permission repair',()=>{
 const helper=read(scope+'internal/executor/docker_compose_cli_linux.go').toString(),invoke=read(scope+'internal/executor/docker_compose_linux.go').toString();
 for(const x of ['openDockerMutationTree(state)','unix.RENAME_NOREPLACE','syscall.O_NOFOLLOW','visible.Size() != 2','bytes.Equal(raw, []byte("{}"))','!tree.current()','DOCKER_CONFIG='])assert(helper.includes(x),x);
 assert(invoke.includes('environment, err := composeCLIEnvironment()')&&invoke.includes('cmd.Env = environment'));
 for(const x of ['os.Chmod','os.Chown','os.Setenv','os.Getenv'])assert(!helper.includes(x),x);
 assert(!helper.includes('HOME=')&&!helper.includes('DOCKER_HOST='));
});
test('Redis app-only no-store authority and executable masked-memory UI regression remain in ordinary release inputs',()=>{
 const core=read(scope+'internal/core/redis_auth.go').toString(),engine=read(scope+'internal/executor/redis_auth_linux.go').toString(),ui=read(scope+'web/src/RedisManager.vue').toString(),build=read(scope+'packaging/build-release.sh').toString();
 for(const x of ['Cache-Control", "no-store','access.Role == "admin"','redis.credentials.read','reflect.DeepEqual(before, after)','app-"+id[:12]'])assert(core.includes(x),x);
 assert(engine.includes('user default reset off')&&engine.includes('-@admin -@dangerous'));
 assert(ui.includes('type="password" show-password readonly autocomplete="new-password"'));assert(!ui.includes('localStorage')&&!ui.includes('sessionStorage')&&!ui.includes('navigator.clipboard'));
 assert(build.includes('node --test scripts/test-redis-credentials.mjs'));
 assert(Object.hasOwn(json(scope+'source-sha256.json').files,'scripts/test-redis-credentials.mjs'));
});
