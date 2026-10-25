import{historicalMemcachedUnixInput}from'./reviewed-memcached-unix-inputs.mjs';
import{originalReviewedHTTPSFixtureWorkflow}from'./reviewed-https-fixture-workflow.mjs';
import test from'node:test';
import assert from'node:assert/strict';
import fs from'node:fs';
import path from'node:path';
import{createHash}from'node:crypto';
import{execFileSync}from'node:child_process';
import{fileURLToPath}from'node:url';
const root=fileURLToPath(new URL('../',import.meta.url)),scope='panel-integration-geodata-admission/',read=n=>historicalMemcachedUnixInput(root,n),json=n=>JSON.parse(read(n)),sha=b=>createHash('sha256').update(b).digest('hex');
const inputs='0d6a44f5ac65e2e62c209f68ea4f208276888e3ad7fd8a06777da164dc234fad';
test('F43 contains exactly1810 normal frozen members and all1355 Go inputs are byte-identical to F42',()=>{
 const raw=read(scope+'source-sha256.json'),now=JSON.parse(raw),oldRaw=read('panel-integration-redis-cli/source-sha256.json'),old=JSON.parse(oldRaw);
 assert.equal(sha(raw),'ea16ede378153191b7265807399078fcaabc3940aa322d21b9dd8ded79d188f4');
 assert.equal(sha(oldRaw),'e3a905357c346b266607ce3debc804a429727d390db624413c283c2a81d8717f');
 assert.equal(now.release.frozen_inputs_sha256,inputs);
 assert.equal(now.release.archive,'panel-0.1.0-dev.proapps24geoadmissionbkwc-linux-amd64.tar.gz');
 assert.equal(now.release.archive_sha256,'2b373c7ec2742b9b803711eb7dbdd0ae48bf9acedf4e8413b13fdc105728e225');
 assert.deepEqual(now.test_overrides,{});assert.equal(Object.keys(now.files).length,1810);
 assert.deepEqual(json(scope+'release-source-inputs.json'),{...now.release,files:now.files});
 assert.equal(sha(read(scope+'release-source-inputs.json')),'5a77be9892ec09210abdc09b05dfa5f052cf629497f9f91f1e7318d5eadf94de');
 assert.deepEqual(Object.keys(old.files).filter(n=>old.files[n]!==now.files[n]),['packaging/upgrade-release.py']);
 assert.deepEqual(Object.keys(now.files).filter(n=>!old.files[n]),['packaging/test_statistics_reader_admission.py']);
 const go=Object.keys(now.files).filter(n=>n.endsWith('.go'));assert.equal(go.length,1355);for(const n of go)assert.equal(now.files[n],old.files[n],n);
 for(const[n,h]of Object.entries(now.files)){
  assert.equal(path.posix.normalize(n),n);assert(!path.isAbsolute(n)&&!n.split('/').some(p=>['..','.git','.local','node_modules'].includes(p)));
  const s=fs.lstatSync(root+scope+n);assert(s.isFile()&&!s.isSymbolicLink()&&s.nlink===1);assert.equal(sha(read(scope+n)),h,n);
 }
});
test('complete guard and all mutation/recovery paths keep their exact original AST',()=>{
 const code="import ast,copy,json,sys\np=json.load(sys.stdin);before=ast.parse(p['before']);after=ast.parse(p['after'])\ndef normalize(tree):\n tree=copy.deepcopy(tree);tree.body=[n for n in tree.body if not(isinstance(n,ast.FunctionDef)and n.name=='original_statistics_reader_can_be_observed_again')]\n for n in tree.body:\n  if isinstance(n,ast.ClassDef)and n.name=='Upgrade':n.body=[x for x in n.body if not(isinstance(x,ast.FunctionDef)and x.name=='preflight_queue_check')]\n return ast.dump(tree,include_attributes=False)\nassert normalize(before)==normalize(after)\nadded=[n.name for n in after.body if isinstance(n,ast.FunctionDef)and n.name not in {x.name for x in before.body if isinstance(x,ast.FunctionDef)}]\nassert added==['original_statistics_reader_can_be_observed_again'];print(json.dumps({'complete_guard_and_mutation_recovery_AST_identical':True,'only_new_closed_classifier_and_preflight_method':True}))\n";
 const out=JSON.parse(execFileSync('python3',['-I','-B','-c',code],{input:JSON.stringify({before:read('panel-integration-redis-cli/packaging/upgrade-release.py').toString(),after:read(scope+'packaging/upgrade-release.py').toString()}),encoding:'utf8'}));
 assert(out.complete_guard_and_mutation_recovery_AST_identical&&out.only_new_closed_classifier_and_preflight_method);
});
test('new read-only admission waits only exact original typed cache observations and retains finite independent guard bounds',()=>{
 const s=read(scope+'packaging/upgrade-release.py').toString(),method=s.slice(s.indexOf('    def preflight_queue_check('),s.indexOf('    def preflight_service_states('));
 for(const x of ["value['unit'] != 'panel-geodata-verify-cache.service'","original_native_queue_observation_reason(text)","statistics_deadline = now + 310","statistics_reads == 64","not self.preflight_admission_is_readonly()","periodic_reads == 2","time.sleep(0.25)","time.sleep(5)","self.queue_check()","raise statistics_error"])assert((x.startsWith("value[")||x.startsWith('original_native'))?s.includes(x):method.includes(x),x);
 for(const x of ['systemctl','reset-failed','SIGKILL','killall','subprocess.run','self.stop_timer','self.acquire_geodata_lease','self.create_pending'])assert(!method.includes(x),x);
 const regression=read(scope+'packaging/test_statistics_reader_admission.py').toString();
 for(const x of ['test_real_new_sql_job_during_wait_refuses_before_backup_or_program_change','test_real_under_runtime_lease_guard_stays_direct_and_never_waits','test_late_success_is_not_a_bounded_admission_proof','test_count_cap_refuses_even_if_clock_does_not_advance','test_scope_is_revalidated_before_every_further_read','test_real_filesystem_both_layouts_observe_before_each_readonly_admission'])assert(regression.includes(x),x);
 assert(read(scope+'packaging/build-release.sh').toString().includes("unittest discover -s packaging -p 'test_*.py'"));
});
test('all29 original workflow jobs remain byte-exact before an independent bounded Root264-test gate',()=>{
 const raw=originalReviewedHTTPSFixtureWorkflow(read('.github/workflows/verify.yml')),at=raw.indexOf('\n  geodata-admission-native-amd64:\n');assert.equal(at,100016);
 assert.equal(sha(raw.subarray(0,at)),'02f4edf5a95458b985e54955a82f14fe0aba5d8736d69267c5e1054f448f5d61');
 const gate=raw.subarray(at).toString();
 for(const x of ['tools/run-geodata-admission-packaging-ci.py','tests/geodata-admission-source.test.mjs','timeout 240s','timeout-minutes: 10'])assert(gate.includes(x),x);
 for(const x of ['continue-on-error','reset-failed','pkill','killall','--overlay'])assert(!gate.includes(x),x);
 const runner=read('tools/run-geodata-admission-packaging-ci.py').toString();for(const x of ['result.testsRun==264','not result.skipped',"os.geteuid()==0","pattern='test_*.py'","'all50_commercial':False"])assert(runner.includes(x),x);
});
test('original signed50 catalog,File Manager and unavailable Memcached drafts are untouched',()=>{
 assert.equal(sha(read('dist/catalog-v1.json')),'bc0dcdbcd0bcd5e75c889471a9e26168c951f943f772e0400d328af8d3e5f84f');
 const index=json(scope+'source-sha256.json');assert.equal(index.files['web/src/FileManager.vue'],'f4ae7a99782e0705d9e7cc34b2b6df130fee5fdf5546afc3cad4d9b1370f92bc');
 assert(!Object.keys(index.files).some(n=>n.includes('memcached_unix')||n.includes('memcached_sandbox')));
});
