import test from 'node:test';import assert from 'node:assert/strict';import {readFile} from 'node:fs/promises';import {createHash} from 'node:crypto';
const read=p=>readFile(new URL('../'+p,import.meta.url),'utf8');
test('complete private inventory optimization retains exact limits, byte identity, bounded readers and original CI failure evidence',async()=>{
 const index=JSON.parse(await read('panel-integration/source-sha256.json')),inputs=JSON.parse(await read('panel-integration/release-source-inputs.json'));
 assert.equal(inputs.archive_sha256,'89e1afb677871c939b955970dd914649dc517f8dfd0913405b2b720cfb0c6241');assert.equal(inputs.frozen_inputs_sha256,'202f4a57cdbf8889fac52778f7d191e6b40139de36264d17a857c563d2946832');assert.equal(Object.keys(index.files).length,1217);assert.equal(Object.keys(index.test_overrides??{}).length,0);
 for(const file of ['internal/executor/app_load_balance_linux.go','internal/executor/app_load_balance_history_linux.go','internal/executor/app_load_balance_history_read_linux_test.go','internal/executor/app_load_balance_traffic_alert_linux_test.go']){
  const sha=createHash('sha256').update(await read('panel-integration/'+file)).digest('hex');assert.equal(inputs.files[file],sha);assert.equal(index.files[file],sha);
 }
 const privateRead=await read('panel-integration/internal/executor/app_load_balance_linux.go');
 for(const text of ['io.ReadFull(f, b)','readError != io.EOF','unix.Fstat(int(f.Fd()), &after)','loadBalancePrivateStatUnchanged(st, after)','a.Nlink == b.Nlink','a.Mtim == b.Mtim && a.Ctim == b.Ctim','st.Mode&07777 != 0600','st.Nlink != 1','st.Size > limit'])assert(privateRead.includes(text),text);
 const history=await read('panel-integration/internal/executor/app_load_balance_history_linux.go');
 for(const text of ['bytes.TrimRight(b, " \\t\\r\\n")','sha256.Sum256(b)','hex.EncodeToString(digest[:])','for i := 0; i < 2 && i < len(records); i++','workers.Wait()','row.Bytes != item.bytes','return nil, firstError','ctx.Err()','loadBalanceActiveTransactions = 512','loadBalanceArchivedTransactions = 2048','loadBalanceArchiveBytes int64 = 256 << 20','size > spec.budget-st.Size()'])assert(history.includes(text),text);
 assert.equal((await read('panel-integration/internal/executor/app_load_balance_history_read_linux_test.go')).match(/^func Test/gm).length,3);
 const capacity=await read('panel-integration/internal/executor/app_load_balance_traffic_alert_linux_test.go');assert(capacity.includes('context.WithTimeout(context.Background(), 2*time.Second)'));assert(capacity.includes('len(bounded.Records) != 2560'));assert(capacity.includes('production-size private warm fixture exceeded source read budget'));
 const ci=await read('.github/workflows/verify.yml');assert(ci.includes("test -race ./internal/executor -run '^TestLoadBalanceHistoryParallelReadersRemainBoundedAndFailClosed$' -count=1"));
 const c=JSON.parse(await read('registry/functional-contracts.json')),r=c.reviewed_normal_release,previous=c.previous_gateway_release;
 assert.equal(r.release,'0.1.0-dev.proapps24inventorybefm');assert.equal(r.frozen_source_files,16851);assert.equal(r.source_overrides,0);assert.equal(r.actual_signed_ordinary_upgrade_proof_sha256,'fe0e1b1a4cecd44827682eb4d39fa011e9b0364684e1630157bc3b11d3485dd5');assert.equal(r.actual_ordinary_upgrade_original_sql_tables_compared,19);
 assert.equal(previous.actual_first_github_pr_ci_passed,false);assert.equal(previous.actual_first_github_pr_ci_run,38182561913);assert.equal(previous.actual_first_github_pr_ci_failure_log_sha256,'56d8e48832b48ea794ceaf389e4812c55f3013c0bd20df152b1b42e9a201a0f5');assert.equal(previous.actual_first_github_pr_ci_capacity_scan_seconds,3.020288724);assert.equal(previous.actual_first_github_pr_ci_source_deadline_seconds,2);
 assert.equal(r.candidate_inventory_reader_performance.pass_count,5);assert.equal(c.commercial_feature_parity_complete,false);assert.equal(r.all_50_commercial,false);assert.equal(r.main_release_delivered,true);
});
