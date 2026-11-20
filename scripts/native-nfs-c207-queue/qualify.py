from pathlib import Path
import json,sys,platform,hashlib
out=Path(sys.argv[1]);fixture=Path(sys.argv[2]);p=json.loads((fixture/'dispatch.json').read_bytes())
assert platform.machine()=='x86_64'
before=(out/'original-baseline.stdout').read_text();after=(out/'reviewed-native.stdout').read_text()
assert '--- FAIL: TestQueuedModuleOperationCannotRunAfterUninstall' in before and '409' in before and '未执行排队操作' in before
assert after.count('--- PASS:')==6 and '--- FAIL:'not in after and 'PASS\n' in after
for name in ('disk-read','nfs-client-read','nfs-server-start','nfs-export-write','nfs-client-mount'):assert '--- PASS: TestQueuedModuleOperationCannotRunAfterUninstall/'+name in after
proof={'ok':True,'scope':'Native Linux AMD64 Root shared handler tests only; not real NFS business acceptance','original_baseline_failed':True,'reviewed_tests_passed':6,'programme_source_inputs_sha256':p['programme_source_inputs_sha256'],'test_only_replacement_sha256':p['reviewed_test_sha256'],'production_code_changed':False,'artifacts':{f.name:hashlib.sha256(f.read_bytes()).hexdigest()for f in out.iterdir()if f.is_file()},'Main_changed':False,'all50_commercial':False}
(out/'qualified.json').write_text(json.dumps(proof,indent=2)+'\n');print(json.dumps(proof))
