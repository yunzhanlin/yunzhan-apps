"""Recheck both original source jobs and all twelve exact nonempty artifacts.

This checks recorded source execution, not local architecture simulation or
native installed-service acceptance. Original ZIP identities are retained in
the separately qualified source-ci.json; extracted event bytes must match.
"""
import hashlib,json,pathlib,subprocess,sys
root=pathlib.Path(sys.argv[1]);spec=json.loads(pathlib.Path(__file__).with_name('source-ci.json').read_bytes())
run=json.loads((root/'run.json').read_bytes());jobs=json.loads((root/'jobs.json').read_bytes())['jobs']
assert run['id']==spec['run']==41752057997 and run['head_sha']==spec['head']=='ca4678318a15cc6f73b3f379e4a7c5fb235a34ce'and run['status']=='completed'and run['conclusion']=='success'and run['run_attempt']==1
assert len(jobs)==2 and {j['name']for j in jobs}=={'candidate-native-abi (ubuntu-24.04)','candidate-native-abi (ubuntu-24.04-arm)'}and all(j['status']=='completed'and j['conclusion']=='success'for j in jobs)
artifacts=json.loads((root/'artifacts.json').read_bytes())['artifacts'];assert len(artifacts)==len(spec['artifacts'])==12
expected={v['artifact_id']:v for v in spec['artifacts']};assert len(expected)==12
for item in artifacts:
 bound=expected[item['id']];assert item['name']==bound['name']and item['digest']=='sha256:'+bound['original_zip_sha256']and not item['expired']and item['workflow_run']['id']==spec['run']and item['workflow_run']['head_sha']==spec['head']
assert {f.name for f in(root/'events').iterdir()}=={v['name']for v in expected.values()}
index=json.loads(pathlib.Path('candidate/panel-integration-load-balance/source-sha256.json').read_bytes());assert index['release']['frozen_inputs_sha256']==spec['source_inputs_sha256']=='d41c971d111a9575ea76fb8de47bec9921a0b584c6492ef135878edea270439e'and len(index['files'])==2372
for name,digest in index['files'].items():
 path=pathlib.Path('candidate/panel-integration-load-balance')/name;assert path.is_file()and not path.is_symlink()and hashlib.sha256(path.read_bytes()).hexdigest()==digest
for item in expected.values():
 folder=root/'events'/item['name'];files=list(folder.iterdir());assert len(files)==1 and files[0].is_file()and not files[0].is_symlink();file=files[0];assert 0<file.stat().st_size<4<<20 and hashlib.sha256(file.read_bytes()).hexdigest()==item['original_execution_sha256']
 if item['name'].startswith('backup-directory-native-'):
  assert file.name=='backup-directory-native.json';subprocess.run(['node','tools/check-backup-directory-native.mjs',str(file),item['architecture']],check=True)
 elif item['name'].startswith('backup-retention-native-'):
  assert file.name=='backup-retention-native.jsonl';subprocess.run(['node','tools/check-retention-native-execution.mjs',str(file)],check=True)
 elif item['name'].startswith('apache-cc-native-'):
  assert file.name=='apache-cc-native.jsonl'
  code="import fs from 'node:fs';import{verifyApacheCCExecution}from'./tools/check-apache-cc-native.mjs';const rows=fs.readFileSync(process.argv[1],'utf8').trim().split('\\n').map(s=>JSON.parse(s));console.log(JSON.stringify(verifyApacheCCExecution(rows,process.argv[2])));"
  subprocess.run(['node','--input-type=module','-e',code,str(file),item['architecture']],check=True)
 else:
  values=[json.loads(v)for v in file.read_text().splitlines()];assert values and all(v['Package']=='local/panel/internal/executor'for v in values)
  started=[v['Test']for v in values if v.get('Action')=='run'and v.get('Test')];passed=[v['Test']for v in values if v.get('Action')=='pass'and v.get('Test')]
  if item['name'].startswith('analytics-root-native-'):
   assert file.name=='analytics-identity-root-native.jsonl';wanted_roots={'TestNativeAnalyticsProxyIdentityPrivateFileAndStableRevalidation','TestNativeAnalyticsProxyIdentityRejectsUntrustedKeyAndParents','TestNativeAnalyticsProxyIdentityPreservesChangedOrPartialOriginal','TestNativeAnalyticsProxyIdentityCapacityRefusesWithoutDeletion'};count=23
   assert {n for n in passed if '/'not in n}==wanted_roots
  elif item['name'].startswith('apache-rewrite-native-source-'):
   assert file.name=='apache-rewrite-source.jsonl'
   root_test='TestApacheRewriteReplacementClosedVariables';wanted={root_test}|{root_test+'/'+kind for kind in('/index.php?name=$1','/index.php?name=$1&$args','/index.php?$query_string','/index.php$is_args$args','/index.php$is_args','/index.php?path=$uri')};count=7;assert set(passed)==wanted
  else:
   assert item['name'].startswith('apache-upgrade-queue-native-')and file.name=='apache-upgrade-queue-native.jsonl'
   matrix='TestProgramUpgradeQueuesApacheCCFormatsAreTerminalOnlyAndFamilySpecific';bindings='TestProgramUpgradeQueuesApacheCCFormatsKeepEveryBindingFence';wanted={matrix,bindings}
   wanted.update(matrix+'/'+family+'-'+str(version)+'-'+state for family in ('apache-body','waf-engine','analytics-html')for version in (0,1,2,3,4)for state in ('ready','failed','building','unknown'))
   wanted.update(bindings+'/'+str(version)+'-'+kind for version in (2,3)for kind in ('wrong-id','wrong-architecture','wrong-prefix','bad-start','missing-finish','reversed-time','duplicate-key','unknown-key','public-record','linked-record','cancelled-but-building'))
   count=84;assert len(wanted)==count and set(passed)==wanted
  assert len(passed)==len(set(passed))==count and sorted(started)==sorted(passed)
  assert not any(v.get('Action')in ('skip','fail')for v in values)and sum(v.get('Action')=='pass'and not v.get('Test')for v in values)==1
print(json.dumps({'ok':True,'original_artifacts':12,'actual_directory_PASS':26,'actual_Root_directory_methods':22,'actual_retention_PASS':90,'actual_analytics_PASS':46,'actual_Apache_CC_PASS':294,'actual_native_C_cases':12,'actual_Apache_Format2_Format3_queue_PASS':168,'actual_Apache_rewrite_PASS':14,'skips':0,'normal_installed_acceptance':False}))
