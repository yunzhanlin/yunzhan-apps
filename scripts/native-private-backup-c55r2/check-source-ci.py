"""Bind both real native source jobs and all six original execution files."""
import hashlib,json,pathlib,subprocess,sys
root=pathlib.Path(sys.argv[1]);spec=json.loads(pathlib.Path(__file__).with_name('source-ci.json').read_bytes())
run=json.loads((root/'run.json').read_bytes());assert run['id']==spec['run']and run['head_sha']==spec['head']and run['status']=='completed'and run['conclusion']=='success'
artifacts=json.loads((root/'artifacts.json').read_bytes())['artifacts'];assert len(artifacts)==len(spec['artifacts'])==6
expected={v['artifact_id']:v for v in spec['artifacts']};assert len(expected)==6
for item in artifacts:
 bound=expected[item['id']];assert item['name']==bound['name']and item['digest']=='sha256:'+bound['original_zip_sha256']and not item['expired']and item['workflow_run']['id']==spec['run']and item['workflow_run']['head_sha']==spec['head']
name_set={v['name']for v in expected.values()};assert {f.name for f in(root/'events').iterdir()}==name_set
for item in expected.values():
 folder=root/'events'/item['name'];files=list(folder.iterdir());assert len(files)==1 and files[0].is_file();file=files[0];assert 0<file.stat().st_size<4<<20 and hashlib.sha256(file.read_bytes()).hexdigest()==item['original_execution_sha256']
 if item['name'].startswith('backup-directory-native-'):
  assert file.name=='backup-directory-native.json';subprocess.run(['node','tools/check-backup-directory-native.mjs',str(file),item['architecture']],check=True)
 elif item['name'].startswith('backup-retention-native-'):
  assert file.name=='backup-retention-native.jsonl';subprocess.run(['node','tools/check-retention-native-execution.mjs',str(file)],check=True)
 else:
  assert item['name'].startswith('analytics-root-native-')and file.name=='analytics-identity-root-native.jsonl'
  values=[json.loads(v)for v in file.read_text().splitlines()if v.strip()];assert values and all(v['Package']=='local/panel/internal/executor'for v in values)
  started=sorted(v['Test']for v in values if v.get('Action')=='run'and v.get('Test'));passed=sorted(v['Test']for v in values if v.get('Action')=='pass'and v.get('Test'));roots={n for n in passed if'/'not in n}
  assert len(passed)==len(set(passed))==23 and started==passed and roots=={'TestNativeAnalyticsProxyIdentityPrivateFileAndStableRevalidation','TestNativeAnalyticsProxyIdentityRejectsUntrustedKeyAndParents','TestNativeAnalyticsProxyIdentityPreservesChangedOrPartialOriginal','TestNativeAnalyticsProxyIdentityCapacityRefusesWithoutDeletion'}
  assert not any(v.get('Action')in('skip','fail')for v in values)and sum(v.get('Action')=='pass'and not v.get('Test')for v in values)==1
print(json.dumps({'ok':True,'original_artifacts':6,'actual_directory_methods':26,'actual_Root_directory_methods':22,'actual_retention_PASS':90,'actual_analytics_PASS':46,'skips':0,'normal_installed_acceptance':False}))
