"""Require real, nonempty Linux execution; fixtures are not installed acceptance."""
import hashlib
import json
import pathlib
import platform
import sys

root=pathlib.Path(__file__).resolve().parent.parent
sdk=root/'candidate/panel-integration-load-balance'
index=json.loads((sdk/'source-sha256.json').read_bytes())
assert platform.system()=='Linux' and platform.machine() in ('x86_64','aarch64')
assert index['release']['frozen_inputs_sha256']=='7ae19475cac7a31941533befe97d6288eabcc6f5b8a0ea9b83e3feadc3e8fdda'
assert len(index['files'])==2467 and not index.get('test_overrides')
for name,digest in index['files'].items():
    p=sdk/name
    assert p.is_file() and not p.is_symlink() and hashlib.sha256(p.read_bytes()).hexdigest()==digest,name
expected={
 'local/panel/internal/appcatalog':{
  'TestNativeMobilePublished132RetainsItsOriginalHandler',
  'TestNativeMobileDeliveryRequiresExactCompiledHandler',
  'TestNativeMobileLegacyManifestsAndPlatformBoundary'},
 'local/panel/internal/core':{
  'TestNativeMobileDeliveryFixedArtifacts',
  'TestNativeMobile133ReportsIndependentFixedArtifacts',
  'TestNativeMobileUpdateVersionCannotBorrowOtherClientBuilds',
  'TestNativeMobileDeliveryRetainsEachOriginalInstallationIdentity',
  'TestSignedInstallVersionAllDeclaredModulesKeepExactIdentity',
  'TestSignedInstallLegacyEmptyVersionOriginalIsResolvedWithoutMutation',
  'TestSignedInstallVersionRejectsBorrowedOrChangedOriginalBeforeDispatch',
  'TestSignedInstallWorkerUsesRetainedVersionOnlyInExecutionEnvelope',
  'TestNativeMobileCannotBorrowUnsignedNoopForeignOrRevokedQueueBinding'},
 'local/panel/internal/executor':{
  'TestMobileSelectedVersionSinkPreservesLegacyAndRefusesInstallOverwrite',
  'TestMobileReportReadsOriginalInstalledVersionWithoutRelabelling',
  'TestSignedMobileCoreUnixExactInstallAndExplicitStoreUpdate'}}
path=pathlib.Path(sys.argv[1]);assert path.is_file() and not path.is_symlink() and 0<path.stat().st_size<16<<20
rows=[json.loads(s) for s in path.read_text().splitlines()]
assert rows and all(r.get('Package') in expected and r.get('Action') not in ('fail','skip') for r in rows)
counts={}
for package,roots in expected.items():
    events=[r for r in rows if r.get('Package')==package]
    ran=[r['Test'] for r in events if r.get('Action')=='run' and r.get('Test')]
    passed=[r['Test'] for r in events if r.get('Action')=='pass' and r.get('Test')]
    assert len(ran)==len(set(ran))==len(passed)==len(set(passed)) and set(ran)==set(passed)
    assert {s for s in passed if '/' not in s}==roots,(package,passed)
    assert all(s.split('/')[0] in roots for s in passed)
    assert sum(r.get('Action')=='pass' and not r.get('Test') for r in events)==1
    counts[package]=len(passed)
exec_pass={r.get('Test') for r in rows if r.get('Action')=='pass' and r.get('Package')=='local/panel/internal/executor'}
for version in ('1.3.2','1.3.3'):
    assert 'TestSignedMobileCoreUnixExactInstallAndExplicitStoreUpdate/'+version in exec_pass
print(json.dumps({'ok':True,'architecture':platform.machine(),'source_inputs_sha256':index['release']['frozen_inputs_sha256'],'actual_root_methods':15,'actual_pass_records':counts,'zero_skips_and_failures':True,'real_signed_Core_SQLite_queue_Unix_executor_fixture':True,'normal_installed_or_store_acceptance':False}))
