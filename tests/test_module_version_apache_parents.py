"""Real Linux UID0 parent-policy models, not an Apache build/install receipt.

Extract the two exact prerequisite functions without executing its installer.
Every mutated permission/ownership/link belongs to a NEW private test fixture.
No existing runtime, parent, panel, application, or historical receipt changes.
"""
import ast,hashlib,json,os,pathlib,secrets,stat,sys,unittest
from unittest.mock import patch

assert sys.platform=='linux' and os.geteuid()==0
os.umask(0o022)
source=pathlib.Path(__file__).resolve().parents[1]/'tools/prepare-module-version-apache-ci.py'
raw=source.read_bytes();tree=ast.parse(raw)
nodes=[n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name in('prepare_runtime_parents','verify_runtime_parents')]
assert len(nodes)==2
exec(compile(ast.Module(body=nodes,type_ignores=[]),str(source), 'exec'),globals())
anchor=pathlib.Path('/var/lib/panel-executor')
if not os.path.lexists(anchor):anchor.mkdir(mode=0o755)
for parent in(anchor,*anchor.parents):
 s=parent.lstat();assert stat.S_ISDIR(s.st_mode)and s.st_uid==0 and not s.st_mode&0o022
fixture=anchor/('qa-apache-ci-parents24bkot.'+secrets.token_hex(16));fixture.mkdir(mode=0o700)

def identity(path):
 s=path.lstat()
 return {k:str(getattr(s,k))for k in('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')}

class ParentPolicy(unittest.TestCase):
 def setUp(self):
  self.root=fixture/self._testMethodName;self.root.mkdir(mode=0o700)

 def test_missing_intermediates_explicit0755_even_under_umask000(self):
  before=identity(self.root);mask=os.umask(0)
  try:records=prepare_runtime_parents(self.root/'new'/'apache'/'2.4.68')
  finally:os.umask(mask)
  created=[r for r in records if r['created_by_this_task']]
  self.assertEqual([r['path']for r in created],[str(self.root/'new'),str(self.root/'new/apache')])
  for r in created:self.assertEqual(stat.S_IMODE(pathlib.Path(r['path']).lstat().st_mode),0o755)
  self.assertEqual(identity(self.root)['st_mode'],before['st_mode'])
  verify_runtime_parents(records)

 def test_existing_private_parent_is_not_chmodded(self):
  parent=self.root/'apache';parent.mkdir(mode=0o750);before=identity(parent)
  records=prepare_runtime_parents(parent/'2.4.68')
  self.assertFalse(records[-1]['created_by_this_task']);self.assertEqual(identity(parent),before)

 def test_existing_world_writable_parent_refused_without_repair(self):
  parent=self.root/'apache';parent.mkdir(mode=0o700);parent.chmod(0o777);before=identity(parent)
  with self.assertRaises(AssertionError):prepare_runtime_parents(parent/'2.4.68')
  self.assertEqual(identity(parent),before);self.assertFalse(os.path.lexists(parent/'2.4.68'))

 def test_existing_group_writable_parent_refused_without_repair(self):
  parent=self.root/'apache';parent.mkdir(mode=0o700);parent.chmod(0o775);before=identity(parent)
  with self.assertRaises(AssertionError):prepare_runtime_parents(parent/'2.4.68')
  self.assertEqual(identity(parent),before)

 def test_symlink_parent_refused_without_following_or_repair(self):
  target=self.root/'target';target.mkdir(mode=0o700);parent=self.root/'apache';parent.symlink_to(target,target_is_directory=True)
  before=identity(parent);target_before=identity(target)
  with self.assertRaises(AssertionError):prepare_runtime_parents(parent/'2.4.68')
  self.assertEqual(identity(parent),before);self.assertEqual(identity(target),target_before)

 def test_regular_parent_refused_without_replacement(self):
  parent=self.root/'apache'
  with parent.open('xb')as out:out.write(b'owned fixture,not a runtime')
  before=identity(parent)
  with self.assertRaises(AssertionError):prepare_runtime_parents(parent/'2.4.68')
  self.assertEqual(identity(parent),before)

 def test_foreign_owner_refused_without_adoption(self):
  parent=self.root/'apache';parent.mkdir(mode=0o700);os.chown(parent,65534,65534);before=identity(parent)
  with self.assertRaises(AssertionError):prepare_runtime_parents(parent/'2.4.68')
  self.assertEqual(identity(parent),before)

 def test_concurrent_creator_is_not_adopted(self):
  real=os.mkdir;target=self.root/'apache'
  def concurrent(path,mode):
   real(path,mode)
   raise FileExistsError('owned fault-injection fixture concurrent creator')
  with patch.object(os,'mkdir',side_effect=concurrent):
   with self.assertRaises(FileExistsError):prepare_runtime_parents(target/'2.4.68')
  self.assertEqual(stat.S_IMODE(target.lstat().st_mode),0o755)

 def test_post_build_permission_drift_refused(self):
  parent=self.root/'apache';records=prepare_runtime_parents(parent/'2.4.68');parent.chmod(0o777);before=identity(parent)
  with self.assertRaises(AssertionError):verify_runtime_parents(records)
  self.assertEqual(identity(parent),before)

 def test_post_build_inode_replacement_refused_without_deletion(self):
  parent=self.root/'apache';records=prepare_runtime_parents(parent/'2.4.68');saved=self.root/'retained-original';parent.rename(saved);parent.mkdir(mode=0o755)
  before=identity(parent);saved_before=identity(saved)
  with self.assertRaises(AssertionError):verify_runtime_parents(records)
  self.assertEqual(identity(parent),before);self.assertEqual(identity(saved),saved_before)

 def test_post_build_symlink_replacement_refused(self):
  parent=self.root/'apache';records=prepare_runtime_parents(parent/'2.4.68');saved=self.root/'retained-original';parent.rename(saved);parent.symlink_to(saved,target_is_directory=True)
  before=identity(parent);saved_before=identity(saved)
  with self.assertRaises(AssertionError):verify_runtime_parents(records)
  self.assertEqual(identity(parent),before);self.assertEqual(identity(saved),saved_before)

suite=unittest.defaultTestLoader.loadTestsFromTestCase(ParentPolicy)
result=unittest.TextTestRunner(verbosity=2).run(suite)
proof={'ok':result.wasSuccessful(),'actual_uid':os.geteuid(),'tests_run':result.testsRun,'failures':len(result.failures),'errors':len(result.errors),'skips':len(result.skipped),'source_sha256':hashlib.sha256(raw).hexdigest(),'fixture_root':str(fixture),'scope':'real UID0 parent-policy models ONLY,not an Apache build/install receipt','all_fixture_artifacts_retained':True,'all50_commercial':False}
with(fixture/'proof.json').open('x')as out:json.dump(proof,out,sort_keys=True);out.write('\n')
print(json.dumps(proof));sys.exit(0 if result.wasSuccessful() else 1)
