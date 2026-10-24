"""Real Root DATA-ONLY copy/seal models; no tool executable is fabricated.
All ownership/permission changes belong to NEW copies in a private fixture.
"""
import ast,hashlib,json,os,pathlib,secrets,shutil,stat,sys,unittest
from unittest.mock import patch
assert sys.platform=='linux'and os.geteuid()==0
os.umask(0o022)
source=pathlib.Path(__file__).resolve().parents[1]/'tools/run-module-version-isolated-ci.py'
raw=source.read_bytes();tree=ast.parse(raw)
nodes=[n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name in('check_private_case','tool_content_tree','seal_ci_tool_tree')];assert len(nodes)==3
exec(compile(ast.Module(body=nodes,type_ignores=[]),str(source),'exec'),globals())
anchor=pathlib.Path('/var/lib/panel-executor')
if not os.path.lexists(anchor):anchor.mkdir(mode=0o755)
for parent in(anchor,*anchor.parents):
 s=parent.lstat();assert stat.S_ISDIR(s.st_mode)and s.st_uid==0 and not s.st_mode&0o022
fixture=anchor/('qa-tool-data-seals24bkpf.'+secrets.token_hex(16));fixture.mkdir(mode=0o700)

class SealModels(unittest.TestCase):
 def setUp(self):
  self.base=fixture/self._testMethodName;self.base.mkdir(mode=0o700)
  self.input=self.base/'original-DATA';self.input.mkdir(mode=0o755)
  with(self.input/'data.txt').open('xb')as out:out.write(b'data fixture only,never a compiler or runtime executable')
  self.output=self.base/'new-sealed-DATA'

 def test_writable_source_data_sealed_without_source_metadata_changes(self):
  self.input.chmod(0o777);(self.input/'data.txt').chmod(0o666);before=tool_content_tree(self.input)
  seal=seal_ci_tool_tree(self.input,self.output)
  self.assertTrue(seal['source_metadata_unchanged']);self.assertEqual(tool_content_tree(self.input),before)
  self.assertEqual((self.output/'data.txt').stat().st_uid,0);self.assertEqual(stat.S_IMODE((self.output/'data.txt').stat().st_mode),0o644)
  self.assertEqual(stat.S_IMODE(self.output.stat().st_mode),0o755)

 def test_internal_relative_data_link_preserved(self):
  (self.input/'data-link').symlink_to('data.txt');before=tool_content_tree(self.input)
  seal_ci_tool_tree(self.input,self.output)
  self.assertEqual(os.readlink(self.output/'data-link'),'data.txt');self.assertEqual(tool_content_tree(self.input),before)

 def test_external_data_link_refused_without_following(self):
  outside=self.base/'outside-DATA'
  with outside.open('xb')as out:out.write(b'not part of the source prefix')
  (self.input/'external-link').symlink_to('../outside-DATA')
  before=outside.read_bytes()
  with self.assertRaises(AssertionError):seal_ci_tool_tree(self.input,self.output)
  self.assertEqual(outside.read_bytes(),before);self.assertFalse(os.path.lexists(self.output))

 def test_special_input_refused_without_reading(self):
  os.mkfifo(self.input/'owned-FIFO',0o600)
  with self.assertRaises(AssertionError):seal_ci_tool_tree(self.input,self.output)
  self.assertFalse(os.path.lexists(self.output))

 def test_existing_destination_refused_without_adoption(self):
  self.output.mkdir(mode=0o755)
  with(self.output/'existing-DATA').open('xb')as out:out.write(b'existing copied data must not be replaced')
  before=tool_content_tree(self.output)
  with self.assertRaises(AssertionError):seal_ci_tool_tree(self.input,self.output)
  self.assertEqual(tool_content_tree(self.output),before)

 def test_copied_data_tampering_refused(self):
  real=shutil.copytree
  def tamper(src,dst,*args,**kwargs):
   result=real(src,dst,*args,**kwargs)
   if pathlib.Path(src)==self.input:(pathlib.Path(dst)/'data.txt').write_bytes(b'owned copied-data fault injection')
   return result
  before=tool_content_tree(self.input)
  with patch.object(shutil,'copytree',side_effect=tamper):
   with self.assertRaises(AssertionError):seal_ci_tool_tree(self.input,self.output)
  self.assertEqual(tool_content_tree(self.input),before)

 def test_source_mutation_during_copy_refused(self):
  real=shutil.copytree
  def mutate(src,dst,*args,**kwargs):
   result=real(src,dst,*args,**kwargs)
   if pathlib.Path(src)==self.input:(self.input/'data.txt').write_bytes(b'owned source-data fault injection')
   return result
  with patch.object(shutil,'copytree',side_effect=mutate):
   with self.assertRaises(AssertionError):seal_ci_tool_tree(self.input,self.output)

 def test_untrusted_destination_parent_refused_without_repair(self):
  self.base.chmod(0o777);before=self.base.lstat()
  with self.assertRaises(AssertionError):seal_ci_tool_tree(self.input,self.output)
  after=self.base.lstat();self.assertEqual((after.st_ino,after.st_mode,after.st_uid,after.st_ctime_ns),(before.st_ino,before.st_mode,before.st_uid,before.st_ctime_ns))
  self.assertFalse(os.path.lexists(self.output))

result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(SealModels))
proof={'ok':result.wasSuccessful(),'actual_uid':os.geteuid(),'tests_run':result.testsRun,'failures':len(result.failures),'errors':len(result.errors),'skips':len(result.skipped),'source_sha256':hashlib.sha256(raw).hexdigest(),'fixture':str(fixture),'no_tool_or_Apache_executable_fabricated':True,'source_and_copy_data_models_only_NOT_compiler_or_application_acceptance':True,'all_fixture_artifacts_retained':True,'all50_commercial':False}
with(fixture/'proof.json').open('x')as out:json.dump(proof,out,sort_keys=True)
print(json.dumps(proof));sys.exit(0 if proof['ok']else 1)
