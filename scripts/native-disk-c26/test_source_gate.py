"""QA controller regression only; no native programme/app acceptance."""
import ast,contextlib,datetime,pathlib,types,unittest
tree=ast.parse(pathlib.Path(__file__).with_name('guest-v2.py').read_text());nodes=[n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='healthy_capture'];assert len(nodes)==1
class SourceGate(unittest.TestCase):
 def check(self,rows=(),present=False,count=0,native=False):
  saved={};queries=[];clock=[1793227200.0]
  class DB:
   def execute(self,sql):
    assert sql.startswith(('SELECT ','PRAGMA query_only='));queries.append(sql);return self
   def fetchall(self):return rows
   def fetchone(self):return (count,)
   def close(self):pass
  def save(name,value):
   assert name not in saved;saved[name]=value
  def sleep(seconds):clock[0]+=seconds
  env={'contextlib':contextlib,'sqlite3':types.SimpleNamespace(connect=lambda*a,**k:DB()),'time':types.SimpleNamespace(time=lambda:clock[0],sleep=sleep),'datetime':datetime,'os':types.SimpleNamespace(path=types.SimpleNamespace(lexists=lambda p:present)),'pathlib':types.SimpleNamespace(Path=lambda p:types.SimpleNamespace(iterdir=lambda:[types.SimpleNamespace(name='load-balance-stream-old')]if native else[])),'save':save,'capture':lambda:{'full_census_required':True}}
  exec(compile(ast.Module(body=nodes,type_ignores=[]),'<exact-source-gate>','exec'),env)
  result=env['healthy_capture']('owned');return result,saved,queries
 def test_verified_absence_preserves_complete_capture_without_creating_source(self):
  result,saved,queries=self.check();self.assertEqual(result,{'full_census_required':True});self.assertEqual(len([q for q in queries if q.startswith('SELECT count')]),7);self.assertTrue(saved['owned-source-gate.json']['known_uninstalled_module_and_original_native_authority_absent']);self.assertFalse(saved['owned-source-gate.json']['source_synthesized_or_repaired'])
 def test_absence_cannot_hide_installed_files_or_original_authority(self):
  for options in({'present':True},{'count':1},{'native':True}):
   with self.subTest(options=options):
    with self.assertRaises(AssertionError):self.check(**options)
 def test_present_healthy_source_still_requires_real_identity_and_clock(self):
  result,saved,_=self.check(rows=[(1,'clear','2026-10-28T22:40:00Z')]);self.assertTrue(result['full_census_required']);self.assertTrue(saved['owned-source-gate.json']['original_healthy_source_clock'])
  with self.assertRaises(AssertionError):self.check(rows=[(2,'clear','2026-10-28T22:40:00Z')])
 def test_present_unknown_error_or_stale_source_is_never_treated_as_absence(self):
  for rows in ([(1,'error','2026-10-28T22:40:00Z')],[(1,'unknown','2026-10-28T22:40:00Z')],[(1,'clear','2026-10-28T22:00:00Z')]):
   with self.subTest(rows=rows):
    with self.assertRaises(AssertionError):self.check(rows=rows)
if __name__=='__main__':unittest.main()
