"""QA readiness regressions; no installer, production DB or native claims."""
import ast,contextlib,datetime,pathlib,types,unittest
tree=ast.parse(pathlib.Path(__file__).with_name('guest.py').read_text())
nodes=[n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='initialized_baseline_capture'];assert len(nodes)==1
EXPECTED=[(n,0)for n in sorted(('file-monitor','website-tamper-proof','enterprise-tamper-proof','files-sync','php-code-security'))]
NOW=datetime.datetime(2026,10,29,tzinfo=datetime.timezone.utc).timestamp()
CLOCK='2026-10-29T00:00:00Z'
class InitializedBaseline(unittest.TestCase):
 def check(self,observations=None,error='',checked=CLOCK):
  observations=observations if observations is not None else[EXPECTED];saved={};queries=[];clock=[NOW];connections=[0];captures=[]
  class DB:
   def __init__(self):self.index=connections[0];connections[0]+=1;self.sql=''
   def execute(self,sql):
    assert sql.startswith(('SELECT ','PRAGMA query_only=','BEGIN'));queries.append(sql);self.sql=sql;return self
   def fetchall(self):
    if self.sql.startswith('SELECT module_id'):return observations[min(self.index,len(observations)-1)]
    assert self.sql.startswith('SELECT id,last_error');return[(1,error,checked)]
   def close(self):pass
  def capture(label):
   captures.append(label);return{'full_rows':{'app_notification_cursors':[[['text',n],['integer','0']]for n,_ in EXPECTED]},'all105_full_columns_retained':True}
  def save(name,value):assert name not in saved;saved[name]=value
  def sleep(seconds):clock[0]+=seconds
  env={'contextlib':contextlib,'sqlite3':types.SimpleNamespace(connect=lambda*a,**k:DB()),'time':types.SimpleNamespace(time=lambda:clock[0],sleep=sleep),'datetime':datetime,'save':save,'healthy_capture':capture}
  exec(compile(ast.Module(body=nodes,type_ignores=[]),'<exact-baseline-gate>','exec'),env)
  result=env['initialized_baseline_capture']('baseline')
  return result,saved,queries,connections[0],captures
 def test_real_initialization_is_observed_twice_before_capture_without_writes(self):
  result,saved,queries,count,captures=self.check(observations=[[],EXPECTED[:2],EXPECTED,EXPECTED])
  self.assertEqual(count,4);self.assertEqual(captures,['baseline']);self.assertTrue(result['all105_full_columns_retained'])
  proof=saved['baseline-initialized-cursors-gate.json'];self.assertEqual(len(proof['observations']),4);self.assertFalse(proof['database_rows_synthesized_or_ignored']);self.assertTrue(proof['upgrade_full_row_comparison_unchanged'])
  self.assertTrue(all(q.startswith(('SELECT ','PRAGMA query_only=','BEGIN'))for q in queries))
 def test_existing_initialized_baseline_still_needs_two_consecutive_observations(self):
  result,_,_,count,_=self.check();self.assertEqual(count,2);self.assertEqual(len(result['full_rows']['app_notification_cursors']),5)
 def test_partial_unknown_changed_or_duplicate_cursors_fail_closed(self):
  cases=[
   [EXPECTED[:4]],
   [[('foreign-module',0)]],
   [[('file-monitor',1)]],
   [[EXPECTED[0],EXPECTED[0]]],
  ]
  for observations in cases:
   with self.subTest(observations=observations):
    with self.assertRaises(AssertionError):self.check(observations=observations)
 def test_reported_error_empty_or_stale_dispatch_never_qualifies(self):
  for options in({'error':'failure'},{'checked':''},{'checked':'2026-10-28T23:55:00Z'}):
   with self.subTest(options=options):
    with self.assertRaises(AssertionError):self.check(**options)
 def test_original_source_gate_and_upgrade_comparison_are_unchanged(self):
  old=ast.parse((pathlib.Path(__file__).parent.parent/'native-disk-c26'/'guest-v2.py').read_text())
  for name in('healthy_capture','capture'):
   self.assertEqual(ast.dump(next(n for n in old.body if isinstance(n,ast.FunctionDef)and n.name==name)),ast.dump(next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name==name)))
  source=pathlib.Path(__file__).with_name('guest.py').read_text();self.assertIn("upgrade_preservation=model['compare_rows'](before_upgrade,before)",source)
if __name__=='__main__':unittest.main()


