"""QA acknowledgment contract regressions; no native operation or acceptance claim."""
import ast,pathlib,unittest
P=pathlib.Path(__file__).with_name('native-active-cancel-v3.py')
NODE=next(n for n in ast.parse(P.read_text()).body if isinstance(n,ast.FunctionDef)and n.name=='valid_cancel_ack')
ENV={};exec(compile(ast.Module(body=[NODE],type_ignores=[]),'<exact-acknowledgment-gate>','exec'),ENV)
JOB='a'*32
class OriginalCancelAck(unittest.TestCase):
 def value(self,signaled=True,terminal=False,state='cancel_requested',uncertain=False):
  return{'job':{'id':JOB,'state':state,'cancel_state':'requested'},'cancel_uncertain':uncertain,'native_cancel_requested':signaled,'terminal_verified':terminal}
 def test_existing_signaled_or_already_canceled_protocol_paths_are_accepted(self):
  for v in(self.value(),self.value(signaled=True,terminal=True,state='canceled'),self.value(signaled=False,terminal=True,state='canceled')):
   with self.subTest(value=v):self.assertTrue(ENV['valid_cancel_ack'](202,v,JOB))
 def test_no_signal_without_verified_canceled_terminal_never_passes(self):
  for v in(self.value(signaled=False),self.value(signaled=False,terminal=True,state='complete'),self.value(signaled=False,terminal=True,state='failed')):
   with self.subTest(value=v):self.assertFalse(ENV['valid_cancel_ack'](202,v,JOB))
 def test_uncertain_foreign_malformed_or_uncanceled_acknowledgments_are_refused(self):
  cases=[(200,self.value()),(202,self.value(uncertain=True)),(202,self.value(signaled=False,terminal=True,state='canceled',uncertain=True))]
  for field,value in(('id','b'*32),('cancel_state','')):
   v=self.value();v['job'][field]=value;cases.append((202,v))
  for field in('cancel_uncertain','native_cancel_requested','terminal_verified'):
   v=self.value();v[field]=1;cases.append((202,v))
  v=self.value();v['extra']='foreign';cases.append((202,v))
  for status,value in cases:
   with self.subTest(status=status,value=value):self.assertFalse(ENV['valid_cancel_ack'](status,value,JOB))
 def test_later_native_identity_and_canceled_result_are_still_required(self):
  source=P.read_text();self.assertIn("result['started']==observed['started']",source);self.assertIn("detail['terminal_verified']is True and detail['job']['state']=='canceled'",source);self.assertIn("observed['original_process']=='alive'and observed['original_scope']=='busy'",source)
if __name__=='__main__':unittest.main()

