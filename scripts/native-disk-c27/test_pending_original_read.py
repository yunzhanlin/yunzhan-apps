"""QA HTTP observation regression; zero native/store commands and no acceptance claim."""
import ast,io,json,pathlib,re,secrets,types,unittest,urllib.error,urllib.request
P=pathlib.Path(__file__).with_name('native-active-cancel-v3.py')
NODE=next(n for n in ast.parse(P.read_text()).body if isinstance(n,ast.FunctionDef)and n.name=='api')
PENDING='原全盘执行状态暂不能核对；未重发任务，也未认定结束'
PATH='/software/disk-analysis/host/jobs/'+'a'*32
class PendingOriginalRead(unittest.TestCase):
 def invoke(self,path=PATH,status=409,value=None,body=None,allowed=True):
  value={'error':PENDING}if value is None else value;raw=json.dumps(value,ensure_ascii=False).encode()if not isinstance(value,bytes)else value;requests=[];saved={}
  class Opener:
   def open(self,req,timeout):
    requests.append(req);raise urllib.error.HTTPError(req.full_url,status,'owned fixture',{},io.BytesIO(raw))
  def save(name,value):self.assertNotIn(name,saved);saved[name]=value
  env={'json':json,'urllib':urllib,'re':re,'secrets':types.SimpleNamespace(token_hex=lambda n:'owned'),'save':save,'opener':Opener(),'csrf':'owned-fixture'}
  exec(compile(ast.Module(body=[NODE],type_ignores=[]),'<exact-current-API-observer>','exec'),env)
  return env['api'](path,body=body,allow_pending_read=allowed),requests,saved
 def test_exact_original_get_returns_pending_without_claiming_success_or_replaying(self):
  result,requests,saved=self.invoke();self.assertEqual(result,(409,{'error':PENDING}));self.assertEqual(len(requests),1);self.assertEqual(requests[0].get_method(),'GET');self.assertIsNone(requests[0].data);self.assertEqual(next(iter(saved.values()))['status'],409)
 def test_normal_reads_and_all_writes_remain_strict(self):
  for options in({'allowed':False},{'body':{}},{'path':PATH+'/cancel'},{'path':'/software/disk-analysis/host/jobs'}):
   with self.subTest(options=options):
    with self.assertRaises(AssertionError):self.invoke(**options)
 def test_foreign_failures_and_noncanonical_error_bodies_never_become_pending(self):
  for options in({'status':403},{'status':429},{'status':500},{'value':{'error':'tampered authority'}},{'value':{'error':PENDING,'extra':True}},{'value':b'not-json'}):
   with self.subTest(options=options):
    with self.assertRaises(AssertionError):self.invoke(**options)
 def test_active_phase_and_canceled_terminal_require_real_native_witnesses(self):
  source=P.read_text();self.assertIn("observed['original_process']=='alive'and observed['original_scope']=='busy'",source);self.assertIn("valid_cancel_ack(status,cancel,job)",source);self.assertIn("detail['terminal_verified']is True and detail['job']['state']=='canceled'",source)
if __name__=='__main__':unittest.main()

