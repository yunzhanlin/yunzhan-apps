"""Local acceptance-test client. Credentials are read privately, never logged."""
import http.cookiejar, json, pathlib, urllib.request, urllib.error, uuid, time, subprocess, os
ROOT=pathlib.Path(os.environ.get('PANEL_PROJECT_ROOT',pathlib.Path(__file__).resolve().parents[1]))
DEV=pathlib.Path(os.environ.get('PANEL_DEV_HOME','/Volumes/MacSSD/MacData/PanelDev'))
class PanelClient:
 def __init__(self):
  self.base=os.environ.get('PANEL_BASE','http://127.0.0.1:19100');self.origin=os.environ.get('PANEL_ORIGIN',self.base);self.csrf=''
  self.timeout=float(os.environ.get('PANEL_HTTP_TIMEOUT','30'))
  self.http=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
  access=pathlib.Path(os.environ.get('PANEL_ACCESS_FILE',DEV/'private/access.json'))
  a=json.loads(access.read_text());self.csrf=self.api('/login',{'username':a['username'],'password':a['password']})['csrf']
 def api(self,path,body=None,method=None,idempotency_key=None):
  req=urllib.request.Request(self.base+'/api'+path,data=None if body is None else json.dumps(body).encode(),method=method,headers={'Content-Type':'application/json','Origin':self.origin,'X-CSRF-Token':self.csrf,'Idempotency-Key':idempotency_key or str(uuid.uuid4())})
  for attempt in range(5):
   try:
    with self.http.open(req,timeout=self.timeout) as r:return json.load(r)
   except urllib.error.HTTPError as e:
    message=e.read().decode()
    if body is None and attempt<4 and (e.code in (502,503,504) or '执行服务连接失败' in message):time.sleep(.5);continue
    raise RuntimeError(f'{path}: HTTP {e.code}: {message}') from None
   except (urllib.error.URLError,ConnectionError) as e:
    if body is None and attempt<4:time.sleep(.5);continue
    raise
 def wait(self,job,expected='succeeded',timeout=3600):
  last='';deadline=time.monotonic()+timeout
  while time.monotonic()<deadline:
   j=self.api('/jobs/'+job);status=j['state']+' '+(j['steps'][-1]['message'] if j['steps'] else '')
   if status!=last:print(job[:8],status,flush=True);last=status
   if j['state'] in ('succeeded','failed','needs_attention'):
    assert j['state']==expected,j
    return j
   time.sleep(2)
  raise RuntimeError('job timeout')
 def page(self,site,path='/'):
  req=urllib.request.Request('http://127.0.0.1:19101'+path,headers={'Host':site['domain']})
  try:
   with self.http.open(req,timeout=10) as r:return r.status,r.read().decode()
  except urllib.error.HTTPError as e:return e.code,e.read().decode()
 def vm(self,*args,input=None,check=True):
  if os.environ.get('PANEL_VM_LOCAL')=='1':
   return subprocess.run(list(args),input=input,text=True,capture_output=True,check=check)
  env=os.environ.copy();env['LIMA_HOME']=str(DEV/'lima')
  instance=os.environ.get('PANEL_VM','panel-dev')
  return subprocess.run([str(DEV/'tools/lima/bin/limactl'),'shell','--workdir=/workspace',instance,*args],input=input,text=True,capture_output=True,check=check,env=env)
 def close(self):self.api('/logout',{})
