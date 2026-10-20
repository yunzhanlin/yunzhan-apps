"""phpMyAdmin SQL proof against a short-lived database on its private network."""
import json,uuid,time
def verify_sql(client,project):
 name='pma-sql-'+uuid.uuid4().hex[:12];password=uuid.uuid4().hex+uuid.uuid4().hex;created=False
 create='''import json,sys,subprocess,os
v=json.load(sys.stdin);env=dict(os.environ,MARIADB_ROOT_PASSWORD=v['password'],MARIADB_ROOT_HOST='%')
r=subprocess.run(['docker','run','-d','--name',v['name'],'--network',v['network'],'--network-alias','cloudstack-qa-db','--memory','512m','--env','MARIADB_ROOT_PASSWORD','--env','MARIADB_ROOT_HOST','mariadb:11.8.9@sha256:6422478cb8e159f080fb1d8ccf65101e26fe51385787fde7d16c3b165a331f15'],env=env,check=True,capture_output=True,text=True);print(r.stdout.strip())'''
 try:
  client.vm('sudo','python3','-c',create,input=json.dumps({'name':name,'password':password,'network':project['engine_name']+'_default'}));created=True
  for _ in range(90):
   probe=client.vm('sudo','docker','exec',name,'sh','-lc','mariadb --batch --skip-column-names -h127.0.0.1 -uroot --password="$MARIADB_ROOT_PASSWORD" -e "SELECT 1"',check=False)
   if probe.returncode==0:break
   time.sleep(1)
  assert probe.returncode==0,'QA database not ready'
  code=r'''import json,sys,urllib.request,urllib.parse,http.cookiejar
from html.parser import HTMLParser
v=json.load(sys.stdin);base='http://127.0.0.1:18080/';jar=http.cookiejar.CookieJar();client=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
class Forms(HTMLParser):
 def __init__(self):super().__init__();self.forms=[];self.current=None
 def handle_starttag(self,tag,attrs):
  a=dict(attrs)
  if tag=='form':self.current={'action':a.get('action',''),'id':a.get('id',''),'fields':{}};self.forms.append(self.current)
  elif tag in ['input','textarea'] and self.current is not None and 'name' in a:
   if a.get('type') in ['checkbox','radio'] and 'checked' not in a:return
   self.current['fields'][a['name']]=a.get('value','')
 def handle_endtag(self,tag):
  if tag=='form':self.current=None
def page(url,data=None):
 with client.open(url,urllib.parse.urlencode(data).encode() if data is not None else None,timeout=30) as r:return r.read().decode()
def forms(text):p=Forms();p.feed(text);return p.forms
login=next(f for f in forms(page(base)) if 'pma_username' in f['fields']);data=login['fields'];data.update(pma_username='root',pma_password=v['password'],pma_servername='cloudstack-qa-db');page(urllib.parse.urljoin(base,login['action']),data)
sql_page=page(base+'index.php?route=/server/sql');candidates=[f for f in forms(sql_page) if 'sql_query' in f['fields']]
if not candidates:raise AssertionError('SQL form absent; login still visible='+str('pma_username' in sql_page)+'; form field names='+str([list(f['fields']) for f in forms(sql_page)]))
sql=next((f for f in candidates if f['id']=='sqlqueryform'),candidates[0]);data=sql['fields'];data.update(is_js_confirmed='1',ajax_request='1');data['sql_query']="CREATE DATABASE cloudstack_qa; CREATE TABLE cloudstack_qa.proof(marker varchar(64)); INSERT INTO cloudstack_qa.proof VALUES ('pma-sql-verified'); SELECT marker FROM cloudstack_qa.proof;";response=page(urllib.parse.urljoin(base,sql['action']),data)
try:
 response=json.loads(response)
 assert response.get('success') is not False,str(response.get('error','SQL request rejected'))[:1500]
except json.JSONDecodeError:pass
print('phpMyAdmin authenticated SQL submitted')'''
  execution=client.vm('python3','-c',code,input=json.dumps({'password':password}),check=False)
  assert execution.returncode==0,execution.stderr[-2000:]
  check=client.vm('sudo','docker','exec',name,'sh','-lc','mariadb --batch --skip-column-names -uroot --password="$MARIADB_ROOT_PASSWORD" -e "SELECT marker FROM cloudstack_qa.proof"',check=False)
  assert check.returncode==0,check.stderr[-1000:]
  assert check.stdout.strip()=='pma-sql-verified','phpMyAdmin query did not persist in database'
  return 'Actual phpMyAdmin cookie login, authenticated SQL create/insert/select and independent database verification passed'
 finally:
  if created:client.vm('sudo','docker','rm','-f',name)
