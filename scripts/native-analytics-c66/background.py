"""Strict read-only snapshot delta checks for source-bound autonomous observations."""
import datetime,json,math
BACKGROUND={'database_connection_samples','monitor_conditions','monitor_samples','monitor_services','notification_dispatch_status'}
def qualify_background(a,b,explicit=frozenset()):
 assert a['schema']==b['schema']and a['boot']==b['boot']and a['at']<b['at']
 assert len(a['tables'])==len(b['tables'])==113 and a['tables'].keys()==b['tables'].keys()
 def rows(t):return[dict(zip(t['columns'],x))for x in t['rows']]
 def serial(x):return json.dumps(x,sort_keys=True,separators=(',',':'))
 def between(t):
  if isinstance(t,str):t=datetime.datetime.fromisoformat(t.replace('Z','+00:00')).timestamp()
  assert a['at']-2<=t<=b['at']+2,t
 delta={}
 for n,x in a['tables'].items():
  y=b['tables'][n];assert x['columns']==y['columns']
  if x==y:continue
  old=rows(x);new=rows(y);od={serial(x):x for x in old};nd={serial(x):x for x in new};removed=[od[k]for k in od.keys()-nd.keys()];added=[nd[k]for k in nd.keys()-od.keys()];delta[n]={'removed':len(removed),'added':len(added)}
  if n in explicit:continue
  assert n in BACKGROUND,'Unexpected changed table: '+n
  if n=='monitor_samples':
   assert not removed and len(added)<=math.ceil((b['at']-a['at'])/15)+2
   prior=max((x['id']for x in old),default=0);assert len({x['id']for x in added})==len(added)
   for x in added:
    assert x['id']>prior and x['state']=='ok'and x['error']==''and x['boot_id']==a['boot'];between(x['sampled_at'])
    assert all(0<=x[k]<=100 for k in('cpu_percent','memory_percent','disk_percent'))
    for value in x.values():
     if isinstance(value,(int,float)):assert math.isfinite(value)
  elif n=='database_connection_samples':
   indexed={x['sampled_at']:x for x in new};assert len(indexed)==len(new);cutoff=max(indexed)-86400
   for x in removed:assert x['sampled_at']<cutoff or x['sampled_at']in indexed and x['sampled_at']>=int(a['at'])//60*60
   for x in added:assert int(a['at'])//60*60<=x['sampled_at']<=int(b['at'])//60*60 and x['sampled_at']%60==0 and all(x[k]is None or isinstance(x[k],int)and 0<=x[k]<=1000000 for k in('mysql_clients','redis_clients'))
  elif n=='monitor_conditions':
   old={x['metric']:x for x in old};new={x['metric']:x for x in new};assert old.keys()==new.keys()
   for k,x in new.items():
    if x==old[k]:continue
    assert k in('cpu','memory','disk')and 0<=x['last_value']<=100
    for clock in('active_since','clear_since'):
     if x[clock]!=old[k][clock]and x[clock]!=0:between(x[clock])
    assert x.keys()==old[k].keys()=={'metric','active_since','clear_since','last_value'}
  elif n=='monitor_services':
   old={(x['kind'],x['resource_id']):x for x in old};new={(x['kind'],x['resource_id']):x for x in new};assert old.keys()==new.keys()
   for k,x in new.items():
    if x==old[k]:continue
    between(x['checked_at']);z=dict(x);z['checked_at']=old[k]['checked_at'];assert z==old[k]
  elif n=='notification_dispatch_status':
   assert len(old)==len(new)==1;between(new[0]['last_check_at']);z=dict(new[0]);z['last_check_at']=old[0]['last_check_at'];assert z==old[0]
 return delta
