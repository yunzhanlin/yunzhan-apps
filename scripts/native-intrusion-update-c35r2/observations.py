"""Read-only qualification of actual unchanged-source background observations.
Old rows are preserved. New samples are independently recomputed, never ignored.
This case admits no trigger, recovery, notification, site or application writes.
"""
import collections,copy,json,math

def decode(v):
    assert type(v)is list and len(v)in(1,2)
    if v==['null']:return None
    assert len(v)==2 and type(v[1])is str
    if v[0]=='integer':
        n=int(v[1]);assert str(n)==v[1];return n
    if v[0]=='real':
        n=float.fromhex(v[1]);assert math.isfinite(n)and n.hex()==v[1];return n
    if v[0]=='text':return v[1]
    assert v[0]=='blob'
    import base64
    n=base64.b64decode(v[1],validate=True);assert base64.b64encode(n).decode()==v[1];return n

def values(s,name):
    cols=[v[1]for v in s['columns'][name]]
    return [dict(zip(cols,map(decode,r)))for r in s['rows'][name]]

def snapshot_valid(s):
    assert s['format']==1 and s['all_tables_included']and s['columns'].keys()==s['rows'].keys()
    count=total=0
    for n,rows in s['rows'].items():
        encoded=[]
        for row in rows:
            assert len(row)==len(s['columns'][n]);[decode(v)for v in row]
            b=json.dumps(row,ensure_ascii=False,separators=(',',':'));encoded.append(b);total+=len(b.encode());count+=1
        assert encoded==sorted(encoded)
    assert count==s['row_count']and total==s['typed_row_bytes']and count<=1000000 and total<=32<<20

def close(a,b):assert type(a)in(int,float)and type(b)in(int,float)and math.isfinite(a)and math.isfinite(b)and math.isclose(a,b,rel_tol=1e-12,abs_tol=1e-10)

def appended(a,z,name):
    old=collections.Counter(map(lambda r:json.dumps(r,sort_keys=True),a['rows'][name]));new=collections.Counter(map(lambda r:json.dumps(r,sort_keys=True),z['rows'][name]));assert not(old-new),name+' original historical row changed or deleted'
    extra=new-old;assert all(v==1 for v in extra.values())
    cols=[v[1]for v in z['columns'][name]]
    return [dict(zip(cols,map(decode,json.loads(r))))for r in extra]

def observation_deltas(a,z,boot,stamp):
    snapshot_valid(a);snapshot_valid(z);assert 0<=z['at']-a['at']<=600
    samples=sorted(appended(a,z,'monitor_samples'),key=lambda r:r['sampled_at']);assert 0<=len(samples)<=math.ceil((z['at']-a['at'])/5)+2
    previous=max(values(a,'monitor_samples'),key=lambda r:r['sampled_at']);old_last_id=max(r['id']for r in values(a,'monitor_samples'))
    for i,r in enumerate(samples):
        assert r['id']==old_last_id+i+1 and a['started_at']-1<=r['sampled_at']<=z['at']+1 and type(r['sampled_at'])is int and r['sampled_at']>previous['sampled_at']
        assert r['boot_id']==previous['boot_id']==boot and r['state']==previous['state']=='ok'and r['error']==''
        for n in('cpu_total','cpu_idle','memory_used','memory_total','disk_used','disk_total','network_rx','network_tx','disk_read','disk_write'):
            assert type(r[n])is int and 0<=r[n]<(1<<63)
        assert r['memory_total']==previous['memory_total']and 0<r['memory_used']<=r['memory_total']and r['disk_total']==previous['disk_total']and 0<=r['disk_used']<=r['disk_total']
        close(r['memory_percent'],r['memory_used']*100/r['memory_total']);close(r['disk_percent'],r['disk_used']*100/r['disk_total'])
        elapsed=r['sampled_at']-previous['sampled_at'];dt=r['cpu_total']-previous['cpu_total'];di=r['cpu_idle']-previous['cpu_idle'];assert 0<=di<=dt and dt>0
        close(r['cpu_percent'],(dt-di)*100/dt)
        for field,rate in(('network_rx','network_rx_rate'),('network_tx','network_tx_rate'),('disk_read','disk_read_rate'),('disk_write','disk_write_rate')):
            assert r[field]>=previous[field];close(r[rate],(r[field]-previous[field])/elapsed)
        assert type(r['uptime_seconds'])is float and previous['uptime_seconds']<=r['uptime_seconds']<=previous['uptime_seconds']+elapsed+2
        assert type(r['load_1'])in(int,float)and math.isfinite(r['load_1'])and r['load_1']>=0
        previous=r
    db=appended(a,z,'database_connection_samples');assert len(db)<=math.ceil((z['at']-a['at'])/60)+1
    for r in db:
        assert type(r['sampled_at'])is int and r['sampled_at']%60==0 and int(a['started_at'])//60*60<=r['sampled_at']<=int(z['at'])//60*60
        # This isolated guest has no DB clients; retain exact zero observations.
        assert r['mysql_clients']==r['redis_clients']==0
    before={r['metric']:r for r in values(a,'monitor_conditions')};after={r['metric']:r for r in values(z,'monitor_conditions')};assert before.keys()==after.keys()
    for metric,r in before.items():
        n=after[metric];assert r['active_since']==r['clear_since']==n['active_since']==n['clear_since']==0
        if metric in('cpu','memory','disk'):close(n['last_value'],previous[metric+'_percent'])
        else:assert r==n
    before=values(a,'monitor_services');after=values(z,'monitor_services');assert len(before)==len(after)==1
    for r,n in zip(before,after):
        assert {k:v for k,v in r.items()if k!='checked_at'}=={k:v for k,v in n.items()if k!='checked_at'}
        assert r['actual_state']==n['actual_state']=='active'and r['expected_state']==n['expected_state']=='active'and r['kind']==n['kind']=='nginx'
        assert r['checked_at']<=n['checked_at']<=z['at']+1 and (n['checked_at']==r['checked_at'] or n['checked_at']>=a['started_at']-1)
    before=values(a,'notification_dispatch_status');after=values(z,'notification_dispatch_status');assert len(before)==len(after)==1
    r,n=before[0],after[0];assert r['id']==n['id']==1 and r['last_error']==n['last_error']==''
    assert stamp(r['last_check_at'])<=stamp(n['last_check_at'])<=z['at']+1 and (n['last_check_at']==r['last_check_at'] or stamp(n['last_check_at'])>=a['started_at']-1)
    before={r['name']:r['seq']for r in values(a,'sqlite_sequence')};after={r['name']:r['seq']for r in values(z,'sqlite_sequence')};assert before.keys()==after.keys()
    assert before['monitor_samples']==old_last_id and after['monitor_samples']==old_last_id+len(samples)
    for name in before.keys()-{'monitor_samples'}:assert before[name]==after[name]
    return {'ok':True,'new_monitor_samples':len(samples),'every_new_percent_CPU_network_and_disk_rate_recomputed':True,'new_minute_zero_DB_observations':len(db),'condition_values_bound_to_actual_newest_sample':True,'same_nginx_status_and_only_fresh_clock':True,'notification_error_identity_and_only_fresh_clock':True,'only_matching_monitor_sample_sequence_increment':True,'all_original_observation_rows_preserved':True}
