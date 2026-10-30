"""Complete typed SQLite evidence for a normal C28 to C29 upgrade.
No projected tables, inferred completion, database writes, or repair paths.
"""
import base64,contextlib,datetime,hashlib,json,math,pathlib,re,sqlite3,time

def cell(v):
    if v is None:return ['null']
    if type(v)is int:return ['integer',str(v)]
    if type(v)is float:
        assert math.isfinite(v)
        return ['real',v.hex()]
    if type(v)is str:return ['text',v]
    assert type(v)is bytes
    return ['blob',base64.b64encode(v).decode()]

def capture_core():
    start=time.time()
    with contextlib.closing(sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True,timeout=4))as db:
        db.execute('PRAGMA query_only=ON');db.execute('BEGIN')
        schema=[list(v)for v in db.execute('SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name')]
        tables=[v[0]for v in db.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
        columns={};rows={};total=0;count=0
        for name in tables:
            assert re.fullmatch('[A-Za-z0-9_]+',name)
            columns[name]=[list(v)for v in db.execute('PRAGMA table_info('+name+')')]
            data=[]
            for row in db.execute('SELECT * FROM '+name):
                count+=1;assert count<=1000000
                values=[cell(v)for v in row];assert len(values)==len(columns[name])
                encoded=json.dumps(values,ensure_ascii=False,separators=(',',':'));total+=len(encoded.encode());assert total<=32<<20
                data.append((encoded,values))
            rows[name]=[v[1]for v in sorted(data)]
        return {'format':1,'at':time.time(),'started_at':start,'schema':schema,'columns':columns,'rows':rows,'row_count':count,'typed_row_bytes':total,'all_tables_included':True}

def stamp(v):
    assert type(v)is str and re.fullmatch(r'20\d\d-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z',v)
    m=re.fullmatch(r'(.*?)(?:\.(\d{1,9}))?Z',v);base=datetime.datetime.strptime(m[1],'%Y-%m-%dT%H:%M:%S').replace(tzinfo=datetime.timezone.utc)
    return base.timestamp()+int((m[2]or'').ljust(9,'0'))/1e9

def compare_core(before,after):
    assert before['format']==after['format']==1 and before['all_tables_included']and after['all_tables_included']
    assert 0<=after['at']-before['at']<=600 and before['started_at']<=before['at']<=after['started_at']<=after['at']
    added={'waf_country_requests','waf_country_results'}
    assert set(after['rows'])==set(before['rows'])|added and not set(before['rows'])&added
    assert after['rows']['waf_country_requests']==after['rows']['waf_country_results']==[]
    request='CREATE TABLE waf_country_requests(job_id TEXT PRIMARY KEY REFERENCES runtime_jobs(id),actor_id TEXT NOT NULL,idempotency_key TEXT NOT NULL UNIQUE,payload_sha256 TEXT NOT NULL,created_at TEXT NOT NULL,CHECK(length(job_id)=32 AND length(actor_id)=32 AND length(idempotency_key)=32 AND length(payload_sha256)=64))'
    result="CREATE TABLE waf_country_results(job_id TEXT PRIMARY KEY REFERENCES waf_country_requests(job_id),request_sha256 TEXT NOT NULL,result_sha256 TEXT NOT NULL,body BLOB NOT NULL,state TEXT NOT NULL,created_at TEXT NOT NULL,CHECK(length(request_sha256)=64 AND length(result_sha256)=64 AND length(body)>0 AND length(body)<=32768 AND state IN ('succeeded','failed','needs_attention')))"
    expected=[['index','sqlite_autoindex_waf_country_requests_1','waf_country_requests',None],['index','sqlite_autoindex_waf_country_requests_2','waf_country_requests',None],['index','sqlite_autoindex_waf_country_results_1','waf_country_results',None],['index','waf_country_requests_actor_job','waf_country_requests','CREATE INDEX waf_country_requests_actor_job ON waf_country_requests(actor_id,job_id)'],['table','waf_country_requests','waf_country_requests',request],['table','waf_country_results','waf_country_results',result]]
    assert [v for v in after['schema']if v[2]in added]==expected
    assert [v for v in after['schema']if v[2]not in added]==before['schema']
    moving=[];same=0
    for name,rows in before['rows'].items():
        assert before['columns'][name]==after['columns'][name],name+' column drift'
        current=after['rows'][name]
        if rows==current:same+=1;continue
        cols=[v[1]for v in before['columns'][name]]
        if name=='schema_migrations':
            assert cols==['version','applied_at']
            extra=[v for v in current if v not in rows];assert len(extra)==1 and all(v in current for v in rows)and len(current)==len(rows)+1
            row=extra[0];assert row[0]==['integer','103']and row[1][0]=='text'
            assert before['started_at']-1<=stamp(row[1][1])<=after['at']+1
        elif name=='runtime_installations':
            assert 'detected_at'in cols and 'id'in cols
            at=cols.index('detected_at');key=cols.index('id');a={json.dumps(v[key]):v for v in rows};z={json.dumps(v[key]):v for v in current};assert a.keys()==z.keys()
            for k,r in a.items():
                q=z[k];assert r[:at]+r[at+1:]==q[:at]+q[at+1:]
                assert r[at][0]==q[at][0]=='text'and stamp(r[at][1])<=stamp(q[at][1])<=after['at']+1
        elif name=='load_balance_traffic_source':
            assert cols==['id','worker_state','worker_sequence','worker_checked_at']and len(rows)==len(current)==1
            a,z=rows[0],current[0];assert a[:3]==z[:3]and a[0]==['integer','1']and a[1]==['text','clear']and a[3][0]==z[3][0]=='text'
            assert before['started_at']-30<=stamp(a[3][1])<=before['at']+1 and stamp(a[3][1])<=stamp(z[3][1])<=after['at']+1
        else:raise AssertionError('Unrelated old business table changed: '+name)
        moving.append(name)
    assert 'schema_migrations'in moving
    return {'ok':True,'all_old_tables_compared':len(before['rows']),'all_new_tables_captured':len(after['rows']),'unchanged_tables':same,'qualified_changes':moving,'new_empty_country_tables':sorted(added),'entire_schema_and_all_columns_compared':True,'no_old_jobs_or_business_rows_rewritten':True,'elapsed_seconds':after['at']-before['at']}
