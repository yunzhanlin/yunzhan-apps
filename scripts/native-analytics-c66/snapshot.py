"""Read-only, transaction-consistent original table and lifetime observer."""
import contextlib,hashlib,json,os,pathlib,sqlite3,stat,subprocess,sys,time
assert os.geteuid()==0 and len(sys.argv)==2
path=pathlib.Path(sys.argv[1]);assert not path.exists()
with contextlib.closing(sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True,timeout=15))as db:
 db.row_factory=sqlite3.Row;db.execute('PRAGMA query_only=ON');db.execute('BEGIN')
 schema=[dict(r)for r in db.execute("SELECT type,name,tbl_name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name")]
 tables={}
 for r in schema:
  if r['type']!='table':continue
  name=r['name'];columns=[row[1]for row in db.execute('PRAGMA table_info("'+name.replace('"','""')+'")')]
  rows=[[{'blob_hex':v.hex()}if type(v)is bytes else v for v in row]for row in db.execute('SELECT * FROM "'+name.replace('"','""')+'"')]
  rows.sort(key=lambda row:json.dumps(row,sort_keys=True,separators=(',',':')))
  tables[name]={'columns':columns,'rows':rows}
 db.rollback()
assert len(tables)==113
units={}
for name in('panel','panel-executor','nginx','panel-terminal','panel-terminal-root'):
 r=subprocess.run(['systemctl','show',name+'.service','--property=ActiveState,SubState,MainPID,InvocationID,ExecMainStartTimestampMonotonic,NRestarts'],capture_output=True,text=True,timeout=15);assert r.returncode==0
 units[name]=dict(line.split('=',1)for line in r.stdout.splitlines())
 assert units[name]['ActiveState']=='active' and int(units[name]['MainPID'])>0
files={}
for parent in('/etc/panel','/etc/nginx'):
 for root,dirs,names in os.walk(parent,followlinks=False):
  for name in sorted(dirs+names):
   p=pathlib.Path(root)/name;s=p.lstat();v={'mode':stat.S_IMODE(s.st_mode),'uid':s.st_uid,'gid':s.st_gid,'inode':s.st_ino,'dev':s.st_dev,'nlink':s.st_nlink,'type':stat.S_IFMT(s.st_mode)}
   if stat.S_ISREG(s.st_mode):assert s.st_size<8<<20;v['sha256']=hashlib.sha256(p.read_bytes()).hexdigest()
   elif stat.S_ISLNK(s.st_mode):v['link']=os.readlink(p)
   else:assert stat.S_ISDIR(s.st_mode)
   files[str(p)]=v
with path.open('x')as f:json.dump({'at':time.time(),'boot':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'schema':schema,'tables':tables,'units':units,'files':files,'NSS':{n:hashlib.sha256(pathlib.Path('/etc',n).read_bytes()).hexdigest()for n in('passwd','group','shadow','gshadow')}},f,sort_keys=True);f.write('\n')
