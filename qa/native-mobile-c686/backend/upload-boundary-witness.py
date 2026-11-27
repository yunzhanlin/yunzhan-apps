from pathlib import Path
import hashlib,json,os,sqlite3,stat,sys
os.umask(0o077);assert os.geteuid()==0 and os.environ.get('GITHUB_ACTIONS')=='true'and os.environ.get('GITHUB_REPOSITORY')=='yunzhanlin/yunzhan-apps';private=Path(sys.argv[1]).resolve(strict=True);owner=private.stat();phase=sys.argv[2];assert phase in('before','selected-locked','uploaded','cancelled-locked','cancelled-unlocked','late-result-refused','final');read=lambda p:json.loads(Path(p).read_bytes());sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest();setup=read(private/'real-panel-setup.json');root=Path('/srv/panel/sites')/setup['site']/'public';specs=read(private/'original-owned-native-upload-fixtures.json');assert len(specs)==3;files=[]
for i,spec in enumerate(specs):
 p=root/spec['name'];exists=p.exists();assert not p.is_symlink();expected=i==0 and phase not in('before','selected-locked');assert exists==expected,'Unexpected owned upload state '+str(i)+' '+phase
 if exists:
  s=p.lstat();assert stat.S_ISREG(s.st_mode)and s.st_nlink==1 and s.st_size==spec['bytes']and sha(p)==spec['sha256'];files.append({'name':p.name,'bytes':s.st_size,'sha256':sha(p),'uid':s.st_uid,'gid':s.st_gid,'mode':stat.S_IMODE(s.st_mode),'inode':s.st_ino})
original=root/setup['filename'];assert original.is_file()and sha(original)==setup['sha256']and original.stat().st_size==setup['bytes']
db=sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True);db.row_factory=sqlite3.Row;db.execute('PRAGMA query_only=ON');audit=[dict(v)for v in db.execute('SELECT *FROM audit_logs')];rows=[v for v in audit if v['action']=='file.upload'and v['result']=='success'and any(v['target']==setup['site']+':'+s['name']for s in specs)];assert len(rows)==len(files);assert all(v['actor']=='admin'for v in rows);db.close();value={'ok':True,'phase':phase,'actual_server_upload_files':files,'actual_upload_audit':rows,'original_attachment_preserved':True,'original_requests_replayed':0};dest=private/('original-upload-boundary-'+phase+'.json')
with dest.open('x')as f:json.dump(value,f,indent=2)
os.chown(dest,owner.st_uid,owner.st_gid);print(json.dumps({'ok':True,'phase':phase,'actual_server_uploads':len(files)}))
