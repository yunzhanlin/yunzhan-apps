from pathlib import Path
import hashlib,json,os,platform,sqlite3,stat,subprocess,sys,tarfile,time
os.umask(0o077);base=Path(sys.argv[1]);p=json.loads((base/'plan.json').read_bytes());assert os.geteuid()==0 and platform.machine()=='x86_64';assert Path('/etc/hostname').read_text().strip()==p['hostname']and Path('/proc/sys/kernel/random/boot_id').read_text().strip()==p['boot'];old=Path('/opt/panel/current').resolve(strict=True);assert json.loads((old/'SOURCE_INPUTS.json').read_bytes())['inputs_sha256']=='b223c28247d9d20e50a356643a9744a9ab174068dd567a2c57f15c342934c15f'
def sha(f):return hashlib.sha256(Path(f).read_bytes()).hexdigest()
def save(n,v):
 with(base/n).open('x')as f:json.dump(v,f,indent=2);f.write('\n')
for n,v in p['pins'].items():assert sha(base/n)==v
before={str(f.relative_to('/etc/panel')):sha(f)for f in Path('/etc/panel').rglob('*')if f.is_file()and not f.is_symlink()};save('original-etc-panel-hashes.json',before)
with sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True)as db,sqlite3.connect(base/'original-panel-before.sqlite')as target:db.backup(target)
a=['python3','-I','-B',str(base/'trusted-signed-release.py')];key=['--public-key',str(base/'release-signing-dev.pub')];archive=base/p['archive']
for label,args in [('original-signature-verify',a+['verify',str(archive)]+key),('original-normal-preflight',a+['install',str(archive)]+key+['--preflight-only']),('original-normal-upgrade',a+['install',str(archive)]+key)]:
 save(label+'-intent.json',{'args':args,'maximum_submissions':1})
 with(base/(label+'.stdout')).open('xb')as o,(base/(label+'.stderr')).open('xb')as e:r=subprocess.run(args,stdout=o,stderr=e,timeout=1200)
 save(label+'-outcome.json',{'returncode':r.returncode,'stdout_sha256':sha(base/(label+'.stdout')),'stderr_sha256':sha(base/(label+'.stderr'))});assert r.returncode==0,(label,r.returncode)
new=Path('/opt/panel/current').resolve(strict=True);assert new==Path('/opt/panel/releases')/p['version'];assert json.loads((new/'SOURCE_INPUTS.json').read_bytes())['inputs_sha256']==p['source'];old_snapshot=json.loads((Path(p['old_remote_case'])/'original-inherited-SDK-before.json').read_bytes())
for n,v in old_snapshot.items():
 f=old/n;st=f.lstat();assert st.st_uid==v['uid']and st.st_gid==v['gid']and stat.S_IMODE(st.st_mode)==v['mode']and st.st_ino==v['inode'];assert v['directory']or sha(f)==v['sha256']
checked={}
with tarfile.open(archive)as t:
 members=t.getmembers();prefix=members[0].name
 for m in members:
  n=str(Path(m.name).relative_to(prefix));f=new/n;st=f.lstat();assert st.st_uid==0 and stat.S_IMODE(st.st_mode)==m.mode
  if m.isfile():assert stat.S_ISREG(st.st_mode)and st.st_nlink==1 and f.read_bytes()==t.extractfile(m).read();checked[n]=sha(f)
  else:assert m.isdir()and stat.S_ISDIR(st.st_mode)
assert len(members)==213
for n,v in before.items():assert sha(Path('/etc/panel')/n)==v,n
save('original-normal-upgrade-proof.json',{'ok':True,'source_inputs_sha256':p['source'],'version':p['version'],'original_release_all_entries_preserved':True,'installed_archive_entries':len(members),'etc_panel_original_files_preserved':len(before),'new_programme_files':checked,'Main_changes':0});print(json.dumps({'ok':True,'architecture':'amd64','original_normal_signed_upgrade':True,'old_release_preserved':True,'installed_archive_entries':len(members)}))
