"""Always retain bounded original installer diagnostics; no repair or replay."""
import hashlib,json,os,stat,subprocess,sys
from pathlib import Path
os.umask(0o077)
assert os.geteuid()==0 and os.environ.get('GITHUB_ACTIONS')=='true'and os.environ.get('GITHUB_REPOSITORY')=='yunzhanlin/yunzhan-apps'
out=Path(sys.argv[1])/'original-pm2-diagnostics';out.mkdir(mode=0o700)
for label,args in {
 'dependency-unit-show':['/usr/bin/systemctl','show','panel-app-dependencies@pm2-manager.service'],
 'dependency-unit-original-journal':['/usr/bin/journalctl','--no-pager','-b','-u','panel-app-dependencies@pm2-manager.service','-n','500','-o','json'],
 'executor-original-journal':['/usr/bin/journalctl','--no-pager','-b','-u','panel-executor.service','-n','250','-o','json'],
 'distribution-node-npm-original':['/usr/bin/dpkg-query','-W','-f=${Package}\t${Version}\t${Status}\n','nodejs','npm'],
}.items():
 with(out/(label+'.stdout')).open('xb')as stdout,(out/(label+'.stderr')).open('xb')as stderr:r=subprocess.run(args,stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr,timeout=30)
 with(out/(label+'.json')).open('x')as f:json.dump({'args':args,'exit':r.returncode,'read_only':True},f,indent=2)
for label,name in {'dependency-result':'/etc/panel/security-apps/modules/pm2-manager/dependency-result.json','apt-original-term':'/var/log/apt/term.log','apt-original-history':'/var/log/apt/history.log'}.items():
 try:
  p=Path(name);st=p.lstat();assert stat.S_ISREG(st.st_mode)and st.st_size<=16<<20
  fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW);opened=os.fstat(fd)
  with os.fdopen(fd,'rb')as f:raw=f.read((16<<20)+1)
  assert opened.st_ino==st.st_ino and opened.st_dev==st.st_dev and len(raw)==st.st_size
  with(out/(label+'.original')).open('xb')as f:f.write(raw)
 except FileNotFoundError:pass
summary={}
for name in('/usr/bin/node','/usr/bin/npm','/usr/share/nodejs/npm/bin/npm-cli.js','/opt/panel/app-modules','/opt/panel/app-modules/pm2'):
 p=Path(name)
 try:
  s=p.lstat();summary[name]={'uid':s.st_uid,'gid':s.st_gid,'mode':s.st_mode,'inode':s.st_ino,'dev':s.st_dev,'link':os.readlink(p)if p.is_symlink()else None}
 except FileNotFoundError:summary[name]={'absent':True}
with(out/'original-path-identities.json').open('x')as f:json.dump(summary,f,indent=2)
