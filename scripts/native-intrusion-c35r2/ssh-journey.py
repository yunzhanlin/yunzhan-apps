"""Actual installed C35 SSH dual-stack enforcement, ban-preserving configure and audited unban.
Own connected client namespace only. Normal systemd sshd/Fail2ban/Core/Root; no unit PID
adapter, manual SSH bans, fake sockets, product source patches or request replay.
"""
import ast,contextlib,copy,fcntl,hashlib,json,os,pathlib,pwd,re,secrets,socket,sqlite3,stat,subprocess,threading,time
def run(base,arch,api,save,wait_job,resume=None):
 base=pathlib.Path(base);assert os.geteuid()==0 and arch in('amd64','arm64')
 ident=secrets.token_hex(5);ns='yzc35-'+ident;hostif='yh35'+ident;peerif='yp35'+ident
 v4='192.0.2.2';v6='2001:db8:35::2';a4='192.0.2.1';a6='2001:db8:35::1';healthy=('192.0.2.4','2001:db8:35::4')
 user=pwd.getpwuid(501)if arch=='arm64'else pwd.getpwnam('qa');keyfile=base/'SSH-client-test-key';authorized=pathlib.Path(user.pw_dir)/'.ssh/authorized_keys'
 assert (user.pw_uid==501 if arch=='arm64'else user.pw_name=='qa'and 1000<=user.pw_uid<60000)and user.pw_dir==('/home/guobinlin.guest'if arch=='arm64'else'/home/qa')
 def cmd(args,timeout=8):
  r=subprocess.run(args,capture_output=True,text=True,timeout=timeout);assert len(r.stdout)+len(r.stderr)<1<<20
  assert r.returncode==0,(args[0],r.returncode,r.stderr[-1024:]);return r.stdout
 def sha(f):return hashlib.sha256(pathlib.Path(f).read_bytes()).hexdigest()
 def bans():
  _,s=api('/security/fail2ban');j=next(v for v in s['jails']if v['name']=='sshd');assert s['installed']and s['active']and j['currently_banned']==len(j['banned_ips']);return set(j['banned_ips'])
 def timed_bans():return cmd(['fail2ban-client','get','sshd','banip','--with-time'])
 def filter_values():return {n:cmd(['fail2ban-client','get','sshd',n])for n in('usedns','prefregex','failregex','ignoreregex','maxlines','maxmatches','ignorecommand','ignorecache','ignoreself','ignoreip','logencoding','logtimezone')}
 def pid():
  n=cmd(['systemctl','show','fail2ban.service','--property=MainPID','--value']).strip();assert int(n)>1
  return[n,pathlib.Path('/proc/'+n+'/stat').read_text().rsplit(')',1)[1].split()[19],sha('/proc/'+n+'/exe')]
 def snapshot_files():
  return {n:sha(n)for n in('/etc/fail2ban/jail.d/panel-intrusion.local','/etc/panel/security-apps/intrusion-prevention.json','/etc/panel/security-apps/intrusion-policy.json','/etc/passwd','/etc/group','/etc/shadow','/etc/gshadow','/etc/nsswitch.conf')}
 def nft():return json.loads(cmd(['nft','-j','list','ruleset']))
 def static(value):
  if isinstance(value,list):return[static(v)for v in value]
  if not isinstance(value,dict):return value
  return{k:({'packets':'counter','bytes':'counter'}if k=='counter'and isinstance(v,dict)and set(v)=={'packets','bytes'}else static(v))for k,v in value.items()}
 def ssh(source,who):
  target=a6 if ':'in source else a4
  args=['ip','netns','exec',ns,'ssh','-6'if ':'in source else'-4','-F','/dev/null','-T','-b',source,'-p','22','-l',who,'-i',str(keyfile)]
  for o in('BatchMode=yes','PreferredAuthentications=publickey','IdentitiesOnly=yes','IdentityAgent=none','AddKeysToAgent=no','StrictHostKeyChecking=yes','UpdateHostKeys=no','GlobalKnownHostsFile=/dev/null','UserKnownHostsFile='+str(base/'SSH-known-hosts'),'HostKeyAlgorithms=ssh-ed25519','VerifyHostKeyDNS=no','ConnectTimeout=2','ConnectionAttempts=1','ControlMaster=no','ControlPath=none','ProxyCommand=none','ProxyJump=none','GSSAPIAuthentication=no'):args.extend(['-o',o])
  args.extend([target,'/usr/bin/id -u'])
  r=subprocess.run(args,capture_output=True,text=True,timeout=5,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8','LC_ALL':'C.UTF-8'});assert len(r.stdout)<4096 and len(r.stderr)<8192;return r
 def connected(source,port):
  code="import socket,json; s=socket.socket("+("socket.AF_INET6"if ':'in source else"socket.AF_INET")+",socket.SOCK_STREAM);s.settimeout(1);s.bind(("+repr(source)+",0));r=s.connect_ex(("+repr(a6 if ':'in source else a4)+","+str(port)+"));s.close();print(json.dumps({'connected':r==0}))"
  return json.loads(cmd(['ip','netns','exec',ns,'python3','-I','-B','-c',code]))['connected']
 original_names=cmd(['ip','netns','list']);assert ns not in original_names
 info=authorized.lstat();assert stat.S_ISREG(info.st_mode)and info.st_uid==user.pw_uid and info.st_nlink==1 and not stat.S_IMODE(info.st_mode)&0o022
 original=authorized.read_bytes();assert len(original)<=65536
 original_pid=pid();original_nss={n:sha('/etc/'+n)for n in('passwd','group','shadow','gshadow','nsswitch.conf')}
 _,installed=api('/software/intrusion-prevention/inspection');assert installed['installed']and installed['version']=='1.1.1'and installed['config_matches']and installed['ssh_ports_match']and installed['active_bans_known']
 if resume is None:
  assert installed['active_bans']==0 and not installed['healthy']and installed['kernel_scope_deferred']and not installed['kernel_scope_verified']
 else:
  previous=pathlib.Path(resume['base']);assert re.fullmatch('/opt/panel-intrusion-followup-[a-f0-9]{32}/evidence',str(previous))
  for n,h in resume['files'].items():assert re.fullmatch('[A-Za-z0-9._-]+',n)and sha(previous/n)==h
  old=json.loads((previous/'actual-SSH-configure-unban-journey-proof.json').read_bytes());assert not old['ok']and old['configure_POSTs']==1 and old['explicit_successful_unban_POSTs']==0
  refused=[json.loads((previous/n).read_bytes())for n in resume['files']if n.startswith('HTTP-refusal-')];assert len(refused)==1 and refused[0]['status']==400 and refused[0]['path']=='/software/intrusion-prevention/configure'
  original_key=json.loads((previous/'preserving-configure-once-intent.json').read_bytes())['key']
  with contextlib.closing(sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True))as db:
   db.execute('PRAGMA query_only=ON');assert db.execute('SELECT count(*)FROM runtime_jobs WHERE idempotency_key=?',(original_key,)).fetchone()==(0,)
  assert installed['active_bans']==2 and installed['healthy']and installed['kernel_scope_verified']and bans()=={v4,v6}
 sockets=[];threads=[];done=threading.Event();namespace_created=False;veth_created=False;auth_added=False
 proof={'ok':False,'same_actual_systemd_PID_and_normal_Core_Root':True,'manual_SSH_ban_commands':0,'configure_POSTs':0,'explicit_successful_unban_POSTs':0}
 try:
  cmd(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(keyfile)]);public=(base/'SSH-client-test-key.pub').read_text().split();assert public[0]=='ssh-ed25519'
  host_public=pathlib.Path('/etc/ssh/ssh_host_ed25519_key.pub').read_text().split();assert host_public[0]=='ssh-ed25519'
  (base/'SSH-known-hosts').write_text(a4+' '+host_public[0]+' '+host_public[1]+'\n'+a6+' '+host_public[0]+' '+host_public[1]+'\n')
  fd=os.open(authorized,os.O_WRONLY|os.O_APPEND|os.O_NOFOLLOW);assert os.fstat(fd).st_ino==info.st_ino
  try:os.write(fd,b'\n'+(' '.join(public[:2])+' yunzhan-owned-C35-QA\n').encode());os.fsync(fd);auth_added=True
  finally:os.close(fd)
  cmd(['ip','netns','add',ns]);namespace_created=True
  cmd(['ip','link','add',hostif,'type','veth','peer','name',peerif]);veth_created=True
  cmd(['ip','link','set',peerif,'netns',ns]);cmd(['ip','addr','add',a4+'/29','dev',hostif]);cmd(['ip','-6','addr','add',a6+'/64','dev',hostif,'nodad']);cmd(['ip','link','set',hostif,'up'])
  for address in(v4,healthy[0]):cmd(['ip','-n',ns,'addr','add',address+'/29','dev',peerif])
  for address in(v6,healthy[1]):cmd(['ip','-n',ns,'-6','addr','add',address+'/64','dev',peerif,'nodad'])
  cmd(['ip','-n',ns,'link','set','lo','up']);cmd(['ip','-n',ns,'link','set',peerif,'up'])
  for family,address in((socket.AF_INET,a4),(socket.AF_INET6,a6)):
   s=socket.socket(family,socket.SOCK_STREAM)
   if family==socket.AF_INET6:s.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)
   s.bind((address,28080));s.listen(8);s.settimeout(.2);sockets.append(s)
   def serve(listener):
    while not done.is_set():
     try:c,_=listener.accept()
     except socket.timeout:continue
     except OSError:break
     c.close()
   t=threading.Thread(target=serve,args=(s,),daemon=True);t.start();threads.append(t)
  for address in healthy:
   r=ssh(address,user.pw_name);assert r.returncode==0 and r.stdout==str(user.pw_uid)+'\n',('actual legitimate SSH before bans',address,r.returncode,r.stderr[-800:])
  attempts={}
  if resume is None:
   for address in(v4,v6):
    for attempt in range(1,9):
     r=ssh(address,'yz-c35-denied-'+ident);assert r.returncode!=0 and r.stdout==''
     end=time.monotonic()+1.5
     while time.monotonic()<end:
      if address in bans():break
      time.sleep(.08)
     if address in bans():attempts[address]=attempt;break
    assert address in attempts,('real failed SSH did not ban',address)
  else:proof['original_bans_retained_without_reset_or_repeated_failed_authentication']=resume
  assert bans()=={v4,v6};times=timed_bans();filters=filter_values();configuration_nft=nft()
  save('actual-failed-authentication-and-original-ban-evidence.json',{'failed_attempts':attempts,'resumed_original':resume,'ban_times':times,'filter_values':filters,'nft':configuration_nft,'service_lifetime':original_pid})
  for address in(v4,v6):assert not connected(address,22)and connected(address,28080),'Actual SSH-only kernel enforcement failed'
  for address in healthy:
   r=ssh(address,user.pw_name);assert r.returncode==0 and r.stdout==str(user.pw_uid)+'\n'
  _,live=api('/software/intrusion-prevention/inspection');save('actual-dualstack-bans-inspection.json',live)
  assert live['healthy']and live['kernel_scope_verified']and not live['kernel_scope_deferred']and live['active_bans']==2
  _,principal=api('/software/intrusion-prevention/requests');actor=principal['actor_id'];assert re.fullmatch('[a-f0-9]{32}',actor)and principal['read_only']
  settings={'max_retry':6,'find_time_minutes':11,'ban_time_minutes':60};request={'actor_id':actor,'settings':settings};key=secrets.token_hex(16)
  save('preserving-configure-once-intent.json',{'request':request,'key':key,'maximum_POSTs':1});proof['configure_POSTs']=1
  status,accepted=api('/software/intrusion-prevention/configure',request,key);save('preserving-configure-accepted.json',accepted);assert status==202;wait_job('configure',accepted['job_id']);proof['configure_job']=accepted['job_id']
  configured_times=timed_bans();configured_filters=filter_values();configured_nft=nft();configured_pid=pid()
  save('actual-after-configure-ban-filter-kernel-evidence.json',{'ban_times':configured_times,'filter_values':configured_filters,'nft':configured_nft,'service_lifetime':configured_pid})
  assert bans()=={v4,v6}and configured_times==times and configured_filters==filters and configured_pid==original_pid and static(configuration_nft)==static(configured_nft)
  _,configured=api('/software/intrusion-prevention/inspection');save('actual-configured-bans-preserved-inspection.json',configured)
  assert configured['healthy']and configured['settings']==settings and configured['runtime_settings']=={'maxretry':6,'findtime':660,'bantime':3600}and configured['active_bans']==2
  files=snapshot_files();before_nft=nft();before_times=timed_bans()
  save('actual-before-unban-private-evidence.json',{'files':files,'nft':before_nft,'ban_times':before_times})
  status,unban=api('/security/fail2ban/unban',{'jail':'sshd','ip':v4});save('normal-Core-audited-unban.json',unban);assert status==200 and unban=={'jail':'sshd','ip':v4,'unbanned':True};proof['explicit_successful_unban_POSTs']=1
  assert bans()=={v6}and connected(v4,22)and not connected(v6,22)and connected(v6,28080)and snapshot_files()==files and filter_values()==filters and pid()==original_pid
  policy=json.loads(pathlib.Path('/etc/panel/security-apps/intrusion-policy.json').read_bytes())
  actual_after_nft=nft();old=copy.deepcopy(before_nft);new=copy.deepcopy(actual_after_nft)
  def strip_v4(value,before):
   matches=[v['set']for v in value['nftables']if 'set'in v and v['set'].get('family')=='inet'and v['set'].get('table')==policy['table']and v['set'].get('name')==policy['ipv4_set']]
   assert len(matches)==1;node=matches[0];assert node.get('elem',[])==([v4]if before else[]);node.pop('elem',None)
  strip_v4(old,True);strip_v4(new,False);assert static(old)==static(new),'Unban modified unrelated static kernel state'
  after_times=timed_bans()
  save('actual-after-unban-private-evidence.json',{'files':snapshot_files(),'nft':actual_after_nft,'ban_times':after_times,'filter_values':filter_values(),'service_lifetime':pid()})
  def remaining(raw):
   try:value=ast.literal_eval(raw)
   except(ValueError,SyntaxError):value=raw.splitlines()
   if isinstance(value,str):value=value.splitlines()
   assert isinstance(value,(list,tuple))and all(isinstance(v,str)for v in value)
   found=[v for v in value if v.startswith(v6+' \t')];assert len(found)==1;return found[0]
  assert remaining(before_times)==remaining(after_times),'Remaining IPv6 ban creation/expiry changed'
  r=ssh(v4,user.pw_name);assert r.returncode==0 and r.stdout==str(user.pw_uid)+'\n'
  _,final=api('/software/intrusion-prevention/inspection');save('actual-after-unban-inspection.json',final);assert final['healthy']and final['active_bans']==1
  with contextlib.closing(sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True))as db:
   db.execute('PRAGMA query_only=ON');rows=db.execute("SELECT action,target,result FROM audit_logs WHERE action='security.fail2ban.unban'").fetchall()
  save('actual-Core-unban-audit.json',{'rows':rows});assert rows==[('security.fail2ban.unban','sshd:'+v4,'success')]
  assert {n:sha('/etc/'+n)for n in original_nss}==original_nss
  proof.update(ok=True,actual_failed_auth_attempts_to_ban=attempts,actual_legitimate_SSH_before_during_after=True,IPv4_IPv6_kernel_enforcement_and_other_TCP_port_preserved=True,bans_creation_expiry_and_filter_preserved_during_configuration=True,only_explicit_v4_unbanned_v6_expiry_static_rules_preserved=True,normal_Core_audit=True,NSS_and_original_Fail2ban_lifetime_preserved=True)
 finally:
  done.set()
  for s in sockets:s.close()
  for t in threads:t.join(timeout=1)
  if namespace_created:cmd(['ip','netns','del',ns])
  if veth_created:
   r=subprocess.run(['ip','link','show',hostif],capture_output=True,text=True,timeout=5)
   if r.returncode==0:cmd(['ip','link','del',hostif])
  if auth_added:
   fd=os.open(authorized,os.O_WRONLY|os.O_NOFOLLOW)
   try:assert os.fstat(fd).st_ino==info.st_ino;os.ftruncate(fd,0);os.write(fd,original);os.fsync(fd)
   finally:os.close(fd)
   assert authorized.read_bytes()==original and authorized.stat().st_mode==info.st_mode and authorized.stat().st_uid==info.st_uid
  assert ns not in cmd(['ip','netns','list']);proof['own_client_namespace_and_extra_authorized_key_removed']=True;save('actual-SSH-configure-unban-journey-proof.json',proof)
 return proof

