"""Owned fresh NFS131 IPv4/IPv6 kernel I/O journey through authenticated Core actions.
No Main/reference actions, request replay, arbitrary API command or fake mount.
"""
import contextlib,hashlib,json,os,pathlib,re,secrets,select,socket,sqlite3,stat,subprocess,sys,time

def run(base, arch, api, save, job):
    assert os.geteuid()==0 and arch in ('amd64','arm64')
    tag=secrets.token_hex(4)
    plan={'tag':tag,'site_slug':'nfs-c37r3-'+tag,'marker':'NFS-private-native-'+secrets.token_hex(16),'port':24269,'share':'share-'+tag,'mount4':'client4-'+tag,'mount6':'client6-'+tag}
    proof={'ok':False,'module_actions':[],'native_architecture':arch,'site_create_POSTs':0,'no_original_request_replay':True}
    def sha(path):return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()
    def cmd(args):
        r = subprocess.run(args, capture_output=True, text=True, timeout=30)
        assert r.returncode == 0, (args[0], r.returncode)
        assert len(r.stdout) < 1 << 20
        return r.stdout
    def lifetime(unit):
        d = dict((v.split('=', 1) for v in cmd(['systemctl', 'show', unit, '--property=MainPID,InvocationID,ActiveState']).splitlines()))
        assert d['ActiveState'] == 'active' and int(d['MainPID']) > 1
        p = pathlib.Path('/proc') / d['MainPID']
        d.update(start_ticks=p.joinpath('stat').read_text().rsplit(')', 1)[1].split()[19], exe_sha256=sha(p / 'exe'))
        return d
    def action(label, name, body):
        save(label + '-once-intent.json', {'action': name, 'request': body, 'attempts': 1, 'unknown_outcome_observe_only': True})
        proof['module_actions'].append(name)
        (_, v) = api('/app-modules/nfs-manager/' + name, body)
        save(label + '-response.json', v)
        return v
    def report(label):
        (_, v) = api('/app-modules/nfs-manager/server-report', {})
        save(label + '-server-report.json', v)
        return v
    def pause_for_grace(label):
        save(label + '-grace-start.json', {'monotonic': time.monotonic(), 'reason': 'Configured NFSv4 30-second grace; no RPC file write is retried'})
        time.sleep(31)
    def mountinfo(label, target):
        rows = [v for v in pathlib.Path('/proc/self/mountinfo').read_text().splitlines() if v.split()[4] == target]
        assert len(rows) == 1
        row = rows[0]
        save(label + '-actual-mount.json', {'line': row})
        fields = row.split()
        assert 'nfs4' in fields and all((n in fields[5].split(',') for n in ('nosuid', 'nodev', 'noexec')))
        return row
    def io(label, target, operation, filename):
        code = "import pathlib,os,sys,json,errno\nroot=pathlib.Path(sys.argv[1]);marker=sys.argv[2];operation=sys.argv[3];name=sys.argv[4]\nassert (root/'nfs-read-marker.txt').read_text()==marker\nif operation=='read':print(json.dumps({'ok':True,'read_exact':True}));sys.exit(0)\nf=root/name\ntry:fd=os.open(f,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)\nexcept OSError as e:\n if operation=='deny'and e.errno in(errno.EACCES,errno.EROFS,errno.EPERM):print(json.dumps({'ok':True,'server_RO_denied':True,'errno':e.errno}));sys.exit(0)\n raise\nwith os.fdopen(fd,'w')as stream:stream.write(marker+'-client');stream.flush();os.fsync(stream.fileno())\nassert operation=='write','Server RO export unexpectedly accepted a write; own file retained as evidence'\ns=f.stat();print(json.dumps({'ok':True,'written_exact':f.read_text()==marker+'-client','uid':s.st_uid,'gid':s.st_gid,'mode':s.st_mode&0o777}))\n"
        args = ['/usr/bin/timeout', '-k', '2', '20s', '/usr/bin/python3', '-I', '-B', '-c', code, target, plan['marker'], operation, filename]
        save(label + '-IO-once-intent.json', {'target': target, 'operation': operation, 'filename': filename, 'attempts': 1, 'unknown_outcome_observe_only': True})
        r = subprocess.run(args, capture_output=True, text=True, timeout=25)
        save(label + '-IO-original-outcome.json', {'status': r.returncode, 'stdout': r.stdout, 'stderr': r.stderr})
        assert r.returncode == 0, 'Original NFS file I/O failed or uncertain, never replayed: ' + label
        value = json.loads(r.stdout)
        assert value['ok']
        return value
    def daemon(label, native):
        v = lifetime('panel-nfs-server.service')
        assert v['exe_sha256'] == native['files']['bin/ganesha.nfsd']
        p = pathlib.Path('/proc') / v['MainPID']
        data = dict((line.split(':', 1) for line in (p / 'status').read_text().splitlines() if ':' in line))
        caps = int(data['CapEff'].strip(), 16)
        assert all((not caps & 1 << n for n in (8, 12, 13, 19, 21, 22)))
        assert os.readlink(p / 'ns/mnt') != os.readlink('/proc/1/ns/mnt')
        save(label + '-actual-daemon.json', {'lifetime': v, 'CapEff': data['CapEff'].strip(), 'mount_namespace': os.readlink(p / 'ns/mnt'), 'PID1_mount_namespace': os.readlink('/proc/1/ns/mnt')})
        return v

    save('NFS131-native-functional-plan.json',plan)
    initial=report('initial-functional')
    assert initial['runtime_format']==2 and initial['private_client_ready'] and not initial['service_active'] and initial['config']['revision']==0 and initial['config']['exports']==[]
    native=json.loads(pathlib.Path('/etc/panel/security-apps/modules/nfs-manager/native-runtime.json').read_bytes())
    assert native['format']==2 and len(native['packages'])==3 and len(native['files'])==9 and native['architecture']==arch
    create={'name':'NFS private client native QA','slug':plan['site_slug'],'domain':plan['site_slug']+'.localhost','php_version_id':''}
    key=secrets.token_hex(16);save('site-create-once-intent.json',{'body':create,'key':key,'attempts':1});proof['site_create_POSTs']=1
    status,accepted=api('/sites',create,key);assert status==202
    save('original-site-job-accepted.json',accepted);identity=accepted['job_id'];observed=[];end=time.monotonic()+150
    assert re.fullmatch('[a-f0-9]{32}',identity)
    while True:
        with contextlib.closing(sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True)) as db:
            db.execute('PRAGMA query_only=ON');row=db.execute('SELECT site_id,state,error FROM jobs WHERE id=?',(identity,)).fetchone()
        assert row is not None;observed.append({'at':time.time(),'site_id':row[0],'state':row[1],'error':row[2]})
        if row[1] in ('succeeded','failed','needs_attention','cancelled'):break
        assert time.monotonic()<end,'Original site job unresolved; do not replay'
        time.sleep(.5)
    save('original-site-job-observations.json',observed);assert row[1:]==('succeeded','')
    site=row[0];assert re.fullmatch('[a-f0-9]{32}',site);proof.update(site_id=site,site_job=identity)
    port=plan['port'];share=plan['share']
    v=action('v4-port','server-config',{'bind_address':'127.0.0.1','port':port,'expected_revision':0});assert v['config']['revision']==1 and not v['service_active']
    v=action('RO-export','export-save',{'resource_id':share,'site_id':site,'path':'','client_allow':['127.0.0.1'],'read_only':True,'expected_revision':1});assert v['config']['revision']==2 and len(v['config']['exports'])==1
    public=pathlib.Path('/srv/panel/sites')/site/'public';st=public.lstat();assert stat.S_ISDIR(st.st_mode) and st.st_uid>0 and st.st_gid>0
    marker=public/'nfs-read-marker.txt'
    with os.fdopen(os.open(marker,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600),'w') as f:
        os.fchown(f.fileno(),st.st_uid,st.st_gid);f.write(plan['marker']);f.flush();os.fsync(f.fileno())
    save('owned-website-fixture.json',{'site_id':site,'public':str(public),'uid':st.st_uid,'gid':st.st_gid,'device':st.st_dev,'inode':st.st_ino,'marker_sha256':sha(marker)})
    action('initial-start','server-start',{});pause_for_grace('initial-start');first=daemon('v4-initial',native)
    mount4=plan['mount4'];target4='/srv/panel/nfs/'+mount4
    action('v4-client-mount','mount',{'resource_id':mount4,'source':'127.0.0.1:/'+share,'read_only':False,'port':port})
    original_mount=mountinfo('v4-before-live-apply',target4);assert 'vers=4.2' in original_mount and 'sec=sys' in original_mount
    ro=io('RO-server',target4,'deny','RO-must-refuse-'+plan['tag']);assert ro['server_RO_denied'] and not(public/('RO-must-refuse-'+plan['tag'])).exists()
    v=action('RW-live-export','export-save',{'resource_id':share,'site_id':site,'path':'','client_allow':['127.0.0.1'],'read_only':False,'confirm':'SHARE RW '+share,'expected_revision':2});assert v['config']['revision']==3 and v['service_active']
    pause_for_grace('RW-live-export');warm=daemon('v4-after-live-apply',native);assert warm['MainPID']!=first['MainPID'] and mountinfo('v4-after-live-apply',target4)==original_mount
    write4=io('v4-RW-mapped',target4,'write','client-v4-'+tag);assert write4['written_exact'] and write4['uid']==st.st_uid and write4['gid']==st.st_gid
    assert(public/('client-v4-'+tag)).read_text()==plan['marker']+'-client' and(public/('client-v4-'+tag)).stat().st_uid==st.st_uid
    action('v4-client-unmount','unmount',{'resource_id':mount4});assert not os.path.ismount(target4)
    v=action('v6-listener','server-config',{'bind_address':'::1','port':port,'expected_revision':3});assert v['config']['revision']==4 and v['service_active']
    v=action('v6-export','export-save',{'resource_id':share,'site_id':site,'path':'','client_allow':['::1'],'read_only':False,'confirm':'SHARE RW '+share,'expected_revision':4});assert v['config']['revision']==5
    pause_for_grace('v6-final');daemon('v6',native)
    mount6=plan['mount6'];target6='/srv/panel/nfs/'+mount6
    action('v6-client-mount','mount',{'resource_id':mount6,'source':'[::1]:/'+share,'read_only':False,'port':port})
    original6=mountinfo('v6',target6);assert 'vers=4.2' in original6 and 'sec=sys' in original6
    write6=io('v6-RW-mapped',target6,'write','client-v6-'+tag);assert write6['written_exact'] and write6['uid']==st.st_uid and write6['gid']==st.st_gid
    record=pathlib.Path('/etc/panel/security-apps/modules/nfs-manager/mounts')/(mount6+'.json');record_before=record.read_bytes()
    hold=subprocess.Popen(['/usr/bin/python3','-I','-B','-c','import os,sys,signal;os.chdir(sys.argv[1]);print("ready",flush=True);signal.pause()',target6],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    try:
        assert select.select([hold.stdout],[],[],10)[0] and hold.stdout.readline()==b'ready\n'
        save('busy-unmount-once-intent.json',{'resource_id':mount6,'maximum_POSTs':1,'owned_CWD_pid':hold.pid})
        status,refusal=api('/app-modules/nfs-manager/unmount',{'resource_id':mount6},allowed=(409,))
        save('original-busy-unmount-refusal.json',{'status':status,'response':refusal})
        assert status==409 and isinstance(refusal,dict) and refusal.get('error') and record.read_bytes()==record_before and mountinfo('after-busy-refusal',target6)==original6
    finally:
        if hold.poll() is None:hold.terminate()
        hold.wait(timeout=10)
    action('v6-client-unmount-after-release','unmount',{'resource_id':mount6});assert not os.path.ismount(target6) and not record.exists()
    final=report('final-functional');assert final['runtime_format']==2 and final['private_client_ready'] and final['config']['revision']==5 and final['config']['bind_address']=='::1' and final['runtime_ready'] and final['service_active'] and final['boot_enabled'] and not final['recovery_pending']
    _,clients=api('/app-modules/nfs-manager/run',{});save('actual-final-client-report.json',clients);assert clients['mounts']==[]
    proof.update(ok=True,actual_server_RO_with_RW_client_denied=True,actual_IPv4_IPv6_private_helper_kernel_NFS42_mount_and_IO=True,actual_all_squash_to_nonroot_site_uid_gid=True,live_apply_preserved_original_client_mount_identity=True,daemon_private_namespace_and_bootstrap_caps_dropped=True,busy_unmount_refused_and_record_preserved=True,normal_unmount_after_owned_CWD_release=True,normal_client_unmounts_verified=True,owned_server_retained_enabled_for_separate_reboot_qualification=True)
    save('NFS131-native-functional-proof.json',proof)
    return proof
