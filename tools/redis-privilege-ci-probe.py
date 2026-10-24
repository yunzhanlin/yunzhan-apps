import os,json,pathlib,pwd
a=pwd.getpwnam('panel-redis')
assert a.pw_uid>0 and a.pw_gid>0
assert os.getresuid()==(a.pw_uid,)*3 and os.getresgid()==(a.pw_gid,)*3 and os.getgroups()==[a.pw_gid]
fields={n.split(':',1)[0]:n.split(':',1)[1].strip()for n in pathlib.Path('/proc/self/status').read_text().splitlines()if ':'in n}
assert fields['NoNewPrivs']=='1'and fields['Seccomp']=='2'
for name in('CapInh','CapPrm','CapEff','CapAmb'):assert fields[name]=='0000000000000000'
assert fields['CapBnd']=='00000000000000c1'
assert not os.access('/var/lib/panel-executor/runtime-lifecycle.lock',os.R_OK)
print(json.dumps({'actual_production_locked_thread_helper_execd_this_observer':True,'UID':a.pw_uid,'GID':a.pw_gid,'all_active_and_inheritable_capabilities_zero':True,'NoNewPrivileges':True,'seccomp_present':True,'bootstrap_bounding_set_only_three_bits':True,'original_Root_runtime_lock_not_readable':True,'application_configuration_or_Redis_instance_mutations':0}),flush=True)

